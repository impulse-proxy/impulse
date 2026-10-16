use std::{
    convert::Infallible,
    sync::{Arc, RwLock},
    time::Duration,
};

use bytes::Bytes;
use http::{HeaderMap, Request, Response, StatusCode};
use http_body_util::{BodyExt, combinators::BoxBody};
use hyper::body::Incoming;
use impulse_bridge::request::{
    RequestBuildInput, RequestBuildPolicies, RequestBuildTarget, RequestForwardedContext,
    RequestTraceContext, build_h1_request, build_h2_request_for_target,
};
use impulse_config::backend_endpoint::{BackendEndpoint, BackendScheme};
#[cfg(test)]
use impulse_config::runtime::RuntimeUpstreamPolicy;
use impulse_errors::{BridgeError, ProxyError};
use impulse_lb::upstream_pool::UpstreamPool;
use log::warn;

use super::{
    super::{
        QUICListener,
        admission::{AdmissionPolicyDecision, admission_rejection_response},
        forwarding::{
            BootstrapTargetResolutionInput, ResolutionContext, ResolutionObservation,
            TargetResolutionRequest, evaluate_pending_forward_external_auth,
        },
    },
    context::BootstrapRequestCtx,
    intake::{BootstrapRequestIntake, bootstrap_error_response},
    outcome::{observe_bootstrap_admission_outcome, observe_bootstrap_request_proxy_error},
    response::{BootstrapStreamingBody, boxed_full},
};
use crate::{
    request_pipeline::{
        PipelineRequest, PipelineRoute, ResolvedRequestPolicy, TerminalOutcomeGuard,
        evaluate_pipeline,
    },
    runtime::connection::{
        auth::{
            ExternalAuthDecision, ExternalAuthStateTransition, PendingHeaderMutation,
            apply_auth_request_mutations,
        },
        outcome::AdmissionOutcomeClass,
        request::PendingForward,
    },
};

/// The bootstrap request lifecycle stages, mirroring the QUIC data path so the
/// same reasoning applies at the currently emitted terminal boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::quic_listener) enum BootstrapLifecycleStage {
    Validate,
    ResolveRoute,
    AdmitOrReject,
    Dispatch,
}

impl BootstrapLifecycleStage {
    pub(in crate::quic_listener) fn slug(self) -> &'static str {
        match self {
            Self::Validate => "validate",
            Self::ResolveRoute => "resolve_route",
            Self::AdmitOrReject => "admit_or_reject",
            Self::Dispatch => "dispatch",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::quic_listener) enum BootstrapRequestMode {
    Standard,
    WebsocketUpgrade,
}

impl BootstrapRequestMode {
    pub(in crate::quic_listener) fn is_websocket_upgrade(self) -> bool {
        matches!(self, Self::WebsocketUpgrade)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::quic_listener) enum BootstrapRejectionReason {
    ValidationFailed,
    AuthDenied,
    RateLimited,
    Overloaded,
    RequestBodyTooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::quic_listener) enum BootstrapBackendFailureReason {
    RouteResolutionFailed,
    MissingEndpoint,
    RequestBuildFailed,
    DispatchFailed,
}

/// Bootstrap timeout classification at the currently emitted terminal boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::quic_listener) enum BootstrapTimeoutReason {
    Upstream,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::quic_listener) enum BootstrapTerminalOutcome {
    AcceptedStandardResponse,
    AcceptedWebsocketUpgrade,
    Rejected(BootstrapRejectionReason),
    BackendFailed(BootstrapBackendFailureReason),
    TimedOut(BootstrapTimeoutReason),
}

impl BootstrapTerminalOutcome {
    /// Whether this terminal outcome represents an accepted (non-error) response,
    /// mirroring the QUIC data path's success terminals.
    pub(in crate::quic_listener) fn is_accepted(self) -> bool {
        matches!(
            self,
            Self::AcceptedStandardResponse | Self::AcceptedWebsocketUpgrade
        )
    }

    /// The canonical request-outcome reason for this bootstrap terminal (obs
    /// Phase 10). Ties the bootstrap terminal vocabulary to the *same* canonical
    /// enum the QUIC data path resolves through, so equivalent outcomes on both
    /// planes report one reason. `None` for accepted outcomes (which are not a
    /// failure reason). Test-only for now — it enforces the cross-plane contract
    /// until an emitter consumes it.
    #[cfg(test)]
    pub(in crate::quic_listener) fn canonical_reason(
        self,
    ) -> Option<crate::observability::RequestOutcomeReason> {
        use crate::observability::RequestOutcomeReason as R;
        Some(match self {
            Self::AcceptedStandardResponse | Self::AcceptedWebsocketUpgrade => return None,
            Self::Rejected(reason) => match reason {
                BootstrapRejectionReason::AuthDenied => R::AuthDenied,
                BootstrapRejectionReason::RateLimited => R::RateLimited,
                BootstrapRejectionReason::Overloaded => R::Overloaded,
                BootstrapRejectionReason::ValidationFailed
                | BootstrapRejectionReason::RequestBodyTooLarge => R::ValidationRejected,
            },
            Self::BackendFailed(reason) => match reason {
                BootstrapBackendFailureReason::RouteResolutionFailed
                | BootstrapBackendFailureReason::MissingEndpoint
                | BootstrapBackendFailureReason::RequestBuildFailed
                | BootstrapBackendFailureReason::DispatchFailed => R::BackendTransportFailed,
            },
            Self::TimedOut(_) => R::TimedOut,
        })
    }

    /// A stable slug naming the terminal classification, aligned with the
    /// terminal-state names used in the QUIC data path.
    pub(in crate::quic_listener) fn slug(self) -> &'static str {
        match self {
            Self::AcceptedStandardResponse => "accepted_standard_response",
            Self::AcceptedWebsocketUpgrade => "accepted_websocket_upgrade",
            Self::Rejected(reason) => match reason {
                BootstrapRejectionReason::ValidationFailed => "rejected_validation",
                BootstrapRejectionReason::AuthDenied => "rejected_auth_denied",
                BootstrapRejectionReason::RateLimited => "rejected_rate_limited",
                BootstrapRejectionReason::Overloaded => "rejected_overloaded",
                BootstrapRejectionReason::RequestBodyTooLarge => "rejected_request_body_too_large",
            },
            Self::BackendFailed(reason) => match reason {
                BootstrapBackendFailureReason::RouteResolutionFailed => {
                    "backend_failed_route_resolution"
                }
                BootstrapBackendFailureReason::MissingEndpoint => "backend_failed_missing_endpoint",
                BootstrapBackendFailureReason::RequestBuildFailed => "backend_failed_request_build",
                BootstrapBackendFailureReason::DispatchFailed => "backend_failed_dispatch",
            },
            Self::TimedOut(BootstrapTimeoutReason::Upstream) => "timed_out_upstream",
        }
    }
}

pub(in crate::quic_listener) struct BootstrapTerminalResponse {
    pub(in crate::quic_listener) stage: BootstrapLifecycleStage,
    pub(in crate::quic_listener) outcome: BootstrapTerminalOutcome,
    pub(in crate::quic_listener) response: Response<BoxBody<Bytes, Infallible>>,
}

impl BootstrapTerminalResponse {
    pub(in crate::quic_listener) fn new(
        stage: BootstrapLifecycleStage,
        outcome: BootstrapTerminalOutcome,
        response: Response<BoxBody<Bytes, Infallible>>,
    ) -> Box<Self> {
        Box::new(Self {
            stage,
            outcome,
            response,
        })
    }

    /// Log the terminal state at the terminalization boundary, then return the
    /// response. Phase 11: the terminal outcome is now *observed* rather than a
    /// dead byproduct, so bootstrap terminalization is traceable the same way the
    /// QUIC data path's terminal states are.
    pub(in crate::quic_listener) fn into_observed_response(
        self,
        request_id: u64,
        terminal_outcome: &TerminalOutcomeGuard,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        if terminal_outcome.record() && !self.outcome.is_accepted() {
            log::debug!(
                "bootstrap request {} terminalized at stage={} outcome={}",
                request_id,
                self.stage.slug(),
                self.outcome.slug()
            );
        }
        self.response
    }
}

pub(in crate::quic_listener) type BootstrapTerminalResult<T> =
    Result<T, Box<BootstrapTerminalResponse>>;

pub(in crate::quic_listener) struct BootstrapPreparedRoute {
    pub(in crate::quic_listener) endpoint: BackendEndpoint,
    pub(in crate::quic_listener) backend_addr: String,
    pub(in crate::quic_listener) backend_index: usize,
    pub(in crate::quic_listener) upstream_name: String,
    pub(in crate::quic_listener) request_policy: ResolvedRequestPolicy,
    pub(in crate::quic_listener) upstream_pool: Arc<RwLock<UpstreamPool>>,
}

pub(in crate::quic_listener) struct BootstrapPolicyEvaluationInput<'a> {
    pub(in crate::quic_listener) intake: &'a BootstrapRequestIntake,
    pub(in crate::quic_listener) headers: &'a HeaderMap,
    pub(in crate::quic_listener) request_ctx: BootstrapRequestCtx<'a>,
}

pub(in crate::quic_listener) struct BootstrapBuildRequestInput<'a> {
    pub(in crate::quic_listener) request: Request<Incoming>,
    pub(in crate::quic_listener) intake: &'a BootstrapRequestIntake,
    pub(in crate::quic_listener) prepared_route: &'a BootstrapPreparedRoute,
    pub(in crate::quic_listener) request_ctx: BootstrapRequestCtx<'a>,
    pub(in crate::quic_listener) request_id: u64,
    pub(in crate::quic_listener) traceparent: Option<&'a str>,
    pub(in crate::quic_listener) request_header_mutations: Vec<PendingHeaderMutation>,
}

fn bootstrap_bridge_headers(headers: &HeaderMap) -> Vec<quiche::h3::Header> {
    headers
        .iter()
        .map(|(name, value)| quiche::h3::Header::new(name.as_str().as_bytes(), value.as_bytes()))
        .collect()
}

fn bootstrap_pending_forward(
    request: &Request<Incoming>,
    intake: &BootstrapRequestIntake,
    prepared_route: &BootstrapPreparedRoute,
    request_ctx: BootstrapRequestCtx<'_>,
    request_id: u64,
    traceparent: Option<&str>,
) -> Arc<PendingForward> {
    Arc::new(PendingForward {
        method: Arc::<str>::from(intake.method.as_str()),
        path: Arc::<str>::from(intake.path.as_str()),
        authority: intake.authority.as_deref().map(Arc::<str>::from),
        headers: Arc::new(bootstrap_bridge_headers(request.headers())),
        upstream_name: Arc::<str>::from(prepared_route.upstream_name.as_str()),
        route_reason: Arc::<str>::from("bootstrap"),
        route_path_len: intake.path.len(),
        route_host_specific: intake.authority.is_some(),
        backend_addr: Arc::<str>::from(prepared_route.backend_addr.as_str()),
        backend_index: prepared_route.backend_index,
        backend_lb: None,
        client_addr: request_ctx.peer,
        request_id,
        trace_id: None,
        span_id: None,
        traceparent: traceparent.map(Arc::<str>::from),
        host_policy: prepared_route.request_policy.host_policy.clone(),
        forwarded_header_policy: prepared_route
            .request_policy
            .forwarded_header_policy
            .clone(),
        auth_header_mutations: Vec::new(),
    })
}

fn bootstrap_external_auth_response(
    alt_svc: &str,
    decision: &ExternalAuthDecision,
) -> Response<BoxBody<Bytes, Infallible>> {
    let mut builder = Response::builder().header("alt-svc", alt_svc);
    match decision {
        ExternalAuthDecision::Allow {
            request_header_mutations: _,
        } => Response::new(boxed_full(Bytes::new())),
        ExternalAuthDecision::Deny(response) => {
            builder = builder.status(response.status);
            for (name, value) in &response.headers {
                builder = builder.header(name, value);
            }
            builder
                .body(boxed_full(Bytes::copy_from_slice(&response.body)))
                .unwrap_or_else(|_| Response::new(boxed_full(Bytes::from_static(b"error\n"))))
        }
        ExternalAuthDecision::Redirect(response) => {
            builder = builder.status(response.status);
            for (name, value) in &response.headers {
                builder = builder.header(name, value);
            }
            builder = builder.header("location", &response.location);
            builder
                .body(boxed_full(Bytes::new()))
                .unwrap_or_else(|_| Response::new(boxed_full(Bytes::from_static(b"error\n"))))
        }
        ExternalAuthDecision::Challenge(response) => {
            builder = builder.status(response.status);
            for (name, value) in &response.headers {
                builder = builder.header(name, value);
            }
            builder = builder.header("www-authenticate", &response.www_authenticate);
            builder
                .body(boxed_full(Bytes::copy_from_slice(&response.body)))
                .unwrap_or_else(|_| Response::new(boxed_full(Bytes::from_static(b"error\n"))))
        }
    }
}

pub(in crate::quic_listener) async fn evaluate_bootstrap_external_auth(
    request: &Request<Incoming>,
    intake: &BootstrapRequestIntake,
    prepared_route: &BootstrapPreparedRoute,
    request_ctx: BootstrapRequestCtx<'_>,
    request_id: u64,
    traceparent: Option<&str>,
) -> BootstrapTerminalResult<Vec<PendingHeaderMutation>> {
    let Some(external_auth) = prepared_route
        .request_policy
        .external_auth
        .as_ref()
        .map(|plan| plan.policy.clone())
    else {
        return Ok(Vec::new());
    };

    let pending_forward = bootstrap_pending_forward(
        request,
        intake,
        prepared_route,
        request_ctx,
        request_id,
        traceparent,
    );
    match evaluate_pending_forward_external_auth(pending_forward, external_auth).await {
        ExternalAuthStateTransition::Admitted {
            request_header_mutations,
        } => {
            request_ctx.runtime.metrics.inc_external_auth_allowed();
            Ok(request_header_mutations)
        }
        ExternalAuthStateTransition::RejectedAuthDenied { decision } => {
            request_ctx.runtime.metrics.inc_external_auth_denied();
            Err(BootstrapTerminalResponse::new(
                BootstrapLifecycleStage::AdmitOrReject,
                BootstrapTerminalOutcome::Rejected(BootstrapRejectionReason::AuthDenied),
                bootstrap_external_auth_response(&request_ctx.runtime.alt_svc, &decision),
            ))
        }
        ExternalAuthStateTransition::RejectedAuthUnavailable { status, body, .. } => {
            request_ctx.runtime.metrics.inc_external_auth_error();
            Err(BootstrapTerminalResponse::new(
                BootstrapLifecycleStage::AdmitOrReject,
                BootstrapTerminalOutcome::BackendFailed(
                    BootstrapBackendFailureReason::DispatchFailed,
                ),
                bootstrap_error_response(&request_ctx.runtime.alt_svc, status, body),
            ))
        }
        ExternalAuthStateTransition::TimedOutAuth { status, body } => {
            request_ctx.runtime.metrics.inc_external_auth_timeout();
            Err(BootstrapTerminalResponse::new(
                BootstrapLifecycleStage::AdmitOrReject,
                BootstrapTerminalOutcome::TimedOut(BootstrapTimeoutReason::Upstream),
                bootstrap_error_response(&request_ctx.runtime.alt_svc, status, body),
            ))
        }
    }
}

fn bootstrap_request_build_target<'a>(
    endpoint: &'a BackendEndpoint,
    request_policy: &'a ResolvedRequestPolicy,
) -> RequestBuildTarget<'a> {
    RequestBuildTarget {
        endpoint,
        policies: RequestBuildPolicies {
            host_policy: &request_policy.host_policy,
            forwarded_header_policy: &request_policy.forwarded_header_policy,
        },
    }
}

fn bootstrap_request_build_input<'a>(
    intake: &'a BootstrapRequestIntake,
    headers: &'a [quiche::h3::Header],
    body: BoxBody<Bytes, Infallible>,
    content_length: Option<usize>,
    request_ctx: BootstrapRequestCtx<'a>,
    request_id: u64,
    traceparent: Option<&'a str>,
) -> RequestBuildInput<'a, BoxBody<Bytes, Infallible>> {
    RequestBuildInput {
        method: &intake.method,
        path: &intake.path,
        authority: intake.authority.as_deref(),
        headers,
        auth_header_mutations: &[],
        body,
        body_mode: RequestBuildInput::<BoxBody<Bytes, Infallible>>::body_mode_for_length(
            content_length,
        ),
        trace: RequestTraceContext {
            request_id,
            traceparent,
        },
        forwarded: RequestForwardedContext {
            client_addr: request_ctx.peer,
        },
    }
}

fn internal_proxy_error_response(alt_svc: &str) -> Response<BoxBody<Bytes, Infallible>> {
    bootstrap_error_response(
        alt_svc,
        StatusCode::INTERNAL_SERVER_ERROR,
        b"internal proxy error\n",
    )
}

pub(in crate::quic_listener) fn evaluate_bootstrap_request_policy(
    input: BootstrapPolicyEvaluationInput<'_>,
) -> BootstrapTerminalResult<BootstrapPreparedRoute> {
    let lb_header_lookup = |name: &str| {
        input
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    };

    let resolved = match QUICListener::resolve_bootstrap_target(BootstrapTargetResolutionInput {
        request: TargetResolutionRequest::new(
            &input.intake.method,
            &input.intake.path,
            input.intake.authority.as_deref(),
            None,
            Some(&lb_header_lookup),
        ),
        context: ResolutionContext::new(
            &input.request_ctx.runtime.routing_index,
            &input.request_ctx.runtime.upstream_pools,
            &input.request_ctx.runtime.upstream_policies,
        ),
        observation: ResolutionObservation::new(
            input.request_ctx.runtime.metrics.as_ref(),
            Duration::ZERO,
        ),
    }) {
        Ok(value) => value,
        Err(err) => {
            let (status, body) = QUICListener::bootstrap_route_resolution_error_response(&err);
            return Err(BootstrapTerminalResponse::new(
                BootstrapLifecycleStage::ResolveRoute,
                BootstrapTerminalOutcome::BackendFailed(
                    BootstrapBackendFailureReason::RouteResolutionFailed,
                ),
                bootstrap_error_response(&input.request_ctx.runtime.alt_svc, status, body),
            ));
        }
    };

    let pipeline_evaluation = evaluate_pipeline(
        &input.request_ctx.runtime.resilience,
        PipelineRoute::new(&resolved.upstream_name, &resolved.upstream_policy),
        PipelineRequest {
            method: input.intake.method.as_ref(),
            path: &input.intake.path,
            authority: input.intake.authority.as_deref(),
            peer_address: input.request_ctx.peer,
            headers: Some(&lb_header_lookup),
            runtime_generation: input.request_ctx.runtime.runtime_generation,
            terminal_outcome: input.request_ctx.terminal_outcome.clone(),
        },
    );
    let admission = pipeline_evaluation.admission;
    input
        .request_ctx
        .runtime
        .metrics
        .set_brownout_active(input.request_ctx.runtime.resilience.brownout.is_active());
    let rejection_response = admission_rejection_response(&admission);

    match admission {
        AdmissionPolicyDecision::AdmitReady => {}
        AdmissionPolicyDecision::Unauthorized(_) => {
            input.request_ctx.runtime.metrics.inc_policy_denied();
            observe_bootstrap_admission_outcome(
                input.request_ctx.runtime.metrics.as_ref(),
                &resolved.upstream_name,
                &resolved.backend_addr,
                resolved.backend_index,
                input.request_ctx.request_start,
                StatusCode::UNAUTHORIZED,
                AdmissionOutcomeClass::AuthDenied,
            );
            warn!(
                "admission denied: upstream={} reason=auth_denied",
                resolved.upstream_name
            );
            let Some(response) = rejection_response.as_ref() else {
                warn!(
                    "admission rejection response missing: upstream={} reason=auth_denied",
                    resolved.upstream_name
                );
                return Err(BootstrapTerminalResponse::new(
                    BootstrapLifecycleStage::AdmitOrReject,
                    BootstrapTerminalOutcome::Rejected(BootstrapRejectionReason::AuthDenied),
                    internal_proxy_error_response(&input.request_ctx.runtime.alt_svc),
                ));
            };
            let Some(challenge) = response.www_authenticate else {
                warn!(
                    "admission rejection response missing: upstream={} reason=auth_denied detail=missing_auth_challenge",
                    resolved.upstream_name
                );
                return Err(BootstrapTerminalResponse::new(
                    BootstrapLifecycleStage::AdmitOrReject,
                    BootstrapTerminalOutcome::Rejected(BootstrapRejectionReason::AuthDenied),
                    internal_proxy_error_response(&input.request_ctx.runtime.alt_svc),
                ));
            };
            return Err(BootstrapTerminalResponse::new(
                BootstrapLifecycleStage::AdmitOrReject,
                BootstrapTerminalOutcome::Rejected(BootstrapRejectionReason::AuthDenied),
                Response::builder()
                    .status(response.status)
                    .header("alt-svc", &input.request_ctx.runtime.alt_svc)
                    .header("www-authenticate", challenge)
                    .body(boxed_full(Bytes::from_static(response.body)))
                    .unwrap_or_else(|_| Response::new(boxed_full(Bytes::from_static(b"error\n")))),
            ));
        }
        AdmissionPolicyDecision::RateLimited(decision) => {
            input.request_ctx.runtime.metrics.inc_request_rate_limited();
            observe_bootstrap_admission_outcome(
                input.request_ctx.runtime.metrics.as_ref(),
                &resolved.upstream_name,
                &resolved.backend_addr,
                resolved.backend_index,
                input.request_ctx.request_start,
                StatusCode::TOO_MANY_REQUESTS,
                AdmissionOutcomeClass::RateLimited,
            );
            warn!(
                "admission denied: upstream={} reason=rate_limited rule={}",
                decision.route, decision.rule_name
            );
            let Some(response) = rejection_response.as_ref() else {
                warn!(
                    "admission rejection response missing: upstream={} reason=rate_limited",
                    resolved.upstream_name
                );
                return Err(BootstrapTerminalResponse::new(
                    BootstrapLifecycleStage::AdmitOrReject,
                    BootstrapTerminalOutcome::Rejected(BootstrapRejectionReason::RateLimited),
                    internal_proxy_error_response(&input.request_ctx.runtime.alt_svc),
                ));
            };
            let Some(retry_after_seconds) = response.retry_after_seconds else {
                warn!(
                    "admission rejection response missing: upstream={} reason=rate_limited detail=missing_retry_after",
                    resolved.upstream_name
                );
                return Err(BootstrapTerminalResponse::new(
                    BootstrapLifecycleStage::AdmitOrReject,
                    BootstrapTerminalOutcome::Rejected(BootstrapRejectionReason::RateLimited),
                    internal_proxy_error_response(&input.request_ctx.runtime.alt_svc),
                ));
            };
            return Err(BootstrapTerminalResponse::new(
                BootstrapLifecycleStage::AdmitOrReject,
                BootstrapTerminalOutcome::Rejected(BootstrapRejectionReason::RateLimited),
                Response::builder()
                    .status(response.status)
                    .header("alt-svc", &input.request_ctx.runtime.alt_svc)
                    .header("retry-after", retry_after_seconds.to_string())
                    .body(boxed_full(Bytes::from_static(response.body)))
                    .unwrap_or_else(|_| Response::new(boxed_full(Bytes::from_static(b"error\n")))),
            ));
        }
        AdmissionPolicyDecision::Overloaded(decision) => {
            observe_bootstrap_admission_outcome(
                input.request_ctx.runtime.metrics.as_ref(),
                &resolved.upstream_name,
                &resolved.backend_addr,
                resolved.backend_index,
                input.request_ctx.request_start,
                StatusCode::SERVICE_UNAVAILABLE,
                AdmissionOutcomeClass::OverloadShed {
                    reason: Some(decision.reason.metrics_reason()),
                },
            );
            input
                .request_ctx
                .runtime
                .resilience
                .adaptive_admission
                .observe(input.request_ctx.request_start.elapsed(), true);
            let Some(response) = rejection_response.as_ref() else {
                warn!(
                    "admission rejection response missing: upstream={} reason=overloaded",
                    resolved.upstream_name
                );
                return Err(BootstrapTerminalResponse::new(
                    BootstrapLifecycleStage::AdmitOrReject,
                    BootstrapTerminalOutcome::Rejected(BootstrapRejectionReason::Overloaded),
                    internal_proxy_error_response(&input.request_ctx.runtime.alt_svc),
                ));
            };
            let Some(retry_after_seconds) = response.retry_after_seconds else {
                warn!(
                    "admission rejection response missing: upstream={} reason=overloaded detail=missing_retry_after",
                    resolved.upstream_name
                );
                return Err(BootstrapTerminalResponse::new(
                    BootstrapLifecycleStage::AdmitOrReject,
                    BootstrapTerminalOutcome::Rejected(BootstrapRejectionReason::Overloaded),
                    internal_proxy_error_response(&input.request_ctx.runtime.alt_svc),
                ));
            };
            return Err(BootstrapTerminalResponse::new(
                BootstrapLifecycleStage::AdmitOrReject,
                BootstrapTerminalOutcome::Rejected(BootstrapRejectionReason::Overloaded),
                Response::builder()
                    .status(response.status)
                    .header("alt-svc", &input.request_ctx.runtime.alt_svc)
                    .header("retry-after", retry_after_seconds.to_string())
                    .body(boxed_full(Bytes::from_static(response.body)))
                    .unwrap_or_else(|_| Response::new(boxed_full(Bytes::from_static(b"error\n")))),
            ));
        }
    }

    let endpoint = match input
        .request_ctx
        .runtime
        .backend_endpoints
        .get(&resolved.backend_addr)
    {
        Some(endpoint) => endpoint.clone(),
        None => {
            observe_bootstrap_request_proxy_error(
                input.request_ctx.runtime.metrics.as_ref(),
                &resolved.upstream_name,
                &resolved.backend_addr,
                resolved.backend_index,
                input.request_ctx.request_start,
                StatusCode::BAD_GATEWAY,
                &ProxyError::Transport("no endpoint".into()),
            );
            return Err(BootstrapTerminalResponse::new(
                BootstrapLifecycleStage::ResolveRoute,
                BootstrapTerminalOutcome::BackendFailed(
                    BootstrapBackendFailureReason::MissingEndpoint,
                ),
                bootstrap_error_response(
                    &input.request_ctx.runtime.alt_svc,
                    StatusCode::BAD_GATEWAY,
                    b"no endpoint\n",
                ),
            ));
        }
    };

    Ok(BootstrapPreparedRoute {
        endpoint,
        backend_addr: resolved.backend_addr,
        backend_index: resolved.backend_index,
        upstream_name: resolved.upstream_name,
        request_policy: pipeline_evaluation.policy,
        upstream_pool: resolved.upstream_pool,
    })
}

pub(in crate::quic_listener) fn build_bootstrap_upstream_request(
    input: BootstrapBuildRequestInput<'_>,
) -> Result<Request<BoxBody<Bytes, Infallible>>, BridgeError> {
    let mut bridge_headers = bootstrap_bridge_headers(input.request.headers());
    apply_auth_request_mutations(&mut bridge_headers, &input.request_header_mutations);
    let request_target = bootstrap_request_build_target(
        &input.prepared_route.endpoint,
        &input.prepared_route.request_policy,
    );

    if input.intake.request_mode.is_websocket_upgrade() {
        return build_h1_request(
            request_target,
            bootstrap_request_build_input(
                input.intake,
                &bridge_headers,
                boxed_full(Bytes::new()),
                None,
                input.request_ctx,
                input.request_id,
                input.traceparent,
            ),
        );
    }

    let bridge_body = BootstrapStreamingBody::new(input.request.into_body())
        .map_err(|never| match never {})
        .boxed();
    if input.prepared_route.endpoint.scheme() == BackendScheme::Http {
        build_h1_request(
            request_target,
            bootstrap_request_build_input(
                input.intake,
                &bridge_headers,
                bridge_body,
                None,
                input.request_ctx,
                input.request_id,
                input.traceparent,
            ),
        )
    } else {
        build_h2_request_for_target(
            request_target,
            bootstrap_request_build_input(
                input.intake,
                &bridge_headers,
                bridge_body,
                None,
                input.request_ctx,
                input.request_id,
                input.traceparent,
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use impulse_config::{
        config::{ForwardedHeaderPolicy, ForwardedHeaderPolicyMode},
        runtime::{RuntimeAuthPolicy, RuntimeForwardedHeaderPolicy, RuntimeHostPolicy},
    };
    use quiche::h3::NameValue;

    use super::*;
    use crate::{request_pipeline::resolve_policy, runtime::connection::request::PendingForward};

    #[test]
    fn terminal_outcome_accepted_classification() {
        assert!(BootstrapTerminalOutcome::AcceptedStandardResponse.is_accepted());
        assert!(BootstrapTerminalOutcome::AcceptedWebsocketUpgrade.is_accepted());
        assert!(
            !BootstrapTerminalOutcome::Rejected(BootstrapRejectionReason::AuthDenied).is_accepted()
        );
        assert!(
            !BootstrapTerminalOutcome::BackendFailed(BootstrapBackendFailureReason::DispatchFailed)
                .is_accepted()
        );
        assert!(
            !BootstrapTerminalOutcome::TimedOut(BootstrapTimeoutReason::Upstream).is_accepted()
        );
    }

    #[test]
    fn terminal_outcome_slugs_are_distinct_and_stable() {
        let outcomes = [
            BootstrapTerminalOutcome::AcceptedStandardResponse,
            BootstrapTerminalOutcome::AcceptedWebsocketUpgrade,
            BootstrapTerminalOutcome::Rejected(BootstrapRejectionReason::ValidationFailed),
            BootstrapTerminalOutcome::Rejected(BootstrapRejectionReason::AuthDenied),
            BootstrapTerminalOutcome::Rejected(BootstrapRejectionReason::RateLimited),
            BootstrapTerminalOutcome::Rejected(BootstrapRejectionReason::Overloaded),
            BootstrapTerminalOutcome::Rejected(BootstrapRejectionReason::RequestBodyTooLarge),
            BootstrapTerminalOutcome::BackendFailed(
                BootstrapBackendFailureReason::RouteResolutionFailed,
            ),
            BootstrapTerminalOutcome::BackendFailed(BootstrapBackendFailureReason::MissingEndpoint),
            BootstrapTerminalOutcome::BackendFailed(
                BootstrapBackendFailureReason::RequestBuildFailed,
            ),
            BootstrapTerminalOutcome::BackendFailed(BootstrapBackendFailureReason::DispatchFailed),
            BootstrapTerminalOutcome::TimedOut(BootstrapTimeoutReason::Upstream),
        ];
        let mut slugs: Vec<&str> = outcomes.iter().map(|o| o.slug()).collect();
        let count = slugs.len();
        slugs.sort_unstable();
        slugs.dedup();
        assert_eq!(slugs.len(), count, "terminal outcome slugs must be unique");
        // Accepted outcomes carry accepted-prefixed slugs; everything else names its failure class.
        assert_eq!(
            BootstrapTerminalOutcome::TimedOut(BootstrapTimeoutReason::Upstream).slug(),
            "timed_out_upstream"
        );
    }

    #[test]
    fn websocket_upgrade_is_a_request_mode_state() {
        assert!(BootstrapRequestMode::WebsocketUpgrade.is_websocket_upgrade());
        assert!(!BootstrapRequestMode::Standard.is_websocket_upgrade());
    }

    #[test]
    fn bootstrap_and_quic_terminals_resolve_to_same_canonical_reason() {
        // obs Phase 10 (step 1): equivalent outcomes on the bootstrap and QUIC
        // data planes must report the SAME canonical reason — closing Phase 0
        // finding #1 (two parallel terminal vocabularies).
        use crate::{
            observability::RequestOutcomeReason,
            runtime::connection::stream::{BackendFailureReason, RejectionReason},
        };

        // Auth denied.
        assert_eq!(
            BootstrapTerminalOutcome::Rejected(BootstrapRejectionReason::AuthDenied)
                .canonical_reason(),
            Some(RequestOutcomeReason::from(RejectionReason::AuthDenied))
        );
        // Rate limited.
        assert_eq!(
            BootstrapTerminalOutcome::Rejected(BootstrapRejectionReason::RateLimited)
                .canonical_reason(),
            Some(RequestOutcomeReason::from(RejectionReason::RateLimited))
        );
        // Overloaded.
        assert_eq!(
            BootstrapTerminalOutcome::Rejected(BootstrapRejectionReason::Overloaded)
                .canonical_reason(),
            Some(RequestOutcomeReason::from(RejectionReason::Overloaded))
        );
        // Validation.
        assert_eq!(
            BootstrapTerminalOutcome::Rejected(BootstrapRejectionReason::ValidationFailed)
                .canonical_reason(),
            Some(RequestOutcomeReason::from(
                RejectionReason::ValidationFailed
            ))
        );
        // Backend dispatch failure ↔ QUIC transport failure.
        assert_eq!(
            BootstrapTerminalOutcome::BackendFailed(BootstrapBackendFailureReason::DispatchFailed)
                .canonical_reason(),
            Some(RequestOutcomeReason::from(
                BackendFailureReason::UpstreamTransport
            ))
        );
        // Upstream timeout.
        assert_eq!(
            BootstrapTerminalOutcome::TimedOut(BootstrapTimeoutReason::Upstream).canonical_reason(),
            Some(RequestOutcomeReason::from(
                BackendFailureReason::UpstreamTimeout
            ))
        );
        // Accepted outcomes carry no failure reason on either plane.
        assert_eq!(
            BootstrapTerminalOutcome::AcceptedStandardResponse.canonical_reason(),
            None
        );
    }

    fn sample_bootstrap_policy() -> RuntimeUpstreamPolicy {
        RuntimeUpstreamPolicy {
            upstream_auth: RuntimeAuthPolicy::default(),
            host: RuntimeHostPolicy::default(),
            forwarded_headers: RuntimeForwardedHeaderPolicy(ForwardedHeaderPolicy {
                mode: ForwardedHeaderPolicyMode::Append,
            }),
            protocol: Default::default(),
        }
    }

    fn canonical_headers(
        request: &Request<BoxBody<Bytes, Infallible>>,
    ) -> BTreeMap<String, Vec<String>> {
        let mut map = BTreeMap::<String, Vec<String>>::new();
        for (name, value) in request.headers() {
            map.entry(name.as_str().to_string())
                .or_default()
                .push(value.to_str().expect("header value").to_string());
        }
        map
    }

    #[test]
    fn bootstrap_and_quic_request_builders_emit_same_standard_request_shape() {
        let endpoint = BackendEndpoint::parse("backend.internal:443").expect("endpoint");
        let policy = sample_bootstrap_policy();
        let request_policy = resolve_policy(&policy);
        let logical_headers = vec![
            quiche::h3::Header::new(b"forwarded", b"for=1.2.3.4;proto=http;host=\"old.example\""),
            quiche::h3::Header::new(b"x-forwarded-for", b"1.2.3.4"),
            quiche::h3::Header::new(b"x-forwarded-proto", b"http"),
            quiche::h3::Header::new(b"x-forwarded-host", b"old.example"),
            quiche::h3::Header::new(b"authorization", b"Bearer upstream-token"),
            quiche::h3::Header::new(b"x-api-key", b"route-secret"),
        ];

        let pending_forward = PendingForward {
            request_id: 41,
            traceparent: Some(Arc::<str>::from(
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00",
            )),
            forwarded_header_policy: ForwardedHeaderPolicy {
                mode: ForwardedHeaderPolicyMode::Append,
            },
            ..PendingForward::sample_for_test(logical_headers.clone())
        };
        let quic_headers = pending_forward.headers.as_ref().clone();
        let quic_request = build_h2_request_for_target(
            RequestBuildTarget {
                endpoint: &endpoint,
                policies: RequestBuildPolicies {
                    host_policy: &pending_forward.host_policy,
                    forwarded_header_policy: &pending_forward.forwarded_header_policy,
                },
            },
            RequestBuildInput {
                method: &pending_forward.method,
                path: &pending_forward.path,
                authority: pending_forward.authority.as_deref(),
                headers: &quic_headers,
                auth_header_mutations: &[],
                body: boxed_full(Bytes::new()),
                body_mode: RequestBuildInput::<BoxBody<Bytes, Infallible>>::body_mode_for_length(
                    Some(0),
                ),
                trace: RequestTraceContext {
                    request_id: pending_forward.request_id,
                    traceparent: pending_forward.traceparent.as_deref(),
                },
                forwarded: RequestForwardedContext {
                    client_addr: pending_forward.client_addr,
                },
            },
        )
        .expect("quic request");

        let mut bootstrap_headers = HeaderMap::new();
        for header in &logical_headers {
            let name = http::header::HeaderName::from_bytes(header.name()).expect("header name");
            let value =
                http::header::HeaderValue::from_bytes(header.value()).expect("header value");
            bootstrap_headers.append(name, value);
        }
        let bridge_headers = bootstrap_bridge_headers(&bootstrap_headers);
        let intake = crate::quic_listener::bootstrap::intake::BootstrapRequestIntake {
            method: "GET".to_string(),
            path: "/v1/chat".to_string(),
            authority: Some("api.example.com".to_string()),
            content_length: Some(0),
            suppress_downstream_body: false,
            request_mode: BootstrapRequestMode::Standard,
            client_upgrade: None,
        };
        let bootstrap_request = build_h2_request_for_target(
            bootstrap_request_build_target(&endpoint, &request_policy),
            RequestBuildInput {
                method: &intake.method,
                path: &intake.path,
                authority: intake.authority.as_deref(),
                headers: &bridge_headers,
                auth_header_mutations: &[],
                body: boxed_full(Bytes::new()),
                body_mode: RequestBuildInput::<BoxBody<Bytes, Infallible>>::body_mode_for_length(
                    intake.content_length,
                ),
                trace: RequestTraceContext {
                    request_id: 41,
                    traceparent: Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"),
                },
                forwarded: RequestForwardedContext {
                    client_addr: "203.0.113.55:43210".parse().expect("client addr"),
                },
            },
        )
        .expect("bootstrap request");

        assert_eq!(quic_request.method(), bootstrap_request.method());
        assert_eq!(quic_request.uri(), bootstrap_request.uri());
        assert_eq!(
            canonical_headers(&quic_request),
            canonical_headers(&bootstrap_request)
        );
    }

    #[test]
    fn bootstrap_target_uses_same_forwarded_and_auth_header_contract_as_quic() {
        let endpoint = BackendEndpoint::parse("backend.internal:443").expect("endpoint");
        let policy = sample_bootstrap_policy();
        let request_policy = resolve_policy(&policy);
        let mut bootstrap_headers = HeaderMap::new();
        bootstrap_headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer upstream-token"),
        );
        bootstrap_headers.insert("x-api-key", http::HeaderValue::from_static("route-secret"));
        bootstrap_headers.insert(
            "forwarded",
            http::HeaderValue::from_static("for=1.2.3.4;proto=http;host=\"old.example\""),
        );

        let bridge_headers = bootstrap_bridge_headers(&bootstrap_headers);
        let request = build_h2_request_for_target(
            bootstrap_request_build_target(&endpoint, &request_policy),
            RequestBuildInput {
                method: "GET",
                path: "/v1/chat",
                authority: Some("api.example.com"),
                headers: &bridge_headers,
                auth_header_mutations: &[],
                body: boxed_full(Bytes::new()),
                body_mode: RequestBuildInput::<BoxBody<Bytes, Infallible>>::body_mode_for_length(
                    Some(0),
                ),
                trace: RequestTraceContext {
                    request_id: 99,
                    traceparent: None,
                },
                forwarded: RequestForwardedContext {
                    client_addr: "203.0.113.55:43210".parse().expect("client addr"),
                },
            },
        )
        .expect("bootstrap request");

        assert_eq!(
            request
                .headers()
                .get(http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer upstream-token")
        );
        assert_eq!(
            request
                .headers()
                .get("x-api-key")
                .and_then(|value| value.to_str().ok()),
            Some("route-secret")
        );
        assert_eq!(
            request
                .headers()
                .get("forwarded")
                .and_then(|value| value.to_str().ok()),
            Some(
                "for=1.2.3.4;proto=http;host=\"old.example\", for=203.0.113.55;proto=https;host=\"api.example.com\""
            )
        );
    }
}
