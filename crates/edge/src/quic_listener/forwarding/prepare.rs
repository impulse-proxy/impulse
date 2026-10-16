use std::{borrow::Cow, collections::VecDeque, convert::Infallible};

use http_body_util::Full;
use impulse_config::runtime::RuntimeExternalAuth;
use smallvec::SmallVec;
use tokio::{sync::oneshot, task::AbortHandle};

use super::{
    auth::start_external_auth_task,
    pipeline::{ForwardingRequestPipeline, PipelineResolution},
    resolve::{
        ForwardTargetResolution, ForwardTargetResolutionInput, ResolutionContext,
        ResolutionObservation, TargetResolutionRequest,
    },
    *,
};
use crate::{
    quic_listener::admission::{
        AdmissionPolicyDecision, AdmissionRejectionResponse, admission_rejection_response,
    },
    request_pipeline::PipelineRequest,
    runtime::connection::{
        auth::{
            ExternalAuthCompletion, ExternalAuthFailureDisposition, ExternalAuthResult,
            PendingHeaderMutation, apply_auth_request_mutations, evaluate_external_auth_completion,
        },
        outcome::{
            AdmissionOutcomeClass, BackendOutcomeTarget, RouteOutcomeTarget,
            observe_admission_outcome,
        },
        request::{PendingForward, RequestEnvelope},
        stream::{
            AwaitingAuthState, DispatchReadyState, RequestBodyRuntime, RequestContext,
            RequestIntakeState, RequestMode, RoutingSnapshot,
        },
    },
};

pub(super) struct IntakeRequestCandidate {
    pub(super) state: RequestIntakeState,
}

impl IntakeRequestCandidate {
    fn request_id(&self) -> u64 {
        self.state.context.request_id
    }
}

pub(super) struct DispatchReadyCandidate {
    pub(super) state: DispatchReadyState,
    pub(super) routing: RoutingSnapshot,
    pub(super) upstream_pool: Arc<RwLock<UpstreamPool>>,
}

impl DispatchReadyCandidate {
    fn request_id(&self) -> u64 {
        self.state.context.request_id
    }

    fn upstream_name(&self) -> &str {
        &self.routing.upstream_name
    }

    fn backend_addr(&self) -> &str {
        &self.routing.backend_addr
    }

    fn backend_index(&self) -> usize {
        self.routing.backend_index
    }

    fn into_dispatch_ready_envelope(
        self,
        routing_transparency_enabled: bool,
        routing_transparency_include_reason: bool,
    ) -> RequestEnvelope {
        RequestEnvelope::from_dispatch_ready_state(
            self.state,
            self.upstream_pool,
            routing_transparency_enabled,
            routing_transparency_include_reason,
            0,
            None,
        )
    }

    fn into_awaiting_auth_envelope(
        self,
        routing_transparency_enabled: bool,
        routing_transparency_include_reason: bool,
        auth_result_rx: oneshot::Receiver<ExternalAuthResult>,
        auth_abort: AbortHandle,
        auth_disposition: ExternalAuthFailureDisposition,
        auth_deadline: Instant,
    ) -> RequestEnvelope {
        let DispatchReadyState {
            context,
            routing,
            request_mode,
            request_body,
            request_body_runtime,
            pending_forward,
        } = self.state;

        RequestEnvelope::from_awaiting_auth_state(
            AwaitingAuthState {
                context,
                routing,
                request_mode,
                request_body,
                request_body_runtime,
                pending_forward,
                auth_result_rx,
                auth_abort,
                auth_deadline,
                auth_disposition,
            },
            self.upstream_pool,
            routing_transparency_enabled,
            routing_transparency_include_reason,
            0,
            None,
        )
    }
}

pub(super) struct ExternalAuthCandidate {
    pub(super) request: DispatchReadyCandidate,
    pub(super) external_auth: RuntimeExternalAuth,
    pub(super) auth_disposition: ExternalAuthFailureDisposition,
}

pub(super) struct LocalRejectionCandidate {
    pub(super) response: AdmissionRejectionResponse,
}

pub(super) enum PreAdmissionNextState {
    LocallyRejected(LocalRejectionCandidate),
    RequiresExternalAuth(Box<ExternalAuthCandidate>),
    ReadyForPostAuthAdmission(Box<DispatchReadyCandidate>),
}

pub(super) struct StartedRequestEnvelope {
    pub(super) envelope: RequestEnvelope,
    pub(super) should_materialize_forward: bool,
}

/// The parsed HTTP request-line/header inputs needed to build a request intake.
pub(super) struct IntakeRequestDescriptor<'a> {
    pub(super) quic_trace_id: &'a str,
    pub(super) request_start: Instant,
    pub(super) method: &'a str,
    pub(super) path: &'a str,
    pub(super) authority: Option<&'a str>,
    pub(super) headers: &'a [quiche::h3::Header],
    pub(super) content_length: Option<usize>,
    pub(super) tunnel_mode: TunnelMode,
    pub(super) tracing_enabled: bool,
}

pub(super) struct RequestRoutingInput<'a> {
    pub(super) peer_address: SocketAddr,
    pub(super) sticky_cid_key: &'a str,
    pub(super) intake: IntakeRequestDescriptor<'a>,
}

/// Request-scoped configuration applied when finalizing the request envelope.
pub(super) struct RequestFinalizationConfig {
    pub(super) routing_transparency_enabled: bool,
    pub(super) routing_transparency_include_reason: bool,
    pub(super) backend_total_request_timeout: Duration,
}

impl PendingForward {
    pub(super) fn original_request_headers(&self) -> &[quiche::h3::Header] {
        self.headers.as_ref()
    }

    fn request_headers_cow(&self) -> Cow<'_, [quiche::h3::Header]> {
        if self.auth_header_mutations.is_empty() {
            return Cow::Borrowed(self.original_request_headers());
        }

        let mut headers = self.original_request_headers().to_vec();
        apply_auth_request_mutations(&mut headers, &self.auth_header_mutations);
        Cow::Owned(headers)
    }

    pub(super) fn request_headers_read_only(&self) -> Cow<'_, [quiche::h3::Header]> {
        self.request_headers_cow()
    }

    fn request_headers_for_http1_websocket_tunnel(&self) -> Cow<'_, [quiche::h3::Header]> {
        let request_headers = self.request_headers_cow();
        let has_upgrade = request_headers
            .iter()
            .any(|header| header.name().eq_ignore_ascii_case(b"upgrade"));
        let has_connection = request_headers
            .iter()
            .any(|header| header.name().eq_ignore_ascii_case(b"connection"));
        if has_upgrade && has_connection {
            return request_headers;
        }

        let mut request_headers = request_headers.into_owned();
        if !has_upgrade {
            request_headers.push(quiche::h3::Header::new(b"upgrade", b"websocket"));
        }
        if !has_connection {
            request_headers.push(quiche::h3::Header::new(b"connection", b"upgrade"));
        }
        Cow::Owned(request_headers)
    }

    #[cfg(test)]
    pub(super) fn owned_request_headers(&self) -> Vec<quiche::h3::Header> {
        self.request_headers_cow().into_owned()
    }

    fn request_build_target<'a>(
        &'a self,
        endpoint: &'a BackendEndpoint,
    ) -> impulse_bridge::request::RequestBuildTarget<'a> {
        impulse_bridge::request::RequestBuildTarget {
            endpoint,
            policies: impulse_bridge::request::RequestBuildPolicies {
                host_policy: &self.host_policy,
                forwarded_header_policy: &self.forwarded_header_policy,
            },
        }
    }

    fn request_build_input<'a>(
        &'a self,
        method: &'a str,
        headers: &'a [quiche::h3::Header],
        auth_header_mutations: &'a [impulse_bridge::request::RequestHeaderMutationRef<'a>],
        body: BoxBody<Bytes, Infallible>,
        content_length: Option<usize>,
    ) -> impulse_bridge::request::RequestBuildInput<'a, BoxBody<Bytes, Infallible>> {
        impulse_bridge::request::RequestBuildInput {
            method,
            path: &self.path,
            authority: self.authority.as_deref(),
            headers,
            auth_header_mutations,
            body,
            body_mode:
                impulse_bridge::request::RequestBuildInput::<BoxBody<Bytes, Infallible>>::body_mode_for_length(content_length),
            trace: impulse_bridge::request::RequestTraceContext {
                request_id: self.request_id,
                traceparent: self.traceparent.as_deref(),
            },
            forwarded: impulse_bridge::request::RequestForwardedContext {
                client_addr: self.client_addr,
            },
        }
    }

    fn request_header_mutation_refs(
        &self,
    ) -> SmallVec<[impulse_bridge::request::RequestHeaderMutationRef<'_>; 8]> {
        self.auth_header_mutations
            .iter()
            .map(|mutation| match mutation {
                PendingHeaderMutation::Upsert { name, value } => {
                    impulse_bridge::request::RequestHeaderMutationRef {
                        name: name.as_slice(),
                        value: Some(value.as_slice()),
                    }
                }
                PendingHeaderMutation::Remove { name } => {
                    impulse_bridge::request::RequestHeaderMutationRef {
                        name: name.as_slice(),
                        value: None,
                    }
                }
            })
            .collect()
    }

    pub(super) fn build_request(
        &self,
        endpoint: &BackendEndpoint,
        body: BoxBody<Bytes, Infallible>,
        content_length: Option<usize>,
    ) -> Result<Request<BoxBody<Bytes, Infallible>>, ProxyError> {
        let auth_header_mutations = self.request_header_mutation_refs();
        if endpoint.scheme() == BackendScheme::Http {
            impulse_bridge::request::build_h1_request(
                self.request_build_target(endpoint),
                self.request_build_input(
                    &self.method,
                    self.original_request_headers(),
                    auth_header_mutations.as_slice(),
                    body,
                    content_length,
                ),
            )
            .map_err(ProxyError::from)
        } else {
            impulse_bridge::request::build_h2_request_for_target(
                self.request_build_target(endpoint),
                self.request_build_input(
                    &self.method,
                    self.original_request_headers(),
                    auth_header_mutations.as_slice(),
                    body,
                    content_length,
                ),
            )
            .map_err(ProxyError::from)
        }
    }

    pub(super) fn build_bodyless_request(
        &self,
        endpoint: &BackendEndpoint,
    ) -> Result<Request<BoxBody<Bytes, Infallible>>, ProxyError> {
        self.build_request(endpoint, BoxBody::new(Full::new(Bytes::new())), Some(0))
    }

    pub(super) fn build_http1_websocket_tunnel_request(
        &self,
        endpoint: &BackendEndpoint,
    ) -> Result<Request<BoxBody<Bytes, Infallible>>, ProxyError> {
        let request_headers = self.request_headers_for_http1_websocket_tunnel();

        impulse_bridge::request::build_h1_request(
            self.request_build_target(endpoint),
            self.request_build_input(
                "GET",
                request_headers.as_ref(),
                &[],
                BoxBody::new(Full::new(Bytes::new())),
                None,
            ),
        )
        .map_err(ProxyError::from)
    }
}

impl QUICListener {
    fn build_request_intake(descriptor: IntakeRequestDescriptor<'_>) -> IntakeRequestCandidate {
        let IntakeRequestDescriptor {
            quic_trace_id,
            request_start,
            method,
            path,
            authority,
            headers,
            content_length,
            tunnel_mode,
            tracing_enabled,
        } = descriptor;
        let request_id = REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        let request_mode = RequestMode::from_intake(tunnel_mode, method, content_length);
        let incoming_traceparent =
            extract_header_value(headers, b"traceparent").and_then(parse_traceparent);
        let trace_id = incoming_traceparent
            .as_ref()
            .map(|(trace_id, _)| trace_id.clone())
            .or_else(|| tracing_enabled.then(|| generated_trace_id(quic_trace_id, request_id)));
        let span_id = trace_id.as_ref().map(|_| generated_span_id(request_id));
        let traceparent = trace_id
            .as_ref()
            .zip(span_id.as_ref())
            .map(|(trace_id, span_id)| format!("00-{trace_id}-{span_id}-01"));
        let trace_span = trace_id
            .as_ref()
            .zip(span_id.as_ref())
            .map(|(trace_id, span_id)| {
                info_span!(
                    "impulse.request",
                    request_id = request_id,
                    trace_id = %trace_id,
                    span_id = %span_id,
                    method = %method,
                    path = %path
                )
            });

        IntakeRequestCandidate {
            state: RequestIntakeState {
                context: RequestContext {
                    request_id,
                    trace_id,
                    span_id,
                    traceparent,
                    trace_span,
                    method: method.to_string(),
                    path: path.to_string(),
                    authority: authority.map(str::to_string),
                    start: request_start,
                    total_request_deadline: request_start,
                },
                request_mode,
                request_body: request_mode.initial_body_state(),
            },
        }
    }

    fn build_dispatch_ready_candidate(
        intake: IntakeRequestCandidate,
        routing: RoutingSnapshot,
        upstream_pool: Arc<RwLock<UpstreamPool>>,
        pending_forward: Arc<PendingForward>,
    ) -> DispatchReadyCandidate {
        let RequestIntakeState {
            context,
            request_mode,
            request_body,
        } = intake.state;
        let last_body_activity = context.start;
        DispatchReadyCandidate {
            state: DispatchReadyState {
                context,
                routing: routing.clone(),
                request_mode,
                request_body,
                request_body_runtime: RequestBodyRuntime {
                    body_buf: VecDeque::new(),
                    body_buf_bytes: 0,
                    body_bytes_received: 0,
                    last_body_activity,
                    request_fin_received: request_body.request_fin_received(),
                },
                pending_forward,
            },
            routing,
            upstream_pool,
        }
    }

    pub(super) fn prepare_request_for_auth(
        stream_id: u64,
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        request: RequestRoutingInput<'_>,
        shared_ctx: &ForwardingSharedCtx<'_>,
    ) -> Result<Option<PreAdmissionNextState>, quiche::h3::Error> {
        let RequestRoutingInput {
            peer_address,
            sticky_cid_key,
            intake,
        } = request;
        let IntakeRequestDescriptor {
            quic_trace_id,
            request_start,
            method,
            path,
            authority,
            headers,
            content_length,
            tunnel_mode,
            tracing_enabled,
        } = intake;
        let metrics = shared_ctx.metrics.as_ref();
        let resilience = shared_ctx.resilience;
        let resolution_context = ResolutionContext::new(
            shared_ctx.routing_index,
            shared_ctx.upstream_pools,
            shared_ctx.upstream_policies,
        );
        let intake = Self::build_request_intake(IntakeRequestDescriptor {
            quic_trace_id,
            request_start,
            method,
            path,
            authority,
            headers,
            content_length,
            tunnel_mode,
            tracing_enabled,
        });
        let lb_header_lookup = |name: &str| {
            headers
                .iter()
                .find(|header| header.name().eq_ignore_ascii_case(name.as_bytes()))
                .and_then(|header| std::str::from_utf8(header.value()).ok())
                .map(str::to_string)
        };
        let resolved = ForwardingRequestPipeline::new(resilience).resolve(
            Self::resolve_forwarding_target(ForwardTargetResolutionInput {
                request: TargetResolutionRequest::new(
                    method,
                    path,
                    authority,
                    Some(sticky_cid_key),
                    Some(&lb_header_lookup),
                ),
                context: resolution_context,
                observation: ResolutionObservation::new(metrics, request_start.elapsed()),
            }),
            PipelineRequest {
                method,
                path,
                authority,
                peer_address,
                headers: Some(&lb_header_lookup),
                runtime_generation: shared_ctx.runtime_generation,
            },
        );

        let prepared = match resolved {
            Ok(PipelineResolution {
                target:
                    ForwardTargetResolution {
                        upstream_name,
                        upstream_pool,
                        upstream_policy: _,
                        route_path_len,
                        route_host_specific,
                        route_reason,
                        backend_addr,
                        backend_index,
                        backend_lb,
                    },
                policy: resolved_policy,
                admission,
            }) => {
                let routing = RoutingSnapshot {
                    backend_addr: backend_addr.clone(),
                    backend_index,
                    upstream_name: upstream_name.clone(),
                    route_reason: route_reason.clone(),
                    route_path_len,
                    route_host_specific,
                    backend_lb: Some(backend_lb.clone()),
                };
                metrics.set_brownout_active(resilience.brownout.is_active());
                let rejection_response = admission_rejection_response(&admission);
                match admission {
                    AdmissionPolicyDecision::AdmitReady => {}
                    AdmissionPolicyDecision::Unauthorized(_) => {
                        metrics.inc_policy_denied();
                        let _ = observe_admission_outcome(
                            metrics,
                            RouteOutcomeTarget {
                                route: &upstream_name,
                            },
                            Some(BackendOutcomeTarget {
                                upstream: &upstream_name,
                                backend_addr: Some(backend_addr.as_str()),
                                backend_index: Some(backend_index),
                            }),
                            request_start.elapsed(),
                            http::StatusCode::UNAUTHORIZED,
                            AdmissionOutcomeClass::AuthDenied,
                        );
                        warn!(
                            "admission denied: upstream={} reason=auth_denied",
                            upstream_name
                        );
                        let Some(response) = rejection_response.as_ref() else {
                            warn!(
                                "admission rejection response missing: upstream={} reason=auth_denied",
                                upstream_name
                            );
                            Self::send_simple_response(
                                h3,
                                quic,
                                stream_id,
                                http::StatusCode::INTERNAL_SERVER_ERROR,
                                b"internal proxy error\n",
                            )?;
                            return Ok(None);
                        };
                        return Ok(Some(PreAdmissionNextState::LocallyRejected(
                            LocalRejectionCandidate {
                                response: response.clone(),
                            },
                        )));
                    }
                    AdmissionPolicyDecision::RateLimited(decision) => {
                        metrics.inc_request_rate_limited();
                        let _ = observe_admission_outcome(
                            metrics,
                            RouteOutcomeTarget {
                                route: &upstream_name,
                            },
                            Some(BackendOutcomeTarget {
                                upstream: &upstream_name,
                                backend_addr: Some(backend_addr.as_str()),
                                backend_index: Some(backend_index),
                            }),
                            request_start.elapsed(),
                            http::StatusCode::TOO_MANY_REQUESTS,
                            AdmissionOutcomeClass::RateLimited,
                        );
                        warn!(
                            "admission denied: upstream={} reason=rate_limited rule={}",
                            decision.route, decision.rule_name
                        );
                        let Some(response) = rejection_response.as_ref() else {
                            warn!(
                                "admission rejection response missing: upstream={} reason=rate_limited",
                                upstream_name
                            );
                            Self::send_simple_response(
                                h3,
                                quic,
                                stream_id,
                                http::StatusCode::INTERNAL_SERVER_ERROR,
                                b"internal proxy error\n",
                            )?;
                            return Ok(None);
                        };
                        return Ok(Some(PreAdmissionNextState::LocallyRejected(
                            LocalRejectionCandidate {
                                response: response.clone(),
                            },
                        )));
                    }
                    AdmissionPolicyDecision::Overloaded(decision) => {
                        let _ = observe_admission_outcome(
                            metrics,
                            RouteOutcomeTarget {
                                route: &upstream_name,
                            },
                            Some(BackendOutcomeTarget {
                                upstream: &upstream_name,
                                backend_addr: Some(backend_addr.as_str()),
                                backend_index: Some(backend_index),
                            }),
                            request_start.elapsed(),
                            http::StatusCode::SERVICE_UNAVAILABLE,
                            AdmissionOutcomeClass::OverloadShed {
                                reason: Some(decision.reason.metrics_reason()),
                            },
                        );
                        let Some(response) = rejection_response.as_ref() else {
                            warn!(
                                "admission rejection response missing: upstream={} reason=overloaded",
                                upstream_name
                            );
                            Self::send_simple_response(
                                h3,
                                quic,
                                stream_id,
                                http::StatusCode::INTERNAL_SERVER_ERROR,
                                b"internal proxy error\n",
                            )?;
                            return Ok(None);
                        };
                        resilience
                            .adaptive_admission
                            .observe(request_start.elapsed(), true);
                        return Ok(Some(PreAdmissionNextState::LocallyRejected(
                            LocalRejectionCandidate {
                                response: response.clone(),
                            },
                        )));
                    }
                }

                let request_id = intake.request_id();
                let pending_forward = Arc::new(PendingForward {
                    method: Arc::<str>::from(method),
                    path: Arc::<str>::from(path),
                    authority: authority.map(Arc::<str>::from),
                    headers: Arc::new(headers.to_vec()),
                    upstream_name: Arc::<str>::from(upstream_name.as_str()),
                    route_reason: Arc::<str>::from(route_reason.as_str()),
                    route_path_len,
                    route_host_specific,
                    backend_addr: Arc::<str>::from(backend_addr.as_str()),
                    backend_index,
                    backend_lb: Some(Arc::<str>::from(backend_lb.as_str())),
                    client_addr: peer_address,
                    request_id,
                    trace_id: intake
                        .state
                        .context
                        .trace_id
                        .as_deref()
                        .map(Arc::<str>::from),
                    span_id: intake
                        .state
                        .context
                        .span_id
                        .as_deref()
                        .map(Arc::<str>::from),
                    traceparent: intake
                        .state
                        .context
                        .traceparent
                        .as_deref()
                        .map(Arc::<str>::from),
                    host_policy: resolved_policy.host_policy,
                    forwarded_header_policy: resolved_policy.forwarded_header_policy,
                    auth_header_mutations: Vec::new(),
                });
                let dispatch_ready = Self::build_dispatch_ready_candidate(
                    intake,
                    routing,
                    upstream_pool,
                    pending_forward,
                );

                Some(match resolved_policy.external_auth {
                    Some(external_auth) => PreAdmissionNextState::RequiresExternalAuth(Box::new(
                        ExternalAuthCandidate {
                            request: dispatch_ready,
                            external_auth: external_auth.policy,
                            auth_disposition: external_auth.disposition,
                        },
                    )),
                    None => {
                        PreAdmissionNextState::ReadyForPostAuthAdmission(Box::new(dispatch_ready))
                    }
                })
            }
            Err(err) => {
                let (status, body): (http::StatusCode, &[u8]) = match &err {
                    ProxyError::Bridge(_) => (http::StatusCode::BAD_REQUEST, b"invalid request\n"),
                    ProxyError::Transport(_) | ProxyError::Pool(_) => {
                        Self::bootstrap_route_resolution_error_response(&err)
                    }
                    _ => (
                        http::StatusCode::INTERNAL_SERVER_ERROR,
                        b"internal proxy error\n",
                    ),
                };
                Self::send_simple_response(h3, quic, stream_id, status, body)?;
                resilience
                    .adaptive_admission
                    .observe(request_start.elapsed(), true);
                None
            }
        };

        Ok(prepared)
    }

    pub(super) fn start_request_auth(
        stream_id: u64,
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        request_start: Instant,
        metrics: &Metrics,
        pre_auth: PreAdmissionNextState,
        finalization: RequestFinalizationConfig,
    ) -> Result<Option<StartedRequestEnvelope>, quiche::h3::Error> {
        let RequestFinalizationConfig {
            routing_transparency_enabled,
            routing_transparency_include_reason,
            backend_total_request_timeout,
        } = finalization;
        match pre_auth {
            PreAdmissionNextState::LocallyRejected(rejection) => {
                Self::send_admission_rejection_response(h3, quic, stream_id, &rejection.response)?;
                Ok(None)
            }
            PreAdmissionNextState::ReadyForPostAuthAdmission(request) => {
                let mut request = *request;
                request.state.context.total_request_deadline =
                    request.state.context.start + backend_total_request_timeout;
                Ok(Some(StartedRequestEnvelope {
                    envelope: request.into_dispatch_ready_envelope(
                        routing_transparency_enabled,
                        routing_transparency_include_reason,
                    ),
                    should_materialize_forward: true,
                }))
            }
            PreAdmissionNextState::RequiresExternalAuth(request) => {
                let mut request = *request;
                request.request.state.context.total_request_deadline =
                    request.request.state.context.start + backend_total_request_timeout;
                let auth_disposition = request.auth_disposition;
                let pending_forward = Arc::clone(&request.request.state.pending_forward);
                let auth_start = match start_external_auth_task(
                    pending_forward,
                    request.external_auth,
                ) {
                    Ok(start) => Some(start),
                    Err(err) => {
                        match evaluate_external_auth_completion(Err(err), auth_disposition) {
                            ExternalAuthCompletion::FailOpen { timed_out, error } => {
                                metrics.inc_external_auth_error();
                                if timed_out {
                                    warn!(
                                        "external auth failed open: request_id={} upstream={} reason=auth_timeout",
                                        request.request.request_id(),
                                        request.request.upstream_name()
                                    );
                                } else if let Some(error) = error {
                                    warn!(
                                        "external auth failed open: request_id={} upstream={} reason=auth_unavailable detail={:?}",
                                        request.request.request_id(),
                                        request.request.upstream_name(),
                                        error
                                    );
                                }
                                None
                            }
                            ExternalAuthCompletion::Reject {
                                status,
                                body,
                                timed_out,
                                error,
                            } => {
                                metrics.inc_external_auth_error();
                                let _ = observe_admission_outcome(
                                    metrics,
                                    RouteOutcomeTarget {
                                        route: request.request.upstream_name(),
                                    },
                                    Some(BackendOutcomeTarget {
                                        upstream: request.request.upstream_name(),
                                        backend_addr: Some(request.request.backend_addr()),
                                        backend_index: Some(request.request.backend_index()),
                                    }),
                                    request_start.elapsed(),
                                    status,
                                    AdmissionOutcomeClass::Failed { timed_out },
                                );
                                if let Some(error) = error {
                                    error!(
                                        "admission denied: request_id={} upstream={} reason=auth_unavailable detail={:?}",
                                        request.request.request_id(),
                                        request.request.upstream_name(),
                                        error
                                    );
                                } else {
                                    error!(
                                        "admission denied: request_id={} upstream={} reason=auth_unavailable",
                                        request.request.request_id(),
                                        request.request.upstream_name()
                                    );
                                }
                                Self::send_simple_response(h3, quic, stream_id, status, body)?;
                                return Ok(None);
                            }
                            ExternalAuthCompletion::Allow { .. }
                            | ExternalAuthCompletion::Respond(_) => {
                                unreachable!(
                                    "startup failure must resolve to fail-open or rejection"
                                )
                            }
                        }
                    }
                };
                let should_materialize_forward = auth_start.is_none();
                let envelope = if let Some(start) = auth_start {
                    request.request.into_awaiting_auth_envelope(
                        routing_transparency_enabled,
                        routing_transparency_include_reason,
                        start.rx,
                        start.abort,
                        auth_disposition,
                        start.deadline,
                    )
                } else {
                    request.request.into_dispatch_ready_envelope(
                        routing_transparency_enabled,
                        routing_transparency_include_reason,
                    )
                };
                Ok(Some(StartedRequestEnvelope {
                    envelope,
                    should_materialize_forward,
                }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::header::HOST;
    use http_body_util::{Full, combinators::BoxBody};
    use impulse_config::config::{
        ForwardedHeaderPolicy, ForwardedHeaderPolicyMode, UpstreamHostPolicy,
        UpstreamHostPolicyMode,
    };
    use impulse_errors::{BridgeError, ProxyError};

    use super::*;
    use crate::runtime::connection::auth::PendingHeaderMutation;

    fn empty_body() -> BoxBody<Bytes, Infallible> {
        BoxBody::new(Full::new(Bytes::new()))
    }

    fn h2_endpoint() -> BackendEndpoint {
        BackendEndpoint::parse("backend.internal:443").expect("endpoint")
    }

    #[test]
    fn build_request_resolves_pass_through_rewrite_and_upstream_host_policies() {
        let endpoint = h2_endpoint();

        let pass_through = PendingForward::sample_for_test(vec![]);
        let pass_through_req = pass_through
            .build_request(&endpoint, empty_body(), Some(0))
            .expect("pass-through request");
        assert_eq!(
            pass_through_req
                .headers()
                .get(HOST)
                .and_then(|value| value.to_str().ok()),
            Some("api.example.com")
        );

        let rewrite = PendingForward {
            host_policy: UpstreamHostPolicy {
                mode: UpstreamHostPolicyMode::Rewrite,
                host: Some("origin.example.com".to_string()),
            },
            ..PendingForward::sample_for_test(vec![])
        };
        let rewrite_req = rewrite
            .build_request(&endpoint, empty_body(), Some(0))
            .expect("rewrite request");
        assert_eq!(
            rewrite_req
                .headers()
                .get(HOST)
                .and_then(|value| value.to_str().ok()),
            Some("origin.example.com")
        );
        assert_eq!(
            rewrite_req
                .headers()
                .get("x-forwarded-host")
                .and_then(|value| value.to_str().ok()),
            Some("origin.example.com")
        );

        let upstream = PendingForward {
            host_policy: UpstreamHostPolicy {
                mode: UpstreamHostPolicyMode::Upstream,
                host: None,
            },
            ..PendingForward::sample_for_test(vec![])
        };
        let upstream_req = upstream
            .build_request(&endpoint, empty_body(), Some(0))
            .expect("upstream-host request");
        assert_eq!(
            upstream_req
                .headers()
                .get(HOST)
                .and_then(|value| value.to_str().ok()),
            Some("backend.internal:443")
        );
    }

    #[test]
    fn build_request_applies_forwarded_header_policy_without_duplicate_drift() {
        let pending_forward = PendingForward {
            forwarded_header_policy: ForwardedHeaderPolicy {
                mode: ForwardedHeaderPolicyMode::Append,
            },
            ..PendingForward::sample_for_test(vec![
                quiche::h3::Header::new(
                    b"forwarded",
                    b"for=1.2.3.4;proto=http;host=\"old.example\"",
                ),
                quiche::h3::Header::new(b"x-forwarded-for", b"1.2.3.4"),
                quiche::h3::Header::new(b"x-forwarded-proto", b"http"),
                quiche::h3::Header::new(b"x-forwarded-host", b"old.example"),
                quiche::h3::Header::new(b"authorization", b"Bearer route-token"),
            ])
        };

        let request = pending_forward
            .build_request(&h2_endpoint(), empty_body(), Some(0))
            .expect("request");
        let headers = request.headers();

        assert_eq!(
            headers
                .get("forwarded")
                .and_then(|value| value.to_str().ok()),
            Some(
                "for=1.2.3.4;proto=http;host=\"old.example\", for=203.0.113.55;proto=https;host=\"api.example.com\""
            )
        );
        assert_eq!(
            headers
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok()),
            Some("1.2.3.4, 203.0.113.55")
        );
        assert_eq!(
            headers
                .get("x-forwarded-proto")
                .and_then(|value| value.to_str().ok()),
            Some("http, https")
        );
        assert_eq!(
            headers
                .get("x-forwarded-host")
                .and_then(|value| value.to_str().ok()),
            Some("old.example, api.example.com")
        );
        assert_eq!(
            headers.keys().filter(|name| *name == "forwarded").count(),
            1,
            "forwarded policy should normalize to one forwarded header"
        );
        assert_eq!(
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer route-token")
        );
    }

    #[test]
    fn build_request_injects_auth_mutations_after_configured_headers() {
        let pending_forward = PendingForward {
            auth_header_mutations: vec![
                PendingHeaderMutation::Upsert {
                    name: b"x-auth-user".to_vec(),
                    value: b"alice".to_vec(),
                },
                PendingHeaderMutation::Remove {
                    name: b"x-remove-me".to_vec(),
                },
            ],
            ..PendingForward::sample_for_test(vec![
                quiche::h3::Header::new(b"x-configured-auth", b"route-policy"),
                quiche::h3::Header::new(b"x-auth-user", b"stale"),
                quiche::h3::Header::new(b"x-remove-me", b"1"),
            ])
        };

        let request = pending_forward
            .build_request(&h2_endpoint(), empty_body(), Some(0))
            .expect("request");
        let headers = request.headers();

        assert_eq!(
            headers
                .get("x-configured-auth")
                .and_then(|value| value.to_str().ok()),
            Some("route-policy")
        );
        assert_eq!(
            headers
                .get("x-auth-user")
                .and_then(|value| value.to_str().ok()),
            Some("alice")
        );
        assert!(!headers.contains_key("x-remove-me"));
    }

    #[test]
    fn request_headers_borrows_original_headers_when_no_auth_mutations_are_pending() {
        let pending_forward =
            PendingForward::sample_for_test(vec![quiche::h3::Header::new(b"x-test", b"1")]);

        assert!(matches!(
            pending_forward.request_headers_cow(),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn request_headers_materializes_owned_headers_when_auth_mutations_are_pending() {
        let pending_forward = PendingForward {
            auth_header_mutations: vec![PendingHeaderMutation::Upsert {
                name: b"x-auth-user".to_vec(),
                value: b"alice".to_vec(),
            }],
            ..PendingForward::sample_for_test(vec![quiche::h3::Header::new(b"x-test", b"1")])
        };

        assert!(matches!(
            pending_forward.request_headers_cow(),
            Cow::Owned(_)
        ));
    }

    #[test]
    fn websocket_tunnel_headers_borrow_when_upgrade_headers_are_already_present() {
        let pending_forward = PendingForward::sample_for_test(vec![
            quiche::h3::Header::new(b"upgrade", b"websocket"),
            quiche::h3::Header::new(b"connection", b"upgrade"),
        ]);

        assert!(matches!(
            pending_forward.request_headers_for_http1_websocket_tunnel(),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn websocket_tunnel_headers_materialize_owned_headers_when_upgrade_headers_are_missing() {
        let pending_forward =
            PendingForward::sample_for_test(vec![quiche::h3::Header::new(b"x-test", b"1")]);

        let headers = pending_forward.request_headers_for_http1_websocket_tunnel();
        assert!(matches!(headers, Cow::Owned(_)));
        assert!(
            headers
                .iter()
                .any(|header| header.name().eq_ignore_ascii_case(b"upgrade"))
        );
        assert!(
            headers
                .iter()
                .any(|header| header.name().eq_ignore_ascii_case(b"connection"))
        );
    }

    #[test]
    fn build_request_rejects_invalid_headers_before_upstream_dispatch() {
        let pending_forward =
            PendingForward::sample_for_test(vec![quiche::h3::Header::new(b"bad header", b"1")]);

        let err = pending_forward
            .build_request(&h2_endpoint(), empty_body(), Some(0))
            .expect_err("invalid header should fail request build");

        assert!(matches!(
            err,
            ProxyError::Bridge(BridgeError::InvalidHeader)
        ));
    }
}
