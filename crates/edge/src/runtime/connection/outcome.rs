use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use http::StatusCode;
use impulse_config::runtime::RuntimeBackendTlsPolicy;
use impulse_errors::{
    ClassifiedUpstreamProxyError, PoolError, ProxyError, UpstreamErrorCategory, UpstreamTlsReason,
};
use impulse_lb::{
    HealthTransition, health::HealthFailureReason,
    pingora_backend::PingoraLoadBalancingRuntimeState, upstream_pool::UpstreamPool,
};
use log::{error, info};

use crate::{
    Metrics, OverloadShedReason, RouteOutcome,
    runtime::{
        backend::{
            event::{
                BackendHealthObservation, BackendHealthObservationOutcome,
                BackendHealthObservationSource, BackendRequestFeedback,
            },
            lifecycle::{
                apply_backend_health_observation, apply_backend_request_accounting,
                apply_backend_request_feedback,
            },
            state::BackendIdentity,
        },
        connection::stream::{BackendFailureReason, RejectionReason, TerminalState, TimeoutReason},
    },
};

fn emit_backend_health_transition(
    backend_addr: &str,
    transition: Option<HealthTransition>,
) -> Option<HealthTransition> {
    if let Some(transition) = transition {
        log_backend_health_transition(backend_addr, &transition);
        Some(transition)
    } else {
        None
    }
}

fn tls_metrics_reason(classified: &ClassifiedUpstreamProxyError) -> &'static str {
    match classified
        .classification
        .tls_reason
        .unwrap_or(UpstreamTlsReason::Handshake)
    {
        UpstreamTlsReason::UnknownIssuer => "unknown_issuer",
        UpstreamTlsReason::ExpiredCertificate => "expired_certificate",
        UpstreamTlsReason::HostnameMismatch => "hostname_mismatch",
        UpstreamTlsReason::Alpn => "alpn",
        UpstreamTlsReason::Handshake => "handshake",
        UpstreamTlsReason::ClientCertificateMissing => "client_certificate_missing",
        UpstreamTlsReason::ClientKeyMissing => "client_key_missing",
        UpstreamTlsReason::ClientIdentityInvalid => "client_identity_invalid",
        UpstreamTlsReason::ClientAuthRejected => "client_auth_rejected",
        UpstreamTlsReason::ClientCertificateExpired => "client_certificate_expired",
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanonicalRouteOutcome {
    Success,
    UpstreamFailure,
    Timeout,
    OverloadShed,
    RateLimited,
    AuthDenied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanonicalBackendOutcome {
    Success,
    UpstreamFailure,
    Timeout,
    OverloadShed,
    RateLimited,
    AuthDenied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseStatusClass {
    Informational,
    Success,
    Redirection,
    ClientError,
    ServerError,
    Other,
}

impl From<StatusCode> for ResponseStatusClass {
    fn from(status: StatusCode) -> Self {
        match status.as_u16() {
            100..=199 => Self::Informational,
            200..=299 => Self::Success,
            300..=399 => Self::Redirection,
            400..=499 => Self::ClientError,
            500..=599 => Self::ServerError,
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HealthEffectHint {
    None,
    Success,
    Neutral,
    Failure { reason: HealthFailureReason },
}

/// The fine-grained backend-failure transport class carried alongside the coarse
/// [`CanonicalBackendOutcome`] (Phase 12 step 5). This preserves *why* a backend
/// failed — timeout, transport, protocol, TLS, or bridge — so metrics/diagnostics
/// can be traced directly to the terminal state rather than collapsing every
/// backend failure into one bucket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BackendFailureClass {
    Timeout,
    Transport,
    Protocol,
    Tls,
    Bridge,
}

/// The fine-grained rejection class carried alongside the coarse
/// [`CanonicalRouteOutcome`] (Phase 12 step 4). Distinguishes auth-denied,
/// rate-limited, overload-shed, and validation/policy rejects, which the coarse
/// route outcome would otherwise merge into a single failure bucket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RejectionClass {
    AuthDenied,
    AuthUnavailable,
    RateLimited,
    QuotaDenied,
    OverloadShed,
    ValidationPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RouteOutcomeTarget<'a> {
    pub(crate) route: &'a str,
}

impl<'a> RouteOutcomeTarget<'a> {
    pub(crate) const UNROUTED: Self = Self { route: "unrouted" };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BackendOutcomeTarget<'a> {
    pub(crate) upstream: &'a str,
    pub(crate) backend_addr: Option<&'a str>,
    pub(crate) backend_index: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RequestOutcomeClassification {
    pub(crate) route_outcome: CanonicalRouteOutcome,
    pub(crate) backend_outcome: CanonicalBackendOutcome,
    pub(crate) overload_reason: Option<OverloadShedReason>,
    /// Fine-grained rejection class when this decision is a rejection (Phase 12).
    pub(crate) rejection_kind: Option<RejectionClass>,
    /// Fine-grained backend-failure transport class when this decision is a
    /// backend failure (Phase 12).
    pub(crate) backend_failure_kind: Option<BackendFailureClass>,
    health_effect: HealthEffectHint,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RequestOutcomeObservation<'a> {
    pub(crate) route_target: RouteOutcomeTarget<'a>,
    pub(crate) backend_target: Option<BackendOutcomeTarget<'a>>,
    pub(crate) elapsed: Duration,
    pub(crate) status: Option<u16>,
    pub(crate) metrics_outcome: RouteOutcome,
    pub(crate) overload_reason: Option<OverloadShedReason>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionOutcomeClass {
    AuthDenied,
    RateLimited,
    QuotaDenied,
    OverloadShed { reason: Option<OverloadShedReason> },
    Failed { timed_out: bool },
}

impl RequestOutcomeClassification {
    /// Base decision from a route outcome, mirroring the coarse backend outcome and
    /// leaving the fine-grained kinds unset. Call sites add `rejection_kind` /
    /// `backend_failure_kind` / `overload_reason` as applicable.
    fn from_route(route_outcome: CanonicalRouteOutcome, health_effect: HealthEffectHint) -> Self {
        Self {
            route_outcome,
            backend_outcome: CanonicalBackendOutcome::from_route_outcome(route_outcome),
            overload_reason: None,
            rejection_kind: None,
            backend_failure_kind: None,
            health_effect,
        }
    }
}

impl CanonicalRouteOutcome {
    pub(crate) fn as_metrics_outcome(self) -> RouteOutcome {
        match self {
            Self::Success => RouteOutcome::Success,
            Self::UpstreamFailure | Self::AuthDenied => RouteOutcome::Failure,
            Self::Timeout => RouteOutcome::Timeout,
            Self::OverloadShed => RouteOutcome::OverloadShed,
            Self::RateLimited => RouteOutcome::RateLimited,
        }
    }
}

impl CanonicalBackendOutcome {
    fn from_route_outcome(outcome: CanonicalRouteOutcome) -> Self {
        match outcome {
            CanonicalRouteOutcome::Success => Self::Success,
            CanonicalRouteOutcome::UpstreamFailure => Self::UpstreamFailure,
            CanonicalRouteOutcome::Timeout => Self::Timeout,
            CanonicalRouteOutcome::OverloadShed => Self::OverloadShed,
            CanonicalRouteOutcome::RateLimited => Self::RateLimited,
            CanonicalRouteOutcome::AuthDenied => Self::AuthDenied,
        }
    }
}

fn health_effect_from_status_class(status_class: ResponseStatusClass) -> HealthEffectHint {
    match status_class {
        ResponseStatusClass::ServerError => HealthEffectHint::Failure {
            reason: HealthFailureReason::HttpStatus5xx,
        },
        ResponseStatusClass::ClientError => HealthEffectHint::Neutral,
        ResponseStatusClass::Informational
        | ResponseStatusClass::Success
        | ResponseStatusClass::Redirection => HealthEffectHint::Success,
        ResponseStatusClass::Other => HealthEffectHint::None,
    }
}

pub(crate) fn classify_status_outcome(status: StatusCode) -> RequestOutcomeClassification {
    let status_class = ResponseStatusClass::from(status);
    let route_outcome = match status_class {
        ResponseStatusClass::Informational
        | ResponseStatusClass::Success
        | ResponseStatusClass::Redirection => CanonicalRouteOutcome::Success,
        ResponseStatusClass::ClientError => CanonicalRouteOutcome::UpstreamFailure,
        ResponseStatusClass::ServerError => CanonicalRouteOutcome::UpstreamFailure,
        ResponseStatusClass::Other => CanonicalRouteOutcome::UpstreamFailure,
    };

    RequestOutcomeClassification::from_route(
        route_outcome,
        health_effect_from_status_class(status_class),
    )
}

pub(crate) fn classify_proxy_error_outcome(
    err: &ProxyError,
    overload_reason: Option<OverloadShedReason>,
) -> RequestOutcomeClassification {
    let (route_outcome, health_effect) = match err {
        ProxyError::Timeout => (
            CanonicalRouteOutcome::Timeout,
            HealthEffectHint::Failure {
                reason: HealthFailureReason::Timeout,
            },
        ),
        ProxyError::Pool(PoolError::BackendOverloaded(_))
        | ProxyError::Pool(PoolError::CircuitOpen(_)) => {
            (CanonicalRouteOutcome::OverloadShed, HealthEffectHint::None)
        }
        ProxyError::Pool(PoolError::InflightLimiterClosed)
        | ProxyError::Pool(PoolError::UnknownBackend(_)) => (
            CanonicalRouteOutcome::UpstreamFailure,
            HealthEffectHint::None,
        ),
        ProxyError::Transport(_) | ProxyError::Protocol(_) => (
            CanonicalRouteOutcome::UpstreamFailure,
            HealthEffectHint::Failure {
                reason: HealthFailureReason::Transport,
            },
        ),
        ProxyError::Tls(_) => (
            CanonicalRouteOutcome::UpstreamFailure,
            HealthEffectHint::None,
        ),
        ProxyError::Bridge(_) => (
            CanonicalRouteOutcome::UpstreamFailure,
            HealthEffectHint::None,
        ),
    };

    RequestOutcomeClassification {
        overload_reason,
        ..RequestOutcomeClassification::from_route(route_outcome, health_effect)
    }
}

pub(crate) fn classify_admission_outcome(
    outcome: AdmissionOutcomeClass,
) -> RequestOutcomeClassification {
    let (route_outcome, overload_reason, rejection_kind) = match outcome {
        AdmissionOutcomeClass::AuthDenied => (
            CanonicalRouteOutcome::AuthDenied,
            None,
            Some(RejectionClass::AuthDenied),
        ),
        AdmissionOutcomeClass::RateLimited => (
            CanonicalRouteOutcome::RateLimited,
            None,
            Some(RejectionClass::RateLimited),
        ),
        AdmissionOutcomeClass::QuotaDenied => (
            CanonicalRouteOutcome::RateLimited,
            None,
            Some(RejectionClass::QuotaDenied),
        ),
        AdmissionOutcomeClass::OverloadShed { reason } => (
            CanonicalRouteOutcome::OverloadShed,
            reason,
            Some(RejectionClass::OverloadShed),
        ),
        AdmissionOutcomeClass::Failed { timed_out } => (
            if timed_out {
                CanonicalRouteOutcome::Timeout
            } else {
                CanonicalRouteOutcome::UpstreamFailure
            },
            None,
            None,
        ),
    };

    RequestOutcomeClassification {
        overload_reason,
        rejection_kind,
        ..RequestOutcomeClassification::from_route(route_outcome, HealthEffectHint::None)
    }
}

pub(crate) fn record_request_metrics_observation(
    metrics: &crate::Metrics,
    observation: RequestOutcomeObservation<'_>,
) {
    let RequestOutcomeObservation {
        route_target,
        backend_target,
        elapsed,
        status,
        metrics_outcome,
        overload_reason,
    } = observation;

    if !matches!(metrics_outcome, RouteOutcome::Success) {
        metrics.request_observations().inc_failure();
    }

    if matches!(metrics_outcome, RouteOutcome::OverloadShed) {
        if let Some(reason) = overload_reason {
            metrics
                .policy_observations()
                .inc_overload_shed_reason(reason);
        } else {
            metrics.policy_observations().inc_overload_shed();
        }
    }

    metrics
        .request_observations()
        .record_route(route_target.route, elapsed, metrics_outcome);
    metrics.request_observations().record_request_result(
        route_target.route,
        backend_target.and_then(|target| target.backend_addr),
        status,
        metrics_outcome,
        elapsed,
    );
}

pub(crate) fn observe_request_outcome(
    metrics: &Metrics,
    route_target: RouteOutcomeTarget<'_>,
    backend_target: Option<BackendOutcomeTarget<'_>>,
    elapsed: Duration,
    status: Option<StatusCode>,
    decision: RequestOutcomeClassification,
) -> RequestOutcomeClassification {
    if matches!(decision.route_outcome, CanonicalRouteOutcome::Success) {
        metrics.request_observations().inc_success();
    }

    record_request_metrics_observation(
        metrics,
        RequestOutcomeObservation {
            route_target,
            backend_target,
            elapsed,
            status: status.map(|value| value.as_u16()),
            metrics_outcome: decision.route_outcome.as_metrics_outcome(),
            overload_reason: decision.overload_reason,
        },
    );

    decision
}

pub(crate) fn observe_status_outcome(
    metrics: &Metrics,
    route_target: RouteOutcomeTarget<'_>,
    backend_target: Option<BackendOutcomeTarget<'_>>,
    elapsed: Duration,
    status: StatusCode,
) -> RequestOutcomeClassification {
    observe_request_outcome(
        metrics,
        route_target,
        backend_target,
        elapsed,
        Some(status),
        classify_status_outcome(status),
    )
}

pub(crate) fn observe_proxy_error_outcome(
    metrics: &Metrics,
    route_target: RouteOutcomeTarget<'_>,
    backend_target: Option<BackendOutcomeTarget<'_>>,
    elapsed: Duration,
    status: Option<StatusCode>,
    err: &ProxyError,
    overload_reason: Option<OverloadShedReason>,
) -> RequestOutcomeClassification {
    observe_request_outcome(
        metrics,
        route_target,
        backend_target,
        elapsed,
        status,
        classify_proxy_error_outcome(err, overload_reason),
    )
}

pub(crate) fn observe_admission_outcome(
    metrics: &Metrics,
    route_target: RouteOutcomeTarget<'_>,
    backend_target: Option<BackendOutcomeTarget<'_>>,
    elapsed: Duration,
    status: StatusCode,
    outcome: AdmissionOutcomeClass,
) -> RequestOutcomeClassification {
    observe_request_outcome(
        metrics,
        route_target,
        backend_target,
        elapsed,
        Some(status),
        classify_admission_outcome(outcome),
    )
}

fn terminal_route_target(state: &TerminalState) -> RouteOutcomeTarget<'_> {
    let routing = match state {
        TerminalState::Completed(state) => state.snapshot.routing.as_ref(),
        TerminalState::Cancelled(state) => state.snapshot.routing.as_ref(),
        TerminalState::TimedOut(state) => state.snapshot.routing.as_ref(),
        TerminalState::Rejected(state) => state.snapshot.routing.as_ref(),
        TerminalState::BackendFailed(state) => state.snapshot.routing.as_ref(),
    };
    routing.map_or(RouteOutcomeTarget::UNROUTED, |routing| RouteOutcomeTarget {
        route: &routing.upstream_name,
    })
}

fn terminal_backend_target(state: &TerminalState) -> Option<BackendOutcomeTarget<'_>> {
    let routing = match state {
        TerminalState::Completed(state) => state.snapshot.routing.as_ref(),
        TerminalState::Cancelled(state) => state.snapshot.routing.as_ref(),
        TerminalState::TimedOut(state) => state.snapshot.routing.as_ref(),
        TerminalState::Rejected(state) => state.snapshot.routing.as_ref(),
        TerminalState::BackendFailed(state) => state.snapshot.routing.as_ref(),
    }?;
    Some(BackendOutcomeTarget {
        upstream: &routing.upstream_name,
        backend_addr: Some(&routing.backend_addr),
        backend_index: Some(routing.backend_index),
    })
}

fn terminal_elapsed(state: &TerminalState) -> Duration {
    match state {
        TerminalState::Completed(state) => state.snapshot.context.start.elapsed(),
        TerminalState::Cancelled(state) => state.snapshot.context.start.elapsed(),
        TerminalState::TimedOut(state) => state.snapshot.context.start.elapsed(),
        TerminalState::Rejected(state) => state.snapshot.context.start.elapsed(),
        TerminalState::BackendFailed(state) => state.snapshot.context.start.elapsed(),
    }
}

fn infer_terminal_status(state: &TerminalState) -> Option<StatusCode> {
    match state {
        TerminalState::Completed(state) => state.snapshot.response_status,
        TerminalState::Cancelled(state) => state.snapshot.response_status,
        TerminalState::TimedOut(state) => {
            state.snapshot.response_status.or(Some(match state.reason {
                TimeoutReason::RequestBodyIdle
                | TimeoutReason::RequestBodyTotal
                | TimeoutReason::TotalRequest => StatusCode::REQUEST_TIMEOUT,
                TimeoutReason::ExternalAuth
                | TimeoutReason::AwaitingUpstream
                | TimeoutReason::ResponseBodyIdle
                | TimeoutReason::ResponseBodyTotal => StatusCode::GATEWAY_TIMEOUT,
            }))
        }
        TerminalState::Rejected(state) => {
            state.snapshot.response_status.or(Some(match state.reason {
                RejectionReason::AuthDenied => StatusCode::UNAUTHORIZED,
                RejectionReason::AuthUnavailable => StatusCode::SERVICE_UNAVAILABLE,
                RejectionReason::ValidationFailed | RejectionReason::RequestBodyNotAllowed => {
                    StatusCode::BAD_REQUEST
                }
                RejectionReason::RateLimited | RejectionReason::QuotaDenied => {
                    StatusCode::TOO_MANY_REQUESTS
                }
                RejectionReason::Overloaded | RejectionReason::ResponsePrebufferCap => {
                    StatusCode::SERVICE_UNAVAILABLE
                }
                RejectionReason::RequestBodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            }))
        }
        TerminalState::BackendFailed(state) => {
            state.snapshot.response_status.or(Some(match state.reason {
                BackendFailureReason::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,
                BackendFailureReason::DispatchSpawnFailed
                | BackendFailureReason::UpstreamResultChannelDropped
                | BackendFailureReason::UpstreamTransport
                | BackendFailureReason::UpstreamProtocol
                | BackendFailureReason::UpstreamTls
                | BackendFailureReason::UpstreamBridge
                | BackendFailureReason::ResponseWriteFailed
                | BackendFailureReason::ResponseStreamAborted => StatusCode::BAD_GATEWAY,
            }))
        }
    }
}

pub(crate) fn classify_terminal_outcome(state: &TerminalState) -> RequestOutcomeClassification {
    match state {
        TerminalState::Completed(state) if state.snapshot.overload_reason.is_some() => {
            classify_admission_outcome(AdmissionOutcomeClass::OverloadShed {
                reason: state.snapshot.overload_reason,
            })
        }
        TerminalState::Completed(_) => infer_terminal_status(state)
            .map(classify_status_outcome)
            .unwrap_or_else(|| {
                RequestOutcomeClassification::from_route(
                    CanonicalRouteOutcome::Success,
                    HealthEffectHint::Success,
                )
            }),
        TerminalState::Cancelled(_) => infer_terminal_status(state)
            .map(classify_status_outcome)
            .unwrap_or_else(|| {
                RequestOutcomeClassification::from_route(
                    CanonicalRouteOutcome::UpstreamFailure,
                    HealthEffectHint::None,
                )
            }),
        TerminalState::TimedOut(_) => classify_proxy_error_outcome(&ProxyError::Timeout, None),
        TerminalState::Rejected(state) => match state.reason {
            RejectionReason::AuthDenied => {
                classify_admission_outcome(AdmissionOutcomeClass::AuthDenied)
            }
            RejectionReason::RateLimited => {
                classify_admission_outcome(AdmissionOutcomeClass::RateLimited)
            }
            RejectionReason::QuotaDenied => {
                classify_admission_outcome(AdmissionOutcomeClass::QuotaDenied)
            }
            RejectionReason::Overloaded | RejectionReason::ResponsePrebufferCap => {
                classify_admission_outcome(AdmissionOutcomeClass::OverloadShed {
                    reason: state.snapshot.overload_reason.or(
                        if matches!(state.reason, RejectionReason::ResponsePrebufferCap) {
                            Some(OverloadShedReason::ResponsePrebufferCap)
                        } else {
                            None
                        },
                    ),
                })
            }
            RejectionReason::AuthUnavailable
            | RejectionReason::ValidationFailed
            | RejectionReason::RequestBodyNotAllowed
            | RejectionReason::RequestBodyTooLarge => {
                let rejection_kind = match state.reason {
                    RejectionReason::AuthUnavailable => RejectionClass::AuthUnavailable,
                    _ => RejectionClass::ValidationPolicy,
                };
                let base = infer_terminal_status(&TerminalState::Rejected(
                    crate::runtime::connection::stream::RejectedState {
                        reason: state.reason,
                        snapshot: state.snapshot.clone(),
                    },
                ))
                .map(classify_status_outcome)
                .unwrap_or_else(|| {
                    RequestOutcomeClassification::from_route(
                        CanonicalRouteOutcome::UpstreamFailure,
                        HealthEffectHint::None,
                    )
                });
                RequestOutcomeClassification {
                    rejection_kind: Some(rejection_kind),
                    ..base
                }
            }
        },
        // Phase 12: one mapping from the terminal backend-failure reason to route
        // outcome, fine-grained failure kind, and health effect — replacing five
        // near-identical decision literals.
        TerminalState::BackendFailed(state) => {
            let (route_outcome, failure_kind, health_effect) = match state.reason {
                BackendFailureReason::UpstreamTimeout => (
                    CanonicalRouteOutcome::Timeout,
                    BackendFailureClass::Timeout,
                    HealthEffectHint::Failure {
                        reason: HealthFailureReason::Timeout,
                    },
                ),
                BackendFailureReason::UpstreamTls => (
                    CanonicalRouteOutcome::UpstreamFailure,
                    BackendFailureClass::Tls,
                    HealthEffectHint::None,
                ),
                BackendFailureReason::UpstreamBridge => (
                    CanonicalRouteOutcome::UpstreamFailure,
                    BackendFailureClass::Bridge,
                    HealthEffectHint::None,
                ),
                BackendFailureReason::UpstreamProtocol => (
                    CanonicalRouteOutcome::UpstreamFailure,
                    BackendFailureClass::Protocol,
                    HealthEffectHint::Failure {
                        reason: HealthFailureReason::Transport,
                    },
                ),
                BackendFailureReason::UpstreamTransport
                | BackendFailureReason::DispatchSpawnFailed
                | BackendFailureReason::UpstreamResultChannelDropped
                | BackendFailureReason::ResponseWriteFailed
                | BackendFailureReason::ResponseStreamAborted => (
                    CanonicalRouteOutcome::UpstreamFailure,
                    BackendFailureClass::Transport,
                    HealthEffectHint::Failure {
                        reason: HealthFailureReason::Transport,
                    },
                ),
            };
            RequestOutcomeClassification {
                backend_failure_kind: Some(failure_kind),
                ..RequestOutcomeClassification::from_route(route_outcome, health_effect)
            }
        }
    }
}

pub(crate) fn observe_terminal_request_outcome(
    metrics: &Metrics,
    state: &TerminalState,
) -> RequestOutcomeClassification {
    let status = infer_terminal_status(state);
    observe_request_outcome(
        metrics,
        terminal_route_target(state),
        terminal_backend_target(state),
        terminal_elapsed(state),
        status,
        classify_terminal_outcome(state),
    )
}

#[derive(Clone, Copy)]
pub(crate) struct BackendRequestFinishInput<'a> {
    pub(crate) upstream_pool: Option<&'a Arc<RwLock<UpstreamPool>>>,
    pub(crate) backend_index: Option<usize>,
    pub(crate) elapsed: Duration,
    pub(crate) status: Option<u16>,
}

#[derive(Clone, Copy)]
pub(crate) struct BackendHealthObservationInput<'a> {
    pub(crate) backend_addr: &'a str,
    pub(crate) backend_index: usize,
    pub(crate) upstream_pool: Option<&'a Arc<RwLock<UpstreamPool>>>,
    pub(crate) status: StatusCode,
}

#[derive(Clone, Copy)]
pub(crate) struct ClassifiedBackendFailureInput<'a> {
    pub(crate) metrics_phase: &'a str,
    pub(crate) upstream_name: &'a str,
    pub(crate) backend_addr: &'a str,
    pub(crate) backend_index: usize,
    pub(crate) upstream_pool: Option<&'a Arc<RwLock<UpstreamPool>>>,
    pub(crate) metrics: &'a Metrics,
    pub(crate) classified: &'a ClassifiedUpstreamProxyError,
}

pub(crate) fn finish_backend_request_accounting(input: BackendRequestFinishInput<'_>) {
    let BackendRequestFinishInput {
        upstream_pool,
        backend_index,
        elapsed,
        status,
    } = input;

    apply_backend_request_accounting(upstream_pool, backend_index, elapsed, status);
}

pub(crate) fn finalize_backend_request_cleanup(
    input: BackendRequestFinishInput<'_>,
    should_finalize: bool,
) -> bool {
    if should_finalize {
        finish_backend_request_accounting(input);
        true
    } else {
        false
    }
}

pub(crate) fn observe_backend_response_status(
    input: BackendHealthObservationInput<'_>,
) -> Option<HealthTransition> {
    let BackendHealthObservationInput {
        backend_addr,
        backend_index,
        upstream_pool,
        status,
    } = input;

    let observation = BackendHealthObservation {
        identity: BackendIdentity::new(backend_addr),
        source: BackendHealthObservationSource::PassiveRequest,
        outcome: if status.is_server_error() {
            BackendHealthObservationOutcome::Failure
        } else if status.is_client_error() {
            BackendHealthObservationOutcome::Neutral
        } else {
            BackendHealthObservationOutcome::Success
        },
        reason: if status.is_server_error() {
            Some(HealthFailureReason::HttpStatus5xx)
        } else {
            None
        },
    };

    apply_backend_health_observation(upstream_pool, Some(backend_index), &observation)
}

pub(crate) fn observe_backend_response_status_and_log(
    input: BackendHealthObservationInput<'_>,
) -> Option<HealthTransition> {
    emit_backend_health_transition(input.backend_addr, observe_backend_response_status(input))
}

pub(crate) fn apply_passive_readiness_to_pingora(
    pingora_load_balancing: &PingoraLoadBalancingRuntimeState<RuntimeBackendTlsPolicy>,
    backend_addr: &str,
    transition: Option<HealthTransition>,
) {
    let Some(transition) = transition else {
        return;
    };
    pingora_load_balancing.set_backend_readiness(
        backend_addr,
        matches!(transition, HealthTransition::BecameHealthy),
    );
}

pub(crate) fn record_classified_backend_failure_metrics(
    metrics_phase: &str,
    upstream_name: &str,
    backend_addr: &str,
    metrics: &Metrics,
    classified: &ClassifiedUpstreamProxyError,
) -> Option<HealthFailureReason> {
    if classified.classification.category == UpstreamErrorCategory::Tls {
        metrics.runtime_observations().record_upstream_tls_failure(
            upstream_name,
            backend_addr,
            metrics_phase,
            tls_metrics_reason(classified),
        );
    }
    let health_mapping = classified.health_failure?;
    metrics
        .policy_observations()
        .inc_health_failure(health_mapping.failure_reason);
    Some(health_mapping.failure_reason)
}

pub(crate) fn observe_classified_backend_failure(
    input: ClassifiedBackendFailureInput<'_>,
) -> Option<HealthTransition> {
    let ClassifiedBackendFailureInput {
        metrics_phase,
        upstream_name,
        backend_addr,
        backend_index,
        upstream_pool,
        metrics,
        classified,
    } = input;

    let reason = record_classified_backend_failure_metrics(
        metrics_phase,
        upstream_name,
        backend_addr,
        metrics,
        classified,
    )?;
    let feedback = BackendRequestFeedback::failure(
        BackendIdentity::new(backend_addr),
        Duration::ZERO,
        None,
        Some(reason),
    );

    apply_backend_request_feedback(upstream_pool, Some(backend_index), &feedback)
}

pub(crate) fn observe_classified_backend_failure_and_log(
    input: ClassifiedBackendFailureInput<'_>,
) -> Option<HealthTransition> {
    emit_backend_health_transition(
        input.backend_addr,
        observe_classified_backend_failure(input),
    )
}

pub(crate) fn log_backend_health_transition_result(
    backend_addr: &str,
    transition: Option<HealthTransition>,
) -> Option<HealthTransition> {
    emit_backend_health_transition(backend_addr, transition)
}

pub(crate) fn log_backend_health_transition(addr: &str, transition: &HealthTransition) {
    // Phase 3: canonical `backend=` field + `health_reason=` slug so backend
    // health transitions carry the same dimension names as other backend events.
    match transition {
        HealthTransition::BecameHealthy => {
            info!("backend health transition: backend={addr} health_reason=became_healthy");
        }
        HealthTransition::BecameUnhealthy => {
            error!("backend health transition: backend={addr} health_reason=became_unhealthy");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, time::Duration};

    use impulse_config::{
        config::{
            Backend, Config, ForwardedHeaderPolicy, HealthCheck, Listen, LoadBalancing, RouteAuth,
            RouteMatch, Tls, Upstream, UpstreamHostPolicy,
        },
        runtime::RuntimeConfig,
    };

    use super::*;

    fn test_metrics() -> Metrics {
        Metrics::new(1, [String::from("api"), String::from("unrouted")])
    }

    fn api_route_target() -> RouteOutcomeTarget<'static> {
        RouteOutcomeTarget { route: "api" }
    }

    fn api_backend_target() -> Option<BackendOutcomeTarget<'static>> {
        Some(BackendOutcomeTarget {
            upstream: "api",
            backend_addr: Some("backend-a"),
            backend_index: Some(0),
        })
    }

    fn test_upstream_pool() -> Arc<RwLock<UpstreamPool>> {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "api".to_string(),
            Upstream {
                load_balancing: LoadBalancing {
                    lb_type: "round-robin".to_string(),
                    key: None,
                },
                auth: RouteAuth::default(),
                host_policy: UpstreamHostPolicy::default(),
                forwarded_headers: ForwardedHeaderPolicy::default(),
                compression: Default::default(),
                cache: Default::default(),
                tls: None,
                route: RouteMatch {
                    host: None,
                    path_prefix: Some("/".to_string()),
                    method: None,
                },
                backends: vec![Backend {
                    id: "a".to_string(),
                    address: "http://127.0.0.1:8080".to_string(),
                    weight: 1,
                    health_check: Some(HealthCheck {
                        path: "/health".to_string(),
                        interval: 1,
                        timeout_ms: 1000,
                        failure_threshold: 1,
                        success_threshold: 1,
                        cooldown_ms: 0,
                    }),
                }],
            },
        );
        let runtime = RuntimeConfig::from_config(&Config {
            version: 1,
            listen: Listen {
                protocol: "http1".to_string(),
                tls: Tls {
                    cert: "/tmp/test-cert.pem".to_string(),
                    key: "/tmp/test-key.pem".to_string(),
                    ..Tls::default()
                },
                ..Listen::default()
            },
            listeners: Vec::new(),
            upstream: upstreams,
            load_balancing: None,
            upstream_tls: Default::default(),
            secrets: Default::default(),
            log: Default::default(),
            performance: Default::default(),
            observability: Default::default(),
            resilience: Default::default(),
            security: Default::default(),
        })
        .expect("runtime config");

        let mut runtime_upstream = runtime.upstreams.get("api").expect("upstream").clone();
        runtime_upstream.backends[0].backend.health_check = Some(HealthCheck {
            path: "/health".to_string(),
            interval: 0,
            timeout_ms: 1000,
            failure_threshold: 1,
            success_threshold: 1,
            cooldown_ms: 0,
        });

        Arc::new(RwLock::new(
            crate::quic_listener::upstream_pool_from_runtime(&runtime_upstream).expect("pool"),
        ))
    }

    fn upstream_request_count(
        metrics: &Metrics,
        upstream: &str,
        status_class: &str,
        outcome: &str,
    ) -> u64 {
        metrics
            .snapshot_upstream_request_counts()
            .into_iter()
            .find(|(key, _)| {
                key.upstream == upstream
                    && key.status_class == status_class
                    && key.outcome == outcome
            })
            .map(|(_, count)| count)
            .unwrap_or_default()
    }

    fn backend_request_count(
        metrics: &Metrics,
        upstream: &str,
        backend: &str,
        status_class: &str,
        outcome: &str,
    ) -> u64 {
        metrics
            .snapshot_backend_request_counts()
            .into_iter()
            .find(|(key, _)| {
                key.upstream == upstream
                    && key.backend == backend
                    && key.status_class == status_class
                    && key.outcome == outcome
            })
            .map(|(_, count)| count)
            .unwrap_or_default()
    }

    fn upstream_latency_stats(
        metrics: &Metrics,
        upstream: &str,
        outcome: &str,
    ) -> crate::metrics::RequestLatencyStats {
        metrics
            .snapshot_upstream_request_latency()
            .into_iter()
            .find(|(key, _)| key.upstream == upstream && key.outcome == outcome)
            .map(|(_, stats)| stats)
            .unwrap_or_default()
    }

    fn terminal_snapshot_for_test() -> crate::runtime::connection::stream::TerminalSnapshot {
        use crate::runtime::connection::stream::{RequestContext, RequestMode, TerminalSnapshot};
        let now = std::time::Instant::now();
        TerminalSnapshot {
            context: RequestContext {
                request_id: 1,
                trace_id: None,
                span_id: None,
                traceparent: None,
                trace_span: None,
                method: "GET".to_string(),
                path: "/".to_string(),
                authority: None,
                start: now,
                total_request_deadline: now,
                completion: crate::edge_core::request_completion::RequestCompletion::default(),
            },
            routing: None,
            request_mode: RequestMode::Normal,
            response_status: None,
            overload_reason: None,
            backend_accounting: None,
        }
    }

    mod outcome_classification {
        use super::*;

        #[test]
        fn backend_failure_kinds_are_traceable_from_terminal_state() {
            use crate::runtime::connection::stream::{BackendFailedState, TerminalState};

            let cases = [
                (
                    BackendFailureReason::UpstreamTimeout,
                    BackendFailureClass::Timeout,
                ),
                (BackendFailureReason::UpstreamTls, BackendFailureClass::Tls),
                (
                    BackendFailureReason::UpstreamBridge,
                    BackendFailureClass::Bridge,
                ),
                (
                    BackendFailureReason::UpstreamProtocol,
                    BackendFailureClass::Protocol,
                ),
                (
                    BackendFailureReason::UpstreamTransport,
                    BackendFailureClass::Transport,
                ),
                (
                    BackendFailureReason::DispatchSpawnFailed,
                    BackendFailureClass::Transport,
                ),
            ];
            for (reason, expected_kind) in cases {
                let state = TerminalState::BackendFailed(BackendFailedState {
                    reason,
                    snapshot: terminal_snapshot_for_test(),
                });
                let decision = classify_terminal_outcome(&state);
                assert_eq!(
                    decision.backend_failure_kind,
                    Some(expected_kind),
                    "reason {reason:?} should map to {expected_kind:?}"
                );
                // Timeout maps to the timeout route outcome; every other kind to a
                // generic upstream failure — but the fine-grained kind is preserved.
                if matches!(reason, BackendFailureReason::UpstreamTimeout) {
                    assert_eq!(decision.route_outcome, CanonicalRouteOutcome::Timeout);
                } else {
                    assert_eq!(
                        decision.route_outcome,
                        CanonicalRouteOutcome::UpstreamFailure
                    );
                }
            }
        }

        #[test]
        fn rejection_kinds_distinguish_validation_from_auth_and_overload() {
            use crate::runtime::connection::stream::{RejectedState, TerminalState};

            let validation = classify_terminal_outcome(&TerminalState::Rejected(RejectedState {
                reason: RejectionReason::ValidationFailed,
                snapshot: terminal_snapshot_for_test(),
            }));
            assert_eq!(
                validation.rejection_kind,
                Some(RejectionClass::ValidationPolicy)
            );

            let auth = classify_terminal_outcome(&TerminalState::Rejected(RejectedState {
                reason: RejectionReason::AuthDenied,
                snapshot: terminal_snapshot_for_test(),
            }));
            assert_eq!(auth.rejection_kind, Some(RejectionClass::AuthDenied));

            let overload = classify_terminal_outcome(&TerminalState::Rejected(RejectedState {
                reason: RejectionReason::Overloaded,
                snapshot: terminal_snapshot_for_test(),
            }));
            assert_eq!(overload.rejection_kind, Some(RejectionClass::OverloadShed));
        }

        #[test]
        fn classifies_success_status_as_success() {
            let decision = classify_status_outcome(StatusCode::OK);
            assert_eq!(decision.route_outcome, CanonicalRouteOutcome::Success);
            assert_eq!(decision.backend_outcome, CanonicalBackendOutcome::Success);
            assert_eq!(decision.health_effect, HealthEffectHint::Success);
        }

        #[test]
        fn classifies_timeout_proxy_error_as_timeout() {
            let decision = classify_proxy_error_outcome(&ProxyError::Timeout, None);
            assert_eq!(decision.route_outcome, CanonicalRouteOutcome::Timeout);
            assert_eq!(decision.backend_outcome, CanonicalBackendOutcome::Timeout);
            assert_eq!(
                decision.health_effect,
                HealthEffectHint::Failure {
                    reason: HealthFailureReason::Timeout,
                }
            );
        }

        #[test]
        fn classifies_overload_admission_outcome() {
            let decision = classify_admission_outcome(AdmissionOutcomeClass::OverloadShed {
                reason: Some(OverloadShedReason::GlobalInflight),
            });
            assert_eq!(decision.route_outcome, CanonicalRouteOutcome::OverloadShed);
            assert_eq!(
                decision.backend_outcome,
                CanonicalBackendOutcome::OverloadShed
            );
            assert_eq!(
                decision.overload_reason,
                Some(OverloadShedReason::GlobalInflight)
            );
        }

        #[test]
        fn admission_outcome_classification_covers_auth_rate_limit_and_failed_paths() {
            let auth = classify_admission_outcome(AdmissionOutcomeClass::AuthDenied);
            assert_eq!(auth.route_outcome, CanonicalRouteOutcome::AuthDenied);
            assert_eq!(auth.backend_outcome, CanonicalBackendOutcome::AuthDenied);
            assert_eq!(auth.rejection_kind, Some(RejectionClass::AuthDenied));

            let rate_limited = classify_admission_outcome(AdmissionOutcomeClass::RateLimited);
            assert_eq!(
                rate_limited.route_outcome,
                CanonicalRouteOutcome::RateLimited
            );
            assert_eq!(
                rate_limited.backend_outcome,
                CanonicalBackendOutcome::RateLimited
            );
            assert_eq!(
                rate_limited.rejection_kind,
                Some(RejectionClass::RateLimited)
            );

            let failed_timeout =
                classify_admission_outcome(AdmissionOutcomeClass::Failed { timed_out: true });
            assert_eq!(failed_timeout.route_outcome, CanonicalRouteOutcome::Timeout);
            assert_eq!(
                failed_timeout.backend_outcome,
                CanonicalBackendOutcome::Timeout
            );
            assert_eq!(failed_timeout.rejection_kind, None);

            let failed_upstream =
                classify_admission_outcome(AdmissionOutcomeClass::Failed { timed_out: false });
            assert_eq!(
                failed_upstream.route_outcome,
                CanonicalRouteOutcome::UpstreamFailure
            );
            assert_eq!(
                failed_upstream.backend_outcome,
                CanonicalBackendOutcome::UpstreamFailure
            );
            assert_eq!(failed_upstream.rejection_kind, None);
        }

        #[test]
        fn proxy_error_classification_distinguishes_timeout_overload_and_upstream_failures() {
            let timeout = classify_proxy_error_outcome(&ProxyError::Timeout, None);
            assert_eq!(timeout.route_outcome, CanonicalRouteOutcome::Timeout);
            assert_eq!(timeout.backend_outcome, CanonicalBackendOutcome::Timeout);

            let overload = classify_proxy_error_outcome(
                &ProxyError::Pool(PoolError::BackendOverloaded("busy".to_string())),
                Some(OverloadShedReason::BackendInflight),
            );
            assert_eq!(overload.route_outcome, CanonicalRouteOutcome::OverloadShed);
            assert_eq!(
                overload.backend_outcome,
                CanonicalBackendOutcome::OverloadShed
            );
            assert_eq!(
                overload.overload_reason,
                Some(OverloadShedReason::BackendInflight)
            );

            let unrouted = classify_proxy_error_outcome(
                &ProxyError::Pool(PoolError::UnknownBackend("missing".to_string())),
                None,
            );
            assert_eq!(
                unrouted.route_outcome,
                CanonicalRouteOutcome::UpstreamFailure
            );
            assert_eq!(
                unrouted.backend_outcome,
                CanonicalBackendOutcome::UpstreamFailure
            );
        }

        #[test]
        fn outcome_reason_mapping_stays_canonical_for_admission_and_backend_failures() {
            let auth = classify_terminal_outcome(&TerminalState::Rejected(
                crate::runtime::connection::stream::RejectedState {
                    reason: RejectionReason::AuthDenied,
                    snapshot: terminal_snapshot_for_test(),
                },
            ));
            let overload = classify_terminal_outcome(&TerminalState::Rejected(
                crate::runtime::connection::stream::RejectedState {
                    reason: RejectionReason::Overloaded,
                    snapshot: terminal_snapshot_for_test(),
                },
            ));
            let backend = classify_terminal_outcome(&TerminalState::BackendFailed(
                crate::runtime::connection::stream::BackendFailedState {
                    reason: BackendFailureReason::UpstreamProtocol,
                    snapshot: terminal_snapshot_for_test(),
                },
            ));

            assert_eq!(auth.rejection_kind, Some(RejectionClass::AuthDenied));
            assert_eq!(overload.rejection_kind, Some(RejectionClass::OverloadShed));
            assert_eq!(
                backend.backend_failure_kind,
                Some(BackendFailureClass::Protocol)
            );
            assert_eq!(auth.route_outcome, CanonicalRouteOutcome::AuthDenied);
            assert_eq!(overload.route_outcome, CanonicalRouteOutcome::OverloadShed);
            assert_eq!(
                backend.route_outcome,
                CanonicalRouteOutcome::UpstreamFailure
            );
        }
    }

    mod metrics_recording {
        use super::*;

        #[test]
        fn observe_status_outcome_records_success_metrics() {
            let metrics = test_metrics();

            let decision = observe_status_outcome(
                &metrics,
                api_route_target(),
                api_backend_target(),
                Duration::from_millis(12),
                StatusCode::OK,
            );

            assert_eq!(decision.route_outcome, CanonicalRouteOutcome::Success);
            assert_eq!(
                metrics
                    .requests_success
                    .load(std::sync::atomic::Ordering::Relaxed),
                1
            );
            assert_eq!(
                metrics
                    .requests_failure
                    .load(std::sync::atomic::Ordering::Relaxed),
                0
            );
            assert_eq!(upstream_request_count(&metrics, "api", "2xx", "success"), 1);
            assert_eq!(
                backend_request_count(&metrics, "api", "backend-a", "2xx", "success"),
                1
            );
        }

        #[test]
        fn timeout_outcome_records_5xx_labels_and_matching_latency_bucket() {
            let metrics = test_metrics();

            let timeout = observe_proxy_error_outcome(
                &metrics,
                api_route_target(),
                api_backend_target(),
                Duration::from_millis(320),
                Some(StatusCode::GATEWAY_TIMEOUT),
                &ProxyError::Timeout,
                None,
            );

            assert_eq!(timeout.route_outcome, CanonicalRouteOutcome::Timeout);
            assert_eq!(upstream_request_count(&metrics, "api", "5xx", "timeout"), 1);
            assert_eq!(
                backend_request_count(&metrics, "api", "backend-a", "5xx", "timeout"),
                1
            );

            let latency = upstream_latency_stats(&metrics, "api", "timeout");
            assert_eq!(latency.count, 1);
            assert_eq!(latency.latency_ms_sum, 320);
            assert_eq!(latency.latency_buckets[7], 1);
        }

        #[test]
        fn success_outcome_records_2xx_labels_and_matching_latency_bucket() {
            let metrics = test_metrics();

            let success = observe_status_outcome(
                &metrics,
                api_route_target(),
                api_backend_target(),
                Duration::from_millis(12),
                StatusCode::OK,
            );

            assert_eq!(success.route_outcome, CanonicalRouteOutcome::Success);
            assert_eq!(upstream_request_count(&metrics, "api", "2xx", "success"), 1);
            assert_eq!(
                backend_request_count(&metrics, "api", "backend-a", "2xx", "success"),
                1
            );

            let latency = upstream_latency_stats(&metrics, "api", "success");
            assert_eq!(latency.count, 1);
            assert_eq!(latency.latency_ms_sum, 12);
            assert_eq!(latency.latency_buckets[3], 1);
        }

        #[test]
        fn observe_proxy_error_outcome_records_timeout_and_unrouted_failure() {
            let metrics = test_metrics();

            let timeout = observe_proxy_error_outcome(
                &metrics,
                api_route_target(),
                api_backend_target(),
                Duration::from_millis(50),
                Some(StatusCode::REQUEST_TIMEOUT),
                &ProxyError::Timeout,
                None,
            );
            let unrouted = observe_proxy_error_outcome(
                &metrics,
                RouteOutcomeTarget::UNROUTED,
                None,
                Duration::from_millis(5),
                Some(StatusCode::BAD_GATEWAY),
                &ProxyError::Transport("no route".into()),
                None,
            );

            assert_eq!(timeout.route_outcome, CanonicalRouteOutcome::Timeout);
            assert_eq!(
                unrouted.route_outcome,
                CanonicalRouteOutcome::UpstreamFailure
            );
            assert_eq!(
                metrics
                    .requests_failure
                    .load(std::sync::atomic::Ordering::Relaxed),
                2
            );
            assert_eq!(upstream_request_count(&metrics, "api", "4xx", "timeout"), 1);
            assert_eq!(
                upstream_request_count(&metrics, "unrouted", "5xx", "failure"),
                1
            );
        }

        #[test]
        fn observe_admission_outcome_records_overload_auth_and_rate_limit() {
            let metrics = test_metrics();

            let overload = observe_admission_outcome(
                &metrics,
                api_route_target(),
                api_backend_target(),
                Duration::from_millis(1),
                StatusCode::SERVICE_UNAVAILABLE,
                AdmissionOutcomeClass::OverloadShed {
                    reason: Some(OverloadShedReason::GlobalInflight),
                },
            );
            let auth = observe_admission_outcome(
                &metrics,
                api_route_target(),
                api_backend_target(),
                Duration::from_millis(2),
                StatusCode::UNAUTHORIZED,
                AdmissionOutcomeClass::AuthDenied,
            );
            let rate_limited = observe_admission_outcome(
                &metrics,
                api_route_target(),
                api_backend_target(),
                Duration::from_millis(3),
                StatusCode::TOO_MANY_REQUESTS,
                AdmissionOutcomeClass::RateLimited,
            );

            assert_eq!(overload.route_outcome, CanonicalRouteOutcome::OverloadShed);
            assert_eq!(auth.route_outcome, CanonicalRouteOutcome::AuthDenied);
            assert_eq!(
                rate_limited.route_outcome,
                CanonicalRouteOutcome::RateLimited
            );
            assert_eq!(
                metrics
                    .overload_shed
                    .load(std::sync::atomic::Ordering::Relaxed),
                1
            );
            assert_eq!(
                metrics
                    .overload_shed_global_inflight
                    .load(std::sync::atomic::Ordering::Relaxed),
                1
            );
            assert_eq!(
                upstream_request_count(&metrics, "api", "5xx", "overload_shed"),
                1
            );
            assert_eq!(upstream_request_count(&metrics, "api", "4xx", "failure"), 1);
            assert_eq!(
                upstream_request_count(&metrics, "api", "4xx", "rate_limited"),
                1
            );
        }

        #[test]
        fn request_outcome_observation_accepts_canonical_unrouted_failure_decision() {
            let metrics = test_metrics();
            let decision = RequestOutcomeClassification {
                route_outcome: CanonicalRouteOutcome::UpstreamFailure,
                backend_outcome: CanonicalBackendOutcome::UpstreamFailure,
                overload_reason: None,
                rejection_kind: None,
                backend_failure_kind: Some(BackendFailureClass::Transport),
                health_effect: HealthEffectHint::Failure {
                    reason: HealthFailureReason::Transport,
                },
            };

            let observed = observe_request_outcome(
                &metrics,
                RouteOutcomeTarget::UNROUTED,
                None,
                Duration::from_millis(7),
                Some(StatusCode::BAD_GATEWAY),
                decision,
            );

            assert_eq!(observed, decision);
            assert_eq!(
                metrics
                    .requests_failure
                    .load(std::sync::atomic::Ordering::Relaxed),
                1
            );
            assert_eq!(
                upstream_request_count(&metrics, "unrouted", "5xx", "failure"),
                1
            );
        }
    }

    mod backend_accounting_hooks {
        use super::*;

        #[test]
        fn backend_accounting_hooks_apply_canonical_success_and_failure_feedback() {
            let metrics = test_metrics();
            let pool = test_upstream_pool();

            {
                let guard = pool.read().expect("read");
                assert!(guard.begin_request_if_healthy(0));
            }
            finish_backend_request_accounting(BackendRequestFinishInput {
                upstream_pool: Some(&pool),
                backend_index: Some(0),
                elapsed: Duration::from_millis(20),
                status: Some(StatusCode::OK.as_u16()),
            });
            {
                let guard = pool.read().expect("read");
                let state = guard.backend_runtime_state(0).expect("backend state");
                assert_eq!(state.active_requests, 0);
                assert!(state.ewma_latency_ms.is_some());
            }

            let unhealthy = observe_backend_response_status(BackendHealthObservationInput {
                backend_addr: "backend-a",
                backend_index: 0,
                upstream_pool: Some(&pool),
                status: StatusCode::INTERNAL_SERVER_ERROR,
            });
            assert!(matches!(unhealthy, Some(HealthTransition::BecameUnhealthy)));

            let healthy = observe_backend_response_status(BackendHealthObservationInput {
                backend_addr: "backend-a",
                backend_index: 0,
                upstream_pool: Some(&pool),
                status: StatusCode::OK,
            });
            assert!(matches!(healthy, Some(HealthTransition::BecameHealthy)));

            let classified = impulse_errors::classify_upstream_proxy_error(&ProxyError::Timeout)
                .expect("classified timeout");
            let transition = observe_classified_backend_failure(ClassifiedBackendFailureInput {
                metrics_phase: "bootstrap",
                upstream_name: "api",
                backend_addr: "backend-a",
                backend_index: 0,
                upstream_pool: Some(&pool),
                metrics: &metrics,
                classified: &classified,
            });
            assert!(matches!(
                transition,
                Some(HealthTransition::BecameUnhealthy)
            ));
            assert_eq!(
                metrics
                    .health_failure_timeout
                    .load(std::sync::atomic::Ordering::Relaxed),
                1
            );
        }

        #[test]
        fn backend_request_cleanup_runs_only_when_the_caller_marks_it_required() {
            let pool = test_upstream_pool();
            {
                let guard = pool.read().expect("read");
                assert!(guard.begin_request_if_healthy(0));
            }

            let finalized = finalize_backend_request_cleanup(
                BackendRequestFinishInput {
                    upstream_pool: Some(&pool),
                    backend_index: Some(0),
                    elapsed: Duration::from_millis(15),
                    status: Some(StatusCode::OK.as_u16()),
                },
                false,
            );
            assert!(!finalized);
            {
                let guard = pool.read().expect("read");
                let state = guard.backend_runtime_state(0).expect("backend state");
                assert_eq!(state.active_requests, 1);
            }

            let finalized = finalize_backend_request_cleanup(
                BackendRequestFinishInput {
                    upstream_pool: Some(&pool),
                    backend_index: Some(0),
                    elapsed: Duration::from_millis(15),
                    status: Some(StatusCode::OK.as_u16()),
                },
                true,
            );
            assert!(finalized);
            {
                let guard = pool.read().expect("read");
                let state = guard.backend_runtime_state(0).expect("backend state");
                assert_eq!(state.active_requests, 0);
            }
        }

        #[test]
        fn classified_backend_failure_metrics_follow_the_shared_health_mapping_contract() {
            let metrics = test_metrics();

            let tls = impulse_errors::classify_upstream_proxy_error(&ProxyError::Tls(
                "unknown issuer".to_string(),
            ))
            .expect("classified tls");
            let tls_reason = record_classified_backend_failure_metrics(
                "forwarding",
                "api",
                "backend-a",
                &metrics,
                &tls,
            );
            assert_eq!(tls_reason, None);
            assert_eq!(
                metrics
                    .health_failure_tls
                    .load(std::sync::atomic::Ordering::Relaxed),
                0
            );

            let transport = impulse_errors::classify_upstream_proxy_error(&ProxyError::Transport(
                "connection reset by peer".to_string(),
            ))
            .expect("classified transport");
            let transport_reason = record_classified_backend_failure_metrics(
                "forwarding",
                "api",
                "backend-a",
                &metrics,
                &transport,
            );
            assert_eq!(transport_reason, Some(HealthFailureReason::Transport));
            assert_eq!(
                metrics
                    .health_failure_transport
                    .load(std::sync::atomic::Ordering::Relaxed),
                1
            );
        }
    }
}
