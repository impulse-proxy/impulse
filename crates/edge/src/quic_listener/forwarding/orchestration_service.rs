use impulse_errors::{ClassifiedUpstreamProxyError, PoolError, ProxyError};
use log::error;

use crate::{
    Metrics,
    runtime::connection::{
        outcome::{BackendOutcomeTarget, RouteOutcomeTarget},
        request::RequestEnvelope,
        response::ForwardingPolicyTelemetry,
        stream::{BackendFailureReason, RejectionReason, StreamPhase, TerminalReason},
    },
};

/// Common forwarding outcome and telemetry orchestration independent of the
/// ingress protocol and upstream transport bridge.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ForwardingOrchestrationService;

impl ForwardingOrchestrationService {
    pub(super) fn terminalize(
        request: &mut RequestEnvelope,
        reason: TerminalReason,
        metrics: &Metrics,
    ) -> StreamPhase {
        request.transition_to_terminal_with_cleanup(reason, metrics)
    }

    pub(super) fn backend_failure_reason(error: &ProxyError) -> BackendFailureReason {
        match error {
            ProxyError::Timeout => BackendFailureReason::UpstreamTimeout,
            ProxyError::Tls(_) => BackendFailureReason::UpstreamTls,
            ProxyError::Transport(_) | ProxyError::Pool(_) => {
                BackendFailureReason::UpstreamTransport
            }
            ProxyError::Protocol(_) => BackendFailureReason::UpstreamProtocol,
            ProxyError::Bridge(_) => BackendFailureReason::UpstreamBridge,
        }
    }

    pub(super) fn rejection_reason(status: http::StatusCode) -> RejectionReason {
        match status {
            http::StatusCode::PAYLOAD_TOO_LARGE => RejectionReason::RequestBodyTooLarge,
            http::StatusCode::TOO_MANY_REQUESTS => RejectionReason::RateLimited,
            http::StatusCode::SERVICE_UNAVAILABLE => RejectionReason::Overloaded,
            http::StatusCode::BAD_REQUEST => RejectionReason::ValidationFailed,
            _ => RejectionReason::ValidationFailed,
        }
    }

    pub(super) fn record_policy_metrics(metrics: &Metrics, policy: &ForwardingPolicyTelemetry) {
        if let Some(reason) = policy.hedge.trigger_reason {
            metrics.policy_observations().inc_hedge_trigger(reason);
        }
        if let Some(reason) = policy.hedge.outcome_reason {
            metrics.policy_observations().inc_hedge_outcome(reason);
        }
        if policy.hedge.primary_late_ms > 0 {
            metrics
                .policy_observations()
                .observe_hedge_primary_late_ms(policy.hedge.primary_late_ms);
        }
        if let Some(reason) = policy.retry.attempt_reason {
            metrics.policy_observations().inc_retry_attempt(reason);
        }
        if let Some(reason) = policy.retry.denial_reason {
            metrics.policy_observations().inc_retry_denied(reason);
        }
    }

    pub(super) fn log_classified_upstream_failure(
        phase: &str,
        request_id: Option<u64>,
        upstream_name: Option<&str>,
        backend_addr: &str,
        classified: &ClassifiedUpstreamProxyError,
    ) {
        let request_id = request_id
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        let upstream_name = upstream_name.unwrap_or("-");
        match classified.health_failure {
            Some(health_mapping) => error!(
                "phase={} request_id={} upstream={} backend={} upstream failure kind={:?} retryability={:?} health_reason={:?} metrics_reason={} detail={}",
                phase,
                request_id,
                upstream_name,
                backend_addr,
                classified.kind,
                classified.retryability,
                health_mapping.failure_reason,
                health_mapping.metrics_reason,
                classified.detail
            ),
            None => error!(
                "phase={} request_id={} upstream={} backend={} upstream failure kind={:?} retryability={:?} detail={}",
                phase,
                request_id,
                upstream_name,
                backend_addr,
                classified.kind,
                classified.retryability,
                classified.detail
            ),
        }
    }

    pub(super) fn is_internal_pool_control_error(error: &PoolError) -> bool {
        matches!(
            error,
            PoolError::InflightLimiterClosed | PoolError::UnknownBackend(_)
        )
    }

    pub(super) fn route_target(request: &RequestEnvelope) -> RouteOutcomeTarget<'_> {
        RouteOutcomeTarget {
            route: request.upstream_name.as_deref().unwrap_or("unrouted"),
        }
    }

    pub(super) fn backend_target(request: &RequestEnvelope) -> Option<BackendOutcomeTarget<'_>> {
        request
            .upstream_name
            .as_deref()
            .map(|upstream| BackendOutcomeTarget {
                upstream,
                backend_addr: request.backend_addr.as_deref(),
                backend_index: request.backend_index,
            })
    }
}
