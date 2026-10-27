//! Bounded observability vocabulary shared by Impulse runtime crates.

#![forbid(unsafe_code)]
#![deny(unused_crate_dependencies)]
#![warn(unreachable_pub)]

mod event;
mod labels;
mod metrics;

pub use event::{MetricReasonLabels, OperationalEventContext};
pub use labels::{
    AdmissionDecisionReason, AdmissionOverloadCause, BackendHealthReason, HedgeDecisionReason,
    QuotaBackendHealthReason, QuotaPolicyDecision, QuotaPolicyReason, RequestOutcomeReason,
    RetryDecisionReason, RuntimeOperationOutcomeReason, RuntimeRejectionReason,
    backend_health_reason,
};
pub use metrics::{
    BackendRequestCountKey, DiscoveryRefreshUpdate, Metrics, OverloadShedReason,
    PingoraDiscoveryRefreshOutcome, RequestLatencyStats, ResponseCacheOutcome,
    ResponseCompressionAction, ResponseCompressionBypassReason, RouteOutcome,
    UpstreamRequestCountKey, UpstreamRequestLatencyKey,
};
