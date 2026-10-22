//! Shared error and error-policy contract for Impulse runtime crates.
//!
//! Consumers should depend on the re-exported error types and classifier
//! entrypoints from this crate root instead of reaching into module internals.
//! Backend-selection policy types remain owned by `impulse-lb`.

mod bridge;
mod pool;
mod proxy;
mod retry;
mod upstream;

pub use bridge::BridgeError;
pub use pool::PoolError;
pub use proxy::{
    ClassifiedUpstreamProxyError, ProxyError, UpstreamProxyErrorKind, classify_upstream_proxy_error,
};
pub use retry::{
    HedgeOutcomeTelemetryReason, HedgePolicyDecision, HedgePolicyDenialReason, HedgePolicyFacts,
    HedgePrimaryState, HedgeTriggerTelemetryReason, RetryAttemptTelemetryReason,
    RetryPolicyDecision, RetryPolicyDenialReason, RetryPolicyFacts, UpstreamRetryReason,
    UpstreamRetryability, UpstreamTerminalErrorKind, classify_retryability, evaluate_hedge_policy,
    evaluate_retry_policy, is_idempotent_method,
};
pub use upstream::{
    UpstreamErrorCategory, UpstreamErrorClassification, UpstreamHealthFailureMapping,
    UpstreamTlsReason, classify_upstream_error_detail,
};
