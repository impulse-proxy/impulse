//! Dependency-light contracts shared across Impulse runtime crates.
//!
//! This crate contains data types only. Runtime services, configuration
//! loading, protocol implementations, and infrastructure dependencies belong
//! to their owning crates.

#![warn(unreachable_pub)]

mod identity;
mod outcome;
mod request;

pub use identity::{BackendIdentity, GenerationId, IngressProtocol, RequestId};
pub use outcome::{
    AlternateBackendFailureReason, BackendFailureReason, CancellationReason, HealthFailureReason,
    HedgeOutcomeTelemetryReason, HedgePolicyDenialReason, HedgeTriggerTelemetryReason,
    RejectionReason, RetryAttemptTelemetryReason, RetryPolicyDenialReason, TimeoutReason,
    UpstreamRetryReason, UpstreamTerminalErrorKind,
};
pub use request::{
    AuthChallengeKind, BoundedRejectionResponse, HeaderMutation, HeaderMutationRef,
    OverloadDecision, OverloadDecisionReason, RateLimitedDecision, RequestDecision,
    UnauthorizedDecision,
};
