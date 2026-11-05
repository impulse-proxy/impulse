//! Dependency-light contracts shared across Impulse runtime crates.
//!
//! This crate contains data types only. Runtime services, configuration
//! loading, protocol implementations, and infrastructure dependencies belong
//! to their owning crates.

#![forbid(unsafe_code)]
#![deny(unused_crate_dependencies)]
#![warn(unreachable_pub)]

mod identity;
mod outcome;
mod plugin;
mod request;
mod tunnel;

pub use identity::{BackendIdentity, IngressProtocol, RequestId};
pub use outcome::{
    AdmissionOutcomeKind, AlternateBackendFailureReason, BackendFailureReason,
    BackendHealthObservationOutcome, BackendHealthObservationSource, CancellationReason,
    CompletionReason, HealthFailureReason, HedgeOutcomeTelemetryReason, HedgePolicyDenialReason,
    HedgeTriggerTelemetryReason, RejectionReason, RetryAttemptTelemetryReason,
    RetryPolicyDenialReason, TerminalReason, TimeoutReason, UpstreamRetryReason,
    UpstreamTerminalErrorKind,
};
pub use plugin::{
    PluginActivationOutcome, PluginCacheView, PluginConnectionView, PluginExecutionObservation,
    PluginExecutionOutcome, PluginHeaderLookup, PluginHeaderMutation, PluginHeaderMutationError,
    PluginKind, PluginPhase, PluginRejection, PluginRejectionError, PluginRejectionReason,
    PluginRequestView, PluginResponseHeader, PluginResponseMetadataView, PluginResponseView,
    PluginScope, PluginStateOwnership,
};
pub use request::{
    AuthChallengeKind, BoundedRejectionResponse, HeaderMutation, HeaderMutationRef,
    OverloadDecision, OverloadDecisionReason, RateLimitedDecision, RequestDecision,
    UnauthorizedDecision,
};
pub use tunnel::TunnelMode;
