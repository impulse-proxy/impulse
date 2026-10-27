//! Dependency-light contracts shared across Impulse runtime crates.
//!
//! This crate contains data types only. Runtime services, configuration
//! loading, protocol implementations, and infrastructure dependencies belong
//! to their owning crates.

#![warn(unreachable_pub)]

mod identity;
mod request;

pub use identity::{BackendIdentity, GenerationId, IngressProtocol, RequestId};
pub use request::{
    AuthChallengeKind, BoundedRejectionResponse, HeaderMutation, HeaderMutationRef,
    OverloadDecision, OverloadDecisionReason, RateLimitedDecision, RequestDecision,
    UnauthorizedDecision,
};
