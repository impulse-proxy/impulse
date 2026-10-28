//! Canonical request/response conversion surface for upstream bridging.
//!
//! Consumers should use:
//! - [`request`] for upstream request construction and header policy application
//! - [`response`] for downstream response normalization and emission policy
//! - [`websocket`] for websocket and upgrade helpers
//!
//! Protocol-specific H1/H2 builders are internal implementation details behind
//! the canonical request-building surface.

mod forwarded;
mod h3_to_h1;
mod h3_to_h2;
mod headers;
mod host;
mod input;
pub mod request;
pub mod response;
pub mod websocket;

pub use input::{
    ForwardedHeaderMode, ForwardingPolicyInput, HostPolicyInput, HostPolicyMode,
    NormalizationInput, RequestFramingInput, TrailerPolicyInput, UpstreamScheme,
    UpstreamTargetInput,
};
