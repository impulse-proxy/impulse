//! Canonical request/response conversion surface for upstream bridging.
//!
//! Consumers should use:
//! - [`http3`] for HTTP/3 request translation into upstream protocols
//! - [`request`] for application-owned upstream header policy
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
pub mod http3;
mod input;
pub mod request;
pub mod response;
pub mod websocket;

pub use input::{
    ForwardedHeaderMode, ForwardingPolicyInput, HostPolicyInput, HostPolicyMode,
    NormalizationInput, RequestFramingInput, TrailerPolicyInput, UpstreamScheme,
    UpstreamTargetInput,
};
