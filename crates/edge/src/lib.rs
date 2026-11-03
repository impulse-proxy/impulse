//! Protocol-neutral request execution and shared routing for Impulse.
//!
//! Protocol listeners adapt requests into the internal edge core. Listener
//! startup and process-facing integration are exposed under [`runtime::ingress`]
//! instead of the crate root.
#![warn(unreachable_pub)]

#[cfg(test)]
extern crate self as impulse_edge;

mod body;
mod cid_radix;
pub mod constants;
mod edge_core;
mod hash;
mod observability;
mod pingora_ingress;
mod quic_listener;
pub mod resilience;
pub mod runtime;

pub(crate) use body::ChannelBody;
pub use edge_core::routing;
pub(crate) use hash::{REQUEST_ID_COUNTER, stable_hash_socket_addr, stable_hash64};
pub(crate) use impulse_observability::{Metrics, OverloadShedReason, RouteOutcome};
pub use runtime::supervisor::RuntimeSupervisor;
