//! Protocol-neutral request execution and shared routing for Impulse.
//!
//! Protocol listeners adapt requests into the internal edge core. Listener
//! startup and process-facing integration are exposed under [`runtime::ingress`]
//! instead of the crate root.
#![warn(unreachable_pub)]

#[cfg(test)]
extern crate self as impulse_edge;

mod body;
pub mod cid_radix;
mod constants;
mod edge_core;
mod hash;
pub mod metrics;
mod observability;
mod pingora_ingress;
mod quic_listener;
pub mod resilience;
pub mod runtime;
pub mod watchdog;

pub(crate) use body::ChannelBody;
pub use constants::{
    BACKEND_TIMEOUT_SECS, MAX_DATAGRAM_SIZE_BYTES, MAX_REQUEST_BODY_BYTES,
    MAX_STREAMS_PER_CONNECTION, MAX_UDP_PAYLOAD_BYTES, QUIC_IDLE_TIMEOUT_MS, QUIC_INITIAL_MAX_DATA,
    QUIC_INITIAL_MAX_STREAMS_BIDI, QUIC_INITIAL_MAX_STREAMS_UNI, QUIC_INITIAL_STREAM_DATA,
    REQUEST_TIMEOUT_SECS, UDP_READ_TIMEOUT_MS,
};
pub use edge_core::routing;
pub(crate) use hash::REQUEST_ID_COUNTER;
pub use hash::{stable_hash_socket_addr, stable_hash64};
pub use metrics::{Metrics, OverloadShedReason, RouteOutcome};
pub use observability::{
    AdmissionDecisionReason, AdmissionOverloadCause, BackendHealthReason, HedgeDecisionReason,
    MetricReasonLabels, OperationalEventContext, RequestOutcomeReason, RetryDecisionReason,
    backend_health_reason,
};
