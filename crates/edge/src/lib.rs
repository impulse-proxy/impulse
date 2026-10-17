//! Public API for the Impulse edge runtime.
//!
//! The crate root exposes the small set of entrypoints that other crates should
//! depend on directly. Listener orchestration, runtime wiring, and control-plane
//! mechanics stay behind internal subsystem modules.
#![warn(unreachable_pub)]

#[cfg(test)]
extern crate self as impulse_edge;

pub mod body;
pub mod cid_radix;
mod constants;
mod hash;
pub mod metrics;
mod observability;
mod pingora_ingress;
mod quic_listener;
#[allow(dead_code)] // Introduced before protocol adapters migrate to the shared contracts.
mod request_pipeline;
pub mod resilience;
pub mod routing;
pub mod runtime;
pub mod watchdog;

pub use body::ChannelBody;
pub use constants::{
    BACKEND_TIMEOUT_SECS, MAX_DATAGRAM_SIZE_BYTES, MAX_INFLIGHT_PER_BACKEND,
    MAX_REQUEST_BODY_BYTES, MAX_RESPONSE_BODY_BYTES, MAX_STREAMS_PER_CONNECTION,
    MAX_UDP_PAYLOAD_BYTES, QUIC_IDLE_TIMEOUT_MS, QUIC_INITIAL_MAX_DATA,
    QUIC_INITIAL_MAX_STREAMS_BIDI, QUIC_INITIAL_MAX_STREAMS_UNI, QUIC_INITIAL_STREAM_DATA,
    REQUEST_BUFFERED_CHUNK_BYTES_LIMIT, REQUEST_TIMEOUT_SECS, UDP_READ_TIMEOUT_MS,
};
pub(crate) use hash::REQUEST_ID_COUNTER;
pub use hash::{stable_hash_socket_addr, stable_hash64};
pub use metrics::{Metrics, OverloadShedReason, RouteOutcome};
pub use observability::{
    AdmissionDecisionReason, AdmissionOverloadCause, BackendHealthReason, HedgeDecisionReason,
    MetricReasonLabels, OperationalEventContext, RequestOutcomeReason, RetryDecisionReason,
    backend_health_reason,
};
pub use pingora_ingress::{PingoraListenerTask, spawn_pingora_ingress_listener};
pub use quic_listener::{
    ListenerWorkerGroupConfig, ListenerWorkerRuntimeState, configure_async_runtime,
    release_shard_queue_bytes, shard_index_for_peer, spawn_listener_worker_group,
    try_reserve_shard_queue_bytes,
};
