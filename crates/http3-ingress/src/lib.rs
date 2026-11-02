//! HTTP/3 ingress adapter for Impulse.
//!
//! Protocol-neutral request execution remains owned by `impulse-edge`.

#![forbid(unsafe_code)]
#![deny(unused_crate_dependencies)]
#![warn(unreachable_pub)]

mod connection;
mod socket;
mod stream;
mod worker;

pub use connection::{QuicConnection, QuicConnectionErrorSnapshot};
pub use socket::{UdpSocketConfig, bind_udp_socket};
pub use stream::{
    RequestBodyState, RequestMode, ResponseEmissionState, StreamAdmissionState, StreamPhase,
};
pub use worker::{
    ListenerWorkerGroupConfig, PacketWorker, PacketWorkerObserver, ShutdownSignal,
    release_shard_queue_bytes, shard_index_for_peer, spawn_packet_worker_group,
    try_reserve_shard_queue_bytes,
};
