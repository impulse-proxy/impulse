//! HTTP/3 ingress adapter for Impulse.
//!
//! Protocol-neutral request execution remains owned by `impulse-edge`.

#![forbid(unsafe_code)]
#![deny(unused_crate_dependencies)]
#![warn(unreachable_pub)]

mod admission;
mod connection;
mod socket;
mod stream;
mod tls;
mod worker;

pub use admission::{
    ConnectionAdmissionAdapter, ConnectionAdmissionRejection, admit_initial_connection,
};
pub use connection::{QuicConnection, QuicConnectionErrorSnapshot};
pub use socket::{UdpSocketConfig, bind_udp_socket};
pub use stream::{
    RequestBodyState, RequestMode, ResponseEmissionState, StreamAdmissionState, StreamPhase,
};
pub use tls::{Http3TlsSettings, build_http3_tls_config};
pub use worker::{
    ListenerWorkerGroupConfig, PacketWorker, PacketWorkerObserver, ShutdownSignal,
    release_shard_queue_bytes, shard_index_for_peer, spawn_packet_worker_group,
    try_reserve_shard_queue_bytes,
};
