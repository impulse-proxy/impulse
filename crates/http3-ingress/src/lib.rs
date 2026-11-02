//! HTTP/3 ingress adapter for Impulse.
//!
//! Protocol-neutral request execution remains owned by `impulse-edge`.

#![forbid(unsafe_code)]
#![deny(unused_crate_dependencies)]
#![warn(unreachable_pub)]

mod admission;
mod connection;
mod request;
mod response;
mod socket;
mod stream;
mod tls;
mod tunnel;
mod worker;

pub use admission::{
    ConnectionAdmissionAdapter, ConnectionAdmissionRejection, admit_initial_connection,
};
pub use connection::{QuicConnection, QuicConnectionErrorSnapshot};
pub use request::{
    Http3HeaderLookup, Http3RequestExecutionInput, Http3RequestHead, Http3RequestLimits,
    Http3RequestParseError, Http3RequestService, extract_header_value, generated_span_id,
    generated_trace_id, parse_request_head, parse_traceparent,
};
pub use response::{
    cancel_response_stream, response_header_block, response_headers_with_defaults,
    send_response_body, send_response_head, send_response_trailers, write_complete_response,
    write_overload_response, write_simple_response,
};
pub use socket::{UdpSocketConfig, bind_udp_socket};
pub use stream::{
    RequestBodyState, RequestMode, ResponseEmissionState, StreamAdmissionState, StreamPhase,
};
pub use tls::{Http3TlsSettings, build_http3_tls_config};
pub use tunnel::{
    adapt_h1_websocket_headers, adapt_h1_websocket_method, classify_tunnel,
    downstream_tunnel_status, requires_h1_websocket_adaptation, tunnel_cache_flags,
    tunnel_response_established,
};
pub use worker::{
    ListenerWorkerGroupConfig, PacketWorker, PacketWorkerObserver, ShutdownSignal,
    release_shard_queue_bytes, shard_index_for_peer, spawn_packet_worker_group,
    try_reserve_shard_queue_bytes,
};
