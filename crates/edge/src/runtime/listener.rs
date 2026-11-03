use std::{
    collections::HashMap,
    net::{SocketAddr, UdpSocket},
    sync::Arc,
    time::{Duration, Instant},
};

use impulse_config::runtime::{ListenerRuntimeConfig, RuntimeUpstreamPolicy};
pub use impulse_http3_ingress::ShutdownSignal;
use impulse_operations::watchdog::WatchdogCoordinator;
use tokio::sync::Semaphore;

use crate::{
    Metrics,
    cid_radix::CidRadix,
    constants::MAX_DATAGRAM_SIZE_BYTES,
    resilience::runtime::RuntimeResilience,
    routing::index::RouteIndex,
    runtime::{
        bundle::{ActiveRuntimeGeneration, RuntimeBundleHandle},
        connection::quic::QuicConnection,
        shared_state::SharedRuntimeState,
    },
};

pub enum ListenerRuntimeState {
    Standalone(Arc<SharedRuntimeState>),
    Managed(ActiveRuntimeGeneration),
}

impl ListenerRuntimeState {
    pub fn shared_state(&self) -> &SharedRuntimeState {
        match self {
            Self::Standalone(state) => state,
            Self::Managed(runtime) => runtime.bundle().shared_state.as_ref(),
        }
    }

    pub fn generation(&self) -> u64 {
        match self {
            Self::Standalone(_) => 0,
            Self::Managed(runtime) => runtime.generation(),
        }
    }
}

/// Live listener worker state for the edge data plane.
///
/// This type owns the socket, routing/runtime handles, connection tables, and
/// per-listener limits needed by a running worker. Runtime generation assembly
/// happens in [`crate::runtime::bundle`]; request execution details live under
/// [`crate::runtime::connection`].
pub struct Http3Service {
    pub socket: UdpSocket,
    pub local_addr: SocketAddr,
    pub config: ListenerRuntimeConfig,
    pub listener_label: String,
    pub tls_reload_generation: u64,
    pub runtime_bundle: Option<Arc<RuntimeBundleHandle>>,
    pub runtime_state: ListenerRuntimeState,
    pub quic_config: quiche::Config,
    pub h3_config: Arc<quiche::h3::Config>,
    pub upstream_policies: Arc<HashMap<String, RuntimeUpstreamPolicy>>,
    pub upstream_inflight: HashMap<String, Arc<Semaphore>>,
    pub global_inflight: Arc<Semaphore>,
    pub(crate) routing_index: Arc<RouteIndex>,
    pub metrics: Arc<Metrics>,
    pub resilience: Arc<RuntimeResilience>,
    pub watchdog: Arc<WatchdogCoordinator>,
    pub shutdown: ShutdownSignal,
    pub draining: bool,
    pub drain_start: Option<Instant>,
    pub watchdog_worker_drained: bool,
    pub drain_timeout: Duration,
    pub backend_timeout: Duration,
    pub backend_body_idle_timeout: Duration,
    pub backend_body_total_timeout: Duration,
    pub client_body_idle_timeout: Duration,
    pub backend_total_request_timeout: Duration,
    pub inflight_acquire_wait: Duration,
    pub max_active_connections: usize,
    pub max_streams_per_connection: usize,
    pub max_request_body_bytes: usize,
    pub max_response_body_bytes: usize,
    pub request_buffer_global_cap_bytes: usize,
    pub unknown_length_response_prebuffer_bytes: usize,
    pub require_client_cert: bool,

    pub(crate) recv_buf: Box<[u8; MAX_DATAGRAM_SIZE_BYTES]>,
    pub(crate) send_buf: Box<[u8; MAX_DATAGRAM_SIZE_BYTES]>,

    pub(crate) connections: HashMap<Arc<[u8]>, QuicConnection>, // KEY: SCID(server connection id)
    pub(crate) cid_routes: HashMap<Arc<[u8]>, Arc<[u8]>>, // KEY: alias SCID, VALUE: primary SCID
    pub(crate) peer_routes: HashMap<SocketAddr, Arc<[u8]>>, // KEY: peer address, VALUE: primary SCID
    pub(crate) cid_radix: CidRadix,
    pub(crate) conn_rate_limiter: crate::runtime::connection::TokenBucket,
    pub(crate) source_conn_rate_limiter: crate::runtime::connection::PerSourceTokenBucket,
}

impl Http3Service {
    pub fn connections(&self) -> &HashMap<Arc<[u8]>, QuicConnection> {
        &self.connections
    }

    pub fn cid_routes(&self) -> &HashMap<Arc<[u8]>, Arc<[u8]>> {
        &self.cid_routes
    }

    pub fn peer_routes(&self) -> &HashMap<SocketAddr, Arc<[u8]>> {
        &self.peer_routes
    }

    pub fn cid_radix(&self) -> &CidRadix {
        &self.cid_radix
    }
}
