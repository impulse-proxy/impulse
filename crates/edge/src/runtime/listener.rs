use std::{
    collections::HashMap,
    net::{SocketAddr, UdpSocket},
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

use impulse_config::{
    backend_endpoint::BackendEndpoint,
    runtime::{ListenerRuntimeConfig, RuntimeBackendTlsPolicy, RuntimeUpstreamPolicy},
};
use impulse_lb::pingora_backend::SharedPingoraLoadBalancingRuntimeState;
use impulse_transport::{SharedDnsResolver, UpstreamTransportPool};
use tokio::sync::Semaphore;

use crate::{
    Metrics,
    cid_radix::CidRadix,
    constants::MAX_DATAGRAM_SIZE_BYTES,
    resilience::runtime::RuntimeResilience,
    routing::index::RouteIndex,
    runtime::{
        bundle::RuntimeBundleHandle, connection::quic::QuicConnection,
        tls::store::ListenerTlsReloadStore,
    },
    watchdog::coordinator::WatchdogCoordinator,
};

/// Shared cancellation signal for the QUIC workers in a listener group.
#[derive(Clone, Debug)]
pub struct ShutdownSignal(Arc<AtomicBool>);

impl ShutdownSignal {
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    pub fn load(&self, ordering: std::sync::atomic::Ordering) -> bool {
        self.0.load(ordering)
    }

    pub fn store(&self, value: bool, ordering: std::sync::atomic::Ordering) {
        self.0.store(value, ordering);
    }
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

/// Live listener worker state for the edge data plane.
///
/// This type owns the socket, routing/runtime handles, connection tables, and
/// per-listener limits needed by a running worker. Runtime generation assembly
/// happens in [`crate::runtime::bundle`]; request execution details live under
/// [`crate::runtime::connection`].
pub struct QUICListener {
    pub socket: UdpSocket,
    pub local_addr: SocketAddr,
    pub config: ListenerRuntimeConfig,
    pub listener_label: String,
    pub listener_tls_store: Arc<ListenerTlsReloadStore>,
    pub tls_reload_generation: u64,
    pub runtime_bundle: Option<Arc<RuntimeBundleHandle>>,
    pub runtime_generation: u64,
    pub response_cache_namespace: u64,
    pub quic_config: quiche::Config,
    pub h3_config: Arc<quiche::h3::Config>,
    pub transport_pool: Arc<UpstreamTransportPool>,
    pub backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
    pub backend_dns_resolver: SharedDnsResolver,
    pub upstream_policies: Arc<HashMap<String, RuntimeUpstreamPolicy>>,
    pub pingora_load_balancing: SharedPingoraLoadBalancingRuntimeState<RuntimeBackendTlsPolicy>,
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

impl QUICListener {
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
