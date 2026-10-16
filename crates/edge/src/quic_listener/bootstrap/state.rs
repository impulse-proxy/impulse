use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use impulse_config::{
    backend_endpoint::BackendEndpoint,
    runtime::{ListenerRuntimeConfig, RuntimeUpstreamPolicy},
};
use impulse_lb::upstream_pool::UpstreamPool;
use impulse_transport::UpstreamTransportPool;

use crate::{
    Metrics,
    resilience::runtime::RuntimeResilience,
    routing::index::RouteIndex,
    runtime::{
        bundle::RuntimeBundleHandle, shared_state::SharedRuntimeState,
        tls::store::ListenerTlsReloadStore,
    },
};

pub(in crate::quic_listener) struct BootstrapConnectionState {
    pub(in crate::quic_listener) runtime_generation: crate::runtime::activation::GenerationId,
    pub(in crate::quic_listener) alt_svc_value: String,
    pub(in crate::quic_listener) backend_timeout: Duration,
    pub(in crate::quic_listener) max_request_body_bytes: usize,
    pub(in crate::quic_listener) max_response_body_bytes: usize,
    pub(in crate::quic_listener) max_connections: usize,
    pub(in crate::quic_listener) new_connections_per_sec: u32,
    pub(in crate::quic_listener) new_connections_burst: u32,
    pub(in crate::quic_listener) connection_timeout: Duration,
    pub(in crate::quic_listener) listener_tls_store: Arc<ListenerTlsReloadStore>,
    pub(in crate::quic_listener) transport_pool: Arc<UpstreamTransportPool>,
    pub(in crate::quic_listener) backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
    pub(in crate::quic_listener) upstream_policies: Arc<HashMap<String, RuntimeUpstreamPolicy>>,
    pub(in crate::quic_listener) metrics: Arc<Metrics>,
    pub(in crate::quic_listener) resilience: Arc<RuntimeResilience>,
    pub(in crate::quic_listener) upstream_pools: HashMap<String, Arc<RwLock<UpstreamPool>>>,
    pub(in crate::quic_listener) routing_index: Arc<RouteIndex>,
}

pub(in crate::quic_listener) struct BootstrapStartupState {
    pub(in crate::quic_listener) listener_config: ListenerRuntimeConfig,
    pub(in crate::quic_listener) listener_tls_store: Arc<ListenerTlsReloadStore>,
    pub(in crate::quic_listener) transport_pool: Arc<UpstreamTransportPool>,
    pub(in crate::quic_listener) backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
    pub(in crate::quic_listener) upstream_policies: Arc<HashMap<String, RuntimeUpstreamPolicy>>,
    pub(in crate::quic_listener) metrics: Arc<Metrics>,
    pub(in crate::quic_listener) resilience: Arc<RuntimeResilience>,
    pub(in crate::quic_listener) upstream_pools: HashMap<String, Arc<RwLock<UpstreamPool>>>,
    pub(in crate::quic_listener) routing_index: Arc<RouteIndex>,
}

pub(in crate::quic_listener) fn build_bootstrap_startup_state(
    config: &ListenerRuntimeConfig,
    shared_state: &SharedRuntimeState,
) -> BootstrapStartupState {
    let shared = shared_state.shared_services();
    let generation = shared_state.generation_state();
    BootstrapStartupState {
        listener_config: config.clone(),
        listener_tls_store: Arc::clone(&shared.listener_tls_store),
        transport_pool: Arc::clone(&shared.transport_pool),
        backend_endpoints: Arc::clone(&generation.backend_endpoints),
        upstream_policies: Arc::clone(&generation.upstream_policies),
        metrics: Arc::clone(&shared.metrics),
        resilience: Arc::clone(&generation.resilience),
        upstream_pools: generation.upstream_pools.clone(),
        routing_index: Arc::clone(&generation.routing_index),
    }
}

pub(in crate::quic_listener) fn bootstrap_connection_state(
    listener_label: &str,
    runtime_bundle: Option<&Arc<RuntimeBundleHandle>>,
    startup: &BootstrapStartupState,
) -> Option<BootstrapConnectionState> {
    let (
        runtime_generation,
        listener_config,
        listener_tls_store,
        transport_pool,
        backend_endpoints,
        upstream_policies,
        metrics,
        resilience,
        upstream_pools,
        routing_index,
    ) = if let Some(handle) = runtime_bundle {
        let runtime = handle.current_view();
        let shared = runtime.shared_services();
        let generation = runtime.state();
        (
            runtime.generation(),
            runtime.listener_runtime_config(listener_label)?,
            shared.listener_tls_store.clone(),
            shared.transport_pool.clone(),
            generation.backend_endpoints.clone(),
            generation.upstream_policies.clone(),
            shared.metrics.clone(),
            generation.resilience.clone(),
            generation.upstream_pools.clone(),
            generation.routing_index.clone(),
        )
    } else {
        (
            0,
            startup.listener_config.clone(),
            Arc::clone(&startup.listener_tls_store),
            Arc::clone(&startup.transport_pool),
            Arc::clone(&startup.backend_endpoints),
            Arc::clone(&startup.upstream_policies),
            Arc::clone(&startup.metrics),
            Arc::clone(&startup.resilience),
            startup.upstream_pools.clone(),
            Arc::clone(&startup.routing_index),
        )
    };

    Some(BootstrapConnectionState {
        runtime_generation,
        alt_svc_value: format!("h3=\":{}\"; ma=86400", listener_config.listen.listen.port),
        backend_timeout: listener_config.policies.timeouts.backend_request,
        max_request_body_bytes: listener_config.policies.transport.max_request_body_bytes,
        max_response_body_bytes: listener_config.policies.transport.max_response_body_bytes,
        max_connections: listener_config
            .policies
            .transport
            .connection_limits
            .max_active_connections
            .max(1),
        new_connections_per_sec: listener_config.policies.transport.new_connections_per_sec,
        new_connections_burst: listener_config.policies.transport.new_connections_burst,
        connection_timeout: listener_config.policies.timeouts.client_body_idle,
        listener_tls_store,
        transport_pool,
        backend_endpoints,
        upstream_policies,
        metrics,
        resilience,
        upstream_pools,
        routing_index,
    })
}
