use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Instant,
};

use impulse_config::{backend_endpoint::BackendEndpoint, runtime::RuntimeUpstreamPolicy};
use impulse_lb::upstream_pool::UpstreamPool;
use impulse_transport::UpstreamTransportPool;

use super::state::BootstrapConnectionState;
use crate::{
    Metrics, request_pipeline::TerminalOutcomeGuard, resilience::runtime::RuntimeResilience,
    routing::index::RouteIndex,
};

pub(in crate::quic_listener) struct BootstrapBodyLimits {
    pub(in crate::quic_listener) max_request_body_bytes: usize,
    pub(in crate::quic_listener) max_response_body_bytes: usize,
}

pub(in crate::quic_listener) struct BootstrapRuntimeCtx {
    pub(in crate::quic_listener) runtime_generation: crate::runtime::activation::GenerationId,
    pub(in crate::quic_listener) alt_svc: String,
    pub(in crate::quic_listener) body_limits: BootstrapBodyLimits,
    pub(in crate::quic_listener) transport_pool: Arc<UpstreamTransportPool>,
    pub(in crate::quic_listener) backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
    pub(in crate::quic_listener) upstream_policies: Arc<HashMap<String, RuntimeUpstreamPolicy>>,
    pub(in crate::quic_listener) metrics: Arc<Metrics>,
    pub(in crate::quic_listener) resilience: Arc<RuntimeResilience>,
    pub(in crate::quic_listener) upstream_pools: HashMap<String, Arc<RwLock<UpstreamPool>>>,
    pub(in crate::quic_listener) routing_index: Arc<RouteIndex>,
}

impl BootstrapRuntimeCtx {
    pub(in crate::quic_listener) fn from_connection_state(
        state: &BootstrapConnectionState,
    ) -> Self {
        Self {
            runtime_generation: state.runtime_generation,
            alt_svc: state.alt_svc_value.clone(),
            body_limits: BootstrapBodyLimits {
                max_request_body_bytes: state.max_request_body_bytes,
                max_response_body_bytes: state.max_response_body_bytes,
            },
            transport_pool: Arc::clone(&state.transport_pool),
            backend_endpoints: Arc::clone(&state.backend_endpoints),
            upstream_policies: Arc::clone(&state.upstream_policies),
            metrics: Arc::clone(&state.metrics),
            resilience: Arc::clone(&state.resilience),
            upstream_pools: state.upstream_pools.clone(),
            routing_index: Arc::clone(&state.routing_index),
        }
    }
}

#[derive(Clone, Copy)]
pub(in crate::quic_listener) struct BootstrapRequestCtx<'a> {
    pub(in crate::quic_listener) runtime: &'a BootstrapRuntimeCtx,
    pub(in crate::quic_listener) peer: SocketAddr,
    pub(in crate::quic_listener) request_start: Instant,
    pub(in crate::quic_listener) terminal_outcome: &'a TerminalOutcomeGuard,
}

#[derive(Clone, Copy)]
pub(in crate::quic_listener) struct BootstrapDispatchCtx<'a> {
    pub(in crate::quic_listener) request: BootstrapRequestCtx<'a>,
    pub(in crate::quic_listener) request_id: u64,
    pub(in crate::quic_listener) is_websocket_upgrade: bool,
}
