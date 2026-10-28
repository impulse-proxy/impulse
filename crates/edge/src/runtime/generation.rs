use std::{collections::HashMap, sync::Arc};

use impulse_config::{
    backend_endpoint::BackendEndpoint,
    config::Log,
    runtime::{
        ListenerRuntimeConfig, RuntimeBackendHealthCheck, RuntimeBackendTlsPolicy, RuntimeConfig,
        RuntimeUpstreamPolicy,
    },
};
use impulse_lb::pingora_backend::SharedPingoraLoadBalancingRuntimeState;
use impulse_transport::{SharedDnsResolver, UpstreamTransportPool};
use tokio::sync::Semaphore;

use crate::{
    Metrics,
    resilience::runtime::RuntimeResilience,
    routing::index::RouteIndex,
    runtime::{
        backend::{lifecycle::BackendLifecycleCoordinator, store::RuntimeBackendResolutionStore},
        policy::{OperationalOwnership, OwnedRuntimeState},
        tasks::RuntimeTaskRegistry,
        tls::store::ListenerTlsReloadStore,
    },
    watchdog::coordinator::WatchdogCoordinator,
};

/// Startup-owned runtime state.
///
/// Ownership class: [`OperationalOwnership::StartupOwned`]. Established once at
/// process boot from the on-disk config and **must not change while the process
/// runs** — a reload that would alter any of these fields is rejected as
/// restart-required (see `RESOURCE_DOMAINS` and the reload validators). The
/// generation swap carries this across unchanged; it never replaces it.
#[derive(Clone)]
pub struct StartupOwnedRuntimeState {
    /// Path the running config was loaded from; fixed for the process lifetime.
    pub config_path: String,
    /// Logging sink configuration (file/format). `log.level` is live-reloadable
    /// and handled separately; the rest is startup-owned.
    pub log_config: Log,
}

impl OwnedRuntimeState for StartupOwnedRuntimeState {
    const OWNERSHIP: OperationalOwnership = OperationalOwnership::StartupOwned;
}

/// Process-shared runtime services.
///
/// Ownership class: [`OperationalOwnership::ProcessShared`]. These are the
/// long-lived services the data plane reaches through the active generation.
///
/// Not every field is equally "shared": the config-derived services
/// (`transport_pool`, `metrics`, `backend_lifecycle`,
/// `backend_resolution_store`) legitimately track the active config and are
/// rebuilt per generation on reload. The genuinely process-scoped services -
/// [`Self::listener_tls_store`], [`Self::watchdog`], and
/// [`Self::backend_dns_resolver`] - carry state that must
/// survive a reload (an in-flight watchdog restart/drain; the DNS cache) and are
/// therefore carried forward across generations by [`CarriedProcessSharedServices`]
/// rather than reconstructed. See `build_shared_state` for how the reload path
/// threads them through.
#[derive(Clone)]
pub struct RuntimeSharedServices {
    /// Listener TLS material store (swaps atomically under its own lock).
    pub listener_tls_store: Arc<ListenerTlsReloadStore>,
    /// Upstream transport (connection) pool.
    pub transport_pool: Arc<UpstreamTransportPool>,
    /// Backend lifecycle coordinator (resolution + health merge).
    pub backend_lifecycle: Arc<BackendLifecycleCoordinator>,
    /// Backend DNS resolution store.
    pub backend_resolution_store: Arc<RuntimeBackendResolutionStore>,
    /// Shared DNS resolver handle. Process-scoped: carried across reloads so the
    /// DNS cache is not dropped on every generation swap.
    pub backend_dns_resolver: SharedDnsResolver,
    /// Metrics registry.
    pub metrics: Arc<Metrics>,
    /// Watchdog coordinator (heartbeat/restart signaling). Process-scoped: carried
    /// across reloads so an in-flight restart/drain is not silently reset.
    pub watchdog: Arc<WatchdogCoordinator>,
}

/// The genuinely process-scoped services carried forward from the active
/// generation into a reloaded one, so their runtime state survives the swap.
///
/// Constructed from the current generation's [`RuntimeSharedServices`] and passed
/// to `build_shared_state` on reload. On startup there is nothing to carry, so the
/// builder creates fresh instances.
#[derive(Clone)]
pub struct CarriedProcessSharedServices {
    /// The live listener TLS material store, preserving reload-certs state and
    /// listener identity metadata across generation-only reloads.
    pub listener_tls_store: Arc<ListenerTlsReloadStore>,
    /// The live watchdog coordinator, preserving any in-flight restart/drain state.
    pub watchdog: Arc<WatchdogCoordinator>,
    /// The live DNS resolver, preserving its cache across the reload.
    pub backend_dns_resolver: SharedDnsResolver,
}

impl CarriedProcessSharedServices {
    /// Capture the process-scoped services from the currently active shared state.
    pub fn from_active(shared: &RuntimeSharedServices) -> Self {
        Self {
            listener_tls_store: Arc::clone(&shared.listener_tls_store),
            watchdog: Arc::clone(&shared.watchdog),
            backend_dns_resolver: shared.backend_dns_resolver.clone(),
        }
    }
}

impl OwnedRuntimeState for RuntimeSharedServices {
    const OWNERSHIP: OperationalOwnership = OperationalOwnership::ProcessShared;
}

/// Generation-owned runtime state.
///
/// Ownership class: [`OperationalOwnership::GenerationOwned`]. Rebuilt fresh for
/// each runtime generation and replaced wholesale by the generation swap. This is
/// the *only* state the swap is permitted to move or replace; nothing here is
/// expected to outlive its generation (in-flight work on the old generation
/// keeps a clone alive until it drains).
#[derive(Clone)]
pub struct RuntimeGenerationState {
    /// Per-listener runtime config, keyed by listener label.
    pub listener_runtime_configs: Arc<HashMap<String, ListenerRuntimeConfig>>,
    /// Resolved backend endpoints, keyed by backend id.
    pub backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
    /// Backend health-check definitions, keyed by backend id.
    pub backend_health_checks: Arc<HashMap<String, RuntimeBackendHealthCheck>>,
    /// Upstream policies, keyed by upstream name.
    pub upstream_policies: Arc<HashMap<String, RuntimeUpstreamPolicy>>,
    /// Backend membership, readiness, discovery, and selectors for this generation.
    pub pingora_load_balancing: SharedPingoraLoadBalancingRuntimeState<RuntimeBackendTlsPolicy>,
    /// Per-upstream inflight semaphores.
    pub upstream_inflight: HashMap<String, Arc<Semaphore>>,
    /// Global inflight semaphore.
    pub global_inflight: Arc<Semaphore>,
    /// Routing index for this generation.
    pub routing_index: Arc<RouteIndex>,
    /// Resilience runtime (adaptive admission, hedging, retries).
    pub resilience: Arc<RuntimeResilience>,
    /// Background task registry for this generation (retired on swap).
    pub generation_tasks: Arc<RuntimeTaskRegistry>,
}

impl OwnedRuntimeState for RuntimeGenerationState {
    const OWNERSHIP: OperationalOwnership = OperationalOwnership::GenerationOwned;
}

#[derive(Clone, Copy)]
pub struct RuntimeGenerationView<'a> {
    pub generation: u64,
    pub startup: &'a StartupOwnedRuntimeState,
    pub runtime_config: &'a RuntimeConfig,
    pub shared: &'a RuntimeSharedServices,
    pub state: &'a RuntimeGenerationState,
}

impl<'a> RuntimeGenerationView<'a> {
    pub fn listener_runtime_config(&self, label: &str) -> Option<ListenerRuntimeConfig> {
        self.state.listener_runtime_configs.get(label).cloned()
    }
}
