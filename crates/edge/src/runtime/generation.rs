use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use impulse_config::{
    backend_endpoint::BackendEndpoint,
    config::Log,
    runtime::{
        ListenerRuntimeConfig, RuntimeBackendHealthCheck, RuntimeBackendTlsPolicy, RuntimeConfig,
        RuntimeResponseCachePolicy, RuntimeResponseCompressionPolicy, RuntimeTransportPolicy,
        RuntimeUpstreamPolicy,
    },
};
use impulse_contracts::{BackendId, ListenerId, RouteId, UpstreamId};
use impulse_errors::ProxyError;
use impulse_lb::{
    pingora_backend::{GenerationSelector, SharedPingoraLoadBalancingRuntimeState},
    upstream_pool::UpstreamPool,
};
use impulse_operations::watchdog::WatchdogCoordinator;
use impulse_plugins::{CompiledGenerationPluginPlans, CompiledPluginPlan, RouteExecutionClass};
use impulse_transport::{SharedDnsResolver, UpstreamTransportPool};
use tokio::sync::Semaphore;

use crate::{
    Metrics,
    resilience::{retry_budget::RetryBudget, runtime::RuntimeResilience},
    routing::index::RouteIndex,
    runtime::{
        backend::{lifecycle::BackendLifecycleCoordinator, store::RuntimeBackendResolutionStore},
        policy::{OperationalOwnership, OwnedRuntimeState},
        tasks::RuntimeTaskRegistry,
        tls::store::ListenerTlsReloadStore,
    },
};

#[derive(Clone, Debug)]
pub struct RuntimeIdentities {
    route_ids: HashMap<Arc<str>, RouteId>,
    upstream_ids: HashMap<Arc<str>, UpstreamId>,
    upstream_names: Box<[Arc<str>]>,
    backend_ids: HashMap<UpstreamId, HashMap<Arc<str>, BackendId>>,
    backend_ids_by_upstream: Box<[Box<[BackendId]>]>,
    backend_names: Box<[(UpstreamId, Arc<str>)]>,
    listener_ids: HashMap<Arc<str>, ListenerId>,
    listener_names: Box<[Arc<str>]>,
}

impl RuntimeIdentities {
    pub(crate) fn prepare(config: &RuntimeConfig) -> Result<Self, ProxyError> {
        let mut upstreams = config.upstreams.iter().collect::<Vec<_>>();
        upstreams.sort_unstable_by_key(|(name, _)| name.as_str());

        let mut route_ids = HashMap::with_capacity(upstreams.len());
        let mut upstream_ids = HashMap::with_capacity(upstreams.len());
        let mut upstream_names = Vec::with_capacity(upstreams.len());
        let mut backend_ids = HashMap::with_capacity(upstreams.len());
        let mut backend_ids_by_upstream = Vec::with_capacity(upstreams.len());
        let mut backend_names = Vec::new();

        for (index, (name, upstream)) in upstreams.into_iter().enumerate() {
            let value = compact_identity_value(index, "route and upstream")?;
            let route_id = RouteId::new(value);
            let upstream_id = UpstreamId::new(value);
            let name: Arc<str> = Arc::from(name.as_str());
            route_ids.insert(Arc::clone(&name), route_id);
            upstream_ids.insert(Arc::clone(&name), upstream_id);
            upstream_names.push(name);

            let mut ids = HashMap::with_capacity(upstream.backends.len());
            let mut indexed_ids = Vec::with_capacity(upstream.backends.len());
            for backend in &upstream.backends {
                let backend_id =
                    BackendId::new(compact_identity_value(backend_names.len(), "backend")?);
                let name: Arc<str> = Arc::from(backend.backend.id.as_str());
                ids.insert(Arc::clone(&name), backend_id);
                indexed_ids.push(backend_id);
                backend_names.push((upstream_id, name));
            }
            backend_ids.insert(upstream_id, ids);
            backend_ids_by_upstream.push(indexed_ids.into_boxed_slice());
        }

        let mut listener_ids = HashMap::with_capacity(config.listeners.len());
        let mut listener_names = Vec::with_capacity(config.listeners.len());
        for (index, listener) in config.listeners.iter().enumerate() {
            let listener_id = ListenerId::new(compact_identity_value(index, "listener")?);
            let name: Arc<str> = Arc::from(format!(
                "{}:{}",
                listener.listen.address, listener.listen.port
            ));
            listener_ids.insert(Arc::clone(&name), listener_id);
            listener_names.push(name);
        }

        Ok(Self {
            route_ids,
            upstream_ids,
            upstream_names: upstream_names.into_boxed_slice(),
            backend_ids,
            backend_ids_by_upstream: backend_ids_by_upstream.into_boxed_slice(),
            backend_names: backend_names.into_boxed_slice(),
            listener_ids,
            listener_names: listener_names.into_boxed_slice(),
        })
    }

    #[cfg(test)]
    pub(crate) fn for_upstream_names(names: impl IntoIterator<Item = String>) -> Self {
        let mut names = names.into_iter().collect::<Vec<_>>();
        names.sort_unstable();
        let mut route_ids = HashMap::with_capacity(names.len());
        let mut upstream_ids = HashMap::with_capacity(names.len());
        let mut upstream_names = Vec::with_capacity(names.len());
        for (index, name) in names.into_iter().enumerate() {
            let identity = u32::try_from(index).expect("test identity must fit in u32");
            let name: Arc<str> = Arc::from(name);
            route_ids.insert(Arc::clone(&name), RouteId::new(identity));
            upstream_ids.insert(Arc::clone(&name), UpstreamId::new(identity));
            upstream_names.push(name);
        }
        Self {
            route_ids,
            upstream_ids,
            upstream_names: upstream_names.into_boxed_slice(),
            backend_ids: HashMap::new(),
            backend_ids_by_upstream: Box::new([]),
            backend_names: Box::new([]),
            listener_ids: HashMap::new(),
            listener_names: Box::new([]),
        }
    }

    #[must_use]
    pub fn route_id(&self, name: &str) -> Option<RouteId> {
        self.route_ids.get(name).copied()
    }

    #[must_use]
    pub fn route_name(&self, id: RouteId) -> Option<&str> {
        self.upstream_name(UpstreamId::new(id.get()))
    }

    #[must_use]
    pub fn upstream_id(&self, name: &str) -> Option<UpstreamId> {
        self.upstream_ids.get(name).copied()
    }

    #[must_use]
    pub fn upstream_name(&self, id: UpstreamId) -> Option<&str> {
        self.upstream_names
            .get(id.get() as usize)
            .map(|name| name.as_ref())
    }

    #[must_use]
    pub fn upstream_display_name(&self, id: UpstreamId) -> Option<Arc<str>> {
        self.upstream_names.get(id.get() as usize).map(Arc::clone)
    }

    pub fn upstream_names(&self) -> impl ExactSizeIterator<Item = &str> {
        self.upstream_names.iter().map(|name| name.as_ref())
    }

    #[must_use]
    pub fn backend_id(&self, upstream: UpstreamId, name: &str) -> Option<BackendId> {
        self.backend_ids.get(&upstream)?.get(name).copied()
    }

    fn backend_ids(&self, upstream: UpstreamId) -> Option<&[BackendId]> {
        self.backend_ids_by_upstream
            .get(upstream.get() as usize)
            .map(|ids| ids.as_ref())
    }

    #[must_use]
    pub fn backend_id_at(&self, upstream: UpstreamId, index: usize) -> Option<BackendId> {
        self.backend_ids(upstream)?.get(index).copied()
    }

    #[must_use]
    pub fn backend_name(&self, id: BackendId) -> Option<&str> {
        self.backend_names
            .get(id.get() as usize)
            .map(|(_, name)| name.as_ref())
    }

    pub fn backend_names(&self) -> impl ExactSizeIterator<Item = &str> {
        self.backend_names.iter().map(|(_, name)| name.as_ref())
    }

    #[must_use]
    pub fn backend_upstream(&self, id: BackendId) -> Option<UpstreamId> {
        self.backend_names
            .get(id.get() as usize)
            .map(|(upstream, _)| *upstream)
    }

    #[must_use]
    pub fn listener_id(&self, name: &str) -> Option<ListenerId> {
        self.listener_ids.get(name).copied()
    }

    #[must_use]
    pub fn listener_name(&self, id: ListenerId) -> Option<&str> {
        self.listener_names
            .get(id.get() as usize)
            .map(|name| name.as_ref())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RuntimeObservationFlags {
    pub(crate) detailed_plugin_timing: bool,
}

/// Immutable route state compiled with and owned by one runtime generation.
#[derive(Clone)]
pub(crate) struct RouteRuntime {
    pub(crate) plugin_plan: Arc<CompiledPluginPlan>,
    pub(crate) selector: Arc<GenerationSelector<RuntimeBackendTlsPolicy>>,
    pub(crate) upstream_pool: Arc<RwLock<UpstreamPool>>,
    #[allow(dead_code)]
    pub(crate) transport_policy: Arc<RuntimeTransportPolicy>,
    pub(crate) retry_policy: Arc<RetryBudget>,
    #[allow(dead_code)]
    pub(crate) cache_policy: Arc<RuntimeResponseCachePolicy>,
    #[allow(dead_code)]
    pub(crate) compression_policy: Arc<RuntimeResponseCompressionPolicy>,
    pub(crate) observation_flags: Arc<RuntimeObservationFlags>,
}

fn compact_identity_value(index: usize, kind: &str) -> Result<u32, ProxyError> {
    u32::try_from(index).map_err(|_| {
        ProxyError::Transport(format!(
            "runtime generation contains too many {kind} identities"
        ))
    })
}

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
/// [`Self::backend_dns_resolver`], and [`Self::process_tasks`] - carry state that must
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
    /// Process-scoped background tasks that survive generation replacement.
    pub process_tasks: Arc<RuntimeTaskRegistry>,
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
    /// Process-scoped background task owner.
    pub process_tasks: Arc<RuntimeTaskRegistry>,
}

impl CarriedProcessSharedServices {
    /// Capture the process-scoped services from the currently active shared state.
    pub fn from_active(shared: &RuntimeSharedServices) -> Self {
        Self {
            listener_tls_store: Arc::clone(&shared.listener_tls_store),
            watchdog: Arc::clone(&shared.watchdog),
            backend_dns_resolver: shared.backend_dns_resolver.clone(),
            process_tasks: Arc::clone(&shared.process_tasks),
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
    /// Compact route, upstream, backend, and listener identities for this generation.
    pub identities: Arc<RuntimeIdentities>,
    /// Per-listener runtime config, keyed by listener label.
    pub listener_runtime_configs: Arc<HashMap<String, ListenerRuntimeConfig>>,
    /// Resolved backend endpoints, keyed by configured backend address.
    pub backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
    /// Backend endpoints indexed by compact backend identity for request execution.
    pub backend_endpoints_by_id: Arc<[BackendEndpoint]>,
    /// Backend health-check definitions, keyed by backend id.
    pub backend_health_checks: Arc<HashMap<String, RuntimeBackendHealthCheck>>,
    /// Upstream policies indexed by compact upstream identity.
    pub upstream_policies: Arc<[RuntimeUpstreamPolicy]>,
    /// Normalized transport settings shared by routes in this generation.
    pub transport_policy: Arc<RuntimeTransportPolicy>,
    /// Observation switches shared by route execution in this generation.
    pub(crate) observation_flags: Arc<RuntimeObservationFlags>,
    /// Immutable connection and per-upstream plugin plans compiled for this generation.
    pub plugin_plans: Arc<CompiledGenerationPluginPlans>,
    /// Precompiled route execution classes owned by this runtime generation.
    pub route_execution_classes: Arc<[RouteExecutionClass]>,
    /// Fully compiled route execution state, indexed by upstream identity.
    pub(crate) route_runtimes: Arc<[RouteRuntime]>,
    /// Backend membership, readiness, discovery, and selectors for this generation.
    pub pingora_load_balancing: SharedPingoraLoadBalancingRuntimeState<RuntimeBackendTlsPolicy>,
    /// Per-upstream inflight semaphores.
    pub upstream_inflight: Arc<[Arc<Semaphore>]>,
    /// Global inflight semaphore.
    pub global_inflight: Arc<Semaphore>,
    /// Routing index for this generation.
    pub routing_index: Arc<RouteIndex>,
    /// Resilience runtime (adaptive admission, hedging, retries).
    pub resilience: Arc<RuntimeResilience>,
    /// Background task registry for this generation (retired on swap).
    pub generation_tasks: Arc<RuntimeTaskRegistry>,
}

impl RuntimeGenerationState {
    pub(crate) fn route_runtime(&self, upstream_id: UpstreamId) -> Option<&RouteRuntime> {
        self.route_runtimes.get(upstream_id.get() as usize)
    }
}

impl OwnedRuntimeState for RuntimeGenerationState {
    const OWNERSHIP: OperationalOwnership = OperationalOwnership::GenerationOwned;
}

pub(crate) type RuntimeGenerationView<'a> = impulse_runtime::RuntimeGenerationView<
    'a,
    StartupOwnedRuntimeState,
    RuntimeConfig,
    crate::runtime::shared_state::SharedRuntimeState,
>;
