#[cfg(test)]
use std::collections::BTreeSet;
use std::{
    collections::HashMap,
    future::Future,
    hash::{BuildHasher, RandomState},
    net::SocketAddr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use impulse_contracts::{BackendId, UpstreamId};
#[cfg(test)]
use pingora_load_balancing::discovery::Static as StaticDiscovery;
pub use pingora_load_balancing::{
    Backend as PingoraBackend, HealthCheckService, HealthRegistry,
    health_check::{HealthCheck as PingoraHealthCheck, HttpHealthCheck as PingoraHttpHealthCheck},
};
use pingora_load_balancing::{
    BackendView, LoadBalancer,
    selection::{Random as PingoraRandom, RoundRobin as PingoraRoundRobin},
};

use crate::{
    BackendInput, LoadBalancingStrategy,
    pingora_discovery::ImpulseServiceDiscovery,
    upstream_pool::{UpstreamPool, UpstreamPoolMembership},
};

const WORKER_SELECTION_SLOTS: usize = 256;

fn next_random(state: &AtomicU64) -> u64 {
    let value = state.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed);
    let mut mixed = value;
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    mixed ^ (mixed >> 31)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendSelectionResult<P> {
    runtime_id: BackendId,
    backend_id: String,
    address: SocketAddr,
    index: usize,
    generation: u64,
    connection_policy: P,
}

impl<P> BackendSelectionResult<P> {
    pub fn new(
        runtime_id: BackendId,
        backend_id: impl Into<String>,
        address: SocketAddr,
        index: usize,
        generation: u64,
        connection_policy: P,
    ) -> Self {
        Self {
            runtime_id,
            backend_id: backend_id.into(),
            address,
            index,
            generation,
            connection_policy,
        }
    }

    pub fn runtime_id(&self) -> BackendId {
        self.runtime_id
    }

    pub fn backend_id(&self) -> &str {
        &self.backend_id
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn connection_policy(&self) -> &P {
        &self.connection_policy
    }
}

fn synchronize_backend_readiness<T>(
    view: &BackendView,
    mut is_healthy: impl FnMut(usize) -> bool,
) -> Result<(), String>
where
    T: Clone + Send + Sync + 'static,
{
    for backend in view.get_backend().iter() {
        let identity = backend
            .ext
            .get::<PingoraBackendIdentity<T>>()
            .ok_or_else(|| format!("Pingora backend '{}' has no Impulse identity", backend.addr))?;
        view.set_enable(backend, is_healthy(identity.index()));
    }
    Ok(())
}

fn selection_result<T>(
    backend: PingoraBackend,
    generation: u64,
) -> Option<BackendSelectionResult<T>>
where
    T: Clone + Send + Sync + 'static,
{
    let address = *backend.addr.as_inet()?;
    let identity = backend.ext.get::<PingoraBackendIdentity<T>>()?;

    Some(BackendSelectionResult::new(
        identity.runtime_id(),
        identity.backend_id(),
        address,
        identity.index(),
        generation,
        identity.tls_identity().clone(),
    ))
}

fn candidate_is_available<T>(
    backend: &PingoraBackend,
    healthy: bool,
    excluded_backend_ids: &[BackendId],
) -> bool
where
    T: Clone + Send + Sync + 'static,
{
    healthy
        && backend
            .ext
            .get::<PingoraBackendIdentity<T>>()
            .is_some_and(|identity| !excluded_backend_ids.contains(&identity.runtime_id()))
}

/// Pads a per-worker value to its own cache line so workers that own adjacent
/// slots do not invalidate each other's line on every update (false sharing).
#[repr(align(64))]
struct Padded<T>(T);

/// Weighted pick over the currently available backends without allocating.
///
/// `pick_slot` receives the total weight of the available backends and returns a
/// position in `0..total_weight`. If readiness changes between the two passes and
/// the position no longer lands on a backend, fall back to the first available one.
fn select_weighted_backend<T>(
    backends: &pingora_load_balancing::Backends,
    excluded_backend_ids: &[BackendId],
    pick_slot: impl FnOnce(usize) -> usize,
) -> Option<PingoraBackend>
where
    T: Clone + Send + Sync + 'static,
{
    let backend_set = backends.get_backend();
    let is_available = |backend: &&PingoraBackend| {
        candidate_is_available::<T>(backend, backends.ready(backend), excluded_backend_ids)
    };
    let total_weight = backend_set
        .iter()
        .filter(&is_available)
        .fold(0usize, |total, backend| {
            total.saturating_add(backend.weight)
        });
    if total_weight == 0 {
        return None;
    }

    let mut weight_slot = pick_slot(total_weight);
    backend_set
        .iter()
        .filter(&is_available)
        .find(|backend| {
            if weight_slot < backend.weight {
                true
            } else {
                weight_slot -= backend.weight;
                false
            }
        })
        .cloned()
        .or_else(|| first_available_backend::<T>(backends, excluded_backend_ids))
}

fn first_available_backend<T>(
    backends: &pingora_load_balancing::Backends,
    excluded_backend_ids: &[BackendId],
) -> Option<PingoraBackend>
where
    T: Clone + Send + Sync + 'static,
{
    backends
        .get_backend()
        .iter()
        .find(|backend| {
            candidate_is_available::<T>(backend, backends.ready(backend), excluded_backend_ids)
        })
        .cloned()
}

struct GenerationStickyCid<T> {
    selector: GenerationKetama<T>,
}

impl<T> GenerationStickyCid<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn from_backend_view(view: GenerationBackendView) -> Self {
        Self {
            selector: GenerationKetama::from_backend_view(view),
        }
    }

    fn select_excluding(
        &self,
        cid_key: &str,
        excluded_backend_ids: &[BackendId],
    ) -> Option<BackendSelectionResult<T>> {
        self.selector
            .select_excluding(cid_key.as_bytes(), excluded_backend_ids)
    }

    fn synchronize_readiness(&self, is_healthy: impl FnMut(usize) -> bool) -> Result<(), String> {
        self.selector.synchronize_readiness(is_healthy)
    }

    fn generation(&self) -> u64 {
        self.selector.generation()
    }

    fn upstream_name(&self) -> &str {
        self.selector.upstream_name()
    }
}

struct GenerationKetama<T> {
    generation: u64,
    upstream_name: String,
    selector: LoadBalancer<pingora_load_balancing::selection::Consistent>,
    policy: std::marker::PhantomData<T>,
}

impl<T> GenerationKetama<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn from_backend_view(view: GenerationBackendView) -> Self {
        let GenerationBackendView {
            generation,
            upstream_name,
            backend_ids: _,
            view,
            discovery: _,
        } = view;

        Self {
            generation,
            upstream_name,
            selector: LoadBalancer::from_backends(view),
            policy: std::marker::PhantomData,
        }
    }

    fn select_excluding(
        &self,
        key: &[u8],
        excluded_backend_ids: &[BackendId],
    ) -> Option<BackendSelectionResult<T>> {
        let selected = self
            .selector
            .select_with(
                key,
                self.selector.backends().get_backend().len(),
                |backend, healthy| {
                    candidate_is_available::<T>(backend, healthy, excluded_backend_ids)
                },
            )
            .or_else(|| {
                first_available_backend::<T>(self.selector.backends(), excluded_backend_ids)
            })?;
        selection_result(selected, self.generation)
    }

    fn synchronize_readiness(&self, is_healthy: impl FnMut(usize) -> bool) -> Result<(), String> {
        synchronize_backend_readiness::<T>(self.selector.backends(), is_healthy)
    }

    fn generation(&self) -> u64 {
        self.generation
    }

    fn upstream_name(&self) -> &str {
        &self.upstream_name
    }
}

struct GenerationWeightedRandom<T> {
    generation: u64,
    upstream_name: String,
    selector: LoadBalancer<PingoraRandom>,
    worker_random_states: Box<[Padded<AtomicU64>]>,
    policy: std::marker::PhantomData<T>,
}

impl<T> GenerationWeightedRandom<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn from_backend_view(view: GenerationBackendView) -> Self {
        let GenerationBackendView {
            generation,
            upstream_name,
            backend_ids: _,
            view,
            discovery: _,
        } = view;

        Self {
            generation,
            upstream_name,
            selector: LoadBalancer::from_backends(view),
            worker_random_states: (0..WORKER_SELECTION_SLOTS)
                .map(|slot| {
                    let seed = RandomState::new().hash_one((slot, generation));
                    Padded(AtomicU64::new(seed))
                })
                .collect(),
            policy: std::marker::PhantomData,
        }
    }

    fn select_excluding(
        &self,
        excluded_backend_ids: &[BackendId],
        worker_slot: usize,
    ) -> Option<BackendSelectionResult<T>> {
        let state = &self.worker_random_states[worker_slot % self.worker_random_states.len()].0;
        let selected = select_weighted_backend::<T>(
            self.selector.backends(),
            excluded_backend_ids,
            |total_weight| (next_random(state) % total_weight as u64) as usize,
        )?;
        selection_result(selected, self.generation)
    }

    fn synchronize_readiness(&self, is_healthy: impl FnMut(usize) -> bool) -> Result<(), String> {
        synchronize_backend_readiness::<T>(self.selector.backends(), is_healthy)
    }

    fn generation(&self) -> u64 {
        self.generation
    }

    fn upstream_name(&self) -> &str {
        &self.upstream_name
    }
}

struct GenerationWeightedRoundRobin<T> {
    generation: u64,
    upstream_name: String,
    selector: LoadBalancer<PingoraRoundRobin>,
    worker_cursors: Box<[Padded<AtomicUsize>]>,
    policy: std::marker::PhantomData<T>,
}

impl<T> GenerationWeightedRoundRobin<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn from_backend_view(view: GenerationBackendView) -> Self {
        let GenerationBackendView {
            generation,
            upstream_name,
            backend_ids: _,
            view,
            discovery: _,
        } = view;

        Self {
            generation,
            upstream_name,
            selector: LoadBalancer::from_backends(view),
            worker_cursors: (0..WORKER_SELECTION_SLOTS)
                .map(|_| Padded(AtomicUsize::new(0)))
                .collect(),
            policy: std::marker::PhantomData,
        }
    }

    fn select_excluding(
        &self,
        excluded_backend_ids: &[BackendId],
        worker_slot: usize,
    ) -> Option<BackendSelectionResult<T>> {
        let cursor = &self.worker_cursors[worker_slot % self.worker_cursors.len()].0;
        let selected = select_weighted_backend::<T>(
            self.selector.backends(),
            excluded_backend_ids,
            |total_weight| cursor.fetch_add(1, Ordering::Relaxed) % total_weight,
        )?;
        selection_result(selected, self.generation)
    }

    fn synchronize_readiness(&self, is_healthy: impl FnMut(usize) -> bool) -> Result<(), String> {
        synchronize_backend_readiness::<T>(self.selector.backends(), is_healthy)
    }

    fn generation(&self) -> u64 {
        self.generation
    }

    fn upstream_name(&self) -> &str {
        &self.upstream_name
    }
}

pub struct GenerationBackendView {
    generation: u64,
    upstream_name: String,
    backend_ids: Box<[BackendId]>,
    view: BackendView,
    discovery: Option<ImpulseServiceDiscovery>,
}

enum GenerationSelectorKind<T> {
    WeightedRoundRobin(GenerationWeightedRoundRobin<T>),
    WeightedRandom(GenerationWeightedRandom<T>),
    Ketama(GenerationKetama<T>),
    StickyCid(GenerationStickyCid<T>),
    CustomLeastConnections(GenerationBackendView),
    CustomLatencyAware(GenerationBackendView),
}

pub struct GenerationSelector<T> {
    kind: GenerationSelectorKind<T>,
    backend_ids: Box<[BackendId]>,
}

impl<T> GenerationSelector<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn backends(&self) -> &BackendView {
        match &self.kind {
            GenerationSelectorKind::WeightedRoundRobin(selector) => selector.selector.backends(),
            GenerationSelectorKind::WeightedRandom(selector) => selector.selector.backends(),
            GenerationSelectorKind::Ketama(selector) => selector.selector.backends(),
            GenerationSelectorKind::StickyCid(selector) => selector.selector.selector.backends(),
            GenerationSelectorKind::CustomLeastConnections(view)
            | GenerationSelectorKind::CustomLatencyAware(view) => &view.view,
        }
    }

    fn set_backend_enabled(&self, backend_id: BackendId, enabled: bool) {
        let backends = self.backends();
        for backend in backends.get_backend().iter() {
            if backend
                .ext
                .get::<PingoraBackendIdentity<T>>()
                .is_some_and(|identity| identity.runtime_id() == backend_id)
            {
                backends.set_enable(backend, enabled);
            }
        }
    }

    fn new(
        strategy: LoadBalancingStrategy,
        mut view: GenerationBackendView,
    ) -> Result<Self, String> {
        let mut backend_ids = vec![None; view.view.get_backend().len()];
        for backend in view.view.get_backend().iter() {
            let identity = backend
                .ext
                .get::<PingoraBackendIdentity<T>>()
                .ok_or_else(|| {
                    format!("Pingora backend '{}' has no Impulse identity", backend.addr)
                })?;
            let slot = backend_ids.get_mut(identity.index()).ok_or_else(|| {
                format!("Pingora backend '{}' has an invalid index", backend.addr)
            })?;
            *slot = Some(identity.runtime_id());
        }
        view.backend_ids = backend_ids
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                format!(
                    "upstream '{}' has incomplete backend identities",
                    view.upstream_name
                )
            })?
            .into_boxed_slice();
        let backend_ids = view.backend_ids.clone();
        let kind = match strategy {
            LoadBalancingStrategy::RoundRobin => GenerationSelectorKind::WeightedRoundRobin(
                GenerationWeightedRoundRobin::from_backend_view(view),
            ),
            LoadBalancingStrategy::Random => GenerationSelectorKind::WeightedRandom(
                GenerationWeightedRandom::from_backend_view(view),
            ),
            LoadBalancingStrategy::ConsistentHash => {
                GenerationSelectorKind::Ketama(GenerationKetama::from_backend_view(view))
            }
            LoadBalancingStrategy::StickyCid => {
                GenerationSelectorKind::StickyCid(GenerationStickyCid::from_backend_view(view))
            }
            LoadBalancingStrategy::LeastConnections => {
                GenerationSelectorKind::CustomLeastConnections(view)
            }
            LoadBalancingStrategy::LatencyAware => GenerationSelectorKind::CustomLatencyAware(view),
        };
        Ok(Self { kind, backend_ids })
    }

    pub fn generation(&self) -> u64 {
        match &self.kind {
            GenerationSelectorKind::WeightedRoundRobin(selector) => selector.generation(),
            GenerationSelectorKind::WeightedRandom(selector) => selector.generation(),
            GenerationSelectorKind::Ketama(selector) => selector.generation(),
            GenerationSelectorKind::StickyCid(selector) => selector.generation(),
            GenerationSelectorKind::CustomLeastConnections(view)
            | GenerationSelectorKind::CustomLatencyAware(view) => view.generation(),
        }
    }

    pub fn upstream_name(&self) -> &str {
        match &self.kind {
            GenerationSelectorKind::WeightedRoundRobin(selector) => selector.upstream_name(),
            GenerationSelectorKind::WeightedRandom(selector) => selector.upstream_name(),
            GenerationSelectorKind::Ketama(selector) => selector.upstream_name(),
            GenerationSelectorKind::StickyCid(selector) => selector.upstream_name(),
            GenerationSelectorKind::CustomLeastConnections(view)
            | GenerationSelectorKind::CustomLatencyAware(view) => view.upstream_name(),
        }
    }

    pub fn uses_custom_dynamic_selector(&self) -> bool {
        matches!(
            &self.kind,
            GenerationSelectorKind::CustomLeastConnections(_)
                | GenerationSelectorKind::CustomLatencyAware(_)
        )
    }

    pub fn has_available_backend(&self) -> bool {
        let backends = self.backends();
        backends
            .get_backend()
            .iter()
            .any(|backend| candidate_is_available::<T>(backend, backends.ready(backend), &[]))
    }

    pub fn backend_is_available(&self, backend_id: BackendId) -> bool {
        let backends = self.backends();
        backends.get_backend().iter().any(|backend| {
            backends.ready(backend)
                && backend
                    .ext
                    .get::<PingoraBackendIdentity<T>>()
                    .is_some_and(|identity| identity.runtime_id() == backend_id)
        })
    }

    pub fn custom_backend_runtime_id(&self, index: usize) -> Option<BackendId> {
        match &self.kind {
            GenerationSelectorKind::CustomLeastConnections(view)
            | GenerationSelectorKind::CustomLatencyAware(view) => {
                view.backend_ids.get(index).copied()
            }
            _ => None,
        }
    }

    pub fn backend_id(&self, index: usize) -> Option<BackendId> {
        self.backend_ids.get(index).copied()
    }

    pub fn synchronize_readiness(
        &self,
        is_healthy: impl FnMut(usize) -> bool,
    ) -> Result<(), String> {
        match &self.kind {
            GenerationSelectorKind::WeightedRoundRobin(selector) => {
                selector.synchronize_readiness(is_healthy)
            }
            GenerationSelectorKind::WeightedRandom(selector) => {
                selector.synchronize_readiness(is_healthy)
            }
            GenerationSelectorKind::Ketama(selector) => selector.synchronize_readiness(is_healthy),
            GenerationSelectorKind::StickyCid(selector) => {
                selector.synchronize_readiness(is_healthy)
            }
            GenerationSelectorKind::CustomLeastConnections(view)
            | GenerationSelectorKind::CustomLatencyAware(view) => {
                view.synchronize_readiness::<T>(is_healthy)
            }
        }
    }

    pub fn select_excluding(
        &self,
        key: &str,
        excluded_backend_ids: &[BackendId],
    ) -> Option<BackendSelectionResult<T>> {
        self.select_excluding_for_worker(key, excluded_backend_ids, 0)
    }

    pub fn select_excluding_for_worker(
        &self,
        key: &str,
        excluded_backend_ids: &[BackendId],
        worker_slot: usize,
    ) -> Option<BackendSelectionResult<T>> {
        match &self.kind {
            GenerationSelectorKind::WeightedRoundRobin(selector) => {
                selector.select_excluding(excluded_backend_ids, worker_slot)
            }
            GenerationSelectorKind::WeightedRandom(selector) => {
                selector.select_excluding(excluded_backend_ids, worker_slot)
            }
            GenerationSelectorKind::Ketama(selector) => {
                selector.select_excluding(key.as_bytes(), excluded_backend_ids)
            }
            GenerationSelectorKind::StickyCid(selector) => {
                selector.select_excluding(key, excluded_backend_ids)
            }
            GenerationSelectorKind::CustomLeastConnections(_)
            | GenerationSelectorKind::CustomLatencyAware(_) => None,
        }
    }

    async fn rebuild(&self) -> Result<(), String> {
        let result = match &self.kind {
            GenerationSelectorKind::WeightedRoundRobin(selector) => {
                selector.selector.update().await
            }
            GenerationSelectorKind::WeightedRandom(selector) => selector.selector.update().await,
            GenerationSelectorKind::Ketama(selector) => selector.selector.update().await,
            GenerationSelectorKind::StickyCid(selector) => {
                selector.selector.selector.update().await
            }
            GenerationSelectorKind::CustomLeastConnections(view)
            | GenerationSelectorKind::CustomLatencyAware(view) => view.view.update(|_| {}).await,
        };
        result.map_err(|error| {
            format!(
                "failed to rebuild Pingora selector for upstream '{}': {error}",
                self.upstream_name()
            )
        })
    }
}

pub type SharedPingoraLoadBalancingRuntimeState<T> = Arc<PingoraLoadBalancingRuntimeState<T>>;

#[derive(Clone, Debug)]
pub struct PingoraDiscoveryUpdate {
    upstream_name: String,
    membership_generation: u64,
    membership_changed: bool,
    rebuild_duration: Duration,
}

impl PingoraDiscoveryUpdate {
    pub fn upstream_name(&self) -> &str {
        &self.upstream_name
    }

    pub fn membership_generation(&self) -> u64 {
        self.membership_generation
    }

    pub fn membership_changed(&self) -> bool {
        self.membership_changed
    }

    pub fn rebuild_duration(&self) -> Duration {
        self.rebuild_duration
    }
}

/// Generation-scoped owner of backend pools, discovery membership, readiness,
/// and selector state.
pub struct PingoraLoadBalancingRuntimeState<T> {
    generation: u64,
    upstream_names: Box<[String]>,
    upstream_pools_by_id: Box<[Arc<RwLock<UpstreamPool>>]>,
    upstream_memberships_by_id: Box<[Arc<UpstreamPoolMembership>]>,
    selectors_by_id: Box<[Arc<GenerationSelector<T>>]>,
    discoveries_by_id: Box<[Option<ImpulseServiceDiscovery>]>,
    backend_readiness: Box<[AtomicBool]>,
    backend_upstreams: Box<[usize]>,
    health_registry: Arc<HealthRegistry>,
}

impl<T> PingoraLoadBalancingRuntimeState<T>
where
    T: Clone + Send + Sync + 'static,
{
    pub fn set_backend_readiness(&self, backend_id: BackendId, ready: bool) {
        let index = backend_id.get() as usize;
        let (Some(readiness), Some(upstream_index)) = (
            self.backend_readiness.get(index),
            self.backend_upstreams.get(index),
        ) else {
            return;
        };
        readiness.store(ready, Ordering::Release);
        if let Some(selector) = self.selectors_by_id.get(*upstream_index) {
            selector.set_backend_enabled(backend_id, ready);
        }
    }

    pub fn new(
        generation: u64,
        upstream_pools: HashMap<String, Arc<RwLock<UpstreamPool>>>,
        backend_views: impl IntoIterator<Item = (String, LoadBalancingStrategy, GenerationBackendView)>,
        health_registry: Arc<HealthRegistry>,
    ) -> Result<Self, String> {
        let mut selectors = HashMap::new();
        let mut discoveries = HashMap::new();
        for (upstream_name, strategy, view) in backend_views {
            if !upstream_pools.contains_key(&upstream_name) {
                return Err(format!(
                    "upstream '{upstream_name}' has a selector but no backend pool"
                ));
            }
            if view.generation() != generation {
                return Err(format!(
                    "upstream '{upstream_name}' belongs to runtime generation {}, expected {generation}",
                    view.generation()
                ));
            }
            if view.upstream_name() != upstream_name {
                return Err(format!(
                    "backend view for upstream '{}' was registered as '{upstream_name}'",
                    view.upstream_name()
                ));
            }
            let discovery = view.discovery.clone();
            let selector = GenerationSelector::new(strategy, view)?;
            if selectors
                .insert(upstream_name.clone(), Arc::new(selector))
                .is_some()
            {
                return Err(format!(
                    "duplicate Pingora backend view for upstream '{upstream_name}'"
                ));
            }
            if let Some(discovery) = discovery {
                discoveries.insert(upstream_name, discovery);
            }
        }
        if let Some(upstream_name) = upstream_pools
            .keys()
            .find(|upstream_name| !selectors.contains_key(*upstream_name))
        {
            return Err(format!(
                "upstream '{upstream_name}' has a backend pool but no selector"
            ));
        }

        let mut upstream_names = upstream_pools.keys().cloned().collect::<Vec<_>>();
        upstream_names.sort_unstable();
        let upstream_pools_by_id = upstream_names
            .iter()
            .map(|name| Arc::clone(&upstream_pools[name]))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let upstream_memberships_by_id = upstream_pools_by_id
            .iter()
            .zip(&upstream_names)
            .map(|(pool, upstream_name)| {
                pool.read()
                    .map(|pool| Arc::new(pool.membership_snapshot()))
                    .map_err(|_| {
                        format!(
                            "upstream pool lock poisoned while snapshotting membership for '{upstream_name}'"
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice();
        let selectors_by_id = upstream_names
            .iter()
            .map(|name| Arc::clone(&selectors[name]))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let discoveries_by_id = upstream_names
            .iter()
            .map(|name| discoveries.remove(name))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let backend_count = selectors_by_id
            .iter()
            .flat_map(|selector| selector.backend_ids.iter())
            .map(|backend_id| backend_id.get() as usize + 1)
            .max()
            .unwrap_or_default();
        let mut backend_upstreams = vec![None; backend_count];
        for (upstream_index, selector) in selectors_by_id.iter().enumerate() {
            for backend_id in &selector.backend_ids {
                let slot = backend_upstreams
                    .get_mut(backend_id.get() as usize)
                    .ok_or_else(|| "backend readiness identity is out of bounds".to_string())?;
                if slot.replace(upstream_index).is_some() {
                    return Err(format!(
                        "backend readiness identity {} is duplicated",
                        backend_id.get()
                    ));
                }
            }
        }
        let backend_upstreams = backend_upstreams
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| "backend readiness identities are not contiguous".to_string())?
            .into_boxed_slice();
        let backend_readiness = (0..backend_count).map(|_| AtomicBool::new(true)).collect();

        Ok(Self {
            generation,
            upstream_names: upstream_names.into_boxed_slice(),
            upstream_pools_by_id,
            upstream_memberships_by_id,
            selectors_by_id,
            discoveries_by_id,
            backend_readiness,
            backend_upstreams,
            health_registry,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn selector_by_id(&self, upstream_id: UpstreamId) -> Option<&Arc<GenerationSelector<T>>> {
        self.selectors_by_id.get(upstream_id.get() as usize)
    }

    pub fn upstream_pool_by_id(
        &self,
        upstream_id: UpstreamId,
    ) -> Option<&Arc<RwLock<UpstreamPool>>> {
        self.upstream_pools_by_id.get(upstream_id.get() as usize)
    }

    pub fn upstream_membership_by_id(
        &self,
        upstream_id: UpstreamId,
    ) -> Option<&Arc<UpstreamPoolMembership>> {
        self.upstream_memberships_by_id
            .get(upstream_id.get() as usize)
    }

    pub fn upstream_pools(&self) -> HashMap<String, Arc<RwLock<UpstreamPool>>> {
        self.upstream_names
            .iter()
            .cloned()
            .zip(self.upstream_pools_by_id.iter().map(Arc::clone))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.selectors_by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.selectors_by_id.is_empty()
    }

    pub fn health_registry(&self) -> Arc<HealthRegistry> {
        Arc::clone(&self.health_registry)
    }

    pub async fn publish_dns_result(
        &self,
        configured_address: &str,
        resolved_addrs: Result<Vec<SocketAddr>, String>,
    ) -> Result<PingoraDiscoveryUpdate, String> {
        let (upstream_index, discovery, backend_index) = self
            .discoveries_by_id
            .iter()
            .enumerate()
            .find_map(|(upstream_index, discovery)| {
                let discovery = discovery.as_ref()?;
                discovery
                    .backend_index(configured_address)
                    .map(|backend_index| (upstream_index, discovery, backend_index))
            })
            .ok_or_else(|| {
                format!(
                    "no Pingora discovery backend matches configured address '{configured_address}'"
                )
            })?;
        let upstream_name = self.upstream_names[upstream_index].as_str();
        let selector = self
            .selectors_by_id
            .get(upstream_index)
            .ok_or_else(|| format!("upstream '{upstream_name}' has no Pingora selector"))?;
        let publication =
            discovery.publish_dns_result(self.generation, backend_index, resolved_addrs)?;
        let started = Instant::now();
        selector.rebuild().await?;
        if let Some(backend_id) = selector.backend_id(backend_index)
            && let Some(ready) = self.backend_readiness.get(backend_id.get() as usize)
        {
            loop {
                let rebuilt_ready = ready.load(Ordering::Acquire);
                selector.set_backend_enabled(backend_id, rebuilt_ready);
                if ready.load(Ordering::Acquire) == rebuilt_ready {
                    break;
                }
            }
        }
        let rebuild_duration = started.elapsed();
        Ok(PingoraDiscoveryUpdate {
            upstream_name: upstream_name.to_string(),
            membership_generation: publication.membership_generation(),
            membership_changed: publication.membership_changed(),
            rebuild_duration,
        })
    }
}

impl GenerationBackendView {
    pub fn new<F>(
        generation: u64,
        upstream_name: impl Into<String>,
        backend_inputs: &[BackendInput],
        map_backend: F,
        health_registry: Arc<HealthRegistry>,
    ) -> Result<Self, String>
    where
        F: FnMut(&BackendInput) -> Result<PingoraBackend, String>,
    {
        let upstream_name = upstream_name.into();
        let mut map_backend = map_backend;
        let discovery = ImpulseServiceDiscovery::new(
            generation,
            &upstream_name,
            backend_inputs,
            &mut map_backend,
        )?;
        let view =
            BackendView::new_with_health_registry(Box::new(discovery.clone()), health_registry);
        let mut context = Context::from_waker(Waker::noop());
        let mut update = Box::pin(view.update(|_| {}));
        match update.as_mut().poll(&mut context) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => {
                return Err(format!(
                    "failed to initialize upstream '{upstream_name}': {error}"
                ));
            }
            Poll::Pending => {
                return Err(format!(
                    "static backend initialization unexpectedly blocked for upstream '{upstream_name}'"
                ));
            }
        }
        drop(update);

        Ok(Self {
            generation,
            upstream_name,
            backend_ids: Box::new([]),
            view,
            discovery: Some(discovery),
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn upstream_name(&self) -> &str {
        &self.upstream_name
    }

    pub fn synchronize_readiness<T>(
        &self,
        is_healthy: impl FnMut(usize) -> bool,
    ) -> Result<(), String>
    where
        T: Clone + Send + Sync + 'static,
    {
        synchronize_backend_readiness::<T>(&self.view, is_healthy)
    }
}

#[derive(Clone)]
pub struct PingoraBackendIdentity<T> {
    runtime_id: BackendId,
    backend_id: String,
    index: usize,
    tls_identity: T,
}

impl<T> PingoraBackendIdentity<T> {
    pub fn runtime_id(&self) -> BackendId {
        self.runtime_id
    }

    pub fn backend_id(&self) -> &str {
        &self.backend_id
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn tls_identity(&self) -> &T {
        &self.tls_identity
    }
}

pub fn map_validated_backend<T>(
    backend: &BackendInput,
    runtime_id: BackendId,
    address: SocketAddr,
    tls_identity: T,
) -> Result<PingoraBackend, String>
where
    T: Clone + Send + Sync + 'static,
{
    let mut mapped = PingoraBackend::new_with_weight(
        &address.to_string(),
        usize::try_from(backend.weight().get()).map_err(|_| {
            format!(
                "backend '{}' weight exceeds platform limits",
                backend.backend_id()
            )
        })?,
    )
    .map_err(|error| format!("failed to map backend '{}': {error}", backend.backend_id()))?;
    mapped.ext.insert(PingoraBackendIdentity {
        runtime_id,
        backend_id: backend.backend_id().to_string(),
        index: backend.index(),
        tls_identity,
    });
    Ok(mapped)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };

    use impulse_config::config::Backend;
    use pingora_load_balancing::discovery::ServiceDiscovery;

    use super::*;
    use crate::test_support::runtime_upstream_from_addresses;

    const GENERATION: u64 = 17;
    const HOSTNAME_BACKEND: &str = "http://backend.internal:8080";

    fn health_registry() -> Arc<HealthRegistry> {
        Arc::new(HealthRegistry::with_equivalence(|backend| {
            let mut hasher = DefaultHasher::new();
            backend.hash(&mut hasher);
            hasher.finish()
        }))
    }

    fn poll_ready<F: Future>(future: F) -> F::Output {
        let mut context = Context::from_waker(Waker::noop());
        let mut future = Box::pin(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("test future unexpectedly blocked"),
        }
    }

    fn hostname_backend_view(generation: u64) -> GenerationBackendView {
        let upstream = runtime_upstream_from_addresses("round-robin", None, &[HOSTNAME_BACKEND]);
        let backend_inputs = crate::test_support::backend_inputs(&upstream);
        GenerationBackendView::new(
            generation,
            "api",
            &backend_inputs,
            |backend| {
                map_validated_backend(
                    backend,
                    BackendId::new(backend.index() as u32),
                    SocketAddr::from(([0, 0, 0, 0], 8080)),
                    (),
                )
            },
            health_registry(),
        )
        .expect("hostname backend view")
    }

    fn hostname_runtime() -> PingoraLoadBalancingRuntimeState<()> {
        let upstream = runtime_upstream_from_addresses("round-robin", None, &[HOSTNAME_BACKEND]);
        let upstream_pools = HashMap::from([(
            "api".to_string(),
            Arc::new(RwLock::new(
                crate::test_support::upstream_pool(&upstream).expect("hostname upstream pool"),
            )),
        )]);
        PingoraLoadBalancingRuntimeState::new(
            GENERATION,
            upstream_pools,
            [(
                "api".to_string(),
                LoadBalancingStrategy::RoundRobin,
                hostname_backend_view(GENERATION),
            )],
            health_registry(),
        )
        .expect("hostname selector runtime")
    }

    fn selected_addresses(
        runtime: &PingoraLoadBalancingRuntimeState<()>,
        count: usize,
    ) -> BTreeSet<SocketAddr> {
        let selector = runtime
            .selector_by_id(UpstreamId::new(0))
            .expect("api selector");
        (0..count)
            .map(|_| {
                selector
                    .select_excluding("", &[])
                    .expect("selection")
                    .address()
            })
            .collect()
    }

    fn backend_view(weights: &[u32]) -> GenerationBackendView {
        let backends = weights
            .iter()
            .enumerate()
            .map(|(index, weight)| {
                let port = 8_000 + u16::try_from(index).expect("test backend index");
                let address = SocketAddr::from(([127, 0, 0, 1], port));
                let backend = Backend {
                    id: format!("backend-{index}"),
                    address: address.to_string(),
                    weight: *weight,
                    health_check: None,
                };
                let input = crate::test_support::backend_input(index, &backend);
                map_validated_backend(&input, BackendId::new(input.index() as u32), address, ())
            })
            .collect::<Result<BTreeSet<_>, _>>()
            .expect("map test backends");
        let view = BackendView::new(StaticDiscovery::new(backends));
        let mut context = Context::from_waker(Waker::noop());
        let mut update = Box::pin(view.update(|_| {}));
        assert!(matches!(
            update.as_mut().poll(&mut context),
            Poll::Ready(Ok(()))
        ));
        drop(update);

        GenerationBackendView {
            generation: GENERATION,
            upstream_name: "api".to_string(),
            backend_ids: Box::new([]),
            view,
            discovery: None,
        }
    }

    fn upstream_pools(count: usize) -> HashMap<String, Arc<RwLock<UpstreamPool>>> {
        let addresses = (0..count)
            .map(|index| format!("http://127.0.0.1:{}", 8_000 + index))
            .collect::<Vec<_>>();
        let address_refs = addresses.iter().map(String::as_str).collect::<Vec<_>>();
        let upstream = runtime_upstream_from_addresses("round-robin", None, &address_refs);
        HashMap::from([(
            "api".to_string(),
            Arc::new(RwLock::new(
                crate::test_support::upstream_pool(&upstream).expect("test upstream pool"),
            )),
        )])
    }

    #[test]
    fn validated_backend_mapping_preserves_weight() {
        let backend = Backend {
            id: "backend".to_string(),
            address: "127.0.0.1:8000".to_string(),
            weight: 3,
            health_check: None,
        };

        let input = crate::test_support::backend_input(0, &backend);
        let mapped = map_validated_backend(
            &input,
            BackendId::new(input.index() as u32),
            SocketAddr::from(([127, 0, 0, 1], 8000)),
            (),
        )
        .expect("map backend");

        assert_eq!(mapped.weight, 3);
    }

    #[test]
    fn selector_readiness_excludes_unhealthy_backends() {
        let selector =
            GenerationSelector::<()>::new(LoadBalancingStrategy::RoundRobin, backend_view(&[1, 1]))
                .expect("round-robin selector");
        selector
            .synchronize_readiness(|index| index == 1)
            .expect("synchronize readiness");

        for _ in 0..16 {
            assert_eq!(
                selector
                    .select_excluding("", &[])
                    .expect("selection")
                    .index(),
                1
            );
        }
    }

    #[test]
    fn retry_exclusions_apply_to_every_pingora_strategy() {
        for strategy in [
            LoadBalancingStrategy::RoundRobin,
            LoadBalancingStrategy::Random,
            LoadBalancingStrategy::ConsistentHash,
            LoadBalancingStrategy::StickyCid,
        ] {
            let selector = GenerationSelector::<()>::new(strategy, backend_view(&[1, 1]))
                .expect("Pingora selector");
            selector
                .synchronize_readiness(|_| true)
                .expect("synchronize readiness");

            for key in ["request-a", "request-b", "request-c"] {
                assert_eq!(
                    selector
                        .select_excluding(key, &[BackendId::new(0)])
                        .expect("alternate selection")
                        .index(),
                    1
                );
            }
        }
    }

    #[test]
    fn runtime_and_selection_preserve_selector_generation() {
        let runtime = PingoraLoadBalancingRuntimeState::<()>::new(
            GENERATION,
            upstream_pools(2),
            [(
                "api".to_string(),
                LoadBalancingStrategy::ConsistentHash,
                backend_view(&[1, 1]),
            )],
            health_registry(),
        )
        .expect("selector runtime");
        let selector = runtime
            .selector_by_id(UpstreamId::new(0))
            .expect("api selector");
        selector
            .synchronize_readiness(|_| true)
            .expect("synchronize readiness");

        assert_eq!(runtime.generation(), GENERATION);
        assert_eq!(selector.generation(), GENERATION);
        assert_eq!(
            selector
                .select_excluding("request", &[])
                .expect("selection")
                .generation(),
            GENERATION
        );
        assert!(
            PingoraLoadBalancingRuntimeState::<()>::new(
                GENERATION + 1,
                upstream_pools(1),
                [(
                    "api".to_string(),
                    LoadBalancingStrategy::RoundRobin,
                    backend_view(&[1]),
                )],
                health_registry(),
            )
            .is_err()
        );
    }

    #[test]
    fn dns_rotation_rebuilds_the_live_selector() {
        let runtime = hostname_runtime();
        let first = SocketAddr::from(([10, 0, 0, 1], 8080));
        let second = SocketAddr::from(([10, 0, 0, 2], 8080));
        let rotated = SocketAddr::from(([10, 0, 0, 3], 8080));

        let initial =
            poll_ready(runtime.publish_dns_result(HOSTNAME_BACKEND, Ok(vec![first, second])))
                .expect("initial DNS publication");
        assert!(initial.membership_changed());
        assert_eq!(initial.membership_generation(), 2);
        assert_eq!(
            selected_addresses(&runtime, 2),
            BTreeSet::from([first, second])
        );

        let update = poll_ready(runtime.publish_dns_result(HOSTNAME_BACKEND, Ok(vec![rotated])))
            .expect("rotated DNS publication");
        assert!(update.membership_changed());
        assert_eq!(update.membership_generation(), 3);
        assert_eq!(selected_addresses(&runtime, 1), BTreeSet::from([rotated]));
    }

    #[test]
    fn dns_failure_retains_the_last_known_good_selector_membership() {
        let runtime = hostname_runtime();
        let retained = SocketAddr::from(([10, 0, 0, 4], 8080));
        poll_ready(runtime.publish_dns_result(HOSTNAME_BACKEND, Ok(vec![retained])))
            .expect("initial DNS publication");

        assert!(
            poll_ready(
                runtime.publish_dns_result(HOSTNAME_BACKEND, Err("lookup failed".to_string()),)
            )
            .is_err()
        );
        assert_eq!(selected_addresses(&runtime, 1), BTreeSet::from([retained]));
    }

    #[test]
    fn dns_recovery_replaces_membership_after_a_failure() {
        let runtime = hostname_runtime();
        let retained = SocketAddr::from(([10, 0, 0, 5], 8080));
        let recovered = SocketAddr::from(([10, 0, 0, 6], 8080));
        poll_ready(runtime.publish_dns_result(HOSTNAME_BACKEND, Ok(vec![retained])))
            .expect("initial DNS publication");
        let _ = poll_ready(
            runtime.publish_dns_result(HOSTNAME_BACKEND, Err("lookup failed".to_string())),
        );

        let update = poll_ready(runtime.publish_dns_result(HOSTNAME_BACKEND, Ok(vec![recovered])))
            .expect("recovered DNS publication");
        assert_eq!(update.membership_generation(), 3);
        assert_eq!(selected_addresses(&runtime, 1), BTreeSet::from([recovered]));
    }

    #[test]
    fn stale_dns_result_cannot_mutate_a_newer_generation() {
        let view = hostname_backend_view(GENERATION);
        let discovery = view.discovery.as_ref().expect("service discovery");
        let before = poll_ready(discovery.discover())
            .expect("initial discovery")
            .0;

        assert!(
            discovery
                .publish_dns_result(
                    GENERATION - 1,
                    0,
                    Ok(vec![SocketAddr::from(([10, 0, 0, 7], 8080))]),
                )
                .is_err()
        );
        let after = poll_ready(discovery.discover())
            .expect("discovery after stale result")
            .0;
        assert_eq!(after, before);
    }

    fn ready_selector(strategy: LoadBalancingStrategy, weights: &[u32]) -> GenerationSelector<()> {
        let selector =
            GenerationSelector::<()>::new(strategy, backend_view(weights)).expect("selector");
        selector
            .synchronize_readiness(|_| true)
            .expect("synchronize readiness");
        selector
    }

    fn picks_for_worker(
        selector: &GenerationSelector<()>,
        worker_slot: usize,
        count: usize,
    ) -> Vec<usize> {
        (0..count)
            .map(|_| {
                selector
                    .select_excluding_for_worker("", &[], worker_slot)
                    .expect("selection")
                    .index()
            })
            .collect()
    }

    #[test]
    fn weighted_round_robin_follows_weights_within_a_worker() {
        let selector = ready_selector(LoadBalancingStrategy::RoundRobin, &[3, 1]);
        // Two full cycles of total weight 4.
        let picks = picks_for_worker(&selector, 0, 8);
        assert_eq!(picks.iter().filter(|index| **index == 0).count(), 6);
        assert_eq!(picks.iter().filter(|index| **index == 1).count(), 2);
    }

    #[test]
    fn round_robin_cursors_are_independent_per_worker() {
        let selector = ready_selector(LoadBalancingStrategy::RoundRobin, &[1, 1]);
        assert_eq!(picks_for_worker(&selector, 0, 2), vec![0, 1]);
        // Worker 0 already advanced; worker 1 still starts from its own cursor.
        assert_eq!(picks_for_worker(&selector, 1, 2), vec![0, 1]);
        // Slots wrap around the fixed slot table instead of panicking.
        assert!(
            selector
                .select_excluding_for_worker("", &[], WORKER_SELECTION_SLOTS + 3)
                .is_some()
        );
    }

    #[test]
    fn weighted_random_respects_weights() {
        let selector = ready_selector(LoadBalancingStrategy::Random, &[9, 1]);
        let picks = picks_for_worker(&selector, 0, 4_000);
        let heavy = picks.iter().filter(|index| **index == 0).count();
        // Expected 3600 with a standard deviation of about 19; allow a wide margin.
        assert!(
            (3_400..=3_800).contains(&heavy),
            "heavy backend picked {heavy} of 4000 times"
        );
    }

    #[test]
    fn weighted_selection_skips_excluded_and_unhealthy_backends() {
        for strategy in [
            LoadBalancingStrategy::RoundRobin,
            LoadBalancingStrategy::Random,
        ] {
            let selector = GenerationSelector::<()>::new(strategy, backend_view(&[1, 1, 1]))
                .expect("selector");
            selector
                .synchronize_readiness(|index| index != 1)
                .expect("synchronize readiness");
            for worker_slot in [0, 1, 7] {
                for _ in 0..32 {
                    let picked = selector
                        .select_excluding_for_worker("", &[BackendId::new(0)], worker_slot)
                        .expect("selection")
                        .index();
                    assert_eq!(
                        picked, 2,
                        "{strategy:?} picked an excluded or unhealthy backend"
                    );
                }
            }
        }
    }

    #[test]
    fn weighted_selection_returns_none_without_available_backends() {
        for strategy in [
            LoadBalancingStrategy::RoundRobin,
            LoadBalancingStrategy::Random,
        ] {
            let selector =
                GenerationSelector::<()>::new(strategy, backend_view(&[1, 1])).expect("selector");
            selector
                .synchronize_readiness(|_| false)
                .expect("synchronize readiness");
            assert!(selector.select_excluding_for_worker("", &[], 0).is_none());
        }
    }

    #[test]
    fn per_worker_selection_state_occupies_its_own_cache_line() {
        assert_eq!(std::mem::align_of::<Padded<AtomicUsize>>(), 64);
        assert_eq!(std::mem::size_of::<Padded<AtomicUsize>>(), 64);
        assert_eq!(std::mem::align_of::<Padded<AtomicU64>>(), 64);
        assert_eq!(std::mem::size_of::<Padded<AtomicU64>>(), 64);
    }
}
