#[cfg(test)]
use std::collections::BTreeSet;
use std::{
    collections::HashMap,
    future::Future,
    hash::{BuildHasher, RandomState},
    net::SocketAddr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
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

pub use crate::backend::BackendSelectionState;
use crate::{
    BackendInput, LoadBalancingStrategy, RequestKeyInput,
    pingora_discovery::ImpulseServiceDiscovery, upstream_pool::UpstreamPool,
};

const WORKER_SELECTION_SLOTS: usize = 256;
const ACTIVE_REQUEST_PENALTY_MS: f64 = 10.0;
const UNSAMPLED_PROBE_INTERVAL: u64 = 16;
const EXPLORATION_INTERVAL: u64 = 32;

fn next_random(state: &AtomicU64) -> u64 {
    let value = state.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed);
    let mut mixed = value;
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    mixed ^ (mixed >> 31)
}

#[derive(Clone, Debug)]
pub struct BackendSelectionResult<P> {
    runtime_id: BackendId,
    backend_id: String,
    address: SocketAddr,
    index: usize,
    generation: u64,
    connection_policy: P,
    configured_address: Arc<str>,
    selection_state: Arc<BackendSelectionState>,
}

impl<P> BackendSelectionResult<P> {
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

    pub fn configured_address(&self) -> &str {
        &self.configured_address
    }

    pub fn begin_request(&self) {
        self.selection_state.begin_request();
    }
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
    let selection_state = backend.ext.get::<Arc<BackendSelectionState>>()?;

    Some(BackendSelectionResult {
        runtime_id: identity.runtime_id(),
        backend_id: identity.backend_id().to_string(),
        address,
        index: identity.index(),
        generation,
        connection_policy: identity.tls_identity().clone(),
        configured_address: Arc::clone(&identity.configured_address),
        selection_state: Arc::clone(selection_state),
    })
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

fn least_loaded_backend<T>(
    backends: &pingora_load_balancing::Backends,
    excluded_backend_ids: &[BackendId],
) -> Option<PingoraBackend>
where
    T: Clone + Send + Sync + 'static,
{
    backends
        .get_backend()
        .iter()
        .filter(|backend| {
            candidate_is_available::<T>(backend, backends.ready(backend), excluded_backend_ids)
        })
        .filter_map(|backend| {
            let identity = backend.ext.get::<PingoraBackendIdentity<T>>()?;
            let state = backend.ext.get::<Arc<BackendSelectionState>>()?;
            Some((state.active_requests(), identity.index(), backend))
        })
        .min_by_key(|(active_requests, index, _)| (*active_requests, *index))
        .map(|(_, _, backend)| backend)
        .cloned()
}

#[derive(Clone, Copy)]
struct SampledBackend<'a> {
    score: f64,
    active_requests: usize,
    index: usize,
    backend: &'a PingoraBackend,
}

#[derive(Clone, Copy)]
struct UnsampledBackend<'a> {
    score: f64,
    active_requests: usize,
    index: usize,
    backend: &'a PingoraBackend,
}

#[derive(Default)]
struct LatencyAwareSelectionState {
    unsampled_probe_cursor: AtomicU64,
    exploration_cursor: AtomicUsize,
    selections: AtomicU64,
}

fn rank_latency_backends<'a, T>(
    backends: &'a pingora_load_balancing::Backends,
    excluded_backend_ids: &[BackendId],
) -> (Option<SampledBackend<'a>>, Option<UnsampledBackend<'a>>)
where
    T: Clone + Send + Sync + 'static,
{
    let mut sampled_best = None;
    let mut unsampled_best: Option<UnsampledBackend<'_>> = None;
    let mut sampled_latency_sum = 0.0;
    let mut sampled_count = 0usize;

    for backend in backends.get_backend().iter().filter(|backend| {
        candidate_is_available::<T>(backend, backends.ready(backend), excluded_backend_ids)
    }) {
        let Some(identity) = backend.ext.get::<PingoraBackendIdentity<T>>() else {
            continue;
        };
        let Some(state) = backend.ext.get::<Arc<BackendSelectionState>>() else {
            continue;
        };
        let active_requests = state.active_requests();
        let index = identity.index();
        if let Some(ewma_latency_ms) = state.ewma_latency_ms() {
            let score = ewma_latency_ms + active_requests as f64 * ACTIVE_REQUEST_PENALTY_MS;
            sampled_latency_sum += ewma_latency_ms;
            sampled_count += 1;
            let candidate = SampledBackend {
                score,
                active_requests,
                index,
                backend,
            };
            if sampled_best.is_none_or(|best: SampledBackend<'_>| {
                score < best.score
                    || score == best.score
                        && (active_requests < best.active_requests
                            || active_requests == best.active_requests && index < best.index)
            }) {
                sampled_best = Some(candidate);
            }
        } else {
            let candidate = UnsampledBackend {
                score: 0.0,
                active_requests,
                index,
                backend,
            };
            if unsampled_best.is_none_or(|best| {
                active_requests < best.active_requests
                    || active_requests == best.active_requests && index < best.index
            }) {
                unsampled_best = Some(candidate);
            }
        }
    }

    if sampled_count == 0 {
        return (None, unsampled_best);
    }
    let neutral_baseline = sampled_latency_sum / sampled_count as f64;
    if let Some(candidate) = &mut unsampled_best {
        candidate.score =
            neutral_baseline + candidate.active_requests as f64 * ACTIVE_REQUEST_PENALTY_MS;
    }
    (sampled_best, unsampled_best)
}

fn periodic_latency_exploration<'a, T>(
    backends: &'a pingora_load_balancing::Backends,
    excluded_backend_ids: &[BackendId],
    state: &LatencyAwareSelectionState,
) -> Option<&'a PingoraBackend>
where
    T: Clone + Send + Sync + 'static,
{
    let selection = state
        .selections
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1);
    if !selection.is_multiple_of(EXPLORATION_INTERVAL) {
        return None;
    }
    let backend_set = backends.get_backend();
    let available_count = backend_set
        .iter()
        .filter(|backend| {
            candidate_is_available::<T>(backend, backends.ready(backend), excluded_backend_ids)
        })
        .count();
    if available_count < 2 {
        return None;
    }
    let position = state.exploration_cursor.fetch_add(1, Ordering::Relaxed) % available_count;
    backend_set
        .iter()
        .filter(|backend| {
            candidate_is_available::<T>(backend, backends.ready(backend), excluded_backend_ids)
        })
        .nth(position)
}

fn latency_aware_backend<'a, T>(
    backends: &'a pingora_load_balancing::Backends,
    excluded_backend_ids: &[BackendId],
    state: &LatencyAwareSelectionState,
) -> Option<&'a PingoraBackend>
where
    T: Clone + Send + Sync + 'static,
{
    if excluded_backend_ids.is_empty()
        && let Some(backend) =
            periodic_latency_exploration::<T>(backends, excluded_backend_ids, state)
    {
        return Some(backend);
    }

    let (sampled_best, unsampled_best) = rank_latency_backends::<T>(backends, excluded_backend_ids);
    if !excluded_backend_ids.is_empty() {
        return match (sampled_best, unsampled_best) {
            (Some(sampled), Some(unsampled)) if unsampled.score < sampled.score => {
                Some(unsampled.backend)
            }
            (Some(sampled), _) => Some(sampled.backend),
            (None, Some(unsampled)) => Some(unsampled.backend),
            (None, None) => None,
        };
    }

    let Some(sampled) = sampled_best else {
        return unsampled_best.map(|candidate| candidate.backend);
    };
    if let Some(unsampled) = unsampled_best {
        let probe = state
            .unsampled_probe_cursor
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        if unsampled.active_requests == 0 && probe.is_multiple_of(UNSAMPLED_PROBE_INTERVAL) {
            return Some(unsampled.backend);
        }
    }
    Some(sampled.backend)
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

    fn generation(&self) -> u64 {
        self.generation
    }

    fn upstream_name(&self) -> &str {
        &self.upstream_name
    }
}

struct GenerationLatencyAware<T> {
    generation: u64,
    upstream_name: String,
    backends: BackendView,
    worker_states: Box<[Padded<LatencyAwareSelectionState>]>,
    policy: std::marker::PhantomData<T>,
}

impl<T> GenerationLatencyAware<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn from_backend_view(view: GenerationBackendView) -> Self {
        let GenerationBackendView {
            generation,
            upstream_name,
            view,
            discovery: _,
        } = view;
        Self {
            generation,
            upstream_name,
            backends: view,
            worker_states: (0..WORKER_SELECTION_SLOTS)
                .map(|_| Padded(LatencyAwareSelectionState::default()))
                .collect(),
            policy: std::marker::PhantomData,
        }
    }

    fn select_excluding(
        &self,
        excluded_backend_ids: &[BackendId],
        worker_slot: usize,
    ) -> Option<BackendSelectionResult<T>> {
        let state = &self.worker_states[worker_slot % self.worker_states.len()].0;
        latency_aware_backend::<T>(&self.backends, excluded_backend_ids, state)
            .cloned()
            .and_then(|backend| selection_result(backend, self.generation))
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
    view: BackendView,
    discovery: Option<ImpulseServiceDiscovery>,
}

enum GenerationSelectorKind<T> {
    WeightedRoundRobin(GenerationWeightedRoundRobin<T>),
    WeightedRandom(GenerationWeightedRandom<T>),
    Ketama(GenerationKetama<T>),
    StickyCid(GenerationStickyCid<T>),
    LeastConnections(GenerationBackendView),
    LatencyAware(GenerationLatencyAware<T>),
}

pub struct GenerationSelector<T> {
    kind: GenerationSelectorKind<T>,
    strategy: LoadBalancingStrategy,
    request_key: Option<RequestKeyInput>,
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
            GenerationSelectorKind::LeastConnections(view) => &view.view,
            GenerationSelectorKind::LatencyAware(selector) => &selector.backends,
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
        request_key: Option<RequestKeyInput>,
        view: GenerationBackendView,
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
        if backend_ids
            .into_iter()
            .any(|backend_id| backend_id.is_none())
        {
            return Err(format!(
                "upstream '{}' has incomplete backend identities",
                view.upstream_name
            ));
        }
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
                GenerationSelectorKind::LeastConnections(view)
            }
            LoadBalancingStrategy::LatencyAware => GenerationSelectorKind::LatencyAware(
                GenerationLatencyAware::from_backend_view(view),
            ),
        };
        Ok(Self {
            kind,
            strategy,
            request_key,
        })
    }

    pub fn generation(&self) -> u64 {
        match &self.kind {
            GenerationSelectorKind::WeightedRoundRobin(selector) => selector.generation(),
            GenerationSelectorKind::WeightedRandom(selector) => selector.generation(),
            GenerationSelectorKind::Ketama(selector) => selector.generation(),
            GenerationSelectorKind::StickyCid(selector) => selector.generation(),
            GenerationSelectorKind::LeastConnections(view) => view.generation(),
            GenerationSelectorKind::LatencyAware(selector) => selector.generation(),
        }
    }

    pub fn upstream_name(&self) -> &str {
        match &self.kind {
            GenerationSelectorKind::WeightedRoundRobin(selector) => selector.upstream_name(),
            GenerationSelectorKind::WeightedRandom(selector) => selector.upstream_name(),
            GenerationSelectorKind::Ketama(selector) => selector.upstream_name(),
            GenerationSelectorKind::StickyCid(selector) => selector.upstream_name(),
            GenerationSelectorKind::LeastConnections(view) => view.upstream_name(),
            GenerationSelectorKind::LatencyAware(selector) => selector.upstream_name(),
        }
    }

    pub fn has_available_backend(&self) -> bool {
        let backends = self.backends();
        backends
            .get_backend()
            .iter()
            .any(|backend| candidate_is_available::<T>(backend, backends.ready(backend), &[]))
    }

    pub fn available_backend(&self, backend_id: BackendId) -> Option<BackendSelectionResult<T>> {
        let backends = self.backends();
        backends
            .get_backend()
            .iter()
            .find(|backend| {
                backends.ready(backend)
                    && backend
                        .ext
                        .get::<PingoraBackendIdentity<T>>()
                        .is_some_and(|identity| identity.runtime_id() == backend_id)
            })
            .cloned()
            .and_then(|backend| selection_result(backend, self.generation()))
    }

    pub const fn lb_strategy(&self) -> LoadBalancingStrategy {
        self.strategy
    }

    pub fn lb_key_spec(&self) -> Option<&RequestKeyInput> {
        self.request_key.as_ref()
    }

    fn backend_id_by_configured_address(&self, configured_address: &str) -> Option<BackendId> {
        self.backends().get_backend().iter().find_map(|backend| {
            let identity = backend.ext.get::<PingoraBackendIdentity<T>>()?;
            (identity.configured_address() == configured_address).then_some(identity.runtime_id())
        })
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
            GenerationSelectorKind::LeastConnections(view) => {
                least_loaded_backend::<T>(&view.view, excluded_backend_ids)
                    .and_then(|backend| selection_result(backend, view.generation))
            }
            GenerationSelectorKind::LatencyAware(selector) => {
                selector.select_excluding(excluded_backend_ids, worker_slot)
            }
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
            GenerationSelectorKind::LeastConnections(view) => view.view.update(|_| {}).await,
            GenerationSelectorKind::LatencyAware(selector) => {
                selector.backends.update(|_| {}).await
            }
        };
        result.map_err(|error| {
            format!(
                "failed to rebuild Pingora selector for upstream '{}': {error}",
                self.upstream_name()
            )
        })?;
        Ok(())
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
    selectors_by_id: Box<[Arc<GenerationSelector<T>>]>,
    discoveries_by_id: Box<[Option<ImpulseServiceDiscovery>]>,
    health_registry: Arc<HealthRegistry>,
}

impl<T> PingoraLoadBalancingRuntimeState<T>
where
    T: Clone + Send + Sync + 'static,
{
    pub fn set_backend_enabled(&self, backend_id: BackendId, enabled: bool) {
        for selector in &self.selectors_by_id {
            selector.set_backend_enabled(backend_id, enabled);
        }
    }

    pub fn new(
        generation: u64,
        upstream_pools: HashMap<String, Arc<RwLock<UpstreamPool>>>,
        backend_views: impl IntoIterator<
            Item = (
                String,
                LoadBalancingStrategy,
                Option<RequestKeyInput>,
                GenerationBackendView,
            ),
        >,
        health_registry: Arc<HealthRegistry>,
    ) -> Result<Self, String> {
        let mut selectors = HashMap::new();
        let mut discoveries = HashMap::new();
        for (upstream_name, strategy, request_key, view) in backend_views {
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
            let selector = GenerationSelector::new(strategy, request_key, view)?;
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
        Ok(Self {
            generation,
            upstream_names: upstream_names.into_boxed_slice(),
            upstream_pools_by_id,
            selectors_by_id,
            discoveries_by_id,
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

    pub fn backend_id_by_address(
        &self,
        upstream_name: &str,
        configured_address: &str,
    ) -> Option<BackendId> {
        let upstream_index = self
            .upstream_names
            .binary_search_by(|name| name.as_str().cmp(upstream_name))
            .ok()?;
        self.selectors_by_id[upstream_index].backend_id_by_configured_address(configured_address)
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
        let rebuild_duration = if publication.membership_changed() {
            let started = Instant::now();
            selector.rebuild().await?;
            started.elapsed()
        } else {
            Duration::ZERO
        };
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
}

#[derive(Clone)]
pub struct PingoraBackendIdentity<T> {
    runtime_id: BackendId,
    backend_id: String,
    index: usize,
    tls_identity: T,
    configured_address: Arc<str>,
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

    pub fn configured_address(&self) -> &str {
        &self.configured_address
    }
}

pub fn map_validated_backend<T>(
    backend: &BackendInput,
    runtime_id: BackendId,
    address: SocketAddr,
    tls_identity: T,
    selection_state: Arc<BackendSelectionState>,
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
        configured_address: Arc::from(backend.configured_address()),
    });
    mapped.ext.insert(selection_state);
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
                    Arc::default(),
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
                None,
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
                    protocol: Default::default(),
                    weight: *weight,
                    health_check: None,
                };
                let input = crate::test_support::backend_input(index, &backend);
                map_validated_backend(
                    &input,
                    BackendId::new(input.index() as u32),
                    address,
                    (),
                    Arc::default(),
                )
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

    fn set_test_readiness(
        selector: &GenerationSelector<()>,
        mut is_ready: impl FnMut(usize) -> bool,
    ) {
        for backend in selector.backends().get_backend().iter() {
            let identity = backend
                .ext
                .get::<PingoraBackendIdentity<()>>()
                .expect("test backend identity");
            selector.set_backend_enabled(identity.runtime_id(), is_ready(identity.index()));
        }
    }

    #[test]
    fn validated_backend_mapping_preserves_weight() {
        let backend = Backend {
            id: "backend".to_string(),
            address: "127.0.0.1:8000".to_string(),
            protocol: Default::default(),
            weight: 3,
            health_check: None,
        };

        let input = crate::test_support::backend_input(0, &backend);
        let mapped = map_validated_backend(
            &input,
            BackendId::new(input.index() as u32),
            SocketAddr::from(([127, 0, 0, 1], 8000)),
            (),
            Arc::default(),
        )
        .expect("map backend");

        assert_eq!(mapped.weight, 3);
    }

    #[test]
    fn selector_readiness_excludes_unhealthy_backends() {
        let selector = GenerationSelector::<()>::new(
            LoadBalancingStrategy::RoundRobin,
            None,
            backend_view(&[1, 1]),
        )
        .expect("round-robin selector");
        set_test_readiness(&selector, |index| index == 1);

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
            let selector = GenerationSelector::<()>::new(strategy, None, backend_view(&[1, 1]))
                .expect("Pingora selector");
            set_test_readiness(&selector, |_| true);

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
                None,
                backend_view(&[1, 1]),
            )],
            health_registry(),
        )
        .expect("selector runtime");
        let selector = runtime
            .selector_by_id(UpstreamId::new(0))
            .expect("api selector");
        runtime.set_backend_enabled(BackendId::new(0), true);
        runtime.set_backend_enabled(BackendId::new(1), true);

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
                    None,
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
            GenerationSelector::<()>::new(strategy, None, backend_view(weights)).expect("selector");
        set_test_readiness(&selector, |_| true);
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
            let selector = GenerationSelector::<()>::new(strategy, None, backend_view(&[1, 1, 1]))
                .expect("selector");
            set_test_readiness(&selector, |index| index != 1);
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
            let selector = GenerationSelector::<()>::new(strategy, None, backend_view(&[1, 1]))
                .expect("selector");
            set_test_readiness(&selector, |_| false);
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
