#[cfg(test)]
use std::collections::BTreeSet;
use std::{
    collections::HashMap,
    future::Future,
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
    time::{Duration, Instant},
};

use impulse_config::{
    config::Backend,
    runtime::{RuntimeLoadBalancingStrategy, RuntimeUpstream},
};
#[cfg(test)]
use pingora_load_balancing::discovery::{ServiceDiscovery, Static as StaticDiscovery};
use pingora_load_balancing::{
    Backend as PingoraBackend, BackendView, LoadBalancer,
    selection::{Random as PingoraRandom, RoundRobin as PingoraRoundRobin},
};

use crate::pingora_discovery::ImpulseServiceDiscovery;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendSelectionResult<P> {
    backend_id: String,
    address: SocketAddr,
    index: usize,
    generation: u64,
    connection_policy: P,
}

impl<P> BackendSelectionResult<P> {
    pub fn new(
        backend_id: impl Into<String>,
        address: SocketAddr,
        index: usize,
        generation: u64,
        connection_policy: P,
    ) -> Self {
        Self {
            backend_id: backend_id.into(),
            address,
            index,
            generation,
            connection_policy,
        }
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

    pub fn into_connection_policy(self) -> P {
        self.connection_policy
    }
}

pub fn synchronize_backend_readiness<T>(
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
    excluded_backend_indices: &[usize],
) -> bool
where
    T: Clone + Send + Sync + 'static,
{
    healthy
        && backend
            .ext
            .get::<PingoraBackendIdentity<T>>()
            .is_some_and(|identity| !excluded_backend_indices.contains(&identity.index()))
}

fn first_available_backend<T>(
    backends: &pingora_load_balancing::Backends,
    excluded_backend_indices: &[usize],
) -> Option<PingoraBackend>
where
    T: Clone + Send + Sync + 'static,
{
    backends
        .get_backend()
        .iter()
        .find(|backend| {
            candidate_is_available::<T>(backend, backends.ready(backend), excluded_backend_indices)
        })
        .cloned()
}

pub struct GenerationStickyCid<T> {
    selector: GenerationKetama<T>,
}

impl<T> GenerationStickyCid<T>
where
    T: Clone + Send + Sync + 'static,
{
    pub fn from_backend_view(view: GenerationBackendView) -> Self {
        Self {
            selector: GenerationKetama::from_backend_view(view),
        }
    }

    pub fn select(&self, cid_key: &str) -> Option<BackendSelectionResult<T>> {
        self.select_excluding(cid_key, &[])
    }

    pub fn select_excluding(
        &self,
        cid_key: &str,
        excluded_backend_indices: &[usize],
    ) -> Option<BackendSelectionResult<T>> {
        self.selector
            .select_excluding(cid_key.as_bytes(), excluded_backend_indices)
    }

    pub fn synchronize_readiness(
        &self,
        is_healthy: impl FnMut(usize) -> bool,
    ) -> Result<(), String> {
        self.selector.synchronize_readiness(is_healthy)
    }

    pub fn generation(&self) -> u64 {
        self.selector.generation()
    }

    pub fn upstream_name(&self) -> &str {
        self.selector.upstream_name()
    }
}

pub struct GenerationKetama<T> {
    generation: u64,
    upstream_name: String,
    selector: LoadBalancer<pingora_load_balancing::selection::Consistent>,
    policy: std::marker::PhantomData<T>,
}

impl<T> GenerationKetama<T>
where
    T: Clone + Send + Sync + 'static,
{
    pub fn from_backend_view(view: GenerationBackendView) -> Self {
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

    pub fn select(&self, key: &[u8]) -> Option<BackendSelectionResult<T>> {
        self.select_excluding(key, &[])
    }

    pub fn select_excluding(
        &self,
        key: &[u8],
        excluded_backend_indices: &[usize],
    ) -> Option<BackendSelectionResult<T>> {
        let selected = self
            .selector
            .select_with(
                key,
                self.selector.backends().get_backend().len(),
                |backend, healthy| {
                    candidate_is_available::<T>(backend, healthy, excluded_backend_indices)
                },
            )
            .or_else(|| {
                first_available_backend::<T>(self.selector.backends(), excluded_backend_indices)
            })?;
        selection_result(selected, self.generation)
    }

    pub fn synchronize_readiness(
        &self,
        is_healthy: impl FnMut(usize) -> bool,
    ) -> Result<(), String> {
        synchronize_backend_readiness::<T>(self.selector.backends(), is_healthy)
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn upstream_name(&self) -> &str {
        &self.upstream_name
    }
}

pub struct GenerationWeightedRandom<T> {
    generation: u64,
    upstream_name: String,
    selector: LoadBalancer<PingoraRandom>,
    policy: std::marker::PhantomData<T>,
}

impl<T> GenerationWeightedRandom<T>
where
    T: Clone + Send + Sync + 'static,
{
    pub fn from_backend_view(view: GenerationBackendView) -> Self {
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

    pub fn select(&self) -> Option<BackendSelectionResult<T>> {
        self.select_excluding(&[])
    }

    pub fn select_excluding(
        &self,
        excluded_backend_indices: &[usize],
    ) -> Option<BackendSelectionResult<T>> {
        let selected = self
            .selector
            .select_with(
                b"",
                self.selector.backends().get_backend().len(),
                |backend, healthy| {
                    candidate_is_available::<T>(backend, healthy, excluded_backend_indices)
                },
            )
            .or_else(|| {
                first_available_backend::<T>(self.selector.backends(), excluded_backend_indices)
            })?;
        selection_result(selected, self.generation)
    }

    pub fn synchronize_readiness(
        &self,
        is_healthy: impl FnMut(usize) -> bool,
    ) -> Result<(), String> {
        synchronize_backend_readiness::<T>(self.selector.backends(), is_healthy)
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn upstream_name(&self) -> &str {
        &self.upstream_name
    }
}

pub struct GenerationWeightedRoundRobin<T> {
    generation: u64,
    upstream_name: String,
    selector: LoadBalancer<PingoraRoundRobin>,
    policy: std::marker::PhantomData<T>,
}

impl<T> GenerationWeightedRoundRobin<T>
where
    T: Clone + Send + Sync + 'static,
{
    pub fn from_backend_view(view: GenerationBackendView) -> Self {
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

    pub fn select(&self) -> Option<BackendSelectionResult<T>> {
        self.select_excluding(&[])
    }

    pub fn select_excluding(
        &self,
        excluded_backend_indices: &[usize],
    ) -> Option<BackendSelectionResult<T>> {
        let selected = self
            .selector
            .select_with(
                b"",
                self.selector.backends().get_backend().len(),
                |backend, healthy| {
                    candidate_is_available::<T>(backend, healthy, excluded_backend_indices)
                },
            )
            .or_else(|| {
                first_available_backend::<T>(self.selector.backends(), excluded_backend_indices)
            })?;
        selection_result(selected, self.generation)
    }

    pub fn synchronize_readiness(
        &self,
        is_healthy: impl FnMut(usize) -> bool,
    ) -> Result<(), String> {
        synchronize_backend_readiness::<T>(self.selector.backends(), is_healthy)
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn upstream_name(&self) -> &str {
        &self.upstream_name
    }
}

pub struct GenerationBackendView {
    generation: u64,
    upstream_name: String,
    view: BackendView,
    discovery: Option<ImpulseServiceDiscovery>,
}

pub enum GenerationSelector<T> {
    WeightedRoundRobin(GenerationWeightedRoundRobin<T>),
    WeightedRandom(GenerationWeightedRandom<T>),
    Ketama(GenerationKetama<T>),
    StickyCid(GenerationStickyCid<T>),
    CustomLeastConnections(GenerationBackendView),
    CustomLatencyAware(GenerationBackendView),
    Unsupported(GenerationBackendView),
}

impl<T> GenerationSelector<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn new(strategy: RuntimeLoadBalancingStrategy, view: GenerationBackendView) -> Self {
        match strategy {
            RuntimeLoadBalancingStrategy::RoundRobin => {
                Self::WeightedRoundRobin(GenerationWeightedRoundRobin::from_backend_view(view))
            }
            RuntimeLoadBalancingStrategy::Random => {
                Self::WeightedRandom(GenerationWeightedRandom::from_backend_view(view))
            }
            RuntimeLoadBalancingStrategy::ConsistentHash => {
                Self::Ketama(GenerationKetama::from_backend_view(view))
            }
            RuntimeLoadBalancingStrategy::StickyCid => {
                Self::StickyCid(GenerationStickyCid::from_backend_view(view))
            }
            RuntimeLoadBalancingStrategy::LeastConnections => Self::CustomLeastConnections(view),
            RuntimeLoadBalancingStrategy::LatencyAware => Self::CustomLatencyAware(view),
            RuntimeLoadBalancingStrategy::Other => Self::Unsupported(view),
        }
    }

    pub fn generation(&self) -> u64 {
        match self {
            Self::WeightedRoundRobin(selector) => selector.generation(),
            Self::WeightedRandom(selector) => selector.generation(),
            Self::Ketama(selector) => selector.generation(),
            Self::StickyCid(selector) => selector.generation(),
            Self::CustomLeastConnections(view)
            | Self::CustomLatencyAware(view)
            | Self::Unsupported(view) => view.generation(),
        }
    }

    pub fn upstream_name(&self) -> &str {
        match self {
            Self::WeightedRoundRobin(selector) => selector.upstream_name(),
            Self::WeightedRandom(selector) => selector.upstream_name(),
            Self::Ketama(selector) => selector.upstream_name(),
            Self::StickyCid(selector) => selector.upstream_name(),
            Self::CustomLeastConnections(view)
            | Self::CustomLatencyAware(view)
            | Self::Unsupported(view) => view.upstream_name(),
        }
    }

    pub fn uses_custom_dynamic_selector(&self) -> bool {
        matches!(
            self,
            Self::CustomLeastConnections(_) | Self::CustomLatencyAware(_)
        )
    }

    pub fn synchronize_readiness(
        &self,
        is_healthy: impl FnMut(usize) -> bool,
    ) -> Result<(), String> {
        match self {
            Self::WeightedRoundRobin(selector) => selector.synchronize_readiness(is_healthy),
            Self::WeightedRandom(selector) => selector.synchronize_readiness(is_healthy),
            Self::Ketama(selector) => selector.synchronize_readiness(is_healthy),
            Self::StickyCid(selector) => selector.synchronize_readiness(is_healthy),
            Self::CustomLeastConnections(view)
            | Self::CustomLatencyAware(view)
            | Self::Unsupported(view) => view.synchronize_readiness::<T>(is_healthy),
        }
    }

    pub fn select_excluding(
        &self,
        key: &str,
        excluded_backend_indices: &[usize],
    ) -> Option<BackendSelectionResult<T>> {
        match self {
            Self::WeightedRoundRobin(selector) => {
                selector.select_excluding(excluded_backend_indices)
            }
            Self::WeightedRandom(selector) => selector.select_excluding(excluded_backend_indices),
            Self::Ketama(selector) => {
                selector.select_excluding(key.as_bytes(), excluded_backend_indices)
            }
            Self::StickyCid(selector) => selector.select_excluding(key, excluded_backend_indices),
            Self::CustomLeastConnections(_)
            | Self::CustomLatencyAware(_)
            | Self::Unsupported(_) => None,
        }
    }

    async fn rebuild(&self) -> Result<(), String> {
        let result = match self {
            Self::WeightedRoundRobin(selector) => selector.selector.update().await,
            Self::WeightedRandom(selector) => selector.selector.update().await,
            Self::Ketama(selector) => selector.selector.update().await,
            Self::StickyCid(selector) => selector.selector.selector.update().await,
            Self::CustomLeastConnections(view)
            | Self::CustomLatencyAware(view)
            | Self::Unsupported(view) => view.view.update(|_| {}).await,
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

pub struct PingoraLoadBalancingRuntimeState<T> {
    generation: u64,
    selectors: HashMap<String, Arc<GenerationSelector<T>>>,
    discoveries: HashMap<String, ImpulseServiceDiscovery>,
}

impl<T> PingoraLoadBalancingRuntimeState<T>
where
    T: Clone + Send + Sync + 'static,
{
    pub fn new(
        generation: u64,
        backend_views: impl IntoIterator<
            Item = (String, RuntimeLoadBalancingStrategy, GenerationBackendView),
        >,
    ) -> Result<Self, String> {
        let mut selectors = HashMap::new();
        let mut discoveries = HashMap::new();
        for (upstream_name, strategy, view) in backend_views {
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
            let selector = GenerationSelector::new(strategy, view);
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

        Ok(Self {
            generation,
            selectors,
            discoveries,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn selector(&self, upstream_name: &str) -> Option<&Arc<GenerationSelector<T>>> {
        self.selectors.get(upstream_name)
    }

    pub fn len(&self) -> usize {
        self.selectors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.selectors.is_empty()
    }

    pub async fn publish_dns_result(
        &self,
        configured_address: &str,
        resolved_addrs: Result<Vec<SocketAddr>, String>,
    ) -> Result<PingoraDiscoveryUpdate, String> {
        let (upstream_name, discovery, backend_index) = self
            .discoveries
            .iter()
            .find_map(|(upstream_name, discovery)| {
                discovery
                    .backend_index(configured_address)
                    .map(|backend_index| (upstream_name, discovery, backend_index))
            })
            .ok_or_else(|| {
                format!(
                    "no Pingora discovery backend matches configured address '{configured_address}'"
                )
            })?;
        let publication =
            discovery.publish_dns_result(self.generation, backend_index, resolved_addrs)?;
        let started = Instant::now();
        self.selectors
            .get(upstream_name)
            .expect("discovery and selector maps share upstream keys")
            .rebuild()
            .await?;
        let rebuild_duration = started.elapsed();
        Ok(PingoraDiscoveryUpdate {
            upstream_name: upstream_name.clone(),
            membership_generation: publication.membership_generation(),
            membership_changed: publication.membership_changed(),
            rebuild_duration,
        })
    }
}

impl GenerationBackendView {
    pub fn from_runtime_upstream<F>(
        generation: u64,
        upstream_name: impl Into<String>,
        upstream: &RuntimeUpstream,
        mut map_backend: F,
    ) -> Result<Self, String>
    where
        F: FnMut(usize, &Backend) -> Result<PingoraBackend, String>,
    {
        let upstream_name = upstream_name.into();
        let discovery = ImpulseServiceDiscovery::from_runtime_upstream(
            generation,
            &upstream_name,
            upstream,
            &mut map_backend,
        )?;
        let view = BackendView::new(Box::new(discovery.clone()));
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
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

    pub fn view(&self) -> &BackendView {
        &self.view
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

    pub fn into_view(self) -> BackendView {
        self.view
    }
}

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

#[derive(Clone)]
pub struct PingoraBackendIdentity<T> {
    backend_id: String,
    configured_address: String,
    index: usize,
    tls_identity: T,
}

impl<T> PingoraBackendIdentity<T> {
    pub fn backend_id(&self) -> &str {
        &self.backend_id
    }

    pub fn configured_address(&self) -> &str {
        &self.configured_address
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn tls_identity(&self) -> &T {
        &self.tls_identity
    }
}

pub fn map_validated_backend<T>(
    backend: &Backend,
    index: usize,
    address: SocketAddr,
    tls_identity: T,
) -> Result<PingoraBackend, String>
where
    T: Clone + Send + Sync + 'static,
{
    let mut mapped = PingoraBackend::new_with_weight(
        &address.to_string(),
        usize::try_from(backend.weight)
            .map_err(|_| format!("backend '{}' weight exceeds platform limits", backend.id))?,
    )
    .map_err(|error| format!("failed to map backend '{}': {error}", backend.id))?;
    mapped.ext.insert(PingoraBackendIdentity {
        backend_id: backend.id.clone(),
        configured_address: backend.address.clone(),
        index,
        tls_identity,
    });
    Ok(mapped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::runtime_upstream_from_addresses;

    const GENERATION: u64 = 17;
    const HOSTNAME_BACKEND: &str = "http://backend.internal:8080";

    fn poll_ready<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        let mut future = Box::pin(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("test future unexpectedly blocked"),
        }
    }

    fn hostname_backend_view(generation: u64) -> GenerationBackendView {
        let upstream = runtime_upstream_from_addresses("round-robin", None, &[HOSTNAME_BACKEND]);
        GenerationBackendView::from_runtime_upstream(
            generation,
            "api",
            &upstream,
            |index, backend| {
                map_validated_backend(backend, index, SocketAddr::from(([0, 0, 0, 0], 8080)), ())
            },
        )
        .expect("hostname backend view")
    }

    fn hostname_runtime() -> PingoraLoadBalancingRuntimeState<()> {
        PingoraLoadBalancingRuntimeState::new(
            GENERATION,
            [(
                "api".to_string(),
                RuntimeLoadBalancingStrategy::RoundRobin,
                hostname_backend_view(GENERATION),
            )],
        )
        .expect("hostname selector runtime")
    }

    fn selected_addresses(
        runtime: &PingoraLoadBalancingRuntimeState<()>,
        count: usize,
    ) -> BTreeSet<SocketAddr> {
        let selector = runtime.selector("api").expect("api selector");
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
                map_validated_backend(&backend, index, address, ())
            })
            .collect::<Result<BTreeSet<_>, _>>()
            .expect("map test backends");
        let view = BackendView::new(StaticDiscovery::new(backends));
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
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

    #[test]
    fn validated_backend_mapping_preserves_weight() {
        let backend = Backend {
            id: "backend".to_string(),
            address: "127.0.0.1:8000".to_string(),
            weight: 3,
            health_check: None,
        };

        let mapped =
            map_validated_backend(&backend, 0, SocketAddr::from(([127, 0, 0, 1], 8000)), ())
                .expect("map backend");

        assert_eq!(mapped.weight, 3);
    }

    #[test]
    fn selector_readiness_excludes_unhealthy_backends() {
        let selector = GenerationSelector::<()>::new(
            RuntimeLoadBalancingStrategy::RoundRobin,
            backend_view(&[1, 1]),
        );
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
            RuntimeLoadBalancingStrategy::RoundRobin,
            RuntimeLoadBalancingStrategy::Random,
            RuntimeLoadBalancingStrategy::ConsistentHash,
            RuntimeLoadBalancingStrategy::StickyCid,
        ] {
            let selector = GenerationSelector::<()>::new(strategy, backend_view(&[1, 1]));
            selector
                .synchronize_readiness(|_| true)
                .expect("synchronize readiness");

            for key in ["request-a", "request-b", "request-c"] {
                assert_eq!(
                    selector
                        .select_excluding(key, &[0])
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
            [(
                "api".to_string(),
                RuntimeLoadBalancingStrategy::ConsistentHash,
                backend_view(&[1, 1]),
            )],
        )
        .expect("selector runtime");
        let selector = runtime.selector("api").expect("api selector");
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
                [(
                    "api".to_string(),
                    RuntimeLoadBalancingStrategy::RoundRobin,
                    backend_view(&[1]),
                )],
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
}
