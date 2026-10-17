use std::{
    collections::{BTreeSet, HashMap},
    net::SocketAddr,
    sync::Arc,
};

use impulse_config::{config::Backend, runtime::RuntimeUpstream};
use pingora_load_balancing::{
    Backend as PingoraBackend, BackendView, LoadBalancer,
    discovery::Static as StaticDiscovery,
    selection::{Random as PingoraRandom, RoundRobin as PingoraRoundRobin},
};

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
    backend_count: usize,
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
        } = view;
        let backend_count = view.get_backend().len();

        Self {
            generation,
            upstream_name,
            backend_count,
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
            .select_with(key, self.backend_count, |backend, healthy| {
                candidate_is_available::<T>(backend, healthy, excluded_backend_indices)
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
    backend_count: usize,
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
        } = view;
        let backend_count = view.get_backend().len();

        Self {
            generation,
            upstream_name,
            backend_count,
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
            .select_with(b"", self.backend_count, |backend, healthy| {
                candidate_is_available::<T>(backend, healthy, excluded_backend_indices)
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
    backend_count: usize,
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
        } = view;
        let backend_count = view.get_backend().len();

        Self {
            generation,
            upstream_name,
            backend_count,
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
            .select_with(b"", self.backend_count, |backend, healthy| {
                candidate_is_available::<T>(backend, healthy, excluded_backend_indices)
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
}

pub type SharedPingoraLoadBalancingRuntimeState = Arc<PingoraLoadBalancingRuntimeState>;

pub struct PingoraLoadBalancingRuntimeState {
    generation: u64,
    backend_views: HashMap<String, Arc<GenerationBackendView>>,
}

impl PingoraLoadBalancingRuntimeState {
    pub fn new(
        generation: u64,
        backend_views: impl IntoIterator<Item = (String, GenerationBackendView)>,
    ) -> Result<Self, String> {
        let mut views = HashMap::new();
        for (upstream_name, view) in backend_views {
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
            if views
                .insert(upstream_name.clone(), Arc::new(view))
                .is_some()
            {
                return Err(format!(
                    "duplicate Pingora backend view for upstream '{upstream_name}'"
                ));
            }
        }

        Ok(Self {
            generation,
            backend_views: views,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn backend_view(&self, upstream_name: &str) -> Option<&Arc<GenerationBackendView>> {
        self.backend_views.get(upstream_name)
    }

    pub fn len(&self) -> usize {
        self.backend_views.len()
    }

    pub fn is_empty(&self) -> bool {
        self.backend_views.is_empty()
    }
}

impl GenerationBackendView {
    pub async fn from_runtime_upstream<F>(
        generation: u64,
        upstream_name: impl Into<String>,
        upstream: &RuntimeUpstream,
        mut map_backend: F,
    ) -> Result<Self, String>
    where
        F: FnMut(usize, &Backend) -> Result<PingoraBackend, String>,
    {
        let upstream_name = upstream_name.into();
        let mapped = upstream
            .backends
            .iter()
            .enumerate()
            .map(|(index, backend)| map_backend(index, &backend.backend))
            .collect::<Result<BTreeSet<_>, _>>()?;

        if mapped.len() != upstream.backends.len() {
            return Err(format!(
                "upstream '{upstream_name}' contains backends that collapse to the same Pingora identity"
            ));
        }

        let view = BackendView::new(StaticDiscovery::new(mapped));
        view.update(|_| {})
            .await
            .map_err(|error| format!("failed to initialize upstream '{upstream_name}': {error}"))?;

        Ok(Self {
            generation,
            upstream_name,
            view,
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
