use std::{collections::BTreeSet, net::SocketAddr};

use impulse_config::{config::Backend, runtime::RuntimeUpstream};
use pingora_load_balancing::{
    Backend as PingoraBackend, BackendView, discovery::Static as StaticDiscovery,
};

pub struct GenerationBackendView {
    generation: u64,
    upstream_name: String,
    view: BackendView,
}

impl GenerationBackendView {
    pub async fn from_runtime_upstream<F>(
        generation: u64,
        upstream_name: impl Into<String>,
        upstream: &RuntimeUpstream,
        mut map_backend: F,
    ) -> Result<Self, String>
    where
        F: FnMut(&Backend) -> Result<PingoraBackend, String>,
    {
        let upstream_name = upstream_name.into();
        let mapped = upstream
            .backends
            .iter()
            .map(|backend| map_backend(&backend.backend))
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

    pub fn into_view(self) -> BackendView {
        self.view
    }
}

#[derive(Clone)]
pub struct PingoraBackendIdentity<T> {
    backend_id: String,
    configured_address: String,
    tls_identity: T,
}

impl<T> PingoraBackendIdentity<T> {
    pub fn backend_id(&self) -> &str {
        &self.backend_id
    }

    pub fn configured_address(&self) -> &str {
        &self.configured_address
    }

    pub fn tls_identity(&self) -> &T {
        &self.tls_identity
    }
}

pub fn map_validated_backend<T>(
    backend: &Backend,
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
        tls_identity,
    });
    Ok(mapped)
}
