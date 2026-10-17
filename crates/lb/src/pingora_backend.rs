use std::net::SocketAddr;

use impulse_config::config::Backend;
use pingora_load_balancing::Backend as PingoraBackend;

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
