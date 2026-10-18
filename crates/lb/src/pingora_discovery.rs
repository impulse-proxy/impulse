use std::collections::{BTreeSet, HashMap};

use async_trait::async_trait;
use impulse_config::{config::Backend, runtime::RuntimeUpstream};
use pingora_load_balancing::{Backend as PingoraBackend, discovery::ServiceDiscovery};

pub struct ImpulseServiceDiscovery {
    backends: BTreeSet<PingoraBackend>,
}

impl ImpulseServiceDiscovery {
    pub fn from_runtime_upstream<F>(
        upstream_name: &str,
        upstream: &RuntimeUpstream,
        mut map_backend: F,
    ) -> Result<Self, String>
    where
        F: FnMut(usize, &Backend) -> Result<PingoraBackend, String>,
    {
        let backends = upstream
            .backends
            .iter()
            .enumerate()
            .map(|(index, backend)| map_backend(index, &backend.backend))
            .collect::<Result<BTreeSet<_>, _>>()?;

        if backends.len() != upstream.backends.len() {
            return Err(format!(
                "upstream '{upstream_name}' contains backends that collapse to the same Pingora identity"
            ));
        }

        Ok(Self { backends })
    }
}

#[async_trait]
impl ServiceDiscovery for ImpulseServiceDiscovery {
    async fn discover(
        &self,
    ) -> pingora_error::Result<(BTreeSet<PingoraBackend>, HashMap<u64, bool>)> {
        Ok((self.backends.clone(), HashMap::new()))
    }
}
