use std::{
    collections::{BTreeSet, HashMap},
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use impulse_config::{config::Backend, runtime::RuntimeUpstream};
use pingora_load_balancing::{Backend as PingoraBackend, discovery::ServiceDiscovery};

#[derive(Clone)]
pub struct ImpulseServiceDiscovery {
    upstream_name: String,
    backends: Arc<RwLock<Vec<BTreeSet<PingoraBackend>>>>,
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
            .map(|(index, backend)| {
                map_backend(index, &backend.backend).map(|backend| BTreeSet::from([backend]))
            })
            .collect::<Result<Vec<_>, _>>()?;

        if backend_snapshot(&backends).len() != upstream.backends.len() {
            return Err(format!(
                "upstream '{upstream_name}' contains backends that collapse to the same Pingora identity"
            ));
        }

        Ok(Self {
            upstream_name: upstream_name.to_string(),
            backends: Arc::new(RwLock::new(backends)),
        })
    }

    pub fn publish_dns_result(
        &self,
        backend_index: usize,
        resolved_addrs: Result<Vec<SocketAddr>, String>,
    ) -> Result<(), String> {
        let resolved_addrs = resolved_addrs.map_err(|error| {
            format!(
                "upstream '{}' backend {backend_index} DNS resolution failed: {error}",
                self.upstream_name
            )
        })?;
        self.publish_resolved_backend(backend_index, resolved_addrs)
    }

    pub fn publish_resolved_backend(
        &self,
        backend_index: usize,
        resolved_addrs: impl IntoIterator<Item = SocketAddr>,
    ) -> Result<(), String> {
        let mut backends = self
            .backends
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let current = backends.get(backend_index).ok_or_else(|| {
            format!(
                "upstream '{}' has no backend at index {backend_index}",
                self.upstream_name
            )
        })?;
        let template = current
            .iter()
            .next()
            .expect("backend membership is non-empty");
        let port = template
            .addr
            .as_inet()
            .expect("validated Pingora backend uses an IP socket address")
            .port();
        let resolved = resolved_addrs
            .into_iter()
            .map(|address| {
                let mut backend = template.clone();
                backend.addr = SocketAddr::new(address.ip(), port).into();
                backend
            })
            .collect::<BTreeSet<_>>();
        if resolved.is_empty() {
            return Err(format!(
                "upstream '{}' backend {backend_index} resolved to no addresses",
                self.upstream_name
            ));
        }

        let expected_len = backends
            .iter()
            .enumerate()
            .map(|(index, members)| {
                if index == backend_index {
                    resolved.len()
                } else {
                    members.len()
                }
            })
            .sum();
        let published = backends
            .iter()
            .enumerate()
            .flat_map(|(index, members)| {
                if index == backend_index {
                    resolved.iter()
                } else {
                    members.iter()
                }
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        if published.len() != expected_len {
            return Err(format!(
                "upstream '{}' DNS results collapse distinct backends to the same Pingora identity",
                self.upstream_name
            ));
        }

        backends[backend_index] = resolved;
        Ok(())
    }
}

#[async_trait]
impl ServiceDiscovery for ImpulseServiceDiscovery {
    async fn discover(
        &self,
    ) -> pingora_error::Result<(BTreeSet<PingoraBackend>, HashMap<u64, bool>)> {
        let backends = self
            .backends
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok((backend_snapshot(&backends), HashMap::new()))
    }
}

fn backend_snapshot(backends: &[BTreeSet<PingoraBackend>]) -> BTreeSet<PingoraBackend> {
    backends
        .iter()
        .flat_map(|members| members.iter().cloned())
        .collect()
}
