use std::{
    collections::{BTreeSet, HashMap},
    net::SocketAddr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use async_trait::async_trait;
use impulse_config::{config::Backend, runtime::RuntimeUpstream};
use pingora_load_balancing::{Backend as PingoraBackend, discovery::ServiceDiscovery};

#[derive(Clone)]
pub(crate) struct ImpulseServiceDiscovery {
    generation: u64,
    upstream_name: String,
    backend_addresses: Arc<Vec<String>>,
    backends: Arc<RwLock<Vec<BTreeSet<PingoraBackend>>>>,
    membership_generation: Arc<AtomicU64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DiscoveryPublication {
    membership_changed: bool,
    membership_generation: u64,
}

impl DiscoveryPublication {
    pub(crate) fn membership_changed(self) -> bool {
        self.membership_changed
    }

    pub(crate) fn membership_generation(self) -> u64 {
        self.membership_generation
    }
}

impl ImpulseServiceDiscovery {
    pub(crate) fn from_runtime_upstream<F>(
        generation: u64,
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
            generation,
            upstream_name: upstream_name.to_string(),
            backend_addresses: Arc::new(
                upstream
                    .backends
                    .iter()
                    .map(|backend| backend.backend.address.clone())
                    .collect(),
            ),
            backends: Arc::new(RwLock::new(backends)),
            membership_generation: Arc::new(AtomicU64::new(1)),
        })
    }

    pub(crate) fn backend_index(&self, configured_address: &str) -> Option<usize> {
        self.backend_addresses
            .iter()
            .position(|address| address == configured_address)
    }

    pub(crate) fn publish_dns_result(
        &self,
        generation: u64,
        backend_index: usize,
        resolved_addrs: Result<Vec<SocketAddr>, String>,
    ) -> Result<DiscoveryPublication, String> {
        if generation != self.generation {
            return Err(format!(
                "upstream '{}' rejected DNS result from runtime generation {generation}; active generation is {}",
                self.upstream_name, self.generation
            ));
        }
        let resolved_addrs = resolved_addrs.map_err(|error| {
            format!(
                "upstream '{}' backend {backend_index} DNS resolution failed: {error}",
                self.upstream_name
            )
        })?;
        self.publish_resolved_backend(backend_index, resolved_addrs)
    }

    fn publish_resolved_backend(
        &self,
        backend_index: usize,
        resolved_addrs: impl IntoIterator<Item = SocketAddr>,
    ) -> Result<DiscoveryPublication, String> {
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

        let membership_changed = backends[backend_index] != resolved;
        if membership_changed {
            backends[backend_index] = resolved;
        }
        let membership_generation = if membership_changed {
            self.membership_generation.fetch_add(1, Ordering::Relaxed) + 1
        } else {
            self.membership_generation.load(Ordering::Relaxed)
        };
        Ok(DiscoveryPublication {
            membership_changed,
            membership_generation,
        })
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
