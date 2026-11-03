use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

#[derive(Clone, Default)]
pub struct SharedDnsResolver {
    cache: Arc<RwLock<HashMap<String, Vec<SocketAddr>>>>,
}

impl SharedDnsResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_host_addrs<I>(&self, host: &str, addrs: I)
    where
        I: IntoIterator<Item = SocketAddr>,
    {
        let host = normalize_dns_cache_host(host);
        let addrs = canonicalize_socket_addrs(addrs);
        if let Ok(mut cache) = self.cache.write() {
            if addrs.is_empty() {
                cache.remove(&host);
            } else {
                cache.insert(host, addrs);
            }
        }
    }

    pub fn cached_addrs(&self, host: &str) -> Option<Vec<SocketAddr>> {
        self.cache
            .read()
            .ok()
            .and_then(|cache| cache.get(&normalize_dns_cache_host(host)).cloned())
    }
}

fn normalize_dns_cache_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn canonicalize_socket_addrs<I>(addrs: I) -> Vec<SocketAddr>
where
    I: IntoIterator<Item = SocketAddr>,
{
    let mut addrs = addrs.into_iter().collect::<Vec<_>>();
    addrs.sort_unstable();
    addrs.dedup();
    addrs
}
