use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use impulse_config::runtime::{RuntimeBackendTlsPolicy, RuntimeUpstream};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientConfig {
    pub verify_certificates: bool,
    pub strict_sni: bool,
    pub ca_file_fingerprint_sha256: Option<String>,
    pub ca_dir_fingerprint_sha256: Option<String>,
    pub ca_pem_blobs: Vec<Vec<u8>>,
    pub client_certificate_pem: Option<Vec<u8>>,
    pub client_key_pem: Option<Vec<u8>>,
    pub client_certificate_fingerprint_sha256: Option<String>,
    pub client_key_fingerprint_sha256: Option<String>,
}

impl Default for TlsClientConfig {
    fn default() -> Self {
        Self {
            verify_certificates: true,
            strict_sni: true,
            ca_file_fingerprint_sha256: None,
            ca_dir_fingerprint_sha256: None,
            ca_pem_blobs: Vec::new(),
            client_certificate_pem: None,
            client_key_pem: None,
            client_certificate_fingerprint_sha256: None,
            client_key_fingerprint_sha256: None,
        }
    }
}

impl From<&RuntimeBackendTlsPolicy> for TlsClientConfig {
    fn from(value: &RuntimeBackendTlsPolicy) -> Self {
        Self {
            verify_certificates: value.verify_certificates,
            strict_sni: value.strict_sni,
            ca_file_fingerprint_sha256: value.ca_file_fingerprint_sha256.clone(),
            ca_dir_fingerprint_sha256: value.ca_dir_fingerprint_sha256.clone(),
            ca_pem_blobs: value.ca_pem_blobs().to_vec(),
            client_certificate_pem: value.client_certificate_pem().map(|pem| pem.to_vec()),
            client_key_pem: value.client_key_pem().map(|pem| pem.to_vec()),
            client_certificate_fingerprint_sha256: value
                .client_certificate
                .as_ref()
                .map(|metadata| metadata.fingerprint_sha256.clone()),
            client_key_fingerprint_sha256: value
                .client_key
                .as_ref()
                .map(|metadata| metadata.fingerprint_sha256.clone()),
        }
    }
}

impl TlsClientConfig {
    pub fn from_runtime_upstream(upstream: &RuntimeUpstream) -> Self {
        Self::from(upstream.backend_tls_policy())
    }
}

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

    pub fn snapshot(&self) -> HashMap<String, Vec<SocketAddr>> {
        self.cache
            .read()
            .map(|cache| cache.clone())
            .unwrap_or_default()
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
