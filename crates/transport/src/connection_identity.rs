use std::{
    collections::{BTreeMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    net::SocketAddr,
    path::PathBuf,
};

use impulse_config::runtime::RuntimeBackendTransportKind;
use pingora_core::upstreams::peer::Proxy;

use crate::TlsClientConfig;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PingoraUpstreamProxyIdentity {
    pub next_hop: PathBuf,
    pub host: String,
    pub port: u16,
    pub headers: BTreeMap<String, Vec<u8>>,
}

impl From<&Proxy> for PingoraUpstreamProxyIdentity {
    fn from(proxy: &Proxy) -> Self {
        Self {
            next_hop: proxy.next_hop.to_path_buf(),
            host: proxy.host.clone(),
            port: proxy.port,
            headers: proxy.headers.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PingoraUpstreamConnectionIdentity {
    pub address: SocketAddr,
    pub protocol: RuntimeBackendTransportKind,
    pub sni: String,
    pub verify_certificates: bool,
    pub strict_sni: bool,
    pub ca_file_fingerprint_sha256: Option<String>,
    pub ca_dir_fingerprint_sha256: Option<String>,
    pub client_certificate_fingerprint_sha256: Option<String>,
    pub client_key_fingerprint_sha256: Option<String>,
    pub proxy: Option<PingoraUpstreamProxyIdentity>,
    pub generation: u64,
}

impl PingoraUpstreamConnectionIdentity {
    pub fn new(
        address: SocketAddr,
        protocol: RuntimeBackendTransportKind,
        sni: String,
        tls: Option<&TlsClientConfig>,
        proxy: Option<&Proxy>,
        generation: u64,
    ) -> Self {
        Self {
            address,
            protocol,
            sni,
            verify_certificates: tls.is_some_and(|tls| tls.verify_certificates),
            strict_sni: tls.is_some_and(|tls| tls.strict_sni),
            ca_file_fingerprint_sha256: tls.and_then(|tls| tls.ca_file_fingerprint_sha256.clone()),
            ca_dir_fingerprint_sha256: tls.and_then(|tls| tls.ca_dir_fingerprint_sha256.clone()),
            client_certificate_fingerprint_sha256: tls
                .and_then(|tls| tls.client_certificate_fingerprint_sha256.clone()),
            client_key_fingerprint_sha256: tls
                .and_then(|tls| tls.client_key_fingerprint_sha256.clone()),
            proxy: proxy.map(Into::into),
            generation,
        }
    }

    pub fn pool_key(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
}
