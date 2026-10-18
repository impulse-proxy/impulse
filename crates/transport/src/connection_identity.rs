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
pub(crate) struct PingoraUpstreamProxyIdentity {
    pub(crate) next_hop: PathBuf,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) headers: BTreeMap<String, Vec<u8>>,
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
pub(crate) struct PingoraUpstreamConnectionIdentity {
    pub(crate) address: SocketAddr,
    pub(crate) protocol: RuntimeBackendTransportKind,
    pub(crate) sni: String,
    pub(crate) verify_certificates: bool,
    pub(crate) strict_sni: bool,
    pub(crate) ca_file_fingerprint_sha256: Option<String>,
    pub(crate) ca_dir_fingerprint_sha256: Option<String>,
    pub(crate) client_certificate_fingerprint_sha256: Option<String>,
    pub(crate) client_key_fingerprint_sha256: Option<String>,
    pub(crate) proxy: Option<PingoraUpstreamProxyIdentity>,
    pub(crate) generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PingoraBackendHealthIdentity(u64);

impl PingoraBackendHealthIdentity {
    pub fn equivalence_key(self) -> u64 {
        self.0
    }
}

impl PingoraUpstreamConnectionIdentity {
    pub(crate) fn new(
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

    pub(crate) fn pool_key(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }

    pub(crate) fn health_identity(&self) -> PingoraBackendHealthIdentity {
        PingoraBackendHealthIdentity(self.pool_key())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, net::SocketAddr};

    use impulse_config::runtime::RuntimeBackendTransportKind;

    use super::*;

    fn identity(tls: &TlsClientConfig, generation: u64) -> PingoraUpstreamConnectionIdentity {
        PingoraUpstreamConnectionIdentity::new(
            "127.0.0.1:8443"
                .parse::<SocketAddr>()
                .expect("socket address"),
            RuntimeBackendTransportKind::H2,
            "backend.internal".to_string(),
            Some(tls),
            None,
            generation,
        )
    }

    #[test]
    fn equivalent_backends_share_one_health_probe_identity() {
        let tls = TlsClientConfig::default();
        let identities = HashSet::from([
            identity(&tls, 7).health_identity(),
            identity(&tls, 7).health_identity(),
        ]);

        assert_eq!(identities.len(), 1);
    }

    #[test]
    fn tls_security_identity_prevents_health_probe_sharing() {
        let baseline = TlsClientConfig {
            ca_file_fingerprint_sha256: Some("ca-a".to_string()),
            ca_dir_fingerprint_sha256: Some("ca-dir-a".to_string()),
            client_certificate_fingerprint_sha256: Some("cert-a".to_string()),
            client_key_fingerprint_sha256: Some("key-a".to_string()),
            ..TlsClientConfig::default()
        };
        let baseline_identity = identity(&baseline, 7).health_identity();
        let mut different_sni = identity(&baseline, 7);
        different_sni.sni = "other.internal".to_string();
        assert_ne!(different_sni.health_identity(), baseline_identity);

        let variants = [
            TlsClientConfig {
                verify_certificates: false,
                ..baseline.clone()
            },
            TlsClientConfig {
                strict_sni: false,
                ..baseline.clone()
            },
            TlsClientConfig {
                ca_file_fingerprint_sha256: Some("ca-b".to_string()),
                ..baseline.clone()
            },
            TlsClientConfig {
                ca_dir_fingerprint_sha256: Some("ca-dir-b".to_string()),
                ..baseline.clone()
            },
            TlsClientConfig {
                client_certificate_fingerprint_sha256: Some("cert-b".to_string()),
                ..baseline.clone()
            },
            TlsClientConfig {
                client_key_fingerprint_sha256: Some("key-b".to_string()),
                ..baseline.clone()
            },
        ];

        for variant in variants {
            assert_ne!(identity(&variant, 7).health_identity(), baseline_identity);
        }
    }

    #[test]
    fn runtime_generations_do_not_share_health_probe_identity() {
        let tls = TlsClientConfig::default();

        assert_ne!(
            identity(&tls, 7).health_identity(),
            identity(&tls, 8).health_identity()
        );
    }
}
