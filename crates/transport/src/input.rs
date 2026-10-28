use std::{collections::BTreeMap, path::PathBuf, time::Duration};

/// Upstream HTTP protocol selected for one backend.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UpstreamProtocol {
    Http1,
    Http2,
}

/// Validated endpoint identity required to establish an upstream connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpstreamEndpointInput {
    pub configured_address: String,
    pub authority_host: String,
    pub authority_port: u16,
    pub protocol: UpstreamProtocol,
    pub tls: bool,
}

/// TLS material and verification policy required by upstream connections.
#[derive(Clone, Eq, PartialEq)]
pub struct UpstreamTlsInput {
    pub verify_certificates: bool,
    pub verify_hostname: bool,
    pub ca_file_fingerprint_sha256: Option<String>,
    pub ca_dir_fingerprint_sha256: Option<String>,
    pub ca_pem_blobs: Vec<Vec<u8>>,
    pub client_certificate_pem: Option<Vec<u8>>,
    pub client_key_pem: Option<Vec<u8>>,
    pub client_certificate_fingerprint_sha256: Option<String>,
    pub client_key_fingerprint_sha256: Option<String>,
}

impl Default for UpstreamTlsInput {
    fn default() -> Self {
        Self {
            verify_certificates: true,
            verify_hostname: true,
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

/// Connection and exchange deadlines applied to one upstream backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpstreamTimeoutInput {
    pub connect: Duration,
    pub execution: Duration,
    pub pool_idle: Duration,
}

/// Optional HTTP CONNECT proxy used to reach an upstream backend.
#[derive(Clone, Eq, PartialEq)]
pub struct UpstreamProxyInput {
    pub next_hop: PathBuf,
    pub host: String,
    pub port: u16,
    pub headers: BTreeMap<String, Vec<u8>>,
}

/// Bounded connection ownership for one upstream backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpstreamConnectionLimitsInput {
    pub max_inflight: usize,
    pub max_idle: usize,
}

/// Complete validated input required to construct one upstream transport.
#[derive(Clone, Eq, PartialEq)]
pub struct UpstreamTransportInput {
    pub endpoint: UpstreamEndpointInput,
    pub tls: Option<UpstreamTlsInput>,
    pub timeouts: UpstreamTimeoutInput,
    pub proxy: Option<UpstreamProxyInput>,
    pub connection_limits: UpstreamConnectionLimitsInput,
}
