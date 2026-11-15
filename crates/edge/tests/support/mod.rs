//! Shared support modules for edge integration-style tests.
//!
//! These helpers stay local to `crates/edge/tests` and group by behavioral
//! domain rather than by protocol or scenario file.

use std::collections::HashMap;

use bytes::Bytes;
use http_body_util::Full;
use hyper::Response;
use impulse_config::config::{
    ClientAuth, Config, Listen, LoadBalancing, Log, LogFormat, Secrets, Security, Tls, Upstream,
    UpstreamTls,
};

pub(crate) mod backend_lifecycle;
pub(crate) mod net;
pub(crate) mod parity;
pub(crate) mod request_path;
pub(crate) mod runtime_swap;

pub(super) fn base_quic_test_config(
    listen_port: u16,
    cert_path: &str,
    key_path: &str,
    upstreams: HashMap<String, Upstream>,
) -> Config {
    Config {
        version: 1,
        listen: Listen {
            protocol: "http3".to_string(),
            port: listen_port,
            address: "127.0.0.1".to_string(),
            tls: Tls {
                cert: cert_path.to_string(),
                key: key_path.to_string(),
                certificates: Vec::new(),
                client_auth: ClientAuth::default(),
            },
        },
        listeners: Vec::new(),
        upstream: upstreams,
        load_balancing: Some(LoadBalancing {
            lb_type: "round-robin".to_string(),
            key: None,
        }),
        upstream_tls: UpstreamTls::default(),
        secrets: Secrets::default(),
        log: Log {
            level: "info".to_string(),
            file: Default::default(),
            format: LogFormat::Plain,
            access: Default::default(),
        },
        performance: impulse_config::config::Performance::default(),
        observability: impulse_config::config::Observability::default(),
        resilience: impulse_config::config::Resilience::default(),
        security: Security::default(),
    }
}

pub(super) fn static_full_response(body: &'static [u8]) -> Response<Full<Bytes>> {
    Response::new(Full::new(Bytes::from_static(body)))
}
