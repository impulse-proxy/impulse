//! Transport facade contract tests.
//!
//! These assertions lock the edge-facing behavior of the transport layer while
//! keeping H1/H2 implementation details hidden behind the canonical facade.

mod support;

use std::collections::HashMap;

use impulse_config::{
    config::{
        ClientAuth, Config, Listen, LoadBalancing, Log, Observability, Performance, Resilience,
        RouteMatch, Security, Tls, Upstream, UpstreamTls,
    },
    runtime::{RuntimeBackendTransportKind, RuntimeConfig},
};
use impulse_transport::{SharedDnsResolver, UpstreamTransportPool};

use crate::support::{TransportTestProtocol, build_pool};

fn transport_test_config(http_backend: &str, https_backend: &str) -> Config {
    let mut config = Config {
        version: 1,
        listen: Listen {
            protocol: "http3".to_string(),
            port: 443,
            address: "0.0.0.0".to_string(),
            tls: Tls {
                cert: "/tmp/tls/default.pem".to_string(),
                key: "/tmp/tls/default.key".to_string(),
                certificates: Vec::new(),
                client_auth: ClientAuth::default(),
            },
        },
        listeners: Vec::new(),
        upstream: HashMap::new(),
        load_balancing: None,
        upstream_tls: UpstreamTls::default(),
        secrets: Default::default(),
        log: Log::default(),
        performance: Performance::default(),
        observability: Observability::default(),
        resilience: Resilience::default(),
        security: Security::default(),
    };

    for (name, route_host, backend) in [
        ("plain", "plain.example.com", http_backend),
        ("secure", "secure.example.com", https_backend),
    ] {
        config.upstream.insert(
            name.to_string(),
            Upstream {
                load_balancing: LoadBalancing {
                    lb_type: "round-robin".to_string(),
                    key: None,
                },
                auth: Default::default(),
                host_policy: Default::default(),
                forwarded_headers: Default::default(),
                tls: None,
                route: RouteMatch {
                    host: Some(route_host.to_string()),
                    path_prefix: Some("/".to_string()),
                    method: None,
                },
                backends: vec![impulse_config::config::Backend {
                    id: format!("{name}-1"),
                    address: backend.to_string(),
                    weight: 100,
                    health_check: None,
                }],
            },
        );
    }

    config
}

#[test]
fn runtime_upstream_interpretation_selects_protocol_without_caller_branching() {
    let config = transport_test_config("http://127.0.0.1:8080", "https://127.0.0.1:8443");
    let runtime = RuntimeConfig::from_config(&config).expect("runtime config");

    let pool = UpstreamTransportPool::from_runtime_upstreams(
        runtime.upstreams.values(),
        &runtime.policies.transport.backend_connections,
        SharedDnsResolver::new(),
    )
    .expect("transport pool");

    let h1_rotation = pool
        .rotate_backend_client("http://127.0.0.1:8080")
        .expect("h1 rotation");
    assert!(h1_rotation.rotated());

    let h2_rotation = pool
        .rotate_backend_client("https://127.0.0.1:8443")
        .expect("h2 rotation");
    assert!(h2_rotation.rotated());
}

#[test]
fn transport_facade_exposes_stable_rotation_contract_across_protocols() {
    let pool = build_pool(
        [
            (
                "h1-backend".to_string(),
                TransportTestProtocol::Http1.runtime_kind(),
            ),
            (
                "h2-backend".to_string(),
                TransportTestProtocol::H2.runtime_kind(),
            ),
        ],
        4,
        SharedDnsResolver::new(),
    );

    let h1_rotation = pool
        .rotate_backend_client("h1-backend")
        .expect("h1 rotation");
    assert!(h1_rotation.rotated());

    let h2_rotation = pool
        .rotate_backend_client("h2-backend")
        .expect("h2 rotation");
    assert!(h2_rotation.rotated());

    let h2_second_rotation = pool
        .rotate_backend_client("h2-backend")
        .expect("second h2 rotation");
    assert!(h2_second_rotation.rotated());

    let missing_rotation = pool
        .rotate_backend_client("missing")
        .expect("missing rotation should not error");
    assert!(!missing_rotation.rotated());
}

#[test]
fn transport_facade_preserves_dns_refresh_rotation_contract() {
    let resolver = SharedDnsResolver::new();
    let backend = "https://api.example.com:443".to_string();
    let pool = build_pool(
        [(backend.clone(), RuntimeBackendTransportKind::H2)],
        4,
        resolver.clone(),
    );

    resolver.set_host_addrs(
        "api.example.com",
        [std::net::SocketAddr::from(([127, 0, 0, 10], 443))],
    );
    let first_rotation = pool
        .rotate_backend_client(&backend)
        .expect("first rotation");
    assert!(first_rotation.rotated());

    resolver.set_host_addrs(
        "api.example.com",
        [std::net::SocketAddr::from(([127, 0, 0, 11], 443))],
    );
    let second_rotation = pool
        .rotate_backend_client(&backend)
        .expect("second rotation");
    assert!(second_rotation.rotated());

    assert_eq!(
        resolver.cached_addrs("api.example.com"),
        Some(vec![std::net::SocketAddr::from(([127, 0, 0, 11], 443))])
    );
}
