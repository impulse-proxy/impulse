//! Transport facade contract tests.
//!
//! These assertions lock the edge-facing behavior of the transport layer while
//! keeping H1/H2 implementation details hidden behind the canonical facade.

mod support;

use std::{collections::HashMap, sync::Arc, time::Duration};

use bytes::Bytes;
use impulse_config::{
    config::{
        ClientAuth, Config, Listen, LoadBalancing, Log, Observability, Performance, Resilience,
        RouteMatch, Security, Tls, Upstream, UpstreamTls,
    },
    runtime::{RuntimeBackendTransportKind, RuntimeConfig},
};
use impulse_errors::{PoolError, ProxyError};
use impulse_transport::{SharedDnsResolver, UpstreamTransportPool};

use crate::support::{
    ConcurrencyTracker, TransportTestProtocol, build_pool, build_pool_with_policy,
    connection_policy, loopback_bind_restricted, read_body, request, request_to_backend,
    start_backend_server, start_shared_backend_pool,
};

fn reserve_unused_port_or_skip() -> Option<u16> {
    match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener.local_addr().ok().map(|addr| addr.port()),
        Err(err) if loopback_bind_restricted(&err) => None,
        Err(err) => panic!("bind ephemeral port: {err}"),
    }
}

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
        None,
    )
    .expect("transport pool");

    let h1_rotation = pool
        .rotate_backend_client("http://127.0.0.1:8080")
        .expect("h1 rotation");
    assert!(h1_rotation.rotated());
    assert_eq!(h1_rotation.generations(), None);

    let h2_rotation = pool
        .rotate_backend_client("https://127.0.0.1:8443")
        .expect("h2 rotation");
    assert!(h2_rotation.rotated());
    assert_eq!(h2_rotation.generations(), Some((0, 1)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transport_facade_executes_requests_without_protocol_specific_callers() {
    let h2_backend =
        match start_backend_server(TransportTestProtocol::H2, b"h2", Duration::ZERO, None).await {
            Ok(backend) => backend,
            Err(err) if loopback_bind_restricted(&err) => return,
            Err(err) => panic!("failed to start h2 server: {err}"),
        };

    let pool = build_pool(
        [(h2_backend.clone(), TransportTestProtocol::H2.runtime_kind())],
        4,
        SharedDnsResolver::new(),
    );

    let h2_response = pool
        .send_backend_request(&h2_backend, request_to_backend(&h2_backend))
        .await
        .expect("h2 response");
    assert_eq!(read_body(h2_response).await, Bytes::from_static(b"h2"));
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
    assert_eq!(h1_rotation.generations(), None);

    let h2_rotation = pool
        .rotate_backend_client("h2-backend")
        .expect("h2 rotation");
    assert!(h2_rotation.rotated());
    assert_eq!(h2_rotation.generations(), Some((0, 1)));

    let h2_second_rotation = pool
        .rotate_backend_client("h2-backend")
        .expect("second h2 rotation");
    assert!(h2_second_rotation.rotated());
    assert_eq!(h2_second_rotation.generations(), Some((1, 2)));

    let missing_rotation = pool
        .rotate_backend_client("missing")
        .expect("missing rotation should not error");
    assert!(!missing_rotation.rotated());
    assert_eq!(missing_rotation.generations(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transport_facade_maps_unknown_backend_send_failure_and_overload_consistently() {
    let unknown_pool = build_pool(
        [(
            "known".to_string(),
            TransportTestProtocol::Http1.runtime_kind(),
        )],
        1,
        SharedDnsResolver::new(),
    );
    let unknown_err = unknown_pool
        .send_backend_request("missing", request("http://127.0.0.1:1/"))
        .await
        .expect_err("missing backend should fail");
    assert!(matches!(
        unknown_err,
        ProxyError::Pool(PoolError::UnknownBackend(name)) if name == "missing"
    ));

    let failing_h2_pool = build_pool(
        [(
            "h2-fail".to_string(),
            TransportTestProtocol::H2.runtime_kind(),
        )],
        1,
        SharedDnsResolver::new(),
    );
    let Some(h2_port) = reserve_unused_port_or_skip() else {
        return;
    };
    let h2_err = failing_h2_pool
        .send_backend_request("h2-fail", request(&format!("http://127.0.0.1:{h2_port}/")))
        .await
        .expect_err("h2 send should fail");
    assert!(matches!(h2_err, ProxyError::Pool(PoolError::Send(_))));

    let h2_tracker = Arc::new(ConcurrencyTracker::new());
    let (h2_backend, h2_overload_pool) = match start_shared_backend_pool(
        TransportTestProtocol::H2,
        b"h2",
        Duration::from_millis(50),
        Some(Arc::clone(&h2_tracker)),
        1,
        SharedDnsResolver::new(),
    )
    .await
    {
        Ok(fixture) => fixture,
        Err(err) if loopback_bind_restricted(&err) => return,
        Err(err) => panic!("failed to start h2 overload server: {err}"),
    };
    let h2_task_pool = Arc::clone(&h2_overload_pool);
    let h2_task_backend = h2_backend.clone();
    let h2_task = tokio::spawn(async move {
        h2_task_pool
            .send_backend_request(&h2_task_backend, request_to_backend(&h2_task_backend))
            .await
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    let h2_overload = h2_overload_pool
        .send_backend_request(&h2_backend, request_to_backend(&h2_backend))
        .await;
    assert!(matches!(
        h2_overload,
        Err(ProxyError::Pool(PoolError::BackendOverloaded(_)))
    ));
    let _ = h2_task.await.expect("h2 task join");
    assert_eq!(
        h2_tracker.max_observed(),
        1,
        "tracked h2 overload fixture should observe only one admitted request"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transport_facade_maps_h2_execution_timeout_to_proxy_timeout() {
    let h2_backend = match start_backend_server(
        TransportTestProtocol::H2,
        b"h2",
        Duration::from_millis(50),
        None,
    )
    .await
    {
        Ok(backend) => backend,
        Err(err) if loopback_bind_restricted(&err) => return,
        Err(err) => panic!("failed to start h2 timeout server: {err}"),
    };

    let timeout_policy = impulse_config::runtime::RuntimeBackendConnectionPolicy {
        execution_timeout: Duration::from_millis(5),
        ..connection_policy(4)
    };

    let pool = build_pool_with_policy(
        [(h2_backend.clone(), TransportTestProtocol::H2.runtime_kind())],
        timeout_policy,
        SharedDnsResolver::new(),
    );

    let h2_err = pool
        .send_backend_request(&h2_backend, request_to_backend(&h2_backend))
        .await
        .expect_err("h2 execution should time out");
    assert!(matches!(h2_err, ProxyError::Timeout));
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
    assert_eq!(first_rotation.generations(), Some((0, 1)));

    resolver.set_host_addrs(
        "api.example.com",
        [std::net::SocketAddr::from(([127, 0, 0, 11], 443))],
    );
    let second_rotation = pool
        .rotate_backend_client(&backend)
        .expect("second rotation");
    assert!(second_rotation.rotated());
    assert_eq!(second_rotation.generations(), Some((1, 2)));

    assert_eq!(
        resolver.cached_addrs("api.example.com"),
        Some(vec![std::net::SocketAddr::from(([127, 0, 0, 11], 443))])
    );
}
