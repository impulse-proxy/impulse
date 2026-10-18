use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, body::Incoming};
use rcgen::{Certificate, CertificateParams, SanType};
use tempfile::{TempDir, tempdir};

mod support;

use impulse_config::config::{
    Backend, ClientAuth, Config, HealthCheck, Listen, LoadBalancing, Log, LogFormat, RouteMatch,
    Security, Tls, Upstream, UpstreamTls,
};
use impulse_edge::runtime::listener::QUICListener;
use support::{net::local_listener_bind_available, request_path as request_support};

fn write_test_certs(dir: &TempDir) -> (String, String) {
    let mut params = CertificateParams::new(vec!["localhost".into()]);
    params
        .subject_alt_names
        .push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
    let cert = Certificate::from_params(params).expect("failed to build cert");

    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");

    std::fs::write(&cert_path, cert.serialize_pem().unwrap()).unwrap();
    std::fs::write(&key_path, cert.serialize_private_key_pem()).unwrap();

    (
        cert_path.to_string_lossy().to_string(),
        key_path.to_string_lossy().to_string(),
    )
}
async fn start_h2_backend(body: &'static str) -> SocketAddr {
    let fixture = request_support::start_h1_backend(move |_req: Request<Incoming>| async move {
        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(body))))
    })
    .await;
    let addr = fixture.addr;
    std::mem::forget(fixture);
    addr
}

fn make_config(
    port: u32,
    backends: Vec<Backend>,
    lb_type: &str,
    cert: String,
    key: String,
) -> Config {
    use std::collections::HashMap;

    let mut upstream = HashMap::new();
    upstream.insert(
        "test_pool".to_string(),
        Upstream {
            load_balancing: LoadBalancing {
                lb_type: lb_type.to_string(),
                key: None,
            },
            auth: Default::default(),
            host_policy: Default::default(),
            forwarded_headers: Default::default(),
            tls: None,
            route: RouteMatch {
                path_prefix: Some("/".to_string()),
                ..Default::default()
            },
            backends: backends
                .into_iter()
                .map(|mut backend| {
                    backend.address = request_support::normalize_backend_address(backend.address);
                    backend
                })
                .collect(),
        },
    );

    Config {
        version: 1,
        listen: Listen {
            protocol: "http3".to_string(),
            port: port as u16,
            address: "127.0.0.1".to_string(),
            tls: Tls {
                cert,
                key,
                certificates: vec![],
                client_auth: ClientAuth::default(),
            },
        },
        listeners: vec![],
        upstream,
        load_balancing: Some(LoadBalancing {
            lb_type: lb_type.to_string(),
            key: None,
        }),
        upstream_tls: UpstreamTls::default(),
        secrets: Default::default(),
        log: Log {
            level: "info".to_string(),
            file: Default::default(),
            format: LogFormat::Plain,
        },
        performance: impulse_config::config::Performance::default(),
        observability: impulse_config::config::Observability::default(),
        resilience: impulse_config::config::Resilience::default(),
        security: Security::default(),
    }
}

fn run_h3_client(addr: SocketAddr, authority: &str) -> Result<String, String> {
    request_support::run_h3_get_to(addr, authority, "/", &[])
        .map(|response| String::from_utf8_lossy(&response.body).into_owned())
}

#[test]
fn round_robin_across_backends() {
    if !local_listener_bind_available() {
        return;
    }

    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);

    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let backend_a = rt.block_on(start_h2_backend("backend-a\n"));
    let backend_b = rt.block_on(start_h2_backend("backend-b\n"));

    let backends = vec![
        Backend {
            id: "a".to_string(),
            address: backend_a.to_string(),
            weight: 1,
            health_check: Some(HealthCheck {
                path: "/health".to_string(),
                interval: 1000,
                timeout_ms: 1000,
                failure_threshold: 3,
                success_threshold: 1,
                cooldown_ms: 0,
            }),
        },
        Backend {
            id: "b".to_string(),
            address: backend_b.to_string(),
            weight: 1,
            health_check: Some(HealthCheck {
                path: "/health".to_string(),
                interval: 1000,
                timeout_ms: 1000,
                failure_threshold: 3,
                success_threshold: 1,
                cooldown_ms: 0,
            }),
        },
    ];

    let config = make_config(0, backends, "round-robin", cert, key);
    let listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();

    let _listener_task = request_support::ListenerTaskGuard::spawn(&rt, listener);

    let r1 = run_h3_client(listen_addr, "rr-test").expect("request 1");
    let r2 = run_h3_client(listen_addr, "rr-test").expect("request 2");
    let r3 = run_h3_client(listen_addr, "rr-test").expect("request 3");
    let r4 = run_h3_client(listen_addr, "rr-test").expect("request 4");

    let sequence = vec![r1, r2, r3, r4]
        .into_iter()
        .map(|body| body.trim().to_string())
        .collect::<Vec<_>>();

    assert_eq!(
        sequence,
        vec!["backend-a", "backend-b", "backend-a", "backend-b"]
    );
}
