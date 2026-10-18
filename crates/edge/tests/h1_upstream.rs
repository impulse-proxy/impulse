use std::{collections::HashMap, convert::Infallible, net::SocketAddr, time::Duration};

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, body::Incoming};
use impulse_config::{
    config::{Backend, Config, Upstream, UpstreamTls},
    validator::validate,
};
use impulse_edge::runtime::listener::QUICListener;
use rcgen::{Certificate, CertificateParams, SanType};
use serial_test::serial;
use tempfile::{TempDir, tempdir};

mod support;

use support::{net::local_tcp_bind_available, request_path as request_support};

fn write_test_certs(dir: &TempDir) -> (String, String) {
    let mut params = CertificateParams::new(vec!["localhost".into()]);
    params
        .subject_alt_names
        .push(SanType::DnsName("localhost".to_string()));
    params.subject_alt_names.push(SanType::IpAddress(
        "127.0.0.1".parse().expect("loopback ip"),
    ));
    let cert = Certificate::from_params(params).expect("failed to build cert");

    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");

    std::fs::write(&cert_path, cert.serialize_pem().expect("serialize cert")).expect("write cert");
    std::fs::write(&key_path, cert.serialize_private_key_pem()).expect("write key");

    (
        cert_path.to_string_lossy().to_string(),
        key_path.to_string_lossy().to_string(),
    )
}

fn make_config(
    cert: String,
    key: String,
    upstreams: HashMap<String, Upstream>,
    upstream_tls: UpstreamTls,
) -> Config {
    request_support::make_quic_test_config_with_upstream_tls(&cert, &key, upstreams, upstream_tls)
}

fn make_upstream(
    path_prefix: &str,
    backends: Vec<Backend>,
    tls: Option<UpstreamTls>,
    lb_type: &str,
) -> Upstream {
    request_support::make_upstream(path_prefix, backends, tls, lb_type)
}

fn make_backend(id: &str, address: String) -> Backend {
    request_support::make_backend(id, address)
}

async fn start_h1_backend<F>(handler: F) -> SocketAddr
where
    F: Fn(Request<Incoming>) -> Response<Full<Bytes>> + Clone + Send + Sync + 'static,
{
    let fixture = request_support::start_h1_backend(move |req| {
        let handler = handler.clone();
        async move { Ok::<_, Infallible>(handler(req)) }
    })
    .await;
    let addr = fixture.addr;
    std::mem::forget(fixture);
    addr
}

async fn start_h1_delayed_backend(body: &'static str, delay: Duration) -> SocketAddr {
    let fixture = request_support::start_h1_backend(move |_req| async move {
        tokio::time::sleep(delay).await;
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
            body.as_bytes(),
        ))))
    })
    .await;
    let addr = fixture.addr;
    std::mem::forget(fixture);
    addr
}

async fn start_h2_tls_backend<F>(cert_path: &str, key_path: &str, handler: F) -> SocketAddr
where
    F: Fn(Request<Incoming>) -> Response<Full<Bytes>> + Clone + Send + Sync + 'static,
{
    let fixture = request_support::start_h2_backend(cert_path, key_path, move |req| {
        let handler = handler.clone();
        async move { Ok::<_, Infallible>(handler(req)) }
    })
    .await;
    let addr = fixture.addr;
    std::mem::forget(fixture);
    addr
}

#[test]
#[serial]
fn http_only_upstream_starts_and_forwards_requests_end_to_end() {
    if !local_tcp_bind_available() {
        return;
    }
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let backend_addr = rt.block_on(start_h1_backend(|_req| {
        Response::new(Full::new(Bytes::from_static(b"http-only ok\n")))
    }));

    let mut upstreams = HashMap::new();
    upstreams.insert(
        "plain".to_string(),
        make_upstream(
            "/",
            vec![make_backend("plain-1", format!("http://{backend_addr}"))],
            Some(UpstreamTls {
                verify_certificates: true,
                strict_sni: true,
                ca_file: Some("/path/does/not/exist.pem".to_string()),
                ca_dir: Some("/path/does/not/exist".to_string()),
                ..UpstreamTls::default()
            }),
            "round-robin",
        ),
    );
    let config = make_config(
        cert,
        key,
        upstreams,
        UpstreamTls {
            verify_certificates: true,
            strict_sni: true,
            ca_file: Some("/path/does/not/exist-global.pem".to_string()),
            ca_dir: Some("/path/does/not/exist-global".to_string()),
            ..UpstreamTls::default()
        },
    );

    validate(&config).expect("http-only config should validate");
    let listener = QUICListener::new(config).expect("listener");
    let listen_addr = listener.socket.local_addr().expect("listen addr");
    let _listener_task = request_support::ListenerTaskGuard::spawn(&rt, listener);

    let response = request_support::run_h3_get_to(listen_addr, "public.example.com", "/", &[])
        .expect("h3 request");
    assert_eq!(response.status, 200);
    assert_eq!(String::from_utf8_lossy(&response.body), "http-only ok\n");
}

#[test]
#[serial]
fn http_only_upstream_retries_bodyless_requests_on_alternate_backend() {
    if !local_tcp_bind_available() {
        return;
    }
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let stalled_backend = rt.block_on(start_h1_delayed_backend(
        "too slow\n",
        Duration::from_secs(2),
    ));
    let healthy_backend = rt.block_on(start_h1_backend(|_req| {
        Response::new(Full::new(Bytes::from_static(b"retry ok\n")))
    }));

    let mut upstreams = HashMap::new();
    upstreams.insert(
        "retry".to_string(),
        make_upstream(
            "/retry",
            vec![
                make_backend("stalled", format!("http://{stalled_backend}")),
                make_backend("healthy", format!("http://{healthy_backend}")),
            ],
            None,
            "round-robin",
        ),
    );
    let mut config = make_config(cert, key, upstreams, UpstreamTls::default());
    config.performance.backend_connect_timeout_ms = 50;
    config.performance.backend_timeout_ms = 100;

    validate(&config).expect("config should validate");
    let listener = QUICListener::new(config).expect("listener");
    let listen_addr = listener.socket.local_addr().expect("listen addr");
    let _listener_task = request_support::ListenerTaskGuard::spawn(&rt, listener);

    let response = request_support::run_h3_get_to(listen_addr, "retry.example.com", "/retry", &[])
        .expect("retry request");
    assert_eq!(response.status, 200);
    assert_eq!(String::from_utf8_lossy(&response.body), "retry ok\n");
}

#[test]
#[serial]
fn mixed_http_and_https_upstreams_route_by_scheme() {
    if !local_tcp_bind_available() {
        return;
    }
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let plain_backend = rt.block_on(start_h1_backend(|_req| {
        Response::new(Full::new(Bytes::from_static(b"plain backend\n")))
    }));
    let secure_backend = rt.block_on(start_h2_tls_backend(&cert, &key, |_req| {
        Response::new(Full::new(Bytes::from_static(b"secure backend\n")))
    }));

    let mut upstreams = HashMap::new();
    upstreams.insert(
        "plain".to_string(),
        make_upstream(
            "/plain",
            vec![make_backend("plain-1", format!("http://{plain_backend}"))],
            None,
            "round-robin",
        ),
    );
    upstreams.insert(
        "secure".to_string(),
        make_upstream(
            "/secure",
            vec![make_backend(
                "secure-1",
                format!("https://{secure_backend}"),
            )],
            Some(UpstreamTls {
                verify_certificates: false,
                strict_sni: true,
                ca_file: None,
                ca_dir: None,
                ..UpstreamTls::default()
            }),
            "round-robin",
        ),
    );
    let config = make_config(cert, key, upstreams, UpstreamTls::default());

    validate(&config).expect("mixed config should validate");
    let listener = QUICListener::new(config).expect("listener");
    let listen_addr = listener.socket.local_addr().expect("listen addr");
    let _listener_task = request_support::ListenerTaskGuard::spawn(&rt, listener);

    let plain = request_support::run_h3_get_to(listen_addr, "mixed.example.com", "/plain", &[])
        .expect("plain request");
    let secure = request_support::run_h3_get_to(listen_addr, "mixed.example.com", "/secure", &[])
        .expect("secure request");

    assert_eq!(plain.status, 200);
    assert_eq!(String::from_utf8_lossy(&plain.body), "plain backend\n");
    assert_eq!(secure.status, 200);
    assert_eq!(String::from_utf8_lossy(&secure.body), "secure backend\n");
}
