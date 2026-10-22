use std::{
    collections::HashMap,
    convert::Infallible,
    net::TcpListener,
    sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Response, body::Incoming};
use impulse_config::config::{
    ApiKeyAuth, ExternalAuth, ExternalAuthFailureMode, ExternalAuthRequestHeader, RouteAuth,
    ScopedRateLimit, ScopedRateLimitScope, SecretRef, UpstreamTls,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose, SanType,
};
use serial_test::serial;
use tempfile::{TempDir, tempdir};

mod support;

use support::{
    net::local_listener_bind_available,
    request_path::{
        H3RequestSpec, QuicRequestPathHarness, make_backend, make_upstream, run_request_to,
        run_two_chunk_post_to, run_two_chunk_post_to_with_response_timeout,
    },
};

struct MtlsTestMaterial {
    _dir: TempDir,
    ca_cert_path: String,
    server_cert_path: String,
    server_key_path: String,
    client_cert_path: String,
    client_key_path: String,
}

impl MtlsTestMaterial {
    fn localhost() -> Self {
        let dir = tempdir().expect("tempdir");
        let ca = build_ca("Impulse Edge Test CA");
        let (server_cert, server_key) = signed_cert(
            "localhost",
            &ca,
            vec!["localhost".to_string()],
            vec![
                SanType::DnsName("localhost".to_string()),
                SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1])),
            ],
            ExtendedKeyUsagePurpose::ServerAuth,
        );
        let (client_cert, client_key) = signed_cert(
            "edge-client",
            &ca,
            Vec::new(),
            Vec::new(),
            ExtendedKeyUsagePurpose::ClientAuth,
        );

        let ca_cert_path = dir.path().join("ca.pem");
        let server_cert_path = dir.path().join("server-cert.pem");
        let server_key_path = dir.path().join("server-key.pem");
        let client_cert_path = dir.path().join("client-cert.pem");
        let client_key_path = dir.path().join("client-key.pem");

        std::fs::write(&ca_cert_path, ca.serialize_pem().expect("serialize ca")).expect("write ca");
        std::fs::write(&server_cert_path, server_cert).expect("write server cert");
        std::fs::write(&server_key_path, server_key).expect("write server key");
        std::fs::write(&client_cert_path, client_cert).expect("write client cert");
        std::fs::write(&client_key_path, client_key).expect("write client key");

        Self {
            _dir: dir,
            ca_cert_path: ca_cert_path.to_string_lossy().to_string(),
            server_cert_path: server_cert_path.to_string_lossy().to_string(),
            server_key_path: server_key_path.to_string_lossy().to_string(),
            client_cert_path: client_cert_path.to_string_lossy().to_string(),
            client_key_path: client_key_path.to_string_lossy().to_string(),
        }
    }
}

fn build_ca(common_name: &str) -> Certificate {
    let mut params = CertificateParams::new(Vec::new());
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, common_name);
    params.distinguished_name = distinguished_name;
    Certificate::from_params(params).expect("build ca")
}

fn signed_cert(
    common_name: &str,
    ca: &Certificate,
    dns_names: Vec<String>,
    subject_alt_names: Vec<SanType>,
    usage: ExtendedKeyUsagePurpose,
) -> (String, String) {
    let mut params = CertificateParams::new(dns_names);
    params.extended_key_usages = vec![usage];
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.subject_alt_names = subject_alt_names;
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, common_name);
    params.distinguished_name = distinguished_name;
    let cert = Certificate::from_params(params).expect("build cert");
    (
        cert.serialize_pem_with_signer(ca)
            .expect("serialize signed cert"),
        cert.serialize_private_key_pem(),
    )
}

fn response_line(body: &str, prefix: &str) -> String {
    body.lines()
        .find_map(|line| line.strip_prefix(prefix).map(str::to_string))
        .unwrap_or_else(|| panic!("missing response line with prefix `{prefix}` in body: {body}"))
}

fn metrics_counter(metrics: &str, prefix: &str) -> u64 {
    metrics
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}

fn metrics_delta(before: &str, after: &str, prefix: &str) -> u64 {
    metrics_counter(after, prefix).saturating_sub(metrics_counter(before, prefix))
}

fn start_single_backend_listener(
    harness: &mut QuicRequestPathHarness,
    path: &str,
    backend_id: &str,
    backend_addr: String,
    configure: impl FnOnce(&mut impulse_config::config::Config),
) -> std::net::SocketAddr {
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        make_upstream(
            path,
            vec![make_backend(backend_id, backend_addr)],
            None,
            "round-robin",
        ),
    );

    let mut config = harness.make_config(upstreams);
    configure(&mut config);
    harness.start_listener(config).expect("listener")
}

fn configure_http_external_auth(
    harness: &QuicRequestPathHarness,
    backend_address: String,
    auth_endpoint: String,
    timeout_ms: u64,
    failure_mode: ExternalAuthFailureMode,
    response_header_allowlist: Vec<String>,
) -> impulse_config::config::Config {
    let mut upstream = make_upstream(
        "/auth",
        vec![make_backend("auth-backend", backend_address)],
        None,
        "round-robin",
    );
    upstream.auth.external_auth = Some(ExternalAuth::Http {
        endpoint: auth_endpoint,
        request_headers: vec![ExternalAuthRequestHeader {
            name: "x-auth-static".to_string(),
            value: "1".to_string(),
        }],
        response_header_allowlist,
        timeout_ms,
        failure_mode,
    });

    let mut upstreams = HashMap::new();
    upstreams.insert("api".to_string(), upstream);
    harness.make_config(upstreams)
}

fn single_route_upstreams(
    path: &str,
    backend_id: &str,
    backend_address: String,
    tls: Option<UpstreamTls>,
) -> HashMap<String, impulse_config::config::Upstream> {
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        make_upstream(
            path,
            vec![make_backend(backend_id, backend_address)],
            tls,
            "round-robin",
        ),
    );
    upstreams
}

fn start_single_route_listener(
    harness: &mut QuicRequestPathHarness,
    path: &str,
    backend_id: &str,
    backend_address: String,
    tls: Option<UpstreamTls>,
) {
    harness
        .start_listener(harness.make_config(single_route_upstreams(
            path,
            backend_id,
            backend_address,
            tls,
        )))
        .expect("listener");
}

// Success path contracts

#[test]
#[serial]
fn quic_request_path_h1_round_trip_returns_backend_response() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let backend_addr = harness.start_h1_static_backend(b"h1 harness ok");

    start_single_route_listener(
        &mut harness,
        "/",
        "h1-1",
        format!("http://{backend_addr}"),
        None,
    );

    let response = harness
        .run_request(H3RequestSpec::get("localhost", "/"))
        .expect("h3 request");
    response.assert_status(200);
    response.assert_body_bytes(b"h1 harness ok");
}

#[test]
#[serial]
fn quic_request_path_h2_round_trip_returns_backend_response() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let backend_addr = harness.start_h2_static_backend(b"h2 harness ok");

    start_single_route_listener(
        &mut harness,
        "/",
        "h2-1",
        format!("https://{backend_addr}"),
        Some(UpstreamTls {
            verify_certificates: false,
            strict_sni: false,
            ..UpstreamTls::default()
        }),
    );

    let response = harness
        .run_request(H3RequestSpec::get("localhost", "/"))
        .expect("h3 request");
    response.assert_status(200);
    response.assert_body_text("h2 harness ok");
}

#[test]
#[serial]
fn quic_to_h1_success_path_normalizes_headers_and_keeps_get_bodyless() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let backend_addr = harness.start_h1_backend(|req: hyper::Request<Incoming>| async move {
        let header_value = |name: &str| {
            req.headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("<missing>")
                .to_string()
        };
        let method = req.method().to_string();
        let path = req.uri().path().to_string();
        let host = header_value("host");
        let forwarded = header_value("forwarded");
        let xff = header_value("x-forwarded-for");
        let xfp = header_value("x-forwarded-proto");
        let xfh = header_value("x-forwarded-host");
        let user_agent = header_value("user-agent");
        let request_id = header_value("x-request-id");
        let content_length = req
            .headers()
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("<missing>")
            .to_string();
        let has_connection = req.headers().contains_key("connection");
        let body = req
            .into_body()
            .collect()
            .await
            .expect("collect request body")
            .to_bytes();
        let body = format!(
            "method={method}\npath={path}\nhost={}\nforwarded={}\nxff={}\nxfp={}\nxfh={}\nuser_agent={}\nx_request_id={}\ncontent_length={content_length}\nbody_len={}\nhas_connection={}\n",
            host,
            forwarded,
            xff,
            xfp,
            xfh,
            user_agent,
            request_id,
            body.len(),
            has_connection,
        );
        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(body))))
    });

    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        make_upstream(
            "/headers",
            vec![make_backend("h1-headers", format!("http://{backend_addr}"))],
            None,
            "round-robin",
        ),
    );

    harness
        .start_listener(harness.make_config(upstreams))
        .expect("listener");

    let response = harness
        .run_request(H3RequestSpec {
            method: "GET",
            authority: "public.example.com",
            path: "/headers",
            headers: &[
                ("forwarded", "for=1.2.3.4;proto=http;host=\"evil.example\""),
                ("x-forwarded-for", "1.2.3.4"),
                ("x-forwarded-proto", "http"),
                ("x-forwarded-host", "evil.example"),
                ("connection", "keep-alive, x-secret"),
                ("x-secret", "strip-me"),
            ],
            body: None,
            user_agent: "impulse-success-h1",
        })
        .expect("h3 request");

    response.assert_status(200);
    let body = response.body_text();
    assert_eq!(response_line(&body, "method="), "GET");
    assert_eq!(response_line(&body, "path="), "/headers");
    assert_eq!(response_line(&body, "host="), "public.example.com");
    assert_eq!(
        response_line(&body, "forwarded="),
        "for=127.0.0.1;proto=https;host=\"public.example.com\""
    );
    assert_eq!(response_line(&body, "xff="), "127.0.0.1");
    assert_eq!(response_line(&body, "xfp="), "https");
    assert_eq!(response_line(&body, "xfh="), "public.example.com");
    assert_eq!(response_line(&body, "user_agent="), "impulse-success-h1");
    assert_eq!(response_line(&body, "content_length="), "<missing>");
    assert_eq!(response_line(&body, "body_len="), "0");
    assert_eq!(response_line(&body, "has_connection="), "false");

    let request_id = response_line(&body, "x_request_id=");
    assert!(
        !request_id.is_empty() && request_id.chars().all(|ch| ch.is_ascii_digit()),
        "x-request-id should be a generated numeric request identifier, got `{request_id}`"
    );
}

#[test]
#[serial]
fn quic_to_h1_success_path_streams_response_body_to_completion() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let backend_addr = harness.start_h1_chunked_backend(vec![b"chunk-1:", b"chunk-2:", b"chunk-3"]);

    start_single_route_listener(
        &mut harness,
        "/stream",
        "h1-stream",
        format!("http://{backend_addr}"),
        None,
    );

    let response = harness
        .run_request(H3RequestSpec::get("stream.example.com", "/stream"))
        .expect("h3 request");
    response.assert_status(200);
    response.assert_body_text("chunk-1:chunk-2:chunk-3");
}

#[test]
#[serial]
fn quic_to_h2_success_path_normalizes_headers_and_keeps_get_bodyless() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let backend_addr = harness.start_h2_backend(|req: hyper::Request<Incoming>| async move {
        let header_value = |name: &str| {
            req.headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("<missing>")
                .to_string()
        };
        let method = req.method().to_string();
        let path = req.uri().path().to_string();
        let host = header_value("host");
        let forwarded = header_value("forwarded");
        let xff = header_value("x-forwarded-for");
        let xfp = header_value("x-forwarded-proto");
        let xfh = header_value("x-forwarded-host");
        let user_agent = header_value("user-agent");
        let request_id = header_value("x-request-id");
        let content_length = req
            .headers()
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("<missing>")
            .to_string();
        let has_connection = req.headers().contains_key("connection");
        let body = req
            .into_body()
            .collect()
            .await
            .expect("collect request body")
            .to_bytes();
        let body = format!(
            "method={method}\npath={path}\nhost={}\nforwarded={}\nxff={}\nxfp={}\nxfh={}\nuser_agent={}\nx_request_id={}\ncontent_length={content_length}\nbody_len={}\nhas_connection={}\n",
            host,
            forwarded,
            xff,
            xfp,
            xfh,
            user_agent,
            request_id,
            body.len(),
            has_connection,
        );
        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(body))))
    });

    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        make_upstream(
            "/headers-h2",
            vec![make_backend(
                "h2-headers",
                format!("https://{backend_addr}"),
            )],
            Some(UpstreamTls {
                verify_certificates: false,
                strict_sni: false,
                ..UpstreamTls::default()
            }),
            "round-robin",
        ),
    );

    harness
        .start_listener(harness.make_config(upstreams))
        .expect("listener");

    let response = harness
        .run_request(H3RequestSpec {
            method: "GET",
            authority: "public.example.com",
            path: "/headers-h2",
            headers: &[
                ("forwarded", "for=1.2.3.4;proto=http;host=\"evil.example\""),
                ("x-forwarded-for", "1.2.3.4"),
                ("x-forwarded-proto", "http"),
                ("x-forwarded-host", "evil.example"),
                ("connection", "keep-alive, x-secret"),
                ("x-secret", "strip-me"),
            ],
            body: None,
            user_agent: "impulse-success-h2",
        })
        .expect("h3 request");

    response.assert_status(200);
    let body = response.body_text();
    assert_eq!(response_line(&body, "method="), "GET");
    assert_eq!(response_line(&body, "path="), "/headers-h2");
    assert_eq!(response_line(&body, "host="), "public.example.com");
    assert_eq!(
        response_line(&body, "forwarded="),
        "for=127.0.0.1;proto=https;host=\"public.example.com\""
    );
    assert_eq!(response_line(&body, "xff="), "127.0.0.1");
    assert_eq!(response_line(&body, "xfp="), "https");
    assert_eq!(response_line(&body, "xfh="), "public.example.com");
    assert_eq!(response_line(&body, "user_agent="), "impulse-success-h2");
    assert_eq!(response_line(&body, "content_length="), "<missing>");
    assert_eq!(response_line(&body, "body_len="), "0");
    assert_eq!(response_line(&body, "has_connection="), "false");

    let request_id = response_line(&body, "x_request_id=");
    assert!(
        !request_id.is_empty() && request_id.chars().all(|ch| ch.is_ascii_digit()),
        "x-request-id should be a generated numeric request identifier, got `{request_id}`"
    );
}

#[test]
#[serial]
fn quic_to_h2_success_path_streams_response_body_to_completion() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let backend_addr =
        harness.start_h2_streaming_backend(vec![b"h2-chunk-1:", b"h2-chunk-2:", b"h2-chunk-3"]);

    start_single_route_listener(
        &mut harness,
        "/stream-h2",
        "h2-stream",
        format!("https://{backend_addr}"),
        Some(UpstreamTls {
            verify_certificates: false,
            strict_sni: false,
            ..UpstreamTls::default()
        }),
    );

    let response = harness
        .run_request(H3RequestSpec::get("stream.example.com", "/stream-h2"))
        .expect("h3 request");
    response.assert_status(200);
    response.assert_body_text("h2-chunk-1:h2-chunk-2:h2-chunk-3");
}

#[test]
#[serial]
fn quic_to_h2_upstream_mtls_requires_client_certificate() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let mtls = MtlsTestMaterial::localhost();
    let backend_requests = Arc::new(AtomicUsize::new(0));
    let backend_requests_for_handler = Arc::clone(&backend_requests);
    let backend_addr = harness.start_h2_backend_with_client_auth(
        &mtls.server_cert_path,
        &mtls.server_key_path,
        &mtls.ca_cert_path,
        move |_req| {
            let backend_requests = Arc::clone(&backend_requests_for_handler);
            async move {
                backend_requests.fetch_add(1, Ordering::Relaxed);
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"unexpected"))))
            }
        },
    );

    start_single_backend_listener(
        &mut harness,
        "/mtls-required",
        "h2-mtls",
        format!("https://127.0.0.1:{}", backend_addr.port()),
        |config| {
            config.upstream_tls = UpstreamTls {
                verify_certificates: true,
                strict_sni: true,
                ca_file: Some(mtls.ca_cert_path.clone()),
                ca_dir: None,
                client_certificate: None,
                client_certificate_ref: None,
                client_key: None,
                client_key_ref: None,
            };
        },
    );

    let response = harness
        .run_request(H3RequestSpec::get("public.example.com", "/mtls-required"))
        .expect("h3 request");

    response.assert_status(502);
    assert_eq!(
        backend_requests.load(Ordering::Relaxed),
        0,
        "request must not reach the HTTP handler without a client certificate"
    );
}

#[test]
#[serial]
fn quic_to_h2_upstream_mtls_succeeds_with_client_certificate() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let mtls = MtlsTestMaterial::localhost();
    let backend_addr = harness.start_h2_backend_with_client_auth(
        &mtls.server_cert_path,
        &mtls.server_key_path,
        &mtls.ca_cert_path,
        move |_req| async move {
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                b"mtls-edge-ok",
            ))))
        },
    );

    start_single_backend_listener(
        &mut harness,
        "/mtls-success",
        "h2-mtls",
        format!("https://127.0.0.1:{}", backend_addr.port()),
        |config| {
            config.upstream_tls = UpstreamTls {
                verify_certificates: true,
                strict_sni: true,
                ca_file: Some(mtls.ca_cert_path.clone()),
                ca_dir: None,
                client_certificate: None,
                client_certificate_ref: Some(SecretRef {
                    reference: format!("file://{}", mtls.client_cert_path),
                }),
                client_key: None,
                client_key_ref: Some(SecretRef {
                    reference: format!("file://{}", mtls.client_key_path),
                }),
            };
        },
    );

    let response = harness
        .run_request(H3RequestSpec::get("public.example.com", "/mtls-success"))
        .expect("h3 request");
    response.assert_status(200);
    response.assert_body_text("mtls-edge-ok");
}

// Rejection path contracts

#[test]
#[serial]
fn quic_request_path_auth_deny_rejects_before_upstream_dispatch() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let upstream_calls = Arc::new(AtomicUsize::new(0));
    let backend_observed = Arc::clone(&upstream_calls);
    let backend_addr = harness.start_h1_backend(move |_req: hyper::Request<Incoming>| {
        let backend_observed = Arc::clone(&backend_observed);
        async move {
            backend_observed.fetch_add(1, Ordering::Relaxed);
            Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(
                b"unexpected upstream call",
            ))))
        }
    });

    let mut upstream = make_upstream(
        "/protected",
        vec![make_backend(
            "h1-protected",
            format!("http://{backend_addr}"),
        )],
        None,
        "round-robin",
    );
    upstream.auth = RouteAuth {
        api_key: Some(ApiKeyAuth {
            header_name: "x-api-key".to_string(),
            keys: vec!["edge-key".to_string()],
        }),
        ..RouteAuth::default()
    };

    let mut upstreams = HashMap::new();
    upstreams.insert("api".to_string(), upstream);

    harness
        .start_listener(harness.make_config(upstreams))
        .expect("listener");

    let response = harness
        .run_request(H3RequestSpec::get("localhost", "/protected"))
        .expect("unauthorized request should complete");

    response.assert_status(401);
    assert_eq!(response.header("www-authenticate"), Some("ApiKey"));
    assert!(
        response.body_text().contains("unauthorized"),
        "expected canonical unauthorized response body"
    );
    assert_eq!(
        upstream_calls.load(Ordering::Relaxed),
        0,
        "pre-dispatch auth rejection must not contact upstream"
    );
}

#[test]
#[serial]
fn quic_request_path_rate_limit_deny_rejects_before_second_upstream_dispatch() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let upstream_calls = Arc::new(AtomicUsize::new(0));
    let backend_observed = Arc::clone(&upstream_calls);
    let backend_addr = harness.start_h1_backend(move |_req: hyper::Request<Incoming>| {
        let backend_observed = Arc::clone(&backend_observed);
        async move {
            backend_observed.fetch_add(1, Ordering::Relaxed);
            Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(
                b"rate-limit ok",
            ))))
        }
    });

    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        make_upstream(
            "/limited",
            vec![make_backend("h1-limited", format!("http://{backend_addr}"))],
            None,
            "round-robin",
        ),
    );

    let mut config = harness.make_config(upstreams);
    config.resilience.scoped_rate_limits = vec![ScopedRateLimit {
        name: "route-cap".to_string(),
        scope: ScopedRateLimitScope::Route,
        requests_per_sec: 1,
        burst: 1,
        key: None,
        route_allowlist: vec!["api".to_string()],
        idle_ttl_secs: 300,
    }];

    harness.start_listener(config).expect("listener");

    let first = harness
        .run_request(H3RequestSpec::get("localhost", "/limited"))
        .expect("first request should complete");
    first.assert_status(200);
    first.assert_body_text("rate-limit ok");

    let second = harness
        .run_request(H3RequestSpec::get("localhost", "/limited"))
        .expect("second request should complete");
    second.assert_status(429);
    assert!(
        second.body_text().contains("request rate limited"),
        "expected canonical rate-limit rejection body"
    );
    assert_eq!(
        upstream_calls.load(Ordering::Relaxed),
        1,
        "rate-limit rejection must stop before contacting upstream on the second request"
    );
}

#[test]
#[serial]
fn quic_request_path_upstream_overload_sheds_before_second_upstream_dispatch() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let upstream_calls = Arc::new(AtomicUsize::new(0));
    let backend_observed = Arc::clone(&upstream_calls);
    let backend_addr = harness.start_h1_backend(move |_req: hyper::Request<Incoming>| {
        let backend_observed = Arc::clone(&backend_observed);
        async move {
            backend_observed.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(250)).await;
            Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(
                b"slow ok",
            ))))
        }
    });

    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        make_upstream(
            "/slow",
            vec![make_backend("h1-slow", format!("http://{backend_addr}"))],
            None,
            "round-robin",
        ),
    );

    let mut config = harness.make_config(upstreams);
    config.performance.global_inflight_limit = 64;
    config.performance.per_upstream_inflight_limit = 1;
    let listen_addr = harness.start_listener(config).expect("listener");
    let barrier = Arc::new(Barrier::new(2));

    let responses = thread::scope(|scope| {
        let first_barrier = Arc::clone(&barrier);
        let first = scope.spawn(move || {
            first_barrier.wait();
            run_request_to(listen_addr, H3RequestSpec::get("localhost", "/slow"))
        });

        let second_barrier = Arc::clone(&barrier);
        let second = scope.spawn(move || {
            second_barrier.wait();
            run_request_to(listen_addr, H3RequestSpec::get("localhost", "/slow"))
        });

        [
            first.join().expect("first request thread"),
            second.join().expect("second request thread"),
        ]
    });

    let mut status_200 = 0usize;
    let mut status_503 = 0usize;
    let mut shed_body = String::new();
    for response in responses {
        let response = response.expect("concurrent request should complete");
        match response.status {
            200 => status_200 += 1,
            503 => {
                status_503 += 1;
                shed_body = response.body_text();
            }
            other => panic!("unexpected status in overload test: {other}"),
        }
    }

    assert_eq!(status_200, 1, "expected one successful request");
    assert_eq!(status_503, 1, "expected one shed request");
    assert!(
        shed_body.contains("upstream overloaded"),
        "expected canonical overload response body, got `{shed_body}`"
    );
    assert_eq!(
        upstream_calls.load(Ordering::Relaxed),
        1,
        "upstream overload rejection must happen before the second request reaches the backend"
    );
}

#[test]
#[serial]
fn quic_request_path_external_auth_allow_injects_headers_before_forwarding() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let backend_calls = Arc::new(AtomicUsize::new(0));
    let backend_observed = Arc::clone(&backend_calls);
    let backend_addr = harness.start_h1_backend(move |req: hyper::Request<Incoming>| {
        let backend_observed = Arc::clone(&backend_observed);
        async move {
            backend_observed.fetch_add(1, Ordering::Relaxed);
            let user = req
                .headers()
                .get("x-user-id")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("missing")
                .to_string();
            Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(format!(
                "backend user={user}"
            )))))
        }
    });

    let auth_calls = Arc::new(AtomicUsize::new(0));
    let auth_observed = Arc::clone(&auth_calls);
    let auth_addr = harness.start_h1_backend(move |req: hyper::Request<Incoming>| {
        let auth_observed = Arc::clone(&auth_observed);
        async move {
            auth_observed.fetch_add(1, Ordering::Relaxed);
            assert_eq!(req.uri().path(), "/check");
            assert_eq!(req.method(), hyper::Method::GET);
            assert_eq!(
                req.headers()
                    .get("x-impulse-original-method")
                    .and_then(|value| value.to_str().ok()),
                Some("GET")
            );
            assert_eq!(
                req.headers()
                    .get("x-auth-static")
                    .and_then(|value| value.to_str().ok()),
                Some("1")
            );
            Ok::<_, std::convert::Infallible>(
                Response::builder()
                    .status(hyper::StatusCode::NO_CONTENT)
                    .header("x-user-id", "alice")
                    .body(Full::new(Bytes::new()))
                    .expect("auth allow response"),
            )
        }
    });

    let config = configure_http_external_auth(
        &harness,
        format!("http://{backend_addr}"),
        format!("http://{auth_addr}/check"),
        250,
        ExternalAuthFailureMode::FailClosed,
        vec!["x-user-id".to_string()],
    );

    harness.start_listener(config).expect("listener");

    let response = harness
        .run_request(H3RequestSpec::get("localhost", "/auth"))
        .expect("allow request should complete");
    response.assert_status(200);
    response.assert_body_text("backend user=alice");
    assert_eq!(auth_calls.load(Ordering::Relaxed), 1);
    assert_eq!(backend_calls.load(Ordering::Relaxed), 1);
}

#[test]
#[serial]
fn quic_request_path_external_auth_deny_returns_canonical_denial_without_forwarding() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let backend_calls = Arc::new(AtomicUsize::new(0));
    let backend_observed = Arc::clone(&backend_calls);
    let backend_addr = harness.start_h1_backend(move |_req: hyper::Request<Incoming>| {
        let backend_observed = Arc::clone(&backend_observed);
        async move {
            backend_observed.fetch_add(1, Ordering::Relaxed);
            Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(
                b"unexpected backend call",
            ))))
        }
    });

    let auth_addr = harness.start_h1_backend(|_req: hyper::Request<Incoming>| async move {
        Ok::<_, std::convert::Infallible>(
            Response::builder()
                .status(hyper::StatusCode::FORBIDDEN)
                .header("x-auth-reason", "policy")
                .body(Full::new(Bytes::from_static(b"denied by auth")))
                .expect("auth deny response"),
        )
    });

    let config = configure_http_external_auth(
        &harness,
        format!("http://{backend_addr}"),
        format!("http://{auth_addr}/check"),
        250,
        ExternalAuthFailureMode::FailClosed,
        vec!["x-auth-reason".to_string()],
    );

    harness.start_listener(config).expect("listener");

    let response = harness
        .run_request(H3RequestSpec::get("localhost", "/auth"))
        .expect("deny request should complete");
    response.assert_status(403);
    assert_eq!(response.header("x-auth-reason"), Some("policy"));
    assert!(
        response.body_text().contains("denied by auth"),
        "expected canonical auth denial body"
    );
    assert_eq!(backend_calls.load(Ordering::Relaxed), 0);
}

#[test]
#[serial]
fn quic_request_path_external_auth_challenge_preserves_www_authenticate() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let backend_calls = Arc::new(AtomicUsize::new(0));
    let backend_observed = Arc::clone(&backend_calls);
    let backend_addr = harness.start_h1_backend(move |_req: hyper::Request<Incoming>| {
        let backend_observed = Arc::clone(&backend_observed);
        async move {
            backend_observed.fetch_add(1, Ordering::Relaxed);
            Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(
                b"unexpected backend call",
            ))))
        }
    });

    let auth_addr = harness.start_h1_backend(|_req: hyper::Request<Incoming>| async move {
        Ok::<_, std::convert::Infallible>(
            Response::builder()
                .status(hyper::StatusCode::UNAUTHORIZED)
                .header("www-authenticate", "Bearer realm=\"impulse\"")
                .header("x-auth-reason", "expired")
                .body(Full::new(Bytes::from_static(b"token expired")))
                .expect("auth challenge response"),
        )
    });

    let config = configure_http_external_auth(
        &harness,
        format!("http://{backend_addr}"),
        format!("http://{auth_addr}/check"),
        250,
        ExternalAuthFailureMode::FailClosed,
        vec!["x-auth-reason".to_string()],
    );

    harness.start_listener(config).expect("listener");

    let response = harness
        .run_request(H3RequestSpec::get("localhost", "/auth"))
        .expect("challenge request should complete");
    response.assert_status(401);
    assert_eq!(
        response.header("www-authenticate"),
        Some("Bearer realm=\"impulse\"")
    );
    assert_eq!(response.header("x-auth-reason"), Some("expired"));
    assert!(response.body_text().contains("token expired"));
    assert_eq!(backend_calls.load(Ordering::Relaxed), 0);
}

#[test]
#[serial]
fn quic_request_path_external_auth_redirect_preserves_location() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let backend_calls = Arc::new(AtomicUsize::new(0));
    let backend_observed = Arc::clone(&backend_calls);
    let backend_addr = harness.start_h1_backend(move |_req: hyper::Request<Incoming>| {
        let backend_observed = Arc::clone(&backend_observed);
        async move {
            backend_observed.fetch_add(1, Ordering::Relaxed);
            Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(
                b"unexpected backend call",
            ))))
        }
    });

    let auth_addr = harness.start_h1_backend(|_req: hyper::Request<Incoming>| async move {
        Ok::<_, std::convert::Infallible>(
            Response::builder()
                .status(hyper::StatusCode::FOUND)
                .header("location", "https://login.example.com/")
                .body(Full::new(Bytes::new()))
                .expect("auth redirect response"),
        )
    });

    let config = configure_http_external_auth(
        &harness,
        format!("http://{backend_addr}"),
        format!("http://{auth_addr}/check"),
        250,
        ExternalAuthFailureMode::FailClosed,
        vec![],
    );

    harness.start_listener(config).expect("listener");

    let response = harness
        .run_request(H3RequestSpec::get("localhost", "/auth"))
        .expect("redirect request should complete");
    response.assert_status(302);
    assert_eq!(
        response.header("location"),
        Some("https://login.example.com/")
    );
    assert!(response.body.is_empty(), "redirect body should be empty");
    assert_eq!(backend_calls.load(Ordering::Relaxed), 0);
}

#[test]
#[serial]
fn quic_request_path_external_auth_timeout_fail_closed_returns_gateway_timeout() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let backend_calls = Arc::new(AtomicUsize::new(0));
    let backend_observed = Arc::clone(&backend_calls);
    let backend_addr = harness.start_h1_backend(move |_req: hyper::Request<Incoming>| {
        let backend_observed = Arc::clone(&backend_observed);
        async move {
            backend_observed.fetch_add(1, Ordering::Relaxed);
            Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(
                b"unexpected backend call",
            ))))
        }
    });

    let auth_addr = harness.start_h1_backend(|_req: hyper::Request<Incoming>| async move {
        tokio::time::sleep(Duration::from_millis(80)).await;
        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::new())))
    });

    let config = configure_http_external_auth(
        &harness,
        format!("http://{backend_addr}"),
        format!("http://{auth_addr}/check"),
        15,
        ExternalAuthFailureMode::FailClosed,
        vec![],
    );

    harness.start_listener(config).expect("listener");

    let response = harness
        .run_request(H3RequestSpec::get("localhost", "/auth"))
        .expect("timeout fail-closed request should complete");
    response.assert_status(504);
    assert!(
        response.body_text().contains("external auth timeout"),
        "expected canonical external auth timeout body"
    );
    assert_eq!(backend_calls.load(Ordering::Relaxed), 0);
}

#[test]
#[serial]
fn quic_request_path_external_auth_timeout_fail_open_allows_backend() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let backend_calls = Arc::new(AtomicUsize::new(0));
    let backend_observed = Arc::clone(&backend_calls);
    let backend_addr = harness.start_h1_backend(move |_req: hyper::Request<Incoming>| {
        let backend_observed = Arc::clone(&backend_observed);
        async move {
            backend_observed.fetch_add(1, Ordering::Relaxed);
            Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(
                b"backend after fail-open",
            ))))
        }
    });

    let auth_addr = harness.start_h1_backend(|_req: hyper::Request<Incoming>| async move {
        tokio::time::sleep(Duration::from_millis(80)).await;
        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::new())))
    });

    let config = configure_http_external_auth(
        &harness,
        format!("http://{backend_addr}"),
        format!("http://{auth_addr}/check"),
        15,
        ExternalAuthFailureMode::FailOpen,
        vec![],
    );

    harness.start_listener(config).expect("listener");

    let response = harness
        .run_request(H3RequestSpec::get("localhost", "/auth"))
        .expect("timeout fail-open request should complete");
    response.assert_status(200);
    response.assert_body_text("backend after fail-open");
    assert_eq!(backend_calls.load(Ordering::Relaxed), 1);
}

// Upstream failure contracts

#[test]
#[serial]
fn quic_request_path_backend_timeout_maps_to_upstream_timeout() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let backend_calls = Arc::new(AtomicUsize::new(0));
    let backend_observed = Arc::clone(&backend_calls);
    let backend_addr = harness.start_h1_backend(move |_req: hyper::Request<Incoming>| {
        let backend_observed = Arc::clone(&backend_observed);
        async move {
            backend_observed.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(300)).await;
            Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(
                b"too late",
            ))))
        }
    });

    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        make_upstream(
            "/timeout",
            vec![make_backend("h1-timeout", format!("http://{backend_addr}"))],
            None,
            "round-robin",
        ),
    );

    let mut config = harness.make_config(upstreams);
    config.performance.backend_timeout_ms = 150;
    config.performance.backend_connect_timeout_ms = 150;
    harness.start_listener(config).expect("listener");

    let response = harness
        .run_request(H3RequestSpec::get("localhost", "/timeout"))
        .expect("timeout request should complete");
    response.assert_status(503);
    assert!(
        response.body_text().contains("upstream timeout"),
        "expected canonical upstream timeout body"
    );
    assert_eq!(backend_calls.load(Ordering::Relaxed), 1);
}

#[test]
#[serial]
fn quic_request_path_connect_failure_maps_to_upstream_error() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let unused_listener = TcpListener::bind("127.0.0.1:0").expect("bind unused backend port");
    let unused_addr = unused_listener.local_addr().expect("unused backend addr");
    drop(unused_listener);

    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        make_upstream(
            "/connect-fail",
            vec![make_backend(
                "h1-connect-fail",
                format!("http://{unused_addr}"),
            )],
            None,
            "round-robin",
        ),
    );

    let mut config = harness.make_config(upstreams);
    config.performance.backend_timeout_ms = 150;
    config.performance.backend_connect_timeout_ms = 150;
    harness.start_listener(config).expect("listener");

    let response = harness
        .run_request(H3RequestSpec::get("localhost", "/connect-fail"))
        .expect("connect failure request should complete");
    response.assert_status(502);
    assert!(
        response.body_text().contains("upstream error"),
        "expected canonical upstream transport failure body"
    );
}

// Body and stream guardrail contracts

#[test]
#[serial]
fn quic_request_path_request_body_cap_breach_returns_413_not_503() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let backend_addr = harness.start_h1_static_backend(b"backend upload");
    let listen_addr = start_single_backend_listener(
        &mut harness,
        "/upload",
        "h1-upload",
        format!("http://{backend_addr}"),
        |config| {
            config.performance.max_request_body_bytes = 1024;
        },
    );

    let (response, got_reset) = run_two_chunk_post_to(
        listen_addr,
        "localhost",
        "/upload",
        vec![0u8; 600],
        vec![0u8; 600],
        Duration::ZERO,
    )
    .expect("oversized request should complete");

    response.assert_status(413);
    assert_ne!(
        response.status, 503,
        "request body cap breaches must stay on the bounded 413 path"
    );
    assert!(
        response.body_text().contains("request body too large"),
        "expected canonical request-body-too-large response body"
    );
    assert!(
        !got_reset,
        "oversized request should terminate with HTTP response"
    );
}

#[test]
#[serial]
fn quic_request_path_request_body_at_cap_is_accepted() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let backend_addr = harness.start_h1_backend(|req: hyper::Request<Incoming>| async move {
        let body = req
            .into_body()
            .collect()
            .await
            .expect("collect request body")
            .to_bytes();
        Ok::<_, Infallible>(
            Response::builder()
                .status(200)
                .body(Full::new(Bytes::from(body.len().to_string())))
                .expect("response"),
        )
    });
    let listen_addr = start_single_backend_listener(
        &mut harness,
        "/upload-at-cap",
        "h1-upload-at-cap",
        format!("http://{backend_addr}"),
        |_| {},
    );

    let chunk1 = vec![0u8; impulse_edge::MAX_REQUEST_BODY_BYTES / 2];
    let chunk2 = vec![0u8; impulse_edge::MAX_REQUEST_BODY_BYTES - chunk1.len()];
    let expected_len = chunk1.len() + chunk2.len();

    let (response, got_reset) = run_two_chunk_post_to(
        listen_addr,
        "localhost",
        "/upload-at-cap",
        chunk1,
        chunk2,
        Duration::ZERO,
    )
    .expect("at-cap request should complete");

    response.assert_status(200);
    response.assert_body_text(&expected_len.to_string());
    assert!(!got_reset, "request at cap should not reset stream");
}

#[test]
#[serial]
/// Regression: a slow over-cap producer previously escaped through a generic
/// fallback path and surfaced as 503 instead of the bounded 413 contract.
fn quic_request_path_slow_request_body_cap_breach_stays_on_413_path() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let backend_addr = harness.start_h2_static_backend(b"unexpected backend call");
    let listen_addr = start_single_backend_listener(
        &mut harness,
        "/upload-slow-over-cap",
        "h2-upload-slow-over-cap",
        backend_addr.to_string(),
        |config| {
            config.performance.max_request_body_bytes = 1024;
        },
    );

    let (response, got_reset) = run_two_chunk_post_to_with_response_timeout(
        listen_addr,
        "localhost",
        "/upload-slow-over-cap",
        vec![0u8; 600],
        vec![0u8; 600],
        Duration::from_millis(120),
        Duration::from_secs(impulse_edge::REQUEST_TIMEOUT_SECS + 12),
    )
    .expect("slow over-cap request should complete");

    response.assert_status(413);
    assert_ne!(
        response.status, 503,
        "slow over-cap request bodies must not escape through a fallback 503 path"
    );
    assert!(
        response.body_text().contains("request body too large"),
        "expected canonical request-body-too-large response body"
    );
    assert!(
        !got_reset,
        "slow over-cap request should terminate with HTTP response, not reset"
    );
}

#[test]
#[serial]
fn quic_request_path_concurrent_large_body_pressure_is_bounded() {
    if !local_listener_bind_available() {
        return;
    }

    const CLIENTS: usize = 6;

    let mut harness = QuicRequestPathHarness::new();
    let backend_addr = harness.start_h1_backend(|req: hyper::Request<Incoming>| async move {
        let _body = req
            .into_body()
            .collect()
            .await
            .expect("collect request body")
            .to_bytes();
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
    });

    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        make_upstream(
            "/pressure",
            vec![make_backend(
                "h1-pressure",
                format!("http://{backend_addr}"),
            )],
            None,
            "round-robin",
        ),
    );

    let mut config = harness.make_config(upstreams);
    config.performance.global_inflight_limit = 1;
    config.performance.per_upstream_inflight_limit = 1;
    config.performance.per_backend_inflight_limit = 1;
    let listen_addr = harness.start_listener(config).expect("listener");

    let barrier = Arc::new(Barrier::new(CLIENTS));
    let mut handles = Vec::with_capacity(CLIENTS);
    for _ in 0..CLIENTS {
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let chunk1 = vec![0u8; (impulse_edge::MAX_REQUEST_BODY_BYTES - 8 * 1024) / 2];
            let chunk2 =
                vec![0u8; (impulse_edge::MAX_REQUEST_BODY_BYTES - 8 * 1024) - chunk1.len()];
            run_two_chunk_post_to(
                listen_addr,
                "localhost",
                "/pressure",
                chunk1,
                chunk2,
                Duration::from_millis(20),
            )
        }));
    }

    let mut count_200 = 0usize;
    let mut count_503 = 0usize;
    for handle in handles {
        let (response, got_reset) = handle
            .join()
            .expect("client thread panicked")
            .expect("client request should terminate");
        assert!(!got_reset, "pressure requests should terminate cleanly");
        match response.status {
            200 => count_200 += 1,
            503 => count_503 += 1,
            other => panic!("unexpected status under pressure: {other}"),
        }
    }

    assert!(count_200 >= 1, "expected at least one admitted request");
    assert!(count_503 >= 1, "expected bounded overload shedding");
    assert_eq!(count_200 + count_503, CLIENTS);
}

#[test]
#[serial]
fn quic_request_path_stalled_request_body_producer_returns_408() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let backend_addr = harness.start_h1_static_backend(b"unexpected backend call");

    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        make_upstream(
            "/upload-idle",
            vec![make_backend(
                "h1-upload-idle",
                format!("http://{backend_addr}"),
            )],
            None,
            "round-robin",
        ),
    );

    let mut config = harness.make_config(upstreams);
    config.performance.client_body_idle_timeout_ms = 120;
    config.performance.backend_body_total_timeout_ms = 10_000;
    config.performance.backend_total_request_timeout_ms = 10_000;
    let listen_addr = harness.start_listener(config).expect("listener");

    let (response, got_reset) = run_two_chunk_post_to(
        listen_addr,
        "localhost",
        "/upload-idle",
        vec![0u8; 512],
        vec![0u8; 512],
        Duration::from_millis(250),
    )
    .expect("slow request producer should complete");

    response.assert_status(408);
    assert!(
        response.body_text().contains("request body idle timeout"),
        "expected canonical request body idle-timeout response body"
    );
    assert!(
        !got_reset,
        "request body idle timeout should return HTTP response, not reset"
    );
}

#[test]
#[serial]
fn quic_request_path_unknown_length_response_prebuffer_cap_returns_503() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let backend_addr = harness.start_h1_chunked_backend(vec![b"chunk-1", b"chunk-2"]);

    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        make_upstream(
            "/long-stream",
            vec![make_backend(
                "h1-long-stream",
                format!("http://{backend_addr}"),
            )],
            None,
            "round-robin",
        ),
    );

    let mut config = harness.make_config(upstreams);
    config.performance.max_response_body_bytes = 64 * 1024;
    config.performance.unknown_length_response_prebuffer_bytes = 8;
    harness.start_listener(config).expect("listener");

    let response = harness
        .run_request(H3RequestSpec::get("localhost", "/long-stream"))
        .expect("unknown-length response cap request should complete");

    response.assert_status(503);
    response.assert_body_text("upstream response body too large\n");
}

#[test]
#[serial]
fn quic_request_path_slow_response_body_before_first_chunk_returns_timeout() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let backend_addr = harness.start_h1_delayed_chunked_backend(vec![
        (b"chunk-1".to_vec(), Duration::from_millis(250)),
        (b"chunk-2".to_vec(), Duration::ZERO),
    ]);

    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        make_upstream(
            "/slow-stream",
            vec![make_backend(
                "h1-slow-stream",
                format!("http://{backend_addr}"),
            )],
            None,
            "round-robin",
        ),
    );

    let mut config = harness.make_config(upstreams);
    config.performance.backend_timeout_ms = 100;
    config.performance.backend_connect_timeout_ms = 100;
    config.performance.backend_body_total_timeout_ms = 5_000;
    config.performance.backend_body_idle_timeout_ms = 120;
    harness.start_listener(config).expect("listener");

    let response = harness
        .run_request(H3RequestSpec::get("localhost", "/slow-stream"))
        .expect("slow response stream request should complete");

    response.assert_status(503);
    assert!(
        response.body_text().contains("upstream timeout"),
        "expected canonical upstream timeout body for stalled response body stream"
    );
}

#[test]
#[serial]
/// Regression: the total response-body timer must not kill streams that keep
/// making forward progress before the idle timer expires.
fn quic_request_path_progressing_long_stream_ignores_body_total_timeout() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let backend_addr = harness.start_h1_delayed_chunked_backend(vec![
        (b"part-1".to_vec(), Duration::from_millis(50)),
        (b"part-2".to_vec(), Duration::from_millis(100)),
        (b"part-3".to_vec(), Duration::from_millis(100)),
        (b"part-4".to_vec(), Duration::from_millis(100)),
    ]);

    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        make_upstream(
            "/long-stream",
            vec![make_backend(
                "h1-long-stream-progress",
                format!("http://{backend_addr}"),
            )],
            None,
            "round-robin",
        ),
    );

    let mut config = harness.make_config(upstreams);
    config.performance.backend_timeout_ms = 240;
    config.performance.backend_connect_timeout_ms = 240;
    config.performance.backend_body_total_timeout_ms = 250;
    config.performance.backend_body_idle_timeout_ms = 240;
    config.performance.backend_total_request_timeout_ms = 5_000;
    harness.start_listener(config).expect("listener");

    let response = harness
        .run_request(H3RequestSpec::get("localhost", "/long-stream"))
        .expect("long stream request should complete");

    response.assert_status(200);
    assert_eq!(
        response.body_text(),
        "part-1part-2part-3part-4",
        "body-total timeout must not kill a response stream that keeps making progress"
    );
}

// Observable outcome parity contracts

#[test]
#[serial]
fn quic_request_path_success_outcome_records_success_bucket() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let backend_addr = harness.start_h1_static_backend(b"ok");

    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        make_upstream(
            "/metrics-success",
            vec![make_backend("h1-success", format!("http://{backend_addr}"))],
            None,
            "round-robin",
        ),
    );

    harness
        .start_listener(harness.make_config(upstreams))
        .expect("listener");
    let before = harness
        .metrics_text()
        .expect("metrics snapshot before request");

    let response = harness
        .run_request(H3RequestSpec::get("localhost", "/metrics-success"))
        .expect("success request should complete");
    response.assert_status(200);

    let after = harness
        .metrics_text()
        .expect("metrics snapshot after request");
    assert!(
        metrics_delta(&before, &after, "impulse_requests_success ") > 0,
        "success request should increment success counter"
    );
    assert_eq!(
        metrics_delta(&before, &after, "impulse_requests_failure "),
        0
    );
    assert!(
        metrics_delta(
            &before,
            &after,
            "impulse_route_requests_total{route=\"api\"} "
        ) > 0,
        "success request should increment route request counter"
    );
    assert!(
        metrics_delta(
            &before,
            &after,
            "impulse_route_success_total{route=\"api\"} "
        ) > 0,
        "success request should increment route success counter"
    );
    assert_eq!(
        metrics_delta(
            &before,
            &after,
            "impulse_route_failure_total{route=\"api\"} "
        ),
        0
    );
    assert_eq!(
        metrics_delta(
            &before,
            &after,
            "impulse_route_timeout_total{route=\"api\"} "
        ),
        0
    );
}

#[test]
#[serial]
fn quic_request_path_timeout_outcome_records_timeout_bucket() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let backend_addr = harness.start_h1_backend(|_req: hyper::Request<Incoming>| async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(b"late"))))
    });

    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        make_upstream(
            "/metrics-timeout",
            vec![make_backend("h1-timeout", format!("http://{backend_addr}"))],
            None,
            "round-robin",
        ),
    );

    let mut config = harness.make_config(upstreams);
    config.performance.backend_timeout_ms = 150;
    config.performance.backend_connect_timeout_ms = 150;
    harness.start_listener(config).expect("listener");
    let before = harness
        .metrics_text()
        .expect("metrics snapshot before request");

    let response = harness
        .run_request(H3RequestSpec::get("localhost", "/metrics-timeout"))
        .expect("timeout request should complete");
    response.assert_status(503);
    assert!(response.body_text().contains("upstream timeout"));

    let after = harness
        .metrics_text()
        .expect("metrics snapshot after request");
    assert!(
        metrics_delta(&before, &after, "impulse_backend_timeouts ") > 0,
        "timeout request should increment backend timeout counter"
    );
    assert!(
        metrics_delta(&before, &after, "impulse_requests_failure ") > 0,
        "timeout request should increment failure counter"
    );
    assert!(
        metrics_delta(
            &before,
            &after,
            "impulse_route_timeout_total{route=\"api\"} "
        ) > 0,
        "timeout request should increment timeout bucket"
    );
    assert_eq!(
        metrics_delta(
            &before,
            &after,
            "impulse_route_success_total{route=\"api\"} "
        ),
        0
    );
}

#[test]
#[serial]
fn quic_request_path_failure_outcome_records_failure_bucket() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let unused_listener = TcpListener::bind("127.0.0.1:0").expect("bind unused backend port");
    let unused_addr = unused_listener.local_addr().expect("unused backend addr");
    drop(unused_listener);

    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        make_upstream(
            "/metrics-failure",
            vec![make_backend("h1-failure", format!("http://{unused_addr}"))],
            None,
            "round-robin",
        ),
    );

    let mut config = harness.make_config(upstreams);
    config.performance.backend_timeout_ms = 150;
    config.performance.backend_connect_timeout_ms = 150;
    harness.start_listener(config).expect("listener");
    let before = harness
        .metrics_text()
        .expect("metrics snapshot before request");

    let response = harness
        .run_request(H3RequestSpec::get("localhost", "/metrics-failure"))
        .expect("failure request should complete");
    response.assert_status(502);
    assert!(response.body_text().contains("upstream error"));

    let after = harness
        .metrics_text()
        .expect("metrics snapshot after request");
    assert!(
        metrics_delta(&before, &after, "impulse_backend_errors ") > 0,
        "upstream failure should increment backend error counter"
    );
    assert!(
        metrics_delta(&before, &after, "impulse_requests_failure ") > 0,
        "upstream failure should increment failure counter"
    );
    assert!(
        metrics_delta(
            &before,
            &after,
            "impulse_route_failure_total{route=\"api\"} "
        ) > 0,
        "upstream failure should increment failure bucket"
    );
    assert_eq!(
        metrics_delta(
            &before,
            &after,
            "impulse_route_timeout_total{route=\"api\"} "
        ),
        0
    );
    assert_eq!(
        metrics_delta(
            &before,
            &after,
            "impulse_route_overload_shed_total{route=\"api\"} "
        ),
        0
    );
}

#[test]
#[serial]
fn quic_request_path_rate_limit_outcome_records_rate_limited_bucket() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let backend_addr = harness.start_h1_static_backend(b"rate-limit ok");

    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        make_upstream(
            "/metrics-rate-limit",
            vec![make_backend(
                "h1-rate-limit",
                format!("http://{backend_addr}"),
            )],
            None,
            "round-robin",
        ),
    );

    let mut config = harness.make_config(upstreams);
    config.resilience.scoped_rate_limits = vec![ScopedRateLimit {
        name: "route-cap".to_string(),
        scope: ScopedRateLimitScope::Route,
        requests_per_sec: 1,
        burst: 1,
        key: None,
        route_allowlist: vec!["api".to_string()],
        idle_ttl_secs: 300,
    }];
    harness.start_listener(config).expect("listener");
    let before = harness
        .metrics_text()
        .expect("metrics snapshot before requests");

    let first = harness
        .run_request(H3RequestSpec::get("localhost", "/metrics-rate-limit"))
        .expect("first request should complete");
    first.assert_status(200);

    let second = harness
        .run_request(H3RequestSpec::get("localhost", "/metrics-rate-limit"))
        .expect("rate-limited request should complete");
    second.assert_status(429);

    let after = harness
        .metrics_text()
        .expect("metrics snapshot after requests");
    assert!(
        metrics_delta(&before, &after, "impulse_request_rate_limited ") > 0,
        "rate-limited request should increment rate-limit counter"
    );
    assert!(
        metrics_delta(
            &before,
            &after,
            "impulse_route_rate_limited_total{route=\"api\"} "
        ) > 0,
        "rate-limited request should increment route rate-limit bucket"
    );
    assert!(
        metrics_delta(&before, &after, "impulse_requests_success ") > 0,
        "admitted request should increment success counter"
    );
    assert!(
        metrics_delta(&before, &after, "impulse_requests_failure ") > 0,
        "rate-limited request should increment failure counter"
    );
    assert_eq!(
        metrics_delta(
            &before,
            &after,
            "impulse_route_overload_shed_total{route=\"api\"} "
        ),
        0
    );
}

#[test]
#[serial]
fn quic_request_path_overload_outcome_records_overload_bucket() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = QuicRequestPathHarness::new();
    let backend_addr = harness.start_h1_backend(|_req: hyper::Request<Incoming>| async move {
        tokio::time::sleep(Duration::from_millis(250)).await;
        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(b"slow ok"))))
    });

    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        make_upstream(
            "/metrics-overload",
            vec![make_backend(
                "h1-overload",
                format!("http://{backend_addr}"),
            )],
            None,
            "round-robin",
        ),
    );

    let mut config = harness.make_config(upstreams);
    config.performance.global_inflight_limit = 64;
    config.performance.per_upstream_inflight_limit = 1;
    let listen_addr = harness.start_listener(config).expect("listener");
    let before = harness
        .metrics_text()
        .expect("metrics snapshot before requests");
    let barrier = Arc::new(Barrier::new(2));

    let responses = thread::scope(|scope| {
        let first_barrier = Arc::clone(&barrier);
        let first = scope.spawn(move || {
            first_barrier.wait();
            run_request_to(
                listen_addr,
                H3RequestSpec::get("localhost", "/metrics-overload"),
            )
        });

        let second_barrier = Arc::clone(&barrier);
        let second = scope.spawn(move || {
            second_barrier.wait();
            run_request_to(
                listen_addr,
                H3RequestSpec::get("localhost", "/metrics-overload"),
            )
        });

        [
            first.join().expect("first request thread"),
            second.join().expect("second request thread"),
        ]
    });

    let mut saw_success = false;
    let mut saw_overload = false;
    for response in responses {
        let response = response.expect("concurrent request should complete");
        match response.status {
            200 => saw_success = true,
            503 => saw_overload = true,
            other => panic!("unexpected status in overload metrics test: {other}"),
        }
    }
    assert!(saw_success, "expected one successful request");
    assert!(saw_overload, "expected one overload-shed request");

    let after = harness
        .metrics_text()
        .expect("metrics snapshot after requests");
    assert!(
        metrics_delta(
            &before,
            &after,
            "impulse_route_overload_shed_total{route=\"api\"} "
        ) > 0,
        "overload request should increment route overload bucket"
    );
    assert!(
        metrics_delta(&before, &after, "impulse_requests_success ") > 0,
        "one admitted request should increment success counter"
    );
    assert!(
        metrics_delta(&before, &after, "impulse_requests_failure ") > 0,
        "one shed request should increment failure counter"
    );
    assert_eq!(
        metrics_delta(
            &before,
            &after,
            "impulse_route_rate_limited_total{route=\"api\"} "
        ),
        0
    );
}
