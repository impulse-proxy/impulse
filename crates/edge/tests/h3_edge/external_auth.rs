use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use super::*;

fn configure_http_external_auth(
    config: &mut Config,
    endpoint: String,
    timeout_ms: u64,
    failure_mode: ExternalAuthFailureMode,
    response_header_allowlist: Vec<String>,
) {
    let upstream = config
        .upstream
        .get_mut("test_pool")
        .expect("test_pool upstream");
    upstream.auth.external_auth = Some(ExternalAuth::Http {
        endpoint,
        request_headers: vec![ExternalAuthRequestHeader {
            name: "x-auth-static".to_string(),
            value: "1".to_string(),
        }],
        response_header_allowlist,
        timeout_ms,
        failure_mode,
    });
}

fn configure_oidc_external_auth(
    config: &mut Config,
    discovery_url: String,
    timeout_ms: u64,
    failure_mode: ExternalAuthFailureMode,
) {
    let upstream = config
        .upstream
        .get_mut("test_pool")
        .expect("test_pool upstream");
    upstream.auth.external_auth = Some(ExternalAuth::Oidc {
        discovery_url: Some(discovery_url),
        issuer_url: Some("https://issuer.example.com".to_string()),
        client_id: "edge-client".to_string(),
        client_secret: Some("edge-secret".to_string()),
        client_secret_ref: None,
        audience: Some("api://edge".to_string()),
        scopes: vec!["read".to_string()],
        request_headers: vec![],
        response_header_allowlist: vec![],
        timeout_ms,
        failure_mode,
    });
}

fn send_h3_request_and_close(
    server_addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Result<(), String> {
    let (socket, _local_addr, mut conn, mut h3) = stress_connect(server_addr)?;
    let mut req_headers = vec![
        quiche::h3::Header::new(b":method", method.as_bytes()),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"localhost"),
        quiche::h3::Header::new(b":path", path.as_bytes()),
        quiche::h3::Header::new(b"user-agent", b"impulse-auth-teardown-test"),
    ];
    req_headers.extend(
        headers
            .iter()
            .map(|(name, value)| quiche::h3::Header::new(name.as_bytes(), value.as_bytes())),
    );
    h3.send_request(&mut conn, &req_headers, true)
        .map_err(|err| format!("send_request: {err:?}"))?;

    let mut out = [0u8; MAX_UDP_PAYLOAD_BYTES];
    while let Ok((write, send_info)) = conn.send(&mut out) {
        socket
            .send_to(&out[..write], send_info.to)
            .map_err(|err| format!("send_to: {err}"))?;
    }

    stress_close_gracefully(&socket, &mut conn);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_auth_allow_injects_headers_and_forwards() {
    if !local_listener_bind_available() {
        return;
    }

    let backend_addr = start_h2_backend_service(|req| async move {
        let user = req
            .headers()
            .get("x-user-id")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("missing")
            .to_string();
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!(
            "backend user={user}"
        )))))
    })
    .await;

    let auth_addr = start_http_auth_server(|req| async move {
        assert_eq!(req.uri().path(), "/check");
        assert_eq!(req.method(), http::Method::GET);
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
        let response = Response::builder()
            .status(http::StatusCode::NO_CONTENT)
            .header("x-user-id", "alice")
            .body(Full::new(Bytes::new()))
            .expect("auth allow response");
        Ok::<_, Infallible>(response)
    })
    .await;

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let mut config = make_config(0, cert, key, backend_addr.to_string());
    configure_http_external_auth(
        &mut config,
        format!("http://{auth_addr}/check"),
        250,
        ExternalAuthFailureMode::FailClosed,
        vec!["x-user-id".to_string()],
    );

    let listener = Http3Service::new(config).expect("listener");
    let (addr, stop, handle) = spawn_listener_loop(listener);
    let response = run_h3_client_request(addr, "GET", "/", &[], None).expect("h3 response");
    stop_listener_loop(stop, handle);

    assert_eq!(response.status, 200);
    assert_eq!(response.body, "backend user=alice");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_auth_deny_returns_denial_response_and_headers() {
    if !local_listener_bind_available() {
        return;
    }

    let backend_addr = start_h2_backend("should not reach backend").await;
    let auth_addr = start_http_auth_server(|_req| async move {
        let response = Response::builder()
            .status(http::StatusCode::FORBIDDEN)
            .header("x-auth-reason", "policy")
            .body(Full::new(Bytes::from("denied by auth")))
            .expect("auth deny response");
        Ok::<_, Infallible>(response)
    })
    .await;

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let mut config = make_config(0, cert, key, backend_addr.to_string());
    configure_http_external_auth(
        &mut config,
        format!("http://{auth_addr}/check"),
        250,
        ExternalAuthFailureMode::FailClosed,
        vec!["x-auth-reason".to_string()],
    );

    let listener = Http3Service::new(config).expect("listener");
    let (addr, stop, handle) = spawn_listener_loop(listener);
    let response = run_h3_client_request(addr, "GET", "/", &[], None).expect("h3 response");
    stop_listener_loop(stop, handle);

    assert_eq!(response.status, 403);
    assert_eq!(response.header("x-auth-reason"), Some("policy"));
    assert!(response.body.contains("denied by auth"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_auth_challenge_returns_www_authenticate_and_body() {
    if !local_listener_bind_available() {
        return;
    }

    let backend_addr = start_h2_backend("should not reach backend").await;
    let auth_addr = start_http_auth_server(|_req| async move {
        let response = Response::builder()
            .status(http::StatusCode::UNAUTHORIZED)
            .header("www-authenticate", "Bearer realm=\"impulse\"")
            .header("x-auth-reason", "expired")
            .body(Full::new(Bytes::from("token expired")))
            .expect("auth challenge response");
        Ok::<_, Infallible>(response)
    })
    .await;

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let mut config = make_config(0, cert, key, backend_addr.to_string());
    configure_http_external_auth(
        &mut config,
        format!("http://{auth_addr}/check"),
        250,
        ExternalAuthFailureMode::FailClosed,
        vec!["x-auth-reason".to_string()],
    );

    let listener = Http3Service::new(config).expect("listener");
    let (addr, stop, handle) = spawn_listener_loop(listener);
    let response = run_h3_client_request(addr, "GET", "/", &[], None).expect("h3 response");
    stop_listener_loop(stop, handle);

    assert_eq!(response.status, 401);
    assert_eq!(
        response.header("www-authenticate"),
        Some("Bearer realm=\"impulse\"")
    );
    assert_eq!(response.header("x-auth-reason"), Some("expired"));
    assert!(response.body.contains("token expired"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_auth_redirect_preserves_location() {
    if !local_listener_bind_available() {
        return;
    }

    let backend_addr = start_h2_backend("should not reach backend").await;
    let auth_addr = start_http_auth_server(|_req| async move {
        let response = Response::builder()
            .status(http::StatusCode::FOUND)
            .header("location", "https://login.example.com/")
            .body(Full::new(Bytes::new()))
            .expect("auth redirect response");
        Ok::<_, Infallible>(response)
    })
    .await;

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let mut config = make_config(0, cert, key, backend_addr.to_string());
    configure_http_external_auth(
        &mut config,
        format!("http://{auth_addr}/check"),
        250,
        ExternalAuthFailureMode::FailClosed,
        vec![],
    );

    let listener = Http3Service::new(config).expect("listener");
    let (addr, stop, handle) = spawn_listener_loop(listener);
    let response = run_h3_client_request(addr, "GET", "/", &[], None).expect("h3 response");
    stop_listener_loop(stop, handle);

    assert_eq!(response.status, 302);
    assert_eq!(
        response.header("location"),
        Some("https://login.example.com/")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_auth_transport_error_fail_closed_returns_unavailable() {
    if !local_listener_bind_available() {
        return;
    }

    let backend_addr = start_h2_backend("should not reach backend").await;
    let unused_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind unused port");
    let unused_addr = unused_listener.local_addr().expect("unused addr");
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let mut config = make_config(0, cert, key, backend_addr.to_string());
    configure_http_external_auth(
        &mut config,
        format!("http://{unused_addr}/check"),
        250,
        ExternalAuthFailureMode::FailClosed,
        vec![],
    );
    drop(unused_listener);

    let listener = Http3Service::new(config).expect("listener");
    let (addr, stop, handle) = spawn_listener_loop(listener);
    let response = run_h3_client_request(addr, "GET", "/", &[], None).expect("h3 response");
    stop_listener_loop(stop, handle);

    assert_eq!(response.status, 503);
    assert!(response.body.contains("external auth unavailable"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_auth_timeout_fail_closed_returns_gateway_timeout() {
    if !local_listener_bind_available() {
        return;
    }

    let backend_addr = start_h2_backend("should not reach backend").await;
    let auth_addr = start_http_auth_server(|_req| async move {
        tokio::time::sleep(Duration::from_millis(80)).await;
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
    })
    .await;

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let mut config = make_config(0, cert, key, backend_addr.to_string());
    configure_http_external_auth(
        &mut config,
        format!("http://{auth_addr}/check"),
        15,
        ExternalAuthFailureMode::FailClosed,
        vec![],
    );

    let listener = Http3Service::new(config).expect("listener");
    let (addr, stop, handle) = spawn_listener_loop(listener);
    let response = run_h3_client_request(addr, "GET", "/", &[], None).expect("h3 response");
    stop_listener_loop(stop, handle);

    assert_eq!(response.status, 504);
    assert!(response.body.contains("external auth timeout"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_auth_timeout_fail_open_allows_backend() {
    if !local_listener_bind_available() {
        return;
    }

    let backend_addr = start_h2_backend("backend after fail-open").await;
    let auth_addr = start_http_auth_server(|_req| async move {
        tokio::time::sleep(Duration::from_millis(80)).await;
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
    })
    .await;

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let mut config = make_config(0, cert, key, backend_addr.to_string());
    configure_http_external_auth(
        &mut config,
        format!("http://{auth_addr}/check"),
        15,
        ExternalAuthFailureMode::FailOpen,
        vec![],
    );

    let listener = Http3Service::new(config).expect("listener");
    let (addr, stop, handle) = spawn_listener_loop(listener);
    let response = run_h3_client_request(addr, "GET", "/", &[], None).expect("h3 response");
    stop_listener_loop(stop, handle);

    assert_eq!(response.status, 200);
    assert_eq!(response.body, "backend after fail-open");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_external_auth_uses_discovery_and_introspection() {
    if !local_listener_bind_available() {
        return;
    }

    let backend_addr = start_h2_backend("oidc ok").await;
    let discovery_requests = Arc::new(AtomicUsize::new(0));
    let introspection_requests = Arc::new(AtomicUsize::new(0));
    let discovery_requests_seen = Arc::clone(&discovery_requests);
    let introspection_requests_seen = Arc::clone(&introspection_requests);
    let auth_addr = start_http_auth_server(move |req| {
        let discovery_requests_seen = Arc::clone(&discovery_requests_seen);
        let introspection_requests_seen = Arc::clone(&introspection_requests_seen);
        async move {
            match req.uri().path() {
                "/.well-known/openid-configuration" => {
                    discovery_requests_seen.fetch_add(1, Ordering::Relaxed);
                    let host = req
                        .headers()
                        .get("host")
                        .and_then(|value| value.to_str().ok())
                        .expect("host header");
                    let body = format!(
                        "{{\"introspection_endpoint\":\"http://{host}/introspect\"}}"
                    );
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(http::StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from(body)))
                            .expect("discovery response"),
                    )
                }
                "/introspect" => {
                    introspection_requests_seen.fetch_add(1, Ordering::Relaxed);
                    let body = req
                        .into_body()
                        .collect()
                        .await
                        .expect("introspection body")
                        .to_bytes();
                    let encoded = String::from_utf8_lossy(&body);
                    assert!(encoded.contains("token=good-token"));
                    assert!(encoded.contains("client_id=edge-client"));
                    assert!(encoded.contains("audience=api%3A%2F%2Fedge"));
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(http::StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from(
                                r#"{"active":true,"scope":"openid profile read","aud":"api://edge","iss":"https://issuer.example.com"}"#,
                            )))
                            .expect("introspection response"),
                    )
                }
                other => panic!("unexpected auth path: {other}"),
            }
        }
    })
    .await;

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let mut config = make_config(0, cert, key, backend_addr.to_string());
    configure_oidc_external_auth(
        &mut config,
        format!("http://{auth_addr}/.well-known/openid-configuration"),
        250,
        ExternalAuthFailureMode::FailClosed,
    );

    let listener = Http3Service::new(config).expect("listener");
    let (addr, stop, handle) = spawn_listener_loop(listener);
    let response = run_h3_client_request(
        addr,
        "GET",
        "/",
        &[("authorization", "Bearer good-token")],
        None,
    )
    .expect("h3 response");
    let second_response = run_h3_client_request(
        addr,
        "GET",
        "/",
        &[("authorization", "Bearer good-token")],
        None,
    )
    .expect("second h3 response");
    stop_listener_loop(stop, handle);

    assert_eq!(response.status, 200);
    assert_eq!(response.body, "oidc ok");
    assert_eq!(second_response.status, 200);
    assert_eq!(second_response.body, "oidc ok");
    assert_eq!(discovery_requests.load(Ordering::Relaxed), 1);
    assert_eq!(introspection_requests.load(Ordering::Relaxed), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_body_is_buffered_while_auth_is_pending() {
    if !local_listener_bind_available() {
        return;
    }

    let backend_addr = start_h2_backend_service(|req| async move {
        let user = req
            .headers()
            .get("x-user-id")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("missing")
            .to_string();
        let body = req
            .into_body()
            .collect()
            .await
            .expect("backend body")
            .to_bytes();
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!(
            "len={};user={user}",
            body.len()
        )))))
    })
    .await;

    let auth_addr = start_http_auth_server(|_req| async move {
        tokio::time::sleep(Duration::from_millis(40)).await;
        Ok::<_, Infallible>(
            Response::builder()
                .status(http::StatusCode::NO_CONTENT)
                .header("x-user-id", "buffered")
                .body(Full::new(Bytes::new()))
                .expect("auth allow response"),
        )
    })
    .await;

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let mut config = make_config(0, cert, key, backend_addr.to_string());
    configure_http_external_auth(
        &mut config,
        format!("http://{auth_addr}/check"),
        250,
        ExternalAuthFailureMode::FailClosed,
        vec!["x-user-id".to_string()],
    );

    let listener = Http3Service::new(config).expect("listener");
    let (addr, stop, handle) = spawn_listener_loop(listener);
    let response = run_h3_client_request(
        addr,
        "POST",
        "/upload",
        &[("content-length", "20")],
        Some(b"buffered auth body!!"),
    )
    .expect("h3 response");
    stop_listener_loop(stop, handle);

    assert_eq!(response.status, 200);
    assert_eq!(response.body, "len=20;user=buffered");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_disconnect_during_pending_auth_leaves_no_connection_state() {
    if !local_listener_bind_available() {
        return;
    }

    let auth_seen = Arc::new(AtomicBool::new(false));
    let auth_seen_flag = Arc::clone(&auth_seen);
    let backend_addr = start_h2_backend("should not reach backend").await;
    let auth_addr = start_http_auth_server(move |_req| {
        let auth_seen_flag = Arc::clone(&auth_seen_flag);
        async move {
            auth_seen_flag.store(true, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(200)).await;
            Ok::<_, Infallible>(
                Response::builder()
                    .status(http::StatusCode::NO_CONTENT)
                    .body(Full::new(Bytes::new()))
                    .expect("auth allow response"),
            )
        }
    })
    .await;

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let mut config = make_config(0, cert, key, backend_addr.to_string());
    configure_http_external_auth(
        &mut config,
        format!("http://{auth_addr}/check"),
        500,
        ExternalAuthFailureMode::FailClosed,
        vec![],
    );

    let mut listener = Http3Service::new(config).expect("listener");
    let server_addr = listener.socket.local_addr().expect("listener addr");
    let client = thread::spawn(move || {
        send_h3_request_and_close(server_addr, "GET", "/", &[])
            .unwrap_or_else(|err| panic!("client request failed: {err}"));
    });

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        listener.poll();
        if auth_seen.load(Ordering::Relaxed)
            && listener.connections().is_empty()
            && listener.cid_routes().is_empty()
            && listener.peer_routes().is_empty()
        {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    client.join().expect("client join");
    assert!(
        auth_seen.load(Ordering::Relaxed),
        "auth request was never started"
    );
    assert!(
        listener.connections().is_empty(),
        "connections leaked after client disconnect"
    );
    assert!(
        listener.cid_routes().is_empty(),
        "cid routes leaked after client disconnect"
    );
    assert!(
        listener.peer_routes().is_empty(),
        "peer routes leaked after client disconnect"
    );
}

#[derive(Debug)]
struct AuthLoopBenchmarkSummary {
    label: &'static str,
    request_count: usize,
    wall: Duration,
    cpu_micros: u64,
    poll_report: ListenerLoopReport,
    latencies: Vec<Duration>,
}

impl AuthLoopBenchmarkSummary {
    fn avg_latency(&self) -> Duration {
        Duration::from_micros(
            (self
                .latencies
                .iter()
                .map(|latency| latency.as_micros() as u64)
                .sum::<u64>()
                / self.request_count.max(1) as u64)
                .max(1),
        )
    }

    fn percentile_latency(&self, percentile: f64) -> Duration {
        let mut samples = self.latencies.clone();
        samples.sort_unstable();
        let capped = percentile.clamp(0.0, 100.0);
        let idx = (((samples.len().saturating_sub(1)) as f64) * (capped / 100.0)).round() as usize;
        samples[idx.min(samples.len().saturating_sub(1))]
    }

    fn cpu_per_request_micros(&self) -> u64 {
        (self.cpu_micros / self.request_count.max(1) as u64).max(1)
    }

    fn polls_per_request(&self) -> u64 {
        (self.poll_report.poll_count / self.request_count.max(1) as u64).max(1)
    }
}

#[cfg(unix)]
fn process_cpu_micros() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if rc != 0 {
        return 0;
    }
    let usage = unsafe { usage.assume_init() };
    let user = (usage.ru_utime.tv_sec as u64)
        .saturating_mul(1_000_000)
        .saturating_add(usage.ru_utime.tv_usec as u64);
    let sys = (usage.ru_stime.tv_sec as u64)
        .saturating_mul(1_000_000)
        .saturating_add(usage.ru_stime.tv_usec as u64);
    user.saturating_add(sys)
}

#[cfg(not(unix))]
fn process_cpu_micros() -> u64 {
    0
}

async fn run_auth_loop_benchmark(
    label: &'static str,
    auth_enabled: bool,
    request_count: usize,
) -> AuthLoopBenchmarkSummary {
    const IDLE_TIMEOUT_MS: u64 = 180;

    let backend_addr = start_h2_backend("benchmark backend").await;
    let auth_addr = if auth_enabled {
        Some(
            start_http_auth_server(|_req| async move {
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(http::StatusCode::NO_CONTENT)
                        .body(Full::new(Bytes::new()))
                        .expect("auth allow response"),
                )
            })
            .await,
        )
    } else {
        None
    };

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let mut config = make_config(0, cert, key, backend_addr.to_string());
    config.performance.quic_max_idle_timeout_ms = IDLE_TIMEOUT_MS;
    config.performance.new_connections_per_sec = 10_000;
    config.performance.new_connections_burst = 1_000;
    if let Some(auth_addr) = auth_addr {
        configure_http_external_auth(
            &mut config,
            format!("http://{auth_addr}/check"),
            250,
            ExternalAuthFailureMode::FailClosed,
            vec![],
        );
    }

    let listener = Http3Service::new(config).expect("listener");
    let (addr, stop, handle, report_rx) = spawn_listener_loop_with_report(listener);

    let warmup = run_h3_client_request(addr, "GET", "/", &[], None).expect("warmup response");
    assert_eq!(warmup.status, 200);
    assert_eq!(warmup.body, "benchmark backend");

    let cpu_start = process_cpu_micros();
    let wall_start = Instant::now();
    let mut latencies = Vec::with_capacity(request_count);
    for _ in 0..request_count {
        let req_start = Instant::now();
        let response =
            run_h3_client_request(addr, "GET", "/", &[], None).expect("benchmark response");
        latencies.push(req_start.elapsed());
        assert_eq!(response.status, 200);
        assert_eq!(response.body, "benchmark backend");
    }
    let wall = wall_start.elapsed();
    let cpu_micros = process_cpu_micros().saturating_sub(cpu_start);

    tokio::time::sleep(Duration::from_millis(IDLE_TIMEOUT_MS * 2)).await;
    let poll_report = stop_listener_loop_with_report(stop, handle, report_rx);

    AuthLoopBenchmarkSummary {
        label,
        request_count,
        wall,
        cpu_micros,
        poll_report,
        latencies,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "manual perf benchmark"]
async fn auth_allow_path_latency_smoke_does_not_explode_vs_disabled() {
    if !local_listener_bind_available() {
        return;
    }

    let disabled = run_auth_loop_benchmark("auth_disabled", false, 20).await;
    let enabled = run_auth_loop_benchmark("auth_enabled", true, 20).await;

    eprintln!(
        "{}: requests={} wall={:?} avg={:?} p95={:?} cpu_us={} cpu_per_req_us={} polls={} polls_per_req={} teardown=({},{},{})",
        disabled.label,
        disabled.request_count,
        disabled.wall,
        disabled.avg_latency(),
        disabled.percentile_latency(95.0),
        disabled.cpu_micros,
        disabled.cpu_per_request_micros(),
        disabled.poll_report.poll_count,
        disabled.polls_per_request(),
        disabled.poll_report.remaining_connections,
        disabled.poll_report.remaining_cid_routes,
        disabled.poll_report.remaining_peer_routes,
    );
    eprintln!(
        "{}: requests={} wall={:?} avg={:?} p95={:?} cpu_us={} cpu_per_req_us={} polls={} polls_per_req={} teardown=({},{},{})",
        enabled.label,
        enabled.request_count,
        enabled.wall,
        enabled.avg_latency(),
        enabled.percentile_latency(95.0),
        enabled.cpu_micros,
        enabled.cpu_per_request_micros(),
        enabled.poll_report.poll_count,
        enabled.polls_per_request(),
        enabled.poll_report.remaining_connections,
        enabled.poll_report.remaining_cid_routes,
        enabled.poll_report.remaining_peer_routes,
    );

    for summary in [&disabled, &enabled] {
        assert_eq!(
            summary.poll_report.remaining_connections, 0,
            "{} leaked connections",
            summary.label
        );
        assert_eq!(
            summary.poll_report.remaining_cid_routes, 0,
            "{} leaked cid routes",
            summary.label
        );
        assert_eq!(
            summary.poll_report.remaining_peer_routes, 0,
            "{} leaked peer routes",
            summary.label
        );
        assert!(
            summary.poll_report.poll_count > 0,
            "{} made no loop progress",
            summary.label
        );
    }

    let latency_limit = disabled.percentile_latency(95.0) * 12 + Duration::from_millis(75);
    assert!(
        enabled.percentile_latency(95.0) <= latency_limit,
        "auth-enabled p95 latency regressed too far: disabled={:?} enabled={:?} limit={:?}",
        disabled.percentile_latency(95.0),
        enabled.percentile_latency(95.0),
        latency_limit,
    );

    let cpu_limit = disabled
        .cpu_per_request_micros()
        .saturating_mul(25)
        .max(50_000);
    assert!(
        enabled.cpu_per_request_micros() <= cpu_limit,
        "auth-enabled CPU per request regressed too far: disabled={} enabled={} limit={}",
        disabled.cpu_per_request_micros(),
        enabled.cpu_per_request_micros(),
        cpu_limit,
    );

    let poll_limit = disabled.polls_per_request().saturating_mul(25).max(400);
    assert!(
        enabled.polls_per_request() <= poll_limit,
        "auth-enabled poll-loop work regressed too far: disabled={} enabled={} limit={}",
        disabled.polls_per_request(),
        enabled.polls_per_request(),
        poll_limit,
    );
}
