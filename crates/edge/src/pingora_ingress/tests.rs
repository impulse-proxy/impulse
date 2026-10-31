use std::{
    collections::HashMap,
    io::Write,
    net::{SocketAddr, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use http_body_util::BodyExt;
use impulse_config::{
    config::{ApiKeyAuth, Config, ResponseCache, ResponseCompression, RouteAuth},
    runtime::{ListenerRuntimeConfig, RuntimeConfig},
    validator::validate,
};
use impulse_pingora_ingress::ConnectionAdmission;
use pingora_core::{server::configuration::ServerConf, services::Service as PingoraService};

use super::{
    PingoraConnectionAdmissionState, PingoraListenerTask, PingoraRuntimeConnectionAdmission,
    pingora_ingress_services, spawn_pingora_ingress_listener,
};
use crate::runtime::{
    bundle::RuntimeBundleHandle,
    connection::{PerSourceTokenBucket, TokenBucket},
    listener::QUICListener,
};

#[path = "../../tests/support/mod.rs"]
mod support;

use support::{
    net::local_listener_bind_available,
    parity::{
        ParityRequestSpec, ParityResponseSnapshot, ProtocolParityHarness, make_backend,
        make_upstream,
    },
    request_path::{HttpRequestSpec, reserve_unused_listener_port, run_http2_request_to},
};

struct PingoraTestService {
    shutdown: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    runtime_bundle: RuntimeBundleHandle,
    _runtime: tokio::runtime::Runtime,
}

impl PingoraTestService {
    fn start(config: impulse_config::config::Config) -> Result<(Self, SocketAddr), String> {
        validate(&config).map_err(|error| format!("config validation failed: {error}"))?;
        let runtime_config = RuntimeConfig::from_config(&config)
            .map_err(|error| format!("runtime config: {error}"))?;
        let bundle = QUICListener::build_runtime_bundle(
            "pingora-parity-test".to_string(),
            config.log.clone(),
            &runtime_config,
        )
        .map_err(|error| format!("runtime bundle: {error}"))?;
        let runtime_bundle = RuntimeBundleHandle::new(bundle);
        let mut services =
            pingora_ingress_services(&Arc::new(ServerConf::default()), runtime_bundle.clone())
                .map_err(|error| format!("Pingora ingress service: {error}"))?;
        let mut service = services
            .pop()
            .ok_or_else(|| "Pingora ingress did not create a service".to_string())?;
        let addr = SocketAddr::from(([127, 0, 0, 1], config.listen.port));
        let (shutdown, shutdown_watch) = tokio::sync::watch::channel(false);
        let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
        let task = runtime.spawn(async move {
            #[cfg(unix)]
            service.start_service(None, shutdown_watch, 1).await;
            #[cfg(not(unix))]
            service.start_service(shutdown_watch, 1).await;
        });

        for _ in 0..50 {
            if TcpStream::connect_timeout(&addr, Duration::from_millis(20)).is_ok() {
                return Ok((
                    Self {
                        shutdown,
                        task,
                        runtime_bundle,
                        _runtime: runtime,
                    },
                    addr,
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        task.abort();
        Err(format!("Pingora ingress did not listen on {addr}"))
    }

    fn metrics_text(&self) -> String {
        self.runtime_bundle
            .current()
            .shared_state
            .shared_services()
            .metrics
            .render_prometheus()
    }
}

impl Drop for PingoraTestService {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        self.task.abort();
    }
}

fn pingora_listener_runtime(config: Config) -> (Arc<RuntimeBundleHandle>, ListenerRuntimeConfig) {
    validate(&config).expect("validate Pingora listener config");
    let runtime_config = RuntimeConfig::from_config(&config).expect("build runtime config");
    let listener = runtime_config
        .primary_listener_runtime_config()
        .expect("primary listener config");
    let bundle = QUICListener::build_runtime_bundle(
        "pingora-listener-lifecycle-test".to_string(),
        config.log,
        &runtime_config,
    )
    .expect("build runtime bundle");
    (Arc::new(RuntimeBundleHandle::new(bundle)), listener)
}

async fn stop_pingora_listener(task: &mut PingoraListenerTask) {
    task.request_shutdown();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(result) = task.collect_finished().await {
                result.expect("Pingora listener shutdown");
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Pingora listener shutdown timeout");
    assert!(task.stopped());
}

fn connection_admission_config(
    harness: &ProtocolParityHarness,
    rate_per_sec: u32,
    burst: u32,
) -> Config {
    let mut config = harness.make_config(HashMap::from([(
        "api".to_string(),
        make_upstream(
            "/",
            vec![make_backend("backend-a", "127.0.0.1:9".to_string())],
            None,
            "round-robin",
        ),
    )]));
    config.listen.port = reserve_unused_listener_port();
    config.performance.new_connections_per_sec = rate_per_sec;
    config.performance.new_connections_burst = burst;
    config
}

fn test_connection_filter(
    runtime: &Arc<RuntimeBundleHandle>,
    listener: &ListenerRuntimeConfig,
) -> PingoraRuntimeConnectionAdmission {
    let policy = &listener.policies.transport;
    PingoraRuntimeConnectionAdmission {
        runtime: runtime.as_ref().clone(),
        listener_label: format!(
            "{}:{}",
            listener.listen.listen.address, listener.listen.listen.port
        ),
        state: Mutex::new(PingoraConnectionAdmissionState {
            generation: runtime.current().generation,
            rate_per_sec: policy.new_connections_per_sec,
            burst: policy.new_connections_burst,
            global: TokenBucket::new(policy.new_connections_per_sec, policy.new_connections_burst),
        }),
        per_source: PerSourceTokenBucket::new(
            policy.new_connections_per_sec,
            policy.new_connections_burst,
        ),
    }
}

#[test]
fn pingora_connection_filter_matches_http3_global_and_per_source_admission() {
    let harness = ProtocolParityHarness::new();
    let config = connection_admission_config(&harness, 1, 20);
    let (runtime, listener) = pingora_listener_runtime(config);
    let filter = test_connection_filter(&runtime, &listener);
    let mut quic_global = TokenBucket::new(1, 20);
    let quic_per_source = PerSourceTokenBucket::new(1, 20);
    let sources = [
        "192.0.2.1:1000".parse::<SocketAddr>().unwrap(),
        "192.0.2.1:1001".parse::<SocketAddr>().unwrap(),
        "192.0.2.1:1002".parse::<SocketAddr>().unwrap(),
        "192.0.2.2:1000".parse::<SocketAddr>().unwrap(),
        "192.0.2.2:1001".parse::<SocketAddr>().unwrap(),
        "192.0.2.2:1002".parse::<SocketAddr>().unwrap(),
    ];
    let test_runtime = tokio::runtime::Runtime::new().expect("test runtime");

    for source in sources {
        let pingora_allowed = test_runtime.block_on(filter.should_accept(Some(&source)));
        let http3_allowed = quic_global.try_consume() && quic_per_source.try_consume(source.ip());
        assert_eq!(pingora_allowed, http3_allowed, "source {source}");
    }

    let global_config = connection_admission_config(&harness, 1, 2);
    let (global_runtime, global_listener) = pingora_listener_runtime(global_config);
    let global_filter = test_connection_filter(&global_runtime, &global_listener);
    assert!(test_runtime.block_on(global_filter.should_accept(None)));
    assert!(test_runtime.block_on(global_filter.should_accept(None)));
    assert!(!test_runtime.block_on(global_filter.should_accept(None)));
}

#[test]
fn pingora_connection_filter_applies_reloaded_generation_limits() {
    let harness = ProtocolParityHarness::new();
    let config = connection_admission_config(&harness, 1, 5);
    let (runtime, listener) = pingora_listener_runtime(config.clone());
    let filter = test_connection_filter(&runtime, &listener);
    let test_runtime = tokio::runtime::Runtime::new().expect("test runtime");
    assert!(test_runtime.block_on(filter.should_accept(None)));

    let mut reloaded = config;
    reloaded.performance.new_connections_burst = 2;
    let runtime_config = RuntimeConfig::from_config(&reloaded).expect("reload runtime config");
    let mut bundle = QUICListener::build_runtime_bundle(
        "pingora-connection-admission-reload-test".to_string(),
        reloaded.log,
        &runtime_config,
    )
    .expect("reload runtime bundle");
    bundle.generation = runtime.current().generation + 1;
    runtime
        .replace(bundle)
        .expect("activate reloaded generation");

    assert!(test_runtime.block_on(filter.should_accept(None)));
    assert!(test_runtime.block_on(filter.should_accept(None)));
    assert!(!test_runtime.block_on(filter.should_accept(None)));
}

#[test]
fn pingora_connection_filter_rejects_before_tls_negotiation() {
    if !local_listener_bind_available() {
        return;
    }

    let harness = ProtocolParityHarness::new();
    let config = connection_admission_config(&harness, 1, 1);
    let (service, addr) = PingoraTestService::start(config).expect("start Pingora ingress");
    let before = service.metrics_text();
    let _connections = (0..3)
        .map(|_| {
            let mut connection = TcpStream::connect_timeout(&addr, Duration::from_millis(500))
                .expect("connect to Pingora listener");
            connection
                .set_read_timeout(Some(Duration::from_millis(500)))
                .expect("set read timeout");
            let _ = connection.write_all(b"not a TLS client hello");
            connection
        })
        .collect::<Vec<_>>();
    let mut rejected = 0;
    for _ in 0..50 {
        rejected = metric_delta(
            &before,
            &service.metrics_text(),
            "impulse_ingress_rate_limited_total ",
        );
        if rejected > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        rejected >= 1,
        "at least one TCP connection must be rejected by the pre-TLS filter"
    );
}

#[test]
fn pingora_listener_activation_replacement_rollback_drain_and_shutdown() {
    if !local_listener_bind_available() {
        return;
    }

    let harness = ProtocolParityHarness::new();
    let mut config = harness.make_config(HashMap::from([(
        "api".to_string(),
        make_upstream(
            "/",
            vec![make_backend("backend-a", "127.0.0.1:9".to_string())],
            None,
            "round-robin",
        ),
    )]));
    config.listen.port = reserve_unused_listener_port();
    let active_addr = SocketAddr::from(([127, 0, 0, 1], config.listen.port));
    let (runtime, active_config) = pingora_listener_runtime(config);
    let mut replacement_config = active_config.clone();
    replacement_config.listen.listen.port = reserve_unused_listener_port();
    let replacement_addr =
        SocketAddr::from(([127, 0, 0, 1], replacement_config.listen.listen.port));

    tokio::runtime::Runtime::new()
        .expect("test runtime")
        .block_on(async {
            let mut active =
                spawn_pingora_ingress_listener(Arc::clone(&runtime), active_config.clone())
                    .expect("activate Pingora listener");
            active
                .wait_until_ready()
                .await
                .expect("active listener ready");

            let mut replacement =
                spawn_pingora_ingress_listener(Arc::clone(&runtime), replacement_config.clone())
                    .expect("activate replacement listener");
            replacement
                .wait_until_ready()
                .await
                .expect("replacement listener ready");
            assert!(TcpStream::connect_timeout(&active_addr, Duration::from_millis(100)).is_ok());
            assert!(
                TcpStream::connect_timeout(&replacement_addr, Duration::from_millis(100)).is_ok()
            );

            assert_eq!(
                active
                    .drain(Duration::from_secs(5))
                    .await
                    .expect("drain replaced listener"),
                0
            );
            assert!(
                TcpStream::connect_timeout(&replacement_addr, Duration::from_millis(100)).is_ok()
            );

            let mut invalid_candidate = active_config.clone();
            invalid_candidate.listen.tls.default_identity.cert_path =
                "/missing/pingora-listener-cert.pem".to_string();
            assert!(
                spawn_pingora_ingress_listener(Arc::clone(&runtime), invalid_candidate).is_err()
            );
            assert!(
                TcpStream::connect_timeout(&replacement_addr, Duration::from_millis(100)).is_ok(),
                "failed activation must leave the replacement listener active"
            );

            let mut rollback = spawn_pingora_ingress_listener(Arc::clone(&runtime), active_config)
                .expect("restore rollback listener");
            rollback
                .wait_until_ready()
                .await
                .expect("rollback listener ready");
            assert_eq!(
                replacement
                    .drain(Duration::from_secs(5))
                    .await
                    .expect("drain replacement listener"),
                0
            );
            assert!(TcpStream::connect_timeout(&active_addr, Duration::from_millis(100)).is_ok());

            stop_pingora_listener(&mut rollback).await;
            std::net::TcpListener::bind(active_addr).expect("shutdown releases listener bind");
        });
}

#[test]
fn pingora_and_http3_share_request_contracts() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = ProtocolParityHarness::new();
    let backend_addr = harness.start_h1_backend(|request| async move {
        let body = request
            .into_body()
            .collect()
            .await
            .expect("collect backend request body")
            .to_bytes();
        let body = if body.is_empty() {
            bytes::Bytes::from_static(b"parity ok\n")
        } else {
            body
        };
        Ok::<_, std::convert::Infallible>(
            hyper::Response::builder()
                .status(200)
                .header("x-parity", "ok")
                .body(http_body_util::Full::new(body))
                .expect("backend response"),
        )
    });

    let mut upstream = make_upstream(
        "/api",
        vec![make_backend("backend-a", backend_addr.to_string())],
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
    let config = harness.make_config(HashMap::from([("api".to_string(), upstream)]));
    let mut pingora_config = config.clone();
    pingora_config.listen.port = reserve_unused_listener_port();
    let (_pingora, pingora_addr) =
        PingoraTestService::start(pingora_config).expect("start Pingora ingress");
    harness
        .start_listener(config)
        .expect("start HTTP/3 ingress");

    assert_protocol_parity(
        &harness,
        pingora_addr,
        ParityRequestSpec {
            method: "GET",
            authority: "localhost",
            path: "/api",
            headers: &[],
            body: None,
            user_agent: "impulse-pingora-parity-test",
            selected_response_headers: &["www-authenticate"],
        },
    );
    assert_protocol_parity(
        &harness,
        pingora_addr,
        ParityRequestSpec {
            method: "POST",
            authority: "localhost",
            path: "/api/items",
            headers: &[("x-api-key", "edge-key")],
            body: Some(b"streamed request body"),
            user_agent: "impulse-pingora-parity-test",
            selected_response_headers: &["x-parity"],
        },
    );
    assert_protocol_parity(
        &harness,
        pingora_addr,
        ParityRequestSpec {
            method: "GET",
            authority: "localhost",
            path: "/missing",
            headers: &[],
            body: None,
            user_agent: "impulse-pingora-parity-test",
            selected_response_headers: &[],
        },
    );
}

#[test]
fn pingora_and_http3_match_response_compression_contracts() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = ProtocolParityHarness::new();
    let backend_addr = harness.start_h1_backend(|request| async move {
        let (status, body, content_encoding) = match request.uri().path() {
            "/bodyless" => (http::StatusCode::NO_CONTENT, bytes::Bytes::new(), None),
            "/preencoded" => (
                http::StatusCode::OK,
                bytes::Bytes::from_static(b"already encoded"),
                Some("gzip"),
            ),
            "/too-large" => (
                http::StatusCode::OK,
                bytes::Bytes::from(vec![b'a'; 256]),
                None,
            ),
            _ => (
                http::StatusCode::OK,
                bytes::Bytes::from(vec![b'a'; 96]),
                None,
            ),
        };
        let mut response = hyper::Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, "text/plain")
            .header(http::header::CONTENT_LENGTH, body.len().to_string());
        if let Some(content_encoding) = content_encoding {
            response = response.header(http::header::CONTENT_ENCODING, content_encoding);
        }
        Ok::<_, std::convert::Infallible>(
            response
                .body(http_body_util::Full::new(body))
                .expect("backend response"),
        )
    });

    let mut upstream = make_upstream(
        "/",
        vec![make_backend("backend-a", backend_addr.to_string())],
        None,
        "round-robin",
    );
    upstream.compression = ResponseCompression {
        enabled: true,
        minimum_size_bytes: 1,
    };
    let mut config = harness.make_config(HashMap::from([("api".to_string(), upstream)]));
    config.performance.max_response_body_bytes = 128;
    config.performance.unknown_length_response_prebuffer_bytes = 128;
    let mut pingora_config = config.clone();
    pingora_config.listen.port = reserve_unused_listener_port();
    let (_pingora, pingora_addr) =
        PingoraTestService::start(pingora_config).expect("start Pingora ingress");
    harness
        .start_listener(config)
        .expect("start HTTP/3 ingress");

    let compression_headers = &["content-encoding", "vary"];
    let gzip_headers = &["content-encoding", "content-length", "vary"];
    let (pingora, http3) = protocol_pair(
        &harness,
        pingora_addr,
        ParityRequestSpec {
            method: "GET",
            authority: "localhost",
            path: "/compress",
            headers: &[("accept-encoding", "gzip")],
            body: None,
            user_agent: "impulse-compression-parity-test",
            selected_response_headers: gzip_headers,
        },
    );
    assert_eq!(pingora, http3);
    assert_eq!(selected_header(&pingora, "content-encoding"), Some("gzip"));
    assert!(
        selected_header(&pingora, "vary")
            .is_some_and(|value| value.eq_ignore_ascii_case("accept-encoding"))
    );
    assert_eq!(selected_header(&pingora, "content-length"), None);
    assert_ne!(pingora.body, vec![b'a'; 96]);

    for (method, path, headers) in [
        ("GET", "/compress", &[("accept-encoding", "identity")][..]),
        (
            "GET",
            "/compress",
            &[("accept-encoding", "gzip"), ("range", "bytes=0-15")][..],
        ),
        ("HEAD", "/compress", &[("accept-encoding", "gzip")][..]),
        ("GET", "/bodyless", &[("accept-encoding", "gzip")][..]),
    ] {
        let (pingora, http3) = protocol_pair(
            &harness,
            pingora_addr,
            ParityRequestSpec {
                method,
                authority: "localhost",
                path,
                headers,
                body: None,
                user_agent: "impulse-compression-parity-test",
                selected_response_headers: compression_headers,
            },
        );
        assert_eq!(pingora, http3, "{method} {path}");
        assert_eq!(
            selected_header(&pingora, "content-encoding"),
            None,
            "{method} {path} must bypass compression"
        );
        if method == "HEAD" || path == "/bodyless" {
            assert!(pingora.body.is_empty(), "{method} {path} must be bodyless");
        }
    }

    let (pingora, http3) = protocol_pair(
        &harness,
        pingora_addr,
        ParityRequestSpec {
            method: "GET",
            authority: "localhost",
            path: "/preencoded",
            headers: &[("accept-encoding", "gzip")],
            body: None,
            user_agent: "impulse-compression-parity-test",
            selected_response_headers: compression_headers,
        },
    );
    assert_eq!(pingora, http3);
    assert_eq!(selected_header(&pingora, "content-encoding"), Some("gzip"));
    assert_eq!(pingora.body, b"already encoded".to_vec());

    let (pingora, http3) = protocol_pair(
        &harness,
        pingora_addr,
        ParityRequestSpec {
            method: "GET",
            authority: "localhost",
            path: "/too-large",
            headers: &[("accept-encoding", "gzip")],
            body: None,
            user_agent: "impulse-compression-parity-test",
            selected_response_headers: compression_headers,
        },
    );
    assert_eq!(pingora, http3);
    assert_eq!(
        pingora.status,
        http::StatusCode::SERVICE_UNAVAILABLE.as_u16()
    );
}

#[test]
fn pingora_and_http3_share_bounded_response_cache_behavior() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = ProtocolParityHarness::new();
    let backend_requests = Arc::new(AtomicUsize::new(0));
    let observed_requests = Arc::clone(&backend_requests);
    let backend_addr = harness.start_h1_backend(move |_request| {
        let observed_requests = Arc::clone(&observed_requests);
        async move {
            observed_requests.fetch_add(1, Ordering::Relaxed);
            Ok::<_, std::convert::Infallible>(
                hyper::Response::builder()
                    .status(200)
                    .header(http::header::CACHE_CONTROL, "public, max-age=60")
                    .body(http_body_util::Full::new(bytes::Bytes::from_static(
                        b"cached response\n",
                    )))
                    .expect("cacheable backend response"),
            )
        }
    });
    let mut upstream = make_upstream(
        "/cache",
        vec![make_backend("backend-a", backend_addr.to_string())],
        None,
        "round-robin",
    );
    upstream.cache = ResponseCache {
        enabled: true,
        max_bytes: 4096,
        max_entries: 4,
        max_object_bytes: 1024,
        max_ttl_secs: 60,
    };
    let config = harness.make_config(HashMap::from([("cache".to_string(), upstream)]));
    let mut pingora_config = config.clone();
    pingora_config.listen.port = reserve_unused_listener_port();
    let (pingora_service, pingora_addr) =
        PingoraTestService::start(pingora_config).expect("start Pingora cache ingress");
    harness
        .start_listener(config)
        .expect("start HTTP/3 cache ingress");

    let request = ParityRequestSpec::get("localhost", "/cache/object");
    let first = protocol_pair(&harness, pingora_addr, request);
    assert_eq!(first.0, first.1);
    assert_eq!(backend_requests.load(Ordering::Relaxed), 2);

    let second = protocol_pair(&harness, pingora_addr, request);
    assert_eq!(second, first);
    assert_eq!(
        backend_requests.load(Ordering::Relaxed),
        2,
        "each ingress must serve its second request from the shared cache contract"
    );
    assert!(
        pingora_service
            .metrics_text()
            .contains("impulse_response_cache_outcomes_total{outcome=\"hit\"} 1\n")
    );
    let http3_metrics = harness.metrics_text().expect("HTTP/3 cache metrics");
    assert!(http3_metrics.contains("impulse_response_cache_outcomes_total{outcome=\"hit\"} 1\n"));
}

#[test]
fn pingora_and_http3_use_published_discovery_membership() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = ProtocolParityHarness::new();
    let backend_addr = harness.start_h1_static_backend(b"discovered backend\n");
    let backend_host = "backend.final-runtime.test";
    let configured_address = format!("http://{backend_host}:{}", backend_addr.port());
    let config = harness.make_config(HashMap::from([(
        "api".to_string(),
        make_upstream(
            "/",
            vec![make_backend("discovered", configured_address.clone())],
            None,
            "round-robin",
        ),
    )]));
    let mut pingora_config = config.clone();
    pingora_config.listen.port = reserve_unused_listener_port();
    let (pingora, pingora_addr) =
        PingoraTestService::start(pingora_config).expect("start Pingora discovery ingress");
    harness
        .start_listener(config)
        .expect("start HTTP/3 discovery ingress");

    let pingora_generation = pingora.runtime_bundle.current();
    let pingora_discovery = (
        pingora_generation
            .shared_state
            .shared_services()
            .backend_dns_resolver
            .clone(),
        Arc::clone(
            &pingora_generation
                .shared_state
                .generation_state()
                .pingora_load_balancing,
        ),
    );
    let http3_discovery = harness
        .discovery_runtime()
        .expect("HTTP/3 discovery runtime");
    for (backend_dns_resolver, pingora_load_balancing) in [pingora_discovery, http3_discovery] {
        backend_dns_resolver.set_host_addrs(backend_host, [SocketAddr::new(backend_addr.ip(), 0)]);
        pingora
            ._runtime
            .block_on(
                pingora_load_balancing
                    .publish_dns_result(&configured_address, Ok(vec![backend_addr])),
            )
            .expect("publish discovered backend membership");
    }

    assert_protocol_parity(
        &harness,
        pingora_addr,
        ParityRequestSpec::get("localhost", "/discovered"),
    );
}

fn metric_delta(before: &str, after: &str, prefix: &str) -> u64 {
    fn counter(metrics: &str, prefix: &str) -> u64 {
        metrics
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or_else(|| panic!("missing metrics counter `{prefix}`"))
    }

    counter(after, prefix).saturating_sub(counter(before, prefix))
}

fn selected_header<'a>(response: &'a ParityResponseSnapshot, name: &str) -> Option<&'a str> {
    response
        .selected_headers
        .iter()
        .find_map(|(header, value)| header.eq_ignore_ascii_case(name).then_some(value.as_str()))
}

fn assert_protocol_parity(
    harness: &ProtocolParityHarness,
    pingora_addr: SocketAddr,
    request: ParityRequestSpec<'_>,
) {
    let (pingora, quic) = protocol_pair(harness, pingora_addr, request);
    assert_eq!(pingora, quic);
}

fn protocol_pair(
    harness: &ProtocolParityHarness,
    pingora_addr: SocketAddr,
    request: ParityRequestSpec<'_>,
) -> (ParityResponseSnapshot, ParityResponseSnapshot) {
    let quic = harness.run_quic(request).expect("HTTP/3 parity response");
    let pingora = run_http2_request_to(
        pingora_addr,
        harness.cert_path(),
        HttpRequestSpec {
            method: request.method,
            authority: request.authority,
            path: request.path,
            headers: request.headers,
            body: request.body,
            user_agent: request.user_agent,
        },
    )
    .map(|response| snapshot(response, request.selected_response_headers))
    .expect("Pingora parity response");

    (pingora, quic.response)
}

fn snapshot(
    response: support::request_path::HttpResponse,
    selected_response_headers: &[&str],
) -> ParityResponseSnapshot {
    let mut selected_headers = response
        .headers
        .into_iter()
        .filter(|(name, _)| {
            selected_response_headers
                .iter()
                .any(|selected| name.eq_ignore_ascii_case(selected))
        })
        .collect::<Vec<_>>();
    selected_headers.sort_by(|left, right| {
        left.0
            .to_ascii_lowercase()
            .cmp(&right.0.to_ascii_lowercase())
            .then_with(|| left.1.cmp(&right.1))
    });
    let mut trailers = response.trailers;
    trailers.sort();

    ParityResponseSnapshot {
        status: response.status,
        body: response.body,
        selected_headers,
        trailers,
    }
}
