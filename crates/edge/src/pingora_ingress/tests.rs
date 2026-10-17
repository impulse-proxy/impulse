use std::{
    collections::HashMap,
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
};

use http_body_util::BodyExt;
use impulse_config::{
    config::{ApiKeyAuth, Config, RouteAuth},
    runtime::{ListenerRuntimeConfig, RuntimeConfig},
    validator::validate,
};
use pingora_core::{server::configuration::ServerConf, services::Service as PingoraService};

use super::{PingoraListenerTask, pingora_ingress_services, spawn_pingora_ingress_listener};
use crate::runtime::{bundle::RuntimeBundleHandle, listener::QUICListener};

#[path = "../../tests/support/mod.rs"]
mod support;

use support::{
    net::local_listener_bind_available,
    parity::{
        BootstrapQuicParityHarness, ParityRequestSpec, ParityResponseSnapshot, make_backend,
        make_upstream,
    },
    request_path::{BootstrapRequestSpec, reserve_unused_listener_port, run_bootstrap_request_to},
};

struct PingoraTestService {
    shutdown: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
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
        let mut services = pingora_ingress_services(
            &Arc::new(ServerConf::default()),
            RuntimeBundleHandle::new(bundle),
        )
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

#[test]
fn pingora_listener_activation_replacement_rollback_drain_and_shutdown() {
    if !local_listener_bind_available() {
        return;
    }

    let harness = BootstrapQuicParityHarness::new();
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
fn pingora_bootstrap_and_http3_share_request_contracts() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
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
        .expect("start bootstrap and HTTP/3 ingress");

    assert_three_way_parity(
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
            capture_metrics_delta: false,
        },
    );
    assert_three_way_parity(
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
            capture_metrics_delta: false,
        },
    );
    assert_three_way_parity(
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
            capture_metrics_delta: false,
        },
    );
}

fn assert_three_way_parity(
    harness: &BootstrapQuicParityHarness,
    pingora_addr: SocketAddr,
    request: ParityRequestSpec<'_>,
) {
    let existing = harness
        .run_parity_pair(request)
        .expect("bootstrap and HTTP/3 parity responses");
    let pingora = run_bootstrap_request_to(
        pingora_addr,
        harness.cert_path(),
        BootstrapRequestSpec {
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

    assert_eq!(existing.bootstrap.response, existing.quic.response);
    assert_eq!(pingora, existing.bootstrap.response);
}

fn snapshot(
    response: support::request_path::BootstrapResponse,
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
