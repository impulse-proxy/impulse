use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::Path,
    sync::{Arc, RwLock, atomic::Ordering},
    time::Duration,
};

use http::{HeaderMap, HeaderValue, StatusCode};
use impulse_config::{
    config::{
        Backend, ClientAuth, Config as ImpulseConfigConfig, Listen, LoadBalancing, Log,
        Observability, Performance, Resilience, RouteMatch, Security, Tls, TlsCertificate,
        Upstream, UpstreamTls,
    },
    runtime::{ListenerRuntimeConfig, RuntimeConfig},
};
use impulse_errors::{
    UpstreamErrorCategory, UpstreamErrorClassification, UpstreamTlsReason,
    classify_upstream_error_detail,
};
use rcgen::{Certificate, CertificateParams, SanType};
use tempfile::tempdir;

use super::{
    ConnectionRoutes, TokenBucket, can_poll_upstream_result, classify_active_health_check_response,
    collect_h3_trailers, connection_header_tokens, is_bodyless_request_mode,
    is_connect_tunnel_response, purge_connection_routes, resolve_primary_from_radix_prefix,
    should_strip_bootstrap_request_header, should_strip_bootstrap_response_header,
    should_strip_h3_response_header, sweep_closed_connections,
};
use crate::{
    REQUEST_ID_COUNTER,
    cid_radix::CidRadix,
    quic_listener::forwarding::terminalize_stream,
    runtime::connection::{
        guardrails::{
            BodyLimitKind, ResponseBodyGuardrailConfig, ResponseBodyGuardrailDecision,
            ResponseBodyGuardrailInput, checked_response_body_guardrails,
        },
        request::{PendingForward, RequestEnvelope},
        stream::{
            AdmissionPermits, AwaitingAuthState, BackendFailureReason, CancellationReason,
            DispatchReadyState, RequestBodyRuntime, RequestBodyState, RequestContext,
            RequestExecutionState, RequestMode, ResponseEmissionState, RoutingSnapshot,
            StreamAdmissionState, StreamPhase, TerminalReason, TimeoutReason, TunnelMode,
        },
    },
    watchdog::config::WatchdogRuntimeConfig,
};
type RoutingMaps = (
    HashMap<Arc<[u8]>, Arc<[u8]>>,
    CidRadix,
    HashMap<SocketAddr, Arc<[u8]>>,
);

fn cid(bytes: &[u8]) -> Arc<[u8]> {
    Arc::from(bytes)
}

fn test_upstream(lb_type: &str) -> Upstream {
    test_upstream_with(lb_type, None, None)
}

fn test_upstream_with(lb_type: &str, lb_key: Option<&str>, method: Option<&str>) -> Upstream {
    Upstream {
        load_balancing: LoadBalancing {
            lb_type: lb_type.to_string(),
            key: lb_key.map(str::to_string),
        },
        auth: Default::default(),
        host_policy: Default::default(),
        forwarded_headers: Default::default(),
        tls: None,
        route: RouteMatch {
            host: None,
            path_prefix: Some("/api".to_string()),
            method: method.map(str::to_string),
        },
        backends: vec![
            Backend {
                id: "b1".to_string(),
                address: "127.0.0.1:7001".to_string(),
                weight: 1,
                health_check: None,
            },
            Backend {
                id: "b2".to_string(),
                address: "127.0.0.1:7002".to_string(),
                weight: 1,
                health_check: None,
            },
        ],
    }
}

fn runtime_config_with_upstreams(upstreams: HashMap<String, Upstream>) -> RuntimeConfig {
    RuntimeConfig::from_config(&ImpulseConfigConfig {
        version: 1,
        listen: Listen {
            protocol: "http1".to_string(),
            tls: Tls {
                cert: "/tmp/test-cert.pem".to_string(),
                key: "/tmp/test-key.pem".to_string(),
                ..Tls::default()
            },
            ..Listen::default()
        },
        listeners: Vec::new(),
        upstream: upstreams,
        load_balancing: None,
        upstream_tls: UpstreamTls::default(),
        secrets: Default::default(),
        log: Log::default(),
        performance: Performance::default(),
        observability: Observability::default(),
        resilience: Resilience::default(),
        security: Security::default(),
    })
    .expect("runtime config")
}

fn write_test_cert_for_name(dir: &Path, cert_name: &str, dns_name: &str) -> (String, String) {
    let mut params = CertificateParams::new(vec![dns_name.to_string()]);
    params
        .subject_alt_names
        .push(SanType::DnsName(dns_name.to_string()));
    let cert = Certificate::from_params(params).expect("failed to build cert");

    let cert_path = dir.join(format!("{cert_name}.pem"));
    let key_path = dir.join(format!("{cert_name}.key.pem"));

    std::fs::write(&cert_path, cert.serialize_pem().expect("serialize cert")).expect("write cert");
    std::fs::write(&key_path, cert.serialize_private_key_pem()).expect("write key");
    (
        cert_path.to_string_lossy().to_string(),
        key_path.to_string_lossy().to_string(),
    )
}

fn tls_test_config(
    cert: String,
    key: String,
    certificates: Vec<TlsCertificate>,
) -> ImpulseConfigConfig {
    let mut upstreams = HashMap::new();
    upstreams.insert("api".to_string(), test_upstream("round-robin"));
    ImpulseConfigConfig {
        version: 1,
        listen: Listen {
            protocol: "http3".to_string(),
            port: 9889,
            address: "127.0.0.1".to_string(),
            tls: Tls {
                cert,
                key,
                certificates,
                client_auth: ClientAuth::default(),
            },
        },
        listeners: vec![],
        upstream: upstreams,
        load_balancing: Some(LoadBalancing {
            lb_type: "round-robin".to_string(),
            key: None,
        }),
        upstream_tls: UpstreamTls::default(),
        secrets: Default::default(),
        log: Log::default(),
        performance: Performance::default(),
        observability: Observability::default(),
        resilience: Resilience::default(),
        security: Security::default(),
    }
}

fn tls_test_listener_config(config: &ImpulseConfigConfig) -> ListenerRuntimeConfig {
    RuntimeConfig::from_config(config)
        .expect("runtime config")
        .primary_listener_runtime_config()
        .expect("listener runtime config")
}

fn dns_resolution_test_config(cert: String, key: String) -> ImpulseConfigConfig {
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
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
                host: Some("api.example.com".to_string()),
                path_prefix: Some("/".to_string()),
                method: None,
            },
            backends: vec![
                Backend {
                    id: "dns".to_string(),
                    address: "backend.internal:8443".to_string(),
                    weight: 1,
                    health_check: None,
                },
                Backend {
                    id: "ip".to_string(),
                    address: "10.0.0.10:9443".to_string(),
                    weight: 1,
                    health_check: None,
                },
            ],
        },
    );

    ImpulseConfigConfig {
        version: 1,
        listen: Listen {
            protocol: "http3".to_string(),
            port: 9889,
            address: "127.0.0.1".to_string(),
            tls: Tls {
                cert,
                key,
                certificates: Vec::new(),
                client_auth: ClientAuth::default(),
            },
        },
        listeners: vec![],
        upstream: upstreams,
        load_balancing: Some(LoadBalancing {
            lb_type: "round-robin".to_string(),
            key: None,
        }),
        upstream_tls: UpstreamTls::default(),
        secrets: Default::default(),
        log: Log::default(),
        performance: Performance::default(),
        observability: Observability::default(),
        resilience: Resilience::default(),
        security: Security::default(),
    }
}

#[test]
fn runtime_listener_tls_uses_first_sni_entry_when_legacy_pair_is_missing() {
    let dir = tempdir().expect("tempdir");
    let (api_cert, api_key) = write_test_cert_for_name(dir.path(), "api", "api.example.com");
    let (www_cert, www_key) = write_test_cert_for_name(dir.path(), "www", "www.example.com");
    let config = tls_test_config(
        String::new(),
        String::new(),
        vec![
            TlsCertificate {
                server_name: "api.example.com".to_string(),
                cert: api_cert.clone(),
                key: api_key.clone(),
            },
            TlsCertificate {
                server_name: "www.example.com".to_string(),
                cert: www_cert,
                key: www_key,
            },
        ],
    );

    let runtime_tls = super::QUICListener::runtime_listener_tls(&tls_test_listener_config(&config))
        .expect("runtime listener tls");
    assert_eq!(runtime_tls.default_identity.cert_path, api_cert);
    assert_eq!(runtime_tls.default_identity.key_path, api_key);
}

#[test]
fn listener_tls_reload_state_accepts_sni_certs_without_legacy_pair() {
    let dir = tempdir().expect("tempdir");
    let (api_cert, api_key) = write_test_cert_for_name(dir.path(), "api", "api.example.com");
    let config = tls_test_config(
        String::new(),
        String::new(),
        vec![TlsCertificate {
            server_name: "api.example.com".to_string(),
            cert: api_cert,
            key: api_key,
        }],
    );

    let reload_state =
        super::QUICListener::build_listener_tls_reload_state(&tls_test_listener_config(&config));
    assert!(reload_state.is_ok());
}

#[test]
fn load_listener_tls_material_extracts_leaf_metadata() {
    let dir = tempdir().expect("tempdir");
    let (api_cert, api_key) = write_test_cert_for_name(dir.path(), "api", "api.example.com");
    let runtime_config = tls_test_listener_config(&tls_test_config(
        String::new(),
        String::new(),
        vec![TlsCertificate {
            server_name: "api.example.com".to_string(),
            cert: api_cert.clone(),
            key: api_key.clone(),
        }],
    ));

    let loaded = super::QUICListener::load_listener_tls_material(&runtime_config)
        .expect("loaded listener tls");
    let metadata = loaded.default_identity.metadata();
    assert!(
        !metadata.serial_hex.is_empty(),
        "serial should be populated"
    );
    assert!(
        metadata.not_after_unix_seconds >= metadata.not_before_unix_seconds,
        "certificate validity should be ordered"
    );
    assert!(
        metadata
            .dns_names
            .iter()
            .any(|name| name == "api.example.com"),
        "expected SAN/CN metadata to include the configured hostname"
    );
}

#[test]
fn load_listener_tls_material_loads_client_auth_ca_roots() {
    let dir = tempdir().expect("tempdir");
    let (server_cert, server_key) =
        write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let (client_ca_cert, _client_ca_key) =
        write_test_cert_for_name(dir.path(), "client-ca", "client-ca.example.com");
    let mut config = tls_test_config(server_cert, server_key, Vec::new());
    config.listen.tls.client_auth = ClientAuth {
        enabled: true,
        require_client_cert: true,
        ca_file: Some(client_ca_cert.clone()),
    };

    let loaded =
        super::QUICListener::load_listener_tls_material(&tls_test_listener_config(&config))
            .expect("loaded listener tls");
    let client_auth_ca = loaded.client_auth_ca.expect("client auth ca");
    assert_eq!(client_auth_ca.ca_file, client_ca_cert);
    assert_eq!(client_auth_ca.certificate_count, 1);
}

#[test]
fn listener_tls_reload_store_refreshes_inventory_and_generation() {
    let dir = tempdir().expect("tempdir");
    let (server_cert, server_key) =
        write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut config = tls_test_config(server_cert, server_key, Vec::new());
    config.listen.port = 0;

    let runtime = RuntimeConfig::from_config(&config).expect("runtime config");
    let shared = super::QUICListener::build_shared_state(&runtime).expect("shared state");
    let listener_label = "127.0.0.1:0";
    let initial_inventory = shared
        .shared_services()
        .listener_tls_store
        .inventory(listener_label)
        .expect("initial inventory");
    let initial_serial = initial_inventory
        .default_identity
        .metadata
        .serial_hex
        .clone();
    assert_eq!(
        shared
            .shared_services()
            .listener_tls_store
            .generation(listener_label),
        Some(0)
    );

    let (_rotated_cert, _rotated_key) =
        write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let listener_config = shared
        .generation_state()
        .listener_runtime_configs
        .get(listener_label)
        .expect("listener runtime config");
    let reloaded_state = super::QUICListener::build_listener_tls_reload_state(listener_config)
        .expect("reloaded tls state");
    let generation = shared
        .shared_services()
        .listener_tls_store
        .replace_listener(
            listener_label,
            reloaded_state.inventory,
            reloaded_state.certificate_resolver,
        )
        .expect("replace listener");
    assert_eq!(generation, 1);

    let refreshed_inventory = shared
        .shared_services()
        .listener_tls_store
        .inventory(listener_label)
        .expect("refreshed inventory");
    assert_ne!(
        refreshed_inventory.default_identity.metadata.serial_hex,
        initial_serial
    );
}

#[test]
fn quic_listener_syncs_tls_generation_after_reload() {
    let dir = tempdir().expect("tempdir");
    let (server_cert, server_key) =
        write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut config = tls_test_config(server_cert, server_key, Vec::new());
    config.listen.port = 0;
    let runtime = RuntimeConfig::from_config(&config).expect("runtime config");
    let shared = Arc::new(super::QUICListener::build_shared_state(&runtime).expect("shared"));
    let listener_config = runtime
        .primary_listener_runtime_config()
        .expect("listener runtime config");
    let listener_label = super::QUICListener::listener_label(&listener_config);
    assert_eq!(
        super::QUICListener::tls_reload_generation_if_needed(
            &listener_label,
            0,
            &shared.shared_services().listener_tls_store
        )
        .expect("initial generation"),
        None
    );

    let (_rotated_cert, _rotated_key) =
        write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let reloaded_state = super::QUICListener::build_listener_tls_reload_state(&listener_config)
        .expect("reloaded tls state");
    shared
        .shared_services()
        .listener_tls_store
        .replace_listener(
            &listener_label,
            reloaded_state.inventory,
            reloaded_state.certificate_resolver,
        )
        .expect("replace listener");

    assert_eq!(
        super::QUICListener::tls_reload_generation_if_needed(
            &listener_label,
            0,
            &shared.shared_services().listener_tls_store
        )
        .expect("reloaded generation"),
        Some(1)
    );
}

#[test]
fn metrics_endpoint_state_prefers_reloaded_runtime_settings() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let startup = tls_test_config(cert.clone(), key.clone(), Vec::new());
    let startup_runtime = RuntimeConfig::from_config(&startup).expect("startup runtime");
    let startup_shared =
        Arc::new(super::QUICListener::build_shared_state(&startup_runtime).expect("shared"));
    let mut reloaded = startup.clone();
    reloaded.observability.metrics.enabled = true;
    reloaded.observability.metrics.path = "/metrics-live".to_string();
    reloaded.observability.metrics.max_connections = 29;
    reloaded.observability.metrics.connection_timeout_ms = 3456;

    let reloaded_runtime = RuntimeConfig::from_config(&reloaded).expect("reloaded runtime");
    let reloaded_bundle = super::QUICListener::build_runtime_bundle(
        "reloaded.yaml".to_string(),
        reloaded.log.clone(),
        &reloaded_runtime,
    )
    .expect("reloaded bundle");
    let runtime_handle = Arc::new(super::RuntimeBundleHandle::new(reloaded_bundle));
    let runtime_ctx = super::runtime_state::ControlPlaneRuntimeCtx::from_runtime_sources(
        &startup_runtime,
        startup_shared.as_ref(),
        Some(Arc::clone(&runtime_handle)),
    );
    let service_ctx = super::runtime_state::MetricsServiceCtx::new(runtime_ctx);

    let state = super::QUICListener::current_metrics_endpoint_state(&service_ctx);

    assert_eq!(state.endpoint.path, "/metrics-live");
    assert_eq!(state.endpoint.max_connections, 29);
    assert_eq!(state.endpoint.connection_timeout_ms, 3456);
}

#[test]
fn watchdog_service_state_prefers_reloaded_runtime_view_settings() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let startup = tls_test_config(cert.clone(), key.clone(), Vec::new());
    let startup_runtime = RuntimeConfig::from_config(&startup).expect("startup runtime");
    let startup_shared =
        Arc::new(super::QUICListener::build_shared_state(&startup_runtime).expect("shared"));

    let mut reloaded = startup.clone();
    reloaded.resilience.watchdog.enabled = true;
    reloaded.resilience.watchdog.check_interval_ms = 321;
    reloaded.resilience.watchdog.poll_stall_timeout_ms = 654;
    reloaded.resilience.watchdog.timeout_error_rate_percent = 42;
    reloaded.resilience.watchdog.unhealthy_consecutive_windows = 3;

    let reloaded_runtime = RuntimeConfig::from_config(&reloaded).expect("reloaded runtime");
    let reloaded_bundle = super::QUICListener::build_runtime_bundle(
        "reloaded.yaml".to_string(),
        reloaded.log.clone(),
        &reloaded_runtime,
    )
    .expect("reloaded bundle");
    let runtime_handle = Arc::new(super::RuntimeBundleHandle::new(reloaded_bundle));
    let runtime_ctx = super::runtime_state::ControlPlaneRuntimeCtx::from_runtime_sources(
        &startup_runtime,
        startup_shared.as_ref(),
        Some(Arc::clone(&runtime_handle)),
    );
    let runtime_view = runtime_ctx.current_view();
    let task_registry = runtime_view.generation_tasks();
    let expected_config =
        WatchdogRuntimeConfig::from(&reloaded_runtime.policies.admission.watchdog);
    let expected_metrics = runtime_view.metrics();
    let expected_resilience = runtime_view.resilience();
    let expected_watchdog = runtime_view.watchdog();

    let spawn_state = super::QUICListener::watchdog_spawn_state(
        super::runtime_state::WatchdogServiceCtx::new(runtime_view, task_registry),
    );

    assert_eq!(spawn_state.service.config.check_interval_ms, 321);
    assert_eq!(spawn_state.service.config.poll_stall_timeout_ms, 654);
    assert_eq!(spawn_state.service.config.timeout_error_rate_percent, 42);
    assert_eq!(spawn_state.service.config.unhealthy_consecutive_windows, 3);
    assert_eq!(
        spawn_state.service.config.restart_cooldown_ms,
        expected_config.restart_cooldown_ms
    );
    assert!(
        Arc::ptr_eq(&spawn_state.service.metrics, &expected_metrics),
        "watchdog service should use the metrics handle from the active runtime view"
    );
    assert!(
        Arc::ptr_eq(&spawn_state.service.resilience, &expected_resilience),
        "watchdog service should use the resilience handle from the active runtime view"
    );
    assert!(
        Arc::ptr_eq(&spawn_state.service.watchdog, &expected_watchdog),
        "watchdog service should use the watchdog handle from the active runtime view"
    );
}

#[test]
fn quic_listener_syncs_drain_timeout_and_connection_rate_limiter_after_reload() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut startup = tls_test_config(cert.clone(), key.clone(), Vec::new());
    startup.listen.port = 0;
    startup.performance.shutdown_drain_timeout_ms = 5_000;
    startup.performance.new_connections_per_sec = 100;
    startup.performance.new_connections_burst = 5;

    let startup_runtime = RuntimeConfig::from_config(&startup).expect("startup runtime");
    let startup_bundle = super::QUICListener::build_runtime_bundle(
        "startup.yaml".to_string(),
        startup.log.clone(),
        &startup_runtime,
    )
    .expect("startup bundle");
    let runtime_handle = Arc::new(super::RuntimeBundleHandle::new(startup_bundle.clone()));
    let listener_config = startup_bundle
        .runtime_config
        .primary_listener_runtime_config()
        .expect("listener runtime config");
    let socket = match super::QUICListener::bind_socket(&listener_config, false) {
        Ok(socket) => socket,
        Err(impulse_errors::ProxyError::Transport(message))
            if message.contains("Operation not permitted") =>
        {
            return;
        }
        Err(err) => panic!("bind socket: {err:?}"),
    };
    let mut listener = super::QUICListener::new_with_socket_and_shared_state(
        listener_config,
        socket,
        Arc::clone(&startup_bundle.shared_state),
    )
    .expect("listener")
    .with_runtime_bundle(Arc::clone(&runtime_handle));

    let mut reloaded = startup.clone();
    reloaded.performance.shutdown_drain_timeout_ms = 1_234;
    reloaded.performance.new_connections_per_sec = 50;
    reloaded.performance.new_connections_burst = 2;

    let reloaded_runtime = RuntimeConfig::from_config(&reloaded).expect("reloaded runtime");
    let mut reloaded_bundle = super::QUICListener::build_runtime_bundle(
        "reloaded.yaml".to_string(),
        reloaded.log.clone(),
        &reloaded_runtime,
    )
    .expect("reloaded bundle");
    reloaded_bundle.generation = 1;
    runtime_handle
        .replace(reloaded_bundle)
        .expect("replace runtime bundle");

    listener
        .sync_runtime_bundle_if_needed()
        .expect("sync runtime bundle");

    assert_eq!(listener.drain_timeout, Duration::from_millis(1_234));
    assert!(listener.conn_rate_limiter.try_consume());
    assert!(listener.conn_rate_limiter.try_consume());
    assert!(
        !listener.conn_rate_limiter.try_consume(),
        "reconfigured burst should clamp immediate capacity to the new limit"
    );
}

#[test]
fn start_draining_is_idempotent_and_drain_completes_when_idle() {
    // Phase 9 (#5): draining is idempotent — repeated start_draining() must not
    // reset the drain deadline, and drain_complete() is safe to call repeatedly.
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut startup = tls_test_config(cert, key, Vec::new());
    startup.listen.port = 0;
    startup.performance.shutdown_drain_timeout_ms = 5_000;

    let startup_runtime = RuntimeConfig::from_config(&startup).expect("startup runtime");
    let startup_bundle = super::QUICListener::build_runtime_bundle(
        "startup.yaml".to_string(),
        startup.log.clone(),
        &startup_runtime,
    )
    .expect("startup bundle");
    let listener_config = startup_bundle
        .runtime_config
        .primary_listener_runtime_config()
        .expect("listener runtime config");
    let socket = match super::QUICListener::bind_socket(&listener_config, false) {
        Ok(socket) => socket,
        Err(impulse_errors::ProxyError::Transport(message))
            if message.contains("Operation not permitted") =>
        {
            return;
        }
        Err(err) => panic!("bind socket: {err:?}"),
    };
    let mut listener = super::QUICListener::new_with_socket_and_shared_state(
        listener_config,
        socket,
        Arc::clone(&startup_bundle.shared_state),
    )
    .expect("listener");

    assert!(!listener.draining);
    listener.start_draining();
    assert!(listener.draining);
    let first_start = listener.drain_start.expect("drain_start set");

    // Second call is a no-op: still draining, deadline not reset.
    listener.start_draining();
    assert!(listener.draining);
    assert_eq!(
        listener.drain_start.expect("drain_start still set"),
        first_start,
        "repeated start_draining must not reset the drain deadline"
    );

    // With no connections, drain is complete and remains complete on repeat calls.
    assert!(listener.drain_complete());
    assert!(listener.drain_complete());
}

#[test]
fn process_shutdown_signal_starts_listener_draining_before_worker_exit() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut startup = tls_test_config(cert, key, Vec::new());
    startup.listen.port = 0;

    let startup_runtime = RuntimeConfig::from_config(&startup).expect("startup runtime");
    let startup_bundle = super::QUICListener::build_runtime_bundle(
        "startup.yaml".to_string(),
        startup.log.clone(),
        &startup_runtime,
    )
    .expect("startup bundle");
    let listener_config = startup_bundle
        .runtime_config
        .primary_listener_runtime_config()
        .expect("listener runtime config");
    let socket = match super::QUICListener::bind_socket(&listener_config, false) {
        Ok(socket) => socket,
        Err(impulse_errors::ProxyError::Transport(message))
            if message.contains("Operation not permitted") =>
        {
            return;
        }
        Err(err) => panic!("bind socket: {err:?}"),
    };
    let mut listener = super::QUICListener::new_with_socket_and_shared_state(
        listener_config,
        socket,
        Arc::clone(&startup_bundle.shared_state),
    )
    .expect("listener");

    listener.shutdown.store(true, Ordering::Relaxed);
    assert!(!listener.poll_preamble());
    assert!(listener.draining);
}

#[test]
fn watchdog_restart_transitions_listener_into_draining_and_counts_worker_drain_once() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut startup = tls_test_config(cert, key, Vec::new());
    startup.listen.port = 0;
    startup.performance.shutdown_drain_timeout_ms = 5_000;
    startup.resilience.watchdog.enabled = true;

    let startup_runtime = RuntimeConfig::from_config(&startup).expect("startup runtime");
    let startup_bundle = super::QUICListener::build_runtime_bundle(
        "startup.yaml".to_string(),
        startup.log.clone(),
        &startup_runtime,
    )
    .expect("startup bundle");
    let runtime_handle = Arc::new(super::RuntimeBundleHandle::new(startup_bundle.clone()));
    let listener_config = startup_bundle
        .runtime_config
        .primary_listener_runtime_config()
        .expect("listener runtime config");
    let socket = match super::QUICListener::bind_socket(&listener_config, false) {
        Ok(socket) => socket,
        Err(impulse_errors::ProxyError::Transport(message))
            if message.contains("Operation not permitted") =>
        {
            return;
        }
        Err(err) => panic!("bind socket: {err:?}"),
    };
    let mut listener = super::QUICListener::new_with_socket_and_shared_state(
        listener_config,
        socket,
        Arc::clone(&startup_bundle.shared_state),
    )
    .expect("listener")
    .with_runtime_bundle(Arc::clone(&runtime_handle));

    listener.watchdog.set_expected_workers(2);
    assert!(
        listener.watchdog.request_restart("unit-test-drain"),
        "watchdog restart should be accepted when the runtime watchdog is enabled"
    );
    assert!(!listener.draining);
    assert!(!listener.watchdog_worker_drained);
    assert!(!listener.watchdog.workers_drained());

    assert!(
        !listener.poll_preamble(),
        "an idle listener should finish its watchdog drain in the same preamble cycle"
    );
    assert!(
        listener.draining,
        "watchdog restart should transition the listener into draining mode"
    );
    assert!(
        listener.watchdog_worker_drained,
        "listener should mark its worker drain completion once the watchdog drain finishes"
    );
    assert!(
        !listener.watchdog.workers_drained(),
        "one drained listener must not satisfy a two-worker watchdog restart"
    );

    assert!(
        !listener.poll_preamble(),
        "re-entering the idle drain preamble should remain terminal for this listener"
    );
    assert!(
        !listener.watchdog.workers_drained(),
        "repeated drain completion must not double-count the same worker toward restart completion"
    );
}

#[test]
fn listener_tls_reload_state_rejects_mismatched_sni_certificate_mapping() {
    let dir = tempdir().expect("tempdir");
    let (api_cert, api_key) = write_test_cert_for_name(dir.path(), "api", "api.example.com");
    let config = tls_test_config(
        String::new(),
        String::new(),
        vec![TlsCertificate {
            server_name: "other.example.com".to_string(),
            cert: api_cert,
            key: api_key,
        }],
    );

    let err =
        super::QUICListener::build_listener_tls_reload_state(&tls_test_listener_config(&config))
            .err()
            .expect("mismatched SNI cert mapping should fail");
    assert!(
        err.to_string()
            .contains("failed to add SNI certificate mapping"),
        "unexpected error: {err}"
    );
}

#[test]
fn build_quic_config_accepts_sni_certs_without_legacy_pair() {
    let dir = tempdir().expect("tempdir");
    let (api_cert, api_key) = write_test_cert_for_name(dir.path(), "api", "api.example.com");
    let config = tls_test_config(
        String::new(),
        String::new(),
        vec![TlsCertificate {
            server_name: "api.example.com".to_string(),
            cert: api_cert,
            key: api_key,
        }],
    );

    let quic_config = super::QUICListener::build_quic_config(&tls_test_listener_config(&config));
    if let Err(err) = quic_config {
        panic!("unexpected error: {err}");
    }
}

#[test]
fn build_quic_config_rejects_mismatched_sni_certificate_mapping() {
    let dir = tempdir().expect("tempdir");
    let (api_cert, api_key) = write_test_cert_for_name(dir.path(), "api", "api.example.com");
    let config = tls_test_config(
        String::new(),
        String::new(),
        vec![TlsCertificate {
            server_name: "other.example.com".to_string(),
            cert: api_cert,
            key: api_key,
        }],
    );

    let err = super::QUICListener::build_quic_config(&tls_test_listener_config(&config))
        .err()
        .expect("mismatched SNI cert mapping should fail");
    assert!(
        err.to_string()
            .contains("failed to add SNI certificate mapping"),
        "unexpected error: {err}"
    );
}

#[test]
fn certificate_name_matches_single_label_wildcards_only() {
    assert!(super::QUICListener::certificate_name_matches(
        "*.example.com",
        "api.example.com"
    ));
    assert!(!super::QUICListener::certificate_name_matches(
        "*.example.com",
        "deep.api.example.com"
    ));
    assert!(!super::QUICListener::certificate_name_matches(
        "*.example.com",
        "example.com"
    ));
}

#[test]
fn classify_upstream_failure_reason_distinguishes_tls_causes() {
    assert_eq!(
        classify_upstream_error_detail("tls handshake failed: UnknownIssuer", true),
        UpstreamErrorClassification::tls(UpstreamTlsReason::UnknownIssuer)
    );
    assert_eq!(
        classify_upstream_error_detail("certificate expired while verifying backend", true),
        UpstreamErrorClassification::tls(UpstreamTlsReason::ExpiredCertificate)
    );
    assert_eq!(
        classify_upstream_error_detail("certificate not valid for dns name api.example.com", true,),
        UpstreamErrorClassification::tls(UpstreamTlsReason::HostnameMismatch)
    );
    assert_eq!(
        classify_upstream_error_detail("ALPN negotiation failed", true),
        UpstreamErrorClassification::tls(UpstreamTlsReason::Alpn)
    );
    assert_eq!(
        classify_upstream_error_detail("backend timed out", false),
        UpstreamErrorClassification::timeout()
    );
    assert_eq!(
        classify_upstream_error_detail("connection reset", false),
        UpstreamErrorClassification {
            category: UpstreamErrorCategory::Transport,
            tls_reason: None,
        }
    );
}

#[test]
fn classify_downstream_tls_failure_reason_distinguishes_client_auth_causes() {
    assert_eq!(
        super::QUICListener::classify_downstream_tls_failure_reason("peer sent no certificates"),
        "missing_client_cert"
    );
    assert_eq!(
        super::QUICListener::classify_downstream_tls_failure_reason(
            "certificate verify failed: UnknownIssuer"
        ),
        "unknown_issuer"
    );
    assert_eq!(
        super::QUICListener::classify_downstream_tls_failure_reason("certificate expired"),
        "expired_client_cert"
    );
    assert_eq!(
        super::QUICListener::classify_downstream_tls_failure_reason("bad certificate"),
        "invalid_client_cert"
    );
}

#[test]
fn build_shared_state_separates_backend_identity_from_resolution_state() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let runtime =
        RuntimeConfig::from_config(&dns_resolution_test_config(cert, key)).expect("runtime");
    let shared = super::QUICListener::build_shared_state(&runtime).expect("shared state");
    let snapshot = shared.shared_services().backend_resolution_store.snapshot();

    let dns_backend = snapshot
        .get("backend.internal:8443")
        .expect("dns backend resolution");
    assert!(dns_backend.resolution.is_hostname());
    assert_eq!(dns_backend.resolution.authority_host, "backend.internal");
    assert_eq!(dns_backend.resolution.authority_port, 8443);
    assert!(dns_backend.resolution.resolved_addrs.is_empty());

    let ip_backend = snapshot
        .get("10.0.0.10:9443")
        .expect("ip backend resolution");
    assert!(!ip_backend.resolution.is_hostname());
    assert_eq!(ip_backend.resolution.authority_host, "10.0.0.10");
    assert_eq!(ip_backend.resolution.authority_port, 9443);
    assert_eq!(
        ip_backend.resolution.resolved_addrs,
        vec!["10.0.0.10:9443".parse().expect("addr")]
    );
}

type TestRoutingContext = (
    HashMap<String, Arc<RwLock<super::UpstreamPool>>>,
    HashMap<String, impulse_config::runtime::RuntimeUpstreamPolicy>,
    super::RouteIndex,
    Arc<RwLock<super::UpstreamPool>>,
);

fn test_routing_context(lb_type: &str) -> TestRoutingContext {
    let mut upstreams = HashMap::new();
    upstreams.insert("api_pool".to_string(), test_upstream(lb_type));
    let runtime = runtime_config_with_upstreams(upstreams);
    let routing_index = super::RouteIndex::from_runtime_upstreams(&runtime.upstreams);
    let pool = super::UpstreamPool::from_runtime_upstream(
        runtime.upstreams.get("api_pool").expect("upstream"),
    )
    .expect("pool");
    let pool = Arc::new(RwLock::new(pool));
    let mut upstream_pools = HashMap::new();
    upstream_pools.insert("api_pool".to_string(), Arc::clone(&pool));
    let mut upstream_policies = HashMap::new();
    upstream_policies.insert(
        "api_pool".to_string(),
        runtime
            .upstreams
            .get("api_pool")
            .expect("upstream")
            .policy
            .clone(),
    );
    (upstream_pools, upstream_policies, routing_index, pool)
}

#[test]
fn resolve_backend_round_robin_is_not_pinned_to_first_backend() {
    let (upstream_pools, upstream_policies, routing_index, _pool) =
        test_routing_context("round-robin");

    let mut picks = Vec::new();
    for _ in 0..4 {
        let request = super::forwarding::TestTargetResolutionRequest::new(
            "GET",
            "/api/items",
            None,
            None,
            None,
        );
        let resolved = super::QUICListener::resolve_backend_request_for_test(
            &request,
            &upstream_pools,
            &upstream_policies,
            &routing_index,
        )
        .expect("resolve backend");
        picks.push(resolved.backend.backend_addr);
    }

    assert!(
        picks.iter().any(|addr| addr == "127.0.0.1:7001")
            && picks.iter().any(|addr| addr == "127.0.0.1:7002"),
        "round-robin resolution should not pin all bootstrap picks to the first backend: {:?}",
        picks
    );
}

#[test]
fn resolve_backend_skips_unhealthy_backends() {
    let (upstream_pools, upstream_policies, routing_index, pool) =
        test_routing_context("round-robin");
    {
        let mut guard = pool.write().expect("pool write");
        guard.mark_backend_failure_from_active_check(0);
        guard.mark_backend_failure_from_active_check(0);
        guard.mark_backend_failure_from_active_check(0);
    }

    let request =
        super::forwarding::TestTargetResolutionRequest::new("GET", "/api/items", None, None, None);
    let resolved = super::QUICListener::resolve_backend_request_for_test(
        &request,
        &upstream_pools,
        &upstream_policies,
        &routing_index,
    )
    .expect("resolve backend");

    assert_eq!(
        resolved.backend.backend_addr, "127.0.0.1:7002",
        "unhealthy backend must be excluded from bootstrap backend selection"
    );
}

#[test]
fn resolve_backend_respects_least_connections_strategy() {
    let (upstream_pools, upstream_policies, routing_index, pool) =
        test_routing_context("least-connections");
    {
        let guard = pool.read().expect("pool read");
        guard.begin_request_for_accounting(0);
        guard.begin_request_for_accounting(0);
    }

    let request =
        super::forwarding::TestTargetResolutionRequest::new("GET", "/api/items", None, None, None);
    let resolved = super::QUICListener::resolve_backend_request_for_test(
        &request,
        &upstream_pools,
        &upstream_policies,
        &routing_index,
    )
    .expect("resolve backend");

    assert_eq!(
        resolved.backend.backend_addr, "127.0.0.1:7002",
        "least-connections should prefer lower in-flight backend in bootstrap selection"
    );
}

#[test]
fn resolve_backend_prefers_method_specific_route() {
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "all_methods".to_string(),
        test_upstream_with("round-robin", None, None),
    );
    let mut post_only = test_upstream_with("round-robin", None, Some("POST"));
    post_only.backends = vec![Backend {
        id: "post".to_string(),
        address: "127.0.0.1:7010".to_string(),
        weight: 1,
        health_check: None,
    }];
    upstreams.insert("post_only".to_string(), post_only);

    let runtime = runtime_config_with_upstreams(upstreams);
    let routing_index = super::RouteIndex::from_runtime_upstreams(&runtime.upstreams);
    let mut upstream_pools = HashMap::new();
    let mut upstream_policies = HashMap::new();
    for (name, upstream) in &runtime.upstreams {
        let pool = super::UpstreamPool::from_runtime_upstream(upstream).expect("pool");
        upstream_pools.insert(name.clone(), Arc::new(RwLock::new(pool)));
        upstream_policies.insert(name.clone(), upstream.policy.clone());
    }

    let request =
        super::forwarding::TestTargetResolutionRequest::new("GET", "/api/items", None, None, None);
    let resolved = super::QUICListener::resolve_backend_request_for_test(
        &request,
        &upstream_pools,
        &upstream_policies,
        &routing_index,
    )
    .expect("GET resolve");
    assert_eq!(resolved.route.upstream_name, "all_methods");

    let request =
        super::forwarding::TestTargetResolutionRequest::new("POST", "/api/items", None, None, None);
    let resolved = super::QUICListener::resolve_backend_request_for_test(
        &request,
        &upstream_pools,
        &upstream_policies,
        &routing_index,
    )
    .expect("POST resolve");
    assert_eq!(resolved.route.upstream_name, "post_only");
    assert_eq!(resolved.backend.backend_addr, "127.0.0.1:7010");
}

#[test]
fn resolve_backend_uses_configured_header_lb_key() {
    let (upstream_pools, upstream_policies, routing_index, _pool) = {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "api_pool".to_string(),
            test_upstream_with("consistent-hash", Some("header:x-user-id"), None),
        );
        let runtime = runtime_config_with_upstreams(upstreams);
        let routing_index = super::RouteIndex::from_runtime_upstreams(&runtime.upstreams);
        let pool = super::UpstreamPool::from_runtime_upstream(
            runtime.upstreams.get("api_pool").expect("upstream"),
        )
        .expect("pool");
        let pool = Arc::new(RwLock::new(pool));
        let mut upstream_pools = HashMap::new();
        upstream_pools.insert("api_pool".to_string(), Arc::clone(&pool));
        let mut upstream_policies = HashMap::new();
        upstream_policies.insert(
            "api_pool".to_string(),
            runtime
                .upstreams
                .get("api_pool")
                .expect("upstream")
                .policy
                .clone(),
        );
        (upstream_pools, upstream_policies, routing_index, pool)
    };

    let header_lookup = |name: &str| {
        if name.eq_ignore_ascii_case("x-user-id") {
            Some("alice".to_string())
        } else {
            None
        }
    };

    let first_request = super::forwarding::TestTargetResolutionRequest::new(
        "GET",
        "/api/items",
        None,
        None,
        Some(&header_lookup),
    );
    let first = super::QUICListener::resolve_backend_request_for_test(
        &first_request,
        &upstream_pools,
        &upstream_policies,
        &routing_index,
    )
    .expect("first resolve");
    let second_request = super::forwarding::TestTargetResolutionRequest::new(
        "GET",
        "/api/items",
        None,
        None,
        Some(&header_lookup),
    );
    let second = super::QUICListener::resolve_backend_request_for_test(
        &second_request,
        &upstream_pools,
        &upstream_policies,
        &routing_index,
    )
    .expect("second resolve");

    assert_eq!(
        first.backend.backend_addr, second.backend.backend_addr,
        "consistent-hash should remain stable when configured header key is constant"
    );
}

#[test]
fn active_health_check_classification_matches_shared_policy() {
    assert!(matches!(
        classify_active_health_check_response(StatusCode::MOVED_PERMANENTLY),
        crate::runtime::health::HealthClassification::Success
    ));
    assert!(matches!(
        classify_active_health_check_response(StatusCode::BAD_REQUEST),
        crate::runtime::health::HealthClassification::Neutral
    ));
    assert!(matches!(
        classify_active_health_check_response(StatusCode::BAD_GATEWAY),
        crate::runtime::health::HealthClassification::Failure
    ));
}

#[test]
fn bootstrap_connection_header_tokens_are_parsed_case_insensitively() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONNECTION,
        HeaderValue::from_static("keep-alive, X-Secret"),
    );
    headers.append(
        http::header::CONNECTION,
        HeaderValue::from_static("x-another"),
    );

    let tokens = connection_header_tokens(&headers);
    assert!(tokens.contains("keep-alive"));
    assert!(tokens.contains("x-secret"));
    assert!(tokens.contains("x-another"));
}

#[test]
fn bootstrap_header_filter_strips_connection_nominated_headers() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONNECTION,
        HeaderValue::from_static("keep-alive, x-secret"),
    );
    let tokens = connection_header_tokens(&headers);

    let header = http::HeaderName::from_static("x-secret");
    assert!(should_strip_bootstrap_request_header(&header, &tokens));
}

#[test]
fn bootstrap_header_filter_keeps_non_nominated_custom_headers() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONNECTION,
        HeaderValue::from_static("keep-alive"),
    );
    let tokens = connection_header_tokens(&headers);

    let header = http::HeaderName::from_static("x-custom-keep");
    assert!(!should_strip_bootstrap_request_header(&header, &tokens));
}

#[test]
fn h3_response_filter_strips_te_and_trailer() {
    let tokens = HashSet::new();
    assert!(should_strip_h3_response_header(&http::header::TE, &tokens));
    assert!(should_strip_h3_response_header(
        &http::header::TRAILER,
        &tokens
    ));
}

#[test]
fn h3_trailer_collection_preserves_end_to_end_trailers() {
    let mut trailers = HeaderMap::new();
    trailers.insert(
        http::HeaderName::from_static("grpc-status"),
        HeaderValue::from_static("0"),
    );
    trailers.insert(
        http::HeaderName::from_static("grpc-message"),
        HeaderValue::from_static("ok"),
    );
    let collected = collect_h3_trailers(&trailers);
    assert_eq!(collected.len(), 2);
    assert!(
        collected
            .iter()
            .any(|(k, v)| k.as_slice() == b"grpc-status" && v.as_slice() == b"0")
    );
    assert!(
        collected
            .iter()
            .any(|(k, v)| k.as_slice() == b"grpc-message" && v.as_slice() == b"ok")
    );
}

#[test]
fn h3_trailer_collection_strips_hop_by_hop_and_content_length() {
    let mut trailers = HeaderMap::new();
    trailers.insert(
        http::header::CONTENT_LENGTH,
        HeaderValue::from_static("123"),
    );
    trailers.insert(http::header::TE, HeaderValue::from_static("trailers"));
    trailers.insert(http::header::TRAILER, HeaderValue::from_static("x-next"));
    trailers.insert(
        http::header::CONNECTION,
        HeaderValue::from_static("x-hop-token"),
    );
    trailers.insert(
        http::HeaderName::from_static("x-hop-token"),
        HeaderValue::from_static("secret"),
    );
    trailers.insert(
        http::HeaderName::from_static("grpc-status"),
        HeaderValue::from_static("0"),
    );
    let collected = collect_h3_trailers(&trailers);
    assert_eq!(collected.len(), 1);
    assert_eq!(collected[0].0.as_slice(), b"grpc-status");
    assert_eq!(collected[0].1.as_slice(), b"0");
}

#[test]
fn h3_response_filter_strips_connection_nominated_headers() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONNECTION,
        HeaderValue::from_static("keep-alive, x-internal-hop"),
    );
    let tokens = connection_header_tokens(&headers);
    let nominated = http::HeaderName::from_static("x-internal-hop");
    assert!(should_strip_h3_response_header(&nominated, &tokens));
}

#[test]
fn bootstrap_response_filter_strips_standard_hop_by_hop_headers() {
    let tokens = HashSet::new();
    assert!(should_strip_bootstrap_response_header(
        &http::header::CONNECTION,
        &tokens
    ));
    assert!(should_strip_bootstrap_response_header(
        &http::header::TE,
        &tokens
    ));
    assert!(should_strip_bootstrap_response_header(
        &http::header::TRAILER,
        &tokens
    ));
    assert!(should_strip_bootstrap_response_header(
        &http::header::TRANSFER_ENCODING,
        &tokens
    ));
    assert!(should_strip_bootstrap_response_header(
        &http::header::UPGRADE,
        &tokens
    ));
    assert!(should_strip_bootstrap_response_header(
        &http::header::PROXY_AUTHENTICATE,
        &tokens
    ));
    assert!(should_strip_bootstrap_response_header(
        &http::header::PROXY_AUTHORIZATION,
        &tokens
    ));
    let alt_svc = http::HeaderName::from_static("alt-svc");
    assert!(should_strip_bootstrap_response_header(&alt_svc, &tokens));
    let keep_alive = http::HeaderName::from_static("keep-alive");
    assert!(should_strip_bootstrap_response_header(&keep_alive, &tokens));
}

#[test]
fn bootstrap_response_filter_strips_connection_nominated_headers() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONNECTION,
        HeaderValue::from_static("x-hop-token, x-alt"),
    );
    let tokens = connection_header_tokens(&headers);
    let nominated = http::HeaderName::from_static("x-hop-token");
    assert!(should_strip_bootstrap_response_header(&nominated, &tokens));
}

#[test]
fn bootstrap_response_filter_keeps_end_to_end_headers() {
    let tokens = HashSet::new();
    assert!(!should_strip_bootstrap_response_header(
        &http::header::CACHE_CONTROL,
        &tokens
    ));
}

#[test]
fn response_size_cap_enforced_as_running_total() {
    let config = ResponseBodyGuardrailConfig {
        idle_timeout: Duration::from_secs(5),
        total_timeout: Duration::from_secs(30),
        max_body_bytes: 10,
        unknown_length_prebuffer_bytes: 10,
        chunk_bytes: 4,
    };
    assert!(
        checked_response_body_guardrails(
            config,
            ResponseBodyGuardrailInput {
                elapsed: Duration::ZERO,
                idle_for: Duration::ZERO,
                bytes_received: 0,
                prebuffered_bytes: 0,
                next_chunk_bytes: 4,
                declared_content_length: None,
                headers_emitted: true,
                progressive_emission_allowed: true,
                body_forwarding_enabled: true,
                exempt_from_body_size_cap: false,
            },
        )
        .is_ok()
    );
    assert!(
        checked_response_body_guardrails(
            config,
            ResponseBodyGuardrailInput {
                elapsed: Duration::ZERO,
                idle_for: Duration::ZERO,
                bytes_received: 4,
                prebuffered_bytes: 0,
                next_chunk_bytes: 6,
                declared_content_length: None,
                headers_emitted: true,
                progressive_emission_allowed: true,
                body_forwarding_enabled: true,
                exempt_from_body_size_cap: false,
            },
        )
        .is_ok()
    );
    assert_eq!(
        checked_response_body_guardrails(
            config,
            ResponseBodyGuardrailInput {
                elapsed: Duration::ZERO,
                idle_for: Duration::ZERO,
                bytes_received: 10,
                prebuffered_bytes: 0,
                next_chunk_bytes: 1,
                declared_content_length: None,
                headers_emitted: true,
                progressive_emission_allowed: true,
                body_forwarding_enabled: true,
                exempt_from_body_size_cap: false,
            },
        ),
        Err(ResponseBodyGuardrailDecision::Reject {
            kind: BodyLimitKind::BodySize,
        })
    );
}

#[test]
fn connect_tunnel_response_detected_only_for_success_status() {
    assert!(is_connect_tunnel_response("CONNECT", StatusCode::OK));
    assert!(is_connect_tunnel_response(
        "connect",
        StatusCode::NO_CONTENT
    ));
    assert!(!is_connect_tunnel_response(
        "CONNECT",
        StatusCode::BAD_GATEWAY
    ));
    assert!(!is_connect_tunnel_response("GET", StatusCode::OK));
}

#[test]
fn bodyless_request_mode_only_applies_to_empty_get_and_head() {
    assert!(is_bodyless_request_mode("GET", None));
    assert!(is_bodyless_request_mode("HEAD", Some(0)));
    assert!(!is_bodyless_request_mode("GET", Some(1)));
    assert!(!is_bodyless_request_mode("POST", Some(0)));
    assert!(!is_bodyless_request_mode("HEAD", Some(1)));
}

#[test]
fn connect_can_poll_upstream_before_request_fin() {
    let mut req = make_awaiting_upstream_envelope(Instant::now(), "CONNECT", false);
    req.method = "CONNECT".to_string();
    req.tunnel_mode = TunnelMode::Connect;
    req.set_request_fin_received(false);
    if let RequestExecutionState::AwaitingUpstream(state) = &mut req.execution {
        state.request_mode = RequestMode::ConnectTunnel;
    }
    assert!(can_poll_upstream_result(&req));
}

#[test]
fn non_connect_requires_request_completion_before_upstream_poll() {
    let mut req = make_awaiting_upstream_envelope(Instant::now(), "GET", false);
    req.method = "GET".to_string();
    req.set_request_fin_received(false);
    assert!(!can_poll_upstream_result(&req));

    req.set_request_fin_received(true);
    if let RequestExecutionState::AwaitingUpstream(state) = &mut req.execution {
        state.dispatch.body_tx = None;
        // Request body forwarding is complete once FIN is received and the
        // upstream body channel is closed; production reaches this via
        // `from_runtime(fin, empty, no_tx)` == ClosedToUpstream.
        state.request_body = RequestBodyState::ClosedToUpstream;
    }
    assert!(can_poll_upstream_result(&req));

    let start = req.start;
    req.execution = RequestExecutionState::AwaitingAuth(AwaitingAuthState {
        context: make_request_context(start, "GET"),
        routing: make_routing_snapshot(),
        request_mode: RequestMode::Normal,
        request_body: RequestBodyState::FinReceived,
        request_body_runtime: make_body_runtime(start, true),
        pending_forward: make_pending_forward("GET"),
        auth_result_rx: oneshot::channel::<crate::runtime::connection::auth::ExternalAuthResult>()
            .1,
        auth_abort: tokio::runtime::Runtime::new()
            .expect("runtime")
            .spawn(async {})
            .abort_handle(),
        auth_deadline: start + Duration::from_secs(1),
        auth_disposition:
            crate::runtime::connection::auth::ExternalAuthFailureDisposition::FailClosed,
    });
    assert!(!can_poll_upstream_result(&req));
}

#[test]
fn total_request_timeout_tracks_typed_execution_phase() {
    let start = Instant::now();
    let mut req = make_dispatch_ready_envelope(start, "GET", false);
    req.method = "GET".to_string();
    req.set_request_fin_received(false);
    assert_eq!(
        req.total_request_timeout_reason(),
        TimeoutReason::RequestBodyTotal
    );

    req = make_awaiting_upstream_envelope(start, "GET", true);
    assert_eq!(
        req.total_request_timeout_reason(),
        TimeoutReason::AwaitingUpstream
    );

    req = make_streaming_envelope(start, StatusCode::OK, None);
    assert_eq!(
        req.total_request_timeout_reason(),
        TimeoutReason::ResponseBodyTotal
    );
}

#[test]
fn connect_total_request_timeout_prefers_awaiting_upstream_bucket() {
    let mut req = make_awaiting_upstream_envelope(Instant::now(), "CONNECT", false);
    req.method = "CONNECT".to_string();
    req.tunnel_mode = TunnelMode::Connect;
    req.set_request_fin_received(false);
    if let RequestExecutionState::AwaitingUpstream(state) = &mut req.execution {
        state.request_mode = RequestMode::ConnectTunnel;
    }

    assert!(can_poll_upstream_result(&req));
    assert_eq!(
        req.total_request_timeout_reason(),
        TimeoutReason::AwaitingUpstream
    );
}

#[test]
fn prefix_match_on_alias_resolves_to_primary_connection() {
    let primary = cid(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let alias = cid(&[9, 10, 11, 12, 13, 14, 15, 16]);

    let mut connections: HashMap<Arc<[u8]>, ()> = HashMap::new();
    connections.insert(Arc::clone(&primary), ());

    let mut cid_routes = HashMap::new();
    cid_routes.insert(Arc::clone(&alias), Arc::clone(&primary));

    let mut cid_radix = CidRadix::new();
    cid_radix.insert(Arc::clone(&alias));

    let mut dcid = alias.as_ref().to_vec();
    dcid.extend_from_slice(&[0xAA, 0xBB]);

    let resolved =
        resolve_primary_from_radix_prefix(&dcid, &connections, &mut cid_routes, &mut cid_radix)
            .expect("prefix lookup should resolve to active primary");

    assert_eq!(resolved.as_ref(), primary.as_ref());
    assert!(
        cid_routes.contains_key(alias.as_ref()),
        "live alias should remain mapped to active primary"
    );
    assert!(
        cid_radix.longest_prefix_match(&dcid).is_some(),
        "live alias should remain indexed in radix"
    );
}

#[test]
fn stale_alias_prefix_match_is_cleaned_up() {
    let primary = cid(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let alias = cid(&[9, 10, 11, 12, 13, 14, 15, 16]);

    let connections: HashMap<Arc<[u8]>, ()> = HashMap::new();

    let mut cid_routes = HashMap::new();
    cid_routes.insert(Arc::clone(&alias), Arc::clone(&primary));

    let mut cid_radix = CidRadix::new();
    cid_radix.insert(Arc::clone(&alias));

    let mut dcid = alias.as_ref().to_vec();
    dcid.extend_from_slice(&[0xAA, 0xBB]);

    let resolved =
        resolve_primary_from_radix_prefix(&dcid, &connections, &mut cid_routes, &mut cid_radix);
    assert!(resolved.is_none(), "stale alias must not resolve");
    assert!(
        !cid_routes.contains_key(alias.as_ref()),
        "stale alias mapping should be removed"
    );
    assert!(
        cid_radix.longest_prefix_match(alias.as_ref()).is_none(),
        "stale alias should be removed from radix"
    );
}

// -----------------------------------------------------------------------
// TokenBucket unit tests
// -----------------------------------------------------------------------

#[test]
fn token_bucket_allows_up_to_burst_immediately() {
    let mut tb = TokenBucket::new(100, 5);
    // Bucket starts full; first 5 tokens should all succeed.
    for i in 0..5 {
        assert!(
            tb.try_consume(),
            "token {} should be available (burst=5)",
            i
        );
    }
    // 6th token must fail — bucket is empty.
    assert!(
        !tb.try_consume(),
        "6th token must be denied when burst exhausted"
    );
}

#[test]
fn token_bucket_refills_over_time() {
    let mut tb = TokenBucket::new(10, 2); // 10 tokens/sec = 1 token per 100ms
    // Drain the bucket.
    assert!(tb.try_consume());
    assert!(tb.try_consume());
    assert!(!tb.try_consume());

    // Sleep slightly longer than one refill interval (100ms).
    std::thread::sleep(std::time::Duration::from_millis(120));

    // At least one token must have been refilled.
    assert!(
        tb.try_consume(),
        "bucket should have refilled at least one token after sleep"
    );
}

#[test]
fn token_bucket_rate_zero_clamps_to_one() {
    // rate=0 is clamped to 1; burst=0 is clamped to 1.
    let mut tb = TokenBucket::new(0, 0);
    // Starts with 1 token (burst=1).
    assert!(
        tb.try_consume(),
        "first token should succeed with clamped burst=1"
    );
    assert!(!tb.try_consume(), "second token must fail when burst=1");
}

#[test]
fn token_bucket_never_exceeds_burst() {
    // With rate=1/s a burst of 3 should yield exactly 3 tokens on a fresh
    // bucket, then nothing more (refill is 1ns per second — negligible in a
    // tight loop running for microseconds).
    let burst = 3u32;
    let mut tb = TokenBucket::new(1, burst); // 1 token/sec → ~1ns per token
    let mut consumed = 0;
    for _ in 0..(burst + 10) {
        if tb.try_consume() {
            consumed += 1;
        }
    }
    assert_eq!(
        consumed, burst as usize,
        "fresh bucket must yield exactly burst={} tokens in a tight loop, got {}",
        burst, consumed
    );
}

// -----------------------------------------------------------------------
// purge_connection_routes / idle-timeout cleanup regression tests
// -----------------------------------------------------------------------

fn peer(port: u16) -> SocketAddr {
    format!("127.0.0.1:{}", port).parse().unwrap()
}

fn populated_routing_maps(
    primary: &Arc<[u8]>,
    aliases: &[Arc<[u8]>],
    addr: SocketAddr,
) -> RoutingMaps {
    let mut cid_routes: HashMap<Arc<[u8]>, Arc<[u8]>> = HashMap::new();
    let mut cid_radix = CidRadix::new();
    let mut peer_routes: HashMap<SocketAddr, Arc<[u8]>> = HashMap::new();

    cid_radix.insert(Arc::clone(primary));
    for alias in aliases {
        cid_routes.insert(Arc::clone(alias), Arc::clone(primary));
        cid_radix.insert(Arc::clone(alias));
    }
    peer_routes.insert(addr, Arc::clone(primary));

    (cid_routes, cid_radix, peer_routes)
}

#[test]
fn purge_removes_primary_radix_entry() {
    let primary = cid(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let addr = peer(4433);
    let (mut cid_routes, mut cid_radix, mut peer_routes) =
        populated_routing_maps(&primary, &[], addr);

    purge_connection_routes(
        &mut cid_routes,
        &mut cid_radix,
        &mut peer_routes,
        &primary,
        &HashSet::new(),
        &addr,
    );

    assert!(
        cid_radix.longest_prefix_match(primary.as_ref()).is_none(),
        "primary SCID must be removed from radix after cleanup"
    );
    assert!(
        !peer_routes.contains_key(&addr),
        "peer_routes entry must be removed after cleanup"
    );
}

#[test]
fn purge_removes_all_alias_entries() {
    let primary = cid(&[0xAA; 8]);
    let alias1 = cid(&[0xBB; 8]);
    let alias2 = cid(&[0xCC; 8]);
    let addr = peer(4434);

    let aliases = [Arc::clone(&alias1), Arc::clone(&alias2)];
    let (mut cid_routes, mut cid_radix, mut peer_routes) =
        populated_routing_maps(&primary, &aliases, addr);

    let routing_scids: HashSet<Arc<[u8]>> = aliases.iter().cloned().collect();
    purge_connection_routes(
        &mut cid_routes,
        &mut cid_radix,
        &mut peer_routes,
        &primary,
        &routing_scids,
        &addr,
    );

    assert!(
        !cid_routes.contains_key(alias1.as_ref()),
        "alias1 must be removed from cid_routes"
    );
    assert!(
        !cid_routes.contains_key(alias2.as_ref()),
        "alias2 must be removed from cid_routes"
    );
    assert!(
        cid_radix.longest_prefix_match(alias1.as_ref()).is_none(),
        "alias1 must be removed from radix"
    );
    assert!(
        cid_radix.longest_prefix_match(alias2.as_ref()).is_none(),
        "alias2 must be removed from radix"
    );
    assert!(
        !peer_routes.contains_key(&addr),
        "peer_routes entry must be removed"
    );
}

#[test]
fn repeated_purge_churn_leaves_no_stale_entries() {
    // Simulate repeated connect/timeout/disconnect cycles on distinct
    // connections to verify no entries from prior connections bleed
    // across cycles.
    let mut cid_routes: HashMap<Arc<[u8]>, Arc<[u8]>> = HashMap::new();
    let mut cid_radix = CidRadix::new();
    let mut peer_routes: HashMap<SocketAddr, Arc<[u8]>> = HashMap::new();

    for i in 0u8..20 {
        let primary = cid(&[i, i, i, i, i, i, i, i]);
        let alias = cid(&[
            i | 0x80,
            i | 0x80,
            i | 0x80,
            i | 0x80,
            i | 0x80,
            i | 0x80,
            i | 0x80,
            i | 0x80,
        ]);
        let addr = peer(5000 + u16::from(i));

        // Register
        cid_radix.insert(Arc::clone(&primary));
        cid_radix.insert(Arc::clone(&alias));
        cid_routes.insert(Arc::clone(&alias), Arc::clone(&primary));
        peer_routes.insert(addr, Arc::clone(&primary));

        // Tear down
        let routing_scids: HashSet<Arc<[u8]>> = [Arc::clone(&alias)].into_iter().collect();
        purge_connection_routes(
            &mut cid_routes,
            &mut cid_radix,
            &mut peer_routes,
            &primary,
            &routing_scids,
            &addr,
        );
    }

    assert!(
        cid_routes.is_empty(),
        "cid_routes must be empty after all connections torn down"
    );
    assert!(
        peer_routes.is_empty(),
        "peer_routes must be empty after all connections torn down"
    );
}

#[test]
fn purge_is_idempotent() {
    // Calling purge twice for the same connection must not panic or leave
    // phantom entries.
    let primary = cid(&[0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]);
    let alias = cid(&[0x11, 0x21, 0x31, 0x41, 0x51, 0x61, 0x71, 0x81]);
    let addr = peer(4440);

    let (mut cid_routes, mut cid_radix, mut peer_routes) =
        populated_routing_maps(&primary, &[Arc::clone(&alias)], addr);

    let routing_scids: HashSet<Arc<[u8]>> = [Arc::clone(&alias)].into_iter().collect();

    for _ in 0..2 {
        purge_connection_routes(
            &mut cid_routes,
            &mut cid_radix,
            &mut peer_routes,
            &primary,
            &routing_scids,
            &addr,
        );
    }

    assert!(
        cid_routes.is_empty(),
        "cid_routes must be empty after double purge"
    );
    assert!(
        peer_routes.is_empty(),
        "peer_routes must be empty after double purge"
    );
}

// -----------------------------------------------------------------------
// sweep_closed_connections churn tests
//
// These tests simulate the handle_timeouts removal sweep end-to-end:
// connections are registered in all routing maps, marked as timed-out
// (placed in to_remove), and swept via sweep_closed_connections.  After
// each cycle the invariant is that no stale entries remain in any map.
// -----------------------------------------------------------------------

/// Minimal stand-in for QuicConnection — holds only the routing fields
/// that sweep_closed_connections needs.
struct StubConn {
    primary_scid: Arc<[u8]>,
    routing_scids: HashSet<Arc<[u8]>>,
    peer_address: SocketAddr,
}

fn stub_routes(c: &StubConn) -> ConnectionRoutes {
    ConnectionRoutes {
        primary_scid: Arc::clone(&c.primary_scid),
        routing_scids: c.routing_scids.clone(),
        peer_address: c.peer_address,
    }
}

fn register_stub(
    conn: &StubConn,
    cid_routes: &mut HashMap<Arc<[u8]>, Arc<[u8]>>,
    cid_radix: &mut CidRadix,
    peer_routes: &mut HashMap<SocketAddr, Arc<[u8]>>,
) {
    cid_radix.insert(Arc::clone(&conn.primary_scid));
    for alias in &conn.routing_scids {
        if alias.as_ref() != conn.primary_scid.as_ref() {
            cid_routes.insert(Arc::clone(alias), Arc::clone(&conn.primary_scid));
            cid_radix.insert(Arc::clone(alias));
        }
    }
    peer_routes.insert(conn.peer_address, Arc::clone(&conn.primary_scid));
}

fn assert_maps_empty(
    label: &str,
    connections: &HashMap<Arc<[u8]>, StubConn>,
    cid_routes: &HashMap<Arc<[u8]>, Arc<[u8]>>,
    peer_routes: &HashMap<SocketAddr, Arc<[u8]>>,
) {
    assert!(
        connections.is_empty(),
        "{}: connections must be empty",
        label
    );
    assert!(cid_routes.is_empty(), "{}: cid_routes must be empty", label);
    assert!(
        peer_routes.is_empty(),
        "{}: peer_routes must be empty",
        label
    );
}

#[test]
fn sweep_removes_timed_out_connection_and_all_routes() {
    let primary = cid(&[0x01; 8]);
    let alias = cid(&[0x02; 8]);
    let addr = peer(6000);

    let conn = StubConn {
        primary_scid: Arc::clone(&primary),
        routing_scids: [Arc::clone(&primary), Arc::clone(&alias)]
            .into_iter()
            .collect(),
        peer_address: addr,
    };

    let mut connections: HashMap<Arc<[u8]>, StubConn> = HashMap::new();
    let mut cid_routes = HashMap::new();
    let mut cid_radix = CidRadix::new();
    let mut peer_routes = HashMap::new();

    register_stub(&conn, &mut cid_routes, &mut cid_radix, &mut peer_routes);
    connections.insert(Arc::clone(&primary), conn);

    sweep_closed_connections(
        &mut connections,
        &mut cid_routes,
        &mut cid_radix,
        &mut peer_routes,
        vec![Arc::clone(&primary)],
        stub_routes,
    );

    assert_maps_empty(
        "after single sweep",
        &connections,
        &cid_routes,
        &peer_routes,
    );
    assert!(
        cid_radix.longest_prefix_match(primary.as_ref()).is_none(),
        "primary must be removed from radix"
    );
    assert!(
        cid_radix.longest_prefix_match(alias.as_ref()).is_none(),
        "alias must be removed from radix"
    );
}

#[test]
fn sweep_repeated_timeout_churn_leaves_no_stale_entries() {
    // Simulate N rounds of: connect → timeout → sweep.  After every round
    // all four routing maps must be fully empty — no entries from prior
    // connections bleed into subsequent rounds.
    let rounds = 30usize;

    let mut connections: HashMap<Arc<[u8]>, StubConn> = HashMap::new();
    let mut cid_routes: HashMap<Arc<[u8]>, Arc<[u8]>> = HashMap::new();
    let mut cid_radix = CidRadix::new();
    let mut peer_routes: HashMap<SocketAddr, Arc<[u8]>> = HashMap::new();

    for i in 0..rounds {
        let b = i as u8;
        let primary = cid(&[b, b, b, b, b, b, b, b]);
        let alias1 = cid(&[
            b | 0x80,
            b | 0x80,
            b | 0x80,
            b | 0x80,
            b | 0x80,
            b | 0x80,
            b | 0x80,
            b | 0x80,
        ]);
        let addr = peer(7000 + i as u16);

        let conn = StubConn {
            primary_scid: Arc::clone(&primary),
            routing_scids: [Arc::clone(&primary), Arc::clone(&alias1)]
                .into_iter()
                .collect(),
            peer_address: addr,
        };

        register_stub(&conn, &mut cid_routes, &mut cid_radix, &mut peer_routes);
        connections.insert(Arc::clone(&primary), conn);

        // Simulate handle_timeouts detecting this connection as closed.
        sweep_closed_connections(
            &mut connections,
            &mut cid_routes,
            &mut cid_radix,
            &mut peer_routes,
            vec![Arc::clone(&primary)],
            stub_routes,
        );

        assert_maps_empty(
            &format!("round {}", i),
            &connections,
            &cid_routes,
            &peer_routes,
        );
    }
}

#[test]
fn sweep_partial_batch_clears_only_removed_entries() {
    // Two connections registered; only one timed out.  After sweep the
    // surviving connection's entries must remain intact.
    let p1 = cid(&[0xA1; 8]);
    let p2 = cid(&[0xB1; 8]);
    let addr1 = peer(8001);
    let addr2 = peer(8002);

    let conn1 = StubConn {
        primary_scid: Arc::clone(&p1),
        routing_scids: [Arc::clone(&p1)].into_iter().collect(),
        peer_address: addr1,
    };
    let conn2 = StubConn {
        primary_scid: Arc::clone(&p2),
        routing_scids: [Arc::clone(&p2)].into_iter().collect(),
        peer_address: addr2,
    };

    let mut connections: HashMap<Arc<[u8]>, StubConn> = HashMap::new();
    let mut cid_routes = HashMap::new();
    let mut cid_radix = CidRadix::new();
    let mut peer_routes = HashMap::new();

    register_stub(&conn1, &mut cid_routes, &mut cid_radix, &mut peer_routes);
    register_stub(&conn2, &mut cid_routes, &mut cid_radix, &mut peer_routes);
    connections.insert(Arc::clone(&p1), conn1);
    connections.insert(Arc::clone(&p2), conn2);

    // Only p1 times out.
    sweep_closed_connections(
        &mut connections,
        &mut cid_routes,
        &mut cid_radix,
        &mut peer_routes,
        vec![Arc::clone(&p1)],
        stub_routes,
    );

    assert!(
        !connections.contains_key(p1.as_ref()),
        "timed-out connection must be removed"
    );
    assert!(
        connections.contains_key(p2.as_ref()),
        "surviving connection must remain in connections"
    );
    assert!(
        peer_routes.contains_key(&addr2),
        "surviving connection peer_route must remain"
    );
    assert!(
        !peer_routes.contains_key(&addr1),
        "timed-out connection peer_route must be removed"
    );
    assert!(
        cid_radix.longest_prefix_match(p2.as_ref()).is_some(),
        "surviving connection must remain in radix"
    );
    assert!(
        cid_radix.longest_prefix_match(p1.as_ref()).is_none(),
        "timed-out connection must be removed from radix"
    );
}

// -----------------------------------------------------------------------
// abort_stream / stream teardown path tests (4.2)
//
// These tests exercise the three teardown paths defined in the
// connection-lifecycle spec:
//   (A) client reset before upstream response  (ReceivingRequest /
//       AwaitingUpstream phase)
//   (B) client reset during upstream body streaming (SendingResponse)
//   (C) upstream timeout / error
//
// Each test asserts that abort_stream releases all held resources
// deterministically: permits are dropped, channels are closed, and
// pending chunks are discarded.
// -----------------------------------------------------------------------

use std::time::Instant;

use tokio::sync::{Semaphore, mpsc, oneshot};

use crate::resilience::{adaptive_admission::AdaptiveAdmission, route_queue::RouteQueueLimiter};

fn make_envelope(phase: StreamPhase) -> RequestEnvelope {
    let start = Instant::now();
    match phase {
        StreamPhase::ReceivingRequest => make_dispatch_ready_envelope(start, "GET", false),
        StreamPhase::AwaitingUpstream => make_awaiting_upstream_envelope(start, "GET", false),
        StreamPhase::SendingResponse => make_streaming_envelope(start, StatusCode::OK, None),
        StreamPhase::Completed | StreamPhase::Terminal => {
            panic!("make_envelope is only defined for active execution phases")
        }
    }
}

fn make_request_context(start: Instant, method: &str) -> RequestContext {
    RequestContext {
        request_id: REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed),
        trace_id: None,
        span_id: None,
        traceparent: None,
        trace_span: None,
        method: method.into(),
        path: "/".into(),
        authority: None,
        start,
        total_request_deadline: start + std::time::Duration::from_secs(30),
        terminal_outcome: crate::request_pipeline::TerminalOutcomeGuard::default(),
    }
}

fn make_routing_snapshot() -> RoutingSnapshot {
    RoutingSnapshot {
        backend_addr: "http://127.0.0.1:8080".into(),
        backend_index: 0,
        upstream_name: "api".into(),
        route_reason: "path_prefix".into(),
        route_path_len: 1,
        route_host_specific: false,
        backend_lb: None,
    }
}

fn make_pending_forward(method: &str) -> Arc<PendingForward> {
    Arc::new(PendingForward {
        method: Arc::<str>::from(method),
        path: Arc::<str>::from("/"),
        authority: None,
        route_path_len: 1,
        route_host_specific: false,
        backend_addr: Arc::<str>::from("http://127.0.0.1:8080"),
        client_addr: "127.0.0.1:443".parse().expect("client addr"),
        request_id: 1,
        ..PendingForward::sample_for_test(vec![quiche::h3::Header::new(
            b":method",
            method.as_bytes(),
        )])
    })
}

fn make_body_runtime(start: Instant, request_fin_received: bool) -> RequestBodyRuntime {
    RequestBodyRuntime {
        body_buf: std::collections::VecDeque::new(),
        body_buf_bytes: 0,
        body_bytes_received: 0,
        last_body_activity: start,
        request_fin_received,
    }
}

fn make_test_permits() -> AdmissionPermits {
    let global = Arc::new(Semaphore::new(1))
        .try_acquire_owned()
        .expect("global permit");
    let upstream = Arc::new(Semaphore::new(1))
        .try_acquire_owned()
        .expect("upstream permit");
    let adaptive = Arc::new(AdaptiveAdmission::new(false, 1, 100, 1, 1, 1000))
        .try_acquire()
        .expect("adaptive permit");
    let route_queue = Arc::new(RouteQueueLimiter::new(100, 1000, Default::default()))
        .try_acquire("test")
        .expect("route permit");
    AdmissionPermits {
        global,
        upstream,
        adaptive,
        route_queue,
    }
}

fn make_dispatch_ready_envelope(
    start: Instant,
    method: &str,
    request_fin_received: bool,
) -> RequestEnvelope {
    let context = make_request_context(start, method);
    let routing = make_routing_snapshot();
    RequestEnvelope {
        request_id: context.request_id,
        trace_id: context.trace_id.clone(),
        span_id: context.span_id.clone(),
        traceparent: context.traceparent.clone(),
        trace_span: context.trace_span.clone(),
        method: context.method.clone(),
        path: context.path.clone(),
        authority: context.authority.clone(),
        backend_addr: Some(routing.backend_addr.clone()),
        backend_index: Some(routing.backend_index),
        upstream_name: Some(routing.upstream_name.clone()),
        route_reason: Some(routing.route_reason.clone()),
        route_path_len: Some(routing.route_path_len),
        route_host_specific: Some(routing.route_host_specific),
        backend_lb: routing.backend_lb.clone(),
        upstream_pool: None,
        routing_transparency_enabled: false,
        routing_transparency_include_reason: false,
        response_status: None,
        start: context.start,
        total_request_deadline: context.total_request_deadline,
        bodyless_mode: false,
        tunnel_mode: TunnelMode::None,
        retry_count: 0,
        error_kind: None,
        terminal_overload_reason: None,
        terminal_outcome: context.terminal_outcome.clone(),
        empty_request_body_runtime: RequestBodyRuntime::empty(start),
        execution: RequestExecutionState::DispatchReady(DispatchReadyState {
            context,
            routing,
            request_mode: RequestMode::Normal,
            request_body: if request_fin_received {
                RequestBodyState::FinReceived
            } else {
                RequestBodyState::Open
            },
            request_body_runtime: make_body_runtime(start, request_fin_received),
            pending_forward: make_pending_forward(method),
        }),
    }
}

fn make_admitted_envelope(start: Instant, permits: AdmissionPermits) -> RequestEnvelope {
    let mut req = make_dispatch_ready_envelope(start, "GET", false);
    req.transition_to_admitted(permits)
        .expect("dispatch ready to admitted");
    req
}

fn make_awaiting_upstream_envelope(
    start: Instant,
    method: &str,
    request_fin_received: bool,
) -> RequestEnvelope {
    let mut req = make_admitted_envelope(start, make_test_permits());
    req.method = method.into();
    if let RequestExecutionState::Admitted(state) = &mut req.execution {
        state.context.method = method.into();
        state.request_mode = RequestMode::from_intake(TunnelMode::None, method, None);
        state.pending_forward = make_pending_forward(method);
        state.request_body = if request_fin_received {
            RequestBodyState::FinReceived
        } else {
            RequestBodyState::Open
        };
        state.request_body_runtime.request_fin_received = request_fin_received;
    }
    let (_tx, rx) = oneshot::channel::<crate::runtime::connection::response::UpstreamResult>();
    req.transition_admitted_to_awaiting_upstream(None, rx)
        .expect("admitted to awaiting upstream");
    req
}

fn make_streaming_envelope(
    start: Instant,
    status: StatusCode,
    pending_chunk: Option<crate::runtime::connection::response::ResponseChunk>,
) -> RequestEnvelope {
    let mut req = make_awaiting_upstream_envelope(start, "GET", true);
    let (_tx, rx) = mpsc::channel::<crate::runtime::connection::response::ResponseChunk>(4);
    req.transition_to_streaming_response(rx, ResponseEmissionState::HeadersSent, status)
        .expect("awaiting upstream to streaming response");
    if let Some(chunk) = pending_chunk {
        req.set_pending_chunk(Some(chunk));
    }
    req
}

/// Path A: client reset before upstream response (ReceivingRequest phase).
/// Verifies permits are released and body_tx is dropped.
#[test]
fn abort_stream_receiving_request_releases_permits() {
    let metrics = crate::Metrics::default();
    let global_sem = Arc::new(Semaphore::new(1));
    let upstream_sem = Arc::new(Semaphore::new(1));
    let adaptive = Arc::new(AdaptiveAdmission::new(false, 1, 100, 1, 1, 1000));
    let route_limiter = Arc::new(RouteQueueLimiter::new(100, 1000, Default::default()));

    let global_permit = global_sem.clone().try_acquire_owned().unwrap();
    let upstream_permit = upstream_sem.clone().try_acquire_owned().unwrap();
    let adaptive_permit = adaptive.try_acquire().unwrap();
    let route_permit = route_limiter.try_acquire("test").unwrap();

    let mut req = make_admitted_envelope(
        Instant::now(),
        AdmissionPermits {
            global: global_permit,
            upstream: upstream_permit,
            adaptive: adaptive_permit,
            route_queue: route_permit,
        },
    );

    let phase = terminalize_stream(
        &mut req,
        TerminalReason::Cancelled(CancellationReason::ClientReset),
        &metrics,
    );

    assert_eq!(phase, StreamPhase::ReceivingRequest);

    // Permits released: semaphores should be available again.
    assert_eq!(
        global_sem.available_permits(),
        1,
        "global semaphore must be freed"
    );
    assert_eq!(
        upstream_sem.available_permits(),
        1,
        "upstream semaphore must be freed"
    );

    // All permit ownership should be released.
    assert!(!req.has_global_inflight_permit());
    assert!(!req.has_upstream_inflight_permit());
    assert!(!req.has_adaptive_admission_permit());
    assert!(!req.has_route_queue_permit());
}

#[test]
fn abort_stream_waiting_for_auth_clears_async_auth_state() {
    let metrics = crate::Metrics::default();
    let (auth_tx, auth_rx) =
        oneshot::channel::<crate::runtime::connection::auth::ExternalAuthResult>();
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let auth_task = runtime.spawn(async {});
    let mut req = make_envelope(StreamPhase::ReceivingRequest);
    req.execution = RequestExecutionState::AwaitingAuth(AwaitingAuthState {
        context: crate::runtime::connection::stream::RequestContext {
            request_id: req.request_id,
            trace_id: req.trace_id.clone(),
            span_id: req.span_id.clone(),
            traceparent: req.traceparent.clone(),
            trace_span: req.trace_span.clone(),
            method: req.method.clone(),
            path: req.path.clone(),
            authority: req.authority.clone(),
            start: req.start,
            total_request_deadline: req.total_request_deadline,
            terminal_outcome: req.terminal_outcome.clone(),
        },
        routing: RoutingSnapshot {
            backend_addr: "http://127.0.0.1:8080".into(),
            backend_index: 0,
            upstream_name: "api".into(),
            route_reason: "path_prefix".into(),
            route_path_len: 7,
            route_host_specific: false,
            backend_lb: None,
        },
        request_mode: RequestMode::Normal,
        request_body: RequestBodyState::Open,
        request_body_runtime: RequestBodyRuntime {
            body_buf: std::collections::VecDeque::new(),
            body_buf_bytes: 0,
            body_bytes_received: 0,
            last_body_activity: req.start,
            request_fin_received: false,
        },
        pending_forward: Arc::new(crate::runtime::connection::request::PendingForward {
            method: Arc::<str>::from("POST"),
            path: Arc::<str>::from("/upload"),
            authority: Some(Arc::<str>::from("example.com")),
            route_path_len: 1,
            route_host_specific: false,
            backend_addr: Arc::<str>::from("http://127.0.0.1:8080"),
            client_addr: "127.0.0.1:443".parse().expect("client addr"),
            request_id: 42,
            ..crate::runtime::connection::request::PendingForward::sample_for_test(vec![
                quiche::h3::Header::new(b":method", b"POST"),
            ])
        }),
        auth_result_rx: auth_rx,
        auth_abort: auth_task.abort_handle(),
        auth_deadline: Instant::now() + std::time::Duration::from_secs(1),
        auth_disposition:
            crate::runtime::connection::auth::ExternalAuthFailureDisposition::FailClosed,
    });

    let phase = terminalize_stream(
        &mut req,
        TerminalReason::Cancelled(CancellationReason::ClientReset),
        &metrics,
    );

    assert_eq!(phase, StreamPhase::ReceivingRequest);
    assert_ne!(req.admission_state(), StreamAdmissionState::WaitingForAuth);
    assert!(
        auth_tx
            .send(Ok(
                crate::runtime::connection::auth::ExternalAuthDecision::Allow {
                    request_header_mutations: Vec::new(),
                }
            ))
            .is_err()
    );
}
/// Path A (variant): client reset while awaiting upstream response.
/// Dropping upstream_result_rx cancels the oneshot — the upstream task's
/// send will return Err and it will exit.
#[test]
fn abort_stream_awaiting_upstream_cancels_oneshot() {
    let metrics = crate::Metrics::default();
    let (result_tx, result_rx) =
        oneshot::channel::<crate::runtime::connection::response::UpstreamResult>();

    let start = Instant::now();
    let mut req = make_admitted_envelope(start, make_test_permits());
    req.transition_admitted_to_awaiting_upstream(None, result_rx)
        .expect("admitted to awaiting upstream");

    let phase = terminalize_stream(
        &mut req,
        TerminalReason::Cancelled(CancellationReason::ClientReset),
        &metrics,
    );

    assert_eq!(phase, StreamPhase::AwaitingUpstream);
    assert!(
        !req.has_upstream_result_rx(),
        "oneshot receiver must be cleared"
    );

    // Sending on the now-orphaned sender should return Err (closed).
    let send_result = result_tx.send(crate::runtime::connection::response::UpstreamResult {
        forward: Err(impulse_errors::ProxyError::Transport("test".into())),
        policy: crate::runtime::connection::response::ForwardingPolicyTelemetry::default(),
    });
    assert!(
        send_result.is_err(),
        "upstream task send must fail after receiver dropped"
    );
}

/// Path B: client reset during body streaming (SendingResponse phase).
/// Dropping response_chunk_rx causes the body-pump task's next send to
/// return Err, making the task exit promptly.
#[test]
fn abort_stream_sending_response_closes_chunk_channel() {
    let metrics = crate::Metrics::default();
    let (chunk_tx, chunk_rx) =
        mpsc::channel::<crate::runtime::connection::response::ResponseChunk>(4);

    let start = Instant::now();
    let mut req = make_awaiting_upstream_envelope(start, "GET", true);
    req.transition_to_streaming_response(
        chunk_rx,
        ResponseEmissionState::HeadersSent,
        StatusCode::OK,
    )
    .expect("awaiting upstream to streaming response");
    req.set_pending_chunk(Some(
        crate::runtime::connection::response::ResponseChunk::End,
    ));

    let phase = terminalize_stream(
        &mut req,
        TerminalReason::Cancelled(CancellationReason::ClientReset),
        &metrics,
    );

    assert_eq!(phase, StreamPhase::SendingResponse);
    assert!(
        !req.has_response_chunk_rx(),
        "chunk receiver must be cleared"
    );
    assert!(!req.has_pending_chunk(), "pending chunk must be discarded");

    // The body-pump task's sender should observe a closed channel.
    let send_result = chunk_tx.try_send(crate::runtime::connection::response::ResponseChunk::End);
    assert!(
        send_result.is_err(),
        "body-pump task send must fail after receiver dropped"
    );
}

/// Path C: upstream timeout / error tears down all resources regardless
/// of which fields are populated.
#[test]
fn abort_stream_upstream_error_releases_all_resources() {
    let metrics = crate::Metrics::default();
    let global_sem = Arc::new(Semaphore::new(2));
    let upstream_sem = Arc::new(Semaphore::new(2));

    let global_permit = global_sem.clone().try_acquire_owned().unwrap();
    let upstream_permit = upstream_sem.clone().try_acquire_owned().unwrap();

    let (chunk_tx, chunk_rx) =
        mpsc::channel::<crate::runtime::connection::response::ResponseChunk>(4);

    let adaptive = Arc::new(AdaptiveAdmission::new(false, 1, 100, 1, 1, 1000));
    let route_limiter = Arc::new(RouteQueueLimiter::new(100, 1000, Default::default()));
    let mut req = make_admitted_envelope(
        Instant::now(),
        AdmissionPermits {
            global: global_permit,
            upstream: upstream_permit,
            adaptive: adaptive.try_acquire().unwrap(),
            route_queue: route_limiter.try_acquire("test").unwrap(),
        },
    );
    req.transition_admitted_to_awaiting_upstream(None, oneshot::channel().1)
        .expect("admitted to awaiting upstream");
    req.transition_to_streaming_response(
        chunk_rx,
        ResponseEmissionState::HeadersSent,
        StatusCode::OK,
    )
    .expect("awaiting upstream to streaming response");
    req.set_pending_chunk(Some(
        crate::runtime::connection::response::ResponseChunk::End,
    ));

    let phase = terminalize_stream(
        &mut req,
        TerminalReason::BackendFailed(BackendFailureReason::UpstreamTransport),
        &metrics,
    );

    assert_eq!(phase, StreamPhase::SendingResponse);
    assert_eq!(
        global_sem.available_permits(),
        2,
        "global semaphore must be fully freed"
    );
    assert_eq!(
        upstream_sem.available_permits(),
        2,
        "upstream semaphore must be fully freed"
    );
    assert!(!req.has_response_chunk_rx());
    assert!(!req.has_pending_chunk());

    // Body-pump task sender sees closed channel.
    assert!(
        chunk_tx
            .try_send(crate::runtime::connection::response::ResponseChunk::End)
            .is_err()
    );
}

/// Verify abort_stream is idempotent: calling it twice must not panic or
/// double-decrement any semaphore.
#[test]
fn abort_stream_is_idempotent() {
    let metrics = crate::Metrics::default();
    let global_sem = Arc::new(Semaphore::new(1));
    let permit = global_sem.clone().try_acquire_owned().unwrap();
    let upstream_sem = Arc::new(Semaphore::new(1));
    let adaptive = Arc::new(AdaptiveAdmission::new(false, 1, 100, 1, 1, 1000));
    let route_limiter = Arc::new(RouteQueueLimiter::new(100, 1000, Default::default()));
    let mut req = make_admitted_envelope(
        Instant::now(),
        AdmissionPermits {
            global: permit,
            upstream: upstream_sem.try_acquire_owned().unwrap(),
            adaptive: adaptive.try_acquire().unwrap(),
            route_queue: route_limiter.try_acquire("test").unwrap(),
        },
    );

    terminalize_stream(
        &mut req,
        TerminalReason::Cancelled(CancellationReason::ConnectionClosed),
        &metrics,
    );
    terminalize_stream(
        &mut req,
        TerminalReason::Cancelled(CancellationReason::ConnectionClosed),
        &metrics,
    ); // second call must be a no-op

    assert_eq!(
        global_sem.available_permits(),
        1,
        "must not double-release permit"
    );
}

#[test]
fn traceparent_parser_accepts_valid_value() {
    let parsed =
        super::parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
    assert!(parsed.is_some());
}

#[test]
fn traceparent_parser_rejects_invalid_value() {
    let parsed = super::parse_traceparent("00-xyz-123-01");
    assert!(parsed.is_none());
}

#[test]
fn inflight_micro_wait_acquires_available_permit_without_blocking() {
    let semaphore = Arc::new(Semaphore::new(1));
    let acquired = super::admission::try_acquire_owned_with_micro_wait(
        Arc::clone(&semaphore),
        Duration::from_millis(50),
    );
    let (_permit, waited) = acquired.expect("permit should be acquired");
    assert!(!waited, "acquire must never block the worker thread");
}

#[test]
fn inflight_micro_wait_times_out_without_permit() {
    let semaphore = Arc::new(Semaphore::new(1));
    let _held = semaphore
        .clone()
        .try_acquire_owned()
        .expect("acquire initial permit");

    let acquired = super::admission::try_acquire_owned_with_micro_wait(
        Arc::clone(&semaphore),
        Duration::from_millis(1),
    );
    assert!(acquired.is_err());
}
