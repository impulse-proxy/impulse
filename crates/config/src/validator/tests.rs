use std::collections::HashMap;

use rcgen::{Certificate, CertificateParams, SanType};
use tempfile::tempdir;

use super::validate;
use crate::config::{
    ApiKeyAuth, Backend, ClientAuth, Config, ControlApi, ControlApiAuditSink,
    ControlApiBearerToken, ControlApiClientAuthMode, ControlApiRole, ExternalAuth,
    ExternalAuthFailureMode, ExternalAuthRequestHeader, HealthCheck, JwtAlgorithm, JwtAuth,
    JwtVerificationKey, Listen, LoadBalancing, Log, LogFormat, MetricsEndpoint, Observability,
    Performance, Resilience, RouteAuth, RouteMatch, ScopedRateLimit, ScopedRateLimitScope,
    SecretRef, Security, Tls, TlsCertificate, Tracing, Upstream, UpstreamTls,
};

fn write_test_certs(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let mut params = CertificateParams::new(vec!["localhost".into()]);
    params
        .subject_alt_names
        .push(SanType::IpAddress("127.0.0.1".parse().expect("ip")));
    let cert = Certificate::from_params(params).expect("failed to build cert");

    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");

    std::fs::write(&cert_path, cert.serialize_pem().expect("serialize cert")).expect("write cert");
    std::fs::write(&key_path, cert.serialize_private_key_pem()).expect("write key");

    (cert_path, key_path)
}

fn base_config(cert: &str, key: &str) -> Config {
    let mut upstream = HashMap::new();
    upstream.insert(
        "test_upstream".to_string(),
        Upstream {
            load_balancing: LoadBalancing {
                lb_type: "round-robin".to_string(),
                key: None,
            },
            auth: Default::default(),
            host_policy: Default::default(),
            forwarded_headers: Default::default(),
            compression: Default::default(),
            cache: Default::default(),
            tls: None,
            route: RouteMatch {
                host: None,
                path_prefix: Some("/".to_string()),
                method: None,
            },
            backends: vec![Backend {
                id: "backend-1".to_string(),
                address: "127.0.0.1:8080".to_string(),
                weight: 1,
                health_check: Some(HealthCheck {
                    path: "/health".to_string(),
                    interval: 1000,
                    timeout_ms: 1000,
                    failure_threshold: 3,
                    success_threshold: 1,
                    cooldown_ms: 1000,
                }),
            }],
        },
    );

    Config {
        version: 1,
        listen: Listen {
            protocol: "http3".to_string(),
            port: 9889,
            address: "127.0.0.1".to_string(),
            tls: Tls {
                cert: cert.to_string(),
                key: key.to_string(),
                certificates: vec![],
                client_auth: ClientAuth::default(),
            },
        },
        listeners: vec![],
        upstream,
        load_balancing: Some(LoadBalancing {
            lb_type: "random".to_string(),
            key: None,
        }),
        upstream_tls: UpstreamTls::default(),
        secrets: Default::default(),
        log: Log {
            level: "info".to_string(),
            file: Default::default(),
            format: LogFormat::Plain,
        },
        performance: Performance::default(),
        observability: Observability::default(),
        resilience: Resilience::default(),
        security: Security::default(),
    }
}

#[test]
fn yaml_parse_rejects_invalid_control_api_mtls_mode() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let yaml = format!(
        r#"
version: 1
listen:
  protocol: http3
  address: "127.0.0.1"
  port: 9889
  tls:
    cert: "{}"
    key: "{}"
upstream:
  test_upstream:
    load_balancing:
      type: round-robin
    route:
      path_prefix: "/"
    backends:
      - id: "b1"
        address: "127.0.0.1:8080"
        weight: 1
observability:
  control_api:
    enabled: true
    auth_token: "token"
    tls:
      client_auth:
        mode: "not_a_real_mode"
        ca_file: "{}"
"#,
        cert.to_string_lossy(),
        key.to_string_lossy(),
        cert.to_string_lossy(),
    );

    assert!(serde_yaml::from_str::<Config>(&yaml).is_err());
}

#[test]
fn yaml_parse_rejects_invalid_control_api_role_name() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let yaml = format!(
        r#"
version: 1
listen:
  protocol: http3
  address: "127.0.0.1"
  port: 9889
  tls:
    cert: "{}"
    key: "{}"
upstream:
  test_upstream:
    load_balancing:
      type: round-robin
    route:
      path_prefix: "/"
    backends:
      - id: "b1"
        address: "127.0.0.1:8080"
        weight: 1
observability:
  control_api:
    enabled: true
    auth:
      bearer_tokens:
        - token: "viewer-token"
          role: "super_admin"
"#,
        cert.to_string_lossy(),
        key.to_string_lossy(),
    );

    assert!(serde_yaml::from_str::<Config>(&yaml).is_err());
}

#[test]
fn yaml_parse_applies_performance_and_observability_defaults() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let yaml = format!(
        r#"
version: 1
listen:
  protocol: http3
  address: "127.0.0.1"
  port: 9889
  tls:
    cert: "{}"
    key: "{}"
upstream:
  test_upstream:
    load_balancing:
      type: round-robin
    route:
      path_prefix: "/"
    backends:
      - id: "b1"
        address: "127.0.0.1:8080"
        weight: 1
        health_check: {{}}
"#,
        cert.display(),
        key.display()
    );

    let cfg: Config = serde_yaml::from_str(&yaml).expect("parse");
    assert_eq!(cfg.performance.worker_threads, 1);
    assert_eq!(cfg.performance.control_plane_threads, 2);
    assert_eq!(cfg.performance.packet_shards_per_worker, 1);
    assert_eq!(cfg.performance.packet_shard_queue_capacity, 2048);
    assert_eq!(
        cfg.performance.packet_shard_queue_max_bytes,
        64 * 1024 * 1024
    );
    assert!(cfg.performance.reuseport);
    assert!(!cfg.performance.pin_workers);
    assert_eq!(cfg.performance.global_inflight_limit, 4096);
    assert_eq!(cfg.performance.per_upstream_inflight_limit, 1024);
    assert_eq!(cfg.performance.backend_timeout_ms, 2000);
    assert_eq!(cfg.performance.backend_connect_timeout_ms, 500);
    assert_eq!(cfg.performance.backend_body_idle_timeout_ms, 2000);
    assert_eq!(cfg.performance.backend_body_total_timeout_ms, 30000);
    assert_eq!(cfg.performance.backend_total_request_timeout_ms, 35_000);
    assert_eq!(cfg.performance.shutdown_drain_timeout_ms, 5_000);
    assert_eq!(cfg.performance.udp_recv_buffer_bytes, 8 * 1024 * 1024);
    assert_eq!(cfg.performance.udp_send_buffer_bytes, 8 * 1024 * 1024);
    assert_eq!(cfg.performance.h2_pool_max_idle_per_backend, 256);
    assert_eq!(cfg.performance.h2_pool_idle_timeout_ms, 90_000);
    assert!(!cfg.performance.backend_dns_refresh_enabled);
    assert_eq!(cfg.performance.backend_dns_refresh_interval_ms, 30_000);
    assert_eq!(cfg.performance.per_backend_inflight_limit, 64);
    assert_eq!(cfg.performance.max_active_connections, 20_000);
    assert_eq!(cfg.performance.max_request_body_bytes, 1_000_000);
    assert_eq!(
        cfg.performance.request_buffer_global_cap_bytes,
        64 * 1024 * 1024
    );
    assert_eq!(
        cfg.performance.unknown_length_response_prebuffer_bytes,
        2 * 1024 * 1024
    );
    assert_eq!(cfg.performance.client_body_idle_timeout_ms, 10_000);
    assert!(!cfg.observability.metrics.enabled);
    assert_eq!(cfg.observability.metrics.path, "/metrics");
    assert_eq!(cfg.observability.metrics.max_connections, 512);
    assert_eq!(cfg.observability.metrics.connection_timeout_ms, 30_000);
    assert!(cfg.upstream_tls.verify_certificates);
    assert!(cfg.upstream_tls.strict_sni);
    assert!(!cfg.listen.tls.client_auth.enabled);
    assert!(!cfg.listen.tls.client_auth.require_client_cert);
    assert!(cfg.listen.tls.client_auth.ca_file.is_none());
    assert!(cfg.resilience.adaptive_admission.enabled);
    assert!(cfg.resilience.adaptive_admission.max_limit.is_none());
    assert_eq!(cfg.resilience.route_queue.default_cap, 512);
    assert_eq!(cfg.resilience.route_queue.global_cap, 2048);
    assert_eq!(cfg.resilience.route_queue.shed_retry_after_seconds, 1);
    assert!(!cfg.resilience.protocol.allow_0rtt);
    assert!(!cfg.resilience.protocol.allow_connect);
    assert_eq!(cfg.resilience.protocol.max_headers_count, 128);
    assert_eq!(cfg.resilience.protocol.max_headers_bytes, 16 * 1024);
    assert!(cfg.resilience.protocol.enforce_authority_host_match);
    assert!(cfg.resilience.protocol.connect_allowed_ports.is_empty());
    assert!(
        cfg.resilience
            .protocol
            .connect_allowed_authorities
            .is_empty()
    );
    assert!(!cfg.resilience.watchdog.enabled);
    assert_eq!(cfg.resilience.watchdog.check_interval_ms, 1_000);
    assert_eq!(cfg.observability.control_api.max_connections, 256);
    assert_eq!(cfg.observability.control_api.connection_timeout_ms, 30_000);
}

#[test]
fn yaml_parse_applies_external_auth_defaults() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let yaml = format!(
        r#"
version: 1
listen:
  protocol: http3
  address: "127.0.0.1"
  port: 9889
  tls:
    cert: "{}"
    key: "{}"
upstream:
  test_upstream:
    auth:
      external_auth:
        kind: http
        endpoint: "https://auth.internal/check"
    route:
      path_prefix: "/"
    backends:
      - id: "b1"
        address: "127.0.0.1:8080"
        weight: 1
        health_check: {{}}
"#,
        cert.display(),
        key.display()
    );

    let cfg: Config = serde_yaml::from_str(&yaml).expect("parse");
    let auth = &cfg.upstream.get("test_upstream").expect("upstream").auth;

    match auth.external_auth.as_ref() {
        Some(ExternalAuth::Http {
            endpoint,
            request_headers,
            response_header_allowlist,
            timeout_ms,
            ..
        }) => {
            assert_eq!(endpoint, "https://auth.internal/check");
            assert!(request_headers.is_empty());
            assert!(response_header_allowlist.is_empty());
            assert_eq!(*timeout_ms, 1_000);
        }
        other => panic!("unexpected external auth config: {:?}", other),
    }
}

#[test]
fn yaml_parse_applies_oidc_external_auth_defaults() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let yaml = format!(
        r#"
version: 1
listen:
  protocol: http3
  address: "127.0.0.1"
  port: 9889
  tls:
    cert: "{}"
    key: "{}"
upstream:
  test_upstream:
    auth:
      external_auth:
        kind: oidc
        discovery_url: "https://issuer.example.com/.well-known/openid-configuration"
        client_id: "edge-gateway"
    route:
      path_prefix: "/"
    backends:
      - id: "b1"
        address: "127.0.0.1:8080"
        weight: 1
        health_check: {{}}
"#,
        cert.display(),
        key.display()
    );

    let cfg: Config = serde_yaml::from_str(&yaml).expect("parse");
    match cfg
        .upstream
        .get("test_upstream")
        .expect("upstream")
        .auth
        .external_auth
        .as_ref()
    {
        Some(ExternalAuth::Oidc {
            discovery_url,
            issuer_url,
            client_id,
            client_secret,
            audience,
            scopes,
            request_headers,
            response_header_allowlist,
            timeout_ms,
            ..
        }) => {
            assert_eq!(
                discovery_url.as_deref(),
                Some("https://issuer.example.com/.well-known/openid-configuration")
            );
            assert_eq!(issuer_url, &None);
            assert_eq!(client_id, "edge-gateway");
            assert_eq!(client_secret, &None);
            assert_eq!(audience, &None);
            assert!(scopes.is_empty());
            assert!(request_headers.is_empty());
            assert!(response_header_allowlist.is_empty());
            assert_eq!(*timeout_ms, 1_000);
        }
        other => panic!("unexpected external auth config: {:?}", other),
    }
}

#[test]
fn yaml_parse_rejects_unknown_external_auth_field() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let yaml = format!(
        r#"
version: 1
listen:
  protocol: http3
  address: "127.0.0.1"
  port: 9889
  tls:
    cert: "{}"
    key: "{}"
upstream:
  test_upstream:
    auth:
      external_auth:
        kind: http
        endpoint: "https://auth.internal/check"
        unexpected: true
    route:
      path_prefix: "/"
    backends:
      - id: "b1"
        address: "127.0.0.1:8080"
        weight: 1
        health_check: {{}}
"#,
        cert.display(),
        key.display()
    );

    assert!(serde_yaml::from_str::<Config>(&yaml).is_err());
}

#[test]
fn rejects_invalid_performance_and_observability_values() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.worker_threads = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.worker_threads = 4;
    cfg.performance.reuseport = false;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.packet_shards_per_worker = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.packet_shard_queue_capacity = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.packet_shard_queue_max_bytes = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.backend_connect_timeout_ms = 2_001;
    cfg.performance.backend_timeout_ms = 2_000;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.backend_total_request_timeout_ms = 5_000;
    cfg.performance.backend_body_total_timeout_ms = 6_000;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.backend_body_total_timeout_ms = 100;
    cfg.performance.backend_body_idle_timeout_ms = 200;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.shutdown_drain_timeout_ms = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.udp_recv_buffer_bytes = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.udp_send_buffer_bytes = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.h2_pool_max_idle_per_backend = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.h2_pool_idle_timeout_ms = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.backend_dns_refresh_interval_ms = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.per_backend_inflight_limit = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.new_connections_per_sec = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.new_connections_burst = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.max_active_connections = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.quic_max_idle_timeout_ms = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.quic_initial_max_data = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.quic_initial_max_stream_data = 0;
    assert!(validate(&cfg).is_err());

    // stream limit exceeds connection limit — cross-field violation
    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.quic_initial_max_data = 1_000_000;
    cfg.performance.quic_initial_max_stream_data = 2_000_000;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.quic_initial_max_streams_bidi = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.quic_initial_max_streams_uni = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.max_response_body_bytes = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.max_request_body_bytes = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.request_buffer_global_cap_bytes = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.unknown_length_response_prebuffer_bytes = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.client_body_idle_timeout_ms = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.max_request_body_bytes =
        (cfg.performance.quic_initial_max_stream_data as usize).saturating_add(1);
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.request_buffer_global_cap_bytes =
        cfg.performance.max_request_body_bytes.saturating_sub(1);
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.unknown_length_response_prebuffer_bytes =
        cfg.performance.max_response_body_bytes.saturating_add(1);
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.adaptive_admission.max_limit = Some(0);
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.adaptive_admission.max_limit = Some(
        cfg.resilience
            .adaptive_admission
            .min_limit
            .saturating_sub(1),
    );
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.adaptive_admission.max_limit =
        Some(cfg.performance.global_inflight_limit.saturating_add(1));
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.route_queue.default_cap = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.route_queue.global_cap = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.route_queue.shed_retry_after_seconds = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.protocol.max_headers_count = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.protocol.max_headers_bytes = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.protocol.allow_0rtt = true;
    cfg.resilience.protocol.early_data_safe_methods.clear();
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.protocol.allow_0rtt = true;
    cfg.resilience.protocol.early_data_safe_methods = vec!["POST".to_string()];
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.protocol.allow_0rtt = true;
    cfg.resilience.protocol.early_data_safe_methods = vec!["bad method".to_string()];
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.protocol.denied_path_prefixes = vec!["admin".to_string()];
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.protocol.connect_allowed_ports = vec![443];
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.protocol.allow_connect = true;
    cfg.resilience.protocol.connect_allowed_ports = vec![0];
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.protocol.allow_connect = true;
    cfg.resilience.protocol.connect_allowed_authorities = vec!["example.com".to_string()];
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.protocol.allow_connect = true;
    cfg.resilience.protocol.connect_allowed_authorities = vec!["example.com:443".to_string()];
    cfg.resilience.protocol.connect_allowed_ports = vec![443];
    assert!(validate(&cfg).is_ok());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.protocol.allowed_methods = vec!["".to_string()];
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.protocol.allowed_methods = vec!["GE T".to_string()];
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.protocol.allowed_methods = vec!["GET/".to_string()];
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.protocol.allowed_methods = vec!["GE\nT".to_string()];
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.retry_budget.ratio_percent = 101;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.brownout.trigger_inflight_percent = 50;
    cfg.resilience.brownout.recover_inflight_percent = 50;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.watchdog.timeout_error_rate_percent = 101;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.watchdog.unhealthy_consecutive_windows = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.listen.tls.client_auth.require_client_cert = true;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.listen.tls.client_auth.enabled = true;
    cfg.listen.tls.client_auth.ca_file = None;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream_tls.verify_certificates = false;
    assert!(validate(&cfg).is_ok());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream_tls.ca_file = Some("/path/does/not/exist.pem".to_string());
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream_tls.ca_dir = Some("/path/does/not/exist".to_string());
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability = Observability {
        metrics: MetricsEndpoint {
            enabled: true,
            required: false,
            address: "127.0.0.1".to_string(),
            allow_non_loopback: false,
            port: 9901,
            path: "metrics".to_string(),
            max_connections: 128,
            connection_timeout_ms: 10_000,
        },
        control_api: ControlApi::default(),
        tracing: Tracing::default(),
        routing: crate::config::RoutingTransparency::default(),
    };
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.metrics.enabled = true;
    cfg.observability.metrics.max_connections = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.metrics.enabled = true;
    cfg.observability.metrics.connection_timeout_ms = 0;
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.metrics.enabled = true;
    cfg.observability.metrics.address = "0.0.0.0".to_string();
    assert!(validate(&cfg).is_err());

    cfg.observability.metrics.allow_non_loopback = true;
    assert!(validate(&cfg).is_err());

    cfg.observability.control_api.tls.client_auth.mode = ControlApiClientAuthMode::Required;
    cfg.observability.control_api.tls.client_auth.ca_file =
        Some(cert.to_string_lossy().to_string());
    assert!(validate(&cfg).is_ok());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.control_api.enabled = true;
    cfg.observability.control_api.max_connections = 0;
    cfg.observability.control_api.auth_token = Some("token".to_string());
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.control_api.enabled = true;
    cfg.observability.control_api.connection_timeout_ms = 0;
    cfg.observability.control_api.auth_token = Some("token".to_string());
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.routing.expose_header = true;
    cfg.observability.routing.header_name = "   ".to_string();
    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_unparseable_tls_material() {
    let dir = tempdir().expect("tempdir");
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&cert, "not-a-pem-cert").expect("write cert");
    std::fs::write(&key, "not-a-pem-key").expect("write key");

    let cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_oversized_pem_certificate_material() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    std::fs::write(&cert, vec![b'x'; (1024 * 1024) + 1]).expect("write oversized cert");

    let cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    let err = validate(&cfg).expect_err("oversized cert must fail validation");

    assert!(
        err.to_string()
            .contains("exceeds the maximum supported PEM size")
    );
}

#[test]
fn rejects_oversized_pem_private_key_material() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    std::fs::write(&key, vec![b'x'; (1024 * 1024) + 1]).expect("write oversized key");

    let cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    let err = validate(&cfg).expect_err("oversized key must fail validation");

    assert!(
        err.to_string()
            .contains("exceeds the maximum supported PEM size")
    );
}

#[test]
fn accepts_valid_tls_material_after_bounded_pem_validation() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());

    assert!(validate(&cfg).is_ok());
}

#[test]
fn accepts_sni_certificates_without_legacy_cert_pair() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.listen.tls.cert = String::new();
    cfg.listen.tls.key = String::new();
    cfg.listen.tls.certificates = vec![TlsCertificate {
        server_name: "api.example.com".to_string(),
        cert: cert.to_string_lossy().to_string(),
        key: key.to_string_lossy().to_string(),
    }];

    assert!(validate(&cfg).is_ok());
}

#[test]
fn rejects_duplicate_sni_certificate_server_names() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.listen.tls.certificates = vec![
        TlsCertificate {
            server_name: "api.example.com".to_string(),
            cert: cert.to_string_lossy().to_string(),
            key: key.to_string_lossy().to_string(),
        },
        TlsCertificate {
            server_name: "API.EXAMPLE.COM".to_string(),
            cert: cert.to_string_lossy().to_string(),
            key: key.to_string_lossy().to_string(),
        },
    ];

    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_invalid_sni_certificate_server_name() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.listen.tls.certificates = vec![TlsCertificate {
        server_name: "not a hostname".to_string(),
        cert: cert.to_string_lossy().to_string(),
        key: key.to_string_lossy().to_string(),
    }];

    assert!(validate(&cfg).is_err());
}

#[test]
fn accepts_valid_metrics_and_performance_configuration() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.performance.worker_threads = 4;
    cfg.performance.control_plane_threads = 2;
    cfg.performance.packet_shards_per_worker = 2;
    cfg.performance.packet_shard_queue_capacity = 1024;
    cfg.performance.packet_shard_queue_max_bytes = 16 * 1024 * 1024;
    cfg.performance.reuseport = true;
    cfg.performance.pin_workers = true;
    cfg.performance.global_inflight_limit = 10_000;
    cfg.performance.per_upstream_inflight_limit = 2_000;
    cfg.performance.backend_connect_timeout_ms = 300;
    cfg.performance.backend_timeout_ms = 1500;
    cfg.performance.backend_body_idle_timeout_ms = 2_500;
    cfg.performance.backend_body_total_timeout_ms = 10_000;
    cfg.performance.backend_total_request_timeout_ms = 15_000;
    cfg.performance.shutdown_drain_timeout_ms = 7_500;
    cfg.performance.udp_recv_buffer_bytes = 4 * 1024 * 1024;
    cfg.performance.udp_send_buffer_bytes = 4 * 1024 * 1024;
    cfg.performance.h2_pool_max_idle_per_backend = 128;
    cfg.performance.h2_pool_idle_timeout_ms = 120_000;
    cfg.performance.per_backend_inflight_limit = 32;
    cfg.performance.max_active_connections = 50_000;
    cfg.performance.max_request_body_bytes = 512 * 1024;
    cfg.performance.request_buffer_global_cap_bytes = 8 * 1024 * 1024;
    cfg.performance.unknown_length_response_prebuffer_bytes = 512 * 1024;
    cfg.performance.client_body_idle_timeout_ms = 7_500;
    cfg.resilience.adaptive_admission.max_limit = Some(1024);
    cfg.resilience.route_queue.default_cap = 256;
    cfg.resilience.route_queue.global_cap = 2048;
    cfg.resilience.route_queue.shed_retry_after_seconds = 2;
    cfg.resilience.protocol.allow_0rtt = true;
    cfg.resilience.protocol.early_data_safe_methods = vec!["GET".to_string()];
    cfg.resilience.protocol.max_headers_count = 64;
    cfg.resilience.protocol.max_headers_bytes = 8 * 1024;
    cfg.resilience.protocol.allowed_methods = vec!["GET".to_string(), "POST".to_string()];
    cfg.resilience.protocol.denied_path_prefixes = vec!["/admin".to_string()];
    cfg.resilience.retry_budget.ratio_percent = 30;
    cfg.upstream_tls.verify_certificates = true;
    cfg.upstream_tls.strict_sni = true;
    cfg.upstream_tls.ca_file = Some(cert.to_string_lossy().to_string());
    cfg.upstream_tls.ca_dir = Some(dir.path().to_string_lossy().to_string());
    cfg.listen.tls.client_auth.enabled = true;
    cfg.listen.tls.client_auth.require_client_cert = true;
    cfg.listen.tls.client_auth.ca_file = Some(cert.to_string_lossy().to_string());
    cfg.observability = Observability {
        metrics: MetricsEndpoint {
            enabled: true,
            required: false,
            address: "127.0.0.1".to_string(),
            allow_non_loopback: false,
            port: 9901,
            path: "/metrics".to_string(),
            max_connections: 128,
            connection_timeout_ms: 10_000,
        },
        control_api: ControlApi::default(),
        tracing: Tracing::default(),
        routing: crate::config::RoutingTransparency::default(),
    };

    assert!(validate(&cfg).is_ok());
}

#[test]
fn skips_unused_global_upstream_tls_validation_for_http_only_backends() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream_tls.ca_file = Some("/path/does/not/exist.pem".to_string());
    cfg.upstream_tls.ca_dir = Some("/path/does/not/exist".to_string());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .backends[0]
        .address = "http://127.0.0.1:8080".to_string();

    assert!(validate(&cfg).is_ok());
}

#[test]
fn skips_unused_per_upstream_tls_validation_for_http_only_backends() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream.get_mut("test_upstream").expect("upstream").tls = Some(UpstreamTls {
        verify_certificates: true,
        strict_sni: true,
        ca_file: Some("/path/does/not/exist.pem".to_string()),
        ca_dir: Some("/path/does/not/exist".to_string()),
        client_certificate: None,
        client_certificate_ref: None,
        client_key: None,
        client_key_ref: None,
    });
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .backends[0]
        .address = "http://127.0.0.1:8080".to_string();

    assert!(validate(&cfg).is_ok());
}

#[test]
fn backend_address_validation_supports_secure_default_and_explicit_http() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    // Bare host:port defaults to HTTPS policy.
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .backends[0]
        .address = "api.example.internal:443".to_string();
    assert!(validate(&cfg).is_ok());

    // Explicit HTTP remains allowed as an opt-out.
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .backends[0]
        .address = "http://127.0.0.1:8080".to_string();
    assert!(validate(&cfg).is_ok());
}

#[test]
fn backend_address_validation_rejects_invalid_urls() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .backends[0]
        .address = "https://127.0.0.1:8443/path".to_string();
    assert!(validate(&cfg).is_err());

    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .backends[0]
        .address = "ftp://127.0.0.1:21".to_string();
    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_duplicate_backend_addresses_across_upstreams() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    let mut duplicate = cfg.upstream.get("test_upstream").expect("upstream").clone();
    duplicate.backends[0].id = "backend-2".to_string();
    duplicate.route.path_prefix = Some("/v2".to_string());
    cfg.upstream
        .insert("test_upstream_2".to_string(), duplicate);

    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_non_loopback_control_api_without_auth_token() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.control_api.enabled = true;
    cfg.observability.control_api.address = "0.0.0.0".to_string();
    cfg.observability.control_api.auth_token = None;
    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_loopback_control_api_without_auth_token() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.control_api.enabled = true;
    cfg.observability.control_api.address = "127.0.0.1".to_string();
    cfg.observability.control_api.auth_token = None;
    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_watchdog_grace_shorter_than_shutdown_drain_timeout() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.watchdog.enabled = true;
    cfg.resilience.watchdog.drain_grace_ms = 1_000;
    cfg.performance.shutdown_drain_timeout_ms = 2_000;
    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_known_control_api_placeholder_token() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.control_api.enabled = true;
    cfg.observability.control_api.auth_token = Some("replace-with-strong-token".to_string());
    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_known_control_api_placeholder_in_bearer_token_list_and_literal_ref() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.control_api.enabled = true;
    cfg.observability.control_api.auth_token = None;
    cfg.observability.control_api.auth.bearer_tokens = vec![ControlApiBearerToken {
        token: "change-me".to_string(),
        token_ref: None,
        role: ControlApiRole::Admin,
        actor_id: Some("admin".to_string()),
    }];
    assert!(validate(&cfg).is_err());

    cfg.observability.control_api.auth.bearer_tokens[0]
        .token
        .clear();
    cfg.observability.control_api.auth.bearer_tokens[0].token_ref = Some(SecretRef {
        reference: "literal:replace-me".to_string(),
    });
    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_duplicate_control_api_tokens_with_conflicting_metadata() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.control_api.enabled = true;
    cfg.observability.control_api.auth_token = None;
    cfg.observability.control_api.auth.bearer_tokens = vec![
        ControlApiBearerToken {
            token: "same-token".to_string(),
            token_ref: None,
            role: ControlApiRole::Viewer,
            actor_id: Some("alice".to_string()),
        },
        ControlApiBearerToken {
            token: "same-token".to_string(),
            token_ref: None,
            role: ControlApiRole::Admin,
            actor_id: Some("bob".to_string()),
        },
    ];

    assert!(validate(&cfg).is_err());
}

#[test]
fn accepts_repeated_bearer_token_with_identical_role_and_actor() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.control_api.enabled = true;
    cfg.observability.control_api.auth_token = None;
    cfg.observability.control_api.auth.bearer_tokens = vec![
        ControlApiBearerToken {
            token: "same-token".to_string(),
            token_ref: None,
            role: ControlApiRole::Viewer,
            actor_id: Some("alice".to_string()),
        },
        ControlApiBearerToken {
            token: "same-token".to_string(),
            token_ref: None,
            role: ControlApiRole::Viewer,
            actor_id: Some("alice".to_string()),
        },
    ];

    assert!(validate(&cfg).is_ok());
}

#[test]
fn rejects_legacy_auth_token_duplicated_by_bearer_token_with_conflicting_role() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.control_api.enabled = true;
    cfg.observability.control_api.auth_token = Some("shared-admin-token".to_string());
    cfg.observability.control_api.auth.bearer_tokens = vec![ControlApiBearerToken {
        token: "shared-admin-token".to_string(),
        token_ref: None,
        role: ControlApiRole::Viewer,
        actor_id: Some("viewer".to_string()),
    }];

    assert!(validate(&cfg).is_err());
}

#[test]
fn accepts_control_api_with_bearer_tokens_and_no_legacy_auth_token() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.control_api.enabled = true;
    cfg.observability.control_api.auth_token = None;
    cfg.observability.control_api.auth.bearer_tokens = vec![ControlApiBearerToken {
        token: "viewer-token".to_string(),
        token_ref: None,
        role: ControlApiRole::Viewer,
        actor_id: Some("viewer".to_string()),
    }];
    assert!(validate(&cfg).is_ok());
}

#[test]
fn accepts_control_api_with_required_mtls_and_no_tokens() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.control_api.enabled = true;
    cfg.observability.control_api.auth_token = None;
    cfg.observability.control_api.tls.client_auth.mode = ControlApiClientAuthMode::Required;
    cfg.observability.control_api.tls.client_auth.ca_file =
        Some(cert.to_string_lossy().to_string());
    assert!(validate(&cfg).is_ok());
}

#[test]
fn rejects_control_api_route_collisions_including_generated_paths() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.control_api.enabled = true;
    cfg.observability.control_api.auth_token = Some("strong-test-token".to_string());
    cfg.observability.control_api.reload_path = "/admin/reload".to_string();

    let cases = [
        ("health_path", "/admin/runtime"),
        ("reload_certs_path", "/admin/reload"),
        ("restart_path", "/admin/reload"),
        ("health_path", "/admin/runtime/history/1"),
    ];
    for (field, value) in cases {
        let mut candidate = cfg.clone();
        match field {
            "health_path" => candidate.observability.control_api.health_path = value.to_string(),
            "reload_certs_path" => {
                candidate.observability.control_api.reload_certs_path = value.to_string()
            }
            "restart_path" => candidate.observability.control_api.restart_path = value.to_string(),
            _ => unreachable!("test case field"),
        }
        assert!(
            validate(&candidate).is_err(),
            "collision should be rejected: {field}={value}"
        );
    }
}

#[test]
fn rejects_control_api_with_optional_mtls_as_only_auth_mechanism() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.control_api.enabled = true;
    cfg.observability.control_api.auth_token = None;
    cfg.observability.control_api.tls.client_auth.mode = ControlApiClientAuthMode::Optional;
    cfg.observability.control_api.tls.client_auth.ca_file =
        Some(cert.to_string_lossy().to_string());
    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_control_api_mtls_without_ca_material() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.control_api.enabled = true;
    cfg.observability.control_api.tls.client_auth.mode = ControlApiClientAuthMode::Required;
    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_control_api_client_auth_ca_dir_without_readable_pem_certificates() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let ca_dir = dir.path().join("ca.d");
    std::fs::create_dir_all(&ca_dir).expect("create ca dir");
    std::fs::write(ca_dir.join("notes.txt"), b"not a pem").expect("write notes");

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.control_api.enabled = true;
    cfg.observability.control_api.tls.client_auth.mode = ControlApiClientAuthMode::Required;
    cfg.observability.control_api.tls.client_auth.ca_dir =
        Some(ca_dir.to_string_lossy().to_string());

    let err = validate(&cfg).expect_err("control api ca_dir without pem certs must fail");
    assert_eq!(
        err.to_string(),
        format!(
            "observability.control_api.tls.client_auth.ca_dir '{}' did not contain any readable PEM certificates",
            ca_dir.to_string_lossy()
        )
    );
}

#[test]
fn rejects_control_api_client_auth_oversized_ca_dir_entry() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let ca_dir = dir.path().join("ca.d");
    std::fs::create_dir_all(&ca_dir).expect("create ca dir");
    std::fs::write(ca_dir.join("huge.pem"), vec![b'A'; (1024 * 1024) + 1]).expect("write huge");

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.control_api.enabled = true;
    cfg.observability.control_api.tls.client_auth.mode = ControlApiClientAuthMode::Required;
    cfg.observability.control_api.tls.client_auth.ca_dir =
        Some(ca_dir.to_string_lossy().to_string());

    let err = validate(&cfg).expect_err("oversized control api ca_dir entry must fail");
    assert!(
        err.to_string()
            .contains("exceeds the maximum supported PEM size")
    );
}

#[test]
fn rejects_control_api_invalid_role_ordering() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.control_api.enabled = true;
    cfg.observability
        .control_api
        .authorization
        .runtime_read_role = ControlApiRole::Operator;
    cfg.observability
        .control_api
        .authorization
        .runtime_mutate_role = ControlApiRole::Viewer;
    cfg.observability.control_api.auth_token = Some("token".to_string());
    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_control_api_invalid_ip_allowlist_cidr() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.control_api.enabled = true;
    cfg.observability.control_api.ip_allowlist.cidrs = vec!["10.0.0.0/33".to_string()];
    cfg.observability.control_api.auth_token = Some("token".to_string());
    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_control_api_file_audit_sink_without_path() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.control_api.enabled = true;
    cfg.observability.control_api.audit.sink = ControlApiAuditSink::File;
    cfg.observability.control_api.auth_token = Some("token".to_string());
    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_control_api_identity_source_without_mtls() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.control_api.enabled = true;
    cfg.observability.control_api.auth.identity_source =
        Some(crate::config::ControlApiIdentitySource {
            kind: "mtls_subject".to_string(),
            role_attribute: Some("ou".to_string()),
        });
    cfg.observability.control_api.auth_token = Some("token".to_string());
    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_control_api_unknown_identity_source_kind() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.control_api.enabled = true;
    cfg.observability.control_api.tls.client_auth.mode = ControlApiClientAuthMode::Optional;
    cfg.observability.control_api.tls.client_auth.ca_file = Some(cert.to_string_lossy().into());
    cfg.observability.control_api.auth.identity_source =
        Some(crate::config::ControlApiIdentitySource {
            kind: "mtls_subjectc_cn".to_string(),
            role_attribute: Some("ou".to_string()),
        });
    cfg.observability.control_api.auth_token = Some("token".to_string());

    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_legacy_watchdog_restart_hook() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.watchdog.restart_hook = Some("echo legacy".to_string());
    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_any_provided_legacy_watchdog_restart_hook_value() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.watchdog.restart_hook = None;
    assert!(validate(&cfg).is_ok());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.watchdog.restart_hook = Some(String::new());
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.watchdog.restart_hook = Some("   ".to_string());
    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_empty_privilege_drop_user_or_group() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.security.privileges.enabled = true;
    cfg.security.privileges.user = " ".to_string();
    assert!(validate(&cfg).is_err());

    cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.security.privileges.enabled = true;
    cfg.security.privileges.group = " ".to_string();
    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_relative_watchdog_restart_command_program() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.watchdog.restart_command = vec!["impulse".to_string(), "--restart".to_string()];

    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_ambiguous_route_matchers_with_same_host_path_and_method() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    {
        let upstream = cfg.upstream.get_mut("test_upstream").expect("upstream");
        upstream.route.host = Some("API.EXAMPLE.COM:443".to_string());
        upstream.route.path_prefix = Some("/api".to_string());
        upstream.route.method = Some("get".to_string());
        upstream.backends[0].address = "127.0.0.1:9001".to_string();
    }

    let duplicate = Upstream {
        load_balancing: LoadBalancing {
            lb_type: "round-robin".to_string(),
            key: None,
        },
        auth: Default::default(),
        host_policy: Default::default(),
        forwarded_headers: Default::default(),
        compression: Default::default(),
        cache: Default::default(),
        tls: None,
        route: RouteMatch {
            host: Some("api.example.com".to_string()),
            path_prefix: Some("/api".to_string()),
            method: Some("GET".to_string()),
        },
        backends: vec![Backend {
            id: "backend-2".to_string(),
            address: "127.0.0.1:9002".to_string(),
            weight: 1,
            health_check: None,
        }],
    };
    cfg.upstream
        .insert("test_upstream_2".to_string(), duplicate);

    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_whitespace_only_route_host_without_path_prefix() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    let upstream = cfg.upstream.get_mut("test_upstream").expect("upstream");
    upstream.route.host = Some("   ".to_string());
    upstream.route.path_prefix = None;

    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_malformed_route_host_matcher() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    let upstream = cfg.upstream.get_mut("test_upstream").expect("upstream");
    upstream.route.host = Some("[missing-end".to_string());
    upstream.route.path_prefix = None;

    assert!(validate(&cfg).is_err());
}

#[test]
fn allows_same_host_and_path_when_methods_differ() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    {
        let upstream = cfg.upstream.get_mut("test_upstream").expect("upstream");
        upstream.route.host = Some("api.example.com".to_string());
        upstream.route.path_prefix = Some("/api".to_string());
        upstream.route.method = Some("GET".to_string());
        upstream.backends[0].address = "127.0.0.1:9001".to_string();
    }

    let post_route = Upstream {
        load_balancing: LoadBalancing {
            lb_type: "round-robin".to_string(),
            key: None,
        },
        auth: Default::default(),
        host_policy: Default::default(),
        forwarded_headers: Default::default(),
        compression: Default::default(),
        cache: Default::default(),
        tls: None,
        route: RouteMatch {
            host: Some("api.example.com".to_string()),
            path_prefix: Some("/api".to_string()),
            method: Some("POST".to_string()),
        },
        backends: vec![Backend {
            id: "backend-2".to_string(),
            address: "127.0.0.1:9002".to_string(),
            weight: 1,
            health_check: None,
        }],
    };
    cfg.upstream
        .insert("test_upstream_2".to_string(), post_route);

    assert!(validate(&cfg).is_ok());
}

#[test]
fn listeners_override_invalid_legacy_listen_block() {
    let dir = tempdir().expect("tempdir");
    let (legacy_cert, legacy_key) = write_test_certs(dir.path());
    let (listener_cert, listener_key) = write_test_certs(dir.path());

    let mut cfg = base_config(
        &legacy_cert.to_string_lossy(),
        &legacy_key.to_string_lossy(),
    );
    cfg.listen.tls.cert.clear();
    cfg.listen.tls.key.clear();
    cfg.listeners = vec![Listen {
        protocol: "http3".to_string(),
        port: 9443,
        address: "127.0.0.1".to_string(),
        tls: Tls {
            cert: listener_cert.to_string_lossy().to_string(),
            key: listener_key.to_string_lossy().to_string(),
            certificates: vec![],
            client_auth: ClientAuth::default(),
        },
    }];

    assert!(validate(&cfg).is_ok());
}

#[test]
fn validate_returns_actionable_error_message() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.log.level = "debug-verbose".to_string();

    let err = validate(&cfg).expect_err("invalid config should return structured error");
    assert_eq!(err.message, "Invalid log level: debug-verbose");
}

#[test]
fn rejects_custom_backend_weight_for_least_connections() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    let upstream = cfg.upstream.get_mut("test_upstream").expect("upstream");
    upstream.load_balancing.lb_type = "least-connections".to_string();
    upstream.backends[0].weight = 200;

    let err = validate(&cfg).expect_err("custom weight for least-connections must fail");
    assert_eq!(
        err.message,
        "Backend 'backend-1' in upstream 'test_upstream' uses weight 200 but load balancing type 'least-connections' does not support custom backend weights; use the default weight 100"
    );
}

#[test]
fn rejects_custom_backend_weight_for_latency_aware() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    let upstream = cfg.upstream.get_mut("test_upstream").expect("upstream");
    upstream.load_balancing.lb_type = "latency-aware".to_string();
    upstream.backends[0].weight = 200;

    let err = validate(&cfg).expect_err("custom weight for latency-aware must fail");
    assert_eq!(
        err.message,
        "Backend 'backend-1' in upstream 'test_upstream' uses weight 200 but load balancing type 'latency-aware' does not support custom backend weights; use the default weight 100"
    );
}

#[test]
fn allows_default_backend_weight_for_latency_aware() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    let upstream = cfg.upstream.get_mut("test_upstream").expect("upstream");
    upstream.load_balancing.lb_type = "latency-aware".to_string();
    upstream.backends[0].weight = 100;

    assert!(validate(&cfg).is_ok());
}

#[test]
fn accepts_supported_load_balancers_with_mixed_backend_weights() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    for lb_type in ["consistent-hash", "sticky-cid", "round-robin", "random"] {
        let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
        let upstream = cfg.upstream.get_mut("test_upstream").expect("upstream");
        upstream.load_balancing.lb_type = lb_type.to_string();
        upstream.backends[0].weight = 100;
        upstream.backends.push(Backend {
            id: "backend-2".to_string(),
            address: "127.0.0.1:8081".to_string(),
            weight: 200,
            health_check: None,
        });

        assert!(
            validate(&cfg).is_ok(),
            "supported load balancer {lb_type} should accept mixed backend weights"
        );
    }
}

#[test]
fn rejects_host_policy_host_when_mode_is_not_rewrite() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .host_policy
        .host = Some("ignored.example.com".to_string());

    assert!(validate(&cfg).is_err());
}

#[test]
fn accepts_scoped_rate_limit_with_supported_key_spec() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.scoped_rate_limits.push(ScopedRateLimit {
        name: "tenant-header".to_string(),
        scope: ScopedRateLimitScope::Tenant,
        requests_per_sec: 50,
        burst: 100,
        key: Some("header:x-tenant-id".to_string()),
        route_allowlist: vec!["test_upstream".to_string()],
        idle_ttl_secs: 300,
    });

    assert!(validate(&cfg).is_ok());
}

#[test]
fn rejects_tenant_scoped_rate_limit_without_key() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.scoped_rate_limits.push(ScopedRateLimit {
        name: "tenant-missing-key".to_string(),
        scope: ScopedRateLimitScope::Tenant,
        requests_per_sec: 50,
        burst: 100,
        key: None,
        route_allowlist: Vec::new(),
        idle_ttl_secs: 300,
    });

    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_route_scoped_rate_limit_with_custom_key() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.scoped_rate_limits.push(ScopedRateLimit {
        name: "route-key".to_string(),
        scope: ScopedRateLimitScope::Route,
        requests_per_sec: 10,
        burst: 20,
        key: Some("header:x-tenant-id".to_string()),
        route_allowlist: Vec::new(),
        idle_ttl_secs: 300,
    });

    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_scoped_rate_limit_with_empty_allowlist_entry() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.resilience.scoped_rate_limits.push(ScopedRateLimit {
        name: "empty-route".to_string(),
        scope: ScopedRateLimitScope::Client,
        requests_per_sec: 10,
        burst: 20,
        key: Some("peer_ip".to_string()),
        route_allowlist: vec![" ".to_string()],
        idle_ttl_secs: 300,
    });

    assert!(validate(&cfg).is_err());
}

#[test]
fn accepts_upstream_api_key_auth_with_default_header() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .api_key = Some(ApiKeyAuth {
        header_name: "x-api-key".to_string(),
        keys: vec!["test-key".to_string()],
    });

    assert!(validate(&cfg).is_ok());
}

#[test]
fn rejects_upstream_api_key_auth_without_keys() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth = RouteAuth {
        api_key: Some(ApiKeyAuth {
            header_name: "x-api-key".to_string(),
            keys: Vec::new(),
        }),
        jwt: None,
        external_auth: None,
        required_scopes: Vec::new(),
        required_roles: Vec::new(),
    };

    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_upstream_api_key_auth_with_invalid_header_name() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth = RouteAuth {
        api_key: Some(ApiKeyAuth {
            header_name: "x api key".to_string(),
            keys: vec!["test-key".to_string()],
        }),
        jwt: None,
        external_auth: None,
        required_scopes: Vec::new(),
        required_roles: Vec::new(),
    };

    assert!(validate(&cfg).is_err());
}

#[test]
fn accepts_upstream_jwt_auth_with_issuer_and_audience() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth = RouteAuth {
        api_key: None,
        jwt: Some(JwtAuth {
            secret: "jwt-secret".to_string(),
            issuer: Some("issuer-1".to_string()),
            audience: Some("aud-1".to_string()),
            clock_skew_secs: 30,
            ..JwtAuth::default()
        }),
        external_auth: None,
        required_scopes: Vec::new(),
        required_roles: Vec::new(),
    };

    assert!(validate(&cfg).is_ok());
}

#[test]
fn rejects_upstream_jwt_auth_without_secret() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth = RouteAuth {
        api_key: None,
        jwt: Some(JwtAuth {
            secret: " ".to_string(),
            issuer: None,
            audience: None,
            clock_skew_secs: 30,
            ..JwtAuth::default()
        }),
        external_auth: None,
        required_scopes: Vec::new(),
        required_roles: Vec::new(),
    };

    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_upstream_jwt_auth_with_empty_issuer() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth = RouteAuth {
        api_key: None,
        jwt: Some(JwtAuth {
            secret: "jwt-secret".to_string(),
            issuer: Some(" ".to_string()),
            audience: None,
            clock_skew_secs: 30,
            ..JwtAuth::default()
        }),
        external_auth: None,
        required_scopes: Vec::new(),
        required_roles: Vec::new(),
    };

    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_upstream_jwt_auth_with_ambiguous_scalar_and_list_issuer_policy() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .jwt = Some(JwtAuth {
        secret: "jwt-secret".to_string(),
        issuer: Some("issuer-1".to_string()),
        issuers: Some(vec!["issuer-2".to_string()]),
        ..JwtAuth::default()
    });

    assert!(validate(&cfg).is_err());
}

#[test]
fn accepts_upstream_asymmetric_jwt_auth_with_jwks_url_and_no_secret() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .jwt = Some(JwtAuth {
        secret: String::new(),
        allowed_algorithms: vec![JwtAlgorithm::Rs256],
        jwks_url: Some("https://issuer.example.com/.well-known/jwks.json".to_string()),
        ..JwtAuth::default()
    });

    assert!(validate(&cfg).is_ok());
}

#[test]
fn rejects_upstream_asymmetric_jwt_auth_with_non_https_jwks_url() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .jwt = Some(JwtAuth {
        secret: String::new(),
        allowed_algorithms: vec![JwtAlgorithm::Rs256],
        jwks_url: Some("http://issuer.example.com/.well-known/jwks.json".to_string()),
        ..JwtAuth::default()
    });

    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_upstream_jwt_auth_with_secret_and_no_hs256_algorithm() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .jwt = Some(JwtAuth {
        secret: "jwt-secret".to_string(),
        allowed_algorithms: vec![JwtAlgorithm::Rs256],
        jwks_url: Some("https://issuer.example.com/.well-known/jwks.json".to_string()),
        ..JwtAuth::default()
    });

    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_conflicting_jwt_static_key_ids() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .jwt = Some(JwtAuth {
        secret: String::new(),
        allowed_algorithms: vec![JwtAlgorithm::Rs256],
        static_keys: vec![
            JwtVerificationKey::Pem {
                kid: Some("shared-kid".to_string()),
                alg: Some(JwtAlgorithm::Rs256),
                public_key_pem: "pem-a".to_string(),
            },
            JwtVerificationKey::Pem {
                kid: Some("shared-kid".to_string()),
                alg: Some(JwtAlgorithm::Rs256),
                public_key_pem: "pem-b".to_string(),
            },
        ],
        ..JwtAuth::default()
    });

    assert!(validate(&cfg).is_err());
}

#[test]
fn accepts_http_external_auth_with_default_timeout() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .external_auth = Some(ExternalAuth::Http {
        endpoint: "https://auth.internal/check".to_string(),
        request_headers: Vec::new(),
        response_header_allowlist: Vec::new(),
        timeout_ms: 1_000,
        failure_mode: ExternalAuthFailureMode::FailClosed,
    });

    assert!(validate(&cfg).is_ok());
}

#[test]
fn rejects_remote_plaintext_http_external_auth() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .external_auth = Some(ExternalAuth::Http {
        endpoint: "http://auth.internal/check".to_string(),
        request_headers: Vec::new(),
        response_header_allowlist: Vec::new(),
        timeout_ms: 1_000,
        failure_mode: ExternalAuthFailureMode::FailClosed,
    });

    assert!(validate(&cfg).is_err());
}

#[test]
fn accepts_loopback_plaintext_http_external_auth() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());
    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .external_auth = Some(ExternalAuth::Http {
        endpoint: "http://127.0.0.1:8080/check".to_string(),
        request_headers: Vec::new(),
        response_header_allowlist: Vec::new(),
        timeout_ms: 1_000,
        failure_mode: ExternalAuthFailureMode::FailClosed,
    });

    assert!(validate(&cfg).is_ok());
}

#[test]
fn accepts_oidc_external_auth() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .external_auth = Some(ExternalAuth::Oidc {
        discovery_url: Some(
            "https://issuer.example.com/.well-known/openid-configuration".to_string(),
        ),
        issuer_url: Some("https://issuer.example.com".to_string()),
        client_id: "edge-gateway".to_string(),
        client_secret: Some("secret-1".to_string()),
        client_secret_ref: None,
        audience: Some("impulse-api".to_string()),
        scopes: vec!["openid".to_string(), "profile".to_string()],
        request_headers: Vec::new(),
        response_header_allowlist: Vec::new(),
        timeout_ms: 1_500,
        failure_mode: ExternalAuthFailureMode::FailClosed,
    });

    assert!(validate(&cfg).is_ok());
}

#[test]
fn accepts_oidc_external_auth_with_loopback_http_urls() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .external_auth = Some(ExternalAuth::Oidc {
        discovery_url: Some("http://127.0.0.1:9000/.well-known/openid-configuration".to_string()),
        issuer_url: Some("http://localhost:9000".to_string()),
        client_id: "edge-gateway".to_string(),
        client_secret: Some("secret-1".to_string()),
        client_secret_ref: None,
        audience: Some("impulse-api".to_string()),
        scopes: vec!["openid".to_string(), "profile".to_string()],
        request_headers: Vec::new(),
        response_header_allowlist: Vec::new(),
        timeout_ms: 1_500,
        failure_mode: ExternalAuthFailureMode::FailClosed,
    });

    assert!(validate(&cfg).is_ok());
}

#[test]
fn rejects_oidc_external_auth_without_discovery_or_issuer() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .external_auth = Some(ExternalAuth::Oidc {
        discovery_url: None,
        issuer_url: None,
        client_id: "edge-gateway".to_string(),
        client_secret: Some("secret-1".to_string()),
        client_secret_ref: None,
        audience: Some("impulse-api".to_string()),
        scopes: vec!["openid".to_string()],
        request_headers: Vec::new(),
        response_header_allowlist: Vec::new(),
        timeout_ms: 1_500,
        failure_mode: ExternalAuthFailureMode::FailClosed,
    });

    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_oidc_external_auth_with_empty_client_secret() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .external_auth = Some(ExternalAuth::Oidc {
        discovery_url: Some(
            "https://issuer.example.com/.well-known/openid-configuration".to_string(),
        ),
        issuer_url: Some("https://issuer.example.com".to_string()),
        client_id: "edge-gateway".to_string(),
        client_secret: Some("   ".to_string()),
        client_secret_ref: None,
        audience: Some("impulse-api".to_string()),
        scopes: vec!["openid".to_string()],
        request_headers: Vec::new(),
        response_header_allowlist: Vec::new(),
        timeout_ms: 1_500,
        failure_mode: ExternalAuthFailureMode::FailClosed,
    });

    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_oidc_external_auth_with_empty_scope() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .external_auth = Some(ExternalAuth::Oidc {
        discovery_url: Some(
            "https://issuer.example.com/.well-known/openid-configuration".to_string(),
        ),
        issuer_url: Some("https://issuer.example.com".to_string()),
        client_id: "edge-gateway".to_string(),
        client_secret: Some("secret-1".to_string()),
        client_secret_ref: None,
        audience: Some("impulse-api".to_string()),
        scopes: vec!["openid".to_string(), "   ".to_string()],
        request_headers: Vec::new(),
        response_header_allowlist: Vec::new(),
        timeout_ms: 1_500,
        failure_mode: ExternalAuthFailureMode::FailClosed,
    });

    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_external_auth_with_invalid_request_header_name() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .external_auth = Some(ExternalAuth::Http {
        endpoint: "https://auth.internal/check".to_string(),
        request_headers: vec![ExternalAuthRequestHeader {
            name: "x auth".to_string(),
            value: "allow".to_string(),
        }],
        response_header_allowlist: Vec::new(),
        timeout_ms: 1_000,
        failure_mode: ExternalAuthFailureMode::FailClosed,
    });

    assert!(validate(&cfg).is_err());
}

#[test]
fn accepts_http_external_auth_with_explicit_headers() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .external_auth = Some(ExternalAuth::Http {
        endpoint: "https://auth.internal/check".to_string(),
        request_headers: vec![
            ExternalAuthRequestHeader {
                name: "x-auth-service".to_string(),
                value: "impulse".to_string(),
            },
            ExternalAuthRequestHeader {
                name: "x-auth-mode".to_string(),
                value: "allow".to_string(),
            },
        ],
        response_header_allowlist: vec!["www-authenticate".to_string(), "location".to_string()],
        timeout_ms: 1_000,
        failure_mode: ExternalAuthFailureMode::FailClosed,
    });

    assert!(validate(&cfg).is_ok());
}

#[test]
fn rejects_oidc_external_auth_with_empty_discovery_url() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .external_auth = Some(ExternalAuth::Oidc {
        discovery_url: Some("   ".to_string()),
        issuer_url: None,
        client_id: "edge-gateway".to_string(),
        client_secret: Some("secret-1".to_string()),
        client_secret_ref: None,
        audience: Some("impulse-api".to_string()),
        scopes: vec!["openid".to_string()],
        request_headers: Vec::new(),
        response_header_allowlist: Vec::new(),
        timeout_ms: 1_500,
        failure_mode: ExternalAuthFailureMode::FailClosed,
    });

    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_external_auth_with_invalid_response_allowlist_header_name() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .external_auth = Some(ExternalAuth::Http {
        endpoint: "https://auth.internal/check".to_string(),
        request_headers: Vec::new(),
        response_header_allowlist: vec!["bad header".to_string()],
        timeout_ms: 1_000,
        failure_mode: ExternalAuthFailureMode::FailClosed,
    });

    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_oidc_external_auth_with_non_https_discovery_url() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .external_auth = Some(ExternalAuth::Oidc {
        discovery_url: Some(
            "http://issuer.example.com/.well-known/openid-configuration".to_string(),
        ),
        issuer_url: Some("https://issuer.example.com".to_string()),
        client_id: "edge-gateway".to_string(),
        client_secret: Some("secret-1".to_string()),
        client_secret_ref: None,
        audience: Some("impulse-api".to_string()),
        scopes: vec!["openid".to_string()],
        request_headers: Vec::new(),
        response_header_allowlist: Vec::new(),
        timeout_ms: 1_500,
        failure_mode: ExternalAuthFailureMode::FailClosed,
    });

    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_oidc_external_auth_with_non_loopback_http_issuer_url() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .external_auth = Some(ExternalAuth::Oidc {
        discovery_url: Some(
            "https://issuer.example.com/.well-known/openid-configuration".to_string(),
        ),
        issuer_url: Some("http://issuer.example.com".to_string()),
        client_id: "edge-gateway".to_string(),
        client_secret: Some("secret-1".to_string()),
        client_secret_ref: None,
        audience: Some("impulse-api".to_string()),
        scopes: vec!["openid".to_string()],
        request_headers: Vec::new(),
        response_header_allowlist: Vec::new(),
        timeout_ms: 1_500,
        failure_mode: ExternalAuthFailureMode::FailClosed,
    });

    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_oidc_external_auth_with_response_header_allowlist() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .external_auth = Some(ExternalAuth::Oidc {
        discovery_url: Some(
            "https://issuer.example.com/.well-known/openid-configuration".to_string(),
        ),
        issuer_url: Some("https://issuer.example.com".to_string()),
        client_id: "edge-gateway".to_string(),
        client_secret: Some("secret-1".to_string()),
        client_secret_ref: None,
        audience: Some("impulse-api".to_string()),
        scopes: vec!["openid".to_string()],
        request_headers: Vec::new(),
        response_header_allowlist: vec!["x-user-id".to_string()],
        timeout_ms: 1_500,
        failure_mode: ExternalAuthFailureMode::FailClosed,
    });

    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_external_auth_with_rbac_requirements_in_v1() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth = RouteAuth {
        api_key: None,
        jwt: None,
        external_auth: Some(ExternalAuth::Http {
            endpoint: "https://auth.internal/check".to_string(),
            request_headers: Vec::new(),
            response_header_allowlist: Vec::new(),
            timeout_ms: 1_000,
            failure_mode: ExternalAuthFailureMode::FailClosed,
        }),
        required_scopes: vec!["read:fast".to_string()],
        required_roles: vec!["admin".to_string()],
    };

    assert!(validate(&cfg).is_err());
}

#[test]
fn accepts_upstream_jwt_secret_ref_without_plaintext_secret() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .jwt = Some(JwtAuth {
        secret: String::new(),
        secret_ref: Some(SecretRef {
            reference: "literal:jwt-secret".to_string(),
        }),
        ..JwtAuth::default()
    });

    assert!(validate(&cfg).is_ok());
}

#[test]
fn rejects_upstream_jwt_with_plaintext_secret_and_secret_ref_together() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .jwt = Some(JwtAuth {
        secret: "jwt-secret".to_string(),
        secret_ref: Some(SecretRef {
            reference: "literal:jwt-secret".to_string(),
        }),
        ..JwtAuth::default()
    });

    let err = validate(&cfg).expect_err("jwt secret source conflict must fail");
    assert_eq!(
        err.to_string(),
        "upstream 'test_upstream' auth.jwt.secret and upstream 'test_upstream' auth.jwt.secret_ref cannot both be set"
    );
}

#[test]
fn rejects_secret_ref_with_unsupported_scheme() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .jwt = Some(JwtAuth {
        secret: String::new(),
        secret_ref: Some(SecretRef {
            reference: "env:JWT_SECRET".to_string(),
        }),
        ..JwtAuth::default()
    });

    let err = validate(&cfg).expect_err("unsupported secret scheme must fail");
    assert_eq!(
        err.to_string(),
        "upstream 'test_upstream' auth.jwt.secret_ref.ref uses unsupported secret scheme 'env'; supported schemes are literal and file"
    );
}

#[test]
fn accepts_control_api_bearer_token_ref_without_plaintext_token() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.control_api.enabled = true;
    cfg.observability.control_api.auth_token = None;
    cfg.observability.control_api.auth.bearer_tokens = vec![ControlApiBearerToken {
        token: String::new(),
        token_ref: Some(SecretRef {
            reference: "file:///etc/impulse/secrets/viewer.token".to_string(),
        }),
        role: ControlApiRole::Viewer,
        actor_id: Some("viewer".to_string()),
    }];

    assert!(validate(&cfg).is_ok());
}

#[test]
fn rejects_control_api_bearer_token_with_plaintext_and_ref_together() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.observability.control_api.enabled = true;
    cfg.observability.control_api.auth_token = None;
    cfg.observability.control_api.auth.bearer_tokens = vec![ControlApiBearerToken {
        token: "viewer-token".to_string(),
        token_ref: Some(SecretRef {
            reference: "literal:viewer-token".to_string(),
        }),
        role: ControlApiRole::Viewer,
        actor_id: Some("viewer".to_string()),
    }];

    let err = validate(&cfg).expect_err("control api token source conflict must fail");
    assert_eq!(
        err.to_string(),
        "observability.control_api.auth.bearer_tokens[0].token and observability.control_api.auth.bearer_tokens[0].token_ref cannot both be set"
    );
}

#[test]
fn rejects_upstream_tls_partial_client_mtls_pair() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream.get_mut("test_upstream").expect("upstream").tls = Some(UpstreamTls {
        verify_certificates: true,
        strict_sni: true,
        ca_file: None,
        ca_dir: None,
        client_certificate: None,
        client_certificate_ref: Some(SecretRef {
            reference: "file:///etc/impulse/secrets/client.crt".to_string(),
        }),
        client_key: None,
        client_key_ref: None,
    });

    let err = validate(&cfg).expect_err("partial upstream mTLS pair must fail");
    assert_eq!(
        err.to_string(),
        "upstream['test_upstream'].tls.client_certificate and upstream['test_upstream'].tls.client_key must be configured as a complete mTLS pair"
    );
}

#[test]
fn rejects_external_auth_with_invalid_http_endpoint() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth
        .external_auth = Some(ExternalAuth::Http {
        endpoint: "not-a-url".to_string(),
        request_headers: Vec::new(),
        response_header_allowlist: Vec::new(),
        timeout_ms: 1_000,
        failure_mode: ExternalAuthFailureMode::FailClosed,
    });

    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_external_auth_combined_with_builtin_auth_in_v1() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth = RouteAuth {
        api_key: Some(ApiKeyAuth {
            header_name: "x-api-key".to_string(),
            keys: vec!["test-key".to_string()],
        }),
        jwt: None,
        external_auth: Some(ExternalAuth::Http {
            endpoint: "https://auth.internal/check".to_string(),
            request_headers: Vec::new(),
            response_header_allowlist: Vec::new(),
            timeout_ms: 1_000,
            failure_mode: ExternalAuthFailureMode::FailClosed,
        }),
        required_scopes: Vec::new(),
        required_roles: Vec::new(),
    };

    assert!(validate(&cfg).is_err());
}

#[test]
fn rejects_rbac_requirements_without_jwt_auth() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(dir.path());

    let mut cfg = base_config(&cert.to_string_lossy(), &key.to_string_lossy());
    cfg.upstream
        .get_mut("test_upstream")
        .expect("upstream")
        .auth = RouteAuth {
        api_key: Some(ApiKeyAuth {
            header_name: "x-api-key".to_string(),
            keys: vec!["test-key".to_string()],
        }),
        jwt: None,
        external_auth: None,
        required_scopes: vec!["read:fast".to_string()],
        required_roles: Vec::new(),
    };

    assert!(validate(&cfg).is_err());
}
