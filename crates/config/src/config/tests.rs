use super::{
    ApiKeyAuth, Config, ControlApi, ControlApiAudit, ControlApiAuditFormat, ControlApiAuditSink,
    ControlApiAuth, ControlApiAuthorization, ControlApiClientAuthMode, ControlApiIpAllowlist,
    ControlApiRole, ControlApiTls, DistributedQuotaPolicy, DistributedQuotaSelector,
    DistributedQuotaSelectorSource, DistributedQuotaWindow, ExternalAuth, ForwardedHeaderPolicy,
    JwtAuth, Listen, LoadBalancing, Log, MetricsEndpoint, Performance, PrivilegeDrop,
    QuotaBackendFailurePolicy, QuotaCounterBackend, QuotaEnforcementMode, QuotaLocalFallbackConfig,
    QuotaPolicyConfig, Resilience, RouteAuth, RoutingTransparency, SecretProvider, SecretRef,
    Secrets, Tracing, UpstreamHostPolicy, UpstreamTls, Watchdog,
};
use crate::config::CURRENT_CONFIG_VERSION;

#[test]
fn minimal_yaml_applies_documented_defaults() {
    let yaml = r#"
listen:
  tls: {}
upstream:
  api:
    route: {}
    backends:
      - id: backend1
        address: "http://127.0.0.1:7001"
"#;

    let config: Config = serde_yaml::from_str(yaml).expect("minimal config should parse");
    let upstream = config.upstream.get("api").expect("missing api upstream");
    let backend = upstream
        .backends
        .first()
        .expect("missing backend in minimal config");

    assert_eq!(config.version, 1);
    assert_eq!(config.listen.protocol, "http3");
    assert_eq!(config.listen.port, 9889);
    assert_eq!(config.listen.address, "0.0.0.0");
    assert_eq!(config.log.level, "info");
    assert_eq!(backend.weight, 100);
}

#[test]
fn bearer_token_default_uses_least_privileged_role() {
    assert_eq!(ControlApiRole::default(), ControlApiRole::Viewer);
    assert_eq!(
        super::ControlApiBearerToken::default().role,
        ControlApiRole::Viewer
    );
}

#[test]
fn backend_health_check_defaults_are_filled_by_serde() {
    let yaml = r#"
listen:
  tls: {}
upstream:
  api:
    route: {}
    backends:
      - id: backend1
        address: "http://127.0.0.1:7001"
        health_check: {}
"#;

    let config: Config =
        serde_yaml::from_str(yaml).expect("config with empty health_check should parse");
    let health_check = config.upstream["api"].backends[0]
        .health_check
        .as_ref()
        .expect("missing defaulted health check");

    assert_eq!(health_check.path, "/health");
    assert_eq!(health_check.interval, 5_000);
    assert_eq!(health_check.timeout_ms, 1_000);
    assert_eq!(health_check.failure_threshold, 3);
    assert_eq!(health_check.success_threshold, 2);
    assert_eq!(health_check.cooldown_ms, 5_000);
}

#[test]
fn privilege_drop_defaults_are_filled_by_serde_via_type_default() {
    let yaml = r#"
listen:
  tls: {}
upstream:
  api:
    route: {}
    backends:
      - id: backend1
        address: "http://127.0.0.1:7001"
security:
  privileges: {}
"#;

    let config: Config =
        serde_yaml::from_str(yaml).expect("config with empty privileges should parse");

    assert_eq!(
        config.security.privileges.enabled,
        PrivilegeDrop::default().enabled
    );
    assert_eq!(
        config.security.privileges.user,
        PrivilegeDrop::default().user
    );
    assert_eq!(
        config.security.privileges.group,
        PrivilegeDrop::default().group
    );
}

#[test]
fn serde_defaults_for_leaf_structs_match_type_defaults() {
    let listen: Listen =
        serde_yaml::from_str("{}").expect("empty listen should parse via type defaults");
    assert_eq!(listen.protocol, Listen::default().protocol);
    assert_eq!(listen.port, Listen::default().port);
    assert_eq!(listen.address, Listen::default().address);

    let log: Log = serde_yaml::from_str("{}").expect("empty log should parse via type defaults");
    assert_eq!(log.level, Log::default().level);
    assert_eq!(log.file, Log::default().file);
    assert_eq!(log.format, Log::default().format);

    let api_key: ApiKeyAuth =
        serde_yaml::from_str("{}").expect("empty api key auth should parse via type defaults");
    assert_eq!(api_key.header_name, ApiKeyAuth::default().header_name);
    assert_eq!(api_key.keys, ApiKeyAuth::default().keys);

    let jwt: JwtAuth =
        serde_yaml::from_str(r#"secret: test-secret"#).expect("jwt auth should parse");
    assert_eq!(jwt.issuer, JwtAuth::default().issuer);
    assert_eq!(jwt.audience, JwtAuth::default().audience);
    assert_eq!(jwt.issuers, JwtAuth::default().issuers);
    assert_eq!(jwt.audiences, JwtAuth::default().audiences);
    assert_eq!(
        jwt.allowed_algorithms,
        JwtAuth::default().allowed_algorithms
    );
    assert_eq!(jwt.require_kid, JwtAuth::default().require_kid);
    assert_eq!(jwt.static_keys.len(), JwtAuth::default().static_keys.len());
    assert_eq!(jwt.jwks_url, JwtAuth::default().jwks_url);
    assert_eq!(
        jwt.jwks_refresh_interval_secs,
        JwtAuth::default().jwks_refresh_interval_secs
    );
    assert_eq!(
        jwt.jwks_request_timeout_ms,
        JwtAuth::default().jwks_request_timeout_ms
    );
    assert_eq!(
        jwt.jwks_cache_ttl_secs,
        JwtAuth::default().jwks_cache_ttl_secs
    );
    assert_eq!(
        jwt.jwks_stale_if_error_secs,
        JwtAuth::default().jwks_stale_if_error_secs
    );
    assert_eq!(
        jwt.jwks_startup_behavior,
        JwtAuth::default().jwks_startup_behavior
    );
    assert_eq!(jwt.clock_skew_secs, JwtAuth::default().clock_skew_secs);
}

#[test]
fn serde_defaults_for_small_policy_structs_match_type_defaults() {
    let forwarded: ForwardedHeaderPolicy =
        serde_yaml::from_str("{}").expect("empty forwarded header policy should parse");
    assert_eq!(forwarded, ForwardedHeaderPolicy::default());

    let host_policy: UpstreamHostPolicy =
        serde_yaml::from_str("{}").expect("empty upstream host policy should parse");
    assert_eq!(host_policy, UpstreamHostPolicy::default());

    let metrics: MetricsEndpoint =
        serde_yaml::from_str("{}").expect("empty metrics endpoint should parse");
    assert_eq!(metrics.address, MetricsEndpoint::default().address);
    assert_eq!(metrics.port, MetricsEndpoint::default().port);
    assert_eq!(metrics.path, MetricsEndpoint::default().path);
    assert_eq!(
        metrics.max_connections,
        MetricsEndpoint::default().max_connections
    );
    assert_eq!(
        metrics.connection_timeout_ms,
        MetricsEndpoint::default().connection_timeout_ms
    );

    let control_api: ControlApi =
        serde_yaml::from_str("{}").expect("empty control api should parse");
    assert_eq!(control_api.address, ControlApi::default().address);
    assert_eq!(control_api.port, ControlApi::default().port);
    assert_eq!(control_api.health_path, ControlApi::default().health_path);
    assert_eq!(control_api.ready_path, ControlApi::default().ready_path);
    assert_eq!(control_api.runtime_path, ControlApi::default().runtime_path);
    assert_eq!(control_api.restart_path, ControlApi::default().restart_path);
    assert_eq!(control_api.reload_path, ControlApi::default().reload_path);
    assert_eq!(
        control_api.reload_certs_path,
        ControlApi::default().reload_certs_path
    );
    assert_eq!(
        control_api.tls.client_auth.mode,
        ControlApiClientAuthMode::Disabled
    );
    assert!(control_api.tls.client_auth.ca_file.is_none());
    assert!(control_api.tls.client_auth.ca_dir.is_none());
    assert!(control_api.auth.bearer_tokens.is_empty());
    assert!(control_api.auth.identity_source.is_none());
    assert_eq!(
        control_api.authorization.runtime_read_role,
        ControlApiRole::Viewer
    );
    assert_eq!(
        control_api.authorization.runtime_mutate_role,
        ControlApiRole::Operator
    );
    assert_eq!(
        control_api.authorization.restart_role,
        ControlApiRole::Admin
    );
    assert!(control_api.ip_allowlist.cidrs.is_empty());
    assert!(!control_api.ip_allowlist.trust_proxy_headers);
    assert!(!control_api.audit.enabled);
    assert_eq!(control_api.audit.format, ControlApiAuditFormat::Json);
    assert_eq!(control_api.audit.sink, ControlApiAuditSink::Log);
    assert!(control_api.audit.file_path.is_none());
    assert_eq!(
        control_api.max_connections,
        ControlApi::default().max_connections
    );
    assert_eq!(
        control_api.connection_timeout_ms,
        ControlApi::default().connection_timeout_ms
    );

    let tracing: Tracing = serde_yaml::from_str("{}").expect("empty tracing config should parse");
    assert_eq!(tracing.enabled, Tracing::default().enabled);
    assert_eq!(tracing.service_name, Tracing::default().service_name);
    assert_eq!(tracing.otlp_endpoint, Tracing::default().otlp_endpoint);
    assert_eq!(tracing.sample_ratio, Tracing::default().sample_ratio);

    let routing: RoutingTransparency =
        serde_yaml::from_str("{}").expect("empty routing transparency should parse");
    assert_eq!(routing.enabled, RoutingTransparency::default().enabled);
    assert_eq!(
        routing.include_reason,
        RoutingTransparency::default().include_reason
    );
    assert_eq!(
        routing.expose_header,
        RoutingTransparency::default().expose_header
    );
    assert_eq!(
        routing.header_name,
        RoutingTransparency::default().header_name
    );
}

#[test]
fn serde_defaults_for_performance_match_type_defaults() {
    let performance: Performance =
        serde_yaml::from_str("{}").expect("empty performance config should parse");

    assert_eq!(
        performance.worker_threads,
        Performance::default().worker_threads
    );
    assert_eq!(
        performance.control_plane_threads,
        Performance::default().control_plane_threads
    );
    assert_eq!(
        performance.packet_shards_per_worker,
        Performance::default().packet_shards_per_worker
    );
    assert_eq!(
        performance.global_inflight_limit,
        Performance::default().global_inflight_limit
    );
    assert_eq!(
        performance.backend_timeout_ms,
        Performance::default().backend_timeout_ms
    );
    assert_eq!(
        performance.backend_dns_refresh_enabled,
        Performance::default().backend_dns_refresh_enabled
    );
    assert_eq!(
        performance.max_response_body_bytes,
        Performance::default().max_response_body_bytes
    );
    assert_eq!(
        performance.unknown_length_response_prebuffer_bytes,
        Performance::default().unknown_length_response_prebuffer_bytes
    );
}

#[test]
fn serde_defaults_for_resilience_match_type_defaults() {
    let resilience: Resilience =
        serde_yaml::from_str("{}").expect("empty resilience config should parse");

    assert_eq!(
        resilience.adaptive_admission.enabled,
        Resilience::default().adaptive_admission.enabled
    );
    assert_eq!(
        resilience.route_queue.default_cap,
        Resilience::default().route_queue.default_cap
    );
    assert_eq!(
        resilience.protocol.max_headers_count,
        Resilience::default().protocol.max_headers_count
    );
    assert_eq!(
        resilience.retry_budget.ratio_percent,
        Resilience::default().retry_budget.ratio_percent
    );
    assert_eq!(
        resilience.brownout.trigger_inflight_percent,
        Resilience::default().brownout.trigger_inflight_percent
    );
    assert_eq!(
        resilience.watchdog.restart_cooldown_ms,
        Resilience::default().watchdog.restart_cooldown_ms
    );
    assert_eq!(
        resilience.quota.enabled,
        Resilience::default().quota.enabled
    );
    assert_eq!(
        resilience.quota.enforcement,
        Resilience::default().quota.enforcement
    );
    assert_eq!(
        resilience.quota.backend_failure_policy,
        Resilience::default().quota.backend_failure_policy
    );
}

#[test]
fn watchdog_and_scoped_rate_limit_local_defaults_remain_stable() {
    let watchdog: Watchdog =
        serde_yaml::from_str("{}").expect("empty watchdog should parse via type defaults");
    assert_eq!(watchdog.enabled, Watchdog::default().enabled);
    assert_eq!(
        watchdog.unhealthy_consecutive_windows,
        Watchdog::default().unhealthy_consecutive_windows
    );
    assert_eq!(super::ScopedRateLimit::default_idle_ttl_secs(), 300);
}

#[test]
fn remaining_type_owned_defaults_match_documented_contract() {
    assert_eq!(Config::default_version(), CURRENT_CONFIG_VERSION);

    let lb: LoadBalancing =
        serde_yaml::from_str("{}").expect("empty lb config should parse via type default");
    assert_eq!(lb.lb_type, LoadBalancing::default().lb_type);
    assert_eq!(lb.key, LoadBalancing::default().key);

    let upstream_tls: UpstreamTls =
        serde_yaml::from_str("{}").expect("empty upstream tls config should parse");
    assert!(upstream_tls.verify_certificates);
    assert!(upstream_tls.strict_sni);
    assert_eq!(upstream_tls.ca_file, None);
    assert_eq!(upstream_tls.ca_dir, None);

    assert_eq!(ExternalAuth::default_timeout_ms(), 1_000);
}

#[test]
fn serde_defaults_for_secret_types_match_type_defaults() {
    let secrets: Secrets = serde_yaml::from_str("{}").expect("empty secrets config should parse");
    assert_eq!(secrets, Secrets::default());

    let secret_ref: SecretRef =
        serde_yaml::from_str("ref: literal:test-secret").expect("secret ref should parse");
    assert_eq!(secret_ref.reference, "literal:test-secret");
    assert_eq!(secret_ref.scheme(), Some("literal"));

    let file_provider: SecretProvider =
        serde_yaml::from_str("kind: file\nbase_dir: /etc/impulse/secrets\n")
            .expect("file secret provider should parse");
    assert_eq!(
        file_provider,
        SecretProvider::File {
            base_dir: Some("/etc/impulse/secrets".to_string())
        }
    );
}

#[test]
fn partial_secret_reference_inputs_parse_into_compatibility_fields() {
    let jwt: JwtAuth = serde_yaml::from_str(
        r#"
secret_ref:
  ref: file:///etc/impulse/secrets/jwt-signing.key
"#,
    )
    .expect("jwt secret ref should parse");
    assert!(jwt.secret.is_empty());
    assert_eq!(
        jwt.secret_ref
            .as_ref()
            .map(|secret_ref| secret_ref.reference.as_str()),
        Some("file:///etc/impulse/secrets/jwt-signing.key")
    );

    let control_api: ControlApi = serde_yaml::from_str(
        r#"
auth_token_ref:
  ref: literal:admin-token
auth:
  bearer_tokens:
    - token_ref:
        ref: file:///etc/impulse/secrets/viewer-token
      role: viewer
"#,
    )
    .expect("control api secret refs should parse");
    assert!(control_api.auth_token.is_none());
    assert_eq!(
        control_api
            .auth_token_ref
            .as_ref()
            .map(|secret_ref| secret_ref.reference.as_str()),
        Some("literal:admin-token")
    );
    assert_eq!(control_api.auth.bearer_tokens.len(), 1);
    assert!(control_api.auth.bearer_tokens[0].token.is_empty());
    assert_eq!(
        control_api.auth.bearer_tokens[0]
            .token_ref
            .as_ref()
            .map(|secret_ref| secret_ref.reference.as_str()),
        Some("file:///etc/impulse/secrets/viewer-token")
    );
}

#[test]
fn quota_type_defaults_match_documented_contract() {
    let quota: QuotaPolicyConfig =
        serde_yaml::from_str("{}").expect("empty quota config should parse");

    assert!(!quota.enabled);
    assert_eq!(quota.enforcement, QuotaEnforcementMode::Enforce);
    assert_eq!(
        quota.backend_failure_policy,
        QuotaBackendFailurePolicy::FailClosed
    );
    assert!(quota.local_fallback.is_none());
    assert!(quota.policies.is_empty());
    match quota.backend {
        QuotaCounterBackend::InMemory { key_prefix } => {
            assert_eq!(key_prefix, "impulse:quota");
        }
        QuotaCounterBackend::Redis { .. } => {
            panic!("default quota backend must be in_memory");
        }
    }
}

#[test]
fn resilience_validate_accepts_well_formed_quota_policy() {
    let resilience = Resilience {
        quota: QuotaPolicyConfig {
            enabled: true,
            enforcement: QuotaEnforcementMode::Shadow,
            backend_failure_policy: QuotaBackendFailurePolicy::FailOpen,
            backend: QuotaCounterBackend::Redis {
                url: "redis://127.0.0.1:6379/0".to_string(),
                key_prefix: "impulse:quota".to_string(),
                connect_timeout_ms: 250,
                command_timeout_ms: 100,
                max_inflight: 128,
            },
            local_fallback: Some(QuotaLocalFallbackConfig {
                key_prefix: "impulse:quota:fallback".to_string(),
                max_entries: 512,
            }),
            policies: vec![DistributedQuotaPolicy {
                name: "tenant-burst".to_string(),
                route_allowlist: vec!["api".to_string()],
                selector: DistributedQuotaSelector {
                    route: true,
                    tenant: Some(DistributedQuotaSelectorSource {
                        key: "header:x-tenant-id".to_string(),
                    }),
                    token: None,
                    client: None,
                },
                burst: Some(DistributedQuotaWindow {
                    requests: 100,
                    window_secs: 1,
                }),
                sustained: Some(DistributedQuotaWindow {
                    requests: 5000,
                    window_secs: 60,
                }),
            }],
        },
        ..Resilience::default()
    };

    resilience
        .validate()
        .expect("well-formed distributed quota config should validate");
}

#[test]
fn resilience_validate_rejects_invalid_quota_local_fallback_settings() {
    let unsupported_backend = Resilience {
        quota: QuotaPolicyConfig {
            enabled: true,
            local_fallback: Some(QuotaLocalFallbackConfig {
                key_prefix: "impulse:quota:fallback".to_string(),
                max_entries: 128,
            }),
            policies: vec![DistributedQuotaPolicy {
                name: "tenant-burst".to_string(),
                route_allowlist: vec!["api".to_string()],
                selector: DistributedQuotaSelector {
                    route: true,
                    tenant: Some(DistributedQuotaSelectorSource {
                        key: "header:x-tenant-id".to_string(),
                    }),
                    token: None,
                    client: None,
                },
                burst: Some(DistributedQuotaWindow {
                    requests: 100,
                    window_secs: 1,
                }),
                sustained: None,
            }],
            ..QuotaPolicyConfig::default()
        },
        ..Resilience::default()
    };
    assert_eq!(
        unsupported_backend
            .validate()
            .expect_err("in-memory quota backend must reject local fallback"),
        "resilience.quota.local_fallback is only supported when backend.kind=redis"
    );

    let invalid_capacity = Resilience {
        quota: QuotaPolicyConfig {
            enabled: true,
            backend: QuotaCounterBackend::Redis {
                url: "redis://127.0.0.1:6379/0".to_string(),
                key_prefix: "impulse:quota".to_string(),
                connect_timeout_ms: 250,
                command_timeout_ms: 100,
                max_inflight: 128,
            },
            local_fallback: Some(QuotaLocalFallbackConfig {
                key_prefix: "impulse:quota:fallback".to_string(),
                max_entries: 0,
            }),
            policies: vec![DistributedQuotaPolicy {
                name: "tenant-burst".to_string(),
                route_allowlist: vec!["api".to_string()],
                selector: DistributedQuotaSelector {
                    route: true,
                    tenant: Some(DistributedQuotaSelectorSource {
                        key: "header:x-tenant-id".to_string(),
                    }),
                    token: None,
                    client: None,
                },
                burst: Some(DistributedQuotaWindow {
                    requests: 100,
                    window_secs: 1,
                }),
                sustained: None,
            }],
            ..QuotaPolicyConfig::default()
        },
        ..Resilience::default()
    };
    assert_eq!(
        invalid_capacity
            .validate()
            .expect_err("zero local fallback capacity must be rejected"),
        "resilience.quota.local_fallback.max_entries must be > 0"
    );
}

#[test]
fn resilience_validate_rejects_quota_policy_without_selector_dimensions() {
    let resilience = Resilience {
        quota: QuotaPolicyConfig {
            enabled: true,
            policies: vec![DistributedQuotaPolicy {
                name: "missing-selector".to_string(),
                route_allowlist: Vec::new(),
                selector: DistributedQuotaSelector::default(),
                burst: Some(DistributedQuotaWindow {
                    requests: 10,
                    window_secs: 1,
                }),
                sustained: None,
            }],
            ..QuotaPolicyConfig::default()
        },
        ..Resilience::default()
    };

    let err = resilience
        .validate()
        .expect_err("selector-less quota policy must be rejected");
    assert!(err.contains("selector must include at least one dimension"));
}

#[test]
fn partial_struct_inputs_still_fill_missing_fields_from_type_defaults() {
    let auth: ApiKeyAuth = serde_yaml::from_str(
        r#"
header_name: x-custom-key
"#,
    )
    .expect("partial api key auth should parse");
    assert_eq!(auth.header_name, "x-custom-key");
    assert!(auth.keys.is_empty());

    let control_api: ControlApi = serde_yaml::from_str(
        r#"
enabled: true
"#,
    )
    .expect("partial control api should parse");
    assert!(control_api.enabled);
    assert_eq!(control_api.port, ControlApi::default().port);
    assert_eq!(control_api.auth_token, None);
    assert_eq!(
        control_api.authorization,
        ControlApiAuthorization::default()
    );
    assert_eq!(control_api.tls, ControlApiTls::default());
    assert_eq!(control_api.auth, ControlApiAuth::default());
    assert_eq!(control_api.ip_allowlist, ControlApiIpAllowlist::default());
    assert_eq!(control_api.audit, ControlApiAudit::default());

    let route_auth: RouteAuth = serde_yaml::from_str(
        r#"
required_scopes:
  - payments.read
"#,
    )
    .expect("partial route auth should parse");
    assert_eq!(route_auth.required_scopes, vec!["payments.read"]);
    assert!(route_auth.required_roles.is_empty());
    assert!(route_auth.api_key.is_none());
    assert!(route_auth.jwt.is_none());
    assert!(route_auth.external_auth.is_none());
}

#[test]
fn resolved_auth_secrets_are_redacted_from_debug_and_serialization() {
    let api_key: ApiKeyAuth = serde_yaml::from_str(
        r#"
header_name: x-api-key
keys:
  - api-key-super-secret
"#,
    )
    .expect("API key auth should parse");
    assert_eq!(api_key.keys, ["api-key-super-secret"]);
    let api_key_debug = format!("{api_key:?}");
    let api_key_yaml = serde_yaml::to_string(&api_key).expect("API key auth should serialize");
    assert!(!api_key_debug.contains("api-key-super-secret"));
    assert!(!api_key_yaml.contains("api-key-super-secret"));
    assert!(!api_key_yaml.contains("keys:"));

    let jwt: JwtAuth = serde_yaml::from_str(
        r#"
secret: jwt-super-secret
"#,
    )
    .expect("JWT auth should parse");
    let jwt_debug = format!("{jwt:?}");
    let jwt_json = serde_yaml::to_string(&jwt).expect("JWT auth should serialize");
    assert!(!jwt_debug.contains("jwt-super-secret"));
    assert!(!jwt_json.contains("jwt-super-secret"));
    assert!(!jwt_json.contains("\"secret\""));

    let oidc: ExternalAuth = serde_yaml::from_str(
        r#"
kind: oidc
discovery_url: https://issuer.example/.well-known/openid-configuration
client_id: edge
client_secret: oidc-super-secret
"#,
    )
    .expect("OIDC auth should parse");
    let oidc_debug = format!("{oidc:?}");
    let oidc_json = serde_yaml::to_string(&oidc).expect("OIDC auth should serialize");
    assert!(!oidc_debug.contains("oidc-super-secret"));
    assert!(!oidc_json.contains("oidc-super-secret"));
    assert!(!oidc_json.contains("\"client_secret\""));

    let external_http: ExternalAuth = serde_yaml::from_str(
        r#"
kind: http
endpoint: https://auth.example/check
request_headers:
  - name: authorization
    value: http-header-super-secret
"#,
    )
    .expect("HTTP external auth should parse");
    let external_http_debug = format!("{external_http:?}");
    let external_http_yaml =
        serde_yaml::to_string(&external_http).expect("HTTP external auth should serialize");
    assert!(external_http_debug.contains("authorization"));
    assert!(!external_http_debug.contains("http-header-super-secret"));
    assert!(!external_http_yaml.contains("http-header-super-secret"));
    assert!(!external_http_yaml.contains("request_headers:"));

    let external_oidc: ExternalAuth = serde_yaml::from_str(
        r#"
kind: oidc
client_id: edge
request_headers:
  - name: x-oidc-secret
    value: oidc-header-super-secret
"#,
    )
    .expect("OIDC external auth should parse");
    let external_oidc_debug = format!("{external_oidc:?}");
    let external_oidc_yaml =
        serde_yaml::to_string(&external_oidc).expect("OIDC external auth should serialize");
    assert!(external_oidc_debug.contains("x-oidc-secret"));
    assert!(!external_oidc_debug.contains("oidc-header-super-secret"));
    assert!(!external_oidc_yaml.contains("oidc-header-super-secret"));
    assert!(!external_oidc_yaml.contains("request_headers:"));
}
