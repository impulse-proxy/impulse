use std::collections::HashMap;

use impulse_lb::health::HealthFailureReason;
use serde::Serialize;

#[cfg(test)]
use self::upstreams::health_failure_reason_label;
use super::{state::ControlApiState, *};
use crate::{
    quic_listener::control_api::audit::ADMIN_AUDIT_SCHEMA_VERSION,
    resilience::quota::{
        QuotaBackendErrorSnapshot, QuotaBackendStatusSnapshot, QuotaPolicyIntrospectionSnapshot,
        QuotaSelectorIntrospectionSnapshot, QuotaWindowIntrospectionSnapshot,
    },
    runtime::{
        activation::{
            GenerationChangeEvent, GenerationEventKind, GenerationHistoryEntry,
            GenerationOperation, GenerationStatus,
        },
        backend::state::{
            BackendHealthState, BackendLifecycleInventorySnapshot, BackendMembershipState,
            BackendPoolPlacementSnapshot,
        },
        bundle::RuntimeGenerationRecord,
    },
};

mod redaction;
mod runtime_snapshot;
mod secrets_jwks;
mod upstreams;

const OBSERVABILITY_CONTRACT_VERSION: &str = "v1";
const RECENT_ADMIN_ACTION_LIMIT: usize = 5;

#[derive(Serialize)]
struct ControlApiHealthPayload {
    status: &'static str,
    uptime_ms: u64,
    watchdog: ControlApiHealthWatchdogPayload,
}

#[derive(Serialize)]
struct ControlApiHealthWatchdogPayload {
    enabled: bool,
    degraded: bool,
    restart_requested: bool,
}

#[derive(Serialize)]
struct ControlApiReadyPayload {
    ready: bool,
    healthy_backends: usize,
    total_backends: usize,
    restart_requested: bool,
}

#[derive(Serialize)]
struct ControlApiRuntimePayload {
    uptime_ms: u64,
    workers: ControlApiWorkerPayload,
    watchdog: ControlApiRuntimeWatchdogPayload,
    adaptive_admission: ControlApiAdaptiveAdmissionPayload,
    quota: ControlApiQuotaPayload,
    observability: ControlApiObservabilityPayload,
    auth: ControlApiAuthPayload,
    jwks: ControlApiJwksPayload,
    backends: ControlApiBackendInventoryPayload,
    metrics: ControlApiMetricsPayload,
    tls: ControlApiTlsPayload,
    secrets: ControlApiSecretsPayload,
    extension_model: ControlApiExtensionModelPayload,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime: Option<ControlApiRuntimeGenerationPayload>,
}

#[derive(Serialize)]
struct ControlApiWorkerPayload {
    expected: usize,
}

#[derive(Serialize)]
struct ControlApiRuntimeWatchdogPayload {
    enabled: bool,
    degraded: bool,
    restart_requested: bool,
    restart_reason: String,
    restart_requested_at_ms: u64,
}

#[derive(Serialize)]
struct ControlApiAdaptiveAdmissionPayload {
    enabled: bool,
    current_limit: usize,
    inflight_percent: u8,
}

#[derive(Serialize)]
struct ControlApiQuotaPayload {
    enabled: bool,
    enforcement: &'static str,
    backend_failure_policy: &'static str,
    active_backend: String,
    backend_status: ControlApiQuotaBackendStatusPayload,
    policies: Vec<ControlApiQuotaPolicyPayload>,
}

#[derive(Serialize)]
struct ControlApiQuotaBackendStatusPayload {
    availability: String,
    degraded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    health_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_observed_at_unix_ms: Option<u64>,
    recent_errors: Vec<ControlApiQuotaBackendErrorPayload>,
}

#[derive(Serialize)]
struct ControlApiQuotaBackendErrorPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    observed_at_unix_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_name: Option<String>,
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

#[derive(Serialize)]
struct ControlApiQuotaPolicyPayload {
    name: String,
    route_allowlist: Vec<String>,
    selector: ControlApiQuotaSelectorPayload,
    #[serde(skip_serializing_if = "Option::is_none")]
    burst: Option<ControlApiQuotaWindowPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sustained: Option<ControlApiQuotaWindowPayload>,
}

#[derive(Serialize)]
struct ControlApiQuotaSelectorPayload {
    route: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client: Option<String>,
}

#[derive(Serialize)]
struct ControlApiQuotaWindowPayload {
    requests: u64,
    window_secs: u64,
}

#[derive(Serialize)]
struct ControlApiObservabilityPayload {
    contract_version: &'static str,
    audit_schema_version: &'static str,
    audit_sink: ControlApiAuditSinkPayload,
    current_generation: Option<u64>,
    dashboard_packages: Vec<ControlApiObservabilityDashboardPayload>,
    backend_health_summary: ControlApiBackendHealthSummaryPayload,
    quota_backend_health_summary: ControlApiQuotaBackendHealthSummaryPayload,
    recent_admin_actions: Vec<ControlApiRecentAdminActionPayload>,
}

#[derive(Serialize)]
struct ControlApiAuditSinkPayload {
    enabled: bool,
    target: &'static str,
    degraded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

#[derive(Serialize)]
struct ControlApiObservabilityDashboardPayload {
    dashboard_id: &'static str,
    definition_path: &'static str,
    focus: &'static str,
}

#[derive(Serialize)]
struct ControlApiBackendHealthSummaryPayload {
    availability: &'static str,
    placed_total: usize,
    healthy: usize,
    unhealthy: usize,
    unknown: usize,
    active_membership: usize,
    suppressed_membership: usize,
    removed_membership: usize,
}

#[derive(Serialize)]
struct ControlApiQuotaBackendHealthSummaryPayload {
    enabled: bool,
    active_backend: String,
    availability: String,
    degraded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    health_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_observed_at_unix_ms: Option<u64>,
    recent_error_count: usize,
}

#[derive(Serialize)]
struct ControlApiRecentAdminActionPayload {
    kind: GenerationEventKind,
    operation: GenerationOperation,
    generation: u64,
    status: GenerationStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    config_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trigger_source: Option<String>,
    requested_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_at_ms: Option<u64>,
    event_emitted_at_ms: u64,
    summary: String,
}

#[derive(Serialize)]
struct ControlApiBackendInventoryPayload {
    healthy: usize,
    total: usize,
    lifecycle: Vec<ControlApiBackendLifecyclePayload>,
}

#[derive(Serialize)]
struct ControlApiAuthPayload {
    providers: Vec<ControlApiAuthProviderPayload>,
    jwt_validation_failures: Vec<ControlApiReasonCountPayload>,
    jwt_algorithm_rejections: Vec<ControlApiReasonCountPayload>,
    unknown_kid_events: Vec<ControlApiUnknownKidEventPayload>,
}

#[derive(Serialize)]
struct ControlApiAuthProviderPayload {
    upstream: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwt: Option<ControlApiJwtProviderPayload>,
}

#[derive(Serialize)]
struct ControlApiJwtProviderPayload {
    provider_mode: &'static str,
    allowed_algorithms: Vec<String>,
    require_kid: bool,
    issuers: Vec<String>,
    audiences: Vec<String>,
    static_key_count: usize,
    jwks_configured: bool,
    jwks_active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwks_cache_state: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    serving_from_stale_cache: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usable_key_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_refresh_success_unix_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_refresh_attempt_unix_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_failure_reason: Option<String>,
}

#[derive(Serialize)]
struct ControlApiReasonCountPayload {
    reason: String,
    count: u64,
}

#[derive(Serialize)]
struct ControlApiUnknownKidEventPayload {
    jwks_source_id: String,
    count: u64,
}

#[derive(Serialize)]
struct ControlApiJwksPayload {
    sources: Vec<ControlApiJwksSourcePayload>,
}

#[derive(Serialize)]
struct ControlApiJwksSourcePayload {
    jwks_source_id: String,
    allowed_algorithms: Vec<String>,
    startup_behavior: &'static str,
    cache_state: &'static str,
    active_key_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    age_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_refresh_attempt_unix_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_refresh_success_unix_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_failure_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
}

#[derive(Serialize)]
struct ControlApiBackendLifecyclePayload {
    backend: String,
    health: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    health_reason: Option<&'static str>,
    membership: &'static str,
    authority_host: String,
    authority_port: u16,
    resolved_addrs: Vec<String>,
    resolution_generation: u64,
    last_refresh_success_at_unix_seconds: Option<u64>,
    placements: Vec<ControlApiBackendPlacementPayload>,
}

#[derive(Serialize)]
struct ControlApiBackendPlacementPayload {
    upstream: String,
    backend_index: usize,
    healthy: bool,
    active_requests: usize,
    ewma_latency_ms: Option<f64>,
    membership_epoch: u64,
}

#[derive(Serialize)]
struct ControlApiMetricsPayload {
    requests_total: u64,
    requests_success: u64,
    requests_failure: u64,
    active_connections: u64,
    backend_timeouts: u64,
    backend_errors: u64,
}

#[derive(Serialize)]
struct ControlApiTlsPayload {
    listeners: HashMap<String, ControlApiTlsListenerPayload>,
    upstreams: HashMap<String, ControlApiTlsUpstreamPayload>,
}

#[derive(Serialize)]
struct ControlApiTlsListenerPayload {
    default_cert: String,
    default_key: String,
    default_cert_not_after_unix_seconds: i64,
    sni_names: Vec<String>,
    client_auth_enabled: bool,
    require_client_cert: bool,
    generation: u64,
    last_loaded_at_unix_ms: u64,
    last_reload_status: String,
}

#[derive(Serialize)]
struct ControlApiTlsUpstreamPayload {
    verify_certificates: bool,
    strict_sni: bool,
    custom_ca_file_configured: bool,
    custom_ca_dir_configured: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_certificate: Option<ControlApiSecretMaterialPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_key: Option<ControlApiSecretMaterialPayload>,
}

#[derive(Serialize)]
struct ControlApiSecretsPayload {
    providers: Vec<ControlApiSecretProviderPayload>,
    material: Vec<ControlApiSecretMaterialPayload>,
}

#[derive(Serialize)]
struct ControlApiSecretProviderPayload {
    provider: String,
    kind: &'static str,
    base_dir_configured: bool,
    default_provider: bool,
}

#[derive(Serialize, Clone)]
struct ControlApiSecretMaterialPayload {
    scope: String,
    source_kind: &'static str,
    last_loaded_at_unix_ms: u64,
    last_reload_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiry_not_after_unix_seconds: Option<i64>,
}

#[derive(Serialize)]
struct ControlApiExtensionModelPayload {
    status: &'static str,
    details: &'static str,
}

#[derive(Serialize)]
struct ControlApiRuntimeGenerationPayload {
    generation: u64,
    config_path: String,
}

#[derive(Serialize)]
struct ControlApiRuntimeHistoryPayload {
    active_generation: u64,
    observability: ControlApiObservabilityPayload,
    retained_generations: Vec<ControlApiRetainedGenerationPayload>,
    entries: Vec<GenerationHistoryEntry>,
}

#[derive(Serialize)]
struct ControlApiRuntimeHistoryGenerationPayload {
    generation: u64,
    observability: ControlApiObservabilityPayload,
    retained_generation: ControlApiRetainedGenerationPayload,
    entries: Vec<GenerationHistoryEntry>,
}

#[derive(Serialize)]
struct ControlApiRetainedGenerationPayload {
    generation: u64,
    status: &'static str,
    rollback_candidate: bool,
    has_bundle: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_health_reason_token(reason: HealthFailureReason, expected: &'static str) {
        let control_plane_reason = health_failure_reason_label(reason);
        let structured_log_token = format!("health_reason={control_plane_reason}");

        assert_eq!(
            control_plane_reason, expected,
            "control-plane health reason token should stay canonical"
        );
        assert_eq!(
            structured_log_token,
            format!("health_reason={expected}"),
            "structured log token should reuse the canonical health reason value"
        );
    }

    mod observability_contracts {
        use super::*;

        #[test]
        fn control_plane_health_reason_tokens_match_metric_reason_labels() {
            assert_health_reason_token(HealthFailureReason::HttpStatus5xx, "5xx");
            assert_health_reason_token(HealthFailureReason::Timeout, "timeout");
            assert_health_reason_token(HealthFailureReason::Transport, "transport");
            assert_health_reason_token(HealthFailureReason::Tls, "tls");
            assert_health_reason_token(HealthFailureReason::CircuitOpen, "circuit_open");
        }

        #[test]
        fn unhealthy_backend_reason_tokens_stay_aligned_across_surfaces() {
            for (reason, expected) in [
                (HealthFailureReason::Timeout, "timeout"),
                (HealthFailureReason::Transport, "transport"),
                (HealthFailureReason::Tls, "tls"),
            ] {
                assert_health_reason_token(reason, expected);
            }
        }
    }

    mod runtime_snapshot_rendering {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        use super::*;
        use crate::runtime::backend::{
            resolution::RuntimeBackendAddressKind,
            state::{
                BackendIdentity, BackendPoolPlacementSnapshot, BackendResolutionState,
                CanonicalBackendLifecycleSnapshot,
            },
        };

        #[test]
        fn backend_payload_serialization_omits_or_includes_optional_health_reason_by_contract() {
            let with_reason = ControlApiBackendLifecyclePayload {
                backend: "b".to_string(),
                health: "unhealthy",
                health_reason: Some("timeout"),
                membership: "active",
                authority_host: "h".to_string(),
                authority_port: 443,
                resolved_addrs: vec![],
                resolution_generation: 0,
                last_refresh_success_at_unix_seconds: None,
                placements: vec![],
            };
            let json = serde_json::to_string(&with_reason).expect("serialize");
            assert!(json.contains("\"health_reason\":\"timeout\""));

            let without = ControlApiBackendLifecyclePayload {
                health_reason: None,
                ..with_reason
            };
            let json = serde_json::to_string(&without).expect("serialize");
            assert!(!json.contains("health_reason"));
        }

        #[test]
        fn backend_inventory_payload_preserves_runtime_snapshot_field_meanings() {
            let inventory = BackendLifecycleInventorySnapshot {
                backends: vec![
                    CanonicalBackendLifecycleSnapshot {
                        identity: BackendIdentity::new("backend-a"),
                        resolution: BackendResolutionState {
                            authority_host: "backend-a.internal".into(),
                            authority_port: 8443,
                            address_kind: RuntimeBackendAddressKind::Hostname,
                            resolved_addrs: vec![SocketAddr::new(
                                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
                                8443,
                            )],
                            last_refresh_success_at: None,
                            refresh_generation: 4,
                        },
                        health: BackendHealthState::Unhealthy {
                            reason: Some(HealthFailureReason::Timeout),
                        },
                        membership: BackendMembershipState::Suppressed,
                        placements: Vec::new(),
                    },
                    CanonicalBackendLifecycleSnapshot {
                        identity: BackendIdentity::new("backend-b"),
                        resolution: BackendResolutionState {
                            authority_host: "backend-b.internal".into(),
                            authority_port: 9443,
                            address_kind: RuntimeBackendAddressKind::IpLiteral,
                            resolved_addrs: vec![SocketAddr::new(
                                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 11)),
                                9443,
                            )],
                            last_refresh_success_at: None,
                            refresh_generation: 2,
                        },
                        health: BackendHealthState::Healthy,
                        membership: BackendMembershipState::Active,
                        placements: vec![BackendPoolPlacementSnapshot {
                            upstream_name: "api".into(),
                            backend_index: 0,
                            healthy: true,
                            active_requests: 1,
                            ewma_latency_ms: Some(12.5),
                            membership_epoch: 9,
                        }],
                    },
                ],
            };

            let payload = ControlApiBackendInventoryPayload::from_inventory(inventory, 1, 1);
            let json = serde_json::to_value(payload).expect("serialize backend inventory");
            let lifecycle = json["lifecycle"].as_array().expect("lifecycle array");

            assert_eq!(lifecycle[0]["backend"], "backend-a");
            assert_eq!(lifecycle[0]["health"], "unhealthy");
            assert_eq!(lifecycle[0]["health_reason"], "timeout");
            assert_eq!(lifecycle[0]["membership"], "suppressed");
            assert_eq!(lifecycle[0]["authority_host"], "backend-a.internal");
            assert_eq!(lifecycle[0]["authority_port"], 8443);
            assert_eq!(lifecycle[0]["resolution_generation"], 4);

            assert_eq!(lifecycle[1]["backend"], "backend-b");
            assert_eq!(lifecycle[1]["health"], "healthy");
            assert!(
                lifecycle[1].get("health_reason").is_none(),
                "healthy payloads must omit optional health_reason"
            );
            assert_eq!(lifecycle[1]["membership"], "active");
            assert_eq!(
                lifecycle[1]["placements"]
                    .as_array()
                    .expect("placements")
                    .len(),
                1
            );
        }
    }
}
