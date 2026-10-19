use std::{
    cell::Cell,
    collections::{HashMap, HashSet},
    env,
    sync::{
        RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use impulse_errors::{
    HedgeOutcomeTelemetryReason, HedgeTriggerTelemetryReason, RetryAttemptTelemetryReason,
    RetryPolicyDenialReason,
};
use impulse_lb::health::HealthFailureReason;

use crate::{
    observability::{QuotaBackendHealthReason, QuotaPolicyDecision, QuotaPolicyReason},
    request_pipeline::ResponseCompressionAction,
    runtime::activation::{RuntimeOperationOutcomeReason, RuntimeRejectionReason},
};

mod recording;
mod snapshot;
mod support;
#[cfg(test)]
mod tests;
mod types;

#[derive(Clone, Copy)]
pub(crate) enum PingoraDiscoveryRefreshOutcome {
    Updated,
    Unchanged,
    RetainedFailure,
    PublishFailed,
}

#[derive(Clone, Copy)]
pub(crate) enum ResponseCacheOutcome {
    Hit,
    Miss,
    Bypass,
    Rejection,
    Eviction,
    Expiry,
    LockWait,
}

impl ResponseCacheOutcome {
    const ALL: [Self; 7] = [
        Self::Hit,
        Self::Miss,
        Self::Bypass,
        Self::Rejection,
        Self::Eviction,
        Self::Expiry,
        Self::LockWait,
    ];
    const COUNT: usize = Self::ALL.len();

    const fn index(self) -> usize {
        self as usize
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Miss => "miss",
            Self::Bypass => "bypass",
            Self::Rejection => "rejection",
            Self::Eviction => "eviction",
            Self::Expiry => "expiry",
            Self::LockWait => "lock_wait",
        }
    }
}

impl PingoraDiscoveryRefreshOutcome {
    const ALL: [Self; 4] = [
        Self::Updated,
        Self::Unchanged,
        Self::RetainedFailure,
        Self::PublishFailed,
    ];
    const COUNT: usize = Self::ALL.len();

    const fn index(self) -> usize {
        self as usize
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Updated => "updated",
            Self::Unchanged => "unchanged",
            Self::RetainedFailure => "retained_failure",
            Self::PublishFailed => "publish_failed",
        }
    }
}

#[derive(Clone, Default)]
struct PingoraDiscoveryState {
    membership_generation: u64,
    rebuild_duration_ns: u64,
}

#[allow(unused_imports)]
pub(crate) use self::types::RequestLatencyStats;
pub use self::types::{OverloadShedReason, RouteOutcome};
use self::{
    support::*,
    types::{
        BACKEND_CONNECT_ATTEMPT_LABEL_CAP, BackendConnectAttemptKey, BackendDnsState,
        BackendMetricsSnapshot, BackendMetricsSnapshotCache, BackendRequestCountKey,
        BackendRotationState, ControlPlaneCertReloadKey, DownstreamTlsAlpnKey,
        DownstreamTlsCertExpiryKey, DownstreamTlsCertSelectionKey,
        DownstreamTlsHandshakeFailureKey, JwksSourceState, JwtJwksMetricsSnapshot,
        JwtJwksMetricsSnapshotCache, LATENCY_BUCKETS_MS, METRIC_LABEL_OVER_CAP,
        QuotaBackendHealthKey, QuotaMetricsSnapshot, QuotaMetricsSnapshotCache,
        QuotaPolicyOutcomeKey, ROUTE_LATENCY_SAMPLE_EVERY_ENV, RequestResultMetricsSnapshot,
        RequestResultMetricsSnapshotCache, RequestResultMetricsStore, RouteStats, RouteStatsAtomic,
        RouteWorkerMetricsRenderCache, SecretLastSuccessKey, SecretMetricsSnapshot,
        SecretMetricsSnapshotCache, SecretReloadKey, SecretResolveKey, UpstreamClientCertExpiryKey,
        UpstreamRequestCountKey, UpstreamRequestLatencyKey, UpstreamTlsFailureKey,
        WorkerStatsAtomic,
    },
};

pub struct Metrics {
    pub requests_total: AtomicU64,
    pub requests_success: AtomicU64,
    pub requests_failure: AtomicU64,
    pub request_validation_rejects: AtomicU64,
    pub policy_denied: AtomicU64,
    pub external_auth_allowed: AtomicU64,
    pub external_auth_denied: AtomicU64,
    pub external_auth_timeout: AtomicU64,
    pub external_auth_error: AtomicU64,
    pub request_rate_limited: AtomicU64,
    pub early_data_accepted: AtomicU64,
    pub early_data_rejected: AtomicU64,
    pub health_checks_total: AtomicU64,
    pub health_checks_success: AtomicU64,
    pub health_checks_failure: AtomicU64,
    pub backend_timeouts: AtomicU64,
    pub backend_errors: AtomicU64,
    pub overload_shed: AtomicU64,
    pub overload_shed_brownout: AtomicU64,
    pub overload_shed_adaptive: AtomicU64,
    pub overload_shed_route_cap: AtomicU64,
    pub overload_shed_route_global_cap: AtomicU64,
    pub overload_shed_global_inflight: AtomicU64,
    pub overload_shed_upstream_inflight: AtomicU64,
    pub inflight_wait_admit_global: AtomicU64,
    pub inflight_wait_admit_upstream: AtomicU64,
    pub overload_shed_backend_inflight: AtomicU64,
    pub overload_shed_circuit_open: AtomicU64,
    pub overload_shed_request_buffer: AtomicU64,
    pub overload_shed_response_prebuffer: AtomicU64,
    pub overload_shed_connection_cap: AtomicU64,
    pub active_connections: AtomicU64,
    pub connection_cap_rejects: AtomicU64,
    pub hedge_triggered: AtomicU64,
    pub hedge_won: AtomicU64,
    pub hedge_wasted: AtomicU64,
    pub hedge_primary_won_after_trigger: AtomicU64,
    pub hedge_primary_late_ms_total: AtomicU64,
    pub hedge_primary_late_samples: AtomicU64,
    pub ingress_packets_total: AtomicU64,
    pub ingress_queue_drops: AtomicU64,
    pub ingress_queue_drop_bytes: AtomicU64,
    pub ingress_queue_bytes: AtomicU64,
    pub ingress_bad_header_total: AtomicU64,
    pub ingress_rate_limited_total: AtomicU64,
    pub ingress_unroutable_total: AtomicU64,
    pub ingress_draining_drops_total: AtomicU64,
    pub ingress_connection_create_failed_total: AtomicU64,
    pub ingress_version_neg_failed_total: AtomicU64,
    pub request_buffered_bytes: AtomicU64,
    pub request_buffered_high_watermark_bytes: AtomicU64,
    pub request_buffer_limit_rejects: AtomicU64,
    pub response_prebuffer_limit_rejects: AtomicU64,
    response_compression_outcomes: [AtomicU64; ResponseCompressionAction::COUNT],
    response_compression_input_bytes: AtomicU64,
    response_compression_output_bytes: AtomicU64,
    response_cache_outcomes: [AtomicU64; ResponseCacheOutcome::COUNT],
    pub scid_rotations: AtomicU64,
    pub control_api_connection_limit_drops: AtomicU64,
    pub control_api_audit_event_drops: AtomicU64,
    pub control_api_audit_write_failures: AtomicU64,
    pub watchdog_restart_requests: AtomicU64,
    pub watchdog_restart_hooks: AtomicU64,
    pub watchdog_degraded_windows: AtomicU64,
    pub runtime_panics: AtomicU64,
    pub runtime_rejection_invalid_config: AtomicU64,
    pub runtime_rejection_startup_owned_change: AtomicU64,
    pub runtime_rejection_bind_conflict: AtomicU64,
    pub runtime_rejection_resource_prepare_failed: AtomicU64,
    pub runtime_rejection_incompatible_reload: AtomicU64,
    pub runtime_rejection_unknown_generation: AtomicU64,
    pub runtime_rejection_rollback_not_allowed: AtomicU64,
    pub runtime_validation_attempts: AtomicU64,
    pub runtime_preview_attempts: AtomicU64,
    pub runtime_active_generation: AtomicU64,
    pub runtime_history_depth: AtomicU64,
    pub pingora_lb_selector_generation: AtomicU64,
    pub pingora_lb_selector_rebuilds: AtomicU64,
    pub pingora_lb_selector_failures: AtomicU64,
    pub pingora_lb_selections: AtomicU64,
    pingora_discovery_refresh_outcomes: [AtomicU64; PingoraDiscoveryRefreshOutcome::COUNT],
    pingora_discovery_state: RwLock<HashMap<String, PingoraDiscoveryState>>,
    runtime_activation_outcomes: [AtomicU64; RuntimeOperationOutcomeReason::COUNT],
    runtime_rollback_outcomes: [AtomicU64; RuntimeOperationOutcomeReason::COUNT],
    pub retries_total: AtomicU64,
    pub retry_denied_budget: AtomicU64,
    pub retry_denied_no_bodyless: AtomicU64,
    pub retry_denied_no_alternate: AtomicU64,
    pub retry_reason_timeout: AtomicU64,
    pub retry_reason_transport: AtomicU64,
    pub retry_reason_pool: AtomicU64,
    pub circuit_breaker_rejected_total: AtomicU64,
    pub brownout_active: AtomicU64,
    pub health_failure_5xx: AtomicU64,
    pub health_failure_timeout: AtomicU64,
    pub health_failure_transport: AtomicU64,
    pub health_failure_tls: AtomicU64,
    pub downstream_tls_handshake_success: AtomicU64,
    pub backend_dns_refresh_success: AtomicU64,
    pub backend_dns_refresh_failure: AtomicU64,
    pub backend_dns_refresh_address_changes: AtomicU64,
    pub backend_client_rotations: AtomicU64,
    pub backend_client_rotation_failures: AtomicU64,
    jwt_validation_failures: RwLock<HashMap<String, u64>>,
    jwt_algorithm_rejections: RwLock<HashMap<String, u64>>,
    jwks_unknown_kid_events: RwLock<HashMap<String, u64>>,
    jwks_source_state: RwLock<HashMap<String, JwksSourceState>>,
    route_latency_sample_every: u64,
    route_latency_sample_counter: AtomicU64,
    route_render_order: Vec<(usize, String)>,
    route_label_to_id: HashMap<String, usize>,
    route_stats: Vec<RouteStatsAtomic>,
    unrouted_route_id: usize,
    worker_render_order: Vec<(usize, String)>,
    worker_stats: Vec<WorkerStatsAtomic>,
    backend_dns_state: RwLock<HashMap<String, BackendDnsState>>,
    backend_rotation_state: RwLock<HashMap<String, BackendRotationState>>,
    backend_connect_attempts: RwLock<HashMap<BackendConnectAttemptKey, u64>>,
    request_result_metrics: RwLock<RequestResultMetricsStore>,
    request_result_metrics_version: AtomicU64,
    request_result_metrics_cache: RwLock<RequestResultMetricsSnapshotCache>,
    quota_metrics_version: AtomicU64,
    quota_metrics_cache: RwLock<QuotaMetricsSnapshotCache>,
    jwt_jwks_metrics_version: AtomicU64,
    jwt_jwks_metrics_cache: RwLock<JwtJwksMetricsSnapshotCache>,
    backend_metrics_version: AtomicU64,
    backend_metrics_cache: RwLock<BackendMetricsSnapshotCache>,
    secret_metrics_version: AtomicU64,
    secret_metrics_cache: RwLock<SecretMetricsSnapshotCache>,
    route_worker_metrics_version: AtomicU64,
    route_worker_metrics_cache: RwLock<RouteWorkerMetricsRenderCache>,
    quota_policy_outcomes: RwLock<HashMap<QuotaPolicyOutcomeKey, u64>>,
    quota_backend_health: RwLock<HashMap<QuotaBackendHealthKey, u64>>,
    downstream_tls_handshake_failures: RwLock<HashMap<DownstreamTlsHandshakeFailureKey, u64>>,
    downstream_tls_cert_selections: RwLock<HashMap<DownstreamTlsCertSelectionKey, u64>>,
    downstream_tls_alpn_negotiated: RwLock<HashMap<DownstreamTlsAlpnKey, u64>>,
    downstream_tls_cert_expiry: RwLock<HashMap<DownstreamTlsCertExpiryKey, i64>>,
    upstream_tls_failures: RwLock<HashMap<UpstreamTlsFailureKey, u64>>,
    secret_reload_totals: RwLock<HashMap<SecretReloadKey, u64>>,
    secret_resolve_totals: RwLock<HashMap<SecretResolveKey, u64>>,
    secret_last_success_unixtime: RwLock<HashMap<SecretLastSuccessKey, u64>>,
    upstream_client_cert_expiry: RwLock<HashMap<UpstreamClientCertExpiryKey, i64>>,
    control_plane_cert_reload_totals: RwLock<HashMap<ControlPlaneCertReloadKey, u64>>,
}

mod prometheus;
