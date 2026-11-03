use std::{
    net::SocketAddr,
    time::{Duration, SystemTime},
};

use impulse_contracts::{
    HealthFailureReason, HedgeOutcomeTelemetryReason, HedgeTriggerTelemetryReason,
    RetryAttemptTelemetryReason, RetryPolicyDenialReason,
};

use crate::{
    DiscoveryRefreshUpdate, Metrics, OverloadShedReason, PingoraDiscoveryRefreshOutcome,
    QuotaBackendHealthReason, QuotaPolicyDecision, QuotaPolicyReason, ResponseCacheOutcome,
    ResponseCompressionAction, RouteOutcome, RuntimeOperationOutcomeReason, RuntimeRejectionReason,
};

#[derive(Clone, Copy)]
pub struct RequestObservationRecorder<'a> {
    metrics: &'a Metrics,
}

#[derive(Clone, Copy)]
pub struct PolicyObservationRecorder<'a> {
    metrics: &'a Metrics,
}

#[derive(Clone, Copy)]
pub struct RuntimeObservationRecorder<'a> {
    metrics: &'a Metrics,
}

#[derive(Clone, Copy)]
pub struct IngressObservationRecorder<'a> {
    metrics: &'a Metrics,
}

impl Metrics {
    #[must_use]
    pub fn request_observations(&self) -> RequestObservationRecorder<'_> {
        RequestObservationRecorder { metrics: self }
    }

    #[must_use]
    pub fn policy_observations(&self) -> PolicyObservationRecorder<'_> {
        PolicyObservationRecorder { metrics: self }
    }

    #[must_use]
    pub fn runtime_observations(&self) -> RuntimeObservationRecorder<'_> {
        RuntimeObservationRecorder { metrics: self }
    }

    #[must_use]
    pub fn ingress_observations(&self) -> IngressObservationRecorder<'_> {
        IngressObservationRecorder { metrics: self }
    }
}

impl RequestObservationRecorder<'_> {
    pub fn inc_total(self) {
        self.metrics.inc_total();
    }

    pub fn inc_success(self) {
        self.metrics.inc_success();
    }

    pub fn inc_failure(self) {
        self.metrics.inc_failure();
    }

    pub fn inc_request_validation_reject(self) {
        self.metrics.inc_request_validation_reject();
    }

    pub fn inc_timeout(self) {
        self.metrics.inc_timeout();
    }

    pub fn inc_backend_error(self) {
        self.metrics.inc_backend_error();
    }

    pub fn try_reserve_request_buffer(self, bytes: usize, cap_bytes: usize) -> bool {
        self.metrics.try_reserve_request_buffer(bytes, cap_bytes)
    }

    pub fn release_request_buffer(self, bytes: usize) {
        self.metrics.release_request_buffer(bytes);
    }

    pub fn inc_request_buffer_limit_reject(self) {
        self.metrics.inc_request_buffer_limit_reject();
    }

    pub fn inc_response_prebuffer_limit_reject(self) {
        self.metrics.inc_response_prebuffer_limit_reject();
    }

    pub fn record_route(self, route: &str, latency: Duration, outcome: RouteOutcome) {
        self.metrics.record_route(route, latency, outcome);
    }

    pub fn record_request_result(
        self,
        upstream: &str,
        backend: Option<&str>,
        status: Option<u16>,
        outcome: RouteOutcome,
        latency: Duration,
    ) {
        self.metrics
            .record_request_result(upstream, backend, status, outcome, latency);
    }
}

impl PolicyObservationRecorder<'_> {
    pub fn inc_policy_denied(self) {
        self.metrics.inc_policy_denied();
    }

    pub fn inc_external_auth_allowed(self) {
        self.metrics.inc_external_auth_allowed();
    }

    pub fn inc_external_auth_denied(self) {
        self.metrics.inc_external_auth_denied();
    }

    pub fn inc_external_auth_timeout(self) {
        self.metrics.inc_external_auth_timeout();
    }

    pub fn inc_external_auth_error(self) {
        self.metrics.inc_external_auth_error();
    }

    pub fn inc_request_rate_limited(self) {
        self.metrics.inc_request_rate_limited();
    }

    pub fn record_quota_policy_outcome(
        self,
        policy: &str,
        decision: QuotaPolicyDecision,
        reason: QuotaPolicyReason,
        selector_dimensions: &str,
        backend_mode: &str,
    ) {
        self.metrics.record_quota_policy_outcome(
            policy,
            decision,
            reason,
            selector_dimensions,
            backend_mode,
        );
    }

    pub fn record_quota_backend_health(self, backend_mode: &str, reason: QuotaBackendHealthReason) {
        self.metrics
            .record_quota_backend_health(backend_mode, reason);
    }

    pub fn inc_overload_shed(self) {
        self.metrics.inc_overload_shed();
    }

    pub fn inc_overload_shed_reason(self, reason: OverloadShedReason) {
        self.metrics.inc_overload_shed_reason(reason);
    }

    pub fn inc_inflight_wait_admit_global(self) {
        self.metrics.inc_inflight_wait_admit_global();
    }

    pub fn inc_inflight_wait_admit_upstream(self) {
        self.metrics.inc_inflight_wait_admit_upstream();
    }

    pub fn inc_hedge_trigger(self, reason: HedgeTriggerTelemetryReason) {
        self.metrics.inc_hedge_trigger(reason);
    }

    pub fn inc_hedge_outcome(self, reason: HedgeOutcomeTelemetryReason) {
        self.metrics.inc_hedge_outcome(reason);
    }

    pub fn observe_hedge_primary_late_ms(self, late_ms: u64) {
        self.metrics.observe_hedge_primary_late_ms(late_ms);
    }

    pub fn inc_retry_attempt(self, reason: RetryAttemptTelemetryReason) {
        self.metrics.inc_retry_attempt(reason);
    }

    pub fn inc_retry_denied(self, reason: RetryPolicyDenialReason) {
        self.metrics.inc_retry_denied(reason);
    }

    pub fn inc_circuit_breaker_rejected(self) {
        self.metrics.inc_circuit_breaker_rejected();
    }

    pub fn set_brownout_active(self, active: bool) {
        self.metrics.set_brownout_active(active);
    }

    pub fn inc_health_failure(self, reason: HealthFailureReason) {
        self.metrics.inc_health_failure(reason);
    }
}

impl RuntimeObservationRecorder<'_> {
    pub fn inc_runtime_panic(self) {
        self.metrics.inc_runtime_panic();
    }

    pub fn inc_health_check_success(self) {
        self.metrics.inc_health_check_success();
    }

    pub fn inc_health_check_failure(self) {
        self.metrics.inc_health_check_failure();
    }

    pub fn inc_runtime_rejection_reason(self, reason: RuntimeRejectionReason) {
        self.metrics.inc_runtime_rejection_reason(reason);
    }

    pub fn inc_runtime_validation_attempt(self) {
        self.metrics.inc_runtime_validation_attempt();
    }

    pub fn inc_runtime_preview_attempt(self) {
        self.metrics.inc_runtime_preview_attempt();
    }

    pub fn record_runtime_activation_outcome(self, reason: RuntimeOperationOutcomeReason) {
        self.metrics.record_runtime_activation_outcome(reason);
    }

    pub fn record_runtime_rollback_outcome(self, reason: RuntimeOperationOutcomeReason) {
        self.metrics.record_runtime_rollback_outcome(reason);
    }

    pub fn set_runtime_active_generation(self, generation: u64) {
        self.metrics.set_runtime_active_generation(generation);
    }

    pub fn set_runtime_history_depth(self, depth: usize) {
        self.metrics.set_runtime_history_depth(depth);
    }

    pub fn record_pingora_lb_selector_rebuild(self, generation: u64, selectors: usize) {
        self.metrics
            .record_pingora_lb_selector_rebuild(generation, selectors);
    }

    pub fn inc_pingora_lb_selector_failure(self) {
        self.metrics.inc_pingora_lb_selector_failure();
    }

    pub fn inc_pingora_lb_selection(self) {
        self.metrics.inc_pingora_lb_selection();
    }

    pub fn inc_watchdog_restart_request(self) {
        self.metrics.inc_watchdog_restart_request();
    }

    pub fn inc_watchdog_restart_hook(self) {
        self.metrics.inc_watchdog_restart_hook();
    }

    pub fn inc_watchdog_degraded_window(self) {
        self.metrics.inc_watchdog_degraded_window();
    }

    pub fn bind_worker_slot(self, slot: usize) {
        self.metrics.bind_worker_slot(slot);
    }

    pub fn record_backend_dns_refresh_success(
        self,
        backend: &str,
        refreshed_at: SystemTime,
        resolved_address_count: usize,
        changed: bool,
    ) {
        self.metrics.record_backend_dns_refresh_success(
            backend,
            refreshed_at,
            resolved_address_count,
            changed,
        );
    }

    pub fn inc_backend_dns_refresh_failure(self) {
        self.metrics.inc_backend_dns_refresh_failure();
    }

    pub fn inc_backend_client_rotation(self, backend: &str) {
        self.metrics.inc_backend_client_rotation(backend);
    }

    pub fn inc_backend_client_rotation_failure(self) {
        self.metrics.inc_backend_client_rotation_failure();
    }

    pub fn record_backend_connect(self, backend: &str, hostname: &str, resolved_addr: SocketAddr) {
        self.metrics
            .record_backend_connect(backend, hostname, resolved_addr);
    }

    pub fn record_pingora_discovery_refresh(
        self,
        outcome: PingoraDiscoveryRefreshOutcome,
        update: Option<DiscoveryRefreshUpdate<'_>>,
    ) {
        self.metrics
            .record_pingora_discovery_refresh(outcome, update);
    }

    pub fn record_jwt_validation_failure(self, reason: &str) {
        self.metrics.record_jwt_validation_failure(reason);
    }

    pub fn record_jwt_algorithm_rejection(self, algorithm: &str) {
        self.metrics.record_jwt_algorithm_rejection(algorithm);
    }

    pub fn record_jwks_unknown_kid(self, jwks_source_id: &str) {
        self.metrics.record_jwks_unknown_kid(jwks_source_id);
    }

    pub fn record_jwks_refresh_started(self, jwks_source_id: &str, refreshed_at: SystemTime) {
        self.metrics
            .record_jwks_refresh_started(jwks_source_id, refreshed_at);
    }

    pub fn record_jwks_refresh_success(
        self,
        jwks_source_id: &str,
        state: &'static str,
        active_key_count: usize,
        refreshed_at: SystemTime,
        last_success_at: Option<SystemTime>,
    ) {
        self.metrics.record_jwks_refresh_success(
            jwks_source_id,
            state,
            active_key_count,
            refreshed_at,
            last_success_at,
        );
    }

    pub fn record_jwks_refresh_failure(
        self,
        jwks_source_id: &str,
        state: &'static str,
        active_key_count: usize,
        refreshed_at: SystemTime,
        last_success_at: Option<SystemTime>,
        failure_reason: Option<&'static str>,
    ) {
        self.metrics.record_jwks_refresh_failure(
            jwks_source_id,
            state,
            active_key_count,
            refreshed_at,
            last_success_at,
            failure_reason,
        );
    }

    pub fn reconcile_jwks_sources<'a, I>(self, active_source_ids: I)
    where
        I: IntoIterator<Item = &'a str>,
    {
        self.metrics.reconcile_jwks_sources(active_source_ids);
    }

    pub fn reconcile_runtime_metric_labels<'a, I, J, K, L>(
        self,
        active_upstreams: I,
        active_backends: J,
        active_listeners: K,
        active_quota_policies: L,
    ) where
        I: IntoIterator<Item = &'a str>,
        J: IntoIterator<Item = &'a str>,
        K: IntoIterator<Item = &'a str>,
        L: IntoIterator<Item = &'a str>,
    {
        self.metrics.reconcile_runtime_metric_labels(
            active_upstreams,
            active_backends,
            active_listeners,
            active_quota_policies,
        );
    }

    pub fn record_upstream_tls_failure(
        self,
        upstream: &str,
        backend: &str,
        phase: &str,
        reason: &str,
    ) {
        self.metrics
            .record_upstream_tls_failure(upstream, backend, phase, reason);
    }

    pub fn record_secret_reload(self, scope: &str, result: &str, reason: &str) {
        self.metrics.record_secret_reload(scope, result, reason);
    }

    pub fn record_secret_resolve(self, provider: &str, result: &str, reason: &str) {
        self.metrics.record_secret_resolve(provider, result, reason);
    }

    pub fn set_secret_last_success_unixtime(self, scope: &str, unix_seconds: u64) {
        self.metrics
            .set_secret_last_success_unixtime(scope, unix_seconds);
    }

    pub fn replace_upstream_client_cert_expiry<I>(self, certs: I)
    where
        I: IntoIterator<Item = (String, i64)>,
    {
        self.metrics.replace_upstream_client_cert_expiry(certs);
    }

    pub fn record_control_plane_cert_reload(self, result: &str, reason: &str) {
        self.metrics
            .record_control_plane_cert_reload(result, reason);
    }
}

impl IngressObservationRecorder<'_> {
    pub fn inc_early_data_accepted(self) {
        self.metrics.inc_early_data_accepted();
    }

    pub fn inc_early_data_rejected(self) {
        self.metrics.inc_early_data_rejected();
    }

    pub fn inc_ingress_packet(self) {
        self.metrics.inc_ingress_packet();
    }

    pub fn inc_ingress_queue_drop(self) {
        self.metrics.inc_ingress_queue_drop();
    }

    pub fn inc_ingress_queue_drop_bytes(self, bytes: usize) {
        self.metrics.inc_ingress_queue_drop_bytes(bytes);
    }

    pub fn set_ingress_queue_bytes(self, bytes: usize) {
        self.metrics.set_ingress_queue_bytes(bytes);
    }

    pub fn inc_ingress_bad_header(self) {
        self.metrics.inc_ingress_bad_header();
    }

    pub fn inc_ingress_rate_limited(self) {
        self.metrics.inc_ingress_rate_limited();
    }

    pub fn inc_ingress_unroutable(self) {
        self.metrics.inc_ingress_unroutable();
    }

    pub fn inc_ingress_draining_drop(self) {
        self.metrics.inc_ingress_draining_drop();
    }

    pub fn inc_ingress_connection_create_failed(self) {
        self.metrics.inc_ingress_connection_create_failed();
    }

    pub fn inc_ingress_version_neg_failed(self) {
        self.metrics.inc_ingress_version_neg_failed();
    }

    pub fn set_active_connections(self, count: usize) {
        self.metrics.set_active_connections(count);
    }

    pub fn inc_connection_cap_reject(self) {
        self.metrics.inc_connection_cap_reject();
    }

    pub fn inc_scid_rotation(self) {
        self.metrics.inc_scid_rotation();
    }

    pub fn record_response_compression_outcome(self, outcome: ResponseCompressionAction) {
        self.metrics.record_response_compression_outcome(outcome);
    }

    pub fn add_response_compression_bytes(self, input: usize, output: usize) {
        self.metrics.add_response_compression_bytes(input, output);
    }

    pub fn record_response_cache_outcome(self, outcome: ResponseCacheOutcome) {
        self.metrics.record_response_cache_outcome(outcome);
    }

    pub fn add_response_cache_outcomes(self, outcome: ResponseCacheOutcome, count: usize) {
        self.metrics.add_response_cache_outcomes(outcome, count);
    }

    pub fn inc_downstream_tls_handshake_success(self) {
        self.metrics.inc_downstream_tls_handshake_success();
    }

    pub fn record_downstream_tls_handshake_failure(self, listener: &str, reason: &str) {
        self.metrics
            .record_downstream_tls_handshake_failure(listener, reason);
    }

    pub fn record_downstream_tls_cert_selection(self, listener: &str, selection: &str) {
        self.metrics
            .record_downstream_tls_cert_selection(listener, selection);
    }

    pub fn record_downstream_tls_alpn(self, listener: &str, protocol: &str) {
        self.metrics.record_downstream_tls_alpn(listener, protocol);
    }

    pub fn replace_downstream_tls_cert_expiry<I>(self, listener: &str, certs: I)
    where
        I: IntoIterator<Item = (String, i64)>,
    {
        self.metrics
            .replace_downstream_tls_cert_expiry(listener, certs);
    }

    pub fn inc_control_api_connection_limit_drop(self) {
        self.metrics.inc_control_api_connection_limit_drop();
    }

    pub fn inc_control_api_audit_event_drop(self) {
        self.metrics.inc_control_api_audit_event_drop();
    }

    pub fn inc_control_api_audit_write_failure(self) {
        self.metrics.inc_control_api_audit_write_failure();
    }
}
