use super::*;

impl Default for Metrics {
    fn default() -> Self {
        Self::new(1, [String::from("unrouted")])
    }
}

thread_local! {
    static WORKER_METRICS_SLOT: Cell<usize> = const { Cell::new(0) };
}

impl Metrics {
    fn mark_route_worker_metrics_stale(&self) {
        self.route_worker_metrics_version
            .fetch_add(1, Ordering::Relaxed);
    }

    fn mark_quota_metrics_stale(&self) {
        self.quota_metrics_version.fetch_add(1, Ordering::Relaxed);
    }

    fn mark_jwt_jwks_metrics_stale(&self) {
        self.jwt_jwks_metrics_version
            .fetch_add(1, Ordering::Relaxed);
    }

    fn mark_backend_metrics_stale(&self) {
        self.backend_metrics_version.fetch_add(1, Ordering::Relaxed);
    }

    fn mark_secret_metrics_stale(&self) {
        self.secret_metrics_version.fetch_add(1, Ordering::Relaxed);
    }

    pub fn new<I>(worker_slots: usize, route_labels: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        let route_latency_sample_every = env::var(ROUTE_LATENCY_SAMPLE_EVERY_ENV)
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(1);

        let mut route_labels_dedup = Vec::new();
        let mut route_label_to_id = HashMap::new();
        for raw in route_labels {
            let label = raw.trim();
            if label.is_empty() || route_label_to_id.contains_key(label) {
                continue;
            }
            let id = route_labels_dedup.len();
            route_labels_dedup.push(label.to_string());
            route_label_to_id.insert(label.to_string(), id);
        }
        if !route_label_to_id.contains_key("unrouted") {
            let id = route_labels_dedup.len();
            route_labels_dedup.push("unrouted".to_string());
            route_label_to_id.insert("unrouted".to_string(), id);
        }
        let unrouted_route_id = route_label_to_id.get("unrouted").copied().unwrap_or(0);

        let worker_slots = worker_slots.max(1);
        let worker_labels = (0..worker_slots)
            .map(|idx| format!("worker-{idx}"))
            .collect::<Vec<_>>();
        let mut worker_render_order = worker_labels
            .iter()
            .enumerate()
            .map(|(idx, label)| (idx, label.to_string()))
            .collect::<Vec<_>>();
        worker_render_order.sort_by(|(_, left), (_, right)| left.cmp(right));
        let worker_stats = (0..worker_slots)
            .map(|_| WorkerStatsAtomic::new())
            .collect::<Vec<_>>();
        let route_stats = route_labels_dedup
            .iter()
            .map(|_| RouteStatsAtomic::new())
            .collect::<Vec<_>>();
        let mut route_render_order = route_labels_dedup
            .iter()
            .enumerate()
            .map(|(idx, label)| (idx, label.to_string()))
            .collect::<Vec<_>>();
        route_render_order.sort_by(|(_, left), (_, right)| left.cmp(right));

        Self {
            requests_total: AtomicU64::new(0),
            requests_success: AtomicU64::new(0),
            requests_failure: AtomicU64::new(0),
            request_validation_rejects: AtomicU64::new(0),
            policy_denied: AtomicU64::new(0),
            external_auth_allowed: AtomicU64::new(0),
            external_auth_denied: AtomicU64::new(0),
            external_auth_timeout: AtomicU64::new(0),
            external_auth_error: AtomicU64::new(0),
            request_rate_limited: AtomicU64::new(0),
            early_data_accepted: AtomicU64::new(0),
            early_data_rejected: AtomicU64::new(0),
            health_checks_total: AtomicU64::new(0),
            health_checks_success: AtomicU64::new(0),
            health_checks_failure: AtomicU64::new(0),
            backend_timeouts: AtomicU64::new(0),
            backend_errors: AtomicU64::new(0),
            overload_shed: AtomicU64::new(0),
            overload_shed_brownout: AtomicU64::new(0),
            overload_shed_adaptive: AtomicU64::new(0),
            overload_shed_route_cap: AtomicU64::new(0),
            overload_shed_route_global_cap: AtomicU64::new(0),
            overload_shed_global_inflight: AtomicU64::new(0),
            overload_shed_upstream_inflight: AtomicU64::new(0),
            inflight_wait_admit_global: AtomicU64::new(0),
            inflight_wait_admit_upstream: AtomicU64::new(0),
            overload_shed_backend_inflight: AtomicU64::new(0),
            overload_shed_circuit_open: AtomicU64::new(0),
            overload_shed_request_buffer: AtomicU64::new(0),
            overload_shed_response_prebuffer: AtomicU64::new(0),
            overload_shed_connection_cap: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            connection_cap_rejects: AtomicU64::new(0),
            hedge_triggered: AtomicU64::new(0),
            hedge_won: AtomicU64::new(0),
            hedge_wasted: AtomicU64::new(0),
            hedge_primary_won_after_trigger: AtomicU64::new(0),
            hedge_primary_late_ms_total: AtomicU64::new(0),
            hedge_primary_late_samples: AtomicU64::new(0),
            ingress_packets_total: AtomicU64::new(0),
            ingress_queue_drops: AtomicU64::new(0),
            ingress_queue_drop_bytes: AtomicU64::new(0),
            ingress_queue_bytes: AtomicU64::new(0),
            ingress_bad_header_total: AtomicU64::new(0),
            ingress_rate_limited_total: AtomicU64::new(0),
            ingress_unroutable_total: AtomicU64::new(0),
            ingress_draining_drops_total: AtomicU64::new(0),
            ingress_connection_create_failed_total: AtomicU64::new(0),
            ingress_version_neg_failed_total: AtomicU64::new(0),
            request_buffered_bytes: AtomicU64::new(0),
            request_buffered_high_watermark_bytes: AtomicU64::new(0),
            request_buffer_limit_rejects: AtomicU64::new(0),
            response_prebuffer_limit_rejects: AtomicU64::new(0),
            response_compression_outcomes: std::array::from_fn(|_| AtomicU64::new(0)),
            response_compression_input_bytes: AtomicU64::new(0),
            response_compression_output_bytes: AtomicU64::new(0),
            response_cache_outcomes: std::array::from_fn(|_| AtomicU64::new(0)),
            scid_rotations: AtomicU64::new(0),
            control_api_connection_limit_drops: AtomicU64::new(0),
            control_api_audit_event_drops: AtomicU64::new(0),
            control_api_audit_write_failures: AtomicU64::new(0),
            watchdog_restart_requests: AtomicU64::new(0),
            watchdog_restart_hooks: AtomicU64::new(0),
            watchdog_degraded_windows: AtomicU64::new(0),
            runtime_panics: AtomicU64::new(0),
            runtime_rejection_invalid_config: AtomicU64::new(0),
            runtime_rejection_startup_owned_change: AtomicU64::new(0),
            runtime_rejection_bind_conflict: AtomicU64::new(0),
            runtime_rejection_resource_prepare_failed: AtomicU64::new(0),
            runtime_rejection_incompatible_reload: AtomicU64::new(0),
            runtime_rejection_unknown_generation: AtomicU64::new(0),
            runtime_rejection_rollback_not_allowed: AtomicU64::new(0),
            runtime_validation_attempts: AtomicU64::new(0),
            runtime_preview_attempts: AtomicU64::new(0),
            runtime_active_generation: AtomicU64::new(0),
            runtime_history_depth: AtomicU64::new(0),
            pingora_lb_selector_generation: AtomicU64::new(0),
            pingora_lb_selector_rebuilds: AtomicU64::new(0),
            pingora_lb_selector_failures: AtomicU64::new(0),
            pingora_lb_selections: AtomicU64::new(0),
            pingora_discovery_refresh_outcomes: std::array::from_fn(|_| AtomicU64::new(0)),
            pingora_discovery_state: RwLock::new(HashMap::new()),
            runtime_activation_outcomes: std::array::from_fn(|_| AtomicU64::new(0)),
            runtime_rollback_outcomes: std::array::from_fn(|_| AtomicU64::new(0)),
            retries_total: AtomicU64::new(0),
            retry_denied_budget: AtomicU64::new(0),
            retry_denied_no_bodyless: AtomicU64::new(0),
            retry_denied_no_alternate: AtomicU64::new(0),
            retry_reason_timeout: AtomicU64::new(0),
            retry_reason_transport: AtomicU64::new(0),
            retry_reason_pool: AtomicU64::new(0),
            circuit_breaker_rejected_total: AtomicU64::new(0),
            brownout_active: AtomicU64::new(0),
            health_failure_5xx: AtomicU64::new(0),
            health_failure_timeout: AtomicU64::new(0),
            health_failure_transport: AtomicU64::new(0),
            health_failure_tls: AtomicU64::new(0),
            downstream_tls_handshake_success: AtomicU64::new(0),
            backend_dns_refresh_success: AtomicU64::new(0),
            backend_dns_refresh_failure: AtomicU64::new(0),
            backend_dns_refresh_address_changes: AtomicU64::new(0),
            backend_client_rotations: AtomicU64::new(0),
            backend_client_rotation_failures: AtomicU64::new(0),
            jwt_validation_failures: RwLock::new(HashMap::new()),
            jwt_algorithm_rejections: RwLock::new(HashMap::new()),
            jwks_unknown_kid_events: RwLock::new(HashMap::new()),
            jwks_source_state: RwLock::new(HashMap::new()),
            route_latency_sample_every,
            route_latency_sample_counter: AtomicU64::new(0),
            route_render_order,
            route_label_to_id,
            route_stats,
            unrouted_route_id,
            worker_render_order,
            worker_stats,
            backend_dns_state: RwLock::new(HashMap::new()),
            backend_rotation_state: RwLock::new(HashMap::new()),
            backend_connect_attempts: RwLock::new(HashMap::new()),
            request_result_metrics: RwLock::new(RequestResultMetricsStore::default()),
            request_result_metrics_version: AtomicU64::new(0),
            request_result_metrics_cache: RwLock::new(RequestResultMetricsSnapshotCache::default()),
            quota_metrics_version: AtomicU64::new(0),
            quota_metrics_cache: RwLock::new(QuotaMetricsSnapshotCache::default()),
            jwt_jwks_metrics_version: AtomicU64::new(0),
            jwt_jwks_metrics_cache: RwLock::new(JwtJwksMetricsSnapshotCache::default()),
            backend_metrics_version: AtomicU64::new(0),
            backend_metrics_cache: RwLock::new(BackendMetricsSnapshotCache::default()),
            secret_metrics_version: AtomicU64::new(0),
            secret_metrics_cache: RwLock::new(SecretMetricsSnapshotCache::default()),
            route_worker_metrics_version: AtomicU64::new(0),
            route_worker_metrics_cache: RwLock::new(RouteWorkerMetricsRenderCache::default()),
            quota_policy_outcomes: RwLock::new(HashMap::new()),
            quota_backend_health: RwLock::new(HashMap::new()),
            downstream_tls_handshake_failures: RwLock::new(HashMap::new()),
            downstream_tls_cert_selections: RwLock::new(HashMap::new()),
            downstream_tls_alpn_negotiated: RwLock::new(HashMap::new()),
            downstream_tls_cert_expiry: RwLock::new(HashMap::new()),
            upstream_tls_failures: RwLock::new(HashMap::new()),
            secret_reload_totals: RwLock::new(HashMap::new()),
            secret_resolve_totals: RwLock::new(HashMap::new()),
            secret_last_success_unixtime: RwLock::new(HashMap::new()),
            upstream_client_cert_expiry: RwLock::new(HashMap::new()),
            control_plane_cert_reload_totals: RwLock::new(HashMap::new()),
        }
    }

    pub fn bind_worker_slot(&self, slot: usize) {
        let max_index = self.worker_stats.len().saturating_sub(1);
        WORKER_METRICS_SLOT.with(|current| current.set(slot.min(max_index)));
    }

    pub fn inc_total(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.inc_worker_requests_total();
    }

    pub fn inc_success(&self) {
        self.requests_success.fetch_add(1, Ordering::Relaxed);
        self.inc_worker_requests_success();
    }

    pub fn inc_failure(&self) {
        self.requests_failure.fetch_add(1, Ordering::Relaxed);
        self.inc_worker_requests_failure();
    }

    pub fn inc_request_validation_reject(&self) {
        self.request_validation_rejects
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_policy_denied(&self) {
        self.policy_denied.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_external_auth_allowed(&self) {
        self.external_auth_allowed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_external_auth_denied(&self) {
        self.external_auth_denied.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_external_auth_timeout(&self) {
        self.external_auth_timeout.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_external_auth_error(&self) {
        self.external_auth_error.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_request_rate_limited(&self) {
        self.request_rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_quota_policy_outcome(
        &self,
        policy: &str,
        decision: QuotaPolicyDecision,
        reason: QuotaPolicyReason,
        selector_dimensions: &str,
        backend_mode: &str,
    ) {
        if let Ok(mut guard) = self.quota_policy_outcomes.write() {
            let key = QuotaPolicyOutcomeKey {
                policy: policy.to_string(),
                decision: decision.slug().to_string(),
                reason: reason.slug().to_string(),
                selector_dimensions: selector_dimensions.to_string(),
                backend_mode: backend_mode.to_string(),
            };
            *guard.entry(key).or_default() += 1;
            self.mark_quota_metrics_stale();
        }
    }

    pub fn record_quota_backend_health(
        &self,
        backend_mode: &str,
        reason: QuotaBackendHealthReason,
    ) {
        if let Ok(mut guard) = self.quota_backend_health.write() {
            let key = QuotaBackendHealthKey {
                backend_mode: backend_mode.to_string(),
                reason: reason.slug().to_string(),
            };
            *guard.entry(key).or_default() += 1;
            self.mark_quota_metrics_stale();
        }
    }

    pub fn inc_early_data_accepted(&self) {
        self.early_data_accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_early_data_rejected(&self) {
        self.early_data_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_health_check_success(&self) {
        self.health_checks_total.fetch_add(1, Ordering::Relaxed);
        self.health_checks_success.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_health_check_failure(&self) {
        self.health_checks_total.fetch_add(1, Ordering::Relaxed);
        self.health_checks_failure.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_timeout(&self) {
        self.backend_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_backend_error(&self) {
        self.backend_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_overload_shed(&self) {
        self.overload_shed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_overload_shed_reason(&self, reason: OverloadShedReason) {
        self.overload_shed.fetch_add(1, Ordering::Relaxed);
        match reason {
            OverloadShedReason::Brownout => {
                self.overload_shed_brownout.fetch_add(1, Ordering::Relaxed);
            }
            OverloadShedReason::AdaptiveAdmission => {
                self.overload_shed_adaptive.fetch_add(1, Ordering::Relaxed);
            }
            OverloadShedReason::RouteCap => {
                self.overload_shed_route_cap.fetch_add(1, Ordering::Relaxed);
            }
            OverloadShedReason::RouteGlobalCap => {
                self.overload_shed_route_global_cap
                    .fetch_add(1, Ordering::Relaxed);
            }
            OverloadShedReason::GlobalInflight => {
                self.overload_shed_global_inflight
                    .fetch_add(1, Ordering::Relaxed);
            }
            OverloadShedReason::UpstreamInflight => {
                self.overload_shed_upstream_inflight
                    .fetch_add(1, Ordering::Relaxed);
            }
            OverloadShedReason::BackendInflight => {
                self.overload_shed_backend_inflight
                    .fetch_add(1, Ordering::Relaxed);
            }
            OverloadShedReason::CircuitOpen => {
                self.overload_shed_circuit_open
                    .fetch_add(1, Ordering::Relaxed);
            }
            OverloadShedReason::RequestBufferCap => {
                self.overload_shed_request_buffer
                    .fetch_add(1, Ordering::Relaxed);
            }
            OverloadShedReason::ResponsePrebufferCap => {
                self.overload_shed_response_prebuffer
                    .fetch_add(1, Ordering::Relaxed);
            }
            OverloadShedReason::ConnectionCap => {
                self.overload_shed_connection_cap
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn set_active_connections(&self, count: usize) {
        self.active_connections
            .store(count as u64, Ordering::Relaxed);
    }

    pub fn inc_connection_cap_reject(&self) {
        self.connection_cap_rejects.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_inflight_wait_admit_global(&self) {
        self.inflight_wait_admit_global
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_inflight_wait_admit_upstream(&self) {
        self.inflight_wait_admit_upstream
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_hedge_trigger(&self, _reason: HedgeTriggerTelemetryReason) {
        self.hedge_triggered.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_hedge_outcome(&self, reason: HedgeOutcomeTelemetryReason) {
        match reason {
            HedgeOutcomeTelemetryReason::PrimaryWonAfterTrigger => {
                self.hedge_primary_won_after_trigger
                    .fetch_add(1, Ordering::Relaxed);
                self.hedge_wasted.fetch_add(1, Ordering::Relaxed);
            }
            HedgeOutcomeTelemetryReason::HedgeWon => {
                self.hedge_won.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn observe_hedge_primary_late_ms(&self, late_ms: u64) {
        self.hedge_primary_late_ms_total
            .fetch_add(late_ms, Ordering::Relaxed);
        self.hedge_primary_late_samples
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ingress_packet(&self) {
        self.ingress_packets_total.fetch_add(1, Ordering::Relaxed);
        self.inc_worker_ingress_packets_total();
    }

    pub fn inc_ingress_queue_drop(&self) {
        self.ingress_queue_drops.fetch_add(1, Ordering::Relaxed);
        self.inc_worker_ingress_queue_drops();
    }

    pub fn inc_ingress_queue_drop_bytes(&self, bytes: usize) {
        self.ingress_queue_drop_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.inc_worker_ingress_queue_drop_bytes(bytes as u64);
    }

    pub fn set_ingress_queue_bytes(&self, bytes: usize) {
        self.ingress_queue_bytes
            .store(bytes as u64, Ordering::Relaxed);
    }

    pub fn inc_ingress_bad_header(&self) {
        self.ingress_bad_header_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ingress_rate_limited(&self) {
        self.ingress_rate_limited_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ingress_unroutable(&self) {
        self.ingress_unroutable_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ingress_draining_drop(&self) {
        self.ingress_draining_drops_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ingress_connection_create_failed(&self) {
        self.ingress_connection_create_failed_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ingress_version_neg_failed(&self) {
        self.ingress_version_neg_failed_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_backend_dns_refresh_success(
        &self,
        backend: &str,
        refreshed_at: SystemTime,
        resolved_address_count: usize,
        changed: bool,
    ) {
        self.backend_dns_refresh_success
            .fetch_add(1, Ordering::Relaxed);
        if changed {
            self.backend_dns_refresh_address_changes
                .fetch_add(1, Ordering::Relaxed);
        }

        let last_success_unix_seconds = refreshed_at
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_secs())
            .unwrap_or_default();
        if let Ok(mut guard) = self.backend_dns_state.write() {
            guard.insert(
                backend.to_string(),
                BackendDnsState {
                    last_success_unix_seconds,
                    resolved_address_count: resolved_address_count as u64,
                },
            );
            self.mark_backend_metrics_stale();
        }
    }

    pub fn inc_backend_dns_refresh_failure(&self) {
        self.backend_dns_refresh_failure
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_backend_client_rotation(&self, backend: &str) {
        self.backend_client_rotations
            .fetch_add(1, Ordering::Relaxed);
        if let Ok(mut guard) = self.backend_rotation_state.write() {
            guard.entry(backend.to_string()).or_default().rotations += 1;
            self.mark_backend_metrics_stale();
        }
    }

    pub fn inc_backend_client_rotation_failure(&self) {
        self.backend_client_rotation_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_jwt_validation_failure(&self, reason: &str) {
        if increment_label_counter(&self.jwt_validation_failures, reason) {
            self.mark_jwt_jwks_metrics_stale();
        }
    }

    pub fn record_jwt_algorithm_rejection(&self, algorithm: &str) {
        if increment_label_counter(&self.jwt_algorithm_rejections, algorithm) {
            self.mark_jwt_jwks_metrics_stale();
        }
    }

    pub fn record_jwks_unknown_kid(&self, jwks_source_id: &str) {
        if increment_label_counter(&self.jwks_unknown_kid_events, jwks_source_id) {
            self.mark_jwt_jwks_metrics_stale();
        }
    }

    pub fn record_jwks_refresh_started(&self, jwks_source_id: &str, refreshed_at: SystemTime) {
        let refreshed_at = refreshed_at
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_secs());
        if let Ok(mut guard) = self.jwks_source_state.write() {
            let entry = jwks_source_state_entry_mut(&mut guard, jwks_source_id);
            entry.last_refresh_attempt_unix_seconds = refreshed_at;
            self.mark_jwt_jwks_metrics_stale();
        }
    }

    pub fn record_jwks_refresh_success(
        &self,
        jwks_source_id: &str,
        state: &'static str,
        active_key_count: usize,
        refreshed_at: SystemTime,
        last_success_at: Option<SystemTime>,
    ) {
        let refreshed_at = refreshed_at
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_secs());
        let last_success_at = last_success_at
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs());
        if let Ok(mut guard) = self.jwks_source_state.write() {
            let entry = jwks_source_state_entry_mut(&mut guard, jwks_source_id);
            entry.refresh_success_total = entry.refresh_success_total.saturating_add(1);
            entry.active_key_count = active_key_count as u64;
            entry.state = state;
            entry.last_refresh_attempt_unix_seconds = refreshed_at;
            entry.last_refresh_success_unix_seconds = last_success_at.or(refreshed_at);
            entry.last_failure_reason = None;
            self.mark_jwt_jwks_metrics_stale();
        }
    }

    pub fn record_jwks_refresh_failure(
        &self,
        jwks_source_id: &str,
        state: &'static str,
        active_key_count: usize,
        refreshed_at: SystemTime,
        last_success_at: Option<SystemTime>,
        failure_reason: Option<&'static str>,
    ) {
        let refreshed_at = refreshed_at
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_secs());
        let last_success_at = last_success_at
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs());
        if let Ok(mut guard) = self.jwks_source_state.write() {
            let entry = jwks_source_state_entry_mut(&mut guard, jwks_source_id);
            entry.refresh_failure_total = entry.refresh_failure_total.saturating_add(1);
            entry.active_key_count = active_key_count as u64;
            entry.state = state;
            entry.last_refresh_attempt_unix_seconds = refreshed_at;
            if let Some(last_success_at) = last_success_at {
                entry.last_refresh_success_unix_seconds = Some(last_success_at);
            }
            entry.last_failure_reason = failure_reason;
            self.mark_jwt_jwks_metrics_stale();
        }
    }

    pub fn reconcile_jwks_sources<'a, I>(&self, active_source_ids: I)
    where
        I: IntoIterator<Item = &'a str>,
    {
        let active_source_ids = active_source_ids
            .into_iter()
            .map(ToOwned::to_owned)
            .collect::<HashSet<_>>();
        let mut marked_stale = false;

        if let Ok(mut guard) = self.jwks_unknown_kid_events.write() {
            guard.retain(|jwks_source_id, _| active_source_ids.contains(jwks_source_id));
            marked_stale = true;
        }

        if let Ok(mut guard) = self.jwks_source_state.write() {
            guard.retain(|jwks_source_id, _| active_source_ids.contains(jwks_source_id));
            marked_stale = true;
        }

        if marked_stale {
            self.mark_jwt_jwks_metrics_stale();
        }
    }

    pub fn reconcile_runtime_metric_labels<'a, I, J, K, L>(
        &self,
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
        let active_upstreams = active_upstreams
            .into_iter()
            .map(ToOwned::to_owned)
            .collect::<HashSet<_>>();
        let active_backends = active_backends
            .into_iter()
            .map(ToOwned::to_owned)
            .collect::<HashSet<_>>();
        let active_listeners = active_listeners
            .into_iter()
            .map(ToOwned::to_owned)
            .collect::<HashSet<_>>();
        let active_quota_policies = active_quota_policies
            .into_iter()
            .map(ToOwned::to_owned)
            .collect::<HashSet<_>>();

        if let Ok(mut guard) = self.backend_dns_state.write() {
            guard.retain(|backend, _| active_backends.contains(backend));
        }
        if let Ok(mut guard) = self.backend_rotation_state.write() {
            guard.retain(|backend, _| active_backends.contains(backend));
        }
        if let Ok(mut guard) = self.backend_connect_attempts.write() {
            guard.retain(|key, _| active_backends.contains(&key.backend));
        }
        if let Ok(mut guard) = self.request_result_metrics.write() {
            guard
                .upstream_request_counts
                .retain(|key, _| active_upstreams.contains(&key.upstream));
            guard.backend_request_counts.retain(|key, _| {
                active_upstreams.contains(&key.upstream) && active_backends.contains(&key.backend)
            });
            guard
                .upstream_request_latency
                .retain(|key, _| active_upstreams.contains(&key.upstream));
        }
        if let Ok(mut guard) = self.downstream_tls_handshake_failures.write() {
            guard.retain(|key, _| active_listeners.contains(&key.listener));
        }
        if let Ok(mut guard) = self.downstream_tls_cert_selections.write() {
            guard.retain(|key, _| active_listeners.contains(&key.listener));
        }
        if let Ok(mut guard) = self.downstream_tls_alpn_negotiated.write() {
            guard.retain(|key, _| active_listeners.contains(&key.listener));
        }
        if let Ok(mut guard) = self.downstream_tls_cert_expiry.write() {
            guard.retain(|key, _| active_listeners.contains(&key.listener));
        }
        if let Ok(mut guard) = self.upstream_tls_failures.write() {
            guard.retain(|key, _| {
                active_upstreams.contains(&key.upstream) && active_backends.contains(&key.backend)
            });
        }
        if let Ok(mut guard) = self.upstream_client_cert_expiry.write() {
            guard.retain(|key, _| active_upstreams.contains(&key.upstream));
        }
        if let Ok(mut guard) = self.quota_policy_outcomes.write() {
            let previous_len = guard.len();
            guard.retain(|key, _| active_quota_policies.contains(&key.policy));
            if guard.len() != previous_len {
                self.mark_quota_metrics_stale();
            }
        }

        self.mark_backend_metrics_stale();
        self.request_result_metrics_version
            .fetch_add(1, Ordering::Relaxed);
        self.mark_secret_metrics_stale();
    }

    pub fn record_backend_connect(
        &self,
        backend: &str,
        hostname: &str,
        resolved_addr: std::net::SocketAddr,
    ) {
        if let Ok(mut guard) = self.backend_connect_attempts.write() {
            let key = BackendConnectAttemptKey {
                backend: backend.to_string(),
                hostname: hostname.to_string(),
                resolved_addr: resolved_addr.to_string(),
            };
            if guard.contains_key(&key) || guard.len() < BACKEND_CONNECT_ATTEMPT_LABEL_CAP {
                *guard.entry(key).or_default() += 1;
            } else {
                *guard
                    .entry(BackendConnectAttemptKey {
                        backend: backend.to_string(),
                        hostname: METRIC_LABEL_OVER_CAP.to_string(),
                        resolved_addr: METRIC_LABEL_OVER_CAP.to_string(),
                    })
                    .or_default() += 1;
            }
            self.mark_backend_metrics_stale();
        }
    }

    pub fn record_request_result(
        &self,
        upstream: &str,
        backend: Option<&str>,
        status: Option<u16>,
        outcome: RouteOutcome,
        latency: Duration,
    ) {
        let upstream = normalize_metric_label(upstream, "unrouted");
        let backend = normalize_metric_label(backend.unwrap_or("__none__"), "__none__");
        let status_class = status_class_label(status);
        let outcome = route_outcome_label(outcome);

        if let Ok(mut guard) = self.request_result_metrics.write() {
            *guard
                .upstream_request_counts
                .entry(UpstreamRequestCountKey {
                    upstream: upstream.clone(),
                    status_class,
                    outcome,
                })
                .or_default() += 1;
            *guard
                .backend_request_counts
                .entry(BackendRequestCountKey {
                    upstream: upstream.clone(),
                    backend,
                    status_class,
                    outcome,
                })
                .or_default() += 1;

            let stats = guard
                .upstream_request_latency
                .entry(UpstreamRequestLatencyKey { upstream, outcome })
                .or_default();
            let latency_ms = latency.as_millis() as u64;
            let bucket = LATENCY_BUCKETS_MS
                .iter()
                .position(|cutoff| latency_ms <= *cutoff)
                .unwrap_or(LATENCY_BUCKETS_MS.len());
            stats.count = stats.count.saturating_add(1);
            stats.latency_ms_sum = stats.latency_ms_sum.saturating_add(latency_ms);
            stats.latency_buckets[bucket] = stats.latency_buckets[bucket].saturating_add(1);
            self.request_result_metrics_version
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn current_worker_stats(&self) -> Option<&WorkerStatsAtomic> {
        let idx = WORKER_METRICS_SLOT.with(|current| current.get());
        self.worker_stats
            .get(idx)
            .or_else(|| self.worker_stats.first())
    }

    fn inc_worker_requests_total(&self) {
        if let Some(stats) = self.current_worker_stats() {
            stats.requests_total.fetch_add(1, Ordering::Relaxed);
            self.mark_route_worker_metrics_stale();
        }
    }

    fn inc_worker_requests_success(&self) {
        if let Some(stats) = self.current_worker_stats() {
            stats.requests_success.fetch_add(1, Ordering::Relaxed);
            self.mark_route_worker_metrics_stale();
        }
    }

    fn inc_worker_requests_failure(&self) {
        if let Some(stats) = self.current_worker_stats() {
            stats.requests_failure.fetch_add(1, Ordering::Relaxed);
            self.mark_route_worker_metrics_stale();
        }
    }

    fn inc_worker_ingress_packets_total(&self) {
        if let Some(stats) = self.current_worker_stats() {
            stats.ingress_packets_total.fetch_add(1, Ordering::Relaxed);
            self.mark_route_worker_metrics_stale();
        }
    }

    fn inc_worker_ingress_queue_drops(&self) {
        if let Some(stats) = self.current_worker_stats() {
            stats.ingress_queue_drops.fetch_add(1, Ordering::Relaxed);
            self.mark_route_worker_metrics_stale();
        }
    }

    fn inc_worker_ingress_queue_drop_bytes(&self, bytes: u64) {
        if let Some(stats) = self.current_worker_stats() {
            stats
                .ingress_queue_drop_bytes
                .fetch_add(bytes, Ordering::Relaxed);
            self.mark_route_worker_metrics_stale();
        }
    }

    pub fn try_reserve_request_buffer(&self, bytes: usize, cap_bytes: usize) -> bool {
        let add = bytes as u64;
        let cap = cap_bytes as u64;
        loop {
            let current = self.request_buffered_bytes.load(Ordering::Relaxed);
            let next = current.saturating_add(add);
            if next > cap {
                return false;
            }
            if self
                .request_buffered_bytes
                .compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                self.observe_request_buffer_high_water(next);
                return true;
            }
        }
    }

    pub fn release_request_buffer(&self, bytes: usize) {
        let sub = bytes as u64;
        loop {
            let current = self.request_buffered_bytes.load(Ordering::Relaxed);
            let next = current.saturating_sub(sub);
            if self
                .request_buffered_bytes
                .compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
        }
    }

    pub fn inc_request_buffer_limit_reject(&self) {
        self.request_buffer_limit_rejects
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_response_prebuffer_limit_reject(&self) {
        self.response_prebuffer_limit_rejects
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_response_compression_outcome(&self, outcome: ResponseCompressionAction) {
        self.response_compression_outcomes[outcome.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn add_response_compression_bytes(&self, input: usize, output: usize) {
        self.response_compression_input_bytes
            .fetch_add(u64::try_from(input).unwrap_or(u64::MAX), Ordering::Relaxed);
        self.response_compression_output_bytes
            .fetch_add(u64::try_from(output).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    pub(crate) fn record_response_cache_outcome(&self, outcome: ResponseCacheOutcome) {
        self.response_cache_outcomes[outcome.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn add_response_cache_outcomes(&self, outcome: ResponseCacheOutcome, count: usize) {
        self.response_cache_outcomes[outcome.index()]
            .fetch_add(u64::try_from(count).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    fn observe_request_buffer_high_water(&self, candidate: u64) {
        loop {
            let current = self
                .request_buffered_high_watermark_bytes
                .load(Ordering::Relaxed);
            if candidate <= current {
                return;
            }
            if self
                .request_buffered_high_watermark_bytes
                .compare_exchange(current, candidate, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
        }
    }

    pub fn inc_scid_rotation(&self) {
        self.scid_rotations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_control_api_connection_limit_drop(&self) {
        self.control_api_connection_limit_drops
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_control_api_audit_event_drop(&self) {
        self.control_api_audit_event_drops
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_control_api_audit_write_failure(&self) {
        self.control_api_audit_write_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_runtime_rejection_reason(&self, reason: RuntimeRejectionReason) {
        match reason {
            RuntimeRejectionReason::InvalidConfig => {
                self.runtime_rejection_invalid_config
                    .fetch_add(1, Ordering::Relaxed);
            }
            RuntimeRejectionReason::StartupOwnedChange => {
                self.runtime_rejection_startup_owned_change
                    .fetch_add(1, Ordering::Relaxed);
            }
            RuntimeRejectionReason::BindConflict => {
                self.runtime_rejection_bind_conflict
                    .fetch_add(1, Ordering::Relaxed);
            }
            RuntimeRejectionReason::ResourcePrepareFailed => {
                self.runtime_rejection_resource_prepare_failed
                    .fetch_add(1, Ordering::Relaxed);
            }
            RuntimeRejectionReason::IncompatibleReload => {
                self.runtime_rejection_incompatible_reload
                    .fetch_add(1, Ordering::Relaxed);
            }
            RuntimeRejectionReason::UnknownGeneration => {
                self.runtime_rejection_unknown_generation
                    .fetch_add(1, Ordering::Relaxed);
            }
            RuntimeRejectionReason::RollbackNotAllowed => {
                self.runtime_rejection_rollback_not_allowed
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn inc_runtime_validation_attempt(&self) {
        self.runtime_validation_attempts
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_runtime_preview_attempt(&self) {
        self.runtime_preview_attempts
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_runtime_activation_outcome(&self, reason: RuntimeOperationOutcomeReason) {
        self.runtime_activation_outcomes[reason.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_runtime_rollback_outcome(&self, reason: RuntimeOperationOutcomeReason) {
        self.runtime_rollback_outcomes[reason.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub fn runtime_rejection_reason_count(&self, reason: RuntimeRejectionReason) -> u64 {
        match reason {
            RuntimeRejectionReason::InvalidConfig => self
                .runtime_rejection_invalid_config
                .load(Ordering::Relaxed),
            RuntimeRejectionReason::StartupOwnedChange => self
                .runtime_rejection_startup_owned_change
                .load(Ordering::Relaxed),
            RuntimeRejectionReason::BindConflict => {
                self.runtime_rejection_bind_conflict.load(Ordering::Relaxed)
            }
            RuntimeRejectionReason::ResourcePrepareFailed => self
                .runtime_rejection_resource_prepare_failed
                .load(Ordering::Relaxed),
            RuntimeRejectionReason::IncompatibleReload => self
                .runtime_rejection_incompatible_reload
                .load(Ordering::Relaxed),
            RuntimeRejectionReason::UnknownGeneration => self
                .runtime_rejection_unknown_generation
                .load(Ordering::Relaxed),
            RuntimeRejectionReason::RollbackNotAllowed => self
                .runtime_rejection_rollback_not_allowed
                .load(Ordering::Relaxed),
        }
    }

    pub fn runtime_activation_outcome_count(&self, reason: RuntimeOperationOutcomeReason) -> u64 {
        self.runtime_activation_outcomes[reason.index()].load(Ordering::Relaxed)
    }

    pub fn runtime_rollback_outcome_count(&self, reason: RuntimeOperationOutcomeReason) -> u64 {
        self.runtime_rollback_outcomes[reason.index()].load(Ordering::Relaxed)
    }

    pub fn set_runtime_active_generation(&self, generation: u64) {
        self.runtime_active_generation
            .store(generation, Ordering::Relaxed);
    }

    pub fn set_runtime_history_depth(&self, depth: usize) {
        let depth = u64::try_from(depth).unwrap_or(u64::MAX);
        self.runtime_history_depth.store(depth, Ordering::Relaxed);
    }

    pub fn record_pingora_lb_selector_rebuild(&self, generation: u64, selectors: usize) {
        self.pingora_lb_selector_generation
            .store(generation, Ordering::Relaxed);
        self.pingora_lb_selector_rebuilds.fetch_add(
            u64::try_from(selectors).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    pub fn inc_pingora_lb_selector_failure(&self) {
        self.pingora_lb_selector_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_pingora_lb_selection(&self) {
        self.pingora_lb_selections.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_pingora_discovery_refresh(
        &self,
        outcome: PingoraDiscoveryRefreshOutcome,
        update: Option<&impulse_lb::pingora_backend::PingoraDiscoveryUpdate>,
    ) {
        self.pingora_discovery_refresh_outcomes[outcome.index()].fetch_add(1, Ordering::Relaxed);
        let Some(update) = update else {
            return;
        };
        if !self.route_label_to_id.contains_key(update.upstream_name()) {
            return;
        }
        let mut states = self
            .pingora_discovery_state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state = states
            .entry(update.upstream_name().to_string())
            .or_default();
        state.membership_generation = update.membership_generation();
        if update.membership_changed() {
            state.rebuild_duration_ns =
                u64::try_from(update.rebuild_duration().as_nanos()).unwrap_or(u64::MAX);
        }
    }

    pub fn inc_watchdog_restart_request(&self) {
        self.watchdog_restart_requests
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_watchdog_restart_hook(&self) {
        self.watchdog_restart_hooks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_watchdog_degraded_window(&self) {
        self.watchdog_degraded_windows
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_runtime_panic(&self) {
        self.runtime_panics.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_retry_attempt(&self, reason: RetryAttemptTelemetryReason) {
        self.retries_total.fetch_add(1, Ordering::Relaxed);
        match reason {
            RetryAttemptTelemetryReason::Timeout => {
                self.retry_reason_timeout.fetch_add(1, Ordering::Relaxed);
            }
            RetryAttemptTelemetryReason::Transport => {
                self.retry_reason_transport.fetch_add(1, Ordering::Relaxed);
            }
            RetryAttemptTelemetryReason::Pool => {
                self.retry_reason_pool.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn inc_retry_denied(&self, reason: RetryPolicyDenialReason) {
        match reason {
            RetryPolicyDenialReason::BudgetDenied => {
                self.retry_denied_budget.fetch_add(1, Ordering::Relaxed);
            }
            RetryPolicyDenialReason::MethodNotIdempotent
            | RetryPolicyDenialReason::RequestBodyNotReplayable => {
                self.retry_denied_no_bodyless
                    .fetch_add(1, Ordering::Relaxed);
            }
            RetryPolicyDenialReason::AlternateBackendUnavailable(_) => {
                self.retry_denied_no_alternate
                    .fetch_add(1, Ordering::Relaxed);
            }
            RetryPolicyDenialReason::TerminalError(_)
            | RetryPolicyDenialReason::AttemptLimitReached => {}
        }
    }

    pub fn inc_circuit_breaker_rejected(&self) {
        self.circuit_breaker_rejected_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_brownout_active(&self, active: bool) {
        self.brownout_active
            .store(if active { 1 } else { 0 }, Ordering::Relaxed);
    }

    pub fn inc_health_failure(&self, reason: HealthFailureReason) {
        match reason {
            HealthFailureReason::HttpStatus5xx => {
                self.health_failure_5xx.fetch_add(1, Ordering::Relaxed);
            }
            HealthFailureReason::Timeout => {
                self.health_failure_timeout.fetch_add(1, Ordering::Relaxed);
            }
            HealthFailureReason::Transport => {
                self.health_failure_transport
                    .fetch_add(1, Ordering::Relaxed);
            }
            HealthFailureReason::Tls => {
                self.health_failure_tls.fetch_add(1, Ordering::Relaxed);
            }
            HealthFailureReason::CircuitOpen => {}
        }
    }

    pub fn inc_downstream_tls_handshake_success(&self) {
        self.downstream_tls_handshake_success
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_downstream_tls_handshake_failure(&self, listener: &str, reason: &str) {
        if let Ok(mut guard) = self.downstream_tls_handshake_failures.write() {
            *guard
                .entry(DownstreamTlsHandshakeFailureKey {
                    listener: listener.to_string(),
                    reason: reason.to_string(),
                })
                .or_default() += 1;
        }
    }

    pub fn record_downstream_tls_cert_selection(&self, listener: &str, selection: &str) {
        if let Ok(mut guard) = self.downstream_tls_cert_selections.write() {
            *guard
                .entry(DownstreamTlsCertSelectionKey {
                    listener: listener.to_string(),
                    selection: selection.to_string(),
                })
                .or_default() += 1;
        }
    }

    pub fn record_downstream_tls_alpn(&self, listener: &str, protocol: &str) {
        if let Ok(mut guard) = self.downstream_tls_alpn_negotiated.write() {
            *guard
                .entry(DownstreamTlsAlpnKey {
                    listener: listener.to_string(),
                    protocol: protocol.to_string(),
                })
                .or_default() += 1;
        }
    }

    pub fn record_upstream_tls_failure(
        &self,
        upstream: &str,
        backend: &str,
        phase: &str,
        reason: &str,
    ) {
        if let Ok(mut guard) = self.upstream_tls_failures.write() {
            *guard
                .entry(UpstreamTlsFailureKey {
                    upstream: upstream.to_string(),
                    backend: backend.to_string(),
                    phase: phase.to_string(),
                    reason: reason.to_string(),
                })
                .or_default() += 1;
        }
    }

    pub fn record_secret_reload(&self, scope: &str, result: &str, reason: &str) {
        if let Ok(mut guard) = self.secret_reload_totals.write() {
            *guard
                .entry(SecretReloadKey {
                    scope: scope.to_string(),
                    result: result.to_string(),
                    reason: reason.to_string(),
                })
                .or_default() += 1;
            self.mark_secret_metrics_stale();
        }
    }

    pub fn record_secret_resolve(&self, provider: &str, result: &str, reason: &str) {
        if let Ok(mut guard) = self.secret_resolve_totals.write() {
            *guard
                .entry(SecretResolveKey {
                    provider: provider.to_string(),
                    result: result.to_string(),
                    reason: reason.to_string(),
                })
                .or_default() += 1;
            self.mark_secret_metrics_stale();
        }
    }

    pub fn set_secret_last_success_unixtime(&self, scope: &str, unix_seconds: u64) {
        if let Ok(mut guard) = self.secret_last_success_unixtime.write() {
            guard.insert(
                SecretLastSuccessKey {
                    scope: scope.to_string(),
                },
                unix_seconds,
            );
            self.mark_secret_metrics_stale();
        }
    }

    pub fn replace_upstream_client_cert_expiry<I>(&self, certs: I)
    where
        I: IntoIterator<Item = (String, i64)>,
    {
        if let Ok(mut guard) = self.upstream_client_cert_expiry.write() {
            guard.clear();
            for (upstream, not_after_unix_seconds) in certs {
                guard.insert(
                    UpstreamClientCertExpiryKey { upstream },
                    not_after_unix_seconds,
                );
            }
            self.mark_secret_metrics_stale();
        }
    }

    pub fn record_control_plane_cert_reload(&self, result: &str, reason: &str) {
        if let Ok(mut guard) = self.control_plane_cert_reload_totals.write() {
            *guard
                .entry(ControlPlaneCertReloadKey {
                    result: result.to_string(),
                    reason: reason.to_string(),
                })
                .or_default() += 1;
            self.mark_secret_metrics_stale();
        }
    }

    pub fn replace_downstream_tls_cert_expiry<I>(&self, listener: &str, certs: I)
    where
        I: IntoIterator<Item = (String, i64)>,
    {
        if let Ok(mut guard) = self.downstream_tls_cert_expiry.write() {
            guard.retain(|key, _| key.listener != listener);
            for (server_name, not_after_unix_seconds) in certs {
                guard.insert(
                    DownstreamTlsCertExpiryKey {
                        listener: listener.to_string(),
                        server_name,
                    },
                    not_after_unix_seconds,
                );
            }
        }
    }

    pub fn record_route(&self, route: &str, latency: Duration, outcome: RouteOutcome) {
        let route_id = self
            .route_label_to_id
            .get(route)
            .copied()
            .unwrap_or(self.unrouted_route_id);
        let Some(entry) = self.route_stats.get(route_id) else {
            return;
        };
        entry.requests_total.fetch_add(1, Ordering::Relaxed);

        match outcome {
            RouteOutcome::Success => {
                entry.success.fetch_add(1, Ordering::Relaxed);
            }
            RouteOutcome::Failure => {
                entry.failure.fetch_add(1, Ordering::Relaxed);
            }
            RouteOutcome::RateLimited => {
                entry.rate_limited.fetch_add(1, Ordering::Relaxed);
            }
            RouteOutcome::Timeout => {
                entry.timeout.fetch_add(1, Ordering::Relaxed);
            }
            RouteOutcome::BackendError => {
                entry.backend_error.fetch_add(1, Ordering::Relaxed);
            }
            RouteOutcome::OverloadShed => {
                entry.overload_shed.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.mark_route_worker_metrics_stale();

        if self.route_latency_sample_every > 1 {
            let seq = self
                .route_latency_sample_counter
                .fetch_add(1, Ordering::Relaxed);
            if !seq.is_multiple_of(self.route_latency_sample_every) {
                return;
            }
        }

        let latency_ms = latency.as_millis() as u64;
        let bucket = LATENCY_BUCKETS_MS
            .iter()
            .position(|cutoff| latency_ms <= *cutoff)
            .unwrap_or(LATENCY_BUCKETS_MS.len());
        entry.latency_buckets[bucket].fetch_add(1, Ordering::Relaxed);
    }
}
