use super::*;
use crate::runtime::activation::{RuntimeOperationOutcomeReason, RuntimeRejectionReason};

fn render_quota_metrics_families(snapshot: &QuotaMetricsSnapshot) -> String {
    let mut out = String::new();
    out.push_str(
        "# HELP impulse_quota_policy_outcomes_total Total quota policy outcomes grouped by policy, decision, reason, selector dimensions, and backend mode.\n",
    );
    out.push_str("# TYPE impulse_quota_policy_outcomes_total counter\n");
    for (key, count) in &snapshot.quota_policy_outcomes {
        out.push_str(&format!(
            "impulse_quota_policy_outcomes_total{{policy=\"{}\",decision=\"{}\",reason=\"{}\",selector_dimensions=\"{}\",backend_mode=\"{}\"}} {}\n",
            escape_prometheus_label(&key.policy),
            escape_prometheus_label(&key.decision),
            escape_prometheus_label(&key.reason),
            escape_prometheus_label(&key.selector_dimensions),
            escape_prometheus_label(&key.backend_mode),
            count
        ));
    }
    out.push_str(
        "# HELP impulse_quota_backend_health_total Total quota backend health/error observations grouped by backend mode and reason.\n",
    );
    out.push_str("# TYPE impulse_quota_backend_health_total counter\n");
    for (key, count) in &snapshot.quota_backend_health {
        out.push_str(&format!(
            "impulse_quota_backend_health_total{{backend_mode=\"{}\",reason=\"{}\"}} {}\n",
            escape_prometheus_label(&key.backend_mode),
            escape_prometheus_label(&key.reason),
            count
        ));
    }
    out
}

fn render_jwt_jwks_metrics_static_families(snapshot: &JwtJwksMetricsSnapshot) -> String {
    let mut out = String::new();
    out.push_str(
        "# HELP impulse_jwt_validation_failures_total Total JWT validation failures grouped by stable rejection reason.\n",
    );
    out.push_str("# TYPE impulse_jwt_validation_failures_total counter\n");
    for (reason, count) in &snapshot.jwt_validation_failures {
        out.push_str(&format!(
            "impulse_jwt_validation_failures_total{{reason=\"{}\"}} {}\n",
            escape_prometheus_label(reason),
            count
        ));
    }
    out.push_str(
        "# HELP impulse_jwt_algorithm_rejections_total Total JWT algorithm rejections grouped by JOSE alg.\n",
    );
    out.push_str("# TYPE impulse_jwt_algorithm_rejections_total counter\n");
    for (algorithm, count) in &snapshot.jwt_algorithm_rejections {
        out.push_str(&format!(
            "impulse_jwt_algorithm_rejections_total{{algorithm=\"{}\"}} {}\n",
            escape_prometheus_label(algorithm),
            count
        ));
    }
    out.push_str(
        "# HELP impulse_jwks_unknown_kid_total Total unknown-kid events that triggered JWKS miss handling.\n",
    );
    out.push_str("# TYPE impulse_jwks_unknown_kid_total counter\n");
    for (jwks_source_id, count) in &snapshot.jwks_unknown_kid_events {
        out.push_str(&format!(
            "impulse_jwks_unknown_kid_total{{jwks_source_id=\"{}\"}} {}\n",
            escape_prometheus_label(jwks_source_id),
            count
        ));
    }
    out.push_str(
        "# HELP impulse_jwks_refresh_success_total Total successful JWKS refreshes grouped by JWKS source identity.\n",
    );
    out.push_str("# TYPE impulse_jwks_refresh_success_total counter\n");
    out.push_str(
        "# HELP impulse_jwks_refresh_failure_total Total failed JWKS refreshes grouped by JWKS source identity.\n",
    );
    out.push_str("# TYPE impulse_jwks_refresh_failure_total counter\n");
    out.push_str(
        "# HELP impulse_jwks_age_seconds Current age of the active JWKS key set in seconds.\n",
    );
    out.push_str("# TYPE impulse_jwks_age_seconds gauge\n");
    out.push_str(
        "# HELP impulse_jwks_state Current JWKS cache state for a configured JWKS source.\n",
    );
    out.push_str("# TYPE impulse_jwks_state gauge\n");
    out.push_str(
        "# HELP impulse_jwks_active_keys Current count of active verification keys retained for a configured JWKS source.\n",
    );
    out.push_str("# TYPE impulse_jwks_active_keys gauge\n");
    out.push_str(
        "# HELP impulse_jwks_last_refresh_attempt_seconds Unix timestamp of the last JWKS refresh attempt.\n",
    );
    out.push_str("# TYPE impulse_jwks_last_refresh_attempt_seconds gauge\n");
    out.push_str(
        "# HELP impulse_jwks_last_refresh_success_seconds Unix timestamp of the last successful JWKS refresh.\n",
    );
    out.push_str("# TYPE impulse_jwks_last_refresh_success_seconds gauge\n");
    for state in &snapshot.jwks_source_state {
        let jwks_source_id = escape_prometheus_label(&state.jwks_source_id);
        out.push_str(&format!(
            "impulse_jwks_refresh_success_total{{jwks_source_id=\"{}\"}} {}\n",
            jwks_source_id, state.refresh_success_total
        ));
        out.push_str(&format!(
            "impulse_jwks_refresh_failure_total{{jwks_source_id=\"{}\"}} {}\n",
            jwks_source_id, state.refresh_failure_total
        ));
        out.push_str(&format!(
            "impulse_jwks_state{{jwks_source_id=\"{}\",state=\"{}\"}} 1\n",
            jwks_source_id,
            escape_prometheus_label(state.state)
        ));
        out.push_str(&format!(
            "impulse_jwks_active_keys{{jwks_source_id=\"{}\"}} {}\n",
            jwks_source_id, state.active_key_count
        ));
        out.push_str(&format!(
            "impulse_jwks_last_refresh_attempt_seconds{{jwks_source_id=\"{}\"}} {}\n",
            jwks_source_id,
            state.last_refresh_attempt_unix_seconds.unwrap_or_default()
        ));
        out.push_str(&format!(
            "impulse_jwks_last_refresh_success_seconds{{jwks_source_id=\"{}\"}} {}\n",
            jwks_source_id,
            state.last_refresh_success_unix_seconds.unwrap_or_default()
        ));
    }
    out
}

fn append_jwks_age_series(
    out: &mut String,
    snapshot: &JwtJwksMetricsSnapshot,
    jwks_now_unix_seconds: u64,
) {
    for state in &snapshot.jwks_source_state {
        let age_seconds = state
            .last_refresh_success_unix_seconds
            .map(|last_success| jwks_now_unix_seconds.saturating_sub(last_success))
            .unwrap_or_default();
        out.push_str(&format!(
            "impulse_jwks_age_seconds{{jwks_source_id=\"{}\"}} {}\n",
            escape_prometheus_label(&state.jwks_source_id),
            age_seconds
        ));
    }
}

fn render_backend_metrics_families(snapshot: &BackendMetricsSnapshot) -> String {
    let mut out = String::new();
    out.push_str(
        "# HELP impulse_backend_dns_last_refresh_success_seconds Unix timestamp of the last successful backend DNS refresh.\n",
    );
    out.push_str("# TYPE impulse_backend_dns_last_refresh_success_seconds gauge\n");
    out.push_str(
        "# HELP impulse_backend_dns_resolved_addresses Current number of resolved addresses retained for a backend identity.\n",
    );
    out.push_str("# TYPE impulse_backend_dns_resolved_addresses gauge\n");
    out.push_str(
        "# HELP impulse_backend_client_rotations Per-backend client rotation count triggered by DNS changes.\n",
    );
    out.push_str("# TYPE impulse_backend_client_rotations counter\n");
    out.push_str(
        "# HELP impulse_backend_connect_attempt_total Observed upstream socket connects grouped by backend identity, hostname, and resolved address.\n",
    );
    out.push_str("# TYPE impulse_backend_connect_attempt_total counter\n");
    for (backend, state) in &snapshot.backend_dns_state {
        let backend = escape_prometheus_label(backend);
        out.push_str(&format!(
            "impulse_backend_dns_last_refresh_success_seconds{{backend=\"{}\"}} {}\n",
            backend, state.last_success_unix_seconds
        ));
        out.push_str(&format!(
            "impulse_backend_dns_resolved_addresses{{backend=\"{}\"}} {}\n",
            backend, state.resolved_address_count
        ));
    }
    for (backend, state) in &snapshot.backend_rotation_state {
        let backend = escape_prometheus_label(backend);
        out.push_str(&format!(
            "impulse_backend_client_rotations{{backend=\"{}\"}} {}\n",
            backend, state.rotations
        ));
    }
    for (key, count) in &snapshot.backend_connect_attempts {
        let backend = escape_prometheus_label(&key.backend);
        let hostname = escape_prometheus_label(&key.hostname);
        let resolved_addr = escape_prometheus_label(&key.resolved_addr);
        out.push_str(&format!(
            "impulse_backend_connect_attempt_total{{backend=\"{}\",hostname=\"{}\",resolved_addr=\"{}\"}} {}\n",
            backend, hostname, resolved_addr, count
        ));
    }
    out
}

impl Metrics {
    fn append_cached_quota_metrics_families(&self, out: &mut String) {
        let version = self.quota_metrics_version.load(Ordering::Relaxed);
        if let Ok(cache) = self.quota_metrics_cache.read()
            && cache.version == version
            && !cache.rendered.is_empty()
        {
            out.push_str(&cache.rendered);
            return;
        }

        let snapshot = self.snapshot_quota_metrics();
        let rendered = render_quota_metrics_families(&snapshot);
        out.push_str(&rendered);
        if let Ok(mut cache) = self.quota_metrics_cache.write()
            && cache.version == version
        {
            cache.rendered = rendered;
        }
    }

    fn append_cached_jwt_jwks_metrics_families(&self, out: &mut String) {
        let version = self.jwt_jwks_metrics_version.load(Ordering::Relaxed);
        let jwks_now_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_secs())
            .unwrap_or_default();
        if let Ok(cache) = self.jwt_jwks_metrics_cache.read()
            && cache.version == version
            && !cache.rendered.is_empty()
        {
            out.push_str(&cache.rendered);
            append_jwks_age_series(out, &cache.snapshot, jwks_now_unix_seconds);
            return;
        }

        let snapshot = self.snapshot_jwt_jwks_metrics();
        let rendered = render_jwt_jwks_metrics_static_families(&snapshot);
        out.push_str(&rendered);
        append_jwks_age_series(out, &snapshot, jwks_now_unix_seconds);
        if let Ok(mut cache) = self.jwt_jwks_metrics_cache.write()
            && cache.version == version
        {
            cache.rendered = rendered;
        }
    }

    fn append_cached_backend_metrics_families(&self, out: &mut String) {
        let version = self.backend_metrics_version.load(Ordering::Relaxed);
        if let Ok(cache) = self.backend_metrics_cache.read()
            && cache.version == version
            && !cache.rendered.is_empty()
        {
            out.push_str(&cache.rendered);
            return;
        }

        let snapshot = self.snapshot_backend_metrics();
        let rendered = render_backend_metrics_families(&snapshot);
        out.push_str(&rendered);
        if let Ok(mut cache) = self.backend_metrics_cache.write()
            && cache.version == version
        {
            cache.rendered = rendered;
        }
    }

    fn render_route_worker_metrics_families(&self) -> String {
        let mut out = String::new();
        out.push_str(
            "# HELP impulse_route_requests_total Total completed requests grouped by route label.\n",
        );
        out.push_str("# TYPE impulse_route_requests_total counter\n");
        out.push_str(
            "# HELP impulse_route_success_total Total successful requests grouped by route label.\n",
        );
        out.push_str("# TYPE impulse_route_success_total counter\n");
        out.push_str(
            "# HELP impulse_route_failure_total Total failed requests grouped by route label.\n",
        );
        out.push_str("# TYPE impulse_route_failure_total counter\n");
        out.push_str(
            "# HELP impulse_route_timeout_total Total timed-out requests grouped by route label.\n",
        );
        out.push_str("# TYPE impulse_route_timeout_total counter\n");
        out.push_str(
            "# HELP impulse_route_rate_limited_total Total rate-limited requests grouped by route label.\n",
        );
        out.push_str("# TYPE impulse_route_rate_limited_total counter\n");
        out.push_str(
            "# HELP impulse_route_backend_error_total Total backend-error requests grouped by route label.\n",
        );
        out.push_str("# TYPE impulse_route_backend_error_total counter\n");
        out.push_str(
            "# HELP impulse_route_overload_shed_total Total overload-shed requests grouped by route label.\n",
        );
        out.push_str("# TYPE impulse_route_overload_shed_total counter\n");
        out.push_str(
            "# HELP impulse_route_latency_sample_every Route latency histogram sampling interval (1 = every request).\n",
        );
        out.push_str("# TYPE impulse_route_latency_sample_every gauge\n");
        out.push_str(&format!(
            "impulse_route_latency_sample_every {}\n",
            self.route_latency_sample_every
        ));

        for (idx, route) in &self.route_render_order {
            let Some(stats) = self.route_stats.get(*idx).map(RouteStatsAtomic::snapshot) else {
                continue;
            };
            let route = escape_prometheus_label(route);
            out.push_str(&format!(
                "impulse_route_requests_total{{route=\"{}\"}} {}\n",
                route, stats.requests_total
            ));
            out.push_str(&format!(
                "impulse_route_success_total{{route=\"{}\"}} {}\n",
                route, stats.success
            ));
            out.push_str(&format!(
                "impulse_route_failure_total{{route=\"{}\"}} {}\n",
                route, stats.failure
            ));
            out.push_str(&format!(
                "impulse_route_timeout_total{{route=\"{}\"}} {}\n",
                route, stats.timeout
            ));
            out.push_str(&format!(
                "impulse_route_rate_limited_total{{route=\"{}\"}} {}\n",
                route, stats.rate_limited
            ));
            out.push_str(&format!(
                "impulse_route_backend_error_total{{route=\"{}\"}} {}\n",
                route, stats.backend_error
            ));
            out.push_str(&format!(
                "impulse_route_overload_shed_total{{route=\"{}\"}} {}\n",
                route, stats.overload_shed
            ));
            out.push_str(&format!(
                "impulse_route_latency_ms_p50{{route=\"{}\"}} {:.2}\n",
                route,
                percentile_ms(&stats, 0.50)
            ));
            out.push_str(&format!(
                "impulse_route_latency_ms_p95{{route=\"{}\"}} {:.2}\n",
                route,
                percentile_ms(&stats, 0.95)
            ));
            out.push_str(&format!(
                "impulse_route_latency_ms_p99{{route=\"{}\"}} {:.2}\n",
                route,
                percentile_ms(&stats, 0.99)
            ));
        }

        out.push_str(
            "# HELP impulse_worker_requests_total Total requests handled by each worker thread.\n",
        );
        out.push_str("# TYPE impulse_worker_requests_total counter\n");
        out.push_str(
            "# HELP impulse_worker_requests_success Total successful requests by worker thread.\n",
        );
        out.push_str("# TYPE impulse_worker_requests_success counter\n");
        out.push_str(
            "# HELP impulse_worker_requests_failure Total failed requests by worker thread.\n",
        );
        out.push_str("# TYPE impulse_worker_requests_failure counter\n");
        out.push_str(
            "# HELP impulse_worker_ingress_packets_total Total ingress packets by worker thread.\n",
        );
        out.push_str("# TYPE impulse_worker_ingress_packets_total counter\n");
        out.push_str(
            "# HELP impulse_worker_ingress_queue_drops Total ingress queue drops by worker thread.\n",
        );
        out.push_str("# TYPE impulse_worker_ingress_queue_drops counter\n");
        out.push_str(
            "# HELP impulse_worker_ingress_queue_drop_bytes Total ingress queue drop bytes by worker thread.\n",
        );
        out.push_str("# TYPE impulse_worker_ingress_queue_drop_bytes counter\n");
        for (idx, worker) in &self.worker_render_order {
            let Some(stats) = self.worker_stats.get(*idx).map(WorkerStatsAtomic::snapshot) else {
                continue;
            };
            let worker = escape_prometheus_label(worker);
            out.push_str(&format!(
                "impulse_worker_requests_total{{worker=\"{}\"}} {}\n",
                worker, stats.requests_total
            ));
            out.push_str(&format!(
                "impulse_worker_requests_success{{worker=\"{}\"}} {}\n",
                worker, stats.requests_success
            ));
            out.push_str(&format!(
                "impulse_worker_requests_failure{{worker=\"{}\"}} {}\n",
                worker, stats.requests_failure
            ));
            out.push_str(&format!(
                "impulse_worker_ingress_packets_total{{worker=\"{}\"}} {}\n",
                worker, stats.ingress_packets_total
            ));
            out.push_str(&format!(
                "impulse_worker_ingress_queue_drops{{worker=\"{}\"}} {}\n",
                worker, stats.ingress_queue_drops
            ));
            out.push_str(&format!(
                "impulse_worker_ingress_queue_drop_bytes{{worker=\"{}\"}} {}\n",
                worker, stats.ingress_queue_drop_bytes
            ));
        }
        out
    }

    fn append_cached_route_worker_metrics_families(&self, out: &mut String) {
        let version = self.route_worker_metrics_version.load(Ordering::Relaxed);
        if let Ok(cache) = self.route_worker_metrics_cache.read()
            && cache.version == version
            && !cache.rendered.is_empty()
        {
            out.push_str(&cache.rendered);
            return;
        }

        let rendered = self.render_route_worker_metrics_families();
        out.push_str(&rendered);
        if let Ok(mut cache) = self.route_worker_metrics_cache.write() {
            cache.version = version;
            cache.rendered = rendered;
        }
    }

    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(8 * 1024);
        let request_result_metrics = self.snapshot_request_result_metrics();
        let secret_metrics = self.snapshot_secret_metrics();
        out.push_str("# HELP impulse_requests_total Total requests seen by impulse.\n");
        out.push_str("# TYPE impulse_requests_total counter\n");
        out.push_str(&format!(
            "impulse_requests_total {}\n",
            self.requests_total.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP impulse_requests_success Total successful upstream responses.\n");
        out.push_str("# TYPE impulse_requests_success counter\n");
        out.push_str(&format!(
            "impulse_requests_success {}\n",
            self.requests_success.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP impulse_requests_failure Total failed requests.\n");
        out.push_str("# TYPE impulse_requests_failure counter\n");
        out.push_str(&format!(
            "impulse_requests_failure {}\n",
            self.requests_failure.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_request_validation_rejects Total requests rejected by protocol validation.\n",
        );
        out.push_str("# TYPE impulse_request_validation_rejects counter\n");
        out.push_str(&format!(
            "impulse_request_validation_rejects {}\n",
            self.request_validation_rejects.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_policy_denied Total requests denied by runtime method/path policies.\n",
        );
        out.push_str("# TYPE impulse_policy_denied counter\n");
        out.push_str(&format!(
            "impulse_policy_denied {}\n",
            self.policy_denied.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_external_auth_allowed Total requests explicitly allowed by external auth.\n",
        );
        out.push_str("# TYPE impulse_external_auth_allowed counter\n");
        out.push_str(&format!(
            "impulse_external_auth_allowed {}\n",
            self.external_auth_allowed.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_external_auth_denied Total requests denied, challenged, or redirected by external auth.\n",
        );
        out.push_str("# TYPE impulse_external_auth_denied counter\n");
        out.push_str(&format!(
            "impulse_external_auth_denied {}\n",
            self.external_auth_denied.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_external_auth_timeout Total external auth decisions that timed out.\n",
        );
        out.push_str("# TYPE impulse_external_auth_timeout counter\n");
        out.push_str(&format!(
            "impulse_external_auth_timeout {}\n",
            self.external_auth_timeout.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_external_auth_error Total external auth transport or execution errors.\n",
        );
        out.push_str("# TYPE impulse_external_auth_error counter\n");
        out.push_str(&format!(
            "impulse_external_auth_error {}\n",
            self.external_auth_error.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_request_rate_limited Total requests rejected by scoped request rate limits.\n",
        );
        out.push_str("# TYPE impulse_request_rate_limited counter\n");
        out.push_str(&format!(
            "impulse_request_rate_limited {}\n",
            self.request_rate_limited.load(Ordering::Relaxed)
        ));

        self.append_cached_quota_metrics_families(&mut out);

        out.push_str("# HELP impulse_early_data_accepted Total requests accepted in early data.\n");
        out.push_str("# TYPE impulse_early_data_accepted counter\n");
        out.push_str(&format!(
            "impulse_early_data_accepted {}\n",
            self.early_data_accepted.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP impulse_early_data_rejected Total requests rejected in early data.\n");
        out.push_str("# TYPE impulse_early_data_rejected counter\n");
        out.push_str(&format!(
            "impulse_early_data_rejected {}\n",
            self.early_data_rejected.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP impulse_health_checks_total Total active health checks executed.\n");
        out.push_str("# TYPE impulse_health_checks_total counter\n");
        out.push_str(&format!(
            "impulse_health_checks_total {}\n",
            self.health_checks_total.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_health_checks_success Total successful active health checks.\n",
        );
        out.push_str("# TYPE impulse_health_checks_success counter\n");
        out.push_str(&format!(
            "impulse_health_checks_success {}\n",
            self.health_checks_success.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP impulse_health_checks_failure Total failed active health checks.\n");
        out.push_str("# TYPE impulse_health_checks_failure counter\n");
        out.push_str(&format!(
            "impulse_health_checks_failure {}\n",
            self.health_checks_failure.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP impulse_backend_timeouts Total backend timeout events.\n");
        out.push_str("# TYPE impulse_backend_timeouts counter\n");
        out.push_str(&format!(
            "impulse_backend_timeouts {}\n",
            self.backend_timeouts.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP impulse_backend_errors Total backend error events.\n");
        out.push_str("# TYPE impulse_backend_errors counter\n");
        out.push_str(&format!(
            "impulse_backend_errors {}\n",
            self.backend_errors.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_overload_shed Total requests dropped due to overload controls.\n",
        );
        out.push_str("# TYPE impulse_overload_shed counter\n");
        out.push_str(&format!(
            "impulse_overload_shed {}\n",
            self.overload_shed.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_overload_shed_by_reason_total Total overload shed decisions grouped by reason.\n",
        );
        out.push_str("# TYPE impulse_overload_shed_by_reason_total counter\n");
        // Phase 2 (step 5): the `reason=` label vocabulary comes from the canonical
        // `OverloadShedReason::reason_label()` (→ AdmissionOverloadCause slug), not
        // ad hoc string literals, so metric and canonical enum cannot drift.
        for reason in [
            OverloadShedReason::Brownout,
            OverloadShedReason::AdaptiveAdmission,
            OverloadShedReason::RouteCap,
            OverloadShedReason::RouteGlobalCap,
            OverloadShedReason::GlobalInflight,
            OverloadShedReason::UpstreamInflight,
            OverloadShedReason::BackendInflight,
            OverloadShedReason::CircuitOpen,
            OverloadShedReason::RequestBufferCap,
            OverloadShedReason::ResponsePrebufferCap,
            OverloadShedReason::ConnectionCap,
        ] {
            let count = match reason {
                OverloadShedReason::Brownout => self.overload_shed_brownout.load(Ordering::Relaxed),
                OverloadShedReason::AdaptiveAdmission => {
                    self.overload_shed_adaptive.load(Ordering::Relaxed)
                }
                OverloadShedReason::RouteCap => {
                    self.overload_shed_route_cap.load(Ordering::Relaxed)
                }
                OverloadShedReason::RouteGlobalCap => {
                    self.overload_shed_route_global_cap.load(Ordering::Relaxed)
                }
                OverloadShedReason::GlobalInflight => {
                    self.overload_shed_global_inflight.load(Ordering::Relaxed)
                }
                OverloadShedReason::UpstreamInflight => {
                    self.overload_shed_upstream_inflight.load(Ordering::Relaxed)
                }
                OverloadShedReason::BackendInflight => {
                    self.overload_shed_backend_inflight.load(Ordering::Relaxed)
                }
                OverloadShedReason::CircuitOpen => {
                    self.overload_shed_circuit_open.load(Ordering::Relaxed)
                }
                OverloadShedReason::RequestBufferCap => {
                    self.overload_shed_request_buffer.load(Ordering::Relaxed)
                }
                OverloadShedReason::ResponsePrebufferCap => self
                    .overload_shed_response_prebuffer
                    .load(Ordering::Relaxed),
                OverloadShedReason::ConnectionCap => {
                    self.overload_shed_connection_cap.load(Ordering::Relaxed)
                }
            };
            out.push_str(&format!(
                "impulse_overload_shed_by_reason_total{{reason=\"{}\"}} {}\n",
                reason.reason_label(),
                count
            ));
        }

        out.push_str(
            "# HELP impulse_inflight_wait_admit_total Successful inflight admissions after micro-wait.\n",
        );
        out.push_str("# TYPE impulse_inflight_wait_admit_total counter\n");
        out.push_str(&format!(
            "impulse_inflight_wait_admit_total{{scope=\"global\"}} {}\n",
            self.inflight_wait_admit_global.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "impulse_inflight_wait_admit_total{{scope=\"upstream\"}} {}\n",
            self.inflight_wait_admit_upstream.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP impulse_active_connections Current active QUIC connections.\n");
        out.push_str("# TYPE impulse_active_connections gauge\n");
        out.push_str(&format!(
            "impulse_active_connections {}\n",
            self.active_connections.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_runtime_rejections_total Total runtime activation or rollback rejections grouped by canonical operator reason.\n",
        );
        out.push_str("# TYPE impulse_runtime_rejections_total counter\n");
        for reason in [
            RuntimeRejectionReason::InvalidConfig,
            RuntimeRejectionReason::StartupOwnedChange,
            RuntimeRejectionReason::BindConflict,
            RuntimeRejectionReason::ResourcePrepareFailed,
            RuntimeRejectionReason::IncompatibleReload,
            RuntimeRejectionReason::UnknownGeneration,
            RuntimeRejectionReason::RollbackNotAllowed,
        ] {
            out.push_str(&format!(
                "impulse_runtime_rejections_total{{reason=\"{}\"}} {}\n",
                reason.slug(),
                self.runtime_rejection_reason_count(reason)
            ));
        }

        out.push_str(
            "# HELP impulse_runtime_validation_attempts_total Total staged runtime validation requests accepted by the control plane.\n",
        );
        out.push_str("# TYPE impulse_runtime_validation_attempts_total counter\n");
        out.push_str(&format!(
            "impulse_runtime_validation_attempts_total {}\n",
            self.runtime_validation_attempts.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_runtime_preview_attempts_total Total staged runtime preview requests accepted by the control plane.\n",
        );
        out.push_str("# TYPE impulse_runtime_preview_attempts_total counter\n");
        out.push_str(&format!(
            "impulse_runtime_preview_attempts_total {}\n",
            self.runtime_preview_attempts.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_runtime_activation_total Total runtime activation outcomes grouped by result and canonical reason.\n",
        );
        out.push_str("# TYPE impulse_runtime_activation_total counter\n");
        for reason in RuntimeOperationOutcomeReason::ALL {
            out.push_str(&format!(
                "impulse_runtime_activation_total{{result=\"{}\",reason=\"{}\"}} {}\n",
                reason.result_label(),
                reason.slug(),
                self.runtime_activation_outcome_count(reason)
            ));
        }

        out.push_str(
            "# HELP impulse_runtime_rollback_total Total runtime rollback outcomes grouped by result and canonical reason.\n",
        );
        out.push_str("# TYPE impulse_runtime_rollback_total counter\n");
        for reason in RuntimeOperationOutcomeReason::ALL {
            out.push_str(&format!(
                "impulse_runtime_rollback_total{{result=\"{}\",reason=\"{}\"}} {}\n",
                reason.result_label(),
                reason.slug(),
                self.runtime_rollback_outcome_count(reason)
            ));
        }

        out.push_str(
            "# HELP impulse_runtime_active_generation Current active runtime generation identifier.\n",
        );
        out.push_str("# TYPE impulse_runtime_active_generation gauge\n");
        out.push_str(&format!(
            "impulse_runtime_active_generation {}\n",
            self.runtime_active_generation.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_runtime_history_depth Number of retained runtime history entries visible to the active generation.\n",
        );
        out.push_str("# TYPE impulse_runtime_history_depth gauge\n");
        out.push_str(&format!(
            "impulse_runtime_history_depth {}\n",
            self.runtime_history_depth.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_pingora_lb_selector_generation Current Pingora selector runtime generation.\n",
        );
        out.push_str("# TYPE impulse_pingora_lb_selector_generation gauge\n");
        out.push_str(&format!(
            "impulse_pingora_lb_selector_generation {}\n",
            self.pingora_lb_selector_generation.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_pingora_lb_selector_rebuilds_total Total Pingora selector instances rebuilt.\n",
        );
        out.push_str("# TYPE impulse_pingora_lb_selector_rebuilds_total counter\n");
        out.push_str(&format!(
            "impulse_pingora_lb_selector_rebuilds_total {}\n",
            self.pingora_lb_selector_rebuilds.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_pingora_lb_selector_failures_total Total Pingora selector rebuild and selection failures.\n",
        );
        out.push_str("# TYPE impulse_pingora_lb_selector_failures_total counter\n");
        out.push_str(&format!(
            "impulse_pingora_lb_selector_failures_total {}\n",
            self.pingora_lb_selector_failures.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_pingora_lb_selections_total Total backends selected by Pingora load balancing.\n",
        );
        out.push_str("# TYPE impulse_pingora_lb_selections_total counter\n");
        out.push_str(&format!(
            "impulse_pingora_lb_selections_total {}\n",
            self.pingora_lb_selections.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_pingora_discovery_refresh_total Pingora discovery refresh outcomes.\n",
        );
        out.push_str("# TYPE impulse_pingora_discovery_refresh_total counter\n");
        for outcome in PingoraDiscoveryRefreshOutcome::ALL {
            out.push_str(&format!(
                "impulse_pingora_discovery_refresh_total{{outcome=\"{}\"}} {}\n",
                outcome.label(),
                self.pingora_discovery_refresh_outcomes[outcome.index()].load(Ordering::Relaxed)
            ));
        }

        out.push_str(
            "# HELP impulse_pingora_discovery_membership_generation Current Pingora discovery membership generation by upstream.\n",
        );
        out.push_str("# TYPE impulse_pingora_discovery_membership_generation gauge\n");
        out.push_str(
            "# HELP impulse_pingora_discovery_rebuild_duration_seconds Duration of the latest Pingora selector rebuild by upstream.\n",
        );
        out.push_str("# TYPE impulse_pingora_discovery_rebuild_duration_seconds gauge\n");
        let mut discovery_states = self
            .pingora_discovery_state
            .read()
            .map(|states| {
                states
                    .iter()
                    .map(|(upstream, state)| (upstream.clone(), state.clone()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        discovery_states.sort_by(|(left, _), (right, _)| left.cmp(right));
        for (upstream, state) in discovery_states {
            let upstream = escape_prometheus_label(&upstream);
            out.push_str(&format!(
                "impulse_pingora_discovery_membership_generation{{upstream=\"{upstream}\"}} {}\n",
                state.membership_generation
            ));
            out.push_str(&format!(
                "impulse_pingora_discovery_rebuild_duration_seconds{{upstream=\"{upstream}\"}} {}\n",
                state.rebuild_duration_ns as f64 / 1_000_000_000.0
            ));
        }

        out.push_str(
            "# HELP impulse_connection_cap_rejects Total new-connection attempts rejected by max_active_connections cap.\n",
        );
        out.push_str("# TYPE impulse_connection_cap_rejects counter\n");
        out.push_str(&format!(
            "impulse_connection_cap_rejects {}\n",
            self.connection_cap_rejects.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP impulse_hedge_triggered_total Total hedge attempts started.\n");
        out.push_str("# TYPE impulse_hedge_triggered_total counter\n");
        out.push_str(&format!(
            "impulse_hedge_triggered_total {}\n",
            self.hedge_triggered.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_hedge_won_total Total requests where hedge response arrived first.\n",
        );
        out.push_str("# TYPE impulse_hedge_won_total counter\n");
        out.push_str(&format!(
            "impulse_hedge_won_total {}\n",
            self.hedge_won.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_hedge_wasted_total Total hedge attempts that did not win the race.\n",
        );
        out.push_str("# TYPE impulse_hedge_wasted_total counter\n");
        out.push_str(&format!(
            "impulse_hedge_wasted_total {}\n",
            self.hedge_wasted.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_hedge_primary_won_after_trigger_total Total hedged requests where primary still won.\n",
        );
        out.push_str("# TYPE impulse_hedge_primary_won_after_trigger_total counter\n");
        out.push_str(&format!(
            "impulse_hedge_primary_won_after_trigger_total {}\n",
            self.hedge_primary_won_after_trigger.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_hedge_primary_late_ms_total Aggregate milliseconds primary was late after hedge trigger.\n",
        );
        out.push_str("# TYPE impulse_hedge_primary_late_ms_total counter\n");
        out.push_str(&format!(
            "impulse_hedge_primary_late_ms_total {}\n",
            self.hedge_primary_late_ms_total.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_hedge_primary_late_samples_total Number of late-primary observations used in hedge tuning.\n",
        );
        out.push_str("# TYPE impulse_hedge_primary_late_samples_total counter\n");
        out.push_str(&format!(
            "impulse_hedge_primary_late_samples_total {}\n",
            self.hedge_primary_late_samples.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_ingress_packets_total Total UDP packets processed by ingress.\n",
        );
        out.push_str("# TYPE impulse_ingress_packets_total counter\n");
        out.push_str(&format!(
            "impulse_ingress_packets_total {}\n",
            self.ingress_packets_total.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_ingress_queue_drops Total ingress packets dropped due to full shard queues.\n",
        );
        out.push_str("# TYPE impulse_ingress_queue_drops counter\n");
        out.push_str(&format!(
            "impulse_ingress_queue_drops {}\n",
            self.ingress_queue_drops.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_ingress_queue_drop_bytes Total UDP datagram bytes dropped due to full shard queues.\n",
        );
        out.push_str("# TYPE impulse_ingress_queue_drop_bytes counter\n");
        out.push_str(&format!(
            "impulse_ingress_queue_drop_bytes {}\n",
            self.ingress_queue_drop_bytes.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_ingress_queue_bytes Current bytes buffered in ingress shard queues.\n",
        );
        out.push_str("# TYPE impulse_ingress_queue_bytes gauge\n");
        out.push_str(&format!(
            "impulse_ingress_queue_bytes {}\n",
            self.ingress_queue_bytes.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_ingress_bad_header_total Ingress packets dropped due to unparseable QUIC header.\n",
        );
        out.push_str("# TYPE impulse_ingress_bad_header_total counter\n");
        out.push_str(&format!(
            "impulse_ingress_bad_header_total {}\n",
            self.ingress_bad_header_total.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_ingress_rate_limited_total Ingress connection attempts rejected by connection admission filtering.\n",
        );
        out.push_str("# TYPE impulse_ingress_rate_limited_total counter\n");
        out.push_str(&format!(
            "impulse_ingress_rate_limited_total {}\n",
            self.ingress_rate_limited_total.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_ingress_unroutable_total Non-Initial packets received for unknown connections.\n",
        );
        out.push_str("# TYPE impulse_ingress_unroutable_total counter\n");
        out.push_str(&format!(
            "impulse_ingress_unroutable_total {}\n",
            self.ingress_unroutable_total.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_ingress_draining_drops_total Packets dropped because the listener is draining.\n",
        );
        out.push_str("# TYPE impulse_ingress_draining_drops_total counter\n");
        out.push_str(&format!(
            "impulse_ingress_draining_drops_total {}\n",
            self.ingress_draining_drops_total.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_ingress_connection_create_failed_total Packets dropped because quiche::accept() failed to create a new connection.\n",
        );
        out.push_str("# TYPE impulse_ingress_connection_create_failed_total counter\n");
        out.push_str(&format!(
            "impulse_ingress_connection_create_failed_total {}\n",
            self.ingress_connection_create_failed_total
                .load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_ingress_version_neg_failed_total Packets dropped because version negotiation response could not be constructed.\n",
        );
        out.push_str("# TYPE impulse_ingress_version_neg_failed_total counter\n");
        out.push_str(&format!(
            "impulse_ingress_version_neg_failed_total {}\n",
            self.ingress_version_neg_failed_total
                .load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_request_buffered_bytes Current bytes buffered in request backpressure queues.\n",
        );
        out.push_str("# TYPE impulse_request_buffered_bytes gauge\n");
        out.push_str(&format!(
            "impulse_request_buffered_bytes {}\n",
            self.request_buffered_bytes.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_request_buffered_high_watermark_bytes Peak request-buffered bytes since process start.\n",
        );
        out.push_str("# TYPE impulse_request_buffered_high_watermark_bytes gauge\n");
        out.push_str(&format!(
            "impulse_request_buffered_high_watermark_bytes {}\n",
            self.request_buffered_high_watermark_bytes
                .load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_request_buffer_limit_rejects Total requests rejected due to request buffer byte caps.\n",
        );
        out.push_str("# TYPE impulse_request_buffer_limit_rejects counter\n");
        out.push_str(&format!(
            "impulse_request_buffer_limit_rejects {}\n",
            self.request_buffer_limit_rejects.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_response_prebuffer_limit_rejects Total unknown-length upstream responses rejected due to prebuffer cap.\n",
        );
        out.push_str("# TYPE impulse_response_prebuffer_limit_rejects counter\n");
        out.push_str(&format!(
            "impulse_response_prebuffer_limit_rejects {}\n",
            self.response_prebuffer_limit_rejects
                .load(Ordering::Relaxed)
        ));

        out.push_str("# HELP impulse_scid_rotations Total SCID rotations.\n");
        out.push_str("# TYPE impulse_scid_rotations counter\n");
        out.push_str(&format!(
            "impulse_scid_rotations {}\n",
            self.scid_rotations.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_control_api_connection_limit_drops Total control API connections dropped due to max-connection limiter.\n",
        );
        out.push_str("# TYPE impulse_control_api_connection_limit_drops counter\n");
        out.push_str(&format!(
            "impulse_control_api_connection_limit_drops {}\n",
            self.control_api_connection_limit_drops
                .load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_control_api_audit_event_drops Total control API admin audit records dropped before persistence.\n",
        );
        out.push_str("# TYPE impulse_control_api_audit_event_drops counter\n");
        out.push_str(&format!(
            "impulse_control_api_audit_event_drops {}\n",
            self.control_api_audit_event_drops.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_control_api_audit_write_failures Total control API admin audit sink open or write failures.\n",
        );
        out.push_str("# TYPE impulse_control_api_audit_write_failures counter\n");
        out.push_str(&format!(
            "impulse_control_api_audit_write_failures {}\n",
            self.control_api_audit_write_failures
                .load(Ordering::Relaxed)
        ));

        out.push_str("# HELP impulse_watchdog_restart_requests Total watchdog restart requests.\n");
        out.push_str("# TYPE impulse_watchdog_restart_requests counter\n");
        out.push_str(&format!(
            "impulse_watchdog_restart_requests {}\n",
            self.watchdog_restart_requests.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_watchdog_restart_hooks Total executed watchdog restart hooks.\n",
        );
        out.push_str("# TYPE impulse_watchdog_restart_hooks counter\n");
        out.push_str(&format!(
            "impulse_watchdog_restart_hooks {}\n",
            self.watchdog_restart_hooks.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP impulse_runtime_panics Total runtime task panics observed.\n");
        out.push_str("# TYPE impulse_runtime_panics counter\n");
        out.push_str(&format!(
            "impulse_runtime_panics {}\n",
            self.runtime_panics.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_watchdog_degraded_windows Total degraded watchdog evaluation windows.\n",
        );
        out.push_str("# TYPE impulse_watchdog_degraded_windows counter\n");
        out.push_str(&format!(
            "impulse_watchdog_degraded_windows {}\n",
            self.watchdog_degraded_windows.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP impulse_retries_total Total retry attempts across all routes.\n");
        out.push_str("# TYPE impulse_retries_total counter\n");
        out.push_str(&format!(
            "impulse_retries_total {}\n",
            self.retries_total.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_retry_denied_total Total retry attempts blocked, by denial reason.\n",
        );
        out.push_str("# TYPE impulse_retry_denied_total counter\n");
        out.push_str(&format!(
            "impulse_retry_denied_total{{reason=\"budget\"}} {}\n",
            self.retry_denied_budget.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "impulse_retry_denied_total{{reason=\"no_bodyless\"}} {}\n",
            self.retry_denied_no_bodyless.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "impulse_retry_denied_total{{reason=\"no_alternate\"}} {}\n",
            self.retry_denied_no_alternate.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_retry_attempts_total Total retries triggered, by error reason.\n",
        );
        out.push_str("# TYPE impulse_retry_attempts_total counter\n");
        out.push_str(&format!(
            "impulse_retry_attempts_total{{reason=\"timeout\"}} {}\n",
            self.retry_reason_timeout.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "impulse_retry_attempts_total{{reason=\"transport\"}} {}\n",
            self.retry_reason_transport.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "impulse_retry_attempts_total{{reason=\"pool\"}} {}\n",
            self.retry_reason_pool.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP impulse_circuit_breaker_rejected_total Requests rejected by an open circuit breaker.\n");
        out.push_str("# TYPE impulse_circuit_breaker_rejected_total counter\n");
        out.push_str(&format!(
            "impulse_circuit_breaker_rejected_total {}\n",
            self.circuit_breaker_rejected_total.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP impulse_brownout_active Whether brownout mode is currently active (1=active, 0=inactive).\n");
        out.push_str("# TYPE impulse_brownout_active gauge\n");
        out.push_str(&format!(
            "impulse_brownout_active {}\n",
            self.brownout_active.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP impulse_health_failures_total Backend health failures, by failure reason.\n",
        );
        out.push_str("# TYPE impulse_health_failures_total counter\n");
        out.push_str(&format!(
            "impulse_health_failures_total{{reason=\"5xx\"}} {}\n",
            self.health_failure_5xx.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "impulse_health_failures_total{{reason=\"timeout\"}} {}\n",
            self.health_failure_timeout.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "impulse_health_failures_total{{reason=\"transport\"}} {}\n",
            self.health_failure_transport.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "impulse_health_failures_total{{reason=\"tls\"}} {}\n",
            self.health_failure_tls.load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP impulse_downstream_tls_handshake_success_total Successful downstream TLS handshakes.\n",
        );
        out.push_str("# TYPE impulse_downstream_tls_handshake_success_total counter\n");
        out.push_str(&format!(
            "impulse_downstream_tls_handshake_success_total {}\n",
            self.downstream_tls_handshake_success
                .load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP impulse_downstream_tls_handshake_failure_total Downstream TLS handshake failures grouped by listener and reason.\n",
        );
        out.push_str("# TYPE impulse_downstream_tls_handshake_failure_total counter\n");
        for (key, value) in self.snapshot_downstream_tls_handshake_failures() {
            out.push_str(&format!(
                "impulse_downstream_tls_handshake_failure_total{{listener=\"{}\",reason=\"{}\"}} {}\n",
                escape_prometheus_label(&key.listener),
                escape_prometheus_label(&key.reason),
                value
            ));
        }
        out.push_str(
            "# HELP impulse_downstream_tls_certificate_selection_total Downstream TLS certificate selection outcomes grouped by listener.\n",
        );
        out.push_str("# TYPE impulse_downstream_tls_certificate_selection_total counter\n");
        for (key, value) in self.snapshot_downstream_tls_cert_selections() {
            out.push_str(&format!(
                "impulse_downstream_tls_certificate_selection_total{{listener=\"{}\",selection=\"{}\"}} {}\n",
                escape_prometheus_label(&key.listener),
                escape_prometheus_label(&key.selection),
                value
            ));
        }
        out.push_str(
            "# HELP impulse_downstream_tls_alpn_total Negotiated downstream ALPN protocols grouped by listener.\n",
        );
        out.push_str("# TYPE impulse_downstream_tls_alpn_total counter\n");
        for (key, value) in self.snapshot_downstream_tls_alpn() {
            out.push_str(&format!(
                "impulse_downstream_tls_alpn_total{{listener=\"{}\",protocol=\"{}\"}} {}\n",
                escape_prometheus_label(&key.listener),
                escape_prometheus_label(&key.protocol),
                value
            ));
        }
        out.push_str(
            "# HELP impulse_downstream_tls_certificate_not_after_seconds Downstream certificate expiration timestamps grouped by listener and server name.\n",
        );
        out.push_str("# TYPE impulse_downstream_tls_certificate_not_after_seconds gauge\n");
        out.push_str(
            "# HELP impulse_downstream_tls_certificate_days_remaining Estimated whole days remaining before certificate expiration.\n",
        );
        out.push_str("# TYPE impulse_downstream_tls_certificate_days_remaining gauge\n");
        let now_unix_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or_default();
        for (key, value) in self.snapshot_downstream_tls_cert_expiry() {
            out.push_str(&format!(
                "impulse_downstream_tls_certificate_not_after_seconds{{listener=\"{}\",server_name=\"{}\"}} {}\n",
                escape_prometheus_label(&key.listener),
                escape_prometheus_label(&key.server_name),
                value
            ));
            let days_remaining = ((value - now_unix_seconds).max(0) as f64) / 86_400.0;
            out.push_str(&format!(
                "impulse_downstream_tls_certificate_days_remaining{{listener=\"{}\",server_name=\"{}\"}} {:.6}\n",
                escape_prometheus_label(&key.listener),
                escape_prometheus_label(&key.server_name),
                days_remaining
            ));
        }
        out.push_str(
            "# HELP impulse_upstream_tls_failure_total Upstream TLS failures grouped by upstream, backend, request phase, and reason.\n",
        );
        out.push_str("# TYPE impulse_upstream_tls_failure_total counter\n");
        for (key, value) in self.snapshot_upstream_tls_failures() {
            out.push_str(&format!(
                "impulse_upstream_tls_failure_total{{upstream=\"{}\",backend=\"{}\",phase=\"{}\",reason=\"{}\"}} {}\n",
                escape_prometheus_label(&key.upstream),
                escape_prometheus_label(&key.backend),
                escape_prometheus_label(&key.phase),
                escape_prometheus_label(&key.reason),
                value
            ));
        }
        out.push_str(
            "# HELP impulse_secret_reload_total Total secret or certificate reload outcomes grouped by scope, result, and reason.\n",
        );
        out.push_str("# TYPE impulse_secret_reload_total counter\n");
        for (key, value) in &secret_metrics.secret_reload_totals {
            out.push_str(&format!(
                "impulse_secret_reload_total{{scope=\"{}\",result=\"{}\",reason=\"{}\"}} {}\n",
                escape_prometheus_label(&key.scope),
                escape_prometheus_label(&key.result),
                escape_prometheus_label(&key.reason),
                value
            ));
        }
        out.push_str(
            "# HELP impulse_secret_resolve_total Total secret resolution outcomes grouped by provider, result, and reason.\n",
        );
        out.push_str("# TYPE impulse_secret_resolve_total counter\n");
        for (key, value) in &secret_metrics.secret_resolve_totals {
            out.push_str(&format!(
                "impulse_secret_resolve_total{{provider=\"{}\",result=\"{}\",reason=\"{}\"}} {}\n",
                escape_prometheus_label(&key.provider),
                escape_prometheus_label(&key.result),
                escape_prometheus_label(&key.reason),
                value
            ));
        }
        out.push_str(
            "# HELP impulse_secret_last_success_unixtime Unix timestamp of the last successful secret or certificate load by scope.\n",
        );
        out.push_str("# TYPE impulse_secret_last_success_unixtime gauge\n");
        for (key, value) in &secret_metrics.secret_last_success_unixtime {
            out.push_str(&format!(
                "impulse_secret_last_success_unixtime{{scope=\"{}\"}} {}\n",
                escape_prometheus_label(&key.scope),
                value
            ));
        }
        out.push_str(
            "# HELP impulse_upstream_client_certificate_not_after_seconds Upstream client certificate expiration timestamps grouped by upstream.\n",
        );
        out.push_str("# TYPE impulse_upstream_client_certificate_not_after_seconds gauge\n");
        out.push_str(
            "# HELP impulse_upstream_client_certificate_days_remaining Estimated whole days remaining before upstream client certificate expiration.\n",
        );
        out.push_str("# TYPE impulse_upstream_client_certificate_days_remaining gauge\n");
        for (key, value) in &secret_metrics.upstream_client_cert_expiry {
            out.push_str(&format!(
                "impulse_upstream_client_certificate_not_after_seconds{{upstream=\"{}\"}} {}\n",
                escape_prometheus_label(&key.upstream),
                value
            ));
            let days_remaining = ((value - now_unix_seconds).max(0) as f64) / 86_400.0;
            out.push_str(&format!(
                "impulse_upstream_client_certificate_days_remaining{{upstream=\"{}\"}} {:.6}\n",
                escape_prometheus_label(&key.upstream),
                days_remaining
            ));
        }
        out.push_str(
            "# HELP impulse_control_plane_cert_reload_total Total control-plane listener certificate reload outcomes grouped by result and reason.\n",
        );
        out.push_str("# TYPE impulse_control_plane_cert_reload_total counter\n");
        for (key, value) in &secret_metrics.control_plane_cert_reload_totals {
            out.push_str(&format!(
                "impulse_control_plane_cert_reload_total{{result=\"{}\",reason=\"{}\"}} {}\n",
                escape_prometheus_label(&key.result),
                escape_prometheus_label(&key.reason),
                value
            ));
        }
        out.push_str(
            "# HELP impulse_backend_dns_refresh_success_total Total successful backend DNS refreshes.\n",
        );
        out.push_str("# TYPE impulse_backend_dns_refresh_success_total counter\n");
        out.push_str(&format!(
            "impulse_backend_dns_refresh_success_total {}\n",
            self.backend_dns_refresh_success.load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP impulse_backend_dns_refresh_failure_total Total failed backend DNS refreshes.\n",
        );
        out.push_str("# TYPE impulse_backend_dns_refresh_failure_total counter\n");
        out.push_str(&format!(
            "impulse_backend_dns_refresh_failure_total {}\n",
            self.backend_dns_refresh_failure.load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP impulse_backend_dns_address_set_changes_total Total successful backend DNS refreshes that changed the resolved address set.\n",
        );
        out.push_str("# TYPE impulse_backend_dns_address_set_changes_total counter\n");
        out.push_str(&format!(
            "impulse_backend_dns_address_set_changes_total {}\n",
            self.backend_dns_refresh_address_changes
                .load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP impulse_backend_client_rotations_total Total backend client rotations triggered by DNS address-set changes.\n",
        );
        out.push_str("# TYPE impulse_backend_client_rotations_total counter\n");
        out.push_str(&format!(
            "impulse_backend_client_rotations_total {}\n",
            self.backend_client_rotations.load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP impulse_backend_client_rotation_failures_total Total backend client rotations that failed after a DNS address-set change (stale pooled connections may persist).\n",
        );
        out.push_str("# TYPE impulse_backend_client_rotation_failures_total counter\n");
        out.push_str(&format!(
            "impulse_backend_client_rotation_failures_total {}\n",
            self.backend_client_rotation_failures
                .load(Ordering::Relaxed)
        ));
        self.append_cached_jwt_jwks_metrics_families(&mut out);
        self.append_cached_backend_metrics_families(&mut out);
        out.push_str(
            "# HELP impulse_upstream_requests_total Total completed requests grouped by upstream, status class, and outcome.\n",
        );
        out.push_str("# TYPE impulse_upstream_requests_total counter\n");
        for (key, count) in &request_result_metrics.upstream_request_counts {
            out.push_str(&format!(
                "impulse_upstream_requests_total{{upstream=\"{}\",status_class=\"{}\",outcome=\"{}\"}} {}\n",
                escape_prometheus_label(&key.upstream),
                escape_prometheus_label(key.status_class),
                escape_prometheus_label(key.outcome),
                count
            ));
        }
        out.push_str(
            "# HELP impulse_backend_requests_total Total completed requests grouped by upstream, backend, status class, and outcome.\n",
        );
        out.push_str("# TYPE impulse_backend_requests_total counter\n");
        for (key, count) in &request_result_metrics.backend_request_counts {
            out.push_str(&format!(
                "impulse_backend_requests_total{{upstream=\"{}\",backend=\"{}\",status_class=\"{}\",outcome=\"{}\"}} {}\n",
                escape_prometheus_label(&key.upstream),
                escape_prometheus_label(&key.backend),
                escape_prometheus_label(key.status_class),
                escape_prometheus_label(key.outcome),
                count
            ));
        }
        out.push_str(
            "# HELP impulse_upstream_request_latency_ms Upstream request latency histogram grouped by upstream and final outcome.\n",
        );
        out.push_str("# TYPE impulse_upstream_request_latency_ms histogram\n");
        for (key, stats) in &request_result_metrics.upstream_request_latency {
            let upstream = escape_prometheus_label(&key.upstream);
            let outcome = escape_prometheus_label(key.outcome);
            let mut cumulative = 0u64;
            for (idx, bucket_value) in stats.latency_buckets.iter().enumerate() {
                cumulative = cumulative.saturating_add(*bucket_value);
                let le = LATENCY_BUCKETS_MS
                    .get(idx)
                    .map(u64::to_string)
                    .unwrap_or_else(|| "+Inf".to_string());
                out.push_str(&format!(
                    "impulse_upstream_request_latency_ms_bucket{{upstream=\"{}\",outcome=\"{}\",le=\"{}\"}} {}\n",
                    upstream, outcome, le, cumulative
                ));
            }
            out.push_str(&format!(
                "impulse_upstream_request_latency_ms_sum{{upstream=\"{}\",outcome=\"{}\"}} {}\n",
                upstream, outcome, stats.latency_ms_sum
            ));
            out.push_str(&format!(
                "impulse_upstream_request_latency_ms_count{{upstream=\"{}\",outcome=\"{}\"}} {}\n",
                upstream, outcome, stats.count
            ));
        }
        self.append_cached_route_worker_metrics_families(&mut out);

        out
    }
}

fn percentile_ms(stats: &RouteStats, quantile: f64) -> f64 {
    // Percentiles are computed over the recorded latency samples, which under
    // latency sampling (SAMPLE_EVERY > 1) are only a subset of requests_total.
    // Using requests_total as the denominator would push the target past the
    // sampled bucket population and always return the sentinel bucket.
    let sampled: u64 = stats.latency_buckets.iter().sum();
    if sampled == 0 {
        return 0.0;
    }

    let target = ((sampled as f64) * quantile).ceil() as u64;
    let mut running = 0u64;

    for (idx, count) in stats.latency_buckets.iter().enumerate() {
        running = running.saturating_add(*count);
        if running >= target {
            return if idx < LATENCY_BUCKETS_MS.len() {
                LATENCY_BUCKETS_MS[idx] as f64
            } else {
                *LATENCY_BUCKETS_MS.last().unwrap_or(&60_000) as f64
            };
        }
    }

    *LATENCY_BUCKETS_MS.last().unwrap_or(&60_000) as f64
}

fn escape_prometheus_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}
