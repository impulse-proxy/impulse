//! Prometheus exposition contract for `Metrics::render_prometheus`.

use std::{sync::atomic::Ordering, time::Duration};

use impulse_contracts::{
    AlternateBackendFailureReason, HedgeOutcomeTelemetryReason, HedgeTriggerTelemetryReason,
    RetryAttemptTelemetryReason, RetryPolicyDenialReason, UpstreamTerminalErrorKind,
};
use impulse_edge::runtime::activation::{RuntimeOperationOutcomeReason, RuntimeRejectionReason};
use impulse_observability::{Metrics, OverloadShedReason, RouteOutcome};

#[test]
fn metrics_render_includes_route_percentiles() {
    let metrics = Metrics::new(1, [String::from("api_pool")]);
    metrics.record_route("api_pool", Duration::from_millis(12), RouteOutcome::Success);
    metrics.record_request_result(
        "api_pool",
        Some("https://10.0.0.10:443"),
        Some(200),
        RouteOutcome::Success,
        Duration::from_millis(12),
    );
    metrics.record_route(
        "api_pool",
        Duration::from_millis(320),
        RouteOutcome::Timeout,
    );
    metrics.record_request_result(
        "api_pool",
        Some("https://10.0.0.10:443"),
        Some(503),
        RouteOutcome::Timeout,
        Duration::from_millis(320),
    );
    metrics.record_route(
        "api_pool",
        Duration::from_millis(900),
        RouteOutcome::BackendError,
    );
    metrics.record_request_result(
        "api_pool",
        Some("https://10.0.0.11:443"),
        Some(502),
        RouteOutcome::BackendError,
        Duration::from_millis(900),
    );

    let output = metrics.render_prometheus();
    assert!(output.contains("impulse_route_requests_total{route=\"api_pool\"} 3"));
    assert!(output.contains("impulse_route_latency_ms_p50{route=\"api_pool\"}"));
    assert!(output.contains("impulse_route_latency_ms_p95{route=\"api_pool\"}"));
    assert!(output.contains("impulse_route_latency_ms_p99{route=\"api_pool\"}"));
    assert!(output.contains(
        "impulse_upstream_requests_total{upstream=\"api_pool\",status_class=\"2xx\",outcome=\"success\"} 1"
    ));
    assert!(output.contains(
        "impulse_upstream_requests_total{upstream=\"api_pool\",status_class=\"5xx\",outcome=\"timeout\"} 1"
    ));
    assert!(output.contains(
        "impulse_backend_requests_total{upstream=\"api_pool\",backend=\"https://10.0.0.11:443\",status_class=\"5xx\",outcome=\"backend_error\"} 1"
    ));
    assert!(output.contains(
        "impulse_upstream_request_latency_ms_bucket{upstream=\"api_pool\",outcome=\"success\",le=\"25\"} 1"
    ));
    assert!(output.contains(
        "impulse_upstream_request_latency_ms_count{upstream=\"api_pool\",outcome=\"backend_error\"} 1"
    ));
}

#[test]
fn metrics_render_collects_routes_from_multiple_shards() {
    let routes: Vec<String> = (0..128).map(|idx| format!("route-{idx:03}")).collect();
    let metrics = Metrics::new(1, routes.clone());
    for (idx, route) in routes.iter().enumerate().take(128) {
        metrics.record_route(
            route,
            Duration::from_millis(5 + idx as u64),
            RouteOutcome::Success,
        );
    }

    let output = metrics.render_prometheus();
    assert!(output.contains("impulse_route_requests_total{route=\"route-000\"} 1"));
    assert!(output.contains("impulse_route_requests_total{route=\"route-127\"} 1"));
}

#[test]
fn request_buffer_reservation_respects_cap_and_releases() {
    let metrics = Metrics::default();
    assert!(metrics.try_reserve_request_buffer(512, 1024));
    assert!(!metrics.try_reserve_request_buffer(600, 1024));
    assert_eq!(metrics.request_buffered_bytes.load(Ordering::Relaxed), 512);
    assert_eq!(
        metrics
            .request_buffered_high_watermark_bytes
            .load(Ordering::Relaxed),
        512
    );

    metrics.release_request_buffer(256);
    assert_eq!(metrics.request_buffered_bytes.load(Ordering::Relaxed), 256);

    metrics.release_request_buffer(512);
    assert_eq!(metrics.request_buffered_bytes.load(Ordering::Relaxed), 0);
}

#[test]
fn metrics_render_includes_overload_reasons_and_hedge_counters() {
    let metrics = Metrics::default();
    metrics.inc_overload_shed_reason(OverloadShedReason::GlobalInflight);
    metrics.inc_overload_shed_reason(OverloadShedReason::BackendInflight);
    metrics.inc_overload_shed_reason(OverloadShedReason::CircuitOpen);
    metrics.set_active_connections(7);
    metrics.inc_connection_cap_reject();
    metrics.inc_hedge_trigger(HedgeTriggerTelemetryReason::DelayElapsed);
    metrics.inc_hedge_outcome(HedgeOutcomeTelemetryReason::HedgeWon);
    metrics.inc_hedge_outcome(HedgeOutcomeTelemetryReason::PrimaryWonAfterTrigger);
    metrics.observe_hedge_primary_late_ms(42);
    metrics.inc_control_api_connection_limit_drop();

    let output = metrics.render_prometheus();
    assert!(output.contains("impulse_overload_shed_by_reason_total{reason=\"global_inflight\"} 1"));
    assert!(
        output.contains("impulse_overload_shed_by_reason_total{reason=\"backend_inflight\"} 1")
    );
    assert!(output.contains("impulse_overload_shed_by_reason_total{reason=\"circuit_open\"} 1"));
    assert!(output.contains("impulse_active_connections 7"));
    assert!(output.contains("impulse_connection_cap_rejects 1"));
    assert!(output.contains("impulse_hedge_triggered_total 1"));
    assert!(output.contains("impulse_hedge_won_total 1"));
    assert!(output.contains("impulse_hedge_wasted_total 1"));
    assert!(output.contains("impulse_hedge_primary_won_after_trigger_total 1"));
    assert!(output.contains("impulse_hedge_primary_late_ms_total 42"));
    assert!(output.contains("impulse_hedge_primary_late_samples_total 1"));
    assert!(output.contains("impulse_ingress_queue_bytes 0\n"));
    assert!(output.contains("impulse_ingress_bad_header_total 0\n"));
    assert!(output.contains("impulse_ingress_rate_limited_total 0\n"));
    assert!(output.contains("impulse_ingress_unroutable_total 0\n"));
    assert!(output.contains("impulse_ingress_draining_drops_total 0\n"));
    assert!(output.contains("impulse_ingress_connection_create_failed_total 0\n"));
    assert!(output.contains("impulse_ingress_version_neg_failed_total 0\n"));
    assert!(output.contains("impulse_control_api_connection_limit_drops 1\n"));
    assert!(output.contains("impulse_circuit_breaker_rejected_total 0\n"));
    assert!(output.contains("impulse_brownout_active 0\n"));
}

#[test]
fn metrics_render_includes_runtime_rejection_reason_vocab() {
    let metrics = Metrics::default();
    metrics.inc_runtime_rejection_reason(RuntimeRejectionReason::InvalidConfig);
    metrics.inc_runtime_rejection_reason(RuntimeRejectionReason::StartupOwnedChange);
    metrics.inc_runtime_rejection_reason(RuntimeRejectionReason::BindConflict);
    metrics.inc_runtime_rejection_reason(RuntimeRejectionReason::ResourcePrepareFailed);
    metrics.inc_runtime_rejection_reason(RuntimeRejectionReason::IncompatibleReload);
    metrics.inc_runtime_rejection_reason(RuntimeRejectionReason::UnknownGeneration);
    metrics.inc_runtime_rejection_reason(RuntimeRejectionReason::RollbackNotAllowed);

    let output = metrics.render_prometheus();
    for expected in [
        "impulse_runtime_rejections_total{reason=\"invalid_config\"} 1",
        "impulse_runtime_rejections_total{reason=\"startup_owned_change\"} 1",
        "impulse_runtime_rejections_total{reason=\"bind_conflict\"} 1",
        "impulse_runtime_rejections_total{reason=\"resource_prepare_failed\"} 1",
        "impulse_runtime_rejections_total{reason=\"incompatible_reload\"} 1",
        "impulse_runtime_rejections_total{reason=\"unknown_generation\"} 1",
        "impulse_runtime_rejections_total{reason=\"rollback_not_allowed\"} 1",
    ] {
        assert!(output.contains(expected), "missing metric line: {expected}");
    }
}

#[test]
fn metrics_render_includes_runtime_activation_observability_contract() {
    let metrics = Metrics::default();
    metrics.inc_runtime_validation_attempt();
    metrics.inc_runtime_preview_attempt();
    metrics.record_runtime_activation_outcome(RuntimeOperationOutcomeReason::Applied);
    metrics.record_runtime_activation_outcome(RuntimeOperationOutcomeReason::InvalidConfig);
    metrics.record_runtime_rollback_outcome(RuntimeOperationOutcomeReason::Applied);
    metrics.record_runtime_rollback_outcome(RuntimeOperationOutcomeReason::RollbackNotAllowed);
    metrics.set_runtime_active_generation(12);
    metrics.set_runtime_history_depth(3);

    let output = metrics.render_prometheus();
    for expected in [
        "impulse_runtime_validation_attempts_total 1",
        "impulse_runtime_preview_attempts_total 1",
        "impulse_runtime_activation_total{result=\"success\",reason=\"applied\"} 1",
        "impulse_runtime_activation_total{result=\"failure\",reason=\"invalid_config\"} 1",
        "impulse_runtime_rollback_total{result=\"success\",reason=\"applied\"} 1",
        "impulse_runtime_rollback_total{result=\"failure\",reason=\"rollback_not_allowed\"} 1",
        "impulse_runtime_active_generation 12",
        "impulse_runtime_history_depth 3",
    ] {
        assert!(output.contains(expected), "missing metric line: {expected}");
    }
}

#[test]
fn resilience_metrics_increment_correctly() {
    let metrics = Metrics::default();
    metrics.inc_retry_attempt(RetryAttemptTelemetryReason::Timeout);
    metrics.inc_retry_denied(RetryPolicyDenialReason::BudgetDenied);
    metrics.inc_circuit_breaker_rejected();
    metrics.inc_circuit_breaker_rejected();
    metrics.set_brownout_active(true);
    let output = metrics.render_prometheus();
    assert!(output.contains("impulse_retries_total 1\n"));
    assert!(output.contains("impulse_retry_attempts_total{reason=\"timeout\"} 1\n"));
    assert!(output.contains("impulse_retry_denied_total{reason=\"budget\"} 1\n"));
    assert!(output.contains("impulse_circuit_breaker_rejected_total 2\n"));
    assert!(output.contains("impulse_brownout_active 1\n"));
    metrics.set_brownout_active(false);
    let output2 = metrics.render_prometheus();
    assert!(output2.contains("impulse_brownout_active 0\n"));
}

#[test]
fn retry_and_hedge_counters_increment_only_on_executed_branches() {
    let metrics = Metrics::default();
    metrics.inc_retry_attempt(RetryAttemptTelemetryReason::Transport);
    metrics.inc_retry_denied(RetryPolicyDenialReason::MethodNotIdempotent);
    metrics.inc_retry_denied(RetryPolicyDenialReason::RequestBodyNotReplayable);
    metrics.inc_retry_denied(RetryPolicyDenialReason::AlternateBackendUnavailable(
        AlternateBackendFailureReason::NoHealthyBackends,
    ));
    metrics.inc_retry_denied(RetryPolicyDenialReason::AttemptLimitReached);
    metrics.inc_retry_denied(RetryPolicyDenialReason::TerminalError(
        UpstreamTerminalErrorKind::Protocol,
    ));
    metrics.inc_hedge_trigger(HedgeTriggerTelemetryReason::DelayElapsed);
    metrics.inc_hedge_outcome(HedgeOutcomeTelemetryReason::PrimaryWonAfterTrigger);

    let output = metrics.render_prometheus();
    assert!(output.contains("impulse_retries_total 1\n"));
    assert!(output.contains("impulse_retry_attempts_total{reason=\"transport\"} 1\n"));
    assert!(output.contains("impulse_retry_attempts_total{reason=\"timeout\"} 0\n"));
    assert!(output.contains("impulse_retry_denied_total{reason=\"budget\"} 0\n"));
    assert!(output.contains("impulse_retry_denied_total{reason=\"no_bodyless\"} 2\n"));
    assert!(output.contains("impulse_retry_denied_total{reason=\"no_alternate\"} 1\n"));
    assert!(output.contains("impulse_hedge_triggered_total 1\n"));
    assert!(output.contains("impulse_hedge_won_total 0\n"));
    assert!(output.contains("impulse_hedge_wasted_total 1\n"));
    assert!(output.contains("impulse_hedge_primary_won_after_trigger_total 1\n"));
}

#[test]
fn metrics_render_keeps_retry_and_outcome_label_vocabularies_stable() {
    let metrics = Metrics::default();
    metrics.inc_retry_attempt(RetryAttemptTelemetryReason::Timeout);
    metrics.inc_retry_attempt(RetryAttemptTelemetryReason::Transport);
    metrics.inc_retry_attempt(RetryAttemptTelemetryReason::Pool);
    metrics.inc_retry_denied(RetryPolicyDenialReason::BudgetDenied);
    metrics.inc_retry_denied(RetryPolicyDenialReason::MethodNotIdempotent);
    metrics.inc_retry_denied(RetryPolicyDenialReason::AlternateBackendUnavailable(
        AlternateBackendFailureReason::NoHealthyBackends,
    ));
    metrics.inc_overload_shed_reason(OverloadShedReason::Brownout);
    metrics.inc_overload_shed_reason(OverloadShedReason::AdaptiveAdmission);
    metrics.inc_overload_shed_reason(OverloadShedReason::RouteCap);
    metrics.inc_overload_shed_reason(OverloadShedReason::RouteGlobalCap);
    metrics.inc_overload_shed_reason(OverloadShedReason::GlobalInflight);
    metrics.inc_overload_shed_reason(OverloadShedReason::UpstreamInflight);
    metrics.inc_overload_shed_reason(OverloadShedReason::BackendInflight);
    metrics.inc_overload_shed_reason(OverloadShedReason::CircuitOpen);
    metrics.inc_overload_shed_reason(OverloadShedReason::RequestBufferCap);
    metrics.inc_overload_shed_reason(OverloadShedReason::ResponsePrebufferCap);
    metrics.inc_overload_shed_reason(OverloadShedReason::ConnectionCap);

    let output = metrics.render_prometheus();
    for expected in [
        "impulse_retry_attempts_total{reason=\"timeout\"} 1",
        "impulse_retry_attempts_total{reason=\"transport\"} 1",
        "impulse_retry_attempts_total{reason=\"pool\"} 1",
        "impulse_retry_denied_total{reason=\"budget\"} 1",
        "impulse_retry_denied_total{reason=\"no_bodyless\"} 1",
        "impulse_retry_denied_total{reason=\"no_alternate\"} 1",
        "impulse_overload_shed_by_reason_total{reason=\"brownout\"} 1",
        "impulse_overload_shed_by_reason_total{reason=\"adaptive_admission\"} 1",
        "impulse_overload_shed_by_reason_total{reason=\"route_cap\"} 1",
        "impulse_overload_shed_by_reason_total{reason=\"route_global_cap\"} 1",
        "impulse_overload_shed_by_reason_total{reason=\"global_inflight\"} 1",
        "impulse_overload_shed_by_reason_total{reason=\"upstream_inflight\"} 1",
        "impulse_overload_shed_by_reason_total{reason=\"backend_inflight\"} 1",
        "impulse_overload_shed_by_reason_total{reason=\"circuit_open\"} 1",
        "impulse_overload_shed_by_reason_total{reason=\"request_buffer_cap\"} 1",
        "impulse_overload_shed_by_reason_total{reason=\"response_prebuffer_cap\"} 1",
        "impulse_overload_shed_by_reason_total{reason=\"connection_cap\"} 1",
    ] {
        assert!(output.contains(expected), "missing metric line: {expected}");
    }
}

#[test]
fn metrics_render_includes_external_auth_counters() {
    let metrics = Metrics::default();
    metrics.inc_external_auth_allowed();
    metrics.inc_external_auth_denied();
    metrics.inc_external_auth_timeout();
    metrics.inc_external_auth_error();

    let output = metrics.render_prometheus();
    assert!(output.contains(
        "impulse_external_auth_allowed 1
"
    ));
    assert!(output.contains(
        "impulse_external_auth_denied 1
"
    ));
    assert!(output.contains(
        "impulse_external_auth_timeout 1
"
    ));
    assert!(output.contains(
        "impulse_external_auth_error 1
"
    ));
}

#[test]
fn metrics_render_includes_rate_limited_counters() {
    let metrics = Metrics::new(1, [String::from("api_pool")]);
    metrics.inc_request_rate_limited();
    metrics.record_route(
        "api_pool",
        Duration::from_millis(8),
        RouteOutcome::RateLimited,
    );

    let output = metrics.render_prometheus();
    assert!(output.contains("impulse_request_rate_limited 1\n"));
    assert!(output.contains("impulse_route_rate_limited_total{route=\"api_pool\"} 1\n"));
}

#[test]
fn ingress_drop_counters_increment_correctly() {
    let metrics = Metrics::default();
    metrics.inc_ingress_bad_header();
    metrics.inc_ingress_bad_header();
    metrics.inc_ingress_rate_limited();
    metrics.inc_ingress_unroutable();
    metrics.inc_ingress_unroutable();
    metrics.inc_ingress_unroutable();
    metrics.inc_ingress_draining_drop();
    metrics.inc_ingress_connection_create_failed();
    metrics.inc_ingress_version_neg_failed();
    metrics.inc_ingress_version_neg_failed();
    let output = metrics.render_prometheus();
    assert!(output.contains("impulse_ingress_bad_header_total 2\n"));
    assert!(output.contains("impulse_ingress_rate_limited_total 1\n"));
    assert!(output.contains("impulse_ingress_unroutable_total 3\n"));
    assert!(output.contains("impulse_ingress_draining_drops_total 1\n"));
    assert!(output.contains("impulse_ingress_connection_create_failed_total 1\n"));
    assert!(output.contains("impulse_ingress_version_neg_failed_total 2\n"));
}

#[test]
fn metrics_render_includes_worker_labels() {
    let metrics = Metrics::default();
    metrics.inc_total();
    metrics.inc_success();
    metrics.inc_failure();
    metrics.inc_ingress_packet();
    metrics.inc_ingress_queue_drop();
    metrics.inc_ingress_queue_drop_bytes(128);

    let output = metrics.render_prometheus();
    assert!(output.contains("impulse_worker_requests_total{worker=\""));
    assert!(output.contains("impulse_worker_requests_success{worker=\""));
    assert!(output.contains("impulse_worker_requests_failure{worker=\""));
    assert!(output.contains("impulse_worker_ingress_packets_total{worker=\""));
    assert!(output.contains("impulse_worker_ingress_queue_drops{worker=\""));
    assert!(output.contains("impulse_worker_ingress_queue_drop_bytes{worker=\""));
    assert!(output.contains("impulse_worker_requests_total{worker=\"") && output.contains("} 1"));
    assert!(
        output.contains("impulse_worker_ingress_queue_drop_bytes{worker=\"")
            && output.contains("} 128")
    );
}

#[test]
fn metrics_render_includes_backend_dns_refresh_telemetry() {
    let metrics = Metrics::default();
    metrics.record_backend_dns_refresh_success(
        "backend.internal:443",
        std::time::UNIX_EPOCH + Duration::from_secs(42),
        2,
        true,
    );
    metrics.inc_backend_dns_refresh_failure();
    metrics.inc_backend_client_rotation("backend.internal:443");
    metrics.record_backend_connect(
        "backend.internal:443",
        "backend.internal",
        "10.0.0.10:443".parse().expect("addr one"),
    );
    metrics.record_backend_connect(
        "backend.internal:443",
        "backend.internal",
        "10.0.0.11:443".parse().expect("addr two"),
    );

    let output = metrics.render_prometheus();
    assert!(output.contains("impulse_backend_dns_refresh_success_total 1"));
    assert!(output.contains("impulse_backend_dns_refresh_failure_total 1"));
    assert!(output.contains("impulse_backend_dns_address_set_changes_total 1"));
    assert!(output.contains("impulse_backend_client_rotations_total 1"));
    assert!(output.contains(
        "impulse_backend_dns_last_refresh_success_seconds{backend=\"backend.internal:443\"} 42"
    ));
    assert!(
        output
            .contains("impulse_backend_dns_resolved_addresses{backend=\"backend.internal:443\"} 2")
    );
    assert!(
        output.contains("impulse_backend_client_rotations{backend=\"backend.internal:443\"} 1")
    );
    assert!(output.contains(
        "impulse_backend_connect_attempt_total{backend=\"backend.internal:443\",hostname=\"backend.internal\",resolved_addr=\"10.0.0.10:443\"} 1"
    ));
    assert!(output.contains(
        "impulse_backend_connect_attempt_total{backend=\"backend.internal:443\",hostname=\"backend.internal\",resolved_addr=\"10.0.0.11:443\"} 1"
    ));
}

#[test]
fn metrics_render_includes_downstream_tls_telemetry() {
    let metrics = Metrics::default();
    metrics.inc_downstream_tls_handshake_success();
    metrics.record_downstream_tls_handshake_failure("127.0.0.1:9889", "missing_client_cert");
    metrics.record_downstream_tls_cert_selection("127.0.0.1:9889", "exact_sni");
    metrics.record_downstream_tls_alpn("127.0.0.1:9889", "h2");

    let output = metrics.render_prometheus();
    assert!(output.contains("impulse_downstream_tls_handshake_success_total 1"));
    assert!(output.contains(
        "impulse_downstream_tls_handshake_failure_total{listener=\"127.0.0.1:9889\",reason=\"missing_client_cert\"} 1"
    ));
    assert!(output.contains(
        "impulse_downstream_tls_certificate_selection_total{listener=\"127.0.0.1:9889\",selection=\"exact_sni\"} 1"
    ));
    assert!(output.contains(
        "impulse_downstream_tls_alpn_total{listener=\"127.0.0.1:9889\",protocol=\"h2\"} 1"
    ));
}

#[test]
fn metrics_render_includes_upstream_tls_telemetry() {
    let metrics = Metrics::default();
    metrics.record_upstream_tls_failure(
        "api",
        "backend.internal:443",
        "data_plane",
        "unknown_issuer",
    );
    metrics.record_upstream_tls_failure(
        "api",
        "backend.internal:443",
        "health_check",
        "hostname_mismatch",
    );

    let output = metrics.render_prometheus();
    assert!(output.contains(
        "impulse_upstream_tls_failure_total{upstream=\"api\",backend=\"backend.internal:443\",phase=\"data_plane\",reason=\"unknown_issuer\"} 1"
    ));
    assert!(output.contains(
        "impulse_upstream_tls_failure_total{upstream=\"api\",backend=\"backend.internal:443\",phase=\"health_check\",reason=\"hostname_mismatch\"} 1"
    ));
}

#[test]
fn metrics_render_includes_downstream_tls_certificate_expiry() {
    let metrics = Metrics::default();
    metrics.replace_downstream_tls_cert_expiry(
        "127.0.0.1:9889",
        [
            ("__default__".to_string(), 2_000_000_000),
            ("api.example.com".to_string(), 2_100_000_000),
        ],
    );

    let output = metrics.render_prometheus();
    assert!(output.contains(
        "impulse_downstream_tls_certificate_not_after_seconds{listener=\"127.0.0.1:9889\",server_name=\"__default__\"} 2000000000"
    ));
    assert!(output.contains(
        "impulse_downstream_tls_certificate_not_after_seconds{listener=\"127.0.0.1:9889\",server_name=\"api.example.com\"} 2100000000"
    ));
    assert!(output.contains(
        "impulse_downstream_tls_certificate_days_remaining{listener=\"127.0.0.1:9889\",server_name=\"api.example.com\"}"
    ));
}

#[test]
fn backend_connect_attempt_labels_are_cardinality_bounded() {
    // obs Phase 2 (step 7): resolved_addr/hostname are otherwise unbounded across
    // DNS churn. Emitting far more distinct addresses than the cap must not create
    // an unbounded number of series — overflow folds into a stable sentinel.
    let metrics = Metrics::default();
    for i in 0..5_000u32 {
        let octet_a = (i / 256) % 256;
        let octet_b = i % 256;
        let addr = format!("10.{octet_a}.{octet_b}.1:443");
        metrics.record_backend_connect(
            "backend.internal:443",
            "backend.internal",
            addr.parse().expect("addr"),
        );
    }

    let output = metrics.render_prometheus();
    let series = output
        .lines()
        .filter(|line| line.starts_with("impulse_backend_connect_attempt_total{"))
        .count();
    assert!(
        series <= 600,
        "connect-attempt series must be bounded, got {series}"
    );
    assert!(
        output.contains("resolved_addr=\"__over_cap__\""),
        "overflow beyond the cap must fold into the stable sentinel series"
    );
}
