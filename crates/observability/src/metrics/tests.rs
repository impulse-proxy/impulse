use std::time::Duration;

use super::*;
use crate::{QuotaBackendHealthReason, QuotaPolicyDecision, QuotaPolicyReason};

#[test]
fn prometheus_render_includes_jwt_and_jwks_observability_series() {
    let metrics = Metrics::default();
    let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    metrics.record_jwt_validation_failure("issuer_mismatch");
    metrics.record_jwt_algorithm_rejection("RS256");
    metrics.record_jwks_unknown_kid("jwks:example");
    metrics.record_jwks_refresh_started("jwks:example", now);
    metrics.record_jwks_refresh_success("jwks:example", "fresh", 2, now, Some(now));
    metrics.record_jwks_refresh_failure(
        "jwks:example",
        "refresh_failed_retained",
        2,
        now,
        Some(now),
        Some("request_failed"),
    );

    let rendered = metrics.render_prometheus();

    assert!(
        rendered.contains("impulse_jwt_validation_failures_total{reason=\"issuer_mismatch\"} 1")
    );
    assert!(rendered.contains("impulse_jwt_algorithm_rejections_total{algorithm=\"RS256\"} 1"));
    assert!(rendered.contains("impulse_jwks_unknown_kid_total{jwks_source_id=\"jwks:example\"} 1"));
    assert!(
        rendered.contains("impulse_jwks_refresh_success_total{jwks_source_id=\"jwks:example\"} 1")
    );
    assert!(
        rendered.contains("impulse_jwks_refresh_failure_total{jwks_source_id=\"jwks:example\"} 1")
    );
    assert!(rendered.contains(
        "impulse_jwks_state{jwks_source_id=\"jwks:example\",state=\"refresh_failed_retained\"} 1"
    ));
    assert!(rendered.contains("impulse_jwks_active_keys{jwks_source_id=\"jwks:example\"} 2"));
}

#[test]
fn reconcile_jwks_sources_prunes_removed_telemetry_state() {
    let metrics = Metrics::default();
    let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);

    metrics.record_jwks_unknown_kid("jwks:active");
    metrics.record_jwks_unknown_kid("jwks:removed");
    metrics.record_jwks_refresh_success("jwks:active", "fresh", 1, now, Some(now));
    metrics.record_jwks_refresh_failure(
        "jwks:removed",
        "empty_unusable",
        0,
        now,
        None,
        Some("request_failed"),
    );

    metrics.reconcile_jwks_sources(["jwks:active"]);

    let unknown_kid = metrics.snapshot_jwks_unknown_kid_events();
    assert_eq!(unknown_kid, vec![("jwks:active".to_string(), 1)]);

    let jwks_state = metrics.snapshot_jwks_source_state();
    assert_eq!(jwks_state.len(), 1);
    assert_eq!(jwks_state[0].jwks_source_id, "jwks:active");
    assert_eq!(jwks_state[0].state, "fresh");

    let rendered = metrics.render_prometheus();
    assert!(rendered.contains("jwks:active"));
    assert!(!rendered.contains("jwks:removed"));
}

#[test]
fn reconcile_runtime_metric_labels_prunes_removed_reload_identities() {
    let metrics = Metrics::default();
    let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    metrics.record_backend_dns_refresh_success("backend-old", now, 1, false);
    metrics.record_backend_dns_refresh_success("backend-new", now, 1, false);
    metrics.record_request_result(
        "upstream-old",
        Some("backend-old"),
        Some(200),
        RouteOutcome::Success,
        Duration::from_millis(1),
    );
    metrics.record_request_result(
        "upstream-new",
        Some("backend-new"),
        Some(200),
        RouteOutcome::Success,
        Duration::from_millis(1),
    );
    metrics.record_quota_policy_outcome(
        "quota-old",
        QuotaPolicyDecision::Denied,
        QuotaPolicyReason::Allowed,
        "route",
        "in_memory",
    );
    metrics.record_quota_policy_outcome(
        "quota-new",
        QuotaPolicyDecision::Allowed,
        QuotaPolicyReason::Allowed,
        "route",
        "in_memory",
    );
    metrics.replace_upstream_client_cert_expiry([
        ("upstream-old".to_string(), 1_800_000_000),
        ("upstream-new".to_string(), 1_800_000_000),
    ]);

    // Warm the rendered quota-family cache before reconciliation. Policy
    // removal must invalidate this text as well as the underlying snapshot.
    let rendered_before = metrics.render_prometheus();
    assert!(rendered_before.contains("policy=\"quota-old\""));
    assert!(rendered_before.contains("policy=\"quota-new\""));

    metrics.reconcile_runtime_metric_labels(
        ["upstream-new"],
        ["backend-new"],
        ["listener-new"],
        ["quota-new"],
    );

    let backend = metrics.snapshot_backend_metrics();
    assert!(
        backend
            .backend_dns_state
            .iter()
            .all(|(backend, _)| backend != "backend-old")
    );
    let requests = metrics.snapshot_request_result_metrics();
    assert!(
        requests
            .upstream_request_counts
            .iter()
            .all(|(key, _)| key.upstream != "upstream-old")
    );
    let quota = metrics.snapshot_quota_metrics();
    assert!(
        quota
            .quota_policy_outcomes
            .iter()
            .all(|(key, _)| key.policy != "quota-old")
    );
    let rendered_after = metrics.render_prometheus();
    assert!(!rendered_after.contains("policy=\"quota-old\""));
    assert!(rendered_after.contains("policy=\"quota-new\""));
    let secrets = metrics.snapshot_secret_metrics();
    assert!(
        secrets
            .upstream_client_cert_expiry
            .iter()
            .all(|(key, _)| key.upstream != "upstream-old")
    );
}

#[test]
fn prometheus_render_includes_quota_observability_series() {
    let metrics = Metrics::default();
    metrics.record_quota_policy_outcome(
        "tenant-write-quota",
        QuotaPolicyDecision::Denied,
        QuotaPolicyReason::BurstQuotaExhausted,
        "route+tenant+token",
        "redis",
    );
    metrics.record_quota_backend_health("redis", QuotaBackendHealthReason::Available);
    metrics.record_quota_backend_health("redis", QuotaBackendHealthReason::Timeout);

    let rendered = metrics.render_prometheus();

    assert!(rendered.contains(
        "impulse_quota_policy_outcomes_total{policy=\"tenant-write-quota\",decision=\"denied\",reason=\"burst_quota_exhausted\",selector_dimensions=\"route+tenant+token\",backend_mode=\"redis\"} 1"
    ));
    assert!(rendered.contains(
        "impulse_quota_backend_health_total{backend_mode=\"redis\",reason=\"available\"} 1"
    ));
    assert!(rendered.contains(
        "impulse_quota_backend_health_total{backend_mode=\"redis\",reason=\"timeout\"} 1"
    ));
}

#[test]
fn prometheus_render_includes_degraded_quota_backend_modes() {
    let metrics = Metrics::default();
    metrics.record_quota_policy_outcome(
        "tenant-write-quota",
        QuotaPolicyDecision::Allowed,
        QuotaPolicyReason::Allowed,
        "route+tenant+client",
        "redis_local_fallback_backend_timeout",
    );
    metrics.record_quota_backend_health(
        "redis_local_fallback_backend_timeout",
        QuotaBackendHealthReason::Timeout,
    );

    let rendered = metrics.render_prometheus();

    assert!(rendered.contains(
        "impulse_quota_policy_outcomes_total{policy=\"tenant-write-quota\",decision=\"allowed\",reason=\"allowed\",selector_dimensions=\"route+tenant+client\",backend_mode=\"redis_local_fallback_backend_timeout\"} 1"
    ));
    assert!(rendered.contains(
        "impulse_quota_backend_health_total{backend_mode=\"redis_local_fallback_backend_timeout\",reason=\"timeout\"} 1"
    ));
}

#[test]
fn prometheus_render_includes_secret_and_upstream_mtls_series() {
    let metrics = Metrics::default();
    metrics.record_secret_reload("listeners", "success", "cert_reload_applied");
    metrics.record_secret_resolve("file", "success", "resolved");
    metrics.record_secret_resolve("file", "failed", "file_not_found");
    metrics.set_secret_last_success_unixtime("upstreams", 1_700_000_123);
    metrics.record_upstream_tls_failure(
        "payments",
        "10.0.0.5:443",
        "data_plane",
        "client_auth_rejected",
    );
    metrics.replace_upstream_client_cert_expiry([("payments".to_string(), 1_800_000_000)]);
    metrics.record_control_plane_cert_reload("success", "cert_reload_applied");

    let rendered = metrics.render_prometheus();

    assert!(rendered.contains(
        "impulse_secret_reload_total{scope=\"listeners\",result=\"success\",reason=\"cert_reload_applied\"} 1"
    ));
    assert!(rendered.contains(
        "impulse_secret_resolve_total{provider=\"file\",result=\"success\",reason=\"resolved\"} 1"
    ));
    assert!(rendered.contains(
        "impulse_secret_resolve_total{provider=\"file\",result=\"failed\",reason=\"file_not_found\"} 1"
    ));
    assert!(
        rendered.contains("impulse_secret_last_success_unixtime{scope=\"upstreams\"} 1700000123")
    );
    assert!(rendered.contains(
        "impulse_upstream_tls_failure_total{upstream=\"payments\",backend=\"10.0.0.5:443\",phase=\"data_plane\",reason=\"client_auth_rejected\"} 1"
    ));
    assert!(!rendered.contains("impulse_upstream_mtls_handshake_failure_total"));
    assert!(rendered.contains(
        "impulse_upstream_client_certificate_not_after_seconds{upstream=\"payments\"} 1800000000"
    ));
    assert!(rendered.contains(
        "impulse_control_plane_cert_reload_total{result=\"success\",reason=\"cert_reload_applied\"} 1"
    ));
}

#[test]
fn request_result_snapshots_stay_sorted_and_refresh_after_updates() {
    let metrics = Metrics::default();
    metrics.record_request_result(
        "z-upstream",
        Some("backend-z"),
        Some(503),
        RouteOutcome::Failure,
        Duration::from_millis(42),
    );
    metrics.record_request_result(
        "a-upstream",
        Some("backend-a"),
        Some(200),
        RouteOutcome::Success,
        Duration::from_millis(12),
    );

    let first_render = metrics.render_prometheus();
    let a_idx = first_render
        .find("impulse_upstream_requests_total{upstream=\"a-upstream\"")
        .expect("a-upstream series");
    let z_idx = first_render
        .find("impulse_upstream_requests_total{upstream=\"z-upstream\"")
        .expect("z-upstream series");
    assert!(a_idx < z_idx, "request-result series should stay sorted");

    metrics.record_request_result(
        "a-upstream",
        Some("backend-a"),
        Some(200),
        RouteOutcome::Success,
        Duration::from_millis(9),
    );

    let second_render = metrics.render_prometheus();
    assert!(second_render.contains(
        "impulse_upstream_requests_total{upstream=\"a-upstream\",status_class=\"2xx\",outcome=\"success\"} 2"
    ));
    assert!(second_render.contains(
        "impulse_backend_requests_total{upstream=\"a-upstream\",backend=\"backend-a\",status_class=\"2xx\",outcome=\"success\"} 2"
    ));
}

#[test]
fn request_result_snapshot_cache_refreshes_only_after_metric_updates() {
    let metrics = Metrics::default();
    metrics.record_request_result(
        "api",
        Some("backend-a"),
        Some(200),
        RouteOutcome::Success,
        Duration::from_millis(10),
    );

    let first = metrics.snapshot_request_result_metrics();
    let second = metrics.snapshot_request_result_metrics();
    assert_eq!(
        first.upstream_request_counts,
        second.upstream_request_counts
    );
    assert_eq!(first.backend_request_counts, second.backend_request_counts);
    assert_eq!(
        first.upstream_request_latency.len(),
        second.upstream_request_latency.len()
    );
    assert_eq!(
        first.upstream_request_latency[0].0.upstream,
        second.upstream_request_latency[0].0.upstream
    );
    assert_eq!(
        first.upstream_request_latency[0].0.outcome,
        second.upstream_request_latency[0].0.outcome
    );
    assert_eq!(
        first.upstream_request_latency[0].1.count,
        second.upstream_request_latency[0].1.count
    );
    assert_eq!(
        first.upstream_request_latency[0].1.latency_ms_sum,
        second.upstream_request_latency[0].1.latency_ms_sum
    );

    metrics.record_request_result(
        "api",
        Some("backend-a"),
        Some(503),
        RouteOutcome::Failure,
        Duration::from_millis(25),
    );

    let refreshed = metrics.snapshot_request_result_metrics();
    assert_eq!(refreshed.upstream_request_counts.len(), 2);
    assert!(
        refreshed
            .upstream_request_counts
            .iter()
            .any(|(key, count)| {
                key.upstream == "api"
                    && key.status_class == "5xx"
                    && key.outcome == "failure"
                    && *count == 1
            })
    );
}

#[test]
fn prometheus_render_is_stable_across_repeated_cached_family_renders() {
    let metrics = Metrics::default();
    let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);

    metrics.record_quota_policy_outcome(
        "tenant-write-quota",
        QuotaPolicyDecision::Denied,
        QuotaPolicyReason::BurstQuotaExhausted,
        "route+tenant+token",
        "redis",
    );
    metrics.record_quota_backend_health("redis", QuotaBackendHealthReason::Timeout);
    metrics.record_jwt_validation_failure("issuer_mismatch");
    metrics.record_jwks_unknown_kid("jwks:example");
    metrics.record_jwks_refresh_success("jwks:example", "fresh", 2, now, Some(now));
    metrics.record_backend_dns_refresh_success("backend-a", now, 2, false);
    metrics.record_backend_connect(
        "backend-a",
        "origin.internal",
        "127.0.0.1:443".parse().expect("socket address"),
    );
    metrics.record_secret_reload("listeners", "success", "cert_reload_applied");
    metrics.set_secret_last_success_unixtime("upstreams", 1_700_000_123);
    metrics.replace_upstream_client_cert_expiry([("payments".to_string(), 1_800_000_000)]);

    let first = metrics.render_prometheus();
    let second = metrics.render_prometheus();

    assert_eq!(first, second);
}

#[test]
fn cached_metric_family_snapshots_refresh_after_targeted_updates() {
    let metrics = Metrics::default();
    let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);

    metrics.record_quota_policy_outcome(
        "tenant-write-quota",
        QuotaPolicyDecision::Allowed,
        QuotaPolicyReason::Allowed,
        "route+tenant+client",
        "redis",
    );
    let quota_before = metrics.snapshot_quota_metrics();
    assert_eq!(quota_before.quota_policy_outcomes.len(), 1);
    assert!(quota_before.quota_backend_health.is_empty());
    metrics.record_quota_backend_health("redis", QuotaBackendHealthReason::Available);
    let quota_after = metrics.snapshot_quota_metrics();
    assert_eq!(quota_after.quota_policy_outcomes.len(), 1);
    assert_eq!(quota_after.quota_backend_health.len(), 1);
    assert_eq!(quota_after.quota_backend_health[0].1, 1);

    metrics.record_jwt_validation_failure("issuer_mismatch");
    let jwt_before = metrics.snapshot_jwt_jwks_metrics();
    assert_eq!(
        jwt_before.jwt_validation_failures,
        vec![("issuer_mismatch".to_string(), 1)]
    );
    assert!(jwt_before.jwks_unknown_kid_events.is_empty());
    metrics.record_jwks_unknown_kid("jwks:example");
    let jwt_after = metrics.snapshot_jwt_jwks_metrics();
    assert_eq!(
        jwt_after.jwt_validation_failures,
        vec![("issuer_mismatch".to_string(), 1)]
    );
    assert_eq!(
        jwt_after.jwks_unknown_kid_events,
        vec![("jwks:example".to_string(), 1)]
    );

    metrics.record_backend_dns_refresh_success("backend-a", now, 2, false);
    let backend_before = metrics.snapshot_backend_metrics();
    assert_eq!(backend_before.backend_dns_state.len(), 1);
    assert!(backend_before.backend_rotation_state.is_empty());
    metrics.inc_backend_client_rotation("backend-a");
    let backend_after = metrics.snapshot_backend_metrics();
    assert_eq!(backend_after.backend_dns_state.len(), 1);
    assert_eq!(backend_after.backend_rotation_state.len(), 1);
    assert_eq!(backend_after.backend_rotation_state[0].0, "backend-a");
    assert_eq!(backend_after.backend_rotation_state[0].1.rotations, 1);

    metrics.record_secret_reload("listeners", "success", "cert_reload_applied");
    let secret_before = metrics.snapshot_secret_metrics();
    assert_eq!(secret_before.secret_reload_totals.len(), 1);
    assert!(secret_before.secret_last_success_unixtime.is_empty());
    metrics.set_secret_last_success_unixtime("listeners", 1_700_000_123);
    let secret_after = metrics.snapshot_secret_metrics();
    assert_eq!(secret_after.secret_reload_totals.len(), 1);
    assert_eq!(secret_after.secret_last_success_unixtime.len(), 1);
    assert_eq!(
        secret_after.secret_last_success_unixtime[0].0.scope,
        "listeners"
    );
    assert_eq!(
        secret_after.secret_last_success_unixtime[0].1,
        1_700_000_123
    );
}
