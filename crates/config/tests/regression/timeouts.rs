//! Timeout / transport-knob normalization and validation.

use std::time::Duration;

use crate::common::{
    assert_config_error_contains, primary_listener_runtime_config, runtime_config, sample_config,
    sample_runtime_config_err_with, sample_runtime_config_with,
};

#[test]
fn runtime_config_normalizes_timeout_and_transport_knobs_into_runtime_policies() {
    let runtime = sample_runtime_config_with(|config| {
        config.performance.backend_timeout_ms = 2_500;
        config.performance.backend_connect_timeout_ms = 400;
        config.performance.backend_body_idle_timeout_ms = 3_500;
        config.performance.backend_body_total_timeout_ms = 4_500;
        config.performance.backend_total_request_timeout_ms = 5_500;
        config.performance.h2_pool_idle_timeout_ms = 91_000;
        config.performance.max_active_connections = 1234;
        config.performance.max_request_body_bytes = 8_000;
        config.performance.request_buffer_global_cap_bytes = 9_999;
        config.resilience.route_queue.shed_retry_after_seconds = 17;
    });
    let policies = &runtime.policies;

    assert_eq!(
        policies.timeouts.backend_request,
        Duration::from_millis(2_500)
    );
    assert_eq!(
        policies.timeouts.backend_connect,
        Duration::from_millis(400)
    );
    assert_eq!(
        policies.timeouts.h2_pool_idle,
        Duration::from_millis(91_000)
    );
    assert_eq!(policies.transport.max_active_connections, 1234);
    assert_eq!(policies.transport.request_buffer_global_cap_bytes, 9_999);
    assert_eq!(policies.admission.route_queue.shed_retry_after_seconds, 17);
}

#[test]
fn runtime_config_keeps_listener_and_runtime_policy_views_in_sync_for_defaults() {
    let config = sample_config();
    let runtime = runtime_config(&config);
    let listener = primary_listener_runtime_config(&runtime);

    assert_eq!(
        runtime.policies.timeouts.backend_request,
        Duration::from_millis(config.performance.backend_timeout_ms)
    );
    assert_eq!(
        runtime.policies.timeouts.quic_max_idle,
        Duration::from_millis(config.performance.quic_max_idle_timeout_ms)
    );
    assert_eq!(
        runtime.policies.transport.connection_limits.global_inflight,
        config.performance.global_inflight_limit
    );
    assert_eq!(
        runtime.policies.transport.quic_initial_max_data,
        config.performance.quic_initial_max_data
    );
    assert_eq!(
        runtime.policies.admission.watchdog.check_interval,
        Duration::from_millis(config.resilience.watchdog.check_interval_ms)
    );
    assert_eq!(listener.policies.timeouts, runtime.policies.timeouts);
    assert_eq!(listener.policies.transport, runtime.policies.transport);
}

#[test]
fn runtime_config_rejects_timeout_ordering_that_breaks_runtime_contract() {
    let err = sample_runtime_config_err_with(|config| {
        config.performance.backend_connect_timeout_ms = 2_000;
        config.performance.backend_timeout_ms = 1_000;
    });
    assert_config_error_contains(
        &err,
        "config_invalid",
        "backend_connect_timeout_ms must be <= backend_timeout_ms",
    );
}
