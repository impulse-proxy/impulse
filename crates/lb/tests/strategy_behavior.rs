//! Impulse-owned fallback load-balancing strategy tests.

mod common;

use std::time::Duration;

use common::pool;

#[test]
fn least_connections_prefers_the_backend_with_fewer_inflight_requests() {
    let mut pool = pool("least-connections", 3);
    pool.begin_request_for_accounting(0);
    pool.begin_request_for_accounting(0);
    pool.begin_request_for_accounting(1);

    assert_eq!(pool.pick_without_begin(""), Some(2));
}

#[test]
fn latency_aware_prefers_the_backend_with_lower_observed_latency() {
    let mut pool = pool("latency-aware", 2);
    pool.finish_request(0, Duration::from_millis(150), Some(200));
    pool.finish_request(1, Duration::from_millis(20), Some(200));

    assert_eq!(pool.pick_without_begin(""), Some(1));
}

#[test]
fn fallback_strategies_return_no_backend_when_every_backend_is_unhealthy() {
    for strategy in ["least-connections", "latency-aware"] {
        let mut pool = pool(strategy, 2);
        let _ = pool.mark_backend_failure_from_active_check(0);
        let _ = pool.mark_backend_failure_from_active_check(1);

        assert!(pool.pick_without_begin("").is_none());
    }
}
