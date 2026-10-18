//! Impulse-owned fallback load-balancing strategy tests.

mod common;

use common::pool;

#[test]
fn fallback_strategies_return_no_backend_when_every_backend_is_unhealthy() {
    for strategy in ["least-connections", "latency-aware"] {
        let mut pool = pool(strategy, 2);
        let _ = pool.mark_backend_failure_from_active_check(0);
        let _ = pool.mark_backend_failure_from_active_check(1);

        assert!(pool.pick_without_begin("").is_none());
    }
}
