use std::panic::{AssertUnwindSafe, catch_unwind};

use impulse_operations::watchdog::{WatchdogCoordinator, WatchdogRuntimeConfig};

fn watchdog_config() -> WatchdogRuntimeConfig {
    WatchdogRuntimeConfig {
        enabled: true,
        check_interval_ms: 1000,
        poll_stall_timeout_ms: 5000,
        timeout_error_rate_percent: 60,
        min_requests_per_window: 20,
        overload_inflight_percent: 90,
        unhealthy_consecutive_windows: 3,
        drain_grace_ms: 5_000,
        restart_cooldown_ms: 60_000,
        restart_command: Vec::new(),
        restart_hook: None,
    }
}

#[test]
fn restart_request_respects_single_pending_cycle() {
    let watchdog = WatchdogCoordinator::from_runtime_config(&watchdog_config());
    assert!(watchdog.request_restart("overload"));
    assert!(!watchdog.request_restart("stall"));
}

#[test]
fn worker_drain_tracking_uses_expected_worker_count() {
    let watchdog = WatchdogCoordinator::from_runtime_config(&watchdog_config());
    watchdog.set_expected_workers(2);
    assert!(watchdog.request_restart("stall"));
    watchdog.mark_worker_drained();
    assert!(!watchdog.workers_drained());
    watchdog.mark_worker_drained();
    assert!(watchdog.workers_drained());
}

#[test]
fn restart_cooldown_blocks_immediate_retrigger_after_cycle() {
    let watchdog = WatchdogCoordinator::from_runtime_config(&watchdog_config());
    assert!(watchdog.request_restart("overload"));
    watchdog.complete_restart_cycle();
    assert!(!watchdog.request_restart("stall"));
}

#[test]
fn poisoned_restart_reason_mutex_preserves_reason_text() {
    let watchdog = WatchdogCoordinator::from_runtime_config(&watchdog_config());

    let _ = catch_unwind(AssertUnwindSafe(|| {
        let mut reason = watchdog.restart_reason.lock().expect("lock");
        *reason = "poisoned_reason".to_string();
        panic!("poison restart reason mutex");
    }));

    assert_eq!(watchdog.restart_reason(), "poisoned_reason");
}
