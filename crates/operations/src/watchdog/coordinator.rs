use std::{
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Instant,
};

use log::warn;

use super::{config::WatchdogRuntimeConfig, time::now_millis};

pub struct WatchdogCoordinator {
    enabled: bool,
    restart_cooldown_ms: u64,
    last_poll_progress_ms: AtomicU64,
    degraded: AtomicBool,
    restart_requested: AtomicBool,
    restart_requested_at_ms: AtomicU64,
    restart_requested_at_instant: Mutex<Option<Instant>>,
    last_restart_at_instant: Mutex<Option<Instant>>,
    expected_workers: AtomicUsize,
    drained_workers: AtomicUsize,
    pub restart_reason: Mutex<String>,
}

impl WatchdogCoordinator {
    pub fn from_runtime_config(config: &WatchdogRuntimeConfig) -> Self {
        let now_ms = now_millis();
        Self {
            enabled: config.enabled,
            restart_cooldown_ms: config.restart_cooldown_ms.max(1),
            last_poll_progress_ms: AtomicU64::new(now_ms),
            degraded: AtomicBool::new(false),
            restart_requested: AtomicBool::new(false),
            restart_requested_at_ms: AtomicU64::new(0),
            restart_requested_at_instant: Mutex::new(None),
            last_restart_at_instant: Mutex::new(None),
            expected_workers: AtomicUsize::new(1),
            drained_workers: AtomicUsize::new(0),
            restart_reason: Mutex::new(String::new()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_expected_workers(&self, workers: usize) {
        self.expected_workers
            .store(workers.max(1), Ordering::Relaxed);
    }

    pub fn mark_poll_progress(&self) {
        self.last_poll_progress_ms
            .store(now_millis(), Ordering::Relaxed);
    }

    pub fn last_poll_progress_ms(&self) -> u64 {
        self.last_poll_progress_ms.load(Ordering::Relaxed)
    }

    pub fn set_degraded(&self, degraded: bool) {
        self.degraded.store(degraded, Ordering::Relaxed);
    }

    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Relaxed)
    }

    pub fn request_restart(&self, reason: &str) -> bool {
        if !self.enabled {
            return false;
        }
        let now_instant = Instant::now();
        if let Some(last_restart_instant) =
            *lock_or_recover(&self.last_restart_at_instant, "last_restart_at_instant")
            && now_instant.duration_since(last_restart_instant).as_millis()
                < self.restart_cooldown_ms as u128
        {
            return false;
        }
        if self
            .restart_requested
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }

        self.restart_requested_at_ms
            .store(now_millis(), Ordering::Relaxed);
        *lock_or_recover(
            &self.restart_requested_at_instant,
            "restart_requested_at_instant",
        ) = Some(now_instant);
        self.drained_workers.store(0, Ordering::Relaxed);
        *lock_or_recover(&self.restart_reason, "restart_reason") = reason.to_string();
        true
    }

    pub fn restart_requested(&self) -> bool {
        self.restart_requested.load(Ordering::Relaxed)
    }

    pub fn restart_reason(&self) -> String {
        lock_or_recover(&self.restart_reason, "restart_reason").clone()
    }

    pub fn restart_requested_at_ms(&self) -> u64 {
        self.restart_requested_at_ms.load(Ordering::Relaxed)
    }

    pub fn restart_requested_elapsed_ms(&self) -> Option<u64> {
        if !self.restart_requested() {
            return None;
        }
        let guard = lock_or_recover(
            &self.restart_requested_at_instant,
            "restart_requested_at_instant",
        );
        let started_at = (*guard)?;
        Some(Instant::now().duration_since(started_at).as_millis() as u64)
    }

    pub fn mark_worker_drained(&self) {
        if !self.restart_requested() {
            return;
        }
        self.drained_workers.fetch_add(1, Ordering::Relaxed);
    }

    pub fn workers_drained(&self) -> bool {
        let expected = self.expected_workers.load(Ordering::Relaxed).max(1);
        self.drained_workers.load(Ordering::Relaxed) >= expected
    }

    pub fn complete_restart_cycle(&self) {
        *lock_or_recover(&self.last_restart_at_instant, "last_restart_at_instant") =
            Some(Instant::now());
        *lock_or_recover(
            &self.restart_requested_at_instant,
            "restart_requested_at_instant",
        ) = None;
        self.restart_requested.store(false, Ordering::Relaxed);
        self.restart_requested_at_ms.store(0, Ordering::Relaxed);
        self.drained_workers.store(0, Ordering::Relaxed);
        self.degraded.store(false, Ordering::Relaxed);
    }
}

fn lock_or_recover<'a, T>(mutex: &'a Mutex<T>, field: &str) -> MutexGuard<'a, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!(
                "WatchdogCoordinator {} mutex poisoned; continuing with recovered inner state",
                field
            );
            poisoned.into_inner()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_watchdog_config() -> WatchdogRuntimeConfig {
        WatchdogRuntimeConfig {
            enabled: true,
            check_interval_ms: 10,
            poll_stall_timeout_ms: 1_000,
            timeout_error_rate_percent: 50,
            min_requests_per_window: 1,
            overload_inflight_percent: 90,
            unhealthy_consecutive_windows: 2,
            drain_grace_ms: 100,
            restart_cooldown_ms: 60_000,
            restart_command: vec!["true".to_string()],
            restart_hook: None,
        }
    }

    #[test]
    fn restart_cycle_transitions_idle_to_pending_then_completes() {
        let watchdog = WatchdogCoordinator::from_runtime_config(&test_watchdog_config());
        watchdog.set_expected_workers(2);

        assert!(!watchdog.restart_requested());
        assert!(!watchdog.is_degraded());
        assert!(!watchdog.workers_drained());

        watchdog.set_degraded(true);
        assert!(watchdog.request_restart("timeout_spike"));
        assert!(watchdog.restart_requested());
        assert_eq!(watchdog.restart_reason(), "timeout_spike");
        assert!(watchdog.restart_requested_at_ms() > 0);
        assert!(watchdog.restart_requested_elapsed_ms().is_some());
        assert!(!watchdog.workers_drained());

        watchdog.mark_worker_drained();
        assert!(!watchdog.workers_drained());
        watchdog.mark_worker_drained();
        assert!(watchdog.workers_drained());

        watchdog.complete_restart_cycle();

        assert!(!watchdog.restart_requested());
        assert_eq!(watchdog.restart_requested_at_ms(), 0);
        assert!(watchdog.restart_requested_elapsed_ms().is_none());
        assert!(!watchdog.is_degraded());
        assert!(!watchdog.workers_drained());
    }

    #[test]
    fn restart_request_is_idempotent_and_cooldown_blocks_immediate_followup() {
        let watchdog = WatchdogCoordinator::from_runtime_config(&test_watchdog_config());

        assert!(watchdog.request_restart("poll_stall"));
        assert!(
            !watchdog.request_restart("timeout_spike"),
            "a pending restart request must not be replaced in place"
        );
        assert_eq!(watchdog.restart_reason(), "poll_stall");

        watchdog.complete_restart_cycle();

        assert!(
            !watchdog.request_restart("timeout_spike"),
            "cooldown should reject an immediate follow-up restart request"
        );
        assert!(!watchdog.restart_requested());
    }

    #[test]
    fn mark_worker_drained_is_ignored_without_pending_restart() {
        let watchdog = WatchdogCoordinator::from_runtime_config(&test_watchdog_config());
        watchdog.set_expected_workers(2);

        watchdog.mark_worker_drained();
        watchdog.mark_worker_drained();

        assert!(
            !watchdog.workers_drained(),
            "worker drain accounting should only advance while a restart is pending"
        );
    }
}
