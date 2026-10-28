use std::{ffi::OsString, path::Path, sync::atomic::Ordering, time::Duration};

use log::{info, warn};

use crate::watchdog::{state::WatchdogServiceState, time::now_millis};

pub(crate) fn watchdog_restart_env(
    path: Option<OsString>,
    restart_reason: &str,
) -> Vec<(OsString, OsString)> {
    let mut env_vars = Vec::with_capacity(2);
    if let Some(path_value) = path {
        env_vars.push((OsString::from("PATH"), path_value));
    }
    env_vars.push((
        OsString::from("IMPULSE_WATCHDOG_REASON"),
        OsString::from(restart_reason),
    ));
    env_vars
}

fn watchdog_restart_program(restart_command: &[String]) -> Option<String> {
    let program = restart_command.first()?.trim();
    if program.is_empty() || !Path::new(program).is_absolute() {
        return None;
    }
    Some(program.to_string())
}

pub(crate) async fn run_watchdog_service(state: WatchdogServiceState) {
    let watchdog_config = state.config;
    let metrics = state.metrics;
    let resilience = state.resilience;
    let watchdog = state.watchdog;

    info!(
        "Watchdog enabled: check_interval_ms={} poll_stall_timeout_ms={} timeout_error_rate_percent={} overload_inflight_percent={} unhealthy_windows={} drain_grace_ms={} restart_cooldown_ms={}",
        watchdog_config.check_interval_ms,
        watchdog_config.poll_stall_timeout_ms,
        watchdog_config.timeout_error_rate_percent,
        watchdog_config.overload_inflight_percent,
        watchdog_config.unhealthy_consecutive_windows,
        watchdog_config.drain_grace_ms,
        watchdog_config.restart_cooldown_ms,
    );

    let mut interval =
        tokio::time::interval(Duration::from_millis(watchdog_config.check_interval_ms));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let restart_program = watchdog_restart_program(&watchdog_config.restart_command);
    let has_restart_command = restart_program.is_some();
    if !watchdog_config.restart_command.is_empty() && !has_restart_command {
        log::error!(
            "Watchdog restart_command[0] must be an absolute executable path; refusing to execute relative restart command"
        );
    }
    if watchdog_config
        .restart_hook
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
    {
        warn!(
            "Watchdog restart_hook is deprecated and ignored; configure resilience.watchdog.restart_command instead"
        );
    }

    let mut previous_requests = metrics.requests_total.load(Ordering::Relaxed);
    let mut previous_timeouts = metrics.backend_timeouts.load(Ordering::Relaxed);
    let mut degraded_windows = 0u32;

    loop {
        interval.tick().await;
        let now = now_millis();
        let stalled = now.saturating_sub(watchdog.last_poll_progress_ms())
            > watchdog_config.poll_stall_timeout_ms;

        let current_requests = metrics.requests_total.load(Ordering::Relaxed);
        let current_timeouts = metrics.backend_timeouts.load(Ordering::Relaxed);
        let request_delta = current_requests.saturating_sub(previous_requests);
        let timeout_delta = current_timeouts.saturating_sub(previous_timeouts);
        previous_requests = current_requests;
        previous_timeouts = current_timeouts;

        let timeout_rate_percent = timeout_delta
            .saturating_mul(100)
            .checked_div(request_delta)
            .unwrap_or(0);

        let timeout_pressure = request_delta >= watchdog_config.min_requests_per_window
            && timeout_rate_percent >= watchdog_config.timeout_error_rate_percent as u64;
        let overload_pressure = resilience.adaptive_admission.inflight_percent()
            >= watchdog_config.overload_inflight_percent;

        if stalled || timeout_pressure || overload_pressure {
            degraded_windows = degraded_windows.saturating_add(1);
            watchdog.set_degraded(true);
            metrics
                .runtime_observations()
                .inc_watchdog_degraded_window();
        } else {
            degraded_windows = 0;
            watchdog.set_degraded(false);
        }

        if degraded_windows >= watchdog_config.unhealthy_consecutive_windows {
            if !has_restart_command {
                warn!(
                    "Watchdog detected unhealthy runtime state, but restart_command is not configured"
                );
                degraded_windows = 0;
                continue;
            }
            let mut reasons = Vec::new();
            if stalled {
                reasons.push("poll_stall");
            }
            if timeout_pressure {
                reasons.push("timeout_spike");
            }
            if overload_pressure {
                reasons.push("inflight_overload");
            }
            let reason = reasons.join("+");
            if watchdog.request_restart(&reason) {
                metrics
                    .runtime_observations()
                    .inc_watchdog_restart_request();
                warn!("Watchdog requested safe restart: {}", reason);
            }
            degraded_windows = 0;
        }

        if !watchdog.restart_requested() {
            continue;
        }

        let grace_elapsed = watchdog
            .restart_requested_elapsed_ms()
            .is_some_and(|elapsed| elapsed >= watchdog_config.drain_grace_ms);
        if !watchdog.workers_drained() && !grace_elapsed {
            continue;
        }

        let restart_reason = watchdog.restart_reason();
        if watchdog.workers_drained() {
            info!(
                "Watchdog safe restart condition reached (all workers drained): {}",
                restart_reason
            );
        } else {
            warn!(
                "Watchdog restart drain grace elapsed; executing hook without full drain: {}",
                restart_reason
            );
        }

        let program = restart_program.as_deref().unwrap_or_default();
        let args: Vec<&str> = watchdog_config
            .restart_command
            .iter()
            .skip(1)
            .map(String::as_str)
            .collect();
        let restart_env = watchdog_restart_env(std::env::var_os("PATH"), &restart_reason);
        let mut command = tokio::process::Command::new(program);
        command.args(args).env_clear();
        for (key, value) in restart_env {
            command.env(key, value);
        }
        let status = command.status().await;
        match status {
            Ok(status) => {
                metrics.runtime_observations().inc_watchdog_restart_hook();
                let exit_status = status
                    .code()
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "signal".to_string());
                if status.success() {
                    info!(
                        "Watchdog restart hook exited successfully with status {}",
                        exit_status
                    );
                    watchdog.complete_restart_cycle();
                } else {
                    log::error!(
                        "Watchdog restart hook exited unsuccessfully with status {}; keeping restart pending",
                        exit_status
                    );
                }
            }
            Err(err) => {
                log::error!(
                    "Watchdog restart hook execution failed: {}; keeping restart pending",
                    err
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, atomic::Ordering},
        time::Duration,
    };

    use impulse_config::config::Resilience as ResilienceConfig;

    use super::*;
    use crate::{
        Metrics, resilience::runtime::RuntimeResilience, watchdog::coordinator::WatchdogCoordinator,
    };

    fn test_watchdog_config() -> crate::watchdog::config::WatchdogRuntimeConfig {
        crate::watchdog::config::WatchdogRuntimeConfig {
            enabled: true,
            check_interval_ms: 5,
            poll_stall_timeout_ms: 60_000,
            timeout_error_rate_percent: 50,
            min_requests_per_window: 1,
            overload_inflight_percent: 100,
            unhealthy_consecutive_windows: 2,
            drain_grace_ms: 60_000,
            restart_cooldown_ms: 1,
            restart_command: vec!["/bin/true".to_string()],
            restart_hook: None,
        }
    }

    #[test]
    fn watchdog_restart_program_requires_absolute_path() {
        assert_eq!(
            watchdog_restart_program(&["/bin/true".to_string(), "--flag".to_string()]),
            Some("/bin/true".to_string())
        );
        assert_eq!(watchdog_restart_program(&["true".to_string()]), None);
        assert_eq!(watchdog_restart_program(&["  ".to_string()]), None);
    }

    fn test_service_state(
        config: crate::watchdog::config::WatchdogRuntimeConfig,
    ) -> (
        WatchdogServiceState,
        Arc<Metrics>,
        Arc<RuntimeResilience>,
        Arc<WatchdogCoordinator>,
    ) {
        let metrics = Arc::new(Metrics::default());
        let resilience = Arc::new(RuntimeResilience::from_config(
            &ResilienceConfig::default(),
            1,
        ));
        let watchdog = Arc::new(WatchdogCoordinator::from_runtime_config(&config));
        (
            WatchdogServiceState {
                config,
                metrics: Arc::clone(&metrics),
                resilience: Arc::clone(&resilience),
                watchdog: Arc::clone(&watchdog),
            },
            metrics,
            resilience,
            watchdog,
        )
    }

    async fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool, context: &str) {
        let start = tokio::time::Instant::now();
        while start.elapsed() < timeout {
            if predicate() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("timed out waiting for {context}");
    }

    #[tokio::test]
    async fn watchdog_service_requests_restart_after_consecutive_timeout_windows() {
        let (state, metrics, _resilience, watchdog) = test_service_state(test_watchdog_config());

        let task = tokio::spawn(run_watchdog_service(state));
        tokio::task::yield_now().await;

        metrics.requests_total.store(10, Ordering::Relaxed);
        metrics.backend_timeouts.store(6, Ordering::Relaxed);
        wait_until(
            Duration::from_secs(3),
            || watchdog.is_degraded(),
            "first degraded watchdog window",
        )
        .await;
        assert!(!watchdog.restart_requested());

        metrics.requests_total.store(20, Ordering::Relaxed);
        metrics.backend_timeouts.store(12, Ordering::Relaxed);
        wait_until(
            Duration::from_secs(3),
            || watchdog.restart_requested(),
            "watchdog restart request",
        )
        .await;

        assert_eq!(watchdog.restart_reason(), "timeout_spike");
        assert_eq!(metrics.watchdog_degraded_windows.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.watchdog_restart_requests.load(Ordering::Relaxed), 1);

        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn watchdog_service_resets_degraded_window_progression_after_recovery() {
        let (state, metrics, _resilience, watchdog) = test_service_state(test_watchdog_config());

        let task = tokio::spawn(run_watchdog_service(state));
        tokio::task::yield_now().await;

        metrics.requests_total.store(10, Ordering::Relaxed);
        metrics.backend_timeouts.store(6, Ordering::Relaxed);
        wait_until(
            Duration::from_secs(3),
            || watchdog.is_degraded(),
            "initial degraded watchdog window",
        )
        .await;
        assert_eq!(metrics.watchdog_degraded_windows.load(Ordering::Relaxed), 1);

        metrics.requests_total.store(10, Ordering::Relaxed);
        metrics.backend_timeouts.store(6, Ordering::Relaxed);
        wait_until(
            Duration::from_secs(3),
            || !watchdog.is_degraded(),
            "watchdog recovery window",
        )
        .await;
        assert!(!watchdog.restart_requested());

        metrics.requests_total.store(20, Ordering::Relaxed);
        metrics.backend_timeouts.store(12, Ordering::Relaxed);
        wait_until(
            Duration::from_secs(3),
            || metrics.watchdog_degraded_windows.load(Ordering::Relaxed) >= 2,
            "post-recovery degraded watchdog window",
        )
        .await;

        assert!(
            !watchdog.restart_requested(),
            "a recovered healthy window should reset degraded progression before the next failure window"
        );
        assert_eq!(metrics.watchdog_degraded_windows.load(Ordering::Relaxed), 2);

        task.abort();
        let _ = task.await;
    }
}
