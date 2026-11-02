//! Normalized watchdog policy used by operational coordination.

use impulse_config::{config::Watchdog as WatchdogConfig, runtime::RuntimeWatchdogPolicy};

#[derive(Debug, Clone)]
pub struct WatchdogRuntimeConfig {
    pub enabled: bool,
    pub check_interval_ms: u64,
    pub poll_stall_timeout_ms: u64,
    pub timeout_error_rate_percent: u8,
    pub min_requests_per_window: u64,
    pub overload_inflight_percent: u8,
    pub unhealthy_consecutive_windows: u32,
    pub drain_grace_ms: u64,
    pub restart_cooldown_ms: u64,
    pub restart_command: Vec<String>,
    pub restart_hook: Option<String>,
}

impl From<&WatchdogConfig> for WatchdogRuntimeConfig {
    fn from(value: &WatchdogConfig) -> Self {
        Self {
            enabled: value.enabled,
            check_interval_ms: value.check_interval_ms.max(1),
            poll_stall_timeout_ms: value.poll_stall_timeout_ms.max(1),
            timeout_error_rate_percent: value.timeout_error_rate_percent.min(100),
            min_requests_per_window: value.min_requests_per_window.max(1),
            overload_inflight_percent: value.overload_inflight_percent.min(100),
            unhealthy_consecutive_windows: value.unhealthy_consecutive_windows.max(1),
            drain_grace_ms: value.drain_grace_ms.max(1),
            restart_cooldown_ms: value.restart_cooldown_ms.max(1),
            restart_command: value.restart_command.clone(),
            restart_hook: value.restart_hook.clone(),
        }
    }
}

impl From<&RuntimeWatchdogPolicy> for WatchdogRuntimeConfig {
    fn from(value: &RuntimeWatchdogPolicy) -> Self {
        Self {
            enabled: value.enabled,
            check_interval_ms: value
                .check_interval
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
            poll_stall_timeout_ms: value
                .poll_stall_timeout
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
            timeout_error_rate_percent: value.timeout_error_rate_percent,
            min_requests_per_window: value.min_requests_per_window,
            overload_inflight_percent: value.overload_inflight_percent,
            unhealthy_consecutive_windows: value.unhealthy_consecutive_windows,
            drain_grace_ms: value.drain_grace.as_millis().try_into().unwrap_or(u64::MAX),
            restart_cooldown_ms: value
                .restart_cooldown
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
            restart_command: value.restart_command.clone(),
            restart_hook: None,
        }
    }
}
