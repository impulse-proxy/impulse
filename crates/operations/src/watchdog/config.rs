//! Normalized watchdog policy used by operational coordination.

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
