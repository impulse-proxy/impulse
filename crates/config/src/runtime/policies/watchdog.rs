use std::{path::Path, time::Duration};

use super::config_invalid;
use crate::{config::Resilience, runtime::RuntimeConfigError};

fn require_nonzero_u64(name: &str, value: u64) -> Result<(), RuntimeConfigError> {
    if value == 0 {
        return Err(config_invalid(format!("{name} must be greater than 0")));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeWatchdogPolicy {
    pub enabled: bool,
    pub check_interval: Duration,
    pub poll_stall_timeout: Duration,
    pub timeout_error_rate_percent: u8,
    pub min_requests_per_window: u64,
    pub overload_inflight_percent: u8,
    pub unhealthy_consecutive_windows: u32,
    pub drain_grace: Duration,
    pub restart_cooldown: Duration,
    pub restart_command: Vec<String>,
}

pub(crate) fn normalize_watchdog_policy(
    resilience: &Resilience,
) -> Result<RuntimeWatchdogPolicy, RuntimeConfigError> {
    require_nonzero_u64(
        "resilience.watchdog.check_interval_ms",
        resilience.watchdog.check_interval_ms,
    )?;
    require_nonzero_u64(
        "resilience.watchdog.poll_stall_timeout_ms",
        resilience.watchdog.poll_stall_timeout_ms,
    )?;
    if resilience.watchdog.timeout_error_rate_percent > 100 {
        return Err(config_invalid(
            "resilience.watchdog.timeout_error_rate_percent must be <= 100",
        ));
    }
    require_nonzero_u64(
        "resilience.watchdog.min_requests_per_window",
        resilience.watchdog.min_requests_per_window,
    )?;
    if resilience.watchdog.overload_inflight_percent > 100 {
        return Err(config_invalid(
            "resilience.watchdog.overload_inflight_percent must be <= 100",
        ));
    }
    if resilience.watchdog.unhealthy_consecutive_windows == 0 {
        return Err(config_invalid(
            "resilience.watchdog.unhealthy_consecutive_windows must be greater than 0",
        ));
    }
    require_nonzero_u64(
        "resilience.watchdog.drain_grace_ms",
        resilience.watchdog.drain_grace_ms,
    )?;
    require_nonzero_u64(
        "resilience.watchdog.restart_cooldown_ms",
        resilience.watchdog.restart_cooldown_ms,
    )?;
    if !resilience.watchdog.restart_command.is_empty()
        && resilience.watchdog.restart_command[0].trim().is_empty()
    {
        return Err(config_invalid(
            "resilience.watchdog.restart_command[0] must be a non-empty executable path",
        ));
    }
    if !resilience.watchdog.restart_command.is_empty()
        && !Path::new(resilience.watchdog.restart_command[0].trim()).is_absolute()
    {
        return Err(config_invalid(
            "resilience.watchdog.restart_command[0] must be an absolute executable path",
        ));
    }
    let mut restart_command = resilience.watchdog.restart_command.clone();
    if let Some(program) = restart_command.first_mut() {
        *program = program.trim().to_string();
    }

    Ok(RuntimeWatchdogPolicy {
        enabled: resilience.watchdog.enabled,
        check_interval: Duration::from_millis(resilience.watchdog.check_interval_ms),
        poll_stall_timeout: Duration::from_millis(resilience.watchdog.poll_stall_timeout_ms),
        timeout_error_rate_percent: resilience.watchdog.timeout_error_rate_percent,
        min_requests_per_window: resilience.watchdog.min_requests_per_window,
        overload_inflight_percent: resilience.watchdog.overload_inflight_percent,
        unhealthy_consecutive_windows: resilience.watchdog.unhealthy_consecutive_windows,
        drain_grace: Duration::from_millis(resilience.watchdog.drain_grace_ms),
        restart_cooldown: Duration::from_millis(resilience.watchdog.restart_cooldown_ms),
        restart_command,
    })
}
