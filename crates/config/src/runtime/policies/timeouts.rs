use std::time::Duration;

use super::config_invalid;
use crate::{config::Performance, runtime::RuntimeConfigError};

fn require_nonzero_u64(name: &str, value: u64) -> Result<(), RuntimeConfigError> {
    if value == 0 {
        return Err(config_invalid(format!("{name} must be greater than 0")));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTimeoutPolicy {
    pub inflight_acquire_wait: Duration,
    pub backend_request: Duration,
    pub backend_connect: Duration,
    pub backend_body_idle: Duration,
    pub backend_body_total: Duration,
    pub backend_total_request: Duration,
    pub shutdown_drain: Duration,
    pub client_body_idle: Duration,
    pub quic_max_idle: Duration,
}

impl RuntimeTimeoutPolicy {
    pub(crate) fn normalize(performance: &Performance) -> Result<Self, RuntimeConfigError> {
        require_nonzero_u64(
            "performance.backend_timeout_ms",
            performance.backend_timeout_ms,
        )?;
        require_nonzero_u64(
            "performance.backend_connect_timeout_ms",
            performance.backend_connect_timeout_ms,
        )?;
        require_nonzero_u64(
            "performance.backend_body_idle_timeout_ms",
            performance.backend_body_idle_timeout_ms,
        )?;
        require_nonzero_u64(
            "performance.backend_body_total_timeout_ms",
            performance.backend_body_total_timeout_ms,
        )?;
        require_nonzero_u64(
            "performance.backend_total_request_timeout_ms",
            performance.backend_total_request_timeout_ms,
        )?;
        require_nonzero_u64(
            "performance.shutdown_drain_timeout_ms",
            performance.shutdown_drain_timeout_ms,
        )?;
        require_nonzero_u64(
            "performance.client_body_idle_timeout_ms",
            performance.client_body_idle_timeout_ms,
        )?;
        require_nonzero_u64(
            "performance.h2_pool_idle_timeout_ms",
            performance.h2_pool_idle_timeout_ms,
        )?;
        require_nonzero_u64(
            "performance.backend_dns_refresh_interval_ms",
            performance.backend_dns_refresh_interval_ms,
        )?;
        require_nonzero_u64(
            "performance.quic_max_idle_timeout_ms",
            performance.quic_max_idle_timeout_ms,
        )?;

        if performance.backend_connect_timeout_ms > performance.backend_timeout_ms {
            return Err(config_invalid(
                "performance.backend_connect_timeout_ms must be <= backend_timeout_ms",
            ));
        }
        if performance.backend_timeout_ms > performance.backend_body_idle_timeout_ms {
            return Err(config_invalid(
                "performance.backend_timeout_ms must be <= backend_body_idle_timeout_ms",
            ));
        }
        if performance.backend_body_idle_timeout_ms > performance.backend_body_total_timeout_ms {
            return Err(config_invalid(
                "performance.backend_body_idle_timeout_ms must be <= backend_body_total_timeout_ms",
            ));
        }
        if performance.backend_body_total_timeout_ms > performance.backend_total_request_timeout_ms
        {
            return Err(config_invalid(
                "performance.backend_body_total_timeout_ms must be <= backend_total_request_timeout_ms",
            ));
        }

        Ok(Self {
            inflight_acquire_wait: Duration::from_millis(performance.inflight_acquire_wait_ms),
            backend_request: Duration::from_millis(performance.backend_timeout_ms),
            backend_connect: Duration::from_millis(performance.backend_connect_timeout_ms),
            backend_body_idle: Duration::from_millis(performance.backend_body_idle_timeout_ms),
            backend_body_total: Duration::from_millis(performance.backend_body_total_timeout_ms),
            backend_total_request: Duration::from_millis(
                performance.backend_total_request_timeout_ms,
            ),
            shutdown_drain: Duration::from_millis(performance.shutdown_drain_timeout_ms),
            client_body_idle: Duration::from_millis(performance.client_body_idle_timeout_ms),
            quic_max_idle: Duration::from_millis(performance.quic_max_idle_timeout_ms),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_performance() -> Performance {
        Performance::default()
    }

    #[test]
    fn runtime_timeout_policy_normalizes_raw_millisecond_fields_into_durations() {
        let mut performance = valid_performance();
        performance.inflight_acquire_wait_ms = 7;
        performance.backend_timeout_ms = 1_000;
        performance.backend_connect_timeout_ms = 250;
        performance.backend_body_idle_timeout_ms = 2_000;
        performance.backend_body_total_timeout_ms = 3_000;
        performance.backend_total_request_timeout_ms = 4_000;
        performance.shutdown_drain_timeout_ms = 5_000;
        performance.client_body_idle_timeout_ms = 6_000;
        performance.quic_max_idle_timeout_ms = 9_000;

        let policy = RuntimeTimeoutPolicy::normalize(&performance).expect("timeout policy");

        assert_eq!(policy.inflight_acquire_wait, Duration::from_millis(7));
        assert_eq!(policy.backend_request, Duration::from_millis(1_000));
        assert_eq!(policy.backend_connect, Duration::from_millis(250));
        assert_eq!(policy.backend_body_idle, Duration::from_millis(2_000));
        assert_eq!(policy.backend_body_total, Duration::from_millis(3_000));
        assert_eq!(policy.backend_total_request, Duration::from_millis(4_000));
        assert_eq!(policy.shutdown_drain, Duration::from_millis(5_000));
        assert_eq!(policy.client_body_idle, Duration::from_millis(6_000));
        assert_eq!(policy.quic_max_idle, Duration::from_millis(9_000));
    }

    #[test]
    fn runtime_timeout_policy_allows_zero_inflight_micro_wait() {
        let mut performance = valid_performance();
        performance.inflight_acquire_wait_ms = 0;

        let policy = RuntimeTimeoutPolicy::normalize(&performance).expect("timeout policy");

        assert_eq!(policy.inflight_acquire_wait, Duration::ZERO);
    }

    #[test]
    fn runtime_timeout_policy_rejects_zero_for_required_timeout_fields() {
        fn zero_backend_timeout(performance: &mut Performance) {
            performance.backend_timeout_ms = 0;
        }
        fn zero_backend_connect_timeout(performance: &mut Performance) {
            performance.backend_connect_timeout_ms = 0;
        }
        fn zero_backend_body_idle_timeout(performance: &mut Performance) {
            performance.backend_body_idle_timeout_ms = 0;
        }
        fn zero_backend_body_total_timeout(performance: &mut Performance) {
            performance.backend_body_total_timeout_ms = 0;
        }
        fn zero_backend_total_request_timeout(performance: &mut Performance) {
            performance.backend_total_request_timeout_ms = 0;
        }
        fn zero_shutdown_drain_timeout(performance: &mut Performance) {
            performance.shutdown_drain_timeout_ms = 0;
        }
        fn zero_client_body_idle_timeout(performance: &mut Performance) {
            performance.client_body_idle_timeout_ms = 0;
        }
        fn zero_h2_pool_idle_timeout(performance: &mut Performance) {
            performance.h2_pool_idle_timeout_ms = 0;
        }
        fn zero_backend_dns_refresh_interval(performance: &mut Performance) {
            performance.backend_dns_refresh_interval_ms = 0;
        }
        fn zero_quic_max_idle_timeout(performance: &mut Performance) {
            performance.quic_max_idle_timeout_ms = 0;
        }

        let cases = [
            (
                "performance.backend_timeout_ms must be greater than 0",
                zero_backend_timeout as fn(&mut Performance),
            ),
            (
                "performance.backend_connect_timeout_ms must be greater than 0",
                zero_backend_connect_timeout as fn(&mut Performance),
            ),
            (
                "performance.backend_body_idle_timeout_ms must be greater than 0",
                zero_backend_body_idle_timeout as fn(&mut Performance),
            ),
            (
                "performance.backend_body_total_timeout_ms must be greater than 0",
                zero_backend_body_total_timeout as fn(&mut Performance),
            ),
            (
                "performance.backend_total_request_timeout_ms must be greater than 0",
                zero_backend_total_request_timeout as fn(&mut Performance),
            ),
            (
                "performance.shutdown_drain_timeout_ms must be greater than 0",
                zero_shutdown_drain_timeout as fn(&mut Performance),
            ),
            (
                "performance.client_body_idle_timeout_ms must be greater than 0",
                zero_client_body_idle_timeout as fn(&mut Performance),
            ),
            (
                "performance.h2_pool_idle_timeout_ms must be greater than 0",
                zero_h2_pool_idle_timeout as fn(&mut Performance),
            ),
            (
                "performance.backend_dns_refresh_interval_ms must be greater than 0",
                zero_backend_dns_refresh_interval as fn(&mut Performance),
            ),
            (
                "performance.quic_max_idle_timeout_ms must be greater than 0",
                zero_quic_max_idle_timeout as fn(&mut Performance),
            ),
        ];

        for (expected, mutate) in cases {
            let mut performance = valid_performance();
            mutate(&mut performance);

            let err = RuntimeTimeoutPolicy::normalize(&performance).expect_err(expected);

            assert_eq!(err.category(), "config_invalid");
            assert_eq!(err.to_string(), format!("config_invalid: {expected}"));
        }
    }

    #[test]
    fn runtime_timeout_policy_rejects_connect_timeout_longer_than_backend_request_timeout() {
        let mut performance = valid_performance();
        performance.backend_timeout_ms = 999;
        performance.backend_connect_timeout_ms = 1_000;

        let err =
            RuntimeTimeoutPolicy::normalize(&performance).expect_err("connect ordering must fail");

        assert_eq!(err.category(), "config_invalid");
        assert_eq!(
            err.to_string(),
            "config_invalid: performance.backend_connect_timeout_ms must be <= backend_timeout_ms"
        );
    }

    #[test]
    fn runtime_timeout_policy_rejects_backend_request_timeout_longer_than_body_idle_timeout() {
        let mut performance = valid_performance();
        performance.backend_timeout_ms = 2_001;
        performance.backend_body_idle_timeout_ms = 2_000;

        let err = RuntimeTimeoutPolicy::normalize(&performance)
            .expect_err("backend request/body idle ordering must fail");

        assert_eq!(err.category(), "config_invalid");
        assert_eq!(
            err.to_string(),
            "config_invalid: performance.backend_timeout_ms must be <= backend_body_idle_timeout_ms"
        );
    }

    #[test]
    fn runtime_timeout_policy_rejects_body_idle_timeout_longer_than_body_total_timeout() {
        let mut performance = valid_performance();
        performance.backend_body_idle_timeout_ms = 3_001;
        performance.backend_body_total_timeout_ms = 3_000;

        let err = RuntimeTimeoutPolicy::normalize(&performance)
            .expect_err("body idle/body total ordering must fail");

        assert_eq!(err.category(), "config_invalid");
        assert_eq!(
            err.to_string(),
            "config_invalid: performance.backend_body_idle_timeout_ms must be <= backend_body_total_timeout_ms"
        );
    }

    #[test]
    fn runtime_timeout_policy_rejects_body_total_timeout_longer_than_backend_total_request_timeout()
    {
        let mut performance = valid_performance();
        performance.backend_body_total_timeout_ms = 4_001;
        performance.backend_total_request_timeout_ms = 4_000;

        let err = RuntimeTimeoutPolicy::normalize(&performance)
            .expect_err("body total/backend total request ordering must fail");

        assert_eq!(err.category(), "config_invalid");
        assert_eq!(
            err.to_string(),
            "config_invalid: performance.backend_body_total_timeout_ms must be <= backend_total_request_timeout_ms"
        );
    }

    #[test]
    fn runtime_timeout_policy_normalizes_shutdown_drain_and_quic_idle_timeouts() {
        let mut performance = valid_performance();
        performance.shutdown_drain_timeout_ms = 12_345;
        performance.quic_max_idle_timeout_ms = 54_321;

        let policy = RuntimeTimeoutPolicy::normalize(&performance).expect("timeout policy");

        assert_eq!(policy.shutdown_drain, Duration::from_millis(12_345));
        assert_eq!(policy.quic_max_idle, Duration::from_millis(54_321));
    }
}
