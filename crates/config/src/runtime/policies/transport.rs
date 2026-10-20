use std::time::Duration;

use super::{RuntimeBackendDnsPolicy, config_invalid};
use crate::{config::Performance, runtime::RuntimeConfigError};

fn require_nonzero_u64(name: &str, value: u64) -> Result<(), RuntimeConfigError> {
    if value == 0 {
        return Err(config_invalid(format!("{name} must be greater than 0")));
    }
    Ok(())
}

fn require_nonzero_usize(name: &str, value: usize) -> Result<(), RuntimeConfigError> {
    if value == 0 {
        return Err(config_invalid(format!("{name} must be greater than 0")));
    }
    Ok(())
}

fn require_nonzero_u32(name: &str, value: u32) -> Result<(), RuntimeConfigError> {
    if value == 0 {
        return Err(config_invalid(format!("{name} must be greater than 0")));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTransportPolicy {
    pub worker_threads: usize,
    pub control_plane_threads: usize,
    pub packet_shards_per_worker: usize,
    pub packet_shard_queue_capacity: usize,
    pub packet_shard_queue_max_bytes: usize,
    pub reuseport: bool,
    pub pin_workers: bool,
    pub udp_recv_buffer_bytes: usize,
    pub udp_send_buffer_bytes: usize,
    pub new_connections_per_sec: u32,
    pub new_connections_burst: u32,
    pub quic_initial_max_data: u64,
    pub quic_initial_max_stream_data: u64,
    pub quic_initial_max_streams_bidi: u64,
    pub quic_initial_max_streams_uni: u64,
    pub max_response_body_bytes: usize,
    pub max_request_body_bytes: usize,
    pub request_buffer_global_cap_bytes: usize,
    pub unknown_length_response_prebuffer_bytes: usize,
    pub connection_limits: RuntimeConnectionLimits,
    pub backend_connections: RuntimeBackendConnectionPolicy,
    pub backend_dns: RuntimeBackendDnsPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConnectionLimits {
    pub global_inflight: usize,
    pub per_upstream_inflight: usize,
    pub per_backend: usize,
    pub backend_pool_max_inflight: usize,
    pub max_active_connections: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBackendConnectionPolicy {
    pub max_inflight: usize,
    pub max_idle_per_backend: usize,
    pub pool_idle_timeout: Duration,
    pub connect_timeout: Duration,
    pub execution_timeout: Duration,
}

impl RuntimeTransportPolicy {
    pub(crate) fn normalize(performance: &Performance) -> Result<Self, RuntimeConfigError> {
        require_nonzero_usize("performance.worker_threads", performance.worker_threads)?;
        if performance.worker_threads > 1024 {
            return Err(config_invalid(format!(
                "performance.worker_threads={} exceeds the maximum of 1024",
                performance.worker_threads
            )));
        }
        require_nonzero_usize(
            "performance.control_plane_threads",
            performance.control_plane_threads,
        )?;
        if performance.control_plane_threads > 1024 {
            return Err(config_invalid(format!(
                "performance.control_plane_threads={} exceeds the maximum of 1024",
                performance.control_plane_threads
            )));
        }
        require_nonzero_usize(
            "performance.packet_shards_per_worker",
            performance.packet_shards_per_worker,
        )?;
        if performance.packet_shards_per_worker > 256 {
            return Err(config_invalid(format!(
                "performance.packet_shards_per_worker={} exceeds the maximum of 256",
                performance.packet_shards_per_worker
            )));
        }
        require_nonzero_usize(
            "performance.packet_shard_queue_capacity",
            performance.packet_shard_queue_capacity,
        )?;
        require_nonzero_usize(
            "performance.packet_shard_queue_max_bytes",
            performance.packet_shard_queue_max_bytes,
        )?;
        if performance.worker_threads > 1 && !performance.reuseport {
            return Err(config_invalid(
                "performance.reuseport must be true when performance.worker_threads > 1",
            ));
        }
        require_nonzero_usize(
            "performance.global_inflight_limit",
            performance.global_inflight_limit,
        )?;
        require_nonzero_usize(
            "performance.per_upstream_inflight_limit",
            performance.per_upstream_inflight_limit,
        )?;
        require_nonzero_usize(
            "performance.per_backend_inflight_limit",
            performance.per_backend_inflight_limit,
        )?;
        require_nonzero_usize(
            "performance.udp_recv_buffer_bytes",
            performance.udp_recv_buffer_bytes,
        )?;
        require_nonzero_usize(
            "performance.udp_send_buffer_bytes",
            performance.udp_send_buffer_bytes,
        )?;
        require_nonzero_usize(
            "performance.h2_pool_max_idle_per_backend",
            performance.h2_pool_max_idle_per_backend,
        )?;
        require_nonzero_u32(
            "performance.new_connections_per_sec",
            performance.new_connections_per_sec,
        )?;
        require_nonzero_u32(
            "performance.new_connections_burst",
            performance.new_connections_burst,
        )?;
        require_nonzero_usize(
            "performance.max_active_connections",
            performance.max_active_connections,
        )?;
        require_nonzero_u64(
            "performance.quic_initial_max_data",
            performance.quic_initial_max_data,
        )?;
        require_nonzero_u64(
            "performance.quic_initial_max_stream_data",
            performance.quic_initial_max_stream_data,
        )?;
        if performance.quic_initial_max_stream_data > performance.quic_initial_max_data {
            return Err(config_invalid(format!(
                "performance.quic_initial_max_stream_data ({}) must be <= quic_initial_max_data ({})",
                performance.quic_initial_max_stream_data, performance.quic_initial_max_data
            )));
        }
        require_nonzero_u64(
            "performance.quic_initial_max_streams_bidi",
            performance.quic_initial_max_streams_bidi,
        )?;
        require_nonzero_u64(
            "performance.quic_initial_max_streams_uni",
            performance.quic_initial_max_streams_uni,
        )?;
        require_nonzero_usize(
            "performance.max_response_body_bytes",
            performance.max_response_body_bytes,
        )?;
        require_nonzero_usize(
            "performance.max_request_body_bytes",
            performance.max_request_body_bytes,
        )?;
        require_nonzero_usize(
            "performance.request_buffer_global_cap_bytes",
            performance.request_buffer_global_cap_bytes,
        )?;
        require_nonzero_usize(
            "performance.unknown_length_response_prebuffer_bytes",
            performance.unknown_length_response_prebuffer_bytes,
        )?;
        if performance.max_request_body_bytes > performance.quic_initial_max_stream_data as usize {
            return Err(config_invalid(format!(
                "performance.max_request_body_bytes ({}) must be <= quic_initial_max_stream_data ({})",
                performance.max_request_body_bytes, performance.quic_initial_max_stream_data
            )));
        }
        if performance.request_buffer_global_cap_bytes < performance.max_request_body_bytes {
            return Err(config_invalid(format!(
                "performance.request_buffer_global_cap_bytes ({}) must be >= max_request_body_bytes ({})",
                performance.request_buffer_global_cap_bytes, performance.max_request_body_bytes
            )));
        }
        if performance.unknown_length_response_prebuffer_bytes > performance.max_response_body_bytes
        {
            return Err(config_invalid(format!(
                "performance.unknown_length_response_prebuffer_bytes ({}) must be <= max_response_body_bytes ({})",
                performance.unknown_length_response_prebuffer_bytes,
                performance.max_response_body_bytes
            )));
        }

        Ok(Self {
            worker_threads: performance.worker_threads,
            control_plane_threads: performance.control_plane_threads,
            packet_shards_per_worker: performance.packet_shards_per_worker,
            packet_shard_queue_capacity: performance.packet_shard_queue_capacity,
            packet_shard_queue_max_bytes: performance.packet_shard_queue_max_bytes,
            reuseport: performance.reuseport,
            pin_workers: performance.pin_workers,
            udp_recv_buffer_bytes: performance.udp_recv_buffer_bytes,
            udp_send_buffer_bytes: performance.udp_send_buffer_bytes,
            new_connections_per_sec: performance.new_connections_per_sec,
            new_connections_burst: performance.new_connections_burst,
            quic_initial_max_data: performance.quic_initial_max_data,
            quic_initial_max_stream_data: performance.quic_initial_max_stream_data,
            quic_initial_max_streams_bidi: performance.quic_initial_max_streams_bidi,
            quic_initial_max_streams_uni: performance.quic_initial_max_streams_uni,
            max_response_body_bytes: performance.max_response_body_bytes,
            max_request_body_bytes: performance.max_request_body_bytes,
            request_buffer_global_cap_bytes: performance.request_buffer_global_cap_bytes,
            unknown_length_response_prebuffer_bytes: performance
                .unknown_length_response_prebuffer_bytes,
            connection_limits: RuntimeConnectionLimits {
                global_inflight: performance.global_inflight_limit,
                per_upstream_inflight: performance.per_upstream_inflight_limit,
                per_backend: performance.per_backend_inflight_limit,
                backend_pool_max_inflight: performance
                    .per_backend_inflight_limit
                    .saturating_mul(performance.worker_threads.max(1)),
                max_active_connections: performance.max_active_connections,
            },
            backend_connections: RuntimeBackendConnectionPolicy {
                max_inflight: performance
                    .per_backend_inflight_limit
                    .saturating_mul(performance.worker_threads.max(1)),
                max_idle_per_backend: performance.h2_pool_max_idle_per_backend,
                pool_idle_timeout: Duration::from_millis(performance.h2_pool_idle_timeout_ms),
                connect_timeout: Duration::from_millis(performance.backend_connect_timeout_ms),
                execution_timeout: Duration::from_millis(performance.backend_timeout_ms),
            },
            backend_dns: RuntimeBackendDnsPolicy::from_performance(performance),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Performance;

    fn valid_performance() -> Performance {
        Performance::default()
    }

    #[test]
    fn normalize_preserves_worker_and_control_plane_thread_values() {
        let mut performance = valid_performance();
        performance.worker_threads = 8;
        performance.control_plane_threads = 3;
        performance.packet_shards_per_worker = 2;
        performance.reuseport = true;

        let policy =
            RuntimeTransportPolicy::normalize(&performance).expect("normalization must succeed");

        assert_eq!(policy.worker_threads, 8);
        assert_eq!(policy.control_plane_threads, 3);
        assert_eq!(policy.packet_shards_per_worker, 2);
        assert!(policy.reuseport);
    }

    #[test]
    fn normalize_preserves_shard_and_queue_settings() {
        let mut performance = valid_performance();
        performance.packet_shards_per_worker = 4;
        performance.packet_shard_queue_capacity = 512;
        performance.packet_shard_queue_max_bytes = 2 * 1024 * 1024;

        let policy =
            RuntimeTransportPolicy::normalize(&performance).expect("normalization must succeed");

        assert_eq!(policy.packet_shards_per_worker, 4);
        assert_eq!(policy.packet_shard_queue_capacity, 512);
        assert_eq!(policy.packet_shard_queue_max_bytes, 2 * 1024 * 1024);
    }

    #[test]
    fn normalize_shapes_inflight_limits_and_backend_pool_capacity() {
        let mut performance = valid_performance();
        performance.worker_threads = 4;
        performance.reuseport = true;
        performance.global_inflight_limit = 1000;
        performance.per_upstream_inflight_limit = 250;
        performance.per_backend_inflight_limit = 32;
        performance.max_active_connections = 4096;

        let policy =
            RuntimeTransportPolicy::normalize(&performance).expect("normalization must succeed");

        assert_eq!(policy.connection_limits.global_inflight, 1000);
        assert_eq!(policy.connection_limits.per_upstream_inflight, 250);
        assert_eq!(policy.connection_limits.per_backend, 32);
        assert_eq!(policy.connection_limits.backend_pool_max_inflight, 128);
        assert_eq!(policy.connection_limits.max_active_connections, 4096);
    }

    #[test]
    fn normalize_preserves_udp_buffer_sizes() {
        let mut performance = valid_performance();
        performance.udp_recv_buffer_bytes = 4 * 1024 * 1024;
        performance.udp_send_buffer_bytes = 2 * 1024 * 1024;

        let policy =
            RuntimeTransportPolicy::normalize(&performance).expect("normalization must succeed");

        assert_eq!(policy.udp_recv_buffer_bytes, 4 * 1024 * 1024);
        assert_eq!(policy.udp_send_buffer_bytes, 2 * 1024 * 1024);
    }

    #[test]
    fn normalize_shapes_backend_connection_policy_from_transport_knobs() {
        let mut performance = valid_performance();
        performance.worker_threads = 3;
        performance.reuseport = true;
        performance.per_backend_inflight_limit = 20;
        performance.h2_pool_max_idle_per_backend = 11;
        performance.h2_pool_idle_timeout_ms = 7_500;
        performance.backend_connect_timeout_ms = 600;
        performance.backend_timeout_ms = 2_500;

        let policy =
            RuntimeTransportPolicy::normalize(&performance).expect("normalization must succeed");

        assert_eq!(policy.backend_connections.max_inflight, 60);
        assert_eq!(policy.backend_connections.max_idle_per_backend, 11);
        assert_eq!(
            policy.backend_connections.pool_idle_timeout,
            Duration::from_millis(7_500)
        );
        assert_eq!(
            policy.backend_connections.connect_timeout,
            Duration::from_millis(600)
        );
        assert_eq!(
            policy.backend_connections.execution_timeout,
            Duration::from_millis(2_500)
        );
    }

    #[test]
    fn normalize_rejects_missing_reuseport_when_multiple_workers_are_configured() {
        let mut performance = valid_performance();
        performance.worker_threads = 2;
        performance.reuseport = false;

        let err =
            RuntimeTransportPolicy::normalize(&performance).expect_err("normalization must fail");

        assert_eq!(err.category(), "config_invalid");
        assert_eq!(
            err.to_string(),
            "config_invalid: performance.reuseport must be true when performance.worker_threads > 1"
        );
    }

    #[test]
    fn normalize_rejects_zero_for_required_worker_and_queue_knobs() {
        let cases = [
            (
                "performance.worker_threads must be greater than 0",
                zero_worker_threads as fn(&mut Performance),
            ),
            (
                "performance.control_plane_threads must be greater than 0",
                zero_control_plane_threads as fn(&mut Performance),
            ),
            (
                "performance.packet_shards_per_worker must be greater than 0",
                zero_packet_shards_per_worker as fn(&mut Performance),
            ),
            (
                "performance.packet_shard_queue_capacity must be greater than 0",
                zero_packet_shard_queue_capacity as fn(&mut Performance),
            ),
            (
                "performance.packet_shard_queue_max_bytes must be greater than 0",
                zero_packet_shard_queue_max_bytes as fn(&mut Performance),
            ),
        ];

        for (expected, mutate) in cases {
            let mut performance = valid_performance();
            mutate(&mut performance);

            let err = RuntimeTransportPolicy::normalize(&performance).expect_err(expected);

            assert_eq!(err.category(), "config_invalid");
            assert_eq!(err.to_string(), format!("config_invalid: {expected}"));
        }
    }

    #[test]
    fn normalize_rejects_worker_and_shard_values_above_supported_bounds() {
        let cases = [
            (
                "config_invalid: performance.worker_threads=1025 exceeds the maximum of 1024",
                excessive_worker_threads as fn(&mut Performance),
            ),
            (
                "config_invalid: performance.control_plane_threads=1025 exceeds the maximum of 1024",
                excessive_control_plane_threads as fn(&mut Performance),
            ),
            (
                "config_invalid: performance.packet_shards_per_worker=257 exceeds the maximum of 256",
                excessive_packet_shards_per_worker as fn(&mut Performance),
            ),
        ];

        for (expected, mutate) in cases {
            let mut performance = valid_performance();
            mutate(&mut performance);
            if performance.worker_threads > 1 {
                performance.reuseport = true;
            }

            let err = RuntimeTransportPolicy::normalize(&performance).expect_err(expected);

            assert_eq!(err.to_string(), expected);
        }
    }

    fn zero_worker_threads(performance: &mut Performance) {
        performance.worker_threads = 0;
    }

    fn zero_control_plane_threads(performance: &mut Performance) {
        performance.control_plane_threads = 0;
    }

    fn zero_packet_shards_per_worker(performance: &mut Performance) {
        performance.packet_shards_per_worker = 0;
    }

    fn zero_packet_shard_queue_capacity(performance: &mut Performance) {
        performance.packet_shard_queue_capacity = 0;
    }

    fn zero_packet_shard_queue_max_bytes(performance: &mut Performance) {
        performance.packet_shard_queue_max_bytes = 0;
    }

    fn excessive_worker_threads(performance: &mut Performance) {
        performance.worker_threads = 1025;
    }

    fn excessive_control_plane_threads(performance: &mut Performance) {
        performance.control_plane_threads = 1025;
    }

    fn excessive_packet_shards_per_worker(performance: &mut Performance) {
        performance.packet_shards_per_worker = 257;
    }

    #[test]
    fn normalize_rejects_unknown_length_prebuffer_above_response_cap() {
        let performance = Performance {
            max_response_body_bytes: 1024,
            unknown_length_response_prebuffer_bytes: 1025,
            ..Performance::default()
        };

        let err =
            RuntimeTransportPolicy::normalize(&performance).expect_err("normalization must fail");

        assert!(
            err.to_string().contains(
                "performance.unknown_length_response_prebuffer_bytes (1025) must be <= max_response_body_bytes (1024)"
            )
        );
    }

    #[test]
    fn normalize_rejects_request_body_cap_above_stream_flow_control() {
        let performance = Performance {
            quic_initial_max_stream_data: 4096,
            max_request_body_bytes: 4097,
            request_buffer_global_cap_bytes: 4097,
            ..Performance::default()
        };

        let err =
            RuntimeTransportPolicy::normalize(&performance).expect_err("normalization must fail");

        assert!(
            err.to_string().contains(
                "performance.max_request_body_bytes (4097) must be <= quic_initial_max_stream_data (4096)"
            )
        );
    }

    #[test]
    fn normalize_rejects_request_buffer_cap_below_request_body_cap() {
        let performance = Performance {
            max_request_body_bytes: 8192,
            request_buffer_global_cap_bytes: 8191,
            quic_initial_max_stream_data: 8192,
            ..Performance::default()
        };

        let err =
            RuntimeTransportPolicy::normalize(&performance).expect_err("normalization must fail");

        assert!(
            err.to_string().contains(
                "performance.request_buffer_global_cap_bytes (8191) must be >= max_request_body_bytes (8192)"
            )
        );
    }

    #[test]
    fn normalize_preserves_guardrail_values_when_limits_are_consistent() {
        let performance = Performance {
            worker_threads: 1,
            reuseport: false,
            quic_initial_max_data: 65_536,
            quic_initial_max_stream_data: 16_384,
            max_request_body_bytes: 16_384,
            request_buffer_global_cap_bytes: 20_000,
            max_response_body_bytes: 32_768,
            unknown_length_response_prebuffer_bytes: 8_192,
            ..Performance::default()
        };

        let policy =
            RuntimeTransportPolicy::normalize(&performance).expect("normalization must succeed");

        assert_eq!(policy.max_request_body_bytes, 16_384);
        assert_eq!(policy.request_buffer_global_cap_bytes, 20_000);
        assert_eq!(policy.max_response_body_bytes, 32_768);
        assert_eq!(policy.unknown_length_response_prebuffer_bytes, 8_192);
    }
}
