use super::*;

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct Log {
    pub level: String,
    pub file: LogFile,
    pub format: LogFormat,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file: LogFile::default(),
            format: LogFormat::Plain,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Plain,
    Json,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct LogFile {
    pub enabled: bool,
    pub path: String,
}

impl Default for LogFile {
    fn default() -> Self {
        Self {
            enabled: false,
            path: "/var/log/impulse/impulse.log".to_string(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct Performance {
    pub worker_threads: usize,
    pub control_plane_threads: usize,
    pub packet_shards_per_worker: usize,
    pub packet_shard_queue_capacity: usize,
    pub packet_shard_queue_max_bytes: usize,
    pub reuseport: bool,
    pub pin_workers: bool,
    pub global_inflight_limit: usize,
    pub per_upstream_inflight_limit: usize,
    pub inflight_acquire_wait_ms: u64,
    pub backend_timeout_ms: u64,
    pub backend_connect_timeout_ms: u64,
    pub backend_body_idle_timeout_ms: u64,
    pub backend_body_total_timeout_ms: u64,
    pub backend_total_request_timeout_ms: u64,
    pub shutdown_drain_timeout_ms: u64,
    pub udp_recv_buffer_bytes: usize,
    pub udp_send_buffer_bytes: usize,
    pub h2_pool_max_idle_per_backend: usize,
    pub h2_pool_idle_timeout_ms: u64,
    pub backend_dns_refresh_enabled: bool,
    pub backend_dns_refresh_interval_ms: u64,
    pub per_backend_inflight_limit: usize,
    pub connection_rate_limit_enabled: bool,
    pub new_connections_per_sec: u32,
    pub new_connections_burst: u32,
    pub max_active_connections: usize,
    pub quic_max_idle_timeout_ms: u64,
    pub quic_initial_max_data: u64,
    pub quic_initial_max_stream_data: u64,
    pub quic_initial_max_streams_bidi: u64,
    pub quic_initial_max_streams_uni: u64,
    pub max_response_body_bytes: usize,
    pub max_request_body_bytes: usize,
    pub request_buffer_global_cap_bytes: usize,
    pub unknown_length_response_prebuffer_bytes: usize,
    pub client_body_idle_timeout_ms: u64,
}

impl Default for Performance {
    fn default() -> Self {
        Self {
            worker_threads: 1,
            control_plane_threads: 2,
            packet_shards_per_worker: 1,
            packet_shard_queue_capacity: 2048,
            packet_shard_queue_max_bytes: 64 * 1024 * 1024,
            reuseport: true,
            pin_workers: false,
            global_inflight_limit: 4096,
            per_upstream_inflight_limit: 1024,
            inflight_acquire_wait_ms: 0,
            backend_timeout_ms: 2_000,
            backend_connect_timeout_ms: 500,
            backend_body_idle_timeout_ms: 2_000,
            backend_body_total_timeout_ms: 30_000,
            backend_total_request_timeout_ms: 35_000,
            shutdown_drain_timeout_ms: 5_000,
            udp_recv_buffer_bytes: 8 * 1024 * 1024,
            udp_send_buffer_bytes: 8 * 1024 * 1024,
            h2_pool_max_idle_per_backend: 256,
            h2_pool_idle_timeout_ms: 90_000,
            backend_dns_refresh_enabled: false,
            backend_dns_refresh_interval_ms: 30_000,
            per_backend_inflight_limit: 64,
            connection_rate_limit_enabled: true,
            new_connections_per_sec: 2000,
            new_connections_burst: 500,
            max_active_connections: 20_000,
            quic_max_idle_timeout_ms: 5_000,
            quic_initial_max_data: 10_000_000,
            quic_initial_max_stream_data: 1_000_000,
            quic_initial_max_streams_bidi: 100,
            quic_initial_max_streams_uni: 100,
            max_response_body_bytes: 100 * 1024 * 1024,
            max_request_body_bytes: 1_000_000,
            request_buffer_global_cap_bytes: 64 * 1024 * 1024,
            unknown_length_response_prebuffer_bytes: 2 * 1024 * 1024,
            client_body_idle_timeout_ms: 10_000,
        }
    }
}
