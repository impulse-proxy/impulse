use std::{collections::HashMap, path::Path};

use super::*;
use crate::validator::{
    control_plane::validate_control_api_security,
    helpers::{
        is_loopback_bind_address, is_valid_connect_authority, is_valid_http_token,
        is_valid_request_key_spec, validate_listen_config,
    },
};

macro_rules! validation_error {
    ($($arg:tt)*) => {{
        let message = format!($($arg)*);
        super::record_validation_error(message.clone());
        log::error!("{}", message);
    }};
}

pub(super) fn validate_global_config(config: &Config) -> bool {
    if config.listeners.is_empty() {
        if !validate_listen_config(&config.listen, "listen") {
            return false;
        }
    } else {
        for (idx, listen) in config.listeners.iter().enumerate() {
            if !validate_listen_config(listen, &format!("listeners[{idx}]")) {
                return false;
            }
        }
    }

    let effective_listeners: Vec<(String, &crate::config::Listen)> = if config.listeners.is_empty()
    {
        vec![("listen".to_string(), &config.listen)]
    } else {
        config
            .listeners
            .iter()
            .enumerate()
            .map(|(idx, listen)| (format!("listeners[{idx}]"), listen))
            .collect()
    };

    let mut seen_listener_bindings: HashMap<(String, u16), String> = HashMap::new();
    for (label, listen) in effective_listeners {
        let key = (listen.address.trim().to_ascii_lowercase(), listen.port);
        if let Some(existing) = seen_listener_bindings.insert(key, label.clone()) {
            validation_error!(
                "listener binding conflict: {} duplicates {} on {}:{}",
                label,
                existing,
                listen.address,
                listen.port
            );
            return false;
        }
    }

    let operational_listeners = [
        (
            "observability.metrics",
            config.observability.metrics.enabled,
            &config.observability.metrics.address,
            config.observability.metrics.port,
        ),
        (
            "observability.control_api",
            config.observability.control_api.enabled,
            &config.observability.control_api.address,
            config.observability.control_api.port,
        ),
    ];
    for (label, enabled, address, port) in operational_listeners {
        if !enabled {
            continue;
        }
        let key = (address.trim().to_ascii_lowercase(), port);
        if let Some(existing) = seen_listener_bindings.insert(key, label.to_string()) {
            validation_error!(
                "operational listener binding conflict: {} duplicates {} on {}:{}",
                label,
                existing,
                address,
                port
            );
            return false;
        }
    }

    if !VALID_LOG_LEVELS
        .iter()
        .any(|lvl| lvl.eq_ignore_ascii_case(&config.log.level))
    {
        validation_error!("Invalid log level: {}", config.log.level);
        return false;
    }

    if let Some(ref lb) = config.load_balancing
        && !VALID_LB_TYPES
            .iter()
            .any(|lb_type| lb_type.eq_ignore_ascii_case(&lb.lb_type))
    {
        validation_error!("Invalid global load balancing type: {}", lb.lb_type);
        return false;
    }

    validate_performance(config)
        && validate_resilience(config)
        && validate_observability(config)
        && validate_security(config)
}

fn validate_performance(config: &Config) -> bool {
    if config.performance.worker_threads == 0 {
        validation_error!("performance.worker_threads must be greater than 0");
        return false;
    }
    if config.performance.worker_threads > 1024 {
        validation_error!(
            "performance.worker_threads={} exceeds the maximum of 1024",
            config.performance.worker_threads
        );
        return false;
    }
    if config.performance.control_plane_threads == 0 {
        validation_error!("performance.control_plane_threads must be greater than 0");
        return false;
    }
    if config.performance.control_plane_threads > 1024 {
        validation_error!(
            "performance.control_plane_threads={} exceeds the maximum of 1024",
            config.performance.control_plane_threads
        );
        return false;
    }
    if config.performance.packet_shards_per_worker == 0 {
        validation_error!("performance.packet_shards_per_worker must be greater than 0");
        return false;
    }
    if config.performance.packet_shards_per_worker > 256 {
        validation_error!(
            "performance.packet_shards_per_worker={} exceeds the maximum of 256",
            config.performance.packet_shards_per_worker
        );
        return false;
    }
    if config.performance.packet_shard_queue_capacity == 0 {
        validation_error!("performance.packet_shard_queue_capacity must be greater than 0");
        return false;
    }
    if config.performance.packet_shard_queue_max_bytes == 0 {
        validation_error!("performance.packet_shard_queue_max_bytes must be greater than 0");
        return false;
    }
    if config.performance.worker_threads > 1 && !config.performance.reuseport {
        validation_error!("performance.reuseport must be true when performance.worker_threads > 1");
        return false;
    }
    if config.performance.global_inflight_limit == 0 {
        validation_error!("performance.global_inflight_limit must be greater than 0");
        return false;
    }
    if config.performance.per_upstream_inflight_limit == 0 {
        validation_error!("performance.per_upstream_inflight_limit must be greater than 0");
        return false;
    }
    if config.performance.inflight_acquire_wait_ms > 25 {
        warn!(
            "performance.inflight_acquire_wait_ms={} may increase tail latency under sustained load; keep it small (0-25ms) for burst smoothing only",
            config.performance.inflight_acquire_wait_ms
        );
    }
    if config.performance.backend_timeout_ms == 0 {
        validation_error!("performance.backend_timeout_ms must be greater than 0");
        return false;
    }
    if config.performance.backend_connect_timeout_ms == 0 {
        validation_error!("performance.backend_connect_timeout_ms must be greater than 0");
        return false;
    }
    if config.performance.backend_body_idle_timeout_ms == 0 {
        validation_error!("performance.backend_body_idle_timeout_ms must be greater than 0");
        return false;
    }
    if config.performance.backend_body_total_timeout_ms == 0 {
        validation_error!("performance.backend_body_total_timeout_ms must be greater than 0");
        return false;
    }
    if config.performance.backend_total_request_timeout_ms == 0 {
        validation_error!("performance.backend_total_request_timeout_ms must be greater than 0");
        return false;
    }
    if config.performance.shutdown_drain_timeout_ms == 0 {
        validation_error!("performance.shutdown_drain_timeout_ms must be greater than 0");
        return false;
    }
    if config.resilience.watchdog.enabled
        && config.resilience.watchdog.drain_grace_ms < config.performance.shutdown_drain_timeout_ms
    {
        validation_error!(
            "resilience.watchdog.drain_grace_ms must be at least performance.shutdown_drain_timeout_ms when the watchdog is enabled"
        );
        return false;
    }
    if config.performance.udp_recv_buffer_bytes == 0 {
        validation_error!("performance.udp_recv_buffer_bytes must be greater than 0");
        return false;
    }
    if config.performance.udp_send_buffer_bytes == 0 {
        validation_error!("performance.udp_send_buffer_bytes must be greater than 0");
        return false;
    }
    if config.performance.h2_pool_max_idle_per_backend == 0 {
        validation_error!("performance.h2_pool_max_idle_per_backend must be greater than 0");
        return false;
    }
    if config.performance.h2_pool_idle_timeout_ms == 0 {
        validation_error!("performance.h2_pool_idle_timeout_ms must be greater than 0");
        return false;
    }
    if config.performance.backend_dns_refresh_interval_ms == 0 {
        validation_error!("performance.backend_dns_refresh_interval_ms must be greater than 0");
        return false;
    }
    if config.performance.per_backend_inflight_limit == 0 {
        validation_error!("performance.per_backend_inflight_limit must be greater than 0");
        return false;
    }
    if config.performance.new_connections_per_sec == 0 {
        validation_error!("performance.new_connections_per_sec must be greater than 0");
        return false;
    }
    if config.performance.new_connections_burst == 0 {
        validation_error!("performance.new_connections_burst must be greater than 0");
        return false;
    }
    if config.performance.max_active_connections == 0 {
        validation_error!("performance.max_active_connections must be greater than 0");
        return false;
    }
    if config.performance.quic_max_idle_timeout_ms == 0 {
        validation_error!("performance.quic_max_idle_timeout_ms must be greater than 0");
        return false;
    }
    if config.performance.quic_initial_max_data == 0 {
        validation_error!("performance.quic_initial_max_data must be greater than 0");
        return false;
    }
    if config.performance.quic_initial_max_stream_data == 0 {
        validation_error!("performance.quic_initial_max_stream_data must be greater than 0");
        return false;
    }
    if config.performance.quic_initial_max_stream_data > config.performance.quic_initial_max_data {
        validation_error!(
            "performance.quic_initial_max_stream_data ({}) must be <= quic_initial_max_data ({})",
            config.performance.quic_initial_max_stream_data,
            config.performance.quic_initial_max_data
        );
        return false;
    }
    if config.performance.quic_initial_max_streams_bidi == 0 {
        validation_error!("performance.quic_initial_max_streams_bidi must be greater than 0");
        return false;
    }
    if config.performance.quic_initial_max_streams_uni == 0 {
        validation_error!("performance.quic_initial_max_streams_uni must be greater than 0");
        return false;
    }
    if config.performance.max_response_body_bytes == 0 {
        validation_error!("performance.max_response_body_bytes must be greater than 0");
        return false;
    }
    if config.performance.max_request_body_bytes == 0 {
        validation_error!("performance.max_request_body_bytes must be greater than 0");
        return false;
    }
    if config.performance.request_buffer_global_cap_bytes == 0 {
        validation_error!("performance.request_buffer_global_cap_bytes must be greater than 0");
        return false;
    }
    if config.performance.unknown_length_response_prebuffer_bytes == 0 {
        validation_error!(
            "performance.unknown_length_response_prebuffer_bytes must be greater than 0"
        );
        return false;
    }
    if config.performance.client_body_idle_timeout_ms == 0 {
        validation_error!("performance.client_body_idle_timeout_ms must be greater than 0");
        return false;
    }
    if config.performance.backend_connect_timeout_ms > config.performance.backend_timeout_ms {
        validation_error!("performance.backend_connect_timeout_ms must be <= backend_timeout_ms");
        return false;
    }
    if config.performance.backend_timeout_ms > config.performance.backend_body_idle_timeout_ms {
        validation_error!("performance.backend_timeout_ms must be <= backend_body_idle_timeout_ms");
        return false;
    }
    if config.performance.backend_body_idle_timeout_ms
        > config.performance.backend_body_total_timeout_ms
    {
        validation_error!(
            "performance.backend_body_idle_timeout_ms must be <= backend_body_total_timeout_ms"
        );
        return false;
    }
    if config.performance.backend_body_total_timeout_ms
        > config.performance.backend_total_request_timeout_ms
    {
        validation_error!(
            "performance.backend_body_total_timeout_ms must be <= backend_total_request_timeout_ms"
        );
        return false;
    }
    if config.performance.max_request_body_bytes
        > config.performance.quic_initial_max_stream_data as usize
    {
        validation_error!(
            "performance.max_request_body_bytes ({}) must be <= quic_initial_max_stream_data ({})",
            config.performance.max_request_body_bytes,
            config.performance.quic_initial_max_stream_data
        );
        return false;
    }
    if config.performance.request_buffer_global_cap_bytes
        < config.performance.max_request_body_bytes
    {
        validation_error!(
            "performance.request_buffer_global_cap_bytes ({}) must be >= max_request_body_bytes ({})",
            config.performance.request_buffer_global_cap_bytes,
            config.performance.max_request_body_bytes
        );
        return false;
    }
    if config.performance.unknown_length_response_prebuffer_bytes
        > config.performance.max_response_body_bytes
    {
        validation_error!(
            "performance.unknown_length_response_prebuffer_bytes ({}) must be <= max_response_body_bytes ({})",
            config.performance.unknown_length_response_prebuffer_bytes,
            config.performance.max_response_body_bytes
        );
        return false;
    }
    true
}

fn validate_resilience(config: &Config) -> bool {
    if config.resilience.adaptive_admission.min_limit == 0 {
        validation_error!("resilience.adaptive_admission.min_limit must be greater than 0");
        return false;
    }
    if let Some(max_limit) = config.resilience.adaptive_admission.max_limit {
        if max_limit == 0 {
            validation_error!("resilience.adaptive_admission.max_limit must be greater than 0");
            return false;
        }
        if max_limit < config.resilience.adaptive_admission.min_limit {
            validation_error!(
                "resilience.adaptive_admission.max_limit ({}) must be >= min_limit ({})",
                max_limit,
                config.resilience.adaptive_admission.min_limit
            );
            return false;
        }
        if max_limit > config.performance.global_inflight_limit {
            validation_error!(
                "resilience.adaptive_admission.max_limit ({}) must be <= performance.global_inflight_limit ({})",
                max_limit,
                config.performance.global_inflight_limit
            );
            return false;
        }
    }
    if config.resilience.adaptive_admission.decrease_step == 0 {
        validation_error!("resilience.adaptive_admission.decrease_step must be greater than 0");
        return false;
    }
    if config.resilience.adaptive_admission.increase_step == 0 {
        validation_error!("resilience.adaptive_admission.increase_step must be greater than 0");
        return false;
    }
    if config.resilience.route_queue.default_cap == 0 {
        validation_error!("resilience.route_queue.default_cap must be greater than 0");
        return false;
    }
    if config.resilience.route_queue.global_cap == 0 {
        validation_error!("resilience.route_queue.global_cap must be greater than 0");
        return false;
    }
    if config.resilience.route_queue.shed_retry_after_seconds == 0 {
        validation_error!("resilience.route_queue.shed_retry_after_seconds must be greater than 0");
        return false;
    }
    if config
        .resilience
        .route_queue
        .caps
        .values()
        .any(|cap| *cap == 0)
    {
        validation_error!("resilience.route_queue.caps values must be greater than 0");
        return false;
    }
    if config.resilience.protocol.max_headers_count == 0 {
        validation_error!("resilience.protocol.max_headers_count must be greater than 0");
        return false;
    }
    if config.resilience.protocol.max_headers_bytes == 0 {
        validation_error!("resilience.protocol.max_headers_bytes must be greater than 0");
        return false;
    }
    if config
        .resilience
        .protocol
        .early_data_safe_methods
        .iter()
        .any(|method| method.trim().is_empty())
    {
        validation_error!(
            "resilience.protocol.early_data_safe_methods must not contain empty values"
        );
        return false;
    }
    if config
        .resilience
        .protocol
        .early_data_safe_methods
        .iter()
        .any(|method| !is_valid_http_token(method))
    {
        validation_error!(
            "resilience.protocol.early_data_safe_methods must contain valid HTTP method tokens"
        );
        return false;
    }
    if config
        .resilience
        .protocol
        .allowed_methods
        .iter()
        .any(|method| method.trim().is_empty())
    {
        validation_error!("resilience.protocol.allowed_methods must not contain empty values");
        return false;
    }
    if config
        .resilience
        .protocol
        .allowed_methods
        .iter()
        .any(|method| !is_valid_http_token(method))
    {
        validation_error!(
            "resilience.protocol.allowed_methods must contain valid HTTP method tokens"
        );
        return false;
    }
    if config
        .resilience
        .protocol
        .denied_path_prefixes
        .iter()
        .any(|prefix| prefix.is_empty() || !prefix.starts_with('/'))
    {
        validation_error!(
            "resilience.protocol.denied_path_prefixes must contain '/'-prefixed paths"
        );
        return false;
    }
    if !config.resilience.protocol.allow_connect
        && (!config.resilience.protocol.connect_allowed_ports.is_empty()
            || !config
                .resilience
                .protocol
                .connect_allowed_authorities
                .is_empty())
    {
        validation_error!(
            "resilience.protocol.connect_allowed_ports/connect_allowed_authorities require allow_connect=true"
        );
        return false;
    }
    if config
        .resilience
        .protocol
        .connect_allowed_ports
        .contains(&0)
    {
        validation_error!(
            "resilience.protocol.connect_allowed_ports must contain ports in range 1-65535"
        );
        return false;
    }
    if config
        .resilience
        .protocol
        .connect_allowed_authorities
        .iter()
        .any(|authority| !is_valid_connect_authority(authority))
    {
        validation_error!(
            "resilience.protocol.connect_allowed_authorities must contain authority-form host:port targets"
        );
        return false;
    }
    if config.resilience.protocol.allow_0rtt
        && config
            .resilience
            .protocol
            .early_data_safe_methods
            .is_empty()
    {
        validation_error!(
            "resilience.protocol.early_data_safe_methods must be non-empty when allow_0rtt=true"
        );
        return false;
    }
    if config.resilience.protocol.allow_0rtt
        && !crate::policy_helpers::early_data_methods_are_safe(
            &config.resilience.protocol.early_data_safe_methods,
        )
    {
        validation_error!(
            "resilience.protocol.early_data_safe_methods may contain only GET or HEAD when allow_0rtt=true"
        );
        return false;
    }
    if config.resilience.circuit_breaker.failure_threshold == 0 {
        validation_error!("resilience.circuit_breaker.failure_threshold must be greater than 0");
        return false;
    }
    if config.resilience.circuit_breaker.open_ms == 0 {
        validation_error!("resilience.circuit_breaker.open_ms must be greater than 0");
        return false;
    }
    if config.resilience.circuit_breaker.half_open_max_probes == 0 {
        validation_error!("resilience.circuit_breaker.half_open_max_probes must be greater than 0");
        return false;
    }
    if config.resilience.retry_budget.ratio_percent > 100 {
        validation_error!("resilience.retry_budget.ratio_percent must be <= 100");
        return false;
    }
    if config
        .resilience
        .retry_budget
        .per_route_ratio_percent
        .values()
        .any(|ratio| *ratio > 100)
    {
        validation_error!("resilience.retry_budget.per_route_ratio_percent values must be <= 100");
        return false;
    }

    let mut seen_scoped_rate_limit_names = std::collections::HashSet::new();
    for rule in &config.resilience.scoped_rate_limits {
        let rule_name = rule.name.trim();
        if rule_name.is_empty() {
            validation_error!("resilience.scoped_rate_limits[].name must be non-empty");
            return false;
        }
        if !seen_scoped_rate_limit_names.insert(rule_name.to_string()) {
            validation_error!(
                "resilience.scoped_rate_limits contains duplicate rule name '{}'",
                rule_name
            );
            return false;
        }
        if rule.requests_per_sec == 0 {
            validation_error!(
                "resilience.scoped_rate_limits['{}'].requests_per_sec must be greater than 0",
                rule_name
            );
            return false;
        }
        if rule.burst == 0 {
            validation_error!(
                "resilience.scoped_rate_limits['{}'].burst must be greater than 0",
                rule_name
            );
            return false;
        }
        if rule.idle_ttl_secs == 0 {
            validation_error!(
                "resilience.scoped_rate_limits['{}'].idle_ttl_secs must be greater than 0",
                rule_name
            );
            return false;
        }
        if rule
            .route_allowlist
            .iter()
            .any(|route| route.trim().is_empty())
        {
            validation_error!(
                "resilience.scoped_rate_limits['{}'].route_allowlist must not contain empty values",
                rule_name
            );
            return false;
        }
        match rule.scope {
            ScopedRateLimitScope::Route => {
                if rule
                    .key
                    .as_ref()
                    .is_some_and(|value| !value.trim().is_empty())
                {
                    validation_error!(
                        "resilience.scoped_rate_limits['{}'].key is invalid for scope=route",
                        rule_name
                    );
                    return false;
                }
            }
            ScopedRateLimitScope::Tenant => {
                let Some(key_spec) = rule.key.as_deref() else {
                    validation_error!(
                        "resilience.scoped_rate_limits['{}'].key is required for scope=tenant",
                        rule_name
                    );
                    return false;
                };
                if !is_valid_request_key_spec(key_spec) {
                    validation_error!(
                        "resilience.scoped_rate_limits['{}'].key must be a supported request key spec",
                        rule_name
                    );
                    return false;
                }
            }
            ScopedRateLimitScope::Client | ScopedRateLimitScope::Token => {
                if let Some(key_spec) = rule.key.as_deref()
                    && !is_valid_request_key_spec(key_spec)
                {
                    validation_error!(
                        "resilience.scoped_rate_limits['{}'].key must be a supported request key spec",
                        rule_name
                    );
                    return false;
                }
            }
        }
    }

    if config.resilience.brownout.trigger_inflight_percent > 100
        || config.resilience.brownout.recover_inflight_percent > 100
    {
        validation_error!("resilience.brownout inflight percentages must be <= 100");
        return false;
    }
    if config.resilience.brownout.recover_inflight_percent
        >= config.resilience.brownout.trigger_inflight_percent
    {
        validation_error!(
            "resilience.brownout.recover_inflight_percent must be < trigger_inflight_percent"
        );
        return false;
    }
    if config.resilience.watchdog.check_interval_ms == 0 {
        validation_error!("resilience.watchdog.check_interval_ms must be greater than 0");
        return false;
    }
    if config.resilience.watchdog.poll_stall_timeout_ms == 0 {
        validation_error!("resilience.watchdog.poll_stall_timeout_ms must be greater than 0");
        return false;
    }
    if config.resilience.watchdog.timeout_error_rate_percent > 100 {
        validation_error!("resilience.watchdog.timeout_error_rate_percent must be <= 100");
        return false;
    }
    if config.resilience.watchdog.min_requests_per_window == 0 {
        validation_error!("resilience.watchdog.min_requests_per_window must be greater than 0");
        return false;
    }
    if config.resilience.watchdog.overload_inflight_percent > 100 {
        validation_error!("resilience.watchdog.overload_inflight_percent must be <= 100");
        return false;
    }
    if config.resilience.watchdog.unhealthy_consecutive_windows == 0 {
        validation_error!(
            "resilience.watchdog.unhealthy_consecutive_windows must be greater than 0"
        );
        return false;
    }
    if config.resilience.watchdog.drain_grace_ms == 0 {
        validation_error!("resilience.watchdog.drain_grace_ms must be greater than 0");
        return false;
    }
    if config.resilience.watchdog.restart_cooldown_ms == 0 {
        validation_error!("resilience.watchdog.restart_cooldown_ms must be greater than 0");
        return false;
    }
    if !config.resilience.watchdog.restart_command.is_empty()
        && config.resilience.watchdog.restart_command[0]
            .trim()
            .is_empty()
    {
        validation_error!(
            "resilience.watchdog.restart_command[0] must be a non-empty executable path"
        );
        return false;
    }
    if !config.resilience.watchdog.restart_command.is_empty()
        && !Path::new(config.resilience.watchdog.restart_command[0].trim()).is_absolute()
    {
        validation_error!(
            "resilience.watchdog.restart_command[0] must be an absolute executable path"
        );
        return false;
    }
    if config.resilience.watchdog.restart_hook.is_some() {
        validation_error!(
            "resilience.watchdog.restart_hook is deprecated and unsupported; use restart_command instead"
        );
        return false;
    }
    true
}

fn validate_observability(config: &Config) -> bool {
    if config.observability.metrics.enabled {
        if config.observability.metrics.address.is_empty() {
            validation_error!(
                "observability.metrics.address cannot be empty when metrics are enabled"
            );
            return false;
        }
        if config.observability.metrics.port == 0 {
            validation_error!("observability.metrics.port must be between 1 and 65535");
            return false;
        }
        if !config.observability.metrics.path.starts_with('/') {
            validation_error!("observability.metrics.path must start with '/'");
            return false;
        }
        if config.observability.metrics.max_connections == 0 {
            validation_error!("observability.metrics.max_connections must be greater than 0");
            return false;
        }
        if config.observability.metrics.connection_timeout_ms == 0 {
            validation_error!("observability.metrics.connection_timeout_ms must be greater than 0");
            return false;
        }
        if !is_loopback_bind_address(&config.observability.metrics.address) {
            if !config.observability.metrics.allow_non_loopback {
                validation_error!(
                    "observability.metrics.address must be loopback unless observability.metrics.allow_non_loopback=true; the metrics endpoint is unauthenticated plaintext HTTP"
                );
                return false;
            }
            if config.observability.control_api.tls.client_auth.mode
                != crate::config::ControlApiClientAuthMode::Required
            {
                validation_error!(
                    "observability.metrics.allow_non_loopback=true requires observability.control_api.tls.client_auth.mode=required so remote metrics use mTLS"
                );
                return false;
            }
            warn!(
                "observability.metrics.allow_non_loopback=true exposes metrics over mTLS on {}",
                config.observability.metrics.address
            );
        }
    }

    if config.observability.control_api.enabled {
        if config.observability.control_api.address.is_empty() {
            validation_error!(
                "observability.control_api.address cannot be empty when control_api is enabled"
            );
            return false;
        }
        if config.observability.control_api.port == 0 {
            validation_error!("observability.control_api.port must be between 1 and 65535");
            return false;
        }

        let control_api = &config.observability.control_api;
        let runtime_history_path = format!("{}/history", control_api.runtime_path);
        let runtime_history_entry_prefix = format!("{}/", runtime_history_path);
        let runtime_routes = [
            ("GET", control_api.health_path.clone(), "health"),
            ("GET", control_api.ready_path.clone(), "ready"),
            ("GET", control_api.runtime_path.clone(), "runtime"),
            ("GET", runtime_history_path.clone(), "runtime_history"),
            (
                "GET_DYNAMIC",
                runtime_history_entry_prefix.clone(),
                "runtime_history_generation",
            ),
            (
                "POST",
                control_api.reload_certs_path.clone(),
                "reload_certs",
            ),
            (
                "POST",
                format!("{}/validate", control_api.runtime_path),
                "runtime_validate",
            ),
            (
                "POST",
                format!("{}/preview", control_api.runtime_path),
                "runtime_preview",
            ),
            (
                "POST",
                format!("{}/activate", control_api.runtime_path),
                "runtime_activate",
            ),
            (
                "POST",
                format!("{}/rollback", control_api.runtime_path),
                "runtime_rollback",
            ),
            ("POST", control_api.reload_path.clone(), "reload"),
            ("POST", control_api.restart_path.clone(), "restart"),
        ];
        for (method, path, name) in &runtime_routes {
            if path.is_empty()
                || !path.starts_with('/')
                || path.contains(['?', '#', '\\'])
                || path.chars().any(char::is_control)
                || (*method != "GET_DYNAMIC" && path != "/" && path.ends_with('/'))
            {
                validation_error!(
                    "observability.control_api route '{}' has invalid {} path '{}'",
                    name,
                    method,
                    path
                );
                return false;
            }
        }

        let mut seen_routes = HashMap::new();
        for (method, path, name) in &runtime_routes {
            if *method == "GET_DYNAMIC" {
                continue;
            }
            if let Some(previous) = seen_routes.insert((*method, path), *name) {
                validation_error!(
                    "observability.control_api routes '{}' and '{}' duplicate {} '{}'",
                    previous,
                    name,
                    method,
                    path
                );
                return false;
            }
        }

        for (method, path, name) in &runtime_routes {
            if *method == "GET"
                && *path != runtime_history_path
                && path.starts_with(runtime_history_entry_prefix.as_str())
            {
                validation_error!(
                    "observability.control_api route '{}' conflicts with dynamic runtime history path prefix '{}'",
                    name,
                    runtime_history_entry_prefix
                );
                return false;
            }
        }
        if config.observability.control_api.max_connections == 0 {
            validation_error!("observability.control_api.max_connections must be greater than 0");
            return false;
        }
        if config.observability.control_api.connection_timeout_ms == 0 {
            validation_error!(
                "observability.control_api.connection_timeout_ms must be greater than 0"
            );
            return false;
        }
        if !validate_control_api_security(&config.observability.control_api) {
            return false;
        }
    }

    if config.observability.routing.expose_header
        && config.observability.routing.header_name.trim().is_empty()
    {
        validation_error!(
            "observability.routing.header_name must be non-empty when expose_header=true"
        );
        return false;
    }

    if config.observability.tracing.enabled {
        if config.observability.tracing.service_name.trim().is_empty() {
            validation_error!(
                "observability.tracing.service_name cannot be empty when tracing is enabled"
            );
            return false;
        }
        if !(0.0..=1.0).contains(&config.observability.tracing.sample_ratio) {
            validation_error!("observability.tracing.sample_ratio must be between 0.0 and 1.0");
            return false;
        }
        if let Some(endpoint) = config.observability.tracing.otlp_endpoint.as_ref()
            && endpoint.trim().is_empty()
        {
            validation_error!("observability.tracing.otlp_endpoint cannot be empty when provided");
            return false;
        }
    }

    true
}

fn validate_security(config: &Config) -> bool {
    if config.security.privileges.enabled {
        if config.security.privileges.user.trim().is_empty() {
            validation_error!(
                "security.privileges.user must be non-empty when privilege drop is enabled"
            );
            return false;
        }
        if config.security.privileges.group.trim().is_empty() {
            validation_error!(
                "security.privileges.group must be non-empty when privilege drop is enabled"
            );
            return false;
        }
    }

    true
}
