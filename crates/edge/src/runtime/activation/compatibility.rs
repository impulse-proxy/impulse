use std::sync::Arc;

use crate::{
    quic_listener::QUICListener,
    runtime::{
        bundle::{ActiveRuntimeGeneration, RuntimeBundle},
        cache::response_cache_storage_limits,
        policy::{ReloadCompatibilityAuthority, TransitionRejection},
    },
};

pub(crate) fn evaluate_runtime_reload_compatibility(
    current: &ActiveRuntimeGeneration,
    next: &RuntimeBundle,
) -> Result<(), Vec<TransitionRejection>> {
    if let Some(rejection) = validate_runtime_reload_compatibility(current.bundle(), next) {
        return Err(vec![rejection]);
    }
    if let Some(rejection) = validate_control_api_reload_compatibility(current.bundle(), next) {
        return Err(vec![rejection]);
    }
    if let Some(rejection) = validate_metrics_reload_compatibility(current.bundle(), next) {
        return Err(vec![rejection]);
    }
    validate_startup_owned_reload_compatibility(current.bundle(), next)
}

pub(crate) fn validate_runtime_reload_compatibility(
    current: &RuntimeBundle,
    next: &RuntimeBundle,
) -> Option<TransitionRejection> {
    let current_listeners = &current
        .shared_state
        .generation_state()
        .listener_runtime_configs;
    let next_listeners = &next
        .shared_state
        .generation_state()
        .listener_runtime_configs;
    if next_listeners.len() < current_listeners.len()
        && let Some(label) = current_listeners
            .keys()
            .find(|label| !next_listeners.contains_key(*label))
    {
        return Some(TransitionRejection::listener_bind_changed(label));
    }

    for (label, listener_config) in next_listeners.iter() {
        if let Err(error) = QUICListener::build_listener_tls_reload_state(listener_config) {
            return Some(TransitionRejection::resource_preflight_failed(
                "Pingora listener TLS",
                label,
                error.to_string(),
            ));
        }
        if current_listeners.contains_key(label) {
            continue;
        }
        let worker_count = listener_config.performance.worker_threads.max(1);
        let bind_result = if worker_count > 1 {
            QUICListener::bind_reuseport_sockets(listener_config, worker_count).map(|_| ())
        } else {
            QUICListener::bind_socket(listener_config, false).map(|_| ())
        };
        if let Err(error) = bind_result {
            return Some(TransitionRejection::resource_preflight_failed(
                "QUIC listener",
                label,
                error.to_string(),
            ));
        }

        let bind = format!(
            "{}:{}",
            listener_config.listen.listen.address, listener_config.listen.listen.port
        );
        if let Err(error) = QUICListener::probe_tcp_bind(&bind, "Pingora listener") {
            return Some(TransitionRejection::resource_preflight_failed(
                "Pingora listener",
                label,
                error,
            ));
        }
    }
    None
}

pub(crate) fn validate_control_api_reload_compatibility(
    current: &RuntimeBundle,
    next: &RuntimeBundle,
) -> Option<TransitionRejection> {
    let next_control_api = &next.runtime_config.observability.control_api;
    if !next_control_api.enabled {
        return None;
    }

    let Some(listener_config) = next.runtime_config.primary_listener_runtime_config() else {
        return Some(TransitionRejection::raw_resource_message(
            "runtime reload rejected: no effective listeners configured for control API TLS",
        ));
    };
    let primary_listener_label = QUICListener::listener_label(&listener_config);
    if next
        .shared_state
        .shared_services()
        .listener_tls_store
        .certificate_resolver(&primary_listener_label)
        .is_none()
    {
        return Some(TransitionRejection::raw_resource_message(format!(
            "runtime reload rejected: control API TLS config missing for listener '{primary_listener_label}'"
        )));
    }

    if let Err(error) = QUICListener::preflight_control_api_server_tls_config(
        &listener_config,
        next_control_api,
        Arc::clone(&next.shared_state.shared_services().metrics),
    ) {
        return Some(TransitionRejection::resource_preflight_failed(
            "control API TLS",
            primary_listener_label,
            error.to_string(),
        ));
    }

    let current_control_api = &current.runtime_config.observability.control_api;
    let bind_changed = !current_control_api.enabled
        || current_control_api.address != next_control_api.address
        || current_control_api.port != next_control_api.port;
    if bind_changed {
        let bind = format!("{}:{}", next_control_api.address, next_control_api.port);
        if let Err(error) = QUICListener::probe_tcp_bind(&bind, "control API endpoint") {
            return Some(TransitionRejection::resource_preflight_failed(
                "control API endpoint",
                bind,
                error,
            ));
        }
    }
    None
}

pub(crate) fn validate_metrics_reload_compatibility(
    current: &RuntimeBundle,
    next: &RuntimeBundle,
) -> Option<TransitionRejection> {
    let next_metrics = &next.runtime_config.observability.metrics;
    if !next_metrics.enabled {
        return None;
    }

    let current_metrics = &current.runtime_config.observability.metrics;
    let bind_changed = !current_metrics.enabled
        || current_metrics.address != next_metrics.address
        || current_metrics.port != next_metrics.port;
    if bind_changed {
        let bind = format!("{}:{}", next_metrics.address, next_metrics.port);
        if let Err(error) = QUICListener::probe_tcp_bind(&bind, "metrics endpoint") {
            return Some(TransitionRejection::resource_preflight_failed(
                "metrics endpoint",
                bind,
                error,
            ));
        }
    }
    if next_metrics.allow_non_loopback {
        let Some(listener_config) = next.runtime_config.primary_listener_runtime_config() else {
            return Some(TransitionRejection::raw_resource_message(
                "runtime reload rejected: no effective listeners configured for metrics TLS",
            ));
        };
        if let Err(error) = QUICListener::preflight_control_api_server_tls_config(
            &listener_config,
            &next.runtime_config.observability.control_api,
            Arc::clone(&next.shared_state.shared_services().metrics),
        ) {
            let label = QUICListener::listener_label(&listener_config);
            return Some(TransitionRejection::resource_preflight_failed(
                "metrics TLS",
                label,
                error.to_string(),
            ));
        }
    }
    None
}

pub(crate) fn validate_startup_owned_reload_compatibility(
    current: &RuntimeBundle,
    next: &RuntimeBundle,
) -> Result<(), Vec<TransitionRejection>> {
    let mut authority = ReloadCompatibilityAuthority::new();

    let current_cache_limits = response_cache_storage_limits(&current.runtime_config);
    let next_cache_limits = response_cache_storage_limits(&next.runtime_config);
    authority.note_restart_required_change(
        "upstreams[].cache.max_bytes",
        &current_cache_limits.map(|limits| limits.0),
        &next_cache_limits.map(|limits| limits.0),
    );
    authority.note_restart_required_change(
        "upstreams[].cache.max_entries",
        &current_cache_limits.map(|limits| limits.1),
        &next_cache_limits.map(|limits| limits.1),
    );
    authority.note_restart_required_change(
        "log.file.enabled",
        &current.startup.log_config.file.enabled,
        &next.startup.log_config.file.enabled,
    );
    authority.note_restart_required_change(
        "log.file.path",
        &current.startup.log_config.file.path,
        &next.startup.log_config.file.path,
    );
    authority.note_restart_required_change(
        "log.format",
        &current.startup.log_config.format,
        &next.startup.log_config.format,
    );

    let current_tracing = &current.runtime_config.observability.tracing;
    let next_tracing = &next.runtime_config.observability.tracing;
    authority.note_restart_required_change(
        "observability.tracing.enabled",
        &current_tracing.enabled,
        &next_tracing.enabled,
    );
    authority.note_restart_required_change(
        "observability.tracing.service_name",
        &current_tracing.service_name,
        &next_tracing.service_name,
    );
    authority.note_restart_required_change(
        "observability.tracing.otlp_endpoint",
        &current_tracing.otlp_endpoint,
        &next_tracing.otlp_endpoint,
    );
    authority.note_restart_required_change(
        "observability.tracing.sample_ratio",
        &current_tracing.sample_ratio,
        &next_tracing.sample_ratio,
    );
    authority.note_restart_required_change(
        "performance.control_plane_threads",
        &current.runtime_config.performance.control_plane_threads,
        &next.runtime_config.performance.control_plane_threads,
    );

    authority.into_result()
}
