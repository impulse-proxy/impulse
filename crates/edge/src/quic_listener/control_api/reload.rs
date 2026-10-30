use bytes::Bytes;
#[cfg(test)]
use http_body_util::BodyExt;
use http_body_util::Full;

#[cfg(test)]
use self::{
    activate::{activation_result_status, legacy_reload_result_status},
    request_body::MAX_CONTROL_API_JSON_BODY_BYTES,
    rollback::rollback_result_status,
};
use super::{
    admin_auth::ControlApiRoute,
    admin_identity::{AdminIdentity, ControlApiRequestContext},
    audit::{AdminAuditAction, AdminAuditEventType, AdminAuditGeneration, AdminAuditResult},
    security::ControlApiSecurityPolicy,
    *,
};
use crate::runtime::{
    activation::{
        ActivationRequest, ActivationResult, RejectedChangeKind, ReloadConfigInput, ReloadPlan,
        RollbackRequest, RollbackResult, RuntimeActivationService, RuntimeRejectionReason,
    },
    bundle::{ActiveRuntimeGeneration, RuntimeBundleHandle},
    cache::response_cache_storage_limits,
    policy::{ReloadCompatibilityAuthority, TransitionRejection},
    tls::lifecycle::{
        record_listener_tls_inventory, rotate_listener_tls_material, stage_listener_tls_rotation,
    },
};

mod activate;
mod parse;
mod preview;
pub(super) mod request_body;
pub(super) mod rollback;

impl QUICListener {
    pub(super) fn reload_listener_certs(
        listener_runtime_configs: &HashMap<String, ListenerRuntimeConfig>,
        listener_tls_store: &ListenerTlsReloadStore,
        metrics: &Metrics,
    ) -> Response<Full<Bytes>> {
        let staged_rotation = stage_listener_tls_rotation(
            listener_runtime_configs,
            Self::build_listener_tls_reload_state,
        );
        let failures = staged_rotation
            .failures
            .into_iter()
            .map(|(listener, error)| {
                json!({
                    "listener": listener,
                    "status": "failed",
                    "reason": "listener_tls_invalid",
                    "error": error.to_string(),
                })
            })
            .collect::<Vec<_>>();
        let staged = staged_rotation.states;

        if !failures.is_empty() {
            metrics
                .runtime_observations()
                .record_control_plane_cert_reload("failed", "cert_reload_failed");
            metrics.runtime_observations().record_secret_reload(
                "listeners",
                "failed",
                "cert_reload_failed",
            );
            return Self::json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "reloaded": false,
                    "reason": "cert_reload_failed",
                    "listeners": failures,
                }),
            );
        }

        let generations = match rotate_listener_tls_material(listener_tls_store, &staged) {
            Ok(generations) => generations,
            Err(err) => {
                metrics
                    .runtime_observations()
                    .record_control_plane_cert_reload("failed", "cert_reload_failed");
                metrics.runtime_observations().record_secret_reload(
                    "listeners",
                    "failed",
                    "cert_reload_failed",
                );
                return Self::json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({
                        "reloaded": false,
                        "reason": "cert_reload_failed",
                        "error": err.to_string(),
                    }),
                );
            }
        };

        let mut reloaded = Vec::with_capacity(staged.len());
        let mut last_loaded_at_unix_ms = 0u64;
        for (listener_label, reloaded_state) in staged {
            record_listener_tls_inventory(metrics, &listener_label, &reloaded_state.inventory);
            last_loaded_at_unix_ms = last_loaded_at_unix_ms.max(reloaded_state.loaded_at_unix_ms);
            reloaded.push(json!({
                "listener": listener_label,
                "status": reloaded_state.last_reload_status,
                "loaded_at_unix_ms": reloaded_state.loaded_at_unix_ms,
                "generation": generations.get(&listener_label).copied().unwrap_or(0),
                "default_cert_not_after_unix_seconds": reloaded_state
                    .inventory
                    .default_identity
                    .metadata
                    .not_after_unix_seconds,
            }));
        }
        if last_loaded_at_unix_ms > 0 {
            metrics
                .runtime_observations()
                .set_secret_last_success_unixtime("listeners", last_loaded_at_unix_ms / 1_000);
        }
        metrics
            .runtime_observations()
            .record_control_plane_cert_reload("success", "cert_reload_applied");
        metrics.runtime_observations().record_secret_reload(
            "listeners",
            "success",
            "cert_reload_applied",
        );

        Self::json_response(
            StatusCode::ACCEPTED,
            json!({
                "reloaded": true,
                "reason": "cert_reload_applied",
                "listener_count": reloaded.len(),
                "listeners": reloaded,
            }),
        )
    }

    pub(super) fn handle_control_api_reload_certs(
        state: &crate::quic_listener::runtime_state::ControlApiServiceCtx,
        identity: Option<AdminIdentity>,
        request_context: Option<ControlApiRequestContext>,
    ) -> Response<Full<Bytes>> {
        let runtime_state = state.current_service_state();
        let active_generation = runtime_state
            .generation
            .as_ref()
            .map(|current| current.generation());
        Self::emit_control_api_audit_event(
            &runtime_state.security,
            identity.as_ref(),
            request_context.as_ref(),
            AdminAuditEventType::CertReload,
            AdminAuditAction::CertReloadAttempt,
            Self::control_api_audit_target_for_route(ControlApiRoute::ReloadCerts, None),
            AdminAuditGeneration {
                active_generation,
                ..Default::default()
            },
            AdminAuditResult::Success,
            Some("requested".to_string()),
        );
        let live_tls_store = runtime_state.listener_tls_store();
        let live_listener_configs = runtime_state.listener_runtime_configs();
        let live_metrics = runtime_state.metrics();
        let response = Self::reload_listener_certs(
            live_listener_configs.as_ref(),
            live_tls_store.as_ref(),
            live_metrics.as_ref(),
        );
        let succeeded = response.status().is_success();
        Self::emit_control_api_audit_event(
            &runtime_state.security,
            identity.as_ref(),
            request_context.as_ref(),
            AdminAuditEventType::CertReload,
            if succeeded {
                AdminAuditAction::CertReloadApplied
            } else {
                AdminAuditAction::CertReloadResult
            },
            Self::control_api_audit_target_for_route(ControlApiRoute::ReloadCerts, None),
            AdminAuditGeneration {
                active_generation,
                ..Default::default()
            },
            if succeeded {
                AdminAuditResult::Success
            } else {
                AdminAuditResult::Failed
            },
            Some(if succeeded {
                "cert_reload_applied".to_string()
            } else {
                "cert_reload_failed".to_string()
            }),
        );
        response
    }

    pub(super) fn handle_control_api_restart(
        state: &crate::quic_listener::runtime_state::ControlApiServiceCtx,
        identity: Option<AdminIdentity>,
        request_context: Option<ControlApiRequestContext>,
    ) -> Response<Full<Bytes>> {
        let runtime_state = state.current_service_state();
        let active_generation = runtime_state
            .generation
            .as_ref()
            .map(|current| current.generation());
        Self::emit_control_api_audit_event(
            &runtime_state.security,
            identity.as_ref(),
            request_context.as_ref(),
            AdminAuditEventType::RuntimeRestart,
            AdminAuditAction::RuntimeRestartAttempt,
            Self::control_api_audit_target_for_route(ControlApiRoute::Restart, None),
            AdminAuditGeneration {
                active_generation,
                ..Default::default()
            },
            AdminAuditResult::Success,
            Some("requested".to_string()),
        );
        let watchdog = runtime_state.watchdog();
        if !watchdog.enabled() {
            Self::emit_control_api_audit_event(
                &runtime_state.security,
                identity.as_ref(),
                request_context.as_ref(),
                AdminAuditEventType::RuntimeRestart,
                AdminAuditAction::RuntimeRestartResult,
                Self::control_api_audit_target_for_route(ControlApiRoute::Restart, None),
                AdminAuditGeneration {
                    active_generation,
                    ..Default::default()
                },
                AdminAuditResult::Failed,
                Some("watchdog_disabled".to_string()),
            );
            return Self::json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({
                    "accepted": false,
                    "error": "watchdog disabled",
                }),
            );
        }

        let accepted = watchdog.request_restart("admin_runtime_api");
        Self::emit_control_api_audit_event(
            &runtime_state.security,
            identity.as_ref(),
            request_context.as_ref(),
            AdminAuditEventType::RuntimeRestart,
            AdminAuditAction::RuntimeRestartResult,
            Self::control_api_audit_target_for_route(ControlApiRoute::Restart, None),
            AdminAuditGeneration {
                active_generation,
                ..Default::default()
            },
            if accepted {
                AdminAuditResult::Success
            } else {
                AdminAuditResult::Failed
            },
            Some(if accepted {
                "restart_requested".to_string()
            } else {
                "restart_pending_or_cooldown_active".to_string()
            }),
        );
        Self::json_response(
            if accepted {
                StatusCode::ACCEPTED
            } else {
                StatusCode::CONFLICT
            },
            json!({
                "accepted": accepted,
                "restart_requested": watchdog.restart_requested(),
                "reason": if accepted { "admin_runtime_api" } else { "restart pending or cooldown active" },
            }),
        )
    }

    pub(crate) fn evaluate_runtime_reload_compatibility(
        current: &ActiveRuntimeGeneration,
        next: &RuntimeBundle,
    ) -> Result<(), Vec<TransitionRejection>> {
        if let Some(rejection) = Self::validate_runtime_reload_compatibility(current.bundle(), next)
        {
            return Err(vec![rejection]);
        }
        if let Some(rejection) =
            Self::validate_control_api_reload_compatibility(current.bundle(), next)
        {
            return Err(vec![rejection]);
        }
        if let Some(rejection) = Self::validate_metrics_reload_compatibility(current.bundle(), next)
        {
            return Err(vec![rejection]);
        }
        Self::validate_startup_owned_reload_compatibility(current.bundle(), next)
    }

    pub(super) fn validate_runtime_reload_compatibility(
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
            if let Err(err) = Self::build_listener_tls_reload_state(listener_config) {
                return Some(TransitionRejection::resource_preflight_failed(
                    "Pingora listener TLS",
                    label,
                    err.to_string(),
                ));
            }
            if current_listeners.contains_key(label) {
                continue;
            }
            let worker_count = listener_config.performance.worker_threads.max(1);
            if worker_count > 1 {
                if let Err(err) = Self::bind_reuseport_sockets(listener_config, worker_count) {
                    return Some(TransitionRejection::resource_preflight_failed(
                        "QUIC listener",
                        label,
                        err.to_string(),
                    ));
                }
            } else if let Err(err) = Self::bind_socket(listener_config, false) {
                return Some(TransitionRejection::resource_preflight_failed(
                    "QUIC listener",
                    label,
                    err.to_string(),
                ));
            }

            let bind = format!(
                "{}:{}",
                listener_config.listen.listen.address, listener_config.listen.listen.port
            );
            if let Err(err) = Self::probe_tcp_bind(&bind, "Pingora listener") {
                return Some(TransitionRejection::resource_preflight_failed(
                    "Pingora listener",
                    label,
                    err,
                ));
            }
        }
        None
    }

    pub(super) fn validate_control_api_reload_compatibility(
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
        let primary_listener_label = Self::listener_label(&listener_config);
        if next
            .shared_state
            .shared_services()
            .listener_tls_store
            .certificate_resolver(&primary_listener_label)
            .is_none()
        {
            return Some(TransitionRejection::raw_resource_message(format!(
                "runtime reload rejected: control API TLS config missing for listener '{}'",
                primary_listener_label
            )));
        }

        let security = ControlApiSecurityPolicy::from_config(
            next_control_api,
            Arc::clone(&next.shared_state.shared_services().metrics),
        );
        if let Err(err) =
            Self::build_control_api_server_tls_config(&listener_config, &security.client_auth)
        {
            return Some(TransitionRejection::resource_preflight_failed(
                "control API TLS",
                primary_listener_label,
                err.to_string(),
            ));
        }

        let current_control_api = &current.runtime_config.observability.control_api;
        let bind_changed = !current_control_api.enabled
            || current_control_api.address != next_control_api.address
            || current_control_api.port != next_control_api.port;
        if bind_changed {
            let bind = format!("{}:{}", next_control_api.address, next_control_api.port);
            if let Err(err) = Self::probe_tcp_bind(&bind, "control API endpoint") {
                return Some(TransitionRejection::resource_preflight_failed(
                    "control API endpoint",
                    bind,
                    err,
                ));
            }
        }
        None
    }

    pub(super) fn validate_metrics_reload_compatibility(
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
            if let Err(err) = Self::probe_tcp_bind(&bind, "metrics endpoint") {
                return Some(TransitionRejection::resource_preflight_failed(
                    "metrics endpoint",
                    bind,
                    err,
                ));
            }
        }
        if next_metrics.allow_non_loopback {
            let Some(listener_config) = next.runtime_config.primary_listener_runtime_config()
            else {
                return Some(TransitionRejection::raw_resource_message(
                    "runtime reload rejected: no effective listeners configured for metrics TLS",
                ));
            };
            let security = ControlApiSecurityPolicy::from_config(
                &next.runtime_config.observability.control_api,
                Arc::clone(&next.shared_state.shared_services().metrics),
            );
            let label = Self::listener_label(&listener_config);
            if let Err(err) =
                Self::build_control_api_server_tls_config(&listener_config, &security.client_auth)
            {
                return Some(TransitionRejection::resource_preflight_failed(
                    "metrics TLS",
                    label,
                    err.to_string(),
                ));
            }
        }
        None
    }

    pub(super) fn validate_startup_owned_reload_compatibility(
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

        let current_perf = &current.runtime_config.performance;
        let next_perf = &next.runtime_config.performance;
        authority.note_restart_required_change(
            "performance.control_plane_threads",
            &current_perf.control_plane_threads,
            &next_perf.control_plane_threads,
        );

        authority.into_result()
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};

    use super::*;
    use crate::runtime::activation::{
        ActivationRequest, GenerationHistoryEntry, GenerationOperation, GenerationStatus,
        RejectedChange, RejectedChangeKind, ReloadDiff, RollbackRequest,
    };

    fn rejected_change(reason: RuntimeRejectionReason, kind: RejectedChangeKind) -> RejectedChange {
        RejectedChange {
            reason,
            kind,
            field_path: None,
            current_value: None,
            requested_value: None,
            operator_action: "retry".to_string(),
            active_generation_changed: false,
            message: "rejected".to_string(),
        }
    }

    fn history_entry(
        operation: GenerationOperation,
        status: GenerationStatus,
    ) -> GenerationHistoryEntry {
        GenerationHistoryEntry {
            generation: 2,
            operation,
            status,
            config_source: "config.yaml".to_string(),
            config_version: Some(1),
            requested_by: Some("test".to_string()),
            trigger_source: Some("unit_test".to_string()),
            requested_at_ms: 1,
            completed_at_ms: Some(2),
            summary: "summary".to_string(),
            diff: ReloadDiff::default(),
            rejected_changes: Vec::new(),
        }
    }

    #[test]
    fn activation_status_maps_stale_generation_conflicts_to_conflict() {
        let activation = ActivationResult {
            request: ActivationRequest {
                requested_by: Some("test".to_string()),
                trigger_source: Some("unit_test".to_string()),
                reason: Some("runtime_activate".to_string()),
                expected_generation: Some(1),
                requested_at_ms: 1,
            },
            active_generation: 3,
            activated_generation: None,
            status: GenerationStatus::Rejected,
            rejected_changes: vec![rejected_change(
                RuntimeRejectionReason::UnknownGeneration,
                RejectedChangeKind::IllegalTransition,
            )],
            history_entry: history_entry(GenerationOperation::Activate, GenerationStatus::Rejected),
        };

        assert_eq!(activation_result_status(&activation), StatusCode::CONFLICT);
        assert_eq!(
            legacy_reload_result_status(&activation),
            StatusCode::CONFLICT
        );
    }

    #[test]
    fn rollback_status_maps_missing_target_to_not_found() {
        let rollback = RollbackResult {
            request: RollbackRequest {
                target_generation: 9,
                requested_by: Some("test".to_string()),
                trigger_source: Some("unit_test".to_string()),
                reason: Some("runtime_rollback".to_string()),
                expected_active_generation: Some(3),
                requested_at_ms: 1,
            },
            active_generation: 3,
            rolled_back_to: None,
            status: GenerationStatus::Rejected,
            rejected_changes: vec![rejected_change(
                RuntimeRejectionReason::UnknownGeneration,
                RejectedChangeKind::RuntimeStateUnavailable,
            )],
            history_entry: history_entry(GenerationOperation::Rollback, GenerationStatus::Rejected),
        };

        assert_eq!(rollback_result_status(&rollback), StatusCode::NOT_FOUND);
    }

    #[test]
    fn rollback_status_keeps_other_operator_conflicts_as_conflict() {
        let rollback = RollbackResult {
            request: RollbackRequest {
                target_generation: 3,
                requested_by: Some("test".to_string()),
                trigger_source: Some("unit_test".to_string()),
                reason: Some("runtime_rollback".to_string()),
                expected_active_generation: Some(3),
                requested_at_ms: 1,
            },
            active_generation: 3,
            rolled_back_to: None,
            status: GenerationStatus::Rejected,
            rejected_changes: vec![rejected_change(
                RuntimeRejectionReason::RollbackNotAllowed,
                RejectedChangeKind::RuntimeStateUnavailable,
            )],
            history_entry: history_entry(GenerationOperation::Rollback, GenerationStatus::Rejected),
        };

        assert_eq!(rollback_result_status(&rollback), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn control_api_json_body_bounded_rejects_oversized_payload() {
        let oversized = vec![b'a'; MAX_CONTROL_API_JSON_BODY_BYTES + 1];

        let response =
            QUICListener::collect_control_api_json_body_bounded(Full::new(Bytes::from(oversized)))
                .await
                .expect_err("oversized control-plane JSON body must be rejected");
        let response = *response;

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("collect error response body")
            .to_bytes();
        let payload: serde_json::Value =
            serde_json::from_slice(&body).expect("oversize error response json");
        assert_eq!(
            payload["error"],
            serde_json::Value::String(format!(
                "request body exceeded {} bytes",
                MAX_CONTROL_API_JSON_BODY_BYTES
            ))
        );
    }
}
