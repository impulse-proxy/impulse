use std::sync::Arc;

use super::{request_body::ControlApiRuntimePlanRequest, *};

pub(super) enum ControlApiActivationError {
    Response(Box<Response<Full<Bytes>>>),
    Activation(Box<ActivationResult>),
}

impl QUICListener {
    pub(in crate::quic_listener::control_api) async fn handle_control_api_runtime_activate(
        req: Request<Incoming>,
        state: &crate::quic_listener::runtime_state::ControlApiServiceCtx,
    ) -> Response<Full<Bytes>> {
        match Self::perform_control_api_runtime_activation(
            req,
            state,
            ControlApiRoute::RuntimeActivate,
            AdminAuditEventType::RuntimeActivate,
            AdminAuditAction::RuntimeActivateAttempt,
            AdminAuditAction::RuntimeActivateResult,
            "runtime_activate",
        )
        .await
        {
            Ok(activation) => Self::json_response(StatusCode::ACCEPTED, activation),
            Err(ControlApiActivationError::Response(response)) => *response,
            Err(ControlApiActivationError::Activation(activation)) => Self::json_response(
                activation_result_status(&activation),
                activation_error_payload(&activation, activation_error(&activation)),
            ),
        }
    }

    pub(in crate::quic_listener::control_api) async fn handle_control_api_runtime_reload(
        req: Request<Incoming>,
        state: &crate::quic_listener::runtime_state::ControlApiServiceCtx,
    ) -> Response<Full<Bytes>> {
        match Self::perform_control_api_runtime_activation(
            req,
            state,
            ControlApiRoute::ReloadRuntime,
            AdminAuditEventType::RuntimeReload,
            AdminAuditAction::RuntimeReloadAttempt,
            AdminAuditAction::RuntimeReloadResult,
            "runtime_reload",
        )
        .await
        {
            Ok(activation) => {
                let Some(generation) = activation.activated_generation else {
                    return Self::json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        json!({
                            "reloaded": false,
                            "error": "activation succeeded without an activated generation",
                        }),
                    );
                };
                Self::json_response(
                    StatusCode::ACCEPTED,
                    json!({
                        "reloaded": true,
                        "generation": generation,
                        "candidate_generation": activation.history_entry.generation,
                        "status": activation.status,
                    }),
                )
            }
            Err(ControlApiActivationError::Response(response)) => *response,
            Err(ControlApiActivationError::Activation(activation)) => Self::json_response(
                legacy_reload_result_status(&activation),
                legacy_reload_error_payload(&activation, activation_error(&activation)),
            ),
        }
    }

    #[cfg(test)]
    pub(crate) async fn handle_control_api_runtime_reload_without_body_for_tests(
        state: &crate::quic_listener::runtime_state::ControlApiServiceCtx,
        identity: Option<AdminIdentity>,
        request_context: Option<ControlApiRequestContext>,
    ) -> Response<Full<Bytes>> {
        match Self::perform_control_api_runtime_activation_from_plan_request(
            ControlApiRuntimePlanRequest::default(),
            state,
            identity,
            request_context,
            ControlApiRoute::ReloadRuntime,
            AdminAuditEventType::RuntimeReload,
            AdminAuditAction::RuntimeReloadAttempt,
            AdminAuditAction::RuntimeReloadResult,
            "runtime_reload",
        )
        .await
        {
            Ok(activation) => {
                let Some(generation) = activation.activated_generation else {
                    return Self::json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        json!({
                            "reloaded": false,
                            "error": "activation succeeded without an activated generation",
                        }),
                    );
                };
                Self::json_response(
                    StatusCode::ACCEPTED,
                    json!({
                        "reloaded": true,
                        "generation": generation,
                        "candidate_generation": activation.history_entry.generation,
                        "status": activation.status,
                    }),
                )
            }
            Err(ControlApiActivationError::Response(response)) => *response,
            Err(ControlApiActivationError::Activation(activation)) => Self::json_response(
                legacy_reload_result_status(&activation),
                legacy_reload_error_payload(&activation, activation_error(&activation)),
            ),
        }
    }

    async fn perform_control_api_runtime_activation(
        req: Request<Incoming>,
        state: &crate::quic_listener::runtime_state::ControlApiServiceCtx,
        route: ControlApiRoute,
        event_type: AdminAuditEventType,
        attempt_action: AdminAuditAction,
        result_action: AdminAuditAction,
        default_reason: &str,
    ) -> Result<ActivationResult, ControlApiActivationError> {
        let runtime_state = state.current_service_state();
        let authorization_generation = req
            .extensions()
            .get::<super::super::state::ControlApiAuthorizationGeneration>()
            .copied();
        let identity = req.extensions().get::<AdminIdentity>().cloned();
        let request_context = req.extensions().get::<ControlApiRequestContext>().cloned();
        let plan_request =
            Self::control_api_json_body_or_default::<ControlApiRuntimePlanRequest>(req)
                .await
                .map_err(|response| {
                    Self::emit_control_api_audit_event(
                        &runtime_state.security,
                        identity.as_ref(),
                        request_context.as_ref(),
                        event_type,
                        result_action,
                        Self::control_api_audit_target_for_route(route, None),
                        AdminAuditGeneration {
                            active_generation: runtime_state
                                .generation
                                .as_ref()
                                .map(|current| current.generation()),
                            ..Default::default()
                        },
                        AdminAuditResult::Failed,
                        Some("invalid_request_body".to_string()),
                    );
                    ControlApiActivationError::Response(response)
                })?;
        let current_auth_generation = state.current_service_state().auth_policy_generation();
        let authorization_is_current = authorization_generation
            .is_some_and(|expected| expected.is_current(current_auth_generation));
        if !authorization_is_current {
            return Err(ControlApiActivationError::Response(Box::new(
                Self::stale_control_api_connection_response(),
            )));
        }
        if let Some(response) =
            Self::missing_expected_generation_response(route, plan_request.expected_generation)
        {
            return Err(ControlApiActivationError::Response(Box::new(response)));
        }
        Self::perform_control_api_runtime_activation_from_plan_request(
            plan_request,
            state,
            identity,
            request_context,
            route,
            event_type,
            attempt_action,
            result_action,
            default_reason,
        )
        .await
    }

    /// Activation and legacy reload require an explicit `expected_generation`
    /// concurrency precondition; a caller that omits it (or misspells it, or
    /// sends a field only valid on another endpoint) must be rejected rather
    /// than silently defaulting to whatever generation happens to be active
    /// at execution time.
    pub(in crate::quic_listener::control_api) fn missing_expected_generation_response(
        route: ControlApiRoute,
        expected_generation: Option<u64>,
    ) -> Option<Response<Full<Bytes>>> {
        let requires_precondition = matches!(
            route,
            ControlApiRoute::RuntimeActivate | ControlApiRoute::ReloadRuntime
        );
        if requires_precondition && expected_generation.is_none() {
            Some(Self::json_response(
                StatusCode::BAD_REQUEST,
                json!({
                    "error": "expected_generation is required for runtime mutation",
                }),
            ))
        } else {
            None
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn perform_control_api_runtime_activation_from_plan_request(
        plan_request: ControlApiRuntimePlanRequest,
        state: &crate::quic_listener::runtime_state::ControlApiServiceCtx,
        identity: Option<AdminIdentity>,
        request_context: Option<ControlApiRequestContext>,
        route: ControlApiRoute,
        event_type: AdminAuditEventType,
        attempt_action: AdminAuditAction,
        result_action: AdminAuditAction,
        default_reason: &str,
    ) -> Result<ActivationResult, ControlApiActivationError> {
        let runtime_state = state.current_service_state();
        let Some(runtime_bundle_handle) = runtime_state.runtime_bundle_handle().cloned() else {
            return Err(ControlApiActivationError::Response(Box::new(
                Self::control_api_not_found_response(),
            )));
        };
        let Some(runtime) = runtime_state.generation.clone() else {
            return Err(ControlApiActivationError::Response(Box::new(
                Self::json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({
                        "reloaded": false,
                        "error": "runtime generation unavailable",
                    }),
                ),
            )));
        };
        let activation_request = Self::control_api_activation_request(
            &plan_request,
            runtime.generation(),
            default_reason,
            identity.as_ref(),
        );
        let reload_input =
            Self::control_api_reload_config_input(&runtime, plan_request.config_path);
        let config_path = Some(reload_input.source_label().to_string());
        Self::emit_control_api_audit_event(
            &runtime_state.security,
            identity.as_ref(),
            request_context.as_ref(),
            event_type,
            attempt_action,
            Self::control_api_audit_target_for_route(route, config_path.clone()),
            AdminAuditGeneration {
                active_generation: Some(runtime.generation()),
                ..Default::default()
            },
            AdminAuditResult::Success,
            activation_request.reason.clone(),
        );
        Self::record_control_api_activation_attempt(
            &runtime_bundle_handle,
            &activation_request,
            &reload_input,
        );
        let Some(activation) = Self::run_control_api_blocking({
            let runtime_bundle_handle = Arc::clone(&runtime_bundle_handle);
            move || {
                RuntimeActivationService::activate_reload(
                    &runtime_bundle_handle,
                    activation_request,
                    reload_input,
                )
            }
        })
        .await
        else {
            return Err(ControlApiActivationError::Response(Box::new(
                Self::control_api_internal_error_response(),
            )));
        };
        Self::record_control_api_activation_outcome(&runtime_bundle_handle, &activation);
        Self::emit_control_api_audit_event(
            &runtime_state.security,
            identity.as_ref(),
            request_context.as_ref(),
            event_type,
            result_action,
            Self::control_api_audit_target_for_route(route, config_path.clone()),
            AdminAuditGeneration {
                active_generation: Some(activation.active_generation),
                candidate_generation: Some(activation.history_entry.generation),
                target_generation: activation.activated_generation,
            },
            if activation.succeeded() {
                AdminAuditResult::Success
            } else {
                AdminAuditResult::Failed
            },
            Some(control_api_activation_reason(&activation)),
        );
        if let Some((action, result, reason)) = upstream_mtls_material_audit_event(&activation) {
            Self::emit_control_api_audit_event(
                &runtime_state.security,
                identity.as_ref(),
                request_context.as_ref(),
                AdminAuditEventType::UpstreamMtlsMaterial,
                action,
                Self::control_api_audit_target_for_route(route, config_path),
                AdminAuditGeneration {
                    active_generation: Some(activation.active_generation),
                    candidate_generation: Some(activation.history_entry.generation),
                    target_generation: activation.activated_generation,
                },
                result,
                Some(reason),
            );
        }
        if !activation.succeeded() {
            return Err(ControlApiActivationError::Activation(Box::new(activation)));
        }
        Ok(activation)
    }

    pub(super) fn record_control_api_activation_attempt(
        handle: &RuntimeBundleHandle,
        request: &ActivationRequest,
        input: &ReloadConfigInput,
    ) {
        let current = handle.current_view();
        info!(
            "runtime activation requested active_generation={} expected_generation={:?} config_source={} requested_by={:?} trigger_source={:?}",
            current.generation(),
            request.expected_generation,
            input.source_label(),
            request.requested_by,
            request.trigger_source,
        );
    }

    pub(super) fn record_control_api_activation_outcome(
        handle: &RuntimeBundleHandle,
        activation: &ActivationResult,
    ) {
        let current = handle.current_view();
        let metrics = Arc::clone(&current.shared_services().metrics);
        let outcome = activation.outcome_reason();
        metrics
            .runtime_observations()
            .record_runtime_activation_outcome(outcome);
        record_control_api_secret_metrics(current.runtime_config(), metrics.as_ref(), activation);
        if let Some(reason) = activation.primary_rejection_reason() {
            metrics
                .runtime_observations()
                .inc_runtime_rejection_reason(reason);
            warn!(
                "runtime activation rejected active_generation={} candidate_generation={} reason={} error={}",
                activation.active_generation,
                activation.history_entry.generation,
                outcome.slug(),
                activation_error(activation)
            );
        } else if let Some(activated_generation) = activation.activated_generation {
            info!(
                "runtime activation succeeded active_generation={} activated_generation={} reason={}",
                activation.active_generation,
                activated_generation,
                outcome.slug()
            );
        }
    }
}

pub(super) fn activation_result_status(activation: &ActivationResult) -> StatusCode {
    if activation
        .rejected_changes
        .iter()
        .any(|rejection| matches!(rejection.kind, RejectedChangeKind::InvalidConfiguration))
    {
        StatusCode::BAD_REQUEST
    } else if activation.rejected_changes.iter().any(|rejection| {
        matches!(
            rejection.kind,
            RejectedChangeKind::ResourcePreparationFailed
        )
    }) || matches!(
        activation.status,
        crate::runtime::activation::GenerationStatus::Failed
    ) {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::CONFLICT
    }
}

fn activation_error(activation: &ActivationResult) -> &str {
    activation
        .rejected_changes
        .first()
        .map(|rejection| rejection.message.as_str())
        .unwrap_or(activation.history_entry.summary.as_str())
}

fn activation_error_payload(activation: &ActivationResult, error: &str) -> serde_json::Value {
    json!({
        "error": error,
        "reason": control_api_activation_reason(activation),
        "rejection_reason": activation.primary_rejection_reason().map(RuntimeRejectionReason::slug),
        "active_generation": activation.active_generation,
        "candidate_generation": activation.history_entry.generation,
        "status": activation.status,
        "rejected_changes": activation.rejected_changes,
        "history_entry": activation.history_entry,
    })
}

fn legacy_reload_error_payload(activation: &ActivationResult, error: &str) -> serde_json::Value {
    json!({
        "reloaded": false,
        "error": error,
        "reason": control_api_activation_reason(activation),
        "rejection_reason": activation.primary_rejection_reason().map(RuntimeRejectionReason::slug),
        "generation": activation.active_generation,
        "candidate_generation": activation.history_entry.generation,
        "status": activation.status,
    })
}

fn record_control_api_secret_metrics(
    runtime_config: &impulse_config::runtime::RuntimeConfig,
    metrics: &Metrics,
    activation: &ActivationResult,
) {
    let reason = control_api_activation_reason(activation);
    if activation.succeeded() {
        if activation
            .history_entry
            .diff
            .entries
            .iter()
            .any(|entry| entry.secret_material_changed)
        {
            metrics
                .runtime_observations()
                .record_secret_reload("upstreams", "success", &reason);
            if let Some(last_loaded_at_unix_ms) = runtime_config
                .upstreams
                .values()
                .flat_map(|upstream| {
                    let policy = upstream.backend_tls_policy();
                    [
                        policy
                            .client_certificate
                            .as_ref()
                            .map(|metadata| metadata.loaded_at_unix_ms),
                        policy
                            .client_key
                            .as_ref()
                            .map(|metadata| metadata.loaded_at_unix_ms),
                    ]
                })
                .flatten()
                .max()
            {
                metrics
                    .runtime_observations()
                    .set_secret_last_success_unixtime("upstreams", last_loaded_at_unix_ms / 1_000);
            }
        }
        return;
    }

    if matches!(
        classify_upstream_mtls_material_outcome(activation),
        Some(UpstreamMtlsMaterialOutcome::ResolutionFailed | UpstreamMtlsMaterialOutcome::Invalid)
    ) {
        metrics
            .runtime_observations()
            .record_secret_reload("upstreams", "failed", &reason);
    }
    if let Some((provider, resolve_reason)) =
        classify_secret_resolution_failure(activation_error(activation))
    {
        metrics
            .runtime_observations()
            .record_secret_resolve(provider, "failed", resolve_reason);
    }
}

enum UpstreamMtlsMaterialOutcome {
    Changed,
    ResolutionFailed,
    Invalid,
}

impl UpstreamMtlsMaterialOutcome {
    fn slug(&self) -> &'static str {
        match self {
            Self::Changed => "upstream_mtls_material_changed",
            Self::ResolutionFailed => "secret_resolution_failed",
            Self::Invalid => "upstream_mtls_material_invalid",
        }
    }

    fn audit_action(&self) -> AdminAuditAction {
        match self {
            Self::Changed => AdminAuditAction::UpstreamMtlsMaterialChanged,
            Self::ResolutionFailed => AdminAuditAction::SecretResolutionFailed,
            Self::Invalid => AdminAuditAction::UpstreamMtlsMaterialInvalid,
        }
    }
}

fn classify_upstream_mtls_material_outcome(
    activation: &ActivationResult,
) -> Option<UpstreamMtlsMaterialOutcome> {
    if activation.succeeded() {
        return activation
            .history_entry
            .diff
            .entries
            .iter()
            .any(|entry| entry.secret_material_changed)
            .then_some(UpstreamMtlsMaterialOutcome::Changed);
    }

    let error = activation_error(activation);
    if error.contains("secret_resolution_failed") || error.contains("secret resolution failed") {
        return Some(UpstreamMtlsMaterialOutcome::ResolutionFailed);
    }
    if error.contains("tls_material_invalid")
        || error.contains("client_certificate")
        || error.contains("client_key")
    {
        return Some(UpstreamMtlsMaterialOutcome::Invalid);
    }
    None
}

fn classify_secret_resolution_failure(error: &str) -> Option<(&'static str, &str)> {
    if !error.contains("secret resolution failed") {
        return None;
    }

    let provider = if error.contains("file secret resolution failed") {
        "file"
    } else if error.contains("literal secret resolution failed") {
        "literal"
    } else {
        "unknown"
    };
    let reason = error.rsplit_once(':').map(|(_, reason)| reason.trim())?;
    if reason.is_empty() {
        None
    } else {
        Some((provider, reason))
    }
}

fn upstream_mtls_material_audit_event(
    activation: &ActivationResult,
) -> Option<(AdminAuditAction, AdminAuditResult, String)> {
    let outcome = classify_upstream_mtls_material_outcome(activation)?;
    let result = if activation.succeeded() {
        AdminAuditResult::Success
    } else {
        AdminAuditResult::Failed
    };
    Some((outcome.audit_action(), result, outcome.slug().to_string()))
}

fn control_api_activation_reason(activation: &ActivationResult) -> String {
    if let Some(outcome) = classify_upstream_mtls_material_outcome(activation) {
        return outcome.slug().to_string();
    }

    activation
        .primary_rejection_reason()
        .map(|reason| reason.slug().to_string())
        .unwrap_or_else(|| activation.outcome_reason().slug().to_string())
}

pub(super) fn legacy_reload_result_status(activation: &ActivationResult) -> StatusCode {
    if activation
        .rejected_changes
        .iter()
        .any(|rejection| matches!(rejection.kind, RejectedChangeKind::InvalidConfiguration))
    {
        StatusCode::BAD_REQUEST
    } else if activation.rejected_changes.iter().any(|rejection| {
        matches!(
            rejection.kind,
            RejectedChangeKind::ResourcePreparationFailed
                | RejectedChangeKind::RuntimeStateUnavailable
        )
    }) || matches!(
        activation.status,
        crate::runtime::activation::GenerationStatus::Failed
    ) {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::CONFLICT
    }
}
