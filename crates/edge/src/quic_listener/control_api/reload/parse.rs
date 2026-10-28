use std::sync::Arc;

use super::{request_body::ControlApiRuntimePlanRequest, *};

impl QUICListener {
    pub(in crate::quic_listener::control_api) async fn handle_control_api_runtime_validate(
        req: Request<Incoming>,
        state: &crate::quic_listener::runtime_state::ControlApiServiceCtx,
    ) -> Response<Full<Bytes>> {
        let runtime_state = state.current_service_state();
        let identity = req.extensions().get::<AdminIdentity>().cloned();
        let request_context = req.extensions().get::<ControlApiRequestContext>().cloned();
        let Some(runtime_bundle_handle) = runtime_state.runtime_bundle_handle().cloned() else {
            return Self::control_api_not_found_response();
        };
        let current = runtime_bundle_handle.current_view();
        let plan_request =
            match Self::control_api_json_body_or_default::<ControlApiRuntimePlanRequest>(req).await
            {
                Ok(payload) => payload,
                Err(response) => {
                    Self::emit_control_api_audit_event(
                        &runtime_state.security,
                        identity.as_ref(),
                        request_context.as_ref(),
                        AdminAuditEventType::RuntimeValidate,
                        AdminAuditAction::RuntimeValidateResult,
                        Self::control_api_audit_target_for_route(
                            ControlApiRoute::RuntimeValidate,
                            None,
                        ),
                        AdminAuditGeneration {
                            active_generation: Some(current.generation()),
                            ..Default::default()
                        },
                        AdminAuditResult::Failed,
                        Some("invalid_request_body".to_string()),
                    );
                    return *response;
                }
            };
        let activation_request = Self::control_api_activation_request(
            &plan_request,
            current.generation(),
            "runtime_validate",
            identity.as_ref(),
        );
        let reload_input =
            Self::control_api_reload_config_input(&current, plan_request.config_path);
        let config_path = Some(reload_input.source_label().to_string());
        Self::emit_control_api_audit_event(
            &runtime_state.security,
            identity.as_ref(),
            request_context.as_ref(),
            AdminAuditEventType::RuntimeValidate,
            AdminAuditAction::RuntimeValidateAttempt,
            Self::control_api_audit_target_for_route(
                ControlApiRoute::RuntimeValidate,
                config_path.clone(),
            ),
            AdminAuditGeneration {
                active_generation: Some(current.generation()),
                ..Default::default()
            },
            AdminAuditResult::Success,
            activation_request.reason.clone(),
        );
        Self::record_control_api_plan_attempt(
            &runtime_bundle_handle,
            "validate",
            &activation_request,
            &reload_input,
        );
        let Some(plan) = Self::run_control_api_blocking({
            let runtime_bundle_handle = Arc::clone(&runtime_bundle_handle);
            move || {
                RuntimeActivationService::validate_reload(
                    &runtime_bundle_handle,
                    activation_request,
                    reload_input,
                )
            }
        })
        .await
        else {
            return Self::control_api_internal_error_response();
        };
        Self::record_control_api_plan_result(&runtime_bundle_handle, "validate", &plan);
        Self::emit_control_api_audit_event(
            &runtime_state.security,
            identity.as_ref(),
            request_context.as_ref(),
            AdminAuditEventType::RuntimeValidate,
            AdminAuditAction::RuntimeValidateResult,
            Self::control_api_audit_target_for_route(ControlApiRoute::RuntimeValidate, config_path),
            AdminAuditGeneration {
                active_generation: Some(current.generation()),
                candidate_generation: Some(plan.candidate_generation),
                ..Default::default()
            },
            if plan.primary_rejection_reason().is_some() {
                AdminAuditResult::Failed
            } else {
                AdminAuditResult::Success
            },
            plan.primary_rejection_reason()
                .map(|reason| reason.slug().to_string()),
        );
        Self::json_response(StatusCode::OK, plan)
    }

    pub(super) fn control_api_reload_config_input(
        current: &ActiveRuntimeGeneration,
        config_path: Option<String>,
    ) -> ReloadConfigInput {
        ReloadConfigInput::Path {
            path: config_path.unwrap_or_else(|| current.startup().config_path.clone()),
        }
    }

    pub(in crate::quic_listener::control_api) fn control_api_activation_request(
        payload: &ControlApiRuntimePlanRequest,
        current_generation: u64,
        default_reason: &str,
        identity: Option<&AdminIdentity>,
    ) -> ActivationRequest {
        ActivationRequest {
            requested_by: Self::control_api_actor(identity),
            trigger_source: Some("control_api".to_string()),
            reason: payload
                .reason
                .clone()
                .or_else(|| Some(default_reason.to_string())),
            expected_generation: payload.expected_generation.or(Some(current_generation)),
            requested_at_ms: crate::watchdog::time::now_millis(),
        }
    }

    pub(in crate::quic_listener::control_api) fn control_api_actor(
        identity: Option<&AdminIdentity>,
    ) -> Option<String> {
        identity
            .and_then(|identity| identity.actor_id.clone())
            .or_else(|| Some("control_api".to_string()))
    }

    pub(super) fn record_control_api_plan_attempt(
        handle: &RuntimeBundleHandle,
        operation: &str,
        request: &ActivationRequest,
        input: &ReloadConfigInput,
    ) {
        let current = handle.current_view();
        let metrics = Arc::clone(&current.shared_services().metrics);
        match operation {
            "validate" => metrics
                .runtime_observations()
                .inc_runtime_validation_attempt(),
            "preview" => metrics.runtime_observations().inc_runtime_preview_attempt(),
            _ => {}
        }
        info!(
            "runtime {} requested active_generation={} expected_generation={:?} config_source={} requested_by={:?} trigger_source={:?}",
            operation,
            current.generation(),
            request.expected_generation,
            input.source_label(),
            request.requested_by,
            request.trigger_source,
        );
    }

    pub(super) fn record_control_api_plan_result(
        handle: &RuntimeBundleHandle,
        operation: &str,
        plan: &ReloadPlan,
    ) {
        if let Some(reason) = plan.primary_rejection_reason() {
            let current = handle.current_view();
            let metrics = Arc::clone(&current.shared_services().metrics);
            metrics
                .runtime_observations()
                .inc_runtime_rejection_reason(reason);
            warn!(
                "runtime {} rejected generation={} reason={} summary={}",
                operation,
                plan.candidate_generation,
                reason.slug(),
                plan.rejection_summary
                    .as_deref()
                    .unwrap_or(plan.summary.as_str())
            );
        } else {
            info!(
                "runtime {} accepted candidate_generation={} summary={}",
                operation, plan.candidate_generation, plan.summary
            );
        }
    }
}
