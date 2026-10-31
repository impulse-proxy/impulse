use super::{request_body::ControlApiRuntimePlanRequest, *};

impl QUICListener {
    pub(in crate::quic_listener::control_api) async fn handle_control_api_runtime_preview(
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
        let plan_request = match Self::control_api_json_body_or_default::<
            ControlApiRuntimePlanRequest,
        >(req)
        .await
        {
            Ok(payload) => payload,
            Err(response) => {
                Self::emit_control_api_audit_event(
                    &runtime_state.security,
                    identity.as_ref(),
                    request_context.as_ref(),
                    AdminAuditEventType::RuntimePreview,
                    AdminAuditAction::RuntimePreviewResult,
                    Self::control_api_audit_target_for_route(ControlApiRoute::RuntimePreview, None),
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
            "runtime_preview",
            identity.as_ref(),
        );
        let reload_input =
            Self::control_api_reload_config_input(&current, plan_request.config_path);
        let config_path = Some(reload_input.source_label().to_string());
        Self::emit_control_api_audit_event(
            &runtime_state.security,
            identity.as_ref(),
            request_context.as_ref(),
            AdminAuditEventType::RuntimePreview,
            AdminAuditAction::RuntimePreviewAttempt,
            Self::control_api_audit_target_for_route(
                ControlApiRoute::RuntimePreview,
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
            "preview",
            &activation_request,
            &reload_input,
        );
        let Some(plan) = Self::run_control_api_blocking({
            let runtime_bundle_handle = Arc::clone(&runtime_bundle_handle);
            move || {
                RuntimeSupervisor::preview_reload(
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
        Self::record_control_api_plan_result(&runtime_bundle_handle, "preview", &plan);
        Self::emit_control_api_audit_event(
            &runtime_state.security,
            identity.as_ref(),
            request_context.as_ref(),
            AdminAuditEventType::RuntimePreview,
            AdminAuditAction::RuntimePreviewResult,
            Self::control_api_audit_target_for_route(ControlApiRoute::RuntimePreview, config_path),
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
}
