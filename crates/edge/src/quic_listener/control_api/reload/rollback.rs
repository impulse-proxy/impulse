use std::sync::Arc;

use super::{admin_identity::AdminRole, request_body::ControlApiRuntimeRollbackPayload, *};

impl QUICListener {
    pub(in crate::quic_listener::control_api) async fn handle_control_api_runtime_rollback(
        req: Request<Incoming>,
        state: &crate::quic_listener::runtime_state::ControlApiServiceCtx,
    ) -> Response<Full<Bytes>> {
        let runtime_state = state.current_service_state();
        let authorization_generation = req
            .extensions()
            .get::<super::super::state::ControlApiAuthorizationGeneration>()
            .copied();
        let identity = req.extensions().get::<AdminIdentity>().cloned();
        let request_context = req.extensions().get::<ControlApiRequestContext>().cloned();
        let Some(runtime_bundle_handle) = runtime_state.runtime_bundle_handle().cloned() else {
            return Self::control_api_not_found_response();
        };
        let payload =
            match Self::control_api_json_body::<ControlApiRuntimeRollbackPayload>(req).await {
                Ok(payload) => payload,
                Err(response) => {
                    Self::emit_control_api_audit_event(
                        &runtime_state.security,
                        identity.as_ref(),
                        request_context.as_ref(),
                        AdminAuditEventType::RuntimeRollback,
                        AdminAuditAction::RuntimeRollbackResult,
                        Self::control_api_audit_target_for_route(
                            ControlApiRoute::RuntimeRollback,
                            None,
                        ),
                        AdminAuditGeneration::default(),
                        AdminAuditResult::Failed,
                        Some("invalid_request_body".to_string()),
                    );
                    return *response;
                }
            };
        let current_auth_generation = state.current_service_state().auth_policy_generation();
        let authorization_is_current = authorization_generation
            .is_some_and(|expected| expected.is_current(current_auth_generation));
        if !authorization_is_current {
            return Self::stale_control_api_connection_response();
        }
        if let Some(response) =
            Self::missing_expected_active_generation_response(payload.expected_active_generation)
        {
            return response;
        }
        let current_bundle = runtime_bundle_handle.current_view();
        if let Some(target_bundle) =
            runtime_bundle_handle.rollback_candidate(payload.target_generation)
            && control_api_security_differs(
                &current_bundle
                    .bundle()
                    .runtime_config
                    .observability
                    .control_api,
                &target_bundle.runtime_config.observability.control_api,
            )
            && !identity
                .as_ref()
                .is_some_and(|identity| identity.roles.contains(&AdminRole::Admin))
        {
            return Self::json_response(
                StatusCode::FORBIDDEN,
                json!({
                    "rolled_back": false,
                    "error": "forbidden",
                    "reason": "rollback_changes_control_api_security",
                }),
            );
        }
        let current_generation = runtime_bundle_handle.current_generation();
        Self::emit_control_api_audit_event(
            &runtime_state.security,
            identity.as_ref(),
            request_context.as_ref(),
            AdminAuditEventType::RuntimeRollback,
            AdminAuditAction::RuntimeRollbackAttempt,
            Self::control_api_audit_target_for_route(ControlApiRoute::RuntimeRollback, None),
            AdminAuditGeneration {
                active_generation: Some(current_generation),
                target_generation: Some(payload.target_generation),
                ..Default::default()
            },
            AdminAuditResult::Success,
            payload
                .reason
                .clone()
                .or_else(|| Some("runtime_rollback".to_string())),
        );
        let Some(rollback) = Self::run_control_api_blocking({
            let runtime_bundle_handle = Arc::clone(&runtime_bundle_handle);
            let request = RollbackRequest {
                target_generation: payload.target_generation,
                requested_by: Self::control_api_actor(identity.as_ref()),
                trigger_source: Some("control_api".to_string()),
                reason: payload
                    .reason
                    .or_else(|| Some("runtime_rollback".to_string())),
                expected_active_generation: payload.expected_active_generation,
                requested_at_ms: crate::watchdog::time::now_millis(),
            };
            move || RuntimeSupervisor::rollback_generation(&runtime_bundle_handle, request)
        })
        .await
        else {
            return Self::control_api_internal_error_response();
        };
        Self::record_control_api_rollback_outcome(&runtime_bundle_handle, &rollback);
        Self::emit_control_api_audit_event(
            &runtime_state.security,
            identity.as_ref(),
            request_context.as_ref(),
            AdminAuditEventType::RuntimeRollback,
            AdminAuditAction::RuntimeRollbackResult,
            Self::control_api_audit_target_for_route(ControlApiRoute::RuntimeRollback, None),
            AdminAuditGeneration {
                active_generation: Some(rollback.active_generation),
                target_generation: Some(rollback.request.target_generation),
                candidate_generation: rollback.rolled_back_to,
            },
            if rollback.succeeded() {
                AdminAuditResult::Success
            } else {
                AdminAuditResult::Failed
            },
            Some(
                rollback
                    .primary_rejection_reason()
                    .map(|reason| reason.slug().to_string())
                    .unwrap_or_else(|| rollback.outcome_reason().slug().to_string()),
            ),
        );
        if !rollback.succeeded() {
            return Self::json_response(
                rollback_result_status(&rollback),
                rollback_error_payload(&rollback, rollback_error(&rollback)),
            );
        }
        Self::json_response(StatusCode::ACCEPTED, rollback)
    }

    pub(super) fn record_control_api_rollback_outcome(
        handle: &RuntimeBundleHandle,
        rollback: &RollbackResult,
    ) {
        let current = handle.current_view();
        let metrics = Arc::clone(&current.shared_services().metrics);
        let outcome = rollback.outcome_reason();
        metrics
            .runtime_observations()
            .record_runtime_rollback_outcome(outcome);
        if let Some(reason) = rollback.primary_rejection_reason() {
            metrics
                .runtime_observations()
                .inc_runtime_rejection_reason(reason);
            warn!(
                "runtime rollback rejected active_generation={} target_generation={} reason={} error={}",
                rollback.active_generation,
                rollback.request.target_generation,
                outcome.slug(),
                rollback_error(rollback)
            );
        } else if let Some(rolled_back_to) = rollback.rolled_back_to {
            info!(
                "runtime rollback succeeded active_generation={} rolled_back_to={} reason={}",
                rollback.active_generation,
                rolled_back_to,
                outcome.slug()
            );
        }
    }

    /// Rollback requires an explicit `expected_active_generation` concurrency
    /// precondition; a caller that omits it (or misspells it, or sends
    /// `expected_generation` intended for the activate endpoint) must be
    /// rejected rather than rolling back unconditionally.
    pub(in crate::quic_listener::control_api) fn missing_expected_active_generation_response(
        expected_active_generation: Option<u64>,
    ) -> Option<Response<Full<Bytes>>> {
        if expected_active_generation.is_none() {
            Some(Self::json_response(
                StatusCode::BAD_REQUEST,
                json!({
                    "error": "expected_active_generation is required for runtime rollback",
                }),
            ))
        } else {
            None
        }
    }
}

pub(in crate::quic_listener::control_api) fn control_api_security_differs(
    current: &impulse_config::config::ControlApi,
    target: &impulse_config::config::ControlApi,
) -> bool {
    current.auth_token != target.auth_token
        || current.auth_token_ref != target.auth_token_ref
        || current.tls != target.tls
        || current.auth != target.auth
        || current.authorization != target.authorization
        || current.ip_allowlist != target.ip_allowlist
        || current.audit != target.audit
}

pub(super) fn rollback_result_status(rollback: &RollbackResult) -> StatusCode {
    if rollback
        .rejected_changes
        .iter()
        .any(|rejection| matches!(rejection.kind, RejectedChangeKind::InvalidConfiguration))
    {
        StatusCode::BAD_REQUEST
    } else if rollback.rejected_changes.iter().any(|rejection| {
        matches!(
            rejection.kind,
            RejectedChangeKind::ResourcePreparationFailed
        )
    }) || matches!(
        rollback.status,
        crate::runtime::activation::GenerationStatus::Failed
    ) {
        StatusCode::INTERNAL_SERVER_ERROR
    } else if rollback.rejected_changes.iter().any(|rejection| {
        rejection.kind == RejectedChangeKind::RuntimeStateUnavailable
            && rejection.reason == RuntimeRejectionReason::UnknownGeneration
    }) {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::CONFLICT
    }
}

pub(super) fn rollback_error(rollback: &RollbackResult) -> &str {
    rollback
        .rejected_changes
        .first()
        .map(|rejection| rejection.message.as_str())
        .unwrap_or(rollback.history_entry.summary.as_str())
}

pub(super) fn rollback_error_payload(rollback: &RollbackResult, error: &str) -> serde_json::Value {
    json!({
        "error": error,
        "rejection_reason": rollback.primary_rejection_reason().map(RuntimeRejectionReason::slug),
        "active_generation": rollback.active_generation,
        "target_generation": rollback.request.target_generation,
        "rolled_back_to": rollback.rolled_back_to,
        "status": rollback.status,
        "rejected_changes": rollback.rejected_changes,
        "history_entry": rollback.history_entry,
    })
}
