use super::{
    admin_auth::ControlApiRoute,
    admin_identity::{AdminIdentity, ControlApiRequestContext},
    audit::{AdminAuditAction, AdminAuditEventType, AdminAuditGeneration, AdminAuditResult},
    state::ControlApiState,
    *,
};

impl Http3Service {
    pub(super) async fn handle_control_api_request(
        mut req: Request<Incoming>,
        state: &ControlApiState,
    ) -> Response<http_body_util::Full<bytes::Bytes>> {
        let route = match Self::gate_control_api_request(&mut req, state) {
            Ok(route) => route,
            Err(response) => return *response,
        };
        let authorization_generation = state.current_service_state().auth_policy_generation();
        req.extensions_mut()
            .insert(super::state::ControlApiAuthorizationGeneration {
                runtime: authorization_generation.0,
                listener_tls: authorization_generation.1,
            });
        let identity = req.extensions().get::<AdminIdentity>().cloned();
        let request_context = req.extensions().get::<ControlApiRequestContext>().cloned();
        let service_state = state.current_service_state();
        let active_generation = service_state
            .generation()
            .map(|current| current.generation());
        match route {
            ControlApiRoute::Health => Self::render_control_api_health(state),
            ControlApiRoute::Ready => Self::render_control_api_ready(state),
            ControlApiRoute::Runtime => {
                Self::emit_control_api_audit_event(
                    &service_state.security,
                    identity.as_ref(),
                    request_context.as_ref(),
                    AdminAuditEventType::RuntimeSnapshot,
                    AdminAuditAction::RuntimeSnapshotRead,
                    Self::control_api_audit_target_for_route(route, None),
                    AdminAuditGeneration {
                        active_generation,
                        ..Default::default()
                    },
                    AdminAuditResult::Success,
                    None,
                );
                Self::render_control_api_runtime_snapshot(state)
            }
            ControlApiRoute::RuntimeValidate => {
                Self::handle_control_api_runtime_validate(req, state).await
            }
            ControlApiRoute::RuntimePreview => {
                Self::handle_control_api_runtime_preview(req, state).await
            }
            ControlApiRoute::RuntimeActivate => {
                Self::handle_control_api_runtime_activate(req, state).await
            }
            ControlApiRoute::ReloadRuntime => {
                Self::handle_control_api_runtime_reload(req, state).await
            }
            ControlApiRoute::RuntimeRollback => {
                Self::handle_control_api_runtime_rollback(req, state).await
            }
            ControlApiRoute::RuntimeHistory => {
                Self::emit_control_api_audit_event(
                    &service_state.security,
                    identity.as_ref(),
                    request_context.as_ref(),
                    AdminAuditEventType::RuntimeSnapshot,
                    AdminAuditAction::RuntimeSnapshotRead,
                    Self::control_api_audit_target_for_route(route, None),
                    AdminAuditGeneration {
                        active_generation,
                        ..Default::default()
                    },
                    AdminAuditResult::Success,
                    None,
                );
                Self::render_control_api_runtime_history(state)
            }
            ControlApiRoute::RuntimeHistoryGeneration(generation) => {
                Self::emit_control_api_audit_event(
                    &service_state.security,
                    identity.as_ref(),
                    request_context.as_ref(),
                    AdminAuditEventType::RuntimeSnapshot,
                    AdminAuditAction::RuntimeSnapshotRead,
                    Self::control_api_audit_target_for_route(route, None),
                    AdminAuditGeneration {
                        active_generation,
                        target_generation: Some(generation),
                        ..Default::default()
                    },
                    AdminAuditResult::Success,
                    None,
                );
                Self::render_control_api_runtime_history_generation(state, generation)
            }
            ControlApiRoute::ReloadCerts => {
                Self::handle_control_api_reload_certs(state, identity, request_context)
            }
            ControlApiRoute::Restart => {
                Self::handle_control_api_restart(state, identity, request_context)
            }
        }
    }
}
