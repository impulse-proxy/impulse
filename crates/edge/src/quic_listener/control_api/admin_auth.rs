use ::http::{Method, header};
use bytes::Bytes;
use http_body_util::Full;

use super::{
    admin_identity::{AdminIdentity, AdminRole, ControlApiRequestContext},
    audit::AdminAuditResult,
    security::{
        ControlApiSecurityPolicy, ControlApiSourcePolicyDecision, SourceIpExtractionError,
        source_ip_from_request,
    },
    state::{ControlApiPaths, ControlApiState},
    *,
};

type ControlApiGateError = Box<Response<Full<Bytes>>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ControlApiRoute {
    Health,
    Ready,
    Runtime,
    RuntimeValidate,
    RuntimePreview,
    RuntimeActivate,
    RuntimeRollback,
    RuntimeHistory,
    RuntimeHistoryGeneration(u64),
    ReloadCerts,
    ReloadRuntime,
    Restart,
}

impl ControlApiRoute {
    fn minimum_role(self, security: &ControlApiSecurityPolicy) -> Option<AdminRole> {
        match self {
            Self::Health => security
                .authorization
                .protect_health
                .then_some(AdminRole::from(security.authorization.runtime_read_role)),
            Self::Ready => security
                .authorization
                .protect_ready
                .then_some(AdminRole::from(security.authorization.runtime_read_role)),
            Self::Runtime | Self::RuntimeHistory | Self::RuntimeHistoryGeneration(_) => {
                Some(AdminRole::from(security.authorization.runtime_read_role))
            }
            Self::RuntimeValidate
            | Self::RuntimePreview
            | Self::RuntimeActivate
            | Self::RuntimeRollback
            | Self::ReloadCerts
            | Self::ReloadRuntime => {
                Some(AdminRole::from(security.authorization.runtime_mutate_role))
            }
            Self::Restart => Some(AdminRole::from(security.authorization.restart_role)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum AuthorizationDecision {
    Allow {
        route: ControlApiRoute,
        identity: Option<AdminIdentity>,
    },
    Deny {
        status: StatusCode,
        error: &'static str,
        reason: &'static str,
        required_role: Option<AdminRole>,
        identity: Option<AdminIdentity>,
        route: ControlApiRoute,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AuthenticationOutcome {
    Authenticated(AdminIdentity),
    Missing,
    Invalid(&'static str),
}

impl Http3Service {
    pub(super) fn control_api_request_route_for<B>(
        req: &::http::Request<B>,
        paths: &ControlApiPaths,
    ) -> Option<ControlApiRoute> {
        let path = req.uri().path();
        let runtime_validate_path = paths.runtime_validate_path();
        let runtime_preview_path = paths.runtime_preview_path();
        let runtime_activate_path = paths.runtime_activate_path();
        let runtime_rollback_path = paths.runtime_rollback_path();
        let runtime_history_path = paths.runtime_history_path();
        let runtime_history_entry_prefix = paths.runtime_history_entry_prefix();

        match *req.method() {
            Method::GET if path == paths.health_path.as_str() => Some(ControlApiRoute::Health),
            Method::GET if path == paths.ready_path.as_str() => Some(ControlApiRoute::Ready),
            Method::GET if path == paths.runtime_path.as_str() => Some(ControlApiRoute::Runtime),
            Method::GET if path == runtime_history_path.as_str() => {
                Some(ControlApiRoute::RuntimeHistory)
            }
            Method::GET if path.starts_with(runtime_history_entry_prefix.as_str()) => path
                .strip_prefix(runtime_history_entry_prefix.as_str())
                .and_then(|raw_generation| raw_generation.parse::<u64>().ok())
                .map(ControlApiRoute::RuntimeHistoryGeneration),
            Method::POST if path == paths.reload_certs_path.as_str() => {
                Some(ControlApiRoute::ReloadCerts)
            }
            Method::POST if path == runtime_validate_path.as_str() => {
                Some(ControlApiRoute::RuntimeValidate)
            }
            Method::POST if path == runtime_preview_path.as_str() => {
                Some(ControlApiRoute::RuntimePreview)
            }
            Method::POST if path == runtime_activate_path.as_str() => {
                Some(ControlApiRoute::RuntimeActivate)
            }
            Method::POST if path == runtime_rollback_path.as_str() => {
                Some(ControlApiRoute::RuntimeRollback)
            }
            Method::POST if path == paths.reload_path.as_str() => {
                Some(ControlApiRoute::ReloadRuntime)
            }
            Method::POST if path == paths.restart_path.as_str() => Some(ControlApiRoute::Restart),
            _ => None,
        }
    }

    pub(super) fn bearer_token_from_authorization_header(raw: &str) -> Option<&str> {
        let raw = raw.trim();
        let split = raw.find(char::is_whitespace)?;
        let (scheme, rest) = raw.split_at(split);
        if !scheme.eq_ignore_ascii_case("bearer") {
            return None;
        }
        let token = rest.trim_start();
        if token.is_empty() {
            return None;
        }
        Some(token)
    }

    fn authenticate_control_api_request<B>(
        req: &::http::Request<B>,
        security: &ControlApiSecurityPolicy,
    ) -> AuthenticationOutcome {
        let request_ctx = req.extensions().get::<ControlApiRequestContext>().cloned();
        if matches!(
            security.client_auth.mode,
            impulse_config::config::ControlApiClientAuthMode::Required
        ) && request_ctx
            .as_ref()
            .and_then(|context| context.mtls_identity.as_ref())
            .is_none()
        {
            return AuthenticationOutcome::Missing;
        }
        let token_match = match req.headers().get(header::AUTHORIZATION) {
            Some(value) => {
                let Ok(raw) = value.to_str() else {
                    return AuthenticationOutcome::Invalid("invalid_authorization_header");
                };
                let Some(provided) = Self::bearer_token_from_authorization_header(raw) else {
                    return AuthenticationOutcome::Invalid("invalid_bearer_token");
                };
                match Self::control_api_token_match(provided, security) {
                    Some(token) => Some(token),
                    None => return AuthenticationOutcome::Invalid("invalid_bearer_token"),
                }
            }
            None => None,
        };

        let has_bearer = token_match.is_some();
        let has_mtls = request_ctx
            .as_ref()
            .and_then(|context| context.mtls_identity.as_ref())
            .is_some();
        match Self::build_admin_identity(
            request_ctx,
            token_match,
            security.identity_source.as_ref(),
        ) {
            Some(identity) => AuthenticationOutcome::Authenticated(identity),
            None if has_bearer && has_mtls => {
                AuthenticationOutcome::Invalid("conflicting_authentication_principals")
            }
            None => AuthenticationOutcome::Missing,
        }
    }

    #[cfg(test)]
    pub(super) fn control_api_is_authorized_for<B>(
        req: &::http::Request<B>,
        security: &ControlApiSecurityPolicy,
    ) -> bool {
        matches!(
            Self::authenticate_control_api_request(req, security),
            AuthenticationOutcome::Authenticated(_)
        )
    }

    fn authorize_control_api_request_for<B>(
        req: &mut ::http::Request<B>,
        state: &ControlApiState,
        route: ControlApiRoute,
    ) -> Result<(), ControlApiGateError> {
        let service_state = state.current_service_state();
        let request_context = req.extensions().get::<ControlApiRequestContext>().cloned();
        let active_generation = service_state
            .generation
            .as_ref()
            .map(|current| current.generation());
        Self::enforce_control_api_source_policy(
            req,
            &service_state.security,
            route,
            active_generation,
        )?;
        let Some(required_role) = route.minimum_role(&service_state.security) else {
            return Ok(());
        };

        // Authentication throttling is keyed to the transport peer, never to
        // request headers. Trusted forwarding headers remain relevant to the
        // source allowlist below, but allowing them to select the throttle key
        // lets one client rotate spoofed addresses to bypass brute-force
        // protection. Authenticate before applying the failure budget so a
        // valid principal behind a shared proxy can still recover access.
        let throttle_ip = request_context
            .as_ref()
            .map(|context| context.peer_addr.ip());

        let decision = match Self::authenticate_control_api_request(req, &service_state.security) {
            AuthenticationOutcome::Missing => {
                if throttle_ip.is_some_and(|ip| service_state.auth_throttle.is_blocked(ip)) {
                    AuthorizationDecision::Deny {
                        status: StatusCode::TOO_MANY_REQUESTS,
                        error: "too_many_requests",
                        reason: "authentication_throttled",
                        required_role: Some(required_role),
                        identity: None,
                        route,
                    }
                } else {
                    if let Some(ip) = throttle_ip {
                        service_state.auth_throttle.record_failure(ip);
                    }
                    AuthorizationDecision::Deny {
                        status: StatusCode::UNAUTHORIZED,
                        error: "unauthorized",
                        reason: "missing_authentication",
                        required_role: Some(required_role),
                        identity: None,
                        route,
                    }
                }
            }
            AuthenticationOutcome::Invalid(reason) => {
                if throttle_ip.is_some_and(|ip| service_state.auth_throttle.is_blocked(ip)) {
                    AuthorizationDecision::Deny {
                        status: StatusCode::TOO_MANY_REQUESTS,
                        error: "too_many_requests",
                        reason: "authentication_throttled",
                        required_role: Some(required_role),
                        identity: None,
                        route,
                    }
                } else {
                    if let Some(ip) = throttle_ip {
                        service_state.auth_throttle.record_failure(ip);
                    }
                    AuthorizationDecision::Deny {
                        status: StatusCode::UNAUTHORIZED,
                        error: "unauthorized",
                        reason,
                        required_role: Some(required_role),
                        identity: None,
                        route,
                    }
                }
            }
            AuthenticationOutcome::Authenticated(identity) => {
                if let Some(ip) = throttle_ip {
                    service_state.auth_throttle.record_success(ip);
                }
                Self::emit_control_api_auth_audit_event(
                    &service_state.security,
                    Some(&identity),
                    request_context.as_ref(),
                    route,
                    active_generation,
                    AdminAuditResult::Success,
                    "authenticated",
                );
                let authorized = identity.roles.iter().any(|role| *role >= required_role);
                if authorized {
                    AuthorizationDecision::Allow {
                        route,
                        identity: Some(identity),
                    }
                } else {
                    AuthorizationDecision::Deny {
                        status: StatusCode::FORBIDDEN,
                        error: "forbidden",
                        reason: "insufficient_role",
                        required_role: Some(required_role),
                        identity: Some(identity),
                        route,
                    }
                }
            }
        };

        match decision {
            AuthorizationDecision::Allow { identity, .. } => {
                if let Some(identity) = identity {
                    req.extensions_mut().insert(identity);
                }
                Ok(())
            }
            AuthorizationDecision::Deny {
                status,
                error,
                reason,
                identity,
                required_role,
                route,
            } => {
                if status == StatusCode::UNAUTHORIZED {
                    Self::emit_control_api_auth_audit_event(
                        &service_state.security,
                        identity.as_ref(),
                        request_context.as_ref(),
                        route,
                        active_generation,
                        AdminAuditResult::Denied,
                        reason,
                    );
                } else {
                    Self::emit_control_api_route_denial_audit_event(
                        &service_state.security,
                        identity.as_ref(),
                        request_context.as_ref(),
                        route,
                        active_generation,
                        reason,
                    );
                }
                Err(Box::new(Self::control_api_auth_error_response(
                    route,
                    status,
                    error,
                    reason,
                    required_role,
                )))
            }
        }
    }

    fn enforce_control_api_source_policy<B>(
        req: &::http::Request<B>,
        security: &ControlApiSecurityPolicy,
        route: ControlApiRoute,
        active_generation: Option<u64>,
    ) -> Result<(), ControlApiGateError> {
        if !security.has_source_policy() {
            return Ok(());
        }
        let request_context = req.extensions().get::<ControlApiRequestContext>().cloned();
        let Some(request_context) = request_context else {
            Self::emit_control_api_auth_audit_event(
                security,
                None,
                None,
                route,
                active_generation,
                AdminAuditResult::Denied,
                "missing_peer_context",
            );
            return Err(Box::new(Self::control_api_auth_error_response(
                route,
                StatusCode::FORBIDDEN,
                "forbidden",
                "missing_peer_context",
                route.minimum_role(security),
            )));
        };

        let source_ip = match source_ip_from_request(
            req,
            request_context.peer_addr.ip(),
            security.ip_allowlist.trust_proxy_headers,
            security.ip_allowlist.trusted_proxy_matcher.as_ref(),
        ) {
            Ok(source_ip) => source_ip,
            Err(SourceIpExtractionError::MalformedForwardingHeaders) => {
                Self::emit_control_api_auth_audit_event(
                    security,
                    None,
                    Some(&request_context),
                    route,
                    active_generation,
                    AdminAuditResult::Denied,
                    "malformed_forwarding_headers",
                );
                return Err(Box::new(Self::control_api_auth_error_response(
                    route,
                    StatusCode::FORBIDDEN,
                    "forbidden",
                    "malformed_forwarding_headers",
                    route.minimum_role(security),
                )));
            }
        };
        match security.evaluate_source_policy(source_ip) {
            ControlApiSourcePolicyDecision::Allow => Ok(()),
            ControlApiSourcePolicyDecision::Deny { reason } => {
                Self::emit_control_api_auth_audit_event(
                    security,
                    None,
                    Some(&request_context),
                    route,
                    active_generation,
                    AdminAuditResult::Denied,
                    reason,
                );
                Self::emit_control_api_route_denial_audit_event(
                    security,
                    None,
                    Some(&request_context),
                    route,
                    active_generation,
                    reason,
                );
                Err(Box::new(Self::control_api_auth_error_response(
                    route,
                    StatusCode::FORBIDDEN,
                    "forbidden",
                    reason,
                    route.minimum_role(security),
                )))
            }
        }
    }

    fn control_api_auth_error_response(
        route: ControlApiRoute,
        status: StatusCode,
        error: &'static str,
        reason: &'static str,
        required_role: Option<AdminRole>,
    ) -> Response<Full<Bytes>> {
        let required_role = required_role.map(|role| match role {
            AdminRole::Viewer => "viewer",
            AdminRole::Operator => "operator",
            AdminRole::Admin => "admin",
        });
        let response = match route {
            ControlApiRoute::Runtime
            | ControlApiRoute::RuntimeValidate
            | ControlApiRoute::RuntimePreview
            | ControlApiRoute::RuntimeActivate
            | ControlApiRoute::RuntimeRollback
            | ControlApiRoute::RuntimeHistory
            | ControlApiRoute::RuntimeHistoryGeneration(_)
            | ControlApiRoute::Health
            | ControlApiRoute::Ready => json!({
                "error": error,
                "reason": reason,
                "required_role": required_role,
            }),
            ControlApiRoute::ReloadCerts | ControlApiRoute::ReloadRuntime => json!({
                "reloaded": false,
                "error": error,
                "reason": reason,
                "required_role": required_role,
            }),
            ControlApiRoute::Restart => json!({
                "accepted": false,
                "error": error,
                "reason": reason,
                "required_role": required_role,
            }),
        };
        let mut response = Self::json_response(status, response);
        if status == StatusCode::TOO_MANY_REQUESTS {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, ::http::HeaderValue::from_static("60"));
        }
        response
    }

    pub(super) fn gate_control_api_request_for<B>(
        req: &mut ::http::Request<B>,
        state: &ControlApiState,
    ) -> Result<ControlApiRoute, ControlApiGateError> {
        let service_state = state.current_service_state();
        let Some(route) = Self::control_api_request_route_for(req, &service_state.paths) else {
            return Err(Box::new(Self::control_api_not_found_response()));
        };
        Self::authorize_control_api_request_for(req, state, route)?;
        Ok(route)
    }

    pub(super) fn gate_control_api_request(
        req: &mut Request<Incoming>,
        state: &ControlApiState,
    ) -> Result<ControlApiRoute, ControlApiGateError> {
        Self::gate_control_api_request_for(req, state)
    }

    pub(super) fn control_api_not_found_response() -> Response<Full<Bytes>> {
        match Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from_static(b"not found\n")))
        {
            Ok(resp) => resp,
            Err(_) => Response::new(Full::new(Bytes::from_static(b"not found\n"))),
        }
    }
}
