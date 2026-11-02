use http::header;

use super::{
    identity::{AdminIdentity, AdministrativeSecurity, ControlApiRequestContext},
    security::ControlApiSecurityPolicy,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticationOutcome {
    Authenticated(AdminIdentity),
    Missing,
    Invalid(&'static str),
}

impl AdministrativeSecurity {
    pub fn bearer_token_from_authorization_header(raw: &str) -> Option<&str> {
        let raw = raw.trim();
        let split = raw.find(char::is_whitespace)?;
        let (scheme, rest) = raw.split_at(split);
        if !scheme.eq_ignore_ascii_case("bearer") {
            return None;
        }
        let token = rest.trim_start();
        (!token.is_empty()).then_some(token)
    }

    pub fn authenticate_control_api_request<B>(
        request: &http::Request<B>,
        security: &ControlApiSecurityPolicy,
    ) -> AuthenticationOutcome {
        let request_context = request
            .extensions()
            .get::<ControlApiRequestContext>()
            .cloned();
        if matches!(
            security.client_auth.mode,
            super::security::AdminClientAuthMode::Required
        ) && request_context
            .as_ref()
            .and_then(|context| context.mtls_identity.as_ref())
            .is_none()
        {
            return AuthenticationOutcome::Missing;
        }

        let token_match = match request.headers().get(header::AUTHORIZATION) {
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
        let has_mtls = request_context
            .as_ref()
            .and_then(|context| context.mtls_identity.as_ref())
            .is_some();
        match Self::build_admin_identity(
            request_context,
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
}
