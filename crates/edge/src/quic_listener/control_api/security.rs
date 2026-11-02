use std::sync::Arc;

use impulse_config::config::{
    ControlApi, ControlApiAuditFormat, ControlApiAuditSink, ControlApiClientAuthMode,
    ControlApiRole,
};
use impulse_operations::administrative::{
    AdminAuditFormat, ControlApiAdminAuditEmitter, ControlApiAdminAuditTarget,
    ControlApiAuthorizationPolicy, ControlApiBearerTokenEntry, ControlApiIpAllowlistPolicy,
};
pub(in crate::quic_listener) use impulse_operations::administrative::{
    AdminClientAuthMode, AdminRole, ControlApiAuthThrottle, ControlApiBearerTokenSource,
    ControlApiClientAuthPolicy, ControlApiClientCaMaterial, ControlApiClientVerifierState,
    ControlApiIdentitySourcePolicy, ControlApiSecurityPolicy, ControlApiSourcePolicyDecision,
    SourceIpExtractionError, source_ip_from_request,
};

use crate::Metrics;

pub(in crate::quic_listener) fn control_api_security_policy_from_config(
    config: &ControlApi,
    metrics: Arc<Metrics>,
) -> ControlApiSecurityPolicy {
    let client_auth = &config.tls.client_auth;
    let client_auth = ControlApiClientAuthPolicy::new(
        admin_client_auth_mode(client_auth.mode),
        client_auth.ca_file.clone(),
        client_auth.ca_dir.clone(),
    );
    let mut bearer_tokens = Vec::with_capacity(config.auth.bearer_tokens.len() + 1);
    if let Some(token) = config.auth_token.as_ref() {
        bearer_tokens.push(ControlApiBearerTokenEntry {
            token: token.clone(),
            role: AdminRole::Admin,
            actor_id: Some("legacy_auth_token".to_string()),
            source: ControlApiBearerTokenSource::LegacyAuthToken,
        });
    }
    bearer_tokens.extend(config.auth.bearer_tokens.iter().map(|token| {
        ControlApiBearerTokenEntry {
            token: token.token.clone(),
            role: admin_role(token.role),
            actor_id: token.actor_id.clone(),
            source: ControlApiBearerTokenSource::StaticTokenList,
        }
    }));
    let authorization = &config.authorization;
    let audit_target = match config.audit.sink {
        ControlApiAuditSink::Log => ControlApiAdminAuditTarget::Log,
        ControlApiAuditSink::File => {
            ControlApiAdminAuditTarget::File(config.audit.file_path.clone())
        }
    };

    ControlApiSecurityPolicy::new(
        client_auth,
        bearer_tokens,
        config
            .auth
            .identity_source
            .as_ref()
            .map(|source| ControlApiIdentitySourcePolicy {
                kind: source.kind.clone(),
                role_attribute: source.role_attribute.clone(),
            }),
        ControlApiAuthorizationPolicy {
            protect_health: authorization.protect_health,
            protect_ready: authorization.protect_ready,
            runtime_read_role: admin_role(authorization.runtime_read_role),
            runtime_mutate_role: admin_role(authorization.runtime_mutate_role),
            restart_role: admin_role(authorization.restart_role),
        },
        ControlApiIpAllowlistPolicy::new(
            config.ip_allowlist.trust_proxy_headers,
            &config.ip_allowlist.cidrs,
            &config.ip_allowlist.trusted_proxy_cidrs,
        ),
        ControlApiAdminAuditEmitter::new(
            config.audit.enabled,
            match config.audit.format {
                ControlApiAuditFormat::Json => AdminAuditFormat::Json,
            },
            audit_target,
            metrics,
        ),
    )
}

fn admin_role(role: ControlApiRole) -> AdminRole {
    match role {
        ControlApiRole::Viewer => AdminRole::Viewer,
        ControlApiRole::Operator => AdminRole::Operator,
        ControlApiRole::Admin => AdminRole::Admin,
    }
}

fn admin_client_auth_mode(mode: ControlApiClientAuthMode) -> AdminClientAuthMode {
    match mode {
        ControlApiClientAuthMode::Disabled => AdminClientAuthMode::Disabled,
        ControlApiClientAuthMode::Optional => AdminClientAuthMode::Optional,
        ControlApiClientAuthMode::Required => AdminClientAuthMode::Required,
    }
}
