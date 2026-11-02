use std::{collections::BTreeSet, net::SocketAddr};

use serde::Serialize;
use subtle::ConstantTimeEq;
use x509_parser::{extensions::GeneralName, parse_x509_certificate, prelude::X509Certificate};

use super::security::{ControlApiIdentitySourcePolicy, ControlApiSecurityPolicy};
use crate::quic_listener::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum AdminRole {
    Viewer,
    Operator,
    Admin,
}

impl From<impulse_config::config::ControlApiRole> for AdminRole {
    fn from(value: impulse_config::config::ControlApiRole) -> Self {
        match value {
            impulse_config::config::ControlApiRole::Viewer => Self::Viewer,
            impulse_config::config::ControlApiRole::Operator => Self::Operator,
            impulse_config::config::ControlApiRole::Admin => Self::Admin,
        }
    }
}

impl AdminRole {
    fn most_privileged(roles: &[Self]) -> Option<Self> {
        roles.iter().copied().max()
    }

    fn least_privileged(left: Self, right: Self) -> Self {
        left.min(right)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum AdminAuthnMechanism {
    BearerToken,
    MutualTls,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct AdminIdentity {
    pub(super) actor_id: Option<String>,
    pub(super) authn_mechanisms: Vec<AdminAuthnMechanism>,
    pub(super) roles: Vec<AdminRole>,
    pub(super) peer_addr: Option<SocketAddr>,
    pub(super) mtls_subject: Option<String>,
    pub(super) mtls_san: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControlApiRequestContext {
    pub(super) peer_addr: SocketAddr,
    pub(super) mtls_identity: Option<AdminMtlsIdentity>,
    pub(super) listener: Option<String>,
    pub(super) request_id: Option<String>,
    pub(super) trace_id: Option<String>,
    pub(super) span_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AdminMtlsIdentity {
    pub(super) subject: Option<String>,
    pub(super) common_name: Option<String>,
    pub(super) san_dns: Vec<String>,
    pub(super) san_uri: Vec<String>,
    pub(super) roles: Vec<AdminRole>,
}

#[derive(Clone, Debug)]
pub(super) struct AdminTokenMatch {
    pub(super) actor_id: Option<String>,
    pub(super) role: AdminRole,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdminPrincipalNamespace {
    CanonicalActor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AdminPrincipal {
    namespace: AdminPrincipalNamespace,
    value: String,
}

impl Http3Service {
    fn reconcile_dual_auth_actor_id(
        token_principal: Option<AdminPrincipal>,
        mtls_principal: Option<AdminPrincipal>,
    ) -> Option<String> {
        match (token_principal, mtls_principal) {
            (Some(token), Some(mtls)) if token == mtls => Some(token.value),
            (Some(_), Some(_)) => None,
            (Some(token), None) => Some(token.value),
            (None, Some(mtls)) => Some(mtls.value),
            (None, None) => None,
        }
    }

    pub(super) fn build_control_api_request_context(
        peer_addr: SocketAddr,
        peer_certificates: Option<&[CertificateDer<'static>]>,
        identity_source: Option<&ControlApiIdentitySourcePolicy>,
        listener: Option<String>,
    ) -> ControlApiRequestContext {
        let mtls_identity = peer_certificates
            .and_then(|certs| certs.first())
            .and_then(|cert| Self::parse_admin_mtls_identity(cert.as_ref(), identity_source));
        ControlApiRequestContext {
            peer_addr,
            mtls_identity,
            listener,
            request_id: None,
            trace_id: None,
            span_id: None,
        }
    }

    pub(super) fn augment_control_api_request_context<B>(
        mut context: ControlApiRequestContext,
        req: &::http::Request<B>,
    ) -> ControlApiRequestContext {
        context.request_id = req
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        if let Some((trace_id, span_id)) = req
            .headers()
            .get("traceparent")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .and_then(parse_traceparent)
        {
            context.trace_id = Some(trace_id);
            context.span_id = Some(span_id);
        }
        context
    }

    fn parse_admin_mtls_identity(
        cert_der: &[u8],
        identity_source: Option<&ControlApiIdentitySourcePolicy>,
    ) -> Option<AdminMtlsIdentity> {
        let (_, cert) = parse_x509_certificate(cert_der).ok()?;
        let subject = Some(cert.subject().to_string());
        let mut common_name = None;
        for cn in cert.subject().iter_common_name() {
            if let Ok(value) = cn.as_str() {
                common_name = Some(value.to_string());
                break;
            }
        }

        let mut san_dns = Vec::new();
        let mut san_uri = Vec::new();
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for name in &san.value.general_names {
                match name {
                    GeneralName::DNSName(dns) => san_dns.push(dns.to_string()),
                    GeneralName::URI(uri) => san_uri.push(uri.to_string()),
                    _ => {}
                }
            }
        }

        let roles = identity_source
            .and_then(|policy| policy.role_attribute.as_deref())
            .map(|attribute| Self::extract_admin_roles_from_subject_attribute(&cert, attribute))
            .unwrap_or_default();

        Some(AdminMtlsIdentity {
            subject,
            common_name,
            san_dns,
            san_uri,
            roles,
        })
    }

    fn extract_admin_roles_from_subject_attribute(
        cert: &X509Certificate<'_>,
        attribute: &str,
    ) -> Vec<AdminRole> {
        let mut roles = Vec::new();
        for attr in cert.subject().iter_attributes() {
            let short_name = attr.attr_type().to_id_string();
            let matches = short_name.eq_ignore_ascii_case(attribute)
                || Self::matches_admin_subject_attribute_alias(&short_name, attribute);
            if !matches {
                continue;
            }
            if let Ok(value) = attr.as_str()
                && let Some(role) = Self::parse_admin_role(value)
            {
                roles.push(role);
            }
        }
        roles
    }

    fn matches_admin_subject_attribute_alias(actual: &str, requested: &str) -> bool {
        match requested.to_ascii_lowercase().as_str() {
            "cn" => actual == "2.5.4.3",
            "o" => actual == "2.5.4.10",
            "ou" => actual == "2.5.4.11",
            _ => false,
        }
    }

    pub(super) fn parse_admin_role(value: &str) -> Option<AdminRole> {
        match value.trim().to_ascii_lowercase().as_str() {
            "viewer" => Some(AdminRole::Viewer),
            "operator" => Some(AdminRole::Operator),
            "admin" => Some(AdminRole::Admin),
            _ => None,
        }
    }

    pub(super) fn actor_id_from_mtls_identity(
        mtls: &AdminMtlsIdentity,
        identity_source: Option<&ControlApiIdentitySourcePolicy>,
    ) -> Option<String> {
        match identity_source
            .map(|policy| policy.kind.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("mtls_subject_cn") => mtls.common_name.clone(),
            Some("mtls_san_dns") => mtls.san_dns.first().cloned(),
            Some("mtls_san_uri") => mtls.san_uri.first().cloned(),
            Some("mtls_subject") => mtls.subject.clone(),
            _ => mtls.common_name.clone().or_else(|| mtls.subject.clone()),
        }
    }

    pub(super) fn control_api_token_match(
        provided: &str,
        security: &ControlApiSecurityPolicy,
    ) -> Option<AdminTokenMatch> {
        let mut matched = None;
        let mut matched_any = 0u8;
        for entry in security.bearer_tokens.iter() {
            let is_match = bool::from(provided.as_bytes().ct_eq(entry.token.as_bytes())) as u8;
            if is_match == 1 {
                matched = Some(AdminTokenMatch {
                    actor_id: entry.actor_id.clone(),
                    role: AdminRole::from(entry.role),
                });
            }
            matched_any |= is_match;
        }
        (matched_any == 1).then_some(matched).flatten()
    }

    pub(super) fn build_admin_identity(
        request_ctx: Option<ControlApiRequestContext>,
        token_match: Option<AdminTokenMatch>,
        identity_source: Option<&ControlApiIdentitySourcePolicy>,
    ) -> Option<AdminIdentity> {
        let mtls_identity = request_ctx
            .as_ref()
            .and_then(|ctx| ctx.mtls_identity.as_ref())
            .cloned();
        if token_match.is_none() && mtls_identity.is_none() {
            return None;
        }

        let mut roles = BTreeSet::new();
        let mut mechanisms = Vec::new();
        let mut token_principal = None;
        let mut effective_role_limit = None;
        if let Some(token) = token_match {
            mechanisms.push(AdminAuthnMechanism::BearerToken);
            roles.insert(token.role);
            effective_role_limit = Some(token.role);
            token_principal = token.actor_id.map(|value| AdminPrincipal {
                namespace: AdminPrincipalNamespace::CanonicalActor,
                value,
            });
        }
        let mut mtls_principal = None;
        if let Some(mtls) = mtls_identity.as_ref() {
            mechanisms.push(AdminAuthnMechanism::MutualTls);
            for role in &mtls.roles {
                roles.insert(*role);
            }
            if let Some(mtls_role_limit) = AdminRole::most_privileged(&mtls.roles) {
                effective_role_limit = Some(
                    effective_role_limit
                        .map(|current| AdminRole::least_privileged(current, mtls_role_limit))
                        .unwrap_or(mtls_role_limit),
                );
            }
            mtls_principal =
                Self::actor_id_from_mtls_identity(mtls, identity_source).map(|value| {
                    AdminPrincipal {
                        namespace: AdminPrincipalNamespace::CanonicalActor,
                        value,
                    }
                });
        }

        let roles = match effective_role_limit {
            Some(role_limit) if mechanisms.len() > 1 => vec![role_limit],
            _ => roles.into_iter().collect(),
        };
        let actor_id = Self::reconcile_dual_auth_actor_id(token_principal, mtls_principal);
        if mechanisms.len() > 1 && actor_id.is_none() {
            // Presenting two authentication mechanisms is an assertion that
            // they represent the same administrator. Never turn an
            // unreconciled pair into an anonymous-but-authorized identity.
            return None;
        }

        Some(AdminIdentity {
            actor_id,
            authn_mechanisms: mechanisms,
            roles,
            peer_addr: request_ctx.as_ref().map(|ctx| ctx.peer_addr),
            mtls_subject: mtls_identity
                .as_ref()
                .and_then(|identity| identity.subject.clone()),
            mtls_san: mtls_identity
                .as_ref()
                .map(|identity| {
                    identity
                        .san_dns
                        .iter()
                        .cloned()
                        .chain(identity.san_uri.iter().cloned())
                        .collect()
                })
                .unwrap_or_default(),
        })
    }
}
