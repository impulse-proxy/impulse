use std::{collections::HashMap, net::IpAddr};

use super::*;
use crate::{
    config::ControlApiRole,
    validator::{
        helpers::validate_pem_certificate_directory, secrets::validate_secret_source_exclusivity,
    },
};

macro_rules! validation_error {
    ($($arg:tt)*) => {{
        let message = format!($($arg)*);
        super::record_validation_error(message.clone());
        log::error!("{}", message);
    }};
}

fn valid_prefix_len(addr: &str, prefix: &str) -> bool {
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => prefix <= 32,
        Ok(IpAddr::V6(_)) => prefix <= 128,
        Err(_) => false,
    }
}

fn is_valid_cidr(cidr: &str) -> bool {
    let Some((addr, prefix)) = cidr.split_once('/') else {
        return false;
    };
    valid_prefix_len(addr.trim(), prefix.trim())
}

pub(super) fn validate_control_api_authentication(control_api: &ControlApi) -> bool {
    if let Some(token) = control_api.auth_token.as_ref()
        && token.trim().is_empty()
    {
        validation_error!("observability.control_api.auth_token cannot be empty when provided");
        return false;
    }
    if let Some(token) = control_api.auth_token.as_ref()
        && crate::config::is_known_placeholder_token(token)
    {
        validation_error!("observability.control_api.auth_token must not use a placeholder value");
        return false;
    }
    if !validate_secret_source_exclusivity(
        control_api
            .auth_token
            .as_deref()
            .is_some_and(|token| !token.trim().is_empty()),
        control_api.auth_token_ref.as_ref(),
        "observability.control_api.auth_token",
        "observability.control_api.auth_token_ref",
    ) {
        return false;
    }

    for (idx, token) in control_api.auth.bearer_tokens.iter().enumerate() {
        let has_literal_token = !token.token.trim().is_empty();
        if !has_literal_token && token.token_ref.is_none() {
            validation_error!(
                "observability.control_api.auth.bearer_tokens[{}] must configure token or token_ref",
                idx
            );
            return false;
        }
        if !validate_secret_source_exclusivity(
            has_literal_token,
            token.token_ref.as_ref(),
            &format!("observability.control_api.auth.bearer_tokens[{idx}].token"),
            &format!("observability.control_api.auth.bearer_tokens[{idx}].token_ref"),
        ) {
            return false;
        }
        if has_literal_token && crate::config::is_known_placeholder_token(&token.token) {
            validation_error!(
                "observability.control_api.auth.bearer_tokens[{}].token must not use a placeholder value",
                idx
            );
            return false;
        }
        if let Some(token_ref) = token.token_ref.as_ref()
            && token_ref
                .raw_value()
                .strip_prefix("literal:")
                .is_some_and(crate::config::is_known_placeholder_token)
        {
            validation_error!(
                "observability.control_api.auth.bearer_tokens[{}].token_ref must not resolve to a placeholder value",
                idx
            );
            return false;
        }
        if let Some(actor_id) = token.actor_id.as_ref()
            && actor_id.trim().is_empty()
        {
            validation_error!(
                "observability.control_api.auth.bearer_tokens[{}].actor_id cannot be empty when provided",
                idx
            );
            return false;
        }
    }

    let mut seen_tokens: HashMap<&str, (ControlApiRole, Option<&str>, String)> = HashMap::new();
    if let Some(token) = control_api.auth_token.as_deref()
        && let Some(previous) = seen_tokens.insert(
            token,
            (ControlApiRole::Admin, None, "auth_token".to_string()),
        )
        && (previous.0 != ControlApiRole::Admin || previous.1.is_some())
    {
        validation_error!(
            "observability.control_api.auth_token duplicates {} with conflicting role or actor",
            previous.2
        );
        return false;
    }
    for (idx, token) in control_api.auth.bearer_tokens.iter().enumerate() {
        if token.token.trim().is_empty() {
            continue;
        }
        if let Some(previous) = seen_tokens.insert(
            token.token.as_str(),
            (
                token.role,
                token.actor_id.as_deref(),
                format!("auth.bearer_tokens[{idx}].token"),
            ),
        ) && (previous.0 != token.role || previous.1 != token.actor_id.as_deref())
        {
            validation_error!(
                "observability.control_api.auth.bearer_tokens[{}].token duplicates {} with conflicting role or actor",
                idx,
                previous.2
            );
            return false;
        }
    }

    if let Some(identity_source) = control_api.auth.identity_source.as_ref() {
        let kind = identity_source.kind.trim();
        if kind.is_empty() {
            validation_error!(
                "observability.control_api.auth.identity_source.kind cannot be empty when provided"
            );
            return false;
        }
        if !VALID_CONTROL_API_IDENTITY_SOURCE_KINDS
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(kind))
        {
            validation_error!(
                "observability.control_api.auth.identity_source.kind must be one of {:?}",
                VALID_CONTROL_API_IDENTITY_SOURCE_KINDS
            );
            return false;
        }
        if matches!(
            control_api.tls.client_auth.mode,
            ControlApiClientAuthMode::Disabled
        ) {
            validation_error!(
                "observability.control_api.auth.identity_source requires observability.control_api.tls.client_auth.mode to be optional or required"
            );
            return false;
        }
    }

    let has_legacy_token = control_api
        .auth_token
        .as_deref()
        .is_some_and(|token| !token.trim().is_empty())
        || control_api.auth_token_ref.is_some();
    let has_static_tokens = control_api
        .auth
        .bearer_tokens
        .iter()
        .any(|token| !token.token.trim().is_empty() || token.token_ref.is_some());
    match control_api.tls.client_auth.mode {
        ControlApiClientAuthMode::Disabled => {
            if !has_legacy_token && !has_static_tokens {
                validation_error!(
                    "observability.control_api requires at least one admin auth mechanism when enabled: auth_token, auth.bearer_tokens, or tls.client_auth.mode=required"
                );
                return false;
            }
        }
        ControlApiClientAuthMode::Optional => {
            if !has_legacy_token && !has_static_tokens {
                validation_error!(
                    "observability.control_api.tls.client_auth.mode=optional cannot be the only admin auth mechanism; configure auth_token, auth.bearer_tokens, or use mode=required"
                );
                return false;
            }
        }
        ControlApiClientAuthMode::Required => {}
    }

    true
}

pub(super) fn validate_control_api_security(control_api: &ControlApi) -> bool {
    let client_auth = &control_api.tls.client_auth;
    if matches!(
        client_auth.mode,
        ControlApiClientAuthMode::Optional | ControlApiClientAuthMode::Required
    ) && client_auth.ca_file.is_none()
        && client_auth.ca_dir.is_none()
    {
        validation_error!(
            "observability.control_api.tls.client_auth.ca_file or ca_dir is required when client_auth.mode is optional or required"
        );
        return false;
    }

    if let Some(ca_file) = client_auth.ca_file.as_ref()
        && ca_file.trim().is_empty()
    {
        validation_error!(
            "observability.control_api.tls.client_auth.ca_file cannot be empty when provided"
        );
        return false;
    }
    if let Some(ca_dir) = client_auth.ca_dir.as_ref()
        && ca_dir.trim().is_empty()
    {
        validation_error!(
            "observability.control_api.tls.client_auth.ca_dir cannot be empty when provided"
        );
        return false;
    }
    if let Some(ca_dir) = client_auth.ca_dir.as_ref()
        && !validate_pem_certificate_directory(
            ca_dir,
            "observability.control_api.tls.client_auth.ca_dir",
        )
    {
        return false;
    }
    if control_api.authorization.runtime_mutate_role < control_api.authorization.runtime_read_role {
        validation_error!(
            "observability.control_api.authorization.runtime_mutate_role must be at least as privileged as runtime_read_role"
        );
        return false;
    }
    if control_api.authorization.restart_role < control_api.authorization.runtime_mutate_role {
        validation_error!(
            "observability.control_api.authorization.restart_role must be at least as privileged as runtime_mutate_role"
        );
        return false;
    }

    for (idx, cidr) in control_api.ip_allowlist.cidrs.iter().enumerate() {
        if cidr.trim().is_empty() {
            validation_error!(
                "observability.control_api.ip_allowlist.cidrs[{}] cannot be empty",
                idx
            );
            return false;
        }
        if !is_valid_cidr(cidr.trim()) {
            validation_error!(
                "observability.control_api.ip_allowlist.cidrs[{}] must be a valid CIDR",
                idx
            );
            return false;
        }
    }

    for (idx, cidr) in control_api
        .ip_allowlist
        .trusted_proxy_cidrs
        .iter()
        .enumerate()
    {
        if cidr.trim().is_empty() {
            validation_error!(
                "observability.control_api.ip_allowlist.trusted_proxy_cidrs[{}] cannot be empty",
                idx
            );
            return false;
        }
        if !is_valid_cidr(cidr.trim()) {
            validation_error!(
                "observability.control_api.ip_allowlist.trusted_proxy_cidrs[{}] must be a valid CIDR",
                idx
            );
            return false;
        }
    }

    if control_api.ip_allowlist.trust_proxy_headers
        && control_api.ip_allowlist.trusted_proxy_cidrs.is_empty()
    {
        validation_error!(
            "observability.control_api.ip_allowlist.trusted_proxy_cidrs must not be empty when trust_proxy_headers=true"
        );
        return false;
    }

    if let Some(path) = control_api.audit.file_path.as_ref()
        && path.trim().is_empty()
    {
        validation_error!(
            "observability.control_api.audit.file_path cannot be empty when provided"
        );
        return false;
    }
    match control_api.audit.sink {
        ControlApiAuditSink::Log => {
            if control_api.audit.file_path.is_some() {
                validation_error!(
                    "observability.control_api.audit.file_path is only valid when audit.sink=file"
                );
                return false;
            }
        }
        ControlApiAuditSink::File => {
            if control_api.audit.file_path.is_none() {
                validation_error!(
                    "observability.control_api.audit.file_path is required when audit.sink=file"
                );
                return false;
            }
        }
    }

    validate_control_api_authentication(control_api)
}
