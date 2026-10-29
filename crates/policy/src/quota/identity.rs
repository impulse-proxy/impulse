use std::net::SocketAddr;

use sha2::{Digest, Sha256};

use super::*;

impl QuotaIdentityLabels {
    pub(crate) fn canonicalize_for_storage(&self) -> Self {
        Self {
            route: canonical_stored_quota_identity(
                QuotaIdentityDimension::Route,
                self.route.as_deref(),
            ),
            tenant: canonical_stored_quota_identity(
                QuotaIdentityDimension::Tenant,
                self.tenant.as_deref(),
            ),
            token: canonical_stored_quota_identity(
                QuotaIdentityDimension::Token,
                self.token.as_deref(),
            ),
            client: canonical_stored_quota_identity(
                QuotaIdentityDimension::Client,
                self.client.as_deref(),
            ),
        }
    }
}

impl QuotaSelectorMatcher {
    pub fn dimensions(&self) -> QuotaSelectorDimensions {
        QuotaSelectorDimensions {
            route: self.route,
            tenant: self.tenant.is_some(),
            token: self.token.is_some(),
            client: self.client.is_some(),
        }
    }

    #[cfg(test)]
    pub(super) fn from_runtime(value: &ConfigRuntimeQuotaSelectorMatcher) -> Self {
        Self {
            route: value.route,
            tenant: value.tenant.as_ref().map(QuotaSelectorKeySpec::from),
            token: value.token.as_ref().map(QuotaSelectorKeySpec::from),
            client: value.client.as_ref().map(QuotaSelectorKeySpec::from),
        }
    }

    pub(crate) fn extract_identities(
        &self,
        policy_name: &str,
        context: &QuotaIdentityContext<'_>,
    ) -> Result<QuotaIdentityLabels, QuotaIdentityRejection> {
        let route = if self.route {
            Some(
                normalize_route_identity(context.route).ok_or_else(|| QuotaIdentityRejection {
                    policy_name: policy_name.to_string(),
                    dimension: QuotaIdentityDimension::Route,
                    reason: QuotaDenyReason::SelectorIdentityMissing,
                })?,
            )
        } else {
            None
        };

        let tenant = self.extract_dimension_identity(
            policy_name,
            QuotaIdentityDimension::Tenant,
            self.tenant.as_ref(),
            context,
        )?;
        let token = self.extract_dimension_identity(
            policy_name,
            QuotaIdentityDimension::Token,
            self.token.as_ref(),
            context,
        )?;
        let client = self.extract_dimension_identity(
            policy_name,
            QuotaIdentityDimension::Client,
            self.client.as_ref(),
            context,
        )?;

        Ok(QuotaIdentityLabels {
            route,
            tenant,
            token,
            client,
        })
    }

    fn extract_dimension_identity(
        &self,
        policy_name: &str,
        dimension: QuotaIdentityDimension,
        spec: Option<&QuotaSelectorKeySpec>,
        context: &QuotaIdentityContext<'_>,
    ) -> Result<Option<String>, QuotaIdentityRejection> {
        let Some(spec) = spec else {
            return Ok(None);
        };

        let extracted = extract_quota_selector_key(spec, context);

        match extracted {
            RequestKeyExtraction::Found(value) => {
                Ok(Some(canonical_quota_identity_value(dimension, &value)))
            }
            RequestKeyExtraction::Missing => Err(QuotaIdentityRejection {
                policy_name: policy_name.to_string(),
                dimension,
                reason: QuotaDenyReason::SelectorIdentityMissing,
            }),
            RequestKeyExtraction::Invalid => Err(QuotaIdentityRejection {
                policy_name: policy_name.to_string(),
                dimension,
                reason: QuotaDenyReason::SelectorIdentityInvalid,
            }),
        }
    }
}

impl QuotaPolicyRuntime {
    pub(crate) fn composite_key(
        &self,
        context: &QuotaIdentityContext<'_>,
    ) -> Result<QuotaCompositeKey, QuotaIdentityRejection> {
        let labels = self.selector.extract_identities(&self.name, context)?;
        let labels = labels.canonicalize_for_storage();
        Ok(QuotaCompositeKey {
            policy_name: self.name.clone(),
            key: compose_quota_key(&self.name, &labels),
            dimensions: self.selector.dimensions(),
            labels,
        })
    }
}

fn extract_quota_selector_key(
    spec: &QuotaSelectorKeySpec,
    context: &QuotaIdentityContext<'_>,
) -> RequestKeyExtraction {
    match spec {
        QuotaSelectorKeySpec::Path => extract_path_value(context.path),
        QuotaSelectorKeySpec::Authority => extract_authority_value(context.authority),
        QuotaSelectorKeySpec::Method => extract_method_value(context.method),
        QuotaSelectorKeySpec::Cid | QuotaSelectorKeySpec::StickyCid => {
            extract_cid_value(context.cid_key)
        }
        QuotaSelectorKeySpec::PeerIp | QuotaSelectorKeySpec::ClientIp => {
            extract_client_ip_value(context.client_addr)
        }
        QuotaSelectorKeySpec::BearerToken => extract_bearer_token_value(context.header_lookup),
        QuotaSelectorKeySpec::Header(name) => extract_header_value(name, context.header_lookup),
        QuotaSelectorKeySpec::Cookie(name) => extract_cookie_key_value(name, context.header_lookup),
        QuotaSelectorKeySpec::Query(name) => extract_query_key_value(context.path, name),
        QuotaSelectorKeySpec::LegacyFallback(inner) => {
            match extract_quota_selector_key(inner.as_ref(), context) {
                RequestKeyExtraction::Found(value) => RequestKeyExtraction::Found(value),
                RequestKeyExtraction::Missing => extract_legacy_default_request_key(context),
                RequestKeyExtraction::Invalid => RequestKeyExtraction::Invalid,
            }
        }
    }
}

fn extract_legacy_default_request_key(context: &QuotaIdentityContext<'_>) -> RequestKeyExtraction {
    if let Some(authority) = context
        .authority
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return bounded_request_key_value(authority);
    }

    let path = context.path.trim();
    if !path.is_empty() {
        return bounded_request_key_value(path);
    }

    let method = context.method.trim();
    if !method.is_empty() {
        return bounded_owned_request_key_value(method.to_ascii_uppercase());
    }

    RequestKeyExtraction::Missing
}

fn extract_path_value(path: &str) -> RequestKeyExtraction {
    let path_only = path.split_once('?').map(|(value, _)| value).unwrap_or(path);
    bounded_request_key_value(path_only)
}

fn extract_authority_value(authority: Option<&str>) -> RequestKeyExtraction {
    let Some(authority) = authority.map(str::trim).filter(|value| !value.is_empty()) else {
        return RequestKeyExtraction::Missing;
    };
    bounded_request_key_value(authority)
}

fn extract_method_value(method: &str) -> RequestKeyExtraction {
    let normalized = method.trim();
    if normalized.is_empty() {
        RequestKeyExtraction::Missing
    } else {
        bounded_owned_request_key_value(normalized.to_ascii_uppercase())
    }
}

fn extract_cid_value(cid_key: Option<&str>) -> RequestKeyExtraction {
    let Some(cid_key) = cid_key.map(str::trim).filter(|value| !value.is_empty()) else {
        return RequestKeyExtraction::Missing;
    };
    bounded_request_key_value(cid_key)
}

fn extract_client_ip_value(client_addr: Option<SocketAddr>) -> RequestKeyExtraction {
    let Some(client_addr) = client_addr else {
        return RequestKeyExtraction::Missing;
    };
    bounded_owned_request_key_value(client_addr.ip().to_string())
}

fn extract_bearer_token_value(
    header_lookup: Option<&QuotaHeaderLookup<'_>>,
) -> RequestKeyExtraction {
    let Some(raw) = header_lookup.and_then(|lookup| lookup(http::header::AUTHORIZATION.as_str()))
    else {
        return RequestKeyExtraction::Missing;
    };

    let raw = raw.trim();
    let Some(split) = raw.find(char::is_whitespace) else {
        return RequestKeyExtraction::Invalid;
    };
    let (scheme, rest) = raw.split_at(split);
    if !scheme.eq_ignore_ascii_case("bearer") {
        return RequestKeyExtraction::Invalid;
    }
    let token = rest.trim_start();
    if token.is_empty() {
        return RequestKeyExtraction::Invalid;
    }
    bounded_request_key_value(token)
}

fn extract_header_value(
    name: &str,
    header_lookup: Option<&QuotaHeaderLookup<'_>>,
) -> RequestKeyExtraction {
    let Some(value) = header_lookup.and_then(|lookup| lookup(name)) else {
        return RequestKeyExtraction::Missing;
    };
    bounded_request_key_value(value.as_str())
}

fn extract_cookie_key_value(
    cookie_name: &str,
    header_lookup: Option<&QuotaHeaderLookup<'_>>,
) -> RequestKeyExtraction {
    let Some(cookie_header) =
        header_lookup.and_then(|lookup| lookup(http::header::COOKIE.as_str()))
    else {
        return RequestKeyExtraction::Missing;
    };

    for pair in cookie_header.split(';') {
        let part = pair.trim();
        if part.is_empty() {
            continue;
        }
        let Some((name, value)) = part.split_once('=') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case(cookie_name) {
            continue;
        }
        let value = value.trim();
        if value.is_empty() {
            return RequestKeyExtraction::Missing;
        }
        return bounded_request_key_value(value);
    }

    RequestKeyExtraction::Missing
}

fn extract_query_key_value(path: &str, param: &str) -> RequestKeyExtraction {
    let Some((_, query)) = path.split_once('?') else {
        return RequestKeyExtraction::Missing;
    };

    for pair in query.split('&') {
        let entry = pair.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((name, value)) = entry.split_once('=') else {
            continue;
        };
        if !name.eq_ignore_ascii_case(param) {
            continue;
        }
        if value.is_empty() {
            return RequestKeyExtraction::Missing;
        }
        return bounded_request_key_value(value);
    }

    RequestKeyExtraction::Missing
}

fn bounded_request_key_value(value: &str) -> RequestKeyExtraction {
    let normalized = value.trim();
    if normalized.is_empty() {
        return RequestKeyExtraction::Missing;
    }
    if normalized.len() > MAX_REQUEST_DERIVED_QUOTA_IDENTITY_BYTES {
        return RequestKeyExtraction::Invalid;
    }
    RequestKeyExtraction::Found(normalized.to_string())
}

fn bounded_owned_request_key_value(value: String) -> RequestKeyExtraction {
    if value.is_empty() {
        return RequestKeyExtraction::Missing;
    }
    if value.len() > MAX_REQUEST_DERIVED_QUOTA_IDENTITY_BYTES {
        return RequestKeyExtraction::Invalid;
    }
    RequestKeyExtraction::Found(value)
}

pub(super) fn canonical_quota_identity_value(
    dimension: QuotaIdentityDimension,
    value: &str,
) -> String {
    let normalized = value.trim();
    if matches!(dimension, QuotaIdentityDimension::Route) {
        return normalized.to_string();
    }

    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    let digest = hasher.finalize();
    format!("sha256:{digest:x}")
}

pub(super) fn canonical_stored_quota_identity(
    dimension: QuotaIdentityDimension,
    value: Option<&str>,
) -> Option<String> {
    let normalized = value.map(str::trim).filter(|value| !value.is_empty())?;
    if matches!(dimension, QuotaIdentityDimension::Route) {
        return Some(normalized.to_string());
    }
    if is_canonical_hashed_quota_identity(normalized) {
        return Some(normalized.to_string());
    }
    Some(canonical_quota_identity_value(dimension, normalized))
}

pub(super) fn is_canonical_hashed_quota_identity(value: &str) -> bool {
    value.len() == "sha256:".len() + 64
        && value.starts_with("sha256:")
        && value["sha256:".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
}

pub(super) fn normalize_route_identity(route: Option<&str>) -> Option<String> {
    route
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(super) fn compose_quota_key(policy_name: &str, labels: &QuotaIdentityLabels) -> String {
    let labels = labels.canonicalize_for_storage();
    let mut key = String::with_capacity(estimated_quota_key_capacity(policy_name));
    append_key_component(&mut key, "policy", policy_name);
    if let Some(route) = labels.route.as_deref() {
        append_key_component(&mut key, "route", route);
    }
    if let Some(tenant) = labels.tenant.as_deref() {
        append_key_component(&mut key, "tenant", tenant);
    }
    if let Some(token) = labels.token.as_deref() {
        append_key_component(&mut key, "token", token);
    }
    if let Some(client) = labels.client.as_deref() {
        append_key_component(&mut key, "client", client);
    }
    key
}

fn estimated_quota_key_capacity(policy_name: &str) -> usize {
    policy_name
        .len()
        .saturating_add(
            MAX_REQUEST_DERIVED_QUOTA_IDENTITY_BYTES
                .saturating_mul(MAX_REQUEST_DERIVED_QUOTA_IDENTITY_COMPONENTS),
        )
        .saturating_add(64)
}

fn append_key_component(output: &mut String, label: &str, value: &str) {
    output.push_str(label);
    output.push('=');
    output.push_str(&value.len().to_string());
    output.push(':');
    output.push_str(value);
    output.push('|');
}
