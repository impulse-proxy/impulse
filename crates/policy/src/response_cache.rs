use std::{
    borrow::Cow,
    time::{Duration, SystemTime},
};

use http::{HeaderMap, header, uri::Authority};

const CACHE_KEY_NAMESPACE: &[u8] = b"impulse-response-cache-v1";
const SUPPORTED_VARY_HEADER: &str = "accept-encoding";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseCachePolicyInput {
    pub enabled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseCacheAuthInput {
    pub api_key: bool,
    pub jwt: bool,
    pub external_auth: bool,
    pub required_scopes: bool,
    pub required_roles: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCacheBypassReason {
    Disabled,
    UnsupportedMethod,
    Authorization,
    Cookie,
    RequestBody,
    Upgrade,
    Tunnel,
    NoCache,
    SetCookie,
    Private,
    NoStore,
    MalformedHeader,
    UnsupportedVary,
}

pub struct ResponseCacheRequestEligibilityInput<'a> {
    pub policy: ResponseCachePolicyInput,
    pub route_auth_enabled: bool,
    pub method: &'a str,
    pub headers: &'a HeaderMap,
    pub has_body: bool,
    pub is_upgrade: bool,
    pub is_tunnel: bool,
}

pub struct ResponseCacheResponseEligibilityInput<'a> {
    pub headers: &'a HeaderMap,
}

pub fn evaluate_cache_request_eligibility(
    input: ResponseCacheRequestEligibilityInput<'_>,
) -> Result<ResponseCacheRepresentation, ResponseCacheBypassReason> {
    if !input.policy.enabled {
        return Err(ResponseCacheBypassReason::Disabled);
    }
    if input.route_auth_enabled || input.headers.contains_key(header::AUTHORIZATION) {
        return Err(ResponseCacheBypassReason::Authorization);
    }
    if input.headers.contains_key(header::COOKIE) {
        return Err(ResponseCacheBypassReason::Cookie);
    }
    if input.has_body {
        return Err(ResponseCacheBypassReason::RequestBody);
    }
    if input.is_upgrade
        || input.headers.contains_key(header::UPGRADE)
        || header_contains_token(input.headers, header::CONNECTION, "upgrade")?
    {
        return Err(ResponseCacheBypassReason::Upgrade);
    }
    if input.is_tunnel {
        return Err(ResponseCacheBypassReason::Tunnel);
    }
    if header_contains_directive(input.headers, header::CACHE_CONTROL, "no-cache")? {
        return Err(ResponseCacheBypassReason::NoCache);
    }
    if header_contains_directive(input.headers, header::CACHE_CONTROL, "no-store")? {
        return Err(ResponseCacheBypassReason::NoStore);
    }
    match input.method {
        method if method.eq_ignore_ascii_case("GET") => Ok(ResponseCacheRepresentation::Get),
        method if method.eq_ignore_ascii_case("HEAD") => Ok(ResponseCacheRepresentation::Head),
        _ => Err(ResponseCacheBypassReason::UnsupportedMethod),
    }
}

pub const fn route_auth_requires_cache_bypass(policy: ResponseCacheAuthInput) -> bool {
    policy.api_key
        || policy.jwt
        || policy.external_auth
        || policy.required_scopes
        || policy.required_roles
}

pub fn evaluate_cache_response_eligibility(
    input: ResponseCacheResponseEligibilityInput<'_>,
) -> Result<(), ResponseCacheBypassReason> {
    if input.headers.contains_key(header::SET_COOKIE) {
        return Err(ResponseCacheBypassReason::SetCookie);
    }
    if header_contains_directive(input.headers, header::CACHE_CONTROL, "private")? {
        return Err(ResponseCacheBypassReason::Private);
    }
    if header_contains_directive(input.headers, header::CACHE_CONTROL, "no-store")? {
        return Err(ResponseCacheBypassReason::NoStore);
    }
    for value in input.headers.get_all(header::VARY).iter() {
        let value = value
            .to_str()
            .map_err(|_| ResponseCacheBypassReason::MalformedHeader)?;
        for name in value.split(',').map(str::trim) {
            if name.is_empty() || !name.eq_ignore_ascii_case(SUPPORTED_VARY_HEADER) {
                return Err(ResponseCacheBypassReason::UnsupportedVary);
            }
        }
    }
    Ok(())
}

pub fn response_cache_ttl(
    headers: &HeaderMap,
    max_ttl_secs: u64,
    now: SystemTime,
) -> Option<Duration> {
    if header_contains_directive(headers, header::CACHE_CONTROL, "no-cache").ok()?
        || header_contains_directive(headers, header::CACHE_CONTROL, "no-store").ok()?
        || header_contains_directive(headers, header::CACHE_CONTROL, "private").ok()?
    {
        return None;
    }

    let origin_ttl = cache_control_seconds(headers, "s-maxage")?
        .or(cache_control_seconds(headers, "max-age")?)
        .map(Duration::from_secs)
        .or_else(|| {
            let expires = headers.get(header::EXPIRES)?.to_str().ok()?;
            httpdate::parse_http_date(expires)
                .ok()?
                .duration_since(now)
                .ok()
        })?;
    let ttl = origin_ttl.min(Duration::from_secs(max_ttl_secs));
    (!ttl.is_zero()).then_some(ttl)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCacheRepresentation {
    Get,
    Head,
}

impl ResponseCacheRepresentation {
    fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Get => b"get",
            Self::Head => b"head",
        }
    }
}

pub struct ResponseCacheKeyInput<'a> {
    pub scheme: &'a str,
    pub authority: &'a str,
    pub path_and_query: &'a str,
    pub representation: ResponseCacheRepresentation,
    pub accept_encoding: Option<&'a str>,
    pub namespace: u64,
}

pub struct CanonicalResponseCacheKey {
    primary: Vec<u8>,
}

impl CanonicalResponseCacheKey {
    pub fn into_primary(self) -> Vec<u8> {
        self.primary
    }
}

pub fn canonical_response_cache_key(
    input: ResponseCacheKeyInput<'_>,
) -> Option<CanonicalResponseCacheKey> {
    let scheme = match input.scheme.trim().to_ascii_lowercase().as_str() {
        "http" => "http",
        "https" => "https",
        _ => return None,
    };
    let authority = canonical_authority(input.authority, scheme)?;
    if !input.path_and_query.starts_with('/') {
        return None;
    }
    let target = canonical_request_target(input.path_and_query);
    let accept_encoding = canonical_accept_encoding(input.accept_encoding);

    let mut primary = Vec::with_capacity(
        CACHE_KEY_NAMESPACE.len()
            + scheme.len()
            + authority.len()
            + target.len()
            + accept_encoding.len()
            + 64,
    );
    push_component(&mut primary, CACHE_KEY_NAMESPACE);
    push_component(&mut primary, &input.namespace.to_be_bytes());
    push_component(&mut primary, scheme.as_bytes());
    push_component(&mut primary, authority.as_bytes());
    push_component(&mut primary, target.as_bytes());
    push_component(&mut primary, input.representation.as_bytes());
    push_component(&mut primary, SUPPORTED_VARY_HEADER.as_bytes());
    push_component(&mut primary, accept_encoding.as_bytes());

    Some(CanonicalResponseCacheKey { primary })
}

fn cache_control_seconds(headers: &HeaderMap, expected: &str) -> Option<Option<u64>> {
    for value in headers.get_all(header::CACHE_CONTROL).iter() {
        let value = match value.to_str() {
            Ok(value) => value,
            Err(_) => return None,
        };
        for directive in value.split(',').map(str::trim) {
            let Some((name, value)) = directive.split_once('=') else {
                continue;
            };
            if name.trim().eq_ignore_ascii_case(expected) {
                return value.trim().trim_matches('"').parse::<u64>().ok().map(Some);
            }
        }
    }
    Some(None)
}

fn canonical_authority(raw: &str, scheme: &str) -> Option<String> {
    let authority = raw.trim().parse::<Authority>().ok()?;
    let host = authority.host().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let mut canonical = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    if let Some(port) = authority.port_u16()
        && !matches!((scheme, port), ("http", 80) | ("https", 443))
    {
        canonical.push(':');
        canonical.push_str(&port.to_string());
    }
    Some(canonical)
}

fn canonical_accept_encoding(raw: Option<&str>) -> String {
    let mut encodings = raw
        .unwrap_or_default()
        .split(',')
        .filter_map(|encoding| {
            let normalized = encoding
                .split(';')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(str::to_ascii_lowercase)
                .collect::<Vec<_>>()
                .join(";");
            (!normalized.is_empty()).then_some(normalized)
        })
        .collect::<Vec<_>>();
    encodings.sort_unstable();
    encodings.join(",")
}

fn canonical_request_target(path_and_query: &str) -> String {
    let path = canonical_uri_path(path_and_query);
    match path_and_query.split_once('?') {
        Some((_, query)) => format!("{path}?{query}"),
        None => path.into_owned(),
    }
}

fn canonical_uri_path(path_and_query: &str) -> Cow<'_, str> {
    let path = path_and_query
        .split_once('?')
        .map_or(path_and_query, |(path, _)| path);
    let bytes = path.as_bytes();
    let mut canonical = None::<String>;
    let mut copied_until = 0;
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_digit(bytes[index + 1]), hex_digit(bytes[index + 2]))
        {
            let decoded = high << 4 | low;
            if decoded.is_ascii_alphanumeric() || matches!(decoded, b'-' | b'.' | b'_' | b'~') {
                let output = canonical.get_or_insert_with(|| String::with_capacity(path.len()));
                output.push_str(&path[copied_until..index]);
                output.push(decoded as char);
                index += 3;
                copied_until = index;
                continue;
            }
        }
        index += 1;
    }

    match canonical {
        Some(mut output) => {
            output.push_str(&path[copied_until..]);
            Cow::Owned(output)
        }
        None => Cow::Borrowed(path),
    }
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn header_contains_token(
    headers: &HeaderMap,
    name: header::HeaderName,
    expected: &str,
) -> Result<bool, ResponseCacheBypassReason> {
    for value in headers.get_all(name).iter() {
        let value = value
            .to_str()
            .map_err(|_| ResponseCacheBypassReason::MalformedHeader)?;
        if value
            .split(',')
            .map(str::trim)
            .any(|token| token.eq_ignore_ascii_case(expected))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn header_contains_directive(
    headers: &HeaderMap,
    name: header::HeaderName,
    expected: &str,
) -> Result<bool, ResponseCacheBypassReason> {
    for value in headers.get_all(name).iter() {
        let value = value
            .to_str()
            .map_err(|_| ResponseCacheBypassReason::MalformedHeader)?;
        if value.split([',', ';']).map(str::trim).any(|directive| {
            directive
                .split_once('=')
                .map_or(directive, |(name, _)| name)
                .trim()
                .eq_ignore_ascii_case(expected)
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn push_component(key: &mut Vec<u8>, component: &[u8]) {
    key.extend_from_slice(&(component.len() as u64).to_be_bytes());
    key.extend_from_slice(component);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ResponseCachePolicyInput {
        ResponseCachePolicyInput { enabled: true }
    }

    fn request_eligibility<'a>(
        policy: ResponseCachePolicyInput,
        method: &'a str,
        headers: &'a HeaderMap,
    ) -> ResponseCacheRequestEligibilityInput<'a> {
        ResponseCacheRequestEligibilityInput {
            policy,
            route_auth_enabled: false,
            method,
            headers,
            has_body: false,
            is_upgrade: false,
            is_tunnel: false,
        }
    }

    #[test]
    fn private_requests_bypass_cache_and_head_has_its_own_representation() {
        let policy = policy();
        for name in [header::AUTHORIZATION, header::COOKIE] {
            let mut headers = HeaderMap::new();
            headers.insert(name, http::HeaderValue::from_static("private"));
            assert!(
                evaluate_cache_request_eligibility(request_eligibility(policy, "GET", &headers,))
                    .is_err()
            );
        }

        let headers = HeaderMap::new();
        assert_eq!(
            evaluate_cache_request_eligibility(request_eligibility(policy, "HEAD", &headers)),
            Ok(ResponseCacheRepresentation::Head)
        );
        let get = canonical_response_cache_key(ResponseCacheKeyInput {
            scheme: "https",
            authority: "example.com",
            path_and_query: "/asset",
            representation: ResponseCacheRepresentation::Get,
            accept_encoding: None,
            namespace: 1,
        })
        .expect("GET cache key");
        let head = canonical_response_cache_key(ResponseCacheKeyInput {
            representation: ResponseCacheRepresentation::Head,
            ..ResponseCacheKeyInput {
                scheme: "https",
                authority: "example.com",
                path_and_query: "/asset",
                representation: ResponseCacheRepresentation::Get,
                accept_encoding: None,
                namespace: 1,
            }
        })
        .expect("HEAD cache key");
        assert_ne!(get.into_primary(), head.into_primary());
    }

    #[test]
    fn authenticated_routes_bypass_cache_without_standard_auth_headers() {
        let auth_policy = ResponseCacheAuthInput {
            api_key: true,
            jwt: false,
            external_auth: false,
            required_scopes: false,
            required_roles: false,
        };
        let policy = policy();
        let headers = HeaderMap::new();
        assert_eq!(
            evaluate_cache_request_eligibility(ResponseCacheRequestEligibilityInput {
                route_auth_enabled: route_auth_requires_cache_bypass(auth_policy),
                ..request_eligibility(policy, "GET", &headers)
            }),
            Err(ResponseCacheBypassReason::Authorization)
        );
    }

    #[test]
    fn vary_policy_and_expiry_are_enforced() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::VARY,
            http::HeaderValue::from_static("accept-encoding"),
        );
        assert!(
            evaluate_cache_response_eligibility(ResponseCacheResponseEligibilityInput {
                headers: &headers,
            })
            .is_ok()
        );
        headers.insert(header::VARY, http::HeaderValue::from_static("user-agent"));
        assert_eq!(
            evaluate_cache_response_eligibility(ResponseCacheResponseEligibilityInput {
                headers: &headers,
            }),
            Err(ResponseCacheBypassReason::UnsupportedVary)
        );
        assert_eq!(
            response_cache_ttl(&HeaderMap::new(), 1, SystemTime::now()),
            None
        );
    }
}
