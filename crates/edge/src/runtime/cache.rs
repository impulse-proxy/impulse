use std::time::{Duration, SystemTime};

use http::{HeaderMap, header, uri::Authority};
use impulse_config::runtime::RuntimeResponseCachePolicy;
use pingora_cache::{
    HttpCache, MemCache, cache_control::CacheControl,
    eviction::simple_lru::Manager as LruEvictionManager, filters::calculate_expires_header_time,
    key::CacheKey, lock::CacheLock,
};
use pingora_http::ResponseHeader;

use crate::routing::util::canonical_request_target;

const CACHE_KEY_NAMESPACE: &[u8] = b"impulse-response-cache-v1";
const CACHE_LOCK_AGE_TIMEOUT: Duration = Duration::from_secs(60);
const SUPPORTED_VARY_HEADER: &str = "accept-encoding";

pub struct BoundedPingoraMemoryCache {
    storage: MemCache,
    eviction: LruEvictionManager,
    lock: CacheLock,
    max_object_bytes: usize,
}

impl BoundedPingoraMemoryCache {
    pub fn new(policy: &RuntimeResponseCachePolicy) -> Self {
        Self {
            storage: MemCache::new(),
            eviction: LruEvictionManager::new_with_watermark(
                policy.max_bytes,
                Some(policy.max_entries),
            ),
            lock: CacheLock::new(CACHE_LOCK_AGE_TIMEOUT),
            max_object_bytes: policy.max_object_bytes,
        }
    }

    pub fn enable(&'static self, cache: &mut HttpCache, max_object_bytes: usize) {
        cache.enable(
            &self.storage,
            Some(&self.eviction),
            None,
            Some(&self.lock),
            None,
        );
        cache.set_max_file_size_bytes(max_object_bytes.min(self.max_object_bytes));
    }
}

pub fn response_cache_ttl(
    response: &ResponseHeader,
    max_ttl_secs: u64,
    now: SystemTime,
) -> Option<Duration> {
    let cache_control_ttl = match CacheControl::from_resp_headers(response) {
        Some(cache_control)
            if cache_control.no_cache()
                || cache_control.no_store()
                || cache_control.has_key("private") =>
        {
            return None;
        }
        Some(cache_control) => cache_control
            .s_maxage()
            .ok()?
            .or(cache_control.max_age().ok()?)
            .map(u64::from),
        None => None,
    };
    let origin_ttl = match cache_control_ttl {
        Some(seconds) => Some(Duration::from_secs(seconds)),
        None if response.headers.contains_key(header::EXPIRES) => Some(
            calculate_expires_header_time(response)?
                .duration_since(now)
                .ok()?,
        ),
        None => None,
    };
    let ttl = origin_ttl
        .unwrap_or_else(|| Duration::from_secs(max_ttl_secs))
        .min(Duration::from_secs(max_ttl_secs));
    (!ttl.is_zero()).then_some(ttl)
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
    SetCookie,
    Private,
    NoStore,
    MalformedHeader,
    UnsupportedVary,
}

pub struct ResponseCacheRequestEligibilityInput<'a> {
    pub policy: &'a RuntimeResponseCachePolicy,
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
    if input.headers.contains_key(header::AUTHORIZATION) {
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
    match input.method {
        method if method.eq_ignore_ascii_case("GET") => Ok(ResponseCacheRepresentation::Get),
        method if method.eq_ignore_ascii_case("HEAD") => Ok(ResponseCacheRepresentation::Head),
        _ => Err(ResponseCacheBypassReason::UnsupportedMethod),
    }
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
    pub generation: u64,
}

pub fn canonical_response_cache_key(input: ResponseCacheKeyInput<'_>) -> Option<CacheKey> {
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
    push_component(&mut primary, &input.generation.to_be_bytes());
    push_component(&mut primary, scheme.as_bytes());
    push_component(&mut primary, authority.as_bytes());
    push_component(&mut primary, target.as_bytes());
    push_component(&mut primary, input.representation.as_bytes());
    push_component(&mut primary, SUPPORTED_VARY_HEADER.as_bytes());
    push_component(&mut primary, accept_encoding.as_bytes());

    Some(CacheKey::new(primary, ""))
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
