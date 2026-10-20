use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use http::{HeaderMap, header, uri::Authority};
use impulse_config::runtime::{RuntimeAuthPolicy, RuntimeResponseCachePolicy};
use pingora_cache::{
    HttpCache, MemCache,
    cache_control::CacheControl,
    eviction::{
        CacheEntryKey, CacheEntryKeyRef, EvictionManager, simple_lru::Manager as LruEvictionManager,
    },
    filters::calculate_expires_header_time,
    key::CacheKey,
    lock::CacheLock,
};
use pingora_http::ResponseHeader;

use crate::{Metrics, metrics::ResponseCacheOutcome, routing::util::canonical_request_target};

const CACHE_KEY_NAMESPACE: &[u8] = b"impulse-response-cache-v1";
const CACHE_LOCK_AGE_TIMEOUT: Duration = Duration::from_secs(60);
const SUPPORTED_VARY_HEADER: &str = "accept-encoding";

pub struct BoundedPingoraMemoryCache {
    storage: MemCache,
    eviction: ObservedEvictionManager,
    lock: CacheLock,
    max_object_bytes: usize,
}

impl BoundedPingoraMemoryCache {
    pub fn new(policy: &RuntimeResponseCachePolicy, metrics: Arc<Metrics>) -> Self {
        Self {
            storage: MemCache::new(),
            eviction: ObservedEvictionManager {
                inner: LruEvictionManager::new_with_watermark(
                    policy.max_bytes,
                    Some(policy.max_entries),
                ),
                metrics,
            },
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

struct ObservedEvictionManager {
    inner: LruEvictionManager,
    metrics: Arc<Metrics>,
}

impl ObservedEvictionManager {
    fn record(&self, evicted: Vec<CacheEntryKey>) -> Vec<CacheEntryKey> {
        self.metrics
            .add_response_cache_outcomes(ResponseCacheOutcome::Eviction, evicted.len());
        evicted
    }
}

#[async_trait]
impl EvictionManager for ObservedEvictionManager {
    fn total_size(&self) -> usize {
        self.inner.total_size()
    }
    fn total_items(&self) -> usize {
        self.inner.total_items()
    }
    fn evicted_size(&self) -> usize {
        self.inner.evicted_size()
    }
    fn evicted_items(&self) -> usize {
        self.inner.evicted_items()
    }

    fn admit(
        &self,
        item: CacheEntryKey,
        size: usize,
        fresh_until: SystemTime,
    ) -> Vec<CacheEntryKey> {
        self.record(self.inner.admit(item, size, fresh_until))
    }

    fn increment_weight(
        &self,
        item: &CacheEntryKey,
        delta: usize,
        max_weight: Option<usize>,
    ) -> Vec<CacheEntryKey> {
        self.record(self.inner.increment_weight(item, delta, max_weight))
    }

    fn remove(&self, item: CacheEntryKeyRef<'_>) {
        self.inner.remove(item);
    }

    fn access(&self, item: &CacheEntryKey, size: usize, fresh_until: SystemTime) -> bool {
        self.inner.access(item, size, fresh_until)
    }

    fn peek(&self, item: &CacheEntryKey) -> bool {
        self.inner.peek(item)
    }

    async fn save(&self, dir_path: &str) -> pingora_core::Result<()> {
        self.inner.save(dir_path).await
    }

    async fn load(&self, dir_path: &str) -> pingora_core::Result<()> {
        self.inner.load(dir_path).await
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
    match input.method {
        method if method.eq_ignore_ascii_case("GET") => Ok(ResponseCacheRepresentation::Get),
        method if method.eq_ignore_ascii_case("HEAD") => Ok(ResponseCacheRepresentation::Head),
        _ => Err(ResponseCacheBypassReason::UnsupportedMethod),
    }
}

pub fn route_auth_requires_cache_bypass(policy: &RuntimeAuthPolicy) -> bool {
    policy.api_key.is_some()
        || policy.jwt.is_some()
        || policy.external_auth.is_some()
        || !policy.required_scopes.is_empty()
        || !policy.required_roles.is_empty()
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
    pub namespace: u64,
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
    push_component(&mut primary, &input.namespace.to_be_bytes());
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

#[cfg(test)]
mod tests {
    use impulse_config::runtime::RuntimeApiKeyAuth;
    use pingora_cache::CacheMeta;

    use super::*;

    fn policy(max_bytes: usize, max_entries: usize) -> RuntimeResponseCachePolicy {
        RuntimeResponseCachePolicy {
            enabled: true,
            max_bytes,
            max_entries,
            max_object_bytes: max_bytes,
            max_ttl_secs: 60,
        }
    }

    fn request_eligibility<'a>(
        method: &'a str,
        headers: &'a HeaderMap,
    ) -> ResponseCacheRequestEligibilityInput<'a> {
        ResponseCacheRequestEligibilityInput {
            policy: Box::leak(Box::new(policy(1024, 8))),
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
        for name in [header::AUTHORIZATION, header::COOKIE] {
            let mut headers = HeaderMap::new();
            headers.insert(name, http::HeaderValue::from_static("private"));
            assert!(
                evaluate_cache_request_eligibility(request_eligibility("GET", &headers)).is_err()
            );
        }

        let headers = HeaderMap::new();
        assert_eq!(
            evaluate_cache_request_eligibility(request_eligibility("HEAD", &headers)),
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
        assert_ne!(get.primary_key_str(), head.primary_key_str());
    }

    #[test]
    fn authenticated_routes_bypass_cache_without_standard_auth_headers() {
        let auth_policy = RuntimeAuthPolicy {
            api_key: Some(RuntimeApiKeyAuth {
                header_name: "x-api-key".to_string(),
                keys: vec!["tenant-key".to_string()],
            }),
            ..RuntimeAuthPolicy::default()
        };
        let headers = HeaderMap::new();
        assert_eq!(
            evaluate_cache_request_eligibility(ResponseCacheRequestEligibilityInput {
                route_auth_enabled: route_auth_requires_cache_bypass(&auth_policy),
                ..request_eligibility("GET", &headers)
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

        let now = SystemTime::now();
        let response = ResponseHeader::build(http::StatusCode::OK, None).expect("response");
        let ttl = response_cache_ttl(&response, 1, now).expect("bounded cache TTL");
        let meta = CacheMeta::new(
            now.checked_add(ttl).expect("fresh timestamp"),
            now,
            0,
            0,
            response,
        );
        assert!(meta.is_fresh(now));
        assert!(!meta.is_fresh(now + Duration::from_secs(2)));
    }

    #[test]
    fn eviction_keeps_cache_within_memory_and_entry_bounds() {
        let metrics = Arc::new(Metrics::default());
        let cache = BoundedPingoraMemoryCache::new(&policy(8, 2), Arc::clone(&metrics));
        let first = CacheEntryKey::key_only(CacheKey::new("first", "").to_compact());
        let second = CacheEntryKey::key_only(CacheKey::new("second", "").to_compact());
        let third = CacheEntryKey::key_only(CacheKey::new("third", "").to_compact());

        assert!(cache.eviction.admit(first, 4, SystemTime::now()).is_empty());
        assert!(
            cache
                .eviction
                .admit(second, 4, SystemTime::now())
                .is_empty()
        );
        assert_eq!(cache.eviction.admit(third, 4, SystemTime::now()).len(), 1);
        assert!(cache.eviction.total_size() <= 8);
        assert!(cache.eviction.total_items() <= 2);
        assert!(
            metrics
                .render_prometheus()
                .contains("impulse_response_cache_outcomes_total{outcome=\"eviction\"} 1\n")
        );
    }
}
