#[cfg(test)]
use impulse_config::config::ScopedRateLimitScope;
use impulse_config::runtime::{RuntimeLoadBalancingStrategy, RuntimeRequestKeySpec};

use super::*;
use crate::resilience::quota::{
    QuotaIdentityContext, RequestKeyExtraction, extract_runtime_request_key,
};

pub(in crate::quic_listener::forwarding) struct LbKeyRequestParts<'a> {
    method: &'a str,
    path: &'a str,
    authority: Option<&'a str>,
    cid_key: Option<&'a str>,
    client_addr: Option<SocketAddr>,
    header_lookup: Option<&'a LbHeaderLookup<'a>>,
}

impl<'a> LbKeyRequestParts<'a> {
    pub(in crate::quic_listener::forwarding) fn new(
        method: &'a str,
        path: &'a str,
        authority: Option<&'a str>,
        cid_key: Option<&'a str>,
        client_addr: Option<SocketAddr>,
        header_lookup: Option<&'a LbHeaderLookup<'a>>,
    ) -> Self {
        Self {
            method,
            path,
            authority,
            cid_key,
            client_addr,
            header_lookup,
        }
    }
}

#[cfg(test)]
struct LbKeyResolutionInput<'a> {
    lb_type: &'a str,
    lb_key_spec: Option<&'a str>,
    request: LbKeyRequestParts<'a>,
}

#[cfg(test)]
impl<'a> LbKeyResolutionInput<'a> {
    fn new(lb_type: &'a str, lb_key_spec: Option<&'a str>, request: LbKeyRequestParts<'a>) -> Self {
        Self {
            lb_type,
            lb_key_spec,
            request,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LbKeySource {
    ConfiguredSpec,
    StickyCidFallback,
    DefaultFallback,
}

pub(super) struct ResolvedLbKey {
    pub(super) value: String,
    pub(super) source: LbKeySource,
}

#[cfg(test)]
fn extract_cookie_value(cookie_header: &str, cookie_name: &str) -> Option<String> {
    for pair in cookie_header.split(';') {
        let part = pair.trim();
        if part.is_empty() {
            continue;
        }
        let (name, value) = part.split_once('=')?;
        if name.trim().eq_ignore_ascii_case(cookie_name) {
            let value = value.trim();
            if value.is_empty() {
                return None;
            }
            return Some(value.to_string());
        }
    }
    None
}

#[cfg(test)]
fn extract_query_param(path: &str, param: &str) -> Option<String> {
    let (_, query) = path.split_once('?')?;
    for pair in query.split('&') {
        let entry = pair.trim();
        if entry.is_empty() {
            continue;
        }
        let (name, value) = entry.split_once('=')?;
        if name.eq_ignore_ascii_case(param) && !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

impl QUICListener {
    pub(in crate::quic_listener::forwarding) fn resolve_lb_key_for_runtime_request(
        lb_strategy: RuntimeLoadBalancingStrategy,
        lb_key_spec: Option<&RuntimeRequestKeySpec>,
        request: &super::resolve::TargetResolutionRequest<'_>,
    ) -> ResolvedLbKey {
        let request = LbKeyRequestParts::new(
            request.method,
            request.path,
            request.authority,
            request.cid_key,
            None,
            request.header_lookup,
        );
        Self::resolve_lb_key_for_runtime_input(lb_strategy, lb_key_spec, &request)
    }

    #[cfg(test)]
    pub(in crate::quic_listener::forwarding) fn resolve_lb_key(
        lb_type: &str,
        lb_key_spec: Option<&str>,
        request: LbKeyRequestParts<'_>,
    ) -> ResolvedLbKey {
        Self::resolve_lb_key_for_input(&LbKeyResolutionInput::new(lb_type, lb_key_spec, request))
    }

    fn resolve_lb_key_from_runtime_parts(
        lb_key_spec: &RuntimeRequestKeySpec,
        request: &LbKeyRequestParts<'_>,
    ) -> Option<String> {
        let context = QuotaIdentityContext::new(
            None,
            request.method,
            request.path,
            request.authority,
            request.cid_key,
            request.client_addr,
            request.header_lookup,
        );

        match extract_runtime_request_key(lb_key_spec, &context) {
            RequestKeyExtraction::Found(value) => Some(value),
            RequestKeyExtraction::Missing | RequestKeyExtraction::Invalid => None,
        }
    }

    #[cfg(test)]
    fn resolve_lb_key_from_parts(
        lb_key_spec: &str,
        request: &LbKeyRequestParts<'_>,
    ) -> Option<String> {
        let spec = lb_key_spec.trim();
        if spec.is_empty() {
            return None;
        }

        if spec.eq_ignore_ascii_case("path") {
            let path_only = request
                .path
                .split_once('?')
                .map(|(p, _)| p)
                .unwrap_or(request.path);
            return Some(path_only.to_string());
        }
        if spec.eq_ignore_ascii_case("authority") {
            return request.authority.map(str::to_string);
        }
        if spec.eq_ignore_ascii_case("method") {
            return Some(request.method.to_string());
        }
        if spec.eq_ignore_ascii_case("cid") || spec.eq_ignore_ascii_case("sticky-cid") {
            return request.cid_key.map(str::to_string);
        }
        if spec.eq_ignore_ascii_case("peer_ip") || spec.eq_ignore_ascii_case("client_ip") {
            return request.client_addr.map(|addr| addr.ip().to_string());
        }
        if spec.eq_ignore_ascii_case("bearer_token") {
            let raw = request
                .header_lookup
                .and_then(|lookup| lookup(http::header::AUTHORIZATION.as_str()))?;
            return Self::bearer_token_from_authorization_value(&raw);
        }

        let (source, key_name) = spec.split_once(':')?;
        let key_name = key_name.trim();
        if key_name.is_empty() {
            return None;
        }

        if source.eq_ignore_ascii_case("header") {
            return request.header_lookup.and_then(|lookup| lookup(key_name));
        }

        if source.eq_ignore_ascii_case("cookie") {
            let cookie_header = request
                .header_lookup
                .and_then(|lookup| lookup(http::header::COOKIE.as_str()))?;
            return extract_cookie_value(cookie_header.as_str(), key_name);
        }

        if source.eq_ignore_ascii_case("query") {
            return extract_query_param(request.path, key_name);
        }

        None
    }

    fn default_lb_request_key_for_parts(request: &LbKeyRequestParts<'_>) -> String {
        request
            .authority
            .unwrap_or(if !request.path.is_empty() {
                request.path
            } else {
                request.method
            })
            .to_string()
    }

    #[cfg(test)]
    fn resolve_lb_key_for_input(input: &LbKeyResolutionInput<'_>) -> ResolvedLbKey {
        let default_key = Self::default_lb_request_key_for_parts(&input.request);

        if let Some(spec) = input.lb_key_spec
            && let Some(value) = Self::resolve_lb_key_from_parts(spec, &input.request)
            && !value.is_empty()
        {
            return ResolvedLbKey {
                value,
                source: LbKeySource::ConfiguredSpec,
            };
        }

        if input.lb_type == "sticky-cid"
            && let Some(cid_key) = input.request.cid_key
        {
            return ResolvedLbKey {
                value: cid_key.to_string(),
                source: LbKeySource::StickyCidFallback,
            };
        }

        ResolvedLbKey {
            value: default_key,
            source: LbKeySource::DefaultFallback,
        }
    }

    fn resolve_lb_key_for_runtime_input(
        lb_strategy: RuntimeLoadBalancingStrategy,
        lb_key_spec: Option<&RuntimeRequestKeySpec>,
        request: &LbKeyRequestParts<'_>,
    ) -> ResolvedLbKey {
        let default_key = Self::default_lb_request_key_for_parts(request);

        if let Some(spec) = lb_key_spec
            && let Some(value) = Self::resolve_lb_key_from_runtime_parts(spec, request)
            && !value.is_empty()
        {
            return ResolvedLbKey {
                value,
                source: LbKeySource::ConfiguredSpec,
            };
        }

        if matches!(lb_strategy, RuntimeLoadBalancingStrategy::StickyCid)
            && let Some(cid_key) = request.cid_key
        {
            return ResolvedLbKey {
                value: cid_key.to_string(),
                source: LbKeySource::StickyCidFallback,
            };
        }

        ResolvedLbKey {
            value: default_key,
            source: LbKeySource::DefaultFallback,
        }
    }

    pub(in crate::quic_listener) fn bearer_token_from_authorization_value(
        raw: &str,
    ) -> Option<String> {
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
        Some(token.to_string())
    }
}

#[cfg(test)]
impl QUICListener {
    pub(crate) fn resolve_scoped_rate_limit_key(
        rule: &crate::resilience::scoped_rate_limit::ScopedRateLimitRule,
        route: &str,
        method: &str,
        path: &str,
        authority: Option<&str>,
        client_addr: SocketAddr,
        header_lookup: Option<&LbHeaderLookup<'_>>,
    ) -> Option<String> {
        match rule.scope() {
            ScopedRateLimitScope::Route => Some(route.to_string()),
            ScopedRateLimitScope::Client => Some(
                Self::resolve_lb_key(
                    "",
                    Some(rule.key_spec().unwrap_or("peer_ip")),
                    LbKeyRequestParts::new(
                        method,
                        path,
                        authority,
                        None,
                        Some(client_addr),
                        header_lookup,
                    ),
                )
                .value,
            ),
            ScopedRateLimitScope::Tenant => rule.key_spec().map(|key_spec| {
                Self::resolve_lb_key(
                    "",
                    Some(key_spec),
                    LbKeyRequestParts::new(
                        method,
                        path,
                        authority,
                        None,
                        Some(client_addr),
                        header_lookup,
                    ),
                )
                .value
            }),
            ScopedRateLimitScope::Token => Some(
                Self::resolve_lb_key(
                    "",
                    Some(rule.key_spec().unwrap_or("bearer_token")),
                    LbKeyRequestParts::new(
                        method,
                        path,
                        authority,
                        None,
                        Some(client_addr),
                        header_lookup,
                    ),
                )
                .value,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, net::SocketAddr};

    use impulse_config::runtime::{RuntimeLoadBalancingStrategy, RuntimeRequestKeySpec};

    use super::{LbKeyRequestParts, LbKeySource, QUICListener, ResolvedLbKey};

    fn request_parts_with_headers(
        method: &'static str,
        path: &'static str,
        authority: Option<&'static str>,
        cid_key: Option<&'static str>,
        client_addr: Option<SocketAddr>,
        headers: HashMap<String, String>,
    ) -> LbKeyRequestParts<'static> {
        let leaked = Box::leak(Box::new(headers));
        let lookup = Box::leak(Box::new(move |name: &str| {
            leaked.get(&name.to_ascii_lowercase()).cloned()
        }));
        LbKeyRequestParts::new(method, path, authority, cid_key, client_addr, Some(lookup))
    }

    fn assert_resolved(
        resolved: ResolvedLbKey,
        expected_value: &str,
        expected_source: LbKeySource,
    ) {
        assert_eq!(resolved.value, expected_value);
        assert_eq!(resolved.source, expected_source);
    }

    #[test]
    fn missing_hash_inputs_fall_back_to_authority_path_or_method_as_intended() {
        let header_request = request_parts_with_headers(
            "POST",
            "/orders?tenant=acme",
            Some("api.example.com"),
            None,
            None,
            HashMap::new(),
        );
        assert_resolved(
            QUICListener::resolve_lb_key_for_runtime_input(
                RuntimeLoadBalancingStrategy::ConsistentHash,
                Some(&RuntimeRequestKeySpec::Header("x-user-id".to_string())),
                &header_request,
            ),
            "api.example.com",
            LbKeySource::DefaultFallback,
        );

        let path_request = request_parts_with_headers(
            "POST",
            "/orders?tenant=acme",
            None,
            None,
            None,
            HashMap::new(),
        );
        assert_resolved(
            QUICListener::resolve_lb_key_for_runtime_input(
                RuntimeLoadBalancingStrategy::ConsistentHash,
                Some(&RuntimeRequestKeySpec::Header("x-user-id".to_string())),
                &path_request,
            ),
            "/orders?tenant=acme",
            LbKeySource::DefaultFallback,
        );

        let method_request =
            request_parts_with_headers("POST", "", None, None, None, HashMap::new());
        assert_resolved(
            QUICListener::resolve_lb_key_for_runtime_input(
                RuntimeLoadBalancingStrategy::ConsistentHash,
                Some(&RuntimeRequestKeySpec::Header("x-user-id".to_string())),
                &method_request,
            ),
            "POST",
            LbKeySource::DefaultFallback,
        );

        let sticky_request = request_parts_with_headers(
            "GET",
            "/resource",
            Some("api.example.com"),
            Some("cid-123"),
            None,
            HashMap::new(),
        );
        assert_resolved(
            QUICListener::resolve_lb_key_for_runtime_input(
                RuntimeLoadBalancingStrategy::StickyCid,
                Some(&RuntimeRequestKeySpec::Header("x-user-id".to_string())),
                &sticky_request,
            ),
            "cid-123",
            LbKeySource::StickyCidFallback,
        );
    }

    #[test]
    fn equivalent_requests_build_identical_keys_across_direct_and_runtime_paths() {
        let headers = HashMap::from([
            ("cookie".to_string(), "session=s123; theme=dark".to_string()),
            ("authorization".to_string(), "Bearer token-1".to_string()),
        ]);
        let request = request_parts_with_headers(
            "GET",
            "/orders?tenant=acme",
            Some("api.example.com"),
            Some("cid-777"),
            Some("203.0.113.9:443".parse().expect("client addr")),
            headers,
        );

        let direct = QUICListener::resolve_lb_key(
            "consistent-hash",
            Some("cookie:session"),
            LbKeyRequestParts::new(
                request.method,
                request.path,
                request.authority,
                request.cid_key,
                request.client_addr,
                request.header_lookup,
            ),
        );
        let runtime = QUICListener::resolve_lb_key_for_runtime_input(
            RuntimeLoadBalancingStrategy::ConsistentHash,
            Some(&RuntimeRequestKeySpec::Cookie("session".to_string())),
            &request,
        );

        assert_eq!(direct.value, runtime.value);
        assert_eq!(direct.source, runtime.source);
    }

    #[test]
    fn key_resolution_does_not_drift_with_header_order_or_absent_optional_fields() {
        let first = request_parts_with_headers(
            "GET",
            "/orders?tenant=acme",
            Some("api.example.com"),
            None,
            None,
            HashMap::from([
                ("x-user-id".to_string(), "alice".to_string()),
                ("cookie".to_string(), "session=s123".to_string()),
            ]),
        );
        let second = request_parts_with_headers(
            "GET",
            "/orders?tenant=acme",
            Some("api.example.com"),
            None,
            None,
            HashMap::from([
                ("cookie".to_string(), "session=s123".to_string()),
                ("x-user-id".to_string(), "alice".to_string()),
            ]),
        );

        let first_header = QUICListener::resolve_lb_key_for_runtime_input(
            RuntimeLoadBalancingStrategy::ConsistentHash,
            Some(&RuntimeRequestKeySpec::Header("x-user-id".to_string())),
            &first,
        );
        let second_header = QUICListener::resolve_lb_key_for_runtime_input(
            RuntimeLoadBalancingStrategy::ConsistentHash,
            Some(&RuntimeRequestKeySpec::Header("x-user-id".to_string())),
            &second,
        );
        assert_eq!(first_header.value, second_header.value);
        assert_eq!(first_header.source, second_header.source);

        let missing_cookie = request_parts_with_headers(
            "GET",
            "/orders?tenant=acme",
            Some("api.example.com"),
            None,
            None,
            HashMap::from([("x-user-id".to_string(), "alice".to_string())]),
        );
        assert_resolved(
            QUICListener::resolve_lb_key_for_runtime_input(
                RuntimeLoadBalancingStrategy::ConsistentHash,
                Some(&RuntimeRequestKeySpec::Cookie("session".to_string())),
                &missing_cookie,
            ),
            "api.example.com",
            LbKeySource::DefaultFallback,
        );
    }

    #[test]
    fn runtime_key_resolver_extracts_each_canonical_source_type() {
        let request = request_parts_with_headers(
            "POST",
            "/api/items?tenant=acme&region=us",
            Some("api.example.com"),
            Some("cid-123"),
            Some("203.0.113.9:443".parse().expect("client addr")),
            HashMap::from([
                ("authorization".to_string(), "Bearer token-3".to_string()),
                (
                    "cookie".to_string(),
                    "session=s123; theme=dark; empty=".to_string(),
                ),
                ("x-user-id".to_string(), "alice".to_string()),
            ]),
        );

        let assert_runtime_key = |spec: RuntimeRequestKeySpec, expected: &str| {
            let resolved = QUICListener::resolve_lb_key_for_runtime_input(
                RuntimeLoadBalancingStrategy::ConsistentHash,
                Some(&spec),
                &request,
            );
            assert_resolved(resolved, expected, LbKeySource::ConfiguredSpec);
        };

        assert_runtime_key(
            RuntimeRequestKeySpec::Header("x-user-id".to_string()),
            "alice",
        );
        assert_runtime_key(RuntimeRequestKeySpec::Cookie("session".to_string()), "s123");
        assert_runtime_key(RuntimeRequestKeySpec::Query("tenant".to_string()), "acme");
        assert_runtime_key(RuntimeRequestKeySpec::BearerToken, "token-3");
        assert_runtime_key(RuntimeRequestKeySpec::Cid, "cid-123");
        assert_runtime_key(RuntimeRequestKeySpec::StickyCid, "cid-123");
        assert_runtime_key(RuntimeRequestKeySpec::PeerIp, "203.0.113.9");
        assert_runtime_key(RuntimeRequestKeySpec::ClientIp, "203.0.113.9");
        assert_runtime_key(RuntimeRequestKeySpec::Path, "/api/items");
        assert_runtime_key(RuntimeRequestKeySpec::Authority, "api.example.com");
        assert_runtime_key(RuntimeRequestKeySpec::Method, "POST");
    }

    #[test]
    fn direct_key_resolver_falls_back_for_invalid_or_missing_key_sources() {
        let request = request_parts_with_headers(
            "GET",
            "/resource?tenant=&region=us",
            Some("api.example.com"),
            Some("cid-456"),
            Some("198.51.100.2:443".parse().expect("client addr")),
            HashMap::from([
                ("authorization".to_string(), "Basic abc".to_string()),
                ("cookie".to_string(), "session=; theme=dark".to_string()),
            ]),
        );

        let assert_default_fallback = |spec: &str, expected: &str| {
            let resolved = QUICListener::resolve_lb_key(
                "",
                Some(spec),
                LbKeyRequestParts::new(
                    request.method,
                    request.path,
                    request.authority,
                    request.cid_key,
                    request.client_addr,
                    request.header_lookup,
                ),
            );
            assert_resolved(resolved, expected, LbKeySource::DefaultFallback);
        };

        assert_default_fallback("header:x-user-id", "api.example.com");
        assert_default_fallback("header:", "api.example.com");
        assert_default_fallback("cookie:session", "api.example.com");
        assert_default_fallback("query:tenant", "api.example.com");
        assert_default_fallback("bearer_token", "api.example.com");
        assert_default_fallback("not-a-real-spec", "api.example.com");
    }

    #[test]
    fn sticky_cid_runtime_strategy_uses_cid_before_default_fallback() {
        let sticky_request = request_parts_with_headers(
            "GET",
            "/resource",
            Some("api.example.com"),
            Some("cid-999"),
            None,
            HashMap::new(),
        );
        assert_resolved(
            QUICListener::resolve_lb_key_for_runtime_input(
                RuntimeLoadBalancingStrategy::StickyCid,
                Some(&RuntimeRequestKeySpec::Header("x-missing".to_string())),
                &sticky_request,
            ),
            "cid-999",
            LbKeySource::StickyCidFallback,
        );

        let no_cid_request = request_parts_with_headers(
            "GET",
            "/resource",
            Some("api.example.com"),
            None,
            None,
            HashMap::new(),
        );
        assert_resolved(
            QUICListener::resolve_lb_key_for_runtime_input(
                RuntimeLoadBalancingStrategy::StickyCid,
                Some(&RuntimeRequestKeySpec::Header("x-missing".to_string())),
                &no_cid_request,
            ),
            "api.example.com",
            LbKeySource::DefaultFallback,
        );
    }
}
