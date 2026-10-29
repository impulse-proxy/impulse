use std::net::SocketAddr;

use impulse_config::runtime::RuntimeRequestKeySpec;
use impulse_contracts::{RateLimitedDecision, RequestDecision};

const MAX_REQUEST_DERIVED_IDENTITY_BYTES: usize = 256;

pub type ScopedRateLimitHeaderLookup<'a> = dyn Fn(&str) -> Option<String> + Sync + 'a;

#[derive(Clone, Copy)]
pub struct ScopedRateLimitIdentity<'a> {
    pub route: Option<&'a str>,
    pub method: &'a str,
    pub path: &'a str,
    pub authority: Option<&'a str>,
    pub cid_key: Option<&'a str>,
    pub client_addr: Option<SocketAddr>,
    pub header_lookup: Option<&'a ScopedRateLimitHeaderLookup<'a>>,
}

impl<'a> ScopedRateLimitIdentity<'a> {
    #[must_use]
    pub fn new(
        route: Option<&'a str>,
        method: &'a str,
        path: &'a str,
        authority: Option<&'a str>,
        cid_key: Option<&'a str>,
        client_addr: Option<SocketAddr>,
        header_lookup: Option<&'a ScopedRateLimitHeaderLookup<'a>>,
    ) -> Self {
        Self {
            route,
            method,
            path,
            authority,
            cid_key,
            client_addr,
            header_lookup,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopedRateLimitKeyExtraction {
    Found(String),
    Missing,
    Invalid,
}

#[must_use]
pub fn extract_scoped_rate_limit_key(
    spec: &RuntimeRequestKeySpec,
    context: &ScopedRateLimitIdentity<'_>,
) -> ScopedRateLimitKeyExtraction {
    match spec {
        RuntimeRequestKeySpec::Path => bounded(path_without_query(context.path)),
        RuntimeRequestKeySpec::Authority => optional_bounded(context.authority),
        RuntimeRequestKeySpec::Method => {
            let method = context.method.trim();
            if method.is_empty() {
                ScopedRateLimitKeyExtraction::Missing
            } else {
                ScopedRateLimitKeyExtraction::Found(method.to_ascii_uppercase())
            }
        }
        RuntimeRequestKeySpec::Cid | RuntimeRequestKeySpec::StickyCid => {
            optional_bounded(context.cid_key)
        }
        RuntimeRequestKeySpec::PeerIp | RuntimeRequestKeySpec::ClientIp => context
            .client_addr
            .map(|address| ScopedRateLimitKeyExtraction::Found(address.ip().to_string()))
            .unwrap_or(ScopedRateLimitKeyExtraction::Missing),
        RuntimeRequestKeySpec::BearerToken => bearer_token(context.header_lookup),
        RuntimeRequestKeySpec::Header(name) => header_value(name, context.header_lookup),
        RuntimeRequestKeySpec::Cookie(name) => cookie_value(name, context.header_lookup),
        RuntimeRequestKeySpec::Query(name) => query_value(context.path, name),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopedRateLimitEvaluation {
    Admit,
    Deny {
        rule_name: String,
        retry_after_seconds: u32,
    },
}

#[must_use]
pub fn evaluate_scoped_rate_limit(
    route: &str,
    evaluation: ScopedRateLimitEvaluation,
) -> RequestDecision {
    match evaluation {
        ScopedRateLimitEvaluation::Admit => RequestDecision::AdmitReady,
        ScopedRateLimitEvaluation::Deny {
            rule_name,
            retry_after_seconds,
        } => RequestDecision::RateLimited(RateLimitedDecision {
            rule_name,
            route: route.to_string(),
            status: http::StatusCode::TOO_MANY_REQUESTS,
            body: b"request rate limited\n",
            retry_after_seconds: retry_after_seconds.max(1),
        }),
    }
}

fn path_without_query(path: &str) -> &str {
    path.split_once('?').map_or(path, |(value, _)| value)
}

fn optional_bounded(value: Option<&str>) -> ScopedRateLimitKeyExtraction {
    value.map_or(ScopedRateLimitKeyExtraction::Missing, bounded)
}

fn bearer_token(lookup: Option<&ScopedRateLimitHeaderLookup<'_>>) -> ScopedRateLimitKeyExtraction {
    let Some(raw) = lookup.and_then(|lookup| lookup(http::header::AUTHORIZATION.as_str())) else {
        return ScopedRateLimitKeyExtraction::Missing;
    };
    let raw = raw.trim();
    let Some(split) = raw.find(char::is_whitespace) else {
        return ScopedRateLimitKeyExtraction::Invalid;
    };
    let (scheme, value) = raw.split_at(split);
    if !scheme.eq_ignore_ascii_case("bearer") {
        return ScopedRateLimitKeyExtraction::Invalid;
    }
    let value = value.trim_start();
    if value.is_empty() {
        ScopedRateLimitKeyExtraction::Invalid
    } else {
        bounded(value)
    }
}

fn header_value(
    name: &str,
    lookup: Option<&ScopedRateLimitHeaderLookup<'_>>,
) -> ScopedRateLimitKeyExtraction {
    lookup
        .and_then(|lookup| lookup(name))
        .map_or(ScopedRateLimitKeyExtraction::Missing, |value| {
            bounded(&value)
        })
}

fn cookie_value(
    cookie_name: &str,
    lookup: Option<&ScopedRateLimitHeaderLookup<'_>>,
) -> ScopedRateLimitKeyExtraction {
    let Some(cookies) = lookup.and_then(|lookup| lookup(http::header::COOKIE.as_str())) else {
        return ScopedRateLimitKeyExtraction::Missing;
    };
    cookies
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case(cookie_name))
        .map_or(ScopedRateLimitKeyExtraction::Missing, |(_, value)| {
            bounded(value)
        })
}

fn query_value(path: &str, parameter: &str) -> ScopedRateLimitKeyExtraction {
    let Some((_, query)) = path.split_once('?') else {
        return ScopedRateLimitKeyExtraction::Missing;
    };
    query
        .split('&')
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| name.eq_ignore_ascii_case(parameter))
        .map_or(ScopedRateLimitKeyExtraction::Missing, |(_, value)| {
            bounded(value)
        })
}

fn bounded(value: &str) -> ScopedRateLimitKeyExtraction {
    let value = value.trim();
    if value.is_empty() {
        ScopedRateLimitKeyExtraction::Missing
    } else if value.len() > MAX_REQUEST_DERIVED_IDENTITY_BYTES {
        ScopedRateLimitKeyExtraction::Invalid
    } else {
        ScopedRateLimitKeyExtraction::Found(value.to_string())
    }
}
