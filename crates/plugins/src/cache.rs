use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::SystemTime,
};

use http::{HeaderMap, StatusCode};
use impulse_contracts::PluginRequestView;
use impulse_policy::{
    ResponseCacheBypassReason, ResponseCacheKeyInput, ResponseCachePolicyInput,
    ResponseCacheRepresentation, ResponseCacheRequestEligibilityInput,
    ResponseCacheResponseEligibilityInput, canonical_response_cache_key,
    evaluate_cache_request_eligibility, evaluate_cache_response_eligibility, response_cache_ttl,
};

use crate::{CachePluginFillDecision, ResponseCacheInput};

pub struct ResponseCacheKeyParts<'a> {
    pub scheme: &'a str,
    pub authority: &'a str,
    pub path_and_query: &'a str,
    pub representation: ResponseCacheRepresentation,
    pub accept_encoding: Option<&'a str>,
}

pub struct CompiledResponseCache {
    input: ResponseCacheInput,
    namespace: Arc<AtomicU64>,
}

impl CompiledResponseCache {
    pub(crate) fn new(input: ResponseCacheInput, namespace: Arc<AtomicU64>) -> Self {
        Self { input, namespace }
    }

    pub fn request_eligibility(
        &self,
        request: PluginRequestView<'_>,
        headers: &HeaderMap,
        is_upgrade: bool,
        is_tunnel: bool,
    ) -> Result<ResponseCacheRepresentation, ResponseCacheBypassReason> {
        evaluate_cache_request_eligibility(ResponseCacheRequestEligibilityInput {
            policy: ResponseCachePolicyInput { enabled: true },
            route_auth_enabled: self.input.authenticated_route,
            method: request.method,
            headers,
            has_body: request.has_body,
            is_upgrade,
            is_tunnel,
        })
    }

    #[must_use]
    pub fn fill_decision(
        &self,
        status: StatusCode,
        headers: &HeaderMap,
        fill_enabled: bool,
        now: SystemTime,
    ) -> CachePluginFillDecision {
        if !fill_enabled {
            return CachePluginFillDecision::Disabled;
        }
        if status != StatusCode::OK
            || evaluate_cache_response_eligibility(ResponseCacheResponseEligibilityInput {
                headers,
            })
            .is_err()
        {
            return CachePluginFillDecision::Reject;
        }
        let Some(ttl) = response_cache_ttl(headers, self.input.max_ttl_seconds, now) else {
            return CachePluginFillDecision::Reject;
        };
        let Some(fresh_until) = now.checked_add(ttl) else {
            return CachePluginFillDecision::Reject;
        };
        CachePluginFillDecision::Store {
            stored_at: now,
            fresh_until,
        }
    }

    #[must_use]
    pub fn key(&self, parts: ResponseCacheKeyParts<'_>) -> Option<Vec<u8>> {
        canonical_response_cache_key(ResponseCacheKeyInput {
            scheme: parts.scheme,
            authority: parts.authority,
            path_and_query: parts.path_and_query,
            representation: parts.representation,
            accept_encoding: parts.accept_encoding,
            namespace: self.namespace(),
        })
        .map(impulse_policy::CanonicalResponseCacheKey::into_primary)
    }

    #[must_use]
    pub fn namespace(&self) -> u64 {
        self.namespace.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn max_object_bytes(&self) -> usize {
        self.input.max_object_bytes
    }
}

impl PartialEq for CompiledResponseCache {
    fn eq(&self, other: &Self) -> bool {
        self.input == other.input
    }
}

impl Eq for CompiledResponseCache {}
