use std::time::SystemTime;

use http::{HeaderMap, StatusCode};
use impulse_bridge::{
    ResponseBodyMode, ResponseBodyPolicy, ResponseNormalizationInput, ResponseProtocolConstraints,
    UpstreamResponseView, normalize_upstream_response,
};
use impulse_policy::{
    ResponseCacheResponseEligibilityInput, ResponseCompressionEvaluation, ResponseCompressionInput,
    ResponseCompressionPolicyInput, ensure_vary_accept_encoding,
    evaluate_cache_response_eligibility, evaluate_response_compression, response_cache_ttl,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseCacheDecision {
    Disabled,
    Reject,
    Store {
        stored_at: SystemTime,
        fresh_until: SystemTime,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct ResponseProcessingResult {
    pub(crate) headers: HeaderMap,
    pub(crate) body_forwarding_enabled: bool,
    pub(crate) emit_end_stream_on_headers: bool,
    pub(crate) compression: ResponseCompressionEvaluation,
    pub(crate) cache: ResponseCacheDecision,
}

pub(crate) struct ResponseProcessingInput<'a> {
    pub(crate) status: StatusCode,
    pub(crate) upstream_headers: &'a HeaderMap,
    pub(crate) body_mode: ResponseBodyMode,
    pub(crate) constraints: ResponseProtocolConstraints,
    pub(crate) request_method: &'a str,
    pub(crate) request_headers: &'a HeaderMap,
    pub(crate) compression: ResponseCompressionPolicyInput,
    pub(crate) cache_max_ttl_secs: Option<u64>,
    pub(crate) now: SystemTime,
}

/// Applies response-head policy in canonical normalization, cache, compression order.
pub(crate) fn process_response(input: ResponseProcessingInput<'_>) -> ResponseProcessingResult {
    let normalized = normalize_upstream_response(ResponseNormalizationInput {
        upstream: UpstreamResponseView {
            status: input.status,
            headers: input.upstream_headers,
        },
        body_mode: input.body_mode,
        constraints: input.constraints,
    });
    let mut headers = HeaderMap::new();
    for header in normalized.headers {
        headers.append(header.name, header.value);
    }

    let cache = input
        .cache_max_ttl_secs
        .map_or(ResponseCacheDecision::Disabled, |max_ttl| {
            if input.status != StatusCode::OK
                || evaluate_cache_response_eligibility(ResponseCacheResponseEligibilityInput {
                    headers: &headers,
                })
                .is_err()
            {
                return ResponseCacheDecision::Reject;
            }
            let Some(ttl) = response_cache_ttl(&headers, max_ttl, input.now) else {
                return ResponseCacheDecision::Reject;
            };
            let Some(fresh_until) = input.now.checked_add(ttl) else {
                return ResponseCacheDecision::Reject;
            };
            ResponseCacheDecision::Store {
                stored_at: input.now,
                fresh_until,
            }
        });

    let mut compression_headers = headers.clone();
    if !compression_headers.contains_key(http::header::CONTENT_LENGTH)
        && let Some(content_length) = input.upstream_headers.get(http::header::CONTENT_LENGTH)
    {
        compression_headers.insert(http::header::CONTENT_LENGTH, content_length.clone());
    }
    let compression = evaluate_response_compression(ResponseCompressionInput {
        policy: input.compression,
        request_method: input.request_method,
        request_headers: input.request_headers,
        response_status: input.status,
        response_headers: &compression_headers,
    });
    if compression.vary_accept_encoding {
        ensure_vary_accept_encoding(&mut headers);
    }

    ResponseProcessingResult {
        headers,
        body_forwarding_enabled: matches!(normalized.emission.body, ResponseBodyPolicy::Forward),
        emit_end_stream_on_headers: normalized.emission.emit_end_stream_on_headers,
        compression,
        cache,
    }
}
