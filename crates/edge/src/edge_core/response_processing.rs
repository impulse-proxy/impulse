#[cfg(feature = "response-cache")]
use std::time::SystemTime;

use http::{HeaderMap, StatusCode};
use impulse_bridge::response::{
    ResponseBodyMode, ResponseBodyPolicy, ResponseNormalizationInput, ResponseProtocolConstraints,
    UpstreamResponseView, normalize_upstream_response,
};
#[cfg(any(feature = "response-cache", feature = "response-compression"))]
use impulse_contracts::PluginRequestView;
#[cfg(any(feature = "response-cache", feature = "response-compression"))]
use impulse_contracts::PluginResponseMetadataView;
#[cfg(feature = "response-compression")]
use impulse_contracts::PluginResponseView;
#[cfg(feature = "response-cache")]
use impulse_contracts::{PluginCacheView, PluginPhase};
#[cfg(feature = "response-cache")]
use impulse_plugins::CachePluginFillDecision;
#[cfg(any(feature = "response-cache", feature = "response-compression"))]
use impulse_plugins::CompiledPluginPlan;
#[cfg(feature = "response-cache")]
use impulse_plugins::{CachePluginDecision, CompiledCachePlugin, execute_cache_plugins};
#[cfg(feature = "response-compression")]
use impulse_plugins::{CompiledResponsePlugin, ResponsePluginDecision, execute_response_plugins};
#[cfg(feature = "response-cache")]
use impulse_policy::{ResponseCacheBypassReason, ResponseCacheRepresentation};
#[cfg(feature = "response-compression")]
use impulse_policy::{
    ResponseCompressionAction, ResponseCompressionBypassReason, ResponseCompressionEvaluation,
};

#[derive(Clone, Debug)]
pub(crate) struct ResponseProcessingResult {
    pub(crate) headers: HeaderMap,
    pub(crate) body_forwarding_enabled: bool,
    pub(crate) emit_end_stream_on_headers: bool,
    #[cfg(feature = "response-compression")]
    pub(crate) compression: ResponseCompressionEvaluation,
    #[cfg(feature = "response-cache")]
    pub(crate) cache: CachePluginFillDecision,
}

pub(crate) struct ResponseProcessingInput<'a> {
    #[cfg(any(feature = "response-cache", feature = "response-compression"))]
    pub(crate) metrics: &'a crate::Metrics,
    #[cfg(any(feature = "response-cache", feature = "response-compression"))]
    pub(crate) plugin_plan: &'a CompiledPluginPlan,
    #[cfg(any(feature = "response-cache", feature = "response-compression"))]
    pub(crate) plugin_request: Option<PluginRequestView<'a>>,
    pub(crate) status: StatusCode,
    pub(crate) upstream_headers: &'a HeaderMap,
    pub(crate) body_mode: ResponseBodyMode,
    pub(crate) constraints: ResponseProtocolConstraints,
    #[cfg(feature = "response-compression")]
    pub(crate) request_method: &'a str,
    #[cfg(feature = "response-compression")]
    pub(crate) request_headers: Option<&'a HeaderMap>,
    #[cfg(feature = "response-cache")]
    pub(crate) cache_fill_enabled: bool,
    #[cfg(feature = "response-cache")]
    pub(crate) cache_representation: Option<&'a str>,
    #[cfg(feature = "response-cache")]
    pub(crate) now: SystemTime,
}

#[cfg(feature = "response-cache")]
pub(crate) struct CacheLookupProcessingInput<'a> {
    pub(crate) metrics: &'a crate::Metrics,
    pub(crate) plugin_plan: &'a CompiledPluginPlan,
    pub(crate) plugin_request: PluginRequestView<'a>,
    pub(crate) headers: &'a HeaderMap,
    pub(crate) is_upgrade: bool,
    pub(crate) is_tunnel: bool,
}

#[cfg(feature = "response-cache")]
pub(crate) fn process_cache_lookup(
    input: CacheLookupProcessingInput<'_>,
) -> Result<ResponseCacheRepresentation, ResponseCacheBypassReason> {
    let mut decision = Err(ResponseCacheBypassReason::Disabled);
    let _ = execute_cache_plugins(
        input.plugin_plan,
        PluginPhase::CacheLookup,
        PluginCacheView {
            request: input.plugin_request,
            response: None,
            representation: None,
        },
        |observation| {
            input
                .metrics
                .plugin_observations()
                .record_execution(observation);
        },
        |plugin, _| match plugin {
            CompiledCachePlugin::ResponseCache(cache) => {
                decision = cache.request_eligibility(
                    input.plugin_request,
                    input.headers,
                    input.is_upgrade,
                    input.is_tunnel,
                );
                if decision.is_ok() {
                    CachePluginDecision::Continue
                } else {
                    CachePluginDecision::Bypass
                }
            }
        },
    );
    decision
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

    #[cfg(feature = "response-cache")]
    let mut cache = CachePluginFillDecision::Disabled;
    #[cfg(feature = "response-compression")]
    let mut compression = ResponseCompressionEvaluation {
        action: ResponseCompressionAction::Bypass(ResponseCompressionBypassReason::Disabled),
        vary_accept_encoding: false,
    };
    #[cfg(any(feature = "response-cache", feature = "response-compression"))]
    if input.plugin_plan.cache_policy().is_empty() && input.plugin_plan.response_policy().is_empty()
    {
        return ResponseProcessingResult {
            headers,
            body_forwarding_enabled: matches!(
                normalized.emission.body,
                ResponseBodyPolicy::Forward
            ),
            emit_end_stream_on_headers: normalized.emission.emit_end_stream_on_headers,
            #[cfg(feature = "response-compression")]
            compression,
            #[cfg(feature = "response-cache")]
            cache,
        };
    }

    #[cfg(any(feature = "response-cache", feature = "response-compression"))]
    let Some(plugin_request) = input.plugin_request else {
        return ResponseProcessingResult {
            headers,
            body_forwarding_enabled: matches!(
                normalized.emission.body,
                ResponseBodyPolicy::Forward
            ),
            emit_end_stream_on_headers: normalized.emission.emit_end_stream_on_headers,
            #[cfg(feature = "response-compression")]
            compression,
            #[cfg(feature = "response-cache")]
            cache,
        };
    };

    #[cfg(any(feature = "response-cache", feature = "response-compression"))]
    let declared_content_length = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok());
    #[cfg(any(feature = "response-cache", feature = "response-compression"))]
    {
        let response_header = |name: &str| headers.get(name).map(http::HeaderValue::as_bytes);
        let plugin_response = PluginResponseMetadataView {
            status: input.status,
            headers: Some(&response_header),
            declared_content_length,
            body_allowed: matches!(normalized.emission.body, ResponseBodyPolicy::Forward),
        };

        #[cfg(feature = "response-cache")]
        if !input.plugin_plan.cache_policy().is_empty() {
            let _ = execute_cache_plugins(
                input.plugin_plan,
                PluginPhase::CacheFill,
                PluginCacheView {
                    request: plugin_request,
                    response: Some(plugin_response),
                    representation: input.cache_representation,
                },
                |observation| {
                    input
                        .metrics
                        .plugin_observations()
                        .record_execution(observation);
                },
                |plugin, _| match plugin {
                    CompiledCachePlugin::ResponseCache(policy) => {
                        cache = policy.fill_decision(
                            input.status,
                            &headers,
                            input.cache_fill_enabled,
                            input.now,
                        );
                        if matches!(cache, CachePluginFillDecision::Store { .. }) {
                            CachePluginDecision::Continue
                        } else {
                            CachePluginDecision::Bypass
                        }
                    }
                },
            );
        }

        #[cfg(feature = "response-compression")]
        if !input.plugin_plan.response_policy().is_empty()
            && let Some(request_headers) = input.request_headers
        {
            let mut compression_headers = headers.clone();
            if !compression_headers.contains_key(http::header::CONTENT_LENGTH)
                && let Some(content_length) =
                    input.upstream_headers.get(http::header::CONTENT_LENGTH)
            {
                compression_headers.insert(http::header::CONTENT_LENGTH, content_length.clone());
            }
            let _ = execute_response_plugins(
                input.plugin_plan,
                PluginResponseView {
                    request: plugin_request,
                    response: plugin_response,
                },
                |observation| {
                    input
                        .metrics
                        .plugin_observations()
                        .record_execution(observation);
                },
                |plugin, _| match plugin {
                    CompiledResponsePlugin::ResponseCompression(policy) => {
                        compression = policy.evaluate(
                            input.request_method,
                            request_headers,
                            input.status,
                            &compression_headers,
                        );
                        if matches!(
                            compression.action,
                            impulse_observability::ResponseCompressionAction::Gzip
                        ) {
                            ResponsePluginDecision::Continue
                        } else {
                            ResponsePluginDecision::Bypass
                        }
                    }
                },
            );
        }
    }
    #[cfg(feature = "response-compression")]
    if let Some(policy) = input.plugin_plan.response_compression() {
        policy.apply_negotiation_headers(&mut headers, compression);
    }

    ResponseProcessingResult {
        headers,
        body_forwarding_enabled: matches!(normalized.emission.body, ResponseBodyPolicy::Forward),
        emit_end_stream_on_headers: normalized.emission.emit_end_stream_on_headers,
        #[cfg(feature = "response-compression")]
        compression,
        #[cfg(feature = "response-cache")]
        cache,
    }
}
