use std::time::SystemTime;

use http::{HeaderMap, StatusCode};
use impulse_bridge::response::{
    ResponseBodyMode, ResponseBodyPolicy, ResponseNormalizationInput, ResponseProtocolConstraints,
    UpstreamResponseView, normalize_upstream_response,
};
use impulse_contracts::{
    PluginCacheView, PluginPhase, PluginRequestView, PluginResponseMetadataView, PluginResponseView,
};
use impulse_plugins::{
    CachePluginDecision, CachePluginFillDecision, CompiledCachePlugin, CompiledPluginPlan,
    CompiledResponseCompression, CompiledResponsePlugin, ResponseCompressionEvaluation,
    ResponsePluginDecision, execute_cache_plugins, execute_response_plugins,
};
use impulse_policy::{ResponseCacheBypassReason, ResponseCacheRepresentation};

pub(crate) type ResponseCacheDecision = CachePluginFillDecision;

#[derive(Clone, Debug)]
pub(crate) struct ResponseProcessingResult {
    pub(crate) headers: HeaderMap,
    pub(crate) body_forwarding_enabled: bool,
    pub(crate) emit_end_stream_on_headers: bool,
    pub(crate) compression: ResponseCompressionEvaluation,
    pub(crate) cache: ResponseCacheDecision,
}

pub(crate) struct ResponseProcessingInput<'a> {
    pub(crate) metrics: &'a crate::Metrics,
    pub(crate) plugin_plan: &'a CompiledPluginPlan,
    pub(crate) plugin_request: PluginRequestView<'a>,
    pub(crate) status: StatusCode,
    pub(crate) upstream_headers: &'a HeaderMap,
    pub(crate) body_mode: ResponseBodyMode,
    pub(crate) constraints: ResponseProtocolConstraints,
    pub(crate) request_method: &'a str,
    pub(crate) request_headers: &'a HeaderMap,
    pub(crate) cache_fill_enabled: bool,
    pub(crate) cache_representation: Option<&'a str>,
    pub(crate) now: SystemTime,
}

pub(crate) struct CacheLookupProcessingInput<'a> {
    pub(crate) metrics: &'a crate::Metrics,
    pub(crate) plugin_plan: &'a CompiledPluginPlan,
    pub(crate) plugin_request: PluginRequestView<'a>,
    pub(crate) headers: &'a HeaderMap,
    pub(crate) is_upgrade: bool,
    pub(crate) is_tunnel: bool,
}

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

    let declared_content_length = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok());
    let source_request = input.plugin_request;
    let source_request_headers = source_request.headers;
    let request_header = |name: &str| source_request_headers.and_then(|lookup| lookup(name));
    let request_headers = source_request_headers
        .map(|_| &request_header as &impulse_contracts::PluginHeaderLookup<'_>);
    let plugin_request = PluginRequestView {
        request_id: source_request.request_id,
        generation: source_request.generation,
        route_id: source_request.route_id,
        upstream_name: source_request.upstream_name,
        method: source_request.method,
        path: source_request.path,
        authority: source_request.authority,
        peer_address: source_request.peer_address,
        headers: request_headers,
        has_body: source_request.has_body,
        body_replayable: source_request.body_replayable,
        ingress_protocol: source_request.ingress_protocol,
    };
    let (cache, compression) = {
        let response_header = |name: &str| headers.get(name).map(http::HeaderValue::as_bytes);
        let plugin_response = PluginResponseMetadataView {
            status: input.status,
            headers: Some(&response_header),
            declared_content_length,
            body_allowed: matches!(normalized.emission.body, ResponseBodyPolicy::Forward),
        };

        let mut cache = ResponseCacheDecision::Disabled;
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
                    if matches!(cache, ResponseCacheDecision::Store { .. }) {
                        CachePluginDecision::Continue
                    } else {
                        CachePluginDecision::Bypass
                    }
                }
            },
        );

        let mut compression_headers = headers.clone();
        if !compression_headers.contains_key(http::header::CONTENT_LENGTH)
            && let Some(content_length) = input.upstream_headers.get(http::header::CONTENT_LENGTH)
        {
            compression_headers.insert(http::header::CONTENT_LENGTH, content_length.clone());
        }
        let mut compression = CompiledResponseCompression::disabled_evaluation();
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
                        input.request_headers,
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
        (cache, compression)
    };
    if let Some(policy) = input.plugin_plan.response_compression() {
        policy.apply_negotiation_headers(&mut headers, compression);
    }

    ResponseProcessingResult {
        headers,
        body_forwarding_enabled: matches!(normalized.emission.body, ResponseBodyPolicy::Forward),
        emit_end_stream_on_headers: normalized.emission.emit_end_stream_on_headers,
        compression,
        cache,
    }
}
