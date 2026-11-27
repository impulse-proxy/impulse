//! Shared request-building fixtures for the bridge regression suite.

use std::{borrow::Cow, convert::Infallible, net::SocketAddr};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, combinators::BoxBody};
use impulse_bridge::{
    ForwardedHeaderMode, ForwardingPolicyInput, HostPolicyInput, HostPolicyMode, UpstreamScheme,
    UpstreamTargetInput,
    http3::{RequestBodyMode, RequestBuildInput, build_h1_request, build_h2_request_for_target},
    request::{
        RequestBuildPolicies, RequestBuildTarget, RequestForwardedContext, RequestTraceContext,
    },
};
use impulse_config::{
    backend_endpoint::{BackendEndpoint, BackendScheme},
    config::{
        ForwardedHeaderPolicy, ForwardedHeaderPolicyMode, UpstreamHostPolicy,
        UpstreamHostPolicyMode,
    },
};
use impulse_errors::BridgeError;
use quiche::h3::{Header, NameValue};

pub(crate) type CanonicalBridgeRequest = http::Request<BoxBody<Bytes, Infallible>>;
pub(crate) type CanonicalBridgeRequestPair = (CanonicalBridgeRequest, CanonicalBridgeRequest);

#[derive(Clone, Copy)]
pub(crate) struct RequestInputMeta<'a> {
    pub(crate) authority: Option<&'a str>,
    pub(crate) content_length: Option<usize>,
    pub(crate) request_id: u64,
    pub(crate) traceparent: Option<&'a str>,
    pub(crate) client_addr: SocketAddr,
}

pub(crate) fn request_target<'a>(
    endpoint: &'a BackendEndpoint,
    host_policy: &'a UpstreamHostPolicy,
    forwarded_header_policy: &'a ForwardedHeaderPolicy,
) -> RequestBuildTarget<'a> {
    RequestBuildTarget {
        endpoint: UpstreamTargetInput {
            scheme: match endpoint.scheme() {
                BackendScheme::Http => UpstreamScheme::Http,
                BackendScheme::Https => UpstreamScheme::Https,
            },
            authority: endpoint.authority(),
        },
        policies: RequestBuildPolicies {
            host_policy: HostPolicyInput {
                mode: match host_policy.mode {
                    UpstreamHostPolicyMode::PassThrough => HostPolicyMode::PassThrough,
                    UpstreamHostPolicyMode::Rewrite => HostPolicyMode::Rewrite,
                    UpstreamHostPolicyMode::Upstream => HostPolicyMode::Upstream,
                },
                rewrite_host: host_policy.host.as_deref(),
            },
            forwarded_header_policy: ForwardingPolicyInput {
                mode: match forwarded_header_policy.mode {
                    ForwardedHeaderPolicyMode::Preserve => ForwardedHeaderMode::Preserve,
                    ForwardedHeaderPolicyMode::Append => ForwardedHeaderMode::Append,
                    ForwardedHeaderPolicyMode::Overwrite => ForwardedHeaderMode::Overwrite,
                },
            },
        },
    }
}

pub(crate) fn parse_backend_endpoint(backend: &str) -> Result<BackendEndpoint, BridgeError> {
    BackendEndpoint::parse(backend).map_err(|_| BridgeError::InvalidUri)
}

pub(crate) fn request_input<'a>(
    method: &'a str,
    path: &'a str,
    headers: &'a [Header],
    meta: RequestInputMeta<'a>,
) -> RequestBuildInput<'a, BoxBody<Bytes, Infallible>> {
    let websocket_extended_connect =
        impulse_bridge::websocket::h3_websocket_tunnel_requested(method, headers);
    let mut translated_headers = http::HeaderMap::with_capacity(headers.len());
    for header in headers {
        if header.name().starts_with(b":") {
            continue;
        }
        let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(header.name()),
            http::HeaderValue::from_bytes(header.value()),
        ) else {
            continue;
        };
        translated_headers.append(name, value);
    }
    request_input_from_headers(
        method,
        path,
        Cow::Owned(translated_headers),
        meta,
        websocket_extended_connect,
    )
}

pub(crate) fn borrowed_request_input<'a>(
    method: &'a str,
    path: &'a str,
    headers: &'a http::HeaderMap,
    meta: RequestInputMeta<'a>,
) -> RequestBuildInput<'a, BoxBody<Bytes, Infallible>> {
    request_input_from_headers(method, path, Cow::Borrowed(headers), meta, false)
}

fn request_input_from_headers<'a>(
    method: &'a str,
    path: &'a str,
    headers: Cow<'a, http::HeaderMap>,
    meta: RequestInputMeta<'a>,
    websocket_extended_connect: bool,
) -> RequestBuildInput<'a, BoxBody<Bytes, Infallible>> {
    RequestBuildInput {
        method,
        path,
        authority: meta.authority,
        headers,
        policy_header_mutations: &[],
        websocket_extended_connect,
        body: Empty::<Bytes>::new().boxed(),
        body_mode: RequestBuildInput::<BoxBody<Bytes, Infallible>>::body_mode_for_length(
            meta.content_length,
        ),
        trace: RequestTraceContext {
            request_id: meta.request_id,
            traceparent: meta.traceparent,
            trace_id: None,
            span_id: None,
        },
        forwarded: RequestForwardedContext {
            client_addr: meta.client_addr,
        },
    }
}

pub(crate) fn request_input_with_body_mode<'a>(
    method: &'a str,
    path: &'a str,
    headers: &'a [Header],
    meta: RequestInputMeta<'a>,
    body_mode: RequestBodyMode,
) -> RequestBuildInput<'a, BoxBody<Bytes, Infallible>> {
    let mut input = request_input(method, path, headers, meta);
    input.body_mode = body_mode;
    input
}

pub(crate) fn build_h1_and_h2_requests<'a>(
    endpoint: &'a BackendEndpoint,
    host_policy: &'a UpstreamHostPolicy,
    forwarded_header_policy: &'a ForwardedHeaderPolicy,
    method: &'a str,
    path: &'a str,
    headers: &'a [Header],
    meta: RequestInputMeta<'a>,
) -> Result<CanonicalBridgeRequestPair, BridgeError> {
    let h1 = build_h1_request(
        request_target(endpoint, host_policy, forwarded_header_policy),
        request_input(method, path, headers, meta),
    )?;
    let h2 = build_h2_request_for_target(
        request_target(endpoint, host_policy, forwarded_header_policy),
        request_input(method, path, headers, meta),
    )?;
    Ok((h1, h2))
}

pub(crate) fn build_h1_request_for_backend<'a>(
    backend: &str,
    method: &'a str,
    path: &'a str,
    headers: &'a [Header],
    meta: RequestInputMeta<'a>,
) -> Result<CanonicalBridgeRequest, BridgeError> {
    let endpoint = parse_backend_endpoint(backend)?;
    build_h1_request(
        request_target(
            &endpoint,
            &UpstreamHostPolicy::default(),
            &ForwardedHeaderPolicy::default(),
        ),
        request_input(method, path, headers, meta),
    )
}

pub(crate) fn build_h2_request_for_backend<'a>(
    backend: &str,
    method: &'a str,
    path: &'a str,
    headers: &'a [Header],
    meta: RequestInputMeta<'a>,
) -> Result<CanonicalBridgeRequest, BridgeError> {
    let endpoint = parse_backend_endpoint(backend)?;
    build_h2_request_for_target(
        request_target(
            &endpoint,
            &UpstreamHostPolicy::default(),
            &ForwardedHeaderPolicy::default(),
        ),
        request_input(method, path, headers, meta),
    )
}

pub(crate) fn build_h2_request_with_policy<'a>(
    endpoint: &'a BackendEndpoint,
    host_policy: &'a UpstreamHostPolicy,
    forwarded_policy: &'a ForwardedHeaderPolicy,
    method: &'a str,
    path: &'a str,
    headers: &'a [Header],
    meta: RequestInputMeta<'a>,
) -> Result<CanonicalBridgeRequest, BridgeError> {
    build_h2_request_for_target(
        request_target(endpoint, host_policy, forwarded_policy),
        request_input(method, path, headers, meta),
    )
}
