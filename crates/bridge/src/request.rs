//! Canonical upstream request-building surface.
//!
//! This module owns request-shaping inputs, host/forwarded-header policy
//! application, and the stable entrypoints callers should use. Protocol-specific
//! H1/H2 encoding details are delegated to internal builder modules.

use std::{borrow::Cow, convert::Infallible, net::SocketAddr};

use bytes::Bytes;
use http::{HeaderName, HeaderValue};
use http_body_util::combinators::BoxBody;
pub use impulse_contracts::HeaderMutationRef as RequestHeaderMutationRef;
use impulse_contracts::{RequestId, SpanId, TraceId};
use impulse_errors::BridgeError;

use crate::{
    ForwardingPolicyInput, HostPolicyInput, UpstreamTargetInput,
    forwarded::{ForwardedHeaderChains, ForwardedHeaderValues, build_forwarded_header_values},
    h3_to_h1, h3_to_h2,
    headers::{should_strip_proxy_header, should_strip_request_header},
    host::resolve_upstream_host_value,
};

pub fn build_h1_request(
    target: RequestBuildTarget<'_>,
    input: RequestBuildInput<'_, BoxBody<Bytes, Infallible>>,
) -> Result<http::Request<BoxBody<Bytes, Infallible>>, BridgeError> {
    h3_to_h1::build_h1_request(target, input)
}

pub fn build_h2_request_for_target(
    target: RequestBuildTarget<'_>,
    input: RequestBuildInput<'_, BoxBody<Bytes, Infallible>>,
) -> Result<http::Request<BoxBody<Bytes, Infallible>>, BridgeError> {
    h3_to_h2::build_h2_request_for_target(target, input)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestBodyMode {
    Empty,
    KnownLength(usize),
    Streaming,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestTraceContext<'a> {
    pub request_id: RequestId,
    pub traceparent: Option<&'a str>,
    pub trace_id: Option<TraceId>,
    pub span_id: Option<SpanId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestForwardedContext {
    pub client_addr: SocketAddr,
}

#[derive(Clone, Copy, Debug)]
pub struct RequestBuildPolicies<'a> {
    pub host_policy: HostPolicyInput<'a>,
    pub forwarded_header_policy: ForwardingPolicyInput,
}

#[derive(Debug)]
pub struct RequestBuildTarget<'a> {
    pub endpoint: UpstreamTargetInput<'a>,
    pub policies: RequestBuildPolicies<'a>,
}

pub struct RequestBuildInput<'a, B = BoxBody<Bytes, Infallible>> {
    pub method: &'a str,
    pub path: &'a str,
    pub authority: Option<&'a str>,
    pub headers: Cow<'a, http::HeaderMap>,
    pub policy_header_mutations: &'a [RequestHeaderMutationRef<'a>],
    pub websocket_extended_connect: bool,
    pub body: B,
    pub body_mode: RequestBodyMode,
    pub trace: RequestTraceContext<'a>,
    pub forwarded: RequestForwardedContext,
}

#[derive(Debug)]
pub struct RequestPolicyHeaderInput<'a> {
    pub target: RequestBuildTarget<'a>,
    pub authority: Option<&'a str>,
    pub headers: &'a http::HeaderMap,
    pub policy_header_mutations: &'a [RequestHeaderMutationRef<'a>],
    pub trace: RequestTraceContext<'a>,
    pub forwarded: RequestForwardedContext,
    pub include_host_header: bool,
    pub preserve_upgrade: bool,
}

pub type RequestPolicyHeaderMutationOverlay =
    smallvec::SmallVec<[(HeaderName, Option<HeaderValue>); 11]>;

pub(crate) struct RequestHeaderSanitizationInput<'a> {
    pub(crate) headers: &'a http::HeaderMap,
    pub(crate) policy_header_mutations: &'a RequestPolicyHeaderMutationOverlay,
    pub(crate) preserve_upgrade: bool,
}

pub(crate) struct RequestTransportHeaders {
    pub(crate) content_length: Option<usize>,
    pub(crate) include_content_length: bool,
    pub(crate) add_te_trailers: bool,
}

impl<'a, B> RequestBuildInput<'a, B> {
    pub fn body_mode_for_length(content_length: Option<usize>) -> RequestBodyMode {
        match content_length {
            Some(0) => RequestBodyMode::Empty,
            Some(length) => RequestBodyMode::KnownLength(length),
            None => RequestBodyMode::Streaming,
        }
    }
}

impl RequestBodyMode {
    pub(crate) fn content_length(self) -> Option<usize> {
        match self {
            Self::KnownLength(length) => Some(length),
            Self::Empty | Self::Streaming => None,
        }
    }
}

pub(crate) fn copy_sanitized_request_headers(
    mut builder: http::request::Builder,
    input: RequestHeaderSanitizationInput<'_>,
) -> http::request::Builder {
    let RequestHeaderSanitizationInput {
        headers,
        policy_header_mutations,
        preserve_upgrade,
    } = input;

    for (header_name, header_value) in headers {
        if policy_header_mutations
            .iter()
            .any(|(name, _)| name == header_name)
        {
            continue;
        }
        if should_strip_request_header(header_name, headers, preserve_upgrade) {
            continue;
        }
        builder = builder.header(header_name.clone(), header_value.clone());
    }

    builder
}

pub fn request_policy_header_mutations(
    input: RequestPolicyHeaderInput<'_>,
) -> Result<RequestPolicyHeaderMutationOverlay, BridgeError> {
    let RequestPolicyHeaderInput {
        target,
        authority,
        headers,
        policy_header_mutations,
        trace,
        forwarded,
        include_host_header,
        preserve_upgrade,
    } = input;
    let RequestBuildTarget { endpoint, policies } = target;
    let mut host_from_headers = None;
    let mut forwarded_from_headers = smallvec::SmallVec::<[&[u8]; 4]>::new();
    let mut x_forwarded_for_from_headers = smallvec::SmallVec::<[&[u8]; 4]>::new();
    let mut x_forwarded_proto_from_headers = smallvec::SmallVec::<[&[u8]; 4]>::new();
    let mut x_forwarded_host_from_headers = smallvec::SmallVec::<[&[u8]; 4]>::new();

    for (header_name, header_value) in headers {
        let name = header_name.as_str().as_bytes();
        if policy_header_mutations
            .iter()
            .any(|mutation| mutation.name.eq_ignore_ascii_case(name))
        {
            continue;
        }
        let value = header_value.as_bytes();
        if name.eq_ignore_ascii_case(b"forwarded") {
            forwarded_from_headers.push(value);
        } else if name.eq_ignore_ascii_case(b"x-forwarded-for") {
            x_forwarded_for_from_headers.push(value);
        } else if name.eq_ignore_ascii_case(b"x-forwarded-proto") {
            x_forwarded_proto_from_headers.push(value);
        } else if name.eq_ignore_ascii_case(b"x-forwarded-host") {
            x_forwarded_host_from_headers.push(value);
        } else if name.eq_ignore_ascii_case(b"host") {
            host_from_headers = std::str::from_utf8(value).ok();
        }
    }

    let host_value =
        resolve_upstream_host_value(endpoint, policies.host_policy, authority, host_from_headers)?;
    let forwarded_values = build_forwarded_header_values(
        policies.forwarded_header_policy,
        ForwardedHeaderChains {
            forwarded: &forwarded_from_headers,
            x_forwarded_for: &x_forwarded_for_from_headers,
            x_forwarded_proto: &x_forwarded_proto_from_headers,
            x_forwarded_host: &x_forwarded_host_from_headers,
        },
        forwarded.client_addr.ip(),
        host_value,
    )?;

    let mut overlay = RequestPolicyHeaderMutationOverlay::new();

    for mutation in policy_header_mutations {
        let header_name =
            HeaderName::from_bytes(mutation.name).map_err(|_| BridgeError::InvalidHeader)?;
        if should_strip_proxy_header(&header_name, preserve_upgrade)
            || header_name == http::header::HOST
        {
            continue;
        }
        let header_value = mutation
            .value
            .map(HeaderValue::from_bytes)
            .transpose()
            .map_err(|_| BridgeError::InvalidHeader)?;
        overlay.push((header_name, header_value));
    }

    overlay.push((
        http::header::HOST,
        include_host_header
            .then_some(HeaderValue::from_str(host_value))
            .transpose()
            .map_err(|_| BridgeError::InvalidHeader)?,
    ));

    let effective_header_present = |name: &str| {
        policy_header_mutations
            .iter()
            .rev()
            .find(|mutation| mutation.name.eq_ignore_ascii_case(name.as_bytes()))
            .map_or_else(
                || headers.contains_key(name),
                |mutation| mutation.value.is_some(),
            )
    };
    if !effective_header_present("x-request-id") {
        let mut request_id = itoa::Buffer::new();
        overlay.push((
            HeaderName::from_static("x-request-id"),
            Some(
                HeaderValue::from_str(request_id.format(trace.request_id))
                    .map_err(|_| BridgeError::InvalidHeader)?,
            ),
        ));
    }

    if !effective_header_present("traceparent") {
        let traceparent = if let Some(traceparent) = trace.traceparent {
            Some(HeaderValue::from_str(traceparent).map_err(|_| BridgeError::InvalidHeader)?)
        } else if let Some((trace_id, span_id)) = trace.trace_id.zip(trace.span_id) {
            let mut encoded = [0; 55];
            encoded[..3].copy_from_slice(b"00-");
            encoded[3..35].copy_from_slice(trace_id.as_str().as_bytes());
            encoded[35] = b'-';
            encoded[36..52].copy_from_slice(span_id.as_str().as_bytes());
            encoded[52..].copy_from_slice(b"-01");
            Some(HeaderValue::from_bytes(&encoded).map_err(|_| BridgeError::InvalidHeader)?)
        } else {
            None
        };
        if let Some(traceparent) = traceparent {
            overlay.push((HeaderName::from_static("traceparent"), Some(traceparent)));
        }
    }

    overlay.push((
        HeaderName::from_static("forwarded"),
        forwarded_values.forwarded,
    ));
    overlay.push((
        HeaderName::from_static("x-forwarded-for"),
        forwarded_values.x_forwarded_for,
    ));
    overlay.push((
        HeaderName::from_static("x-forwarded-proto"),
        forwarded_values.x_forwarded_proto,
    ));
    overlay.push((
        HeaderName::from_static("x-forwarded-host"),
        forwarded_values.x_forwarded_host,
    ));

    Ok(overlay)
}

pub(crate) fn apply_request_policy_header_mutations(
    mut builder: http::request::Builder,
    mutations: &RequestPolicyHeaderMutationOverlay,
) -> http::request::Builder {
    for (name, value) in mutations {
        if let Some(value) = value {
            builder = builder.header(name, value);
        }
    }

    builder
}

pub(crate) fn apply_request_transport_headers(
    mut builder: http::request::Builder,
    headers: RequestTransportHeaders,
) -> http::request::Builder {
    let RequestTransportHeaders {
        content_length,
        include_content_length,
        add_te_trailers,
    } = headers;

    if include_content_length
        && let Some(len) = content_length
        && len > 0
    {
        builder = builder.header(http::header::CONTENT_LENGTH, len);
    }
    if add_te_trailers {
        builder = builder.header(http::header::TE, "trailers");
    }

    builder
}
