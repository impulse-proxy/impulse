//! HTTP/3 request translation into upstream HTTP/1.1 and HTTP/2 requests.

use std::{borrow::Cow, convert::Infallible};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use impulse_errors::BridgeError;

use crate::{
    h3_to_h1, h3_to_h2,
    headers::should_strip_request_header,
    request::{
        RequestBuildTarget, RequestForwardedContext, RequestHeaderMutationRef,
        RequestPolicyHeaderMutationOverlay, RequestTraceContext,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestBodyMode {
    Empty,
    KnownLength(usize),
    Streaming,
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
