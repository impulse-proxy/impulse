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
use impulse_contracts::RequestId;
use impulse_errors::BridgeError;

use crate::{
    ForwardingPolicyInput, HostPolicyInput, UpstreamTargetInput,
    forwarded::{ForwardedHeaderChains, ForwardedHeaderValues, build_forwarded_header_values},
    h3_to_h1, h3_to_h2,
    headers::{connection_header_tokens, should_strip_proxy_header, should_strip_request_header},
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
    pub headers: &'a [quiche::h3::Header],
    pub auth_header_mutations: &'a [RequestHeaderMutationRef<'a>],
    pub body: B,
    pub body_mode: RequestBodyMode,
    pub trace: RequestTraceContext<'a>,
    pub forwarded: RequestForwardedContext,
}

#[derive(Debug)]
pub(crate) struct RequestHeaderPolicyInput<'a> {
    pub(crate) target: RequestBuildTarget<'a>,
    pub(crate) authority: Option<&'a str>,
    pub(crate) headers: &'a [quiche::h3::Header],
    pub(crate) auth_header_mutations: &'a [RequestHeaderMutationRef<'a>],
    pub(crate) preserve_upgrade: bool,
    pub(crate) forwarded: RequestForwardedContext,
}

#[derive(Debug)]
pub(crate) struct ResolvedRequestHeaderPolicy<'a> {
    pub(crate) passthrough_headers: Vec<(HeaderName, HeaderValue)>,
    pub(crate) host_value: Cow<'a, str>,
    pub(crate) forwarded_values: ForwardedHeaderValues,
}

pub(crate) struct RequestHeaderAssembly<'a> {
    pub(crate) resolved_headers: ResolvedRequestHeaderPolicy<'a>,
    pub(crate) trace: RequestTraceContext<'a>,
    pub(crate) content_length: Option<usize>,
    pub(crate) include_content_length: bool,
    pub(crate) include_host_header: bool,
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

pub(crate) fn apply_request_header_policies(
    input: RequestHeaderPolicyInput<'_>,
) -> Result<ResolvedRequestHeaderPolicy<'_>, BridgeError> {
    use quiche::h3::NameValue;

    let RequestHeaderPolicyInput {
        target,
        authority,
        headers,
        auth_header_mutations,
        preserve_upgrade,
        forwarded,
    } = input;
    let RequestBuildTarget { endpoint, policies } = target;
    let connection_tokens = connection_header_tokens(headers);
    let mut passthrough_headers = Vec::new();
    let mut host_header_index = None;
    let mut forwarded_from_headers = smallvec::SmallVec::<[&[u8]; 4]>::new();
    let mut x_forwarded_for_from_headers = smallvec::SmallVec::<[&[u8]; 4]>::new();
    let mut x_forwarded_proto_from_headers = smallvec::SmallVec::<[&[u8]; 4]>::new();
    let mut x_forwarded_host_from_headers = smallvec::SmallVec::<[&[u8]; 4]>::new();

    for (index, header) in headers.iter().enumerate() {
        let name = header.name();
        if name.starts_with(b":") {
            continue;
        }
        if auth_header_mutations
            .iter()
            .any(|mutation| mutation.name.eq_ignore_ascii_case(name))
        {
            continue;
        }
        if name.eq_ignore_ascii_case(b"forwarded") {
            forwarded_from_headers.push(header.value());
            continue;
        }
        if name.eq_ignore_ascii_case(b"x-forwarded-for") {
            x_forwarded_for_from_headers.push(header.value());
            continue;
        }
        if name.eq_ignore_ascii_case(b"x-forwarded-proto") {
            x_forwarded_proto_from_headers.push(header.value());
            continue;
        }
        if name.eq_ignore_ascii_case(b"x-forwarded-host") {
            x_forwarded_host_from_headers.push(header.value());
            continue;
        }

        let header_name = HeaderName::from_bytes(name).map_err(|_| BridgeError::InvalidHeader)?;
        if should_strip_request_header(&header_name, &connection_tokens, preserve_upgrade) {
            continue;
        }

        let header_value =
            HeaderValue::from_bytes(header.value()).map_err(|_| BridgeError::InvalidHeader)?;
        if header_name == http::header::HOST {
            host_header_index = Some(index);
            continue;
        }
        passthrough_headers.push((header_name, header_value));
    }

    for mutation in auth_header_mutations {
        let Some(value) = mutation.value else {
            continue;
        };
        let header_name =
            HeaderName::from_bytes(mutation.name).map_err(|_| BridgeError::InvalidHeader)?;
        if should_strip_proxy_header(&header_name, preserve_upgrade) {
            continue;
        }
        if header_name == http::header::HOST {
            continue;
        }
        let header_value =
            HeaderValue::from_bytes(value).map_err(|_| BridgeError::InvalidHeader)?;
        passthrough_headers.push((header_name, header_value));
    }

    let host_from_headers =
        host_header_index.and_then(|index| std::str::from_utf8(headers[index].value()).ok());
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

    Ok(ResolvedRequestHeaderPolicy {
        passthrough_headers,
        host_value: Cow::Borrowed(host_value),
        forwarded_values,
    })
}

pub(crate) fn apply_request_header_assembly(
    mut builder: http::request::Builder,
    assembly: RequestHeaderAssembly<'_>,
) -> Result<http::request::Builder, BridgeError> {
    let RequestHeaderAssembly {
        resolved_headers,
        trace,
        content_length,
        include_content_length,
        include_host_header,
        add_te_trailers,
    } = assembly;

    for (header_name, header_value) in resolved_headers.passthrough_headers {
        builder = builder.header(header_name, header_value);
    }

    if include_host_header {
        builder = builder.header(http::header::HOST, resolved_headers.host_value.as_ref());
    }

    if include_content_length
        && let Some(len) = content_length
        && len > 0
    {
        builder = builder.header(http::header::CONTENT_LENGTH, len);
    }

    let has_request_id = builder
        .headers_ref()
        .is_some_and(|h| h.contains_key("x-request-id"));
    if !has_request_id {
        let mut request_id = itoa::Buffer::new();
        builder = builder.header(
            HeaderName::from_static("x-request-id"),
            HeaderValue::from_str(request_id.format(trace.request_id))
                .map_err(|_| BridgeError::InvalidHeader)?,
        );
    }

    let has_traceparent = builder
        .headers_ref()
        .is_some_and(|h| h.contains_key("traceparent"));
    if !has_traceparent && let Some(traceparent) = trace.traceparent {
        builder = builder.header(
            HeaderName::from_static("traceparent"),
            HeaderValue::from_str(traceparent).map_err(|_| BridgeError::InvalidHeader)?,
        );
    }

    if let Some(value) = resolved_headers.forwarded_values.forwarded {
        builder = builder.header(HeaderName::from_static("forwarded"), value);
    }
    if let Some(value) = resolved_headers.forwarded_values.x_forwarded_for {
        builder = builder.header(HeaderName::from_static("x-forwarded-for"), value);
    }
    if let Some(value) = resolved_headers.forwarded_values.x_forwarded_proto {
        builder = builder.header(HeaderName::from_static("x-forwarded-proto"), value);
    }
    if let Some(value) = resolved_headers.forwarded_values.x_forwarded_host {
        builder = builder.header(HeaderName::from_static("x-forwarded-host"), value);
    }

    if add_te_trailers {
        builder = builder.header(http::header::TE, "trailers");
    }

    Ok(builder)
}
