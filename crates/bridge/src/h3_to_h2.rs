use std::convert::Infallible;

use bytes::Bytes;
use http::{Method, Request, Uri, Version};
use http_body_util::combinators::BoxBody;
use hyper::ext::Protocol;
use impulse_errors::BridgeError;

use crate::{
    http3::{
        RequestBuildInput, RequestHeaderSanitizationInput, RequestTransportHeaders,
        apply_request_policy_header_mutations, apply_request_transport_headers,
        copy_sanitized_request_headers,
    },
    request::{RequestBuildTarget, RequestPolicyHeaderInput, request_policy_header_mutations},
};

pub(crate) fn build_h2_request_for_target(
    target: RequestBuildTarget<'_>,
    input: RequestBuildInput<'_, BoxBody<Bytes, Infallible>>,
) -> Result<Request<BoxBody<Bytes, Infallible>>, BridgeError> {
    let RequestBuildTarget { endpoint, policies } = target;
    let RequestBuildInput {
        method,
        path,
        authority,
        headers,
        policy_header_mutations,
        websocket_extended_connect,
        body,
        body_mode,
        trace,
        forwarded,
    } = input;
    let headers = headers.as_ref();

    let content_length = body_mode.content_length();

    let method = Method::from_bytes(method.as_bytes()).map_err(|_| BridgeError::InvalidMethod)?;
    // Extended CONNECT is the H2 websocket path (RFC 8441).
    let upstream_method = if websocket_extended_connect {
        Method::CONNECT
    } else {
        method.clone()
    };
    let is_connect = upstream_method == Method::CONNECT;
    let policy_mutations = request_policy_header_mutations(RequestPolicyHeaderInput {
        target: RequestBuildTarget { endpoint, policies },
        authority,
        headers,
        policy_header_mutations,
        trace,
        forwarded,
        include_host_header: !websocket_extended_connect,
        preserve_upgrade: false,
    })?;
    let builder = Request::builder().method(upstream_method.clone());
    let mut builder = copy_sanitized_request_headers(
        builder,
        RequestHeaderSanitizationInput {
            headers,
            policy_header_mutations: &policy_mutations,
            preserve_upgrade: false,
        },
    );

    let uri = if websocket_extended_connect {
        let request_path = if path.is_empty() { "/" } else { path };
        let uri = endpoint.uri_for_path(request_path);
        Uri::try_from(uri).map_err(|_| BridgeError::InvalidUri)?
    } else if is_connect {
        let host_value = policy_mutations
            .iter()
            .find(|(name, _)| name == http::header::HOST)
            .and_then(|(_, value)| value.as_ref())
            .and_then(|value| value.to_str().ok())
            .ok_or(BridgeError::InvalidUri)?;
        Uri::try_from(host_value).map_err(|_| BridgeError::InvalidUri)?
    } else {
        let request_path = if path.is_empty() { "/" } else { path };
        let uri = endpoint.uri_for_path(request_path);
        Uri::try_from(uri).map_err(|_| BridgeError::InvalidUri)?
    };
    builder = builder.uri(uri);
    if websocket_extended_connect {
        builder = builder
            .version(Version::HTTP_2)
            .extension(Protocol::from_static("websocket"));
    }
    builder = apply_request_policy_header_mutations(builder, &policy_mutations);
    builder = apply_request_transport_headers(
        builder,
        RequestTransportHeaders {
            content_length,
            include_content_length: !websocket_extended_connect,
            add_te_trailers: false,
        },
    );

    builder.body(body).map_err(BridgeError::Build)
}
