use std::convert::Infallible;

use bytes::Bytes;
use http::{Method, Request, Uri};
use http_body_util::combinators::BoxBody;
use impulse_errors::BridgeError;

use crate::{
    request::{
        RequestBuildInput, RequestBuildTarget, RequestHeaderSanitizationInput,
        RequestPolicyHeaderInput, RequestTransportHeaders, apply_request_policy_header_mutations,
        apply_request_transport_headers, copy_sanitized_request_headers,
        request_policy_header_mutations,
    },
    websocket::legacy_websocket_upgrade_requested_for_headers,
};

/// Build an HTTP/1.1 request forwarded to an `http://` upstream.
///
/// For plain requests: strips hop-by-hop headers and adds `TE: trailers`.
/// For explicitly prepared HTTP/1 WebSocket upgrades (`GET` +
/// `Upgrade: websocket`): preserves `Connection` and `Upgrade` so the H1
/// upstream can complete the handshake. HTTP/3 ingress validation must reject
/// this legacy request shape before invoking the bridge.
pub(crate) fn build_h1_request(
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
        websocket_extended_connect: _,
        body,
        body_mode,
        trace,
        forwarded,
    } = input;
    let headers = headers.as_ref();

    let content_length = body_mode.content_length();

    let method = Method::from_bytes(method.as_bytes()).map_err(|_| BridgeError::InvalidMethod)?;
    let preserve_upgrade = legacy_websocket_upgrade_requested_for_headers(method.as_str(), headers);

    let policy_mutations = request_policy_header_mutations(RequestPolicyHeaderInput {
        target: RequestBuildTarget { endpoint, policies },
        authority,
        headers,
        policy_header_mutations,
        trace,
        forwarded,
        include_host_header: true,
        preserve_upgrade,
    })?;
    let builder = Request::builder().method(method.clone());
    let mut builder = copy_sanitized_request_headers(
        builder,
        RequestHeaderSanitizationInput {
            headers,
            policy_header_mutations: &policy_mutations,
            preserve_upgrade,
        },
    );
    let request_path = if path.is_empty() { "/" } else { path };
    let uri =
        Uri::try_from(endpoint.uri_for_path(request_path)).map_err(|_| BridgeError::InvalidUri)?;
    builder = builder.uri(uri);
    builder = apply_request_policy_header_mutations(builder, &policy_mutations);
    builder = apply_request_transport_headers(
        builder,
        RequestTransportHeaders {
            content_length,
            include_content_length: true,
            add_te_trailers: !preserve_upgrade,
        },
    );
    if matches!(body_mode, crate::request::RequestBodyMode::Streaming) {
        builder = builder.header(http::header::TRANSFER_ENCODING, "chunked");
    }

    builder.body(body).map_err(BridgeError::Build)
}
