use std::convert::Infallible;

use bytes::Bytes;
use http::{Method, Request, Uri};
use http_body_util::combinators::BoxBody;
use impulse_errors::BridgeError;

use crate::{
    request::{
        RequestBuildInput, RequestBuildTarget, RequestHeaderAssembly, RequestHeaderPolicyInput,
        apply_request_header_assembly, apply_request_header_policies,
    },
    websocket::legacy_websocket_upgrade_requested,
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
        auth_header_mutations,
        body,
        body_mode,
        trace,
        forwarded,
    } = input;

    let content_length = body_mode.content_length();

    let method = Method::from_bytes(method.as_bytes()).map_err(|_| BridgeError::InvalidMethod)?;
    let preserve_upgrade = legacy_websocket_upgrade_requested(method.as_str(), headers);

    let mut builder = Request::builder().method(method.clone());
    let resolved_headers = apply_request_header_policies(RequestHeaderPolicyInput {
        target: RequestBuildTarget { endpoint, policies },
        authority,
        headers,
        auth_header_mutations,
        preserve_upgrade,
        forwarded,
    })?;

    let request_path = if path.is_empty() { "/" } else { path };
    let uri =
        Uri::try_from(endpoint.uri_for_path(request_path)).map_err(|_| BridgeError::InvalidUri)?;
    builder = builder.uri(uri);
    builder = apply_request_header_assembly(
        builder,
        RequestHeaderAssembly {
            resolved_headers,
            trace,
            content_length,
            include_content_length: true,
            include_host_header: true,
            add_te_trailers: !preserve_upgrade,
        },
    )?;
    if matches!(body_mode, crate::request::RequestBodyMode::Streaming) {
        builder = builder.header(http::header::TRANSFER_ENCODING, "chunked");
    }

    builder.body(body).map_err(BridgeError::Build)
}
