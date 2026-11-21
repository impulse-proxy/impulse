use super::*;

#[cfg(test)]
pub(in crate::quic_listener) fn should_strip_h3_response_header(
    name: &http::header::HeaderName,
    headers: &http::HeaderMap,
) -> bool {
    should_strip_response_header(
        name,
        headers,
        ResponseProtocolConstraints {
            protocol: ResponseNormalizationProtocol::Http3,
            preserve_upgrade: false,
        },
    )
}

pub(crate) fn collect_h3_trailers(trailers: &http::HeaderMap) -> Vec<(Vec<u8>, Vec<u8>)> {
    normalize_response_trailers(
        trailers,
        ResponseProtocolConstraints {
            protocol: ResponseNormalizationProtocol::Http3,
            preserve_upgrade: false,
        },
    )
    .into_iter()
    .map(|header| {
        (
            header.name.as_str().as_bytes().to_vec(),
            header.value.as_bytes().to_vec(),
        )
    })
    .collect()
}

#[cfg(test)]
pub(in crate::quic_listener) fn is_head_method(method: &str) -> bool {
    method.eq_ignore_ascii_case("HEAD")
}

#[cfg(test)]
pub(in crate::quic_listener) fn is_bodyless_request_mode(
    method: &str,
    content_length: Option<usize>,
) -> bool {
    content_length.unwrap_or(0) == 0
        && (method.eq_ignore_ascii_case("GET") || is_head_method(method))
}

#[cfg(test)]
pub(in crate::quic_listener) fn is_connect_tunnel_response(
    method: &str,
    status: StatusCode,
) -> bool {
    impulse_http3_ingress::classify_tunnel(method, false) == TunnelMode::Connect
        && status.is_success()
}

pub(in crate::quic_listener) fn can_poll_upstream_result(req: &RequestEnvelope) -> bool {
    req.can_poll_upstream_result()
}
