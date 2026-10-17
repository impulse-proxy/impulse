use super::*;

#[cfg(test)]
pub(in crate::quic_listener) fn connection_header_tokens(
    headers: &http::HeaderMap,
) -> HashSet<String> {
    let mut tokens = HashSet::new();
    for value in headers.get_all(http::header::CONNECTION) {
        let Ok(raw) = value.to_str() else {
            continue;
        };
        for part in raw.split(',') {
            let token = part.trim().to_ascii_lowercase();
            if token.is_empty() {
                continue;
            }
            tokens.insert(token);
        }
    }
    tokens
}

#[cfg(test)]
pub(in crate::quic_listener) fn should_strip_h3_response_header(
    name: &http::header::HeaderName,
    connection_tokens: &HashSet<String>,
) -> bool {
    should_strip_response_header(
        name,
        connection_tokens,
        ResponseProtocolConstraints {
            protocol: ResponseNormalizationProtocol::Http3,
            strip_connection_headers: true,
            allow_trailers: true,
            preserve_upgrade: false,
        },
    )
}

pub(in crate::quic_listener) fn collect_h3_trailers(
    trailers: &http::HeaderMap,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    normalize_response_trailers(
        trailers,
        ResponseProtocolConstraints {
            protocol: ResponseNormalizationProtocol::Http3,
            strip_connection_headers: true,
            allow_trailers: true,
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

pub(in crate::quic_listener) fn is_connect_method(method: &str) -> bool {
    method.eq_ignore_ascii_case("CONNECT")
}

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

pub(in crate::quic_listener) fn is_tunnel_mode(tunnel_mode: TunnelMode) -> bool {
    tunnel_mode != TunnelMode::None
}

pub(in crate::quic_listener) fn is_tunnel_response(
    tunnel_mode: TunnelMode,
    status: StatusCode,
) -> bool {
    is_tunnel_mode(tunnel_mode) && status.is_success()
}

#[cfg(test)]
pub(in crate::quic_listener) fn is_connect_tunnel_response(
    method: &str,
    status: StatusCode,
) -> bool {
    is_connect_method(method) && status.is_success()
}

pub(in crate::quic_listener) fn can_poll_upstream_result(req: &RequestEnvelope) -> bool {
    req.can_poll_upstream_result()
}

fn header_has_token(value: &http::HeaderValue, token: &str) -> bool {
    value
        .to_str()
        .ok()
        .map(|raw| {
            raw.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
        })
        .unwrap_or(false)
}

pub(in crate::quic_listener) fn is_websocket_upgrade_request(
    req: &Request<Incoming>,
    use_h2: bool,
) -> bool {
    if use_h2 || req.method() != http::Method::GET {
        return false;
    }
    let Some(upgrade_header) = req.headers().get(http::header::UPGRADE) else {
        return false;
    };
    if !upgrade_header
        .to_str()
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
    {
        return false;
    }
    req.headers()
        .get(http::header::CONNECTION)
        .map(|v| header_has_token(v, "upgrade"))
        .unwrap_or(false)
}
