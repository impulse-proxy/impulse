use std::borrow::Cow;

use impulse_contracts::TunnelMode;
use quiche::h3::{Header, NameValue};

pub fn classify_tunnel(method: &str, websocket_tunnel: bool) -> TunnelMode {
    if websocket_tunnel {
        TunnelMode::Websocket
    } else if method.eq_ignore_ascii_case("CONNECT") {
        TunnelMode::Connect
    } else {
        TunnelMode::None
    }
}

pub fn requires_h1_websocket_adaptation(mode: TunnelMode, plain_http_upstream: bool) -> bool {
    mode == TunnelMode::Websocket && plain_http_upstream
}

pub fn adapt_h1_websocket_method(mode: TunnelMode, method: &str) -> &str {
    if mode == TunnelMode::Websocket {
        "GET"
    } else {
        method
    }
}

pub fn adapt_h1_websocket_headers(headers: Cow<'_, [Header]>) -> Cow<'_, [Header]> {
    let has_upgrade = headers
        .iter()
        .any(|header| header.name().eq_ignore_ascii_case(b"upgrade"));
    let has_connection = headers
        .iter()
        .any(|header| header.name().eq_ignore_ascii_case(b"connection"));
    if has_upgrade && has_connection {
        return headers;
    }

    let mut headers = headers.into_owned();
    if !has_upgrade {
        headers.push(Header::new(b"upgrade", b"websocket"));
    }
    if !has_connection {
        headers.push(Header::new(b"connection", b"upgrade"));
    }
    Cow::Owned(headers)
}

pub fn tunnel_response_established(
    mode: TunnelMode,
    method: &str,
    status: http::StatusCode,
) -> bool {
    mode.established_by(method, status)
}

pub fn tunnel_cache_flags(mode: TunnelMode) -> (bool, bool) {
    (false, mode.is_tunnel())
}

pub fn downstream_tunnel_status(
    mode: TunnelMode,
    upstream_status: http::StatusCode,
) -> http::StatusCode {
    if mode == TunnelMode::Websocket && upstream_status == http::StatusCode::SWITCHING_PROTOCOLS {
        http::StatusCode::OK
    } else {
        upstream_status
    }
}
