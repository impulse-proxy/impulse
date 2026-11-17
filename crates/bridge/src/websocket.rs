//! Canonical websocket and upgrade detection helpers for bridge callers.
//!
//! This module owns request-shape inspection for websocket tunneling semantics.
//! Transport execution and tunnel I/O stay outside this crate; callers should
//! use these helpers only to decide whether websocket-specific bridging rules apply.

use crate::request::RequestHeaders;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3WebsocketRequestKind {
    None,
    ExtendedConnect,
}

pub fn h3_websocket_request_kind(
    method: &str,
    headers: &[quiche::h3::Header],
) -> H3WebsocketRequestKind {
    websocket_request_kind(method, headers.into())
}

pub(crate) fn websocket_request_kind(
    method: &str,
    headers: RequestHeaders<'_>,
) -> H3WebsocketRequestKind {
    let protocol_is_websocket = headers.iter().any(|header| {
        header.name().eq_ignore_ascii_case(b":protocol")
            && std::str::from_utf8(header.value())
                .map(|value| value.eq_ignore_ascii_case("websocket"))
                .unwrap_or(false)
    });

    if method.eq_ignore_ascii_case("CONNECT") && protocol_is_websocket {
        H3WebsocketRequestKind::ExtendedConnect
    } else {
        H3WebsocketRequestKind::None
    }
}

/// Detect legacy HTTP/1.1 WebSocket upgrade headers for upstream shaping.
///
/// This is not a valid HTTP/3 ingress shape; H3 callers must use
/// [`h3_websocket_request_kind`] and require extended CONNECT.
pub fn legacy_websocket_upgrade_requested(method: &str, headers: &[quiche::h3::Header]) -> bool {
    legacy_websocket_upgrade_requested_for_headers(method, headers.into())
}

pub(crate) fn legacy_websocket_upgrade_requested_for_headers(
    method: &str,
    headers: RequestHeaders<'_>,
) -> bool {
    method.eq_ignore_ascii_case("GET")
        && headers.iter().any(|header| {
            header.name().eq_ignore_ascii_case(b"upgrade")
                && std::str::from_utf8(header.value())
                    .is_ok_and(|value| value.eq_ignore_ascii_case("websocket"))
        })
        && headers.iter().any(|header| {
            header.name().eq_ignore_ascii_case(b"connection")
                && std::str::from_utf8(header.value()).is_ok_and(|value| {
                    value
                        .split(',')
                        .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
                })
        })
}

pub fn h3_websocket_tunnel_requested(method: &str, headers: &[quiche::h3::Header]) -> bool {
    h3_websocket_request_kind(method, headers) != H3WebsocketRequestKind::None
}

#[cfg(test)]
mod tests {
    use quiche::h3::Header;

    use super::{
        H3WebsocketRequestKind, h3_websocket_request_kind, h3_websocket_tunnel_requested,
        legacy_websocket_upgrade_requested,
    };

    #[test]
    fn legacy_upgrade_is_not_classified_as_an_h3_websocket() {
        let headers = vec![
            Header::new(b"connection", b"keep-alive, upgrade"),
            Header::new(b"upgrade", b"websocket"),
            Header::new(b"sec-websocket-key", b"dGhlIHNhbXBsZSBub25jZQ=="),
        ];

        assert_eq!(
            h3_websocket_request_kind("GET", &headers),
            H3WebsocketRequestKind::None
        );
        assert!(!h3_websocket_tunnel_requested("GET", &headers));
        assert!(legacy_websocket_upgrade_requested("GET", &headers));
    }

    #[test]
    fn detects_extended_connect_only_when_connect_uses_websocket_protocol() {
        let headers = vec![
            Header::new(b":protocol", b"websocket"),
            Header::new(b"sec-websocket-key", b"dGhlIHNhbXBsZSBub25jZQ=="),
        ];

        assert_eq!(
            h3_websocket_request_kind("CONNECT", &headers),
            H3WebsocketRequestKind::ExtendedConnect
        );
        assert!(h3_websocket_tunnel_requested("CONNECT", &headers));
    }

    #[test]
    fn ignores_incomplete_or_invalid_upgrade_candidates() {
        let missing_connection = vec![Header::new(b"upgrade", b"websocket")];
        assert_eq!(
            h3_websocket_request_kind("GET", &missing_connection),
            H3WebsocketRequestKind::None
        );

        let wrong_upgrade_token = vec![
            Header::new(b"connection", b"upgrade"),
            Header::new(b"upgrade", b"h2c"),
        ];
        assert_eq!(
            h3_websocket_request_kind("GET", &wrong_upgrade_token),
            H3WebsocketRequestKind::None
        );

        let connect_without_protocol = vec![Header::new(b"sec-websocket-key", b"abc")];
        assert_eq!(
            h3_websocket_request_kind("CONNECT", &connect_without_protocol),
            H3WebsocketRequestKind::None
        );

        let get_with_protocol_header = vec![Header::new(b":protocol", b"websocket")];
        assert_eq!(
            h3_websocket_request_kind("GET", &get_with_protocol_header),
            H3WebsocketRequestKind::None
        );
    }
}
