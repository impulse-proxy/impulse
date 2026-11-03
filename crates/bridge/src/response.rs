//! Canonical downstream response normalization surface.
//!
//! This module owns header/trailer filtering, bodyless/no-content shaping, and
//! response emission policy decisions shared across ingress protocols.

use std::collections::HashSet;

use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
pub use impulse_contracts::IngressProtocol as ResponseNormalizationProtocol;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseBodyMode {
    Normal,
    HeadRequest,
    TunnelSuccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseBodyPolicy {
    Forward,
    Suppress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseProtocolConstraints {
    pub protocol: ResponseNormalizationProtocol,
    pub preserve_upgrade: bool,
}

#[derive(Debug)]
pub struct UpstreamResponseView<'a> {
    pub status: StatusCode,
    pub headers: &'a HeaderMap,
}

#[derive(Debug)]
pub struct ResponseNormalizationInput<'a> {
    pub upstream: UpstreamResponseView<'a>,
    pub body_mode: ResponseBodyMode,
    pub constraints: ResponseProtocolConstraints,
}

#[derive(Debug)]
pub struct NormalizedHeader {
    pub name: HeaderName,
    pub value: HeaderValue,
}

#[derive(Debug)]
pub struct ResponseEmissionPolicy {
    pub body: ResponseBodyPolicy,
    pub emit_end_stream_on_headers: bool,
}

#[derive(Debug)]
pub struct NormalizedResponse {
    pub headers: Vec<NormalizedHeader>,
    pub emission: ResponseEmissionPolicy,
}

pub(crate) fn status_forbids_response_body(status: StatusCode) -> bool {
    status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
}

fn is_hop_by_hop_response_header(name: &HeaderName, preserve_upgrade: bool) -> bool {
    if preserve_upgrade && (name == http::header::CONNECTION || name == http::header::UPGRADE) {
        return false;
    }

    name == http::header::CONNECTION
        || name == http::header::PROXY_AUTHENTICATE
        || name == http::header::PROXY_AUTHORIZATION
        || name == http::header::TE
        || name == http::header::TRAILER
        || name == http::header::TRANSFER_ENCODING
        || name == http::header::UPGRADE
        || name.as_str().eq_ignore_ascii_case("keep-alive")
        || name.as_str().eq_ignore_ascii_case("proxy-connection")
}

pub(crate) fn response_connection_tokens(headers: &HeaderMap) -> HashSet<String> {
    let mut tokens = HashSet::new();
    for value in headers.get_all(http::header::CONNECTION) {
        let Ok(raw) = value.to_str() else {
            continue;
        };
        for part in raw.split(',') {
            let token = part.trim().to_ascii_lowercase();
            if !token.is_empty() {
                tokens.insert(token);
            }
        }
    }
    tokens
}

pub fn should_strip_response_header(
    name: &HeaderName,
    connection_tokens: &HashSet<String>,
    constraints: ResponseProtocolConstraints,
) -> bool {
    (!(constraints.preserve_upgrade
        && (name == http::header::CONNECTION || name == http::header::UPGRADE))
        && connection_tokens.contains(name.as_str()))
        || is_hop_by_hop_response_header(name, constraints.preserve_upgrade)
        || matches!(constraints.protocol, ResponseNormalizationProtocol::Http3)
            && name == http::header::CONTENT_LENGTH
        || matches!(constraints.protocol, ResponseNormalizationProtocol::Http1)
            && name.as_str().eq_ignore_ascii_case("alt-svc")
}

pub fn normalize_response_trailers(
    trailers: &HeaderMap,
    constraints: ResponseProtocolConstraints,
) -> Vec<NormalizedHeader> {
    let connection_tokens = response_connection_tokens(trailers);
    let mut normalized = Vec::with_capacity(trailers.len());
    for (name, value) in trailers {
        if should_strip_response_header(name, &connection_tokens, constraints) {
            continue;
        }
        normalized.push(NormalizedHeader {
            name: name.clone(),
            value: value.clone(),
        });
    }
    normalized
}

pub fn normalize_upstream_response(input: ResponseNormalizationInput<'_>) -> NormalizedResponse {
    let constraints = input.constraints;
    let headers = input.upstream.headers;
    let connection_tokens = response_connection_tokens(headers);
    let mut normalized_headers = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        if should_strip_response_header(name, &connection_tokens, constraints) {
            continue;
        }
        normalized_headers.push(NormalizedHeader {
            name: name.clone(),
            value: value.clone(),
        });
    }

    let declared_content_length = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    let body_forbidden = status_forbids_response_body(input.upstream.status);
    let suppress_body = !matches!(input.body_mode, ResponseBodyMode::TunnelSuccess)
        && (matches!(input.body_mode, ResponseBodyMode::HeadRequest) || body_forbidden);

    let emission = ResponseEmissionPolicy {
        body: if suppress_body {
            ResponseBodyPolicy::Suppress
        } else {
            ResponseBodyPolicy::Forward
        },
        emit_end_stream_on_headers: suppress_body
            || (!matches!(input.body_mode, ResponseBodyMode::TunnelSuccess)
                && (body_forbidden || declared_content_length == Some(0))),
    };

    NormalizedResponse {
        headers: normalized_headers,
        emission,
    }
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};

    use super::{
        NormalizedHeader, ResponseBodyMode, ResponseBodyPolicy, ResponseNormalizationInput,
        ResponseNormalizationProtocol, ResponseProtocolConstraints, UpstreamResponseView,
        normalize_response_trailers, normalize_upstream_response, response_connection_tokens,
        should_strip_response_header, status_forbids_response_body,
    };

    fn http3_constraints() -> ResponseProtocolConstraints {
        ResponseProtocolConstraints {
            protocol: ResponseNormalizationProtocol::Http3,
            preserve_upgrade: false,
        }
    }

    fn http1_constraints() -> ResponseProtocolConstraints {
        ResponseProtocolConstraints {
            protocol: ResponseNormalizationProtocol::Http1,
            preserve_upgrade: false,
        }
    }

    fn header_value<'a>(headers: &'a [NormalizedHeader], name: &str) -> Option<&'a str> {
        let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
        headers
            .iter()
            .find(|header| header.name == name)
            .and_then(|header| header.value.to_str().ok())
    }

    #[test]
    fn forbids_bodies_for_informational_and_empty_statuses() {
        assert!(status_forbids_response_body(StatusCode::CONTINUE));
        assert!(status_forbids_response_body(StatusCode::NO_CONTENT));
        assert!(status_forbids_response_body(StatusCode::NOT_MODIFIED));
        assert!(!status_forbids_response_body(StatusCode::OK));
    }

    #[test]
    fn response_connection_tokens_normalize_multiple_values() {
        let mut headers = HeaderMap::new();
        headers.append(
            http::header::CONNECTION,
            HeaderValue::from_static(" keep-alive , x-hop "),
        );
        headers.append(
            http::header::CONNECTION,
            HeaderValue::from_static("Upgrade, x-extra"),
        );

        let tokens = response_connection_tokens(&headers);

        assert!(tokens.contains("keep-alive"));
        assert!(tokens.contains("x-hop"));
        assert!(tokens.contains("upgrade"));
        assert!(tokens.contains("x-extra"));
    }

    #[test]
    fn http3_header_filter_strips_hop_headers_connection_tokens_and_content_length() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("x-internal-hop"),
        );
        let tokens = response_connection_tokens(&headers);

        assert!(should_strip_response_header(
            &http::header::TE,
            &tokens,
            http3_constraints(),
        ));
        assert!(should_strip_response_header(
            &http::header::TRAILER,
            &tokens,
            http3_constraints(),
        ));
        assert!(should_strip_response_header(
            &http::header::CONTENT_LENGTH,
            &tokens,
            http3_constraints(),
        ));
        assert!(should_strip_response_header(
            &HeaderName::from_static("x-internal-hop"),
            &tokens,
            http3_constraints(),
        ));
        assert!(!should_strip_response_header(
            &http::header::CACHE_CONTROL,
            &tokens,
            http3_constraints(),
        ));
    }

    #[test]
    fn http1_header_filter_strips_alt_svc_and_can_preserve_upgrade() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("x-hop-token"),
        );
        let tokens = response_connection_tokens(&headers);

        assert!(should_strip_response_header(
            &HeaderName::from_static("alt-svc"),
            &tokens,
            http1_constraints(),
        ));
        assert!(should_strip_response_header(
            &HeaderName::from_static("x-hop-token"),
            &tokens,
            http1_constraints(),
        ));
        assert!(!should_strip_response_header(
            &http::header::UPGRADE,
            &tokens,
            ResponseProtocolConstraints {
                preserve_upgrade: true,
                ..http1_constraints()
            },
        ));
    }

    #[test]
    fn trailer_normalization_preserves_end_to_end_and_filters_hop_headers() {
        let mut trailers = HeaderMap::new();
        trailers.insert(
            http::HeaderName::from_static("grpc-status"),
            HeaderValue::from_static("0"),
        );
        trailers.insert(
            http::HeaderName::from_static("grpc-message"),
            HeaderValue::from_static("ok"),
        );
        trailers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("x-hop-token"),
        );
        trailers.insert(http::header::TE, HeaderValue::from_static("trailers"));
        trailers.insert(
            http::HeaderName::from_static("x-hop-token"),
            HeaderValue::from_static("secret"),
        );
        trailers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("12"));

        let normalized = normalize_response_trailers(&trailers, http3_constraints());

        assert_eq!(normalized.len(), 2);
        assert_eq!(header_value(&normalized, "grpc-status"), Some("0"));
        assert_eq!(header_value(&normalized, "grpc-message"), Some("ok"));
        assert_eq!(header_value(&normalized, "x-hop-token"), None);
    }

    #[test]
    fn normalizes_http3_head_response_as_bodyless_and_header_terminal() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("12"));
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain"),
        );
        headers.insert(
            http::HeaderName::from_static("x-custom"),
            HeaderValue::from_static("ok"),
        );

        let normalized = normalize_upstream_response(ResponseNormalizationInput {
            upstream: UpstreamResponseView {
                status: StatusCode::OK,
                headers: &headers,
            },
            body_mode: ResponseBodyMode::HeadRequest,
            constraints: http3_constraints(),
        });

        assert_eq!(normalized.emission.body, ResponseBodyPolicy::Suppress);
        assert!(normalized.emission.emit_end_stream_on_headers);
        assert!(
            normalized
                .headers
                .iter()
                .all(|header| header.name != http::header::CONTENT_LENGTH)
        );
        assert!(
            normalized
                .headers
                .iter()
                .any(|header| header.name == http::HeaderName::from_static("x-custom"))
        );
    }

    #[test]
    fn normalizes_informational_response_as_bodyless_and_terminal() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::HeaderName::from_static("retry-after"),
            HeaderValue::from_static("3"),
        );

        let normalized = normalize_upstream_response(ResponseNormalizationInput {
            upstream: UpstreamResponseView {
                status: StatusCode::CONTINUE,
                headers: &headers,
            },
            body_mode: ResponseBodyMode::Normal,
            constraints: http1_constraints(),
        });

        assert_eq!(normalized.emission.body, ResponseBodyPolicy::Suppress);
        assert!(normalized.emission.emit_end_stream_on_headers);
        assert_eq!(header_value(&normalized.headers, "retry-after"), Some("3"));
    }

    #[test]
    fn normalizes_http1_no_content_without_suppressing_surviving_metadata() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        headers.insert(
            http::HeaderName::from_static("etag"),
            HeaderValue::from_static("\"abc\""),
        );

        let normalized = normalize_upstream_response(ResponseNormalizationInput {
            upstream: UpstreamResponseView {
                status: StatusCode::NO_CONTENT,
                headers: &headers,
            },
            body_mode: ResponseBodyMode::Normal,
            constraints: http1_constraints(),
        });

        assert_eq!(normalized.emission.body, ResponseBodyPolicy::Suppress);
        assert!(normalized.emission.emit_end_stream_on_headers);
        assert!(
            normalized
                .headers
                .iter()
                .any(|header| header.name == http::header::CONTENT_LENGTH)
        );
        assert!(
            normalized
                .headers
                .iter()
                .any(|header| header.name == http::HeaderName::from_static("etag"))
        );
    }

    #[test]
    fn normalizes_not_modified_response_as_bodyless_while_preserving_end_to_end_metadata() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        headers.insert(http::header::ETAG, HeaderValue::from_static("\"etag-304\""));
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=60"),
        );

        let normalized = normalize_upstream_response(ResponseNormalizationInput {
            upstream: UpstreamResponseView {
                status: StatusCode::NOT_MODIFIED,
                headers: &headers,
            },
            body_mode: ResponseBodyMode::Normal,
            constraints: http1_constraints(),
        });

        assert_eq!(normalized.emission.body, ResponseBodyPolicy::Suppress);
        assert!(normalized.emission.emit_end_stream_on_headers);
        assert_eq!(
            header_value(&normalized.headers, "etag"),
            Some("\"etag-304\"")
        );
        assert_eq!(
            header_value(&normalized.headers, "cache-control"),
            Some("max-age=60")
        );
    }

    #[test]
    fn tunnel_success_does_not_force_body_suppression_or_terminal_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("0"));

        let normalized = normalize_upstream_response(ResponseNormalizationInput {
            upstream: UpstreamResponseView {
                status: StatusCode::OK,
                headers: &headers,
            },
            body_mode: ResponseBodyMode::TunnelSuccess,
            constraints: http3_constraints(),
        });

        assert_eq!(normalized.emission.body, ResponseBodyPolicy::Forward);
        assert!(!normalized.emission.emit_end_stream_on_headers);
    }

    #[test]
    fn switching_protocols_preserves_upgrade_headers_when_requested() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("upgrade"),
        );
        headers.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));

        let normalized = normalize_upstream_response(ResponseNormalizationInput {
            upstream: UpstreamResponseView {
                status: StatusCode::SWITCHING_PROTOCOLS,
                headers: &headers,
            },
            body_mode: ResponseBodyMode::TunnelSuccess,
            constraints: ResponseProtocolConstraints {
                preserve_upgrade: true,
                ..http1_constraints()
            },
        });

        assert_eq!(normalized.emission.body, ResponseBodyPolicy::Forward);
        assert!(!normalized.emission.emit_end_stream_on_headers);
        assert_eq!(
            header_value(&normalized.headers, "connection"),
            Some("upgrade")
        );
        assert_eq!(
            header_value(&normalized.headers, "upgrade"),
            Some("websocket")
        );
    }

    #[test]
    fn http3_and_http1_normalizers_preserve_end_to_end_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("x-hop-token"),
        );
        headers.insert(
            HeaderName::from_static("x-hop-token"),
            HeaderValue::from_static("secret"),
        );
        headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("9"));
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=60"),
        );
        headers.insert(http::header::ETAG, HeaderValue::from_static("\"etag-1\""));

        let h3 = normalize_upstream_response(ResponseNormalizationInput {
            upstream: UpstreamResponseView {
                status: StatusCode::OK,
                headers: &headers,
            },
            body_mode: ResponseBodyMode::Normal,
            constraints: http3_constraints(),
        });
        let http1 = normalize_upstream_response(ResponseNormalizationInput {
            upstream: UpstreamResponseView {
                status: StatusCode::OK,
                headers: &headers,
            },
            body_mode: ResponseBodyMode::Normal,
            constraints: http1_constraints(),
        });

        assert_eq!(h3.emission.body, ResponseBodyPolicy::Forward);
        assert_eq!(http1.emission.body, ResponseBodyPolicy::Forward);
        assert!(!h3.emission.emit_end_stream_on_headers);
        assert!(!http1.emission.emit_end_stream_on_headers);
        assert_eq!(
            header_value(&h3.headers, "cache-control"),
            header_value(&http1.headers, "cache-control")
        );
        assert_eq!(
            header_value(&h3.headers, "etag"),
            header_value(&http1.headers, "etag")
        );
        assert_eq!(header_value(&h3.headers, "x-hop-token"), None);
        assert_eq!(header_value(&http1.headers, "x-hop-token"), None);
        assert_eq!(header_value(&h3.headers, "content-length"), None);
        assert_eq!(header_value(&http1.headers, "content-length"), Some("9"));
    }
}
