pub(super) use impulse_http3_ingress::{
    extract_header_value, generated_span_id, generated_trace_id, parse_traceparent,
};

use super::*;
#[cfg(test)]
use crate::edge_core::request_validation::parse_content_length_values;
use crate::edge_core::request_validation::{
    RequestPartErrors, RequestValidationResult, validate_request_parts,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RequestBufferError {
    BodySize,
    Stream,
    Global,
}

pub(super) fn validate_request_headers(
    headers: &[quiche::h3::Header],
    resilience: &RuntimeResilience,
) -> Result<RequestValidationResult, (http::StatusCode, &'static [u8], bool)> {
    let head = impulse_http3_ingress::parse_request_head(
        headers,
        impulse_http3_ingress::Http3RequestLimits {
            max_headers_count: resilience.max_headers_count,
            max_headers_bytes: resilience.max_headers_bytes,
        },
    )
    .map_err(|error| (error.status, error.body, false))?;

    validate_request_parts(
        head.method,
        head.path,
        head.authority,
        head.host,
        head.content_length,
        head.websocket_tunnel,
        resilience,
        RequestPartErrors {
            invalid_method: b"invalid :method header\n",
            invalid_path: b"invalid :path header\n",
            invalid_authority: b"invalid :authority header\n",
            invalid_host: b"invalid host header\n",
            authority_mismatch: b":authority and host headers must match\n",
            connect_path_not_allowed: b"invalid CONNECT :path header\n",
            connect_authority_required: b"CONNECT requires authority host:port\n",
        },
    )
}

#[cfg(test)]
fn parse_http_content_length(
    headers: &http::HeaderMap,
) -> Result<Option<usize>, (http::StatusCode, &'static [u8], bool)> {
    parse_content_length_values(
        headers
            .get_all(http::header::CONTENT_LENGTH)
            .iter()
            .map(http::HeaderValue::as_bytes),
    )
}

#[cfg(test)]
mod tests {
    use impulse_config::config::Resilience;

    use super::*;

    fn runtime_resilience() -> RuntimeResilience {
        RuntimeResilience::from_config(&Resilience::default(), 1024)
    }

    fn h3_header(name: &'static [u8], value: &'static [u8]) -> quiche::h3::Header {
        quiche::h3::Header::new(name, value)
    }

    #[test]
    fn rejects_missing_scheme_for_non_connect_request() {
        let resilience = runtime_resilience();
        let headers = vec![
            h3_header(b":method", b"GET"),
            h3_header(b":path", b"/"),
            h3_header(b":authority", b"example.com"),
        ];

        let err = validate_request_headers(&headers, &resilience)
            .expect_err("ordinary HTTP/3 requests must include :scheme");
        assert_eq!(err.0, http::StatusCode::BAD_REQUEST);
        assert_eq!(err.1, b"missing :scheme header\n");
        assert!(!err.2);
    }

    #[test]
    fn rejects_invalid_http3_scheme_values() {
        let resilience = runtime_resilience();

        for invalid_scheme in [
            b"ftp".as_slice(),
            b"".as_slice(),
            b"https ".as_slice(),
            b"ht\xfftps".as_slice(),
        ] {
            let headers = vec![
                quiche::h3::Header::new(b":method", b"GET"),
                quiche::h3::Header::new(b":scheme", invalid_scheme),
                quiche::h3::Header::new(b":path", b"/"),
                quiche::h3::Header::new(b":authority", b"example.com"),
            ];

            let err = validate_request_headers(&headers, &resilience)
                .expect_err("unsupported or malformed HTTP/3 scheme must be rejected");
            assert_eq!(err.0, http::StatusCode::BAD_REQUEST);
            assert_eq!(err.1, b"invalid :scheme header\n");
            assert!(!err.2);
        }
    }

    #[test]
    fn accepts_registered_http_schemes_case_insensitively() {
        let resilience = runtime_resilience();

        for scheme in [b"http".as_slice(), b"https".as_slice(), b"HTTPS".as_slice()] {
            let headers = vec![
                quiche::h3::Header::new(b":method", b"GET"),
                quiche::h3::Header::new(b":scheme", scheme),
                quiche::h3::Header::new(b":path", b"/"),
                quiche::h3::Header::new(b":authority", b"example.com"),
            ];

            validate_request_headers(&headers, &resilience)
                .expect("registered HTTP scheme should be accepted");
        }
    }

    #[test]
    fn rejects_missing_scheme_for_extended_connect() {
        let mut config = Resilience::default();
        config.protocol.allow_connect = true;
        config.protocol.connect_allowed_authorities = vec!["example.com:443".to_string()];
        let resilience = RuntimeResilience::from_config(&config, 1024);
        let headers = vec![
            h3_header(b":method", b"CONNECT"),
            h3_header(b":protocol", b"websocket"),
            h3_header(b":path", b"/ws"),
            h3_header(b":authority", b"example.com:443"),
        ];

        let err = validate_request_headers(&headers, &resilience)
            .expect_err("extended CONNECT must include :scheme");
        assert_eq!(err.0, http::StatusCode::BAD_REQUEST);
        assert_eq!(err.1, b"missing :scheme header\n");
        assert!(!err.2);
    }

    #[test]
    fn rejects_scheme_on_classic_connect() {
        let mut config = Resilience::default();
        config.protocol.allow_connect = true;
        config.protocol.connect_allowed_authorities = vec!["example.com:443".to_string()];
        let resilience = RuntimeResilience::from_config(&config, 1024);
        let headers = vec![
            h3_header(b":method", b"CONNECT"),
            h3_header(b":scheme", b"https"),
            h3_header(b":authority", b"example.com:443"),
        ];

        let err = validate_request_headers(&headers, &resilience)
            .expect_err("classic CONNECT must omit :scheme");
        assert_eq!(err.0, http::StatusCode::BAD_REQUEST);
        assert_eq!(err.1, b"invalid CONNECT :scheme header\n");
        assert!(!err.2);
    }

    #[test]
    fn rejects_invalid_utf8_method_header() {
        let resilience = runtime_resilience();
        let headers = vec![
            h3_header(b":method", b"GE\xffT"),
            h3_header(b":scheme", b"https"),
            h3_header(b":path", b"/"),
            h3_header(b":authority", b"example.com"),
        ];

        let err = match validate_request_headers(&headers, &resilience) {
            Ok(_) => panic!("expected invalid utf-8 :method to be rejected"),
            Err(err) => err,
        };
        assert_eq!(err.0, http::StatusCode::BAD_REQUEST);
        assert_eq!(err.1, b"invalid :method header\n");
        assert!(!err.2);
    }

    #[test]
    fn rejects_invalid_utf8_path_header() {
        let resilience = runtime_resilience();
        let headers = vec![
            h3_header(b":method", b"GET"),
            h3_header(b":scheme", b"https"),
            h3_header(b":path", b"/\xff"),
            h3_header(b":authority", b"example.com"),
        ];

        let err = match validate_request_headers(&headers, &resilience) {
            Ok(_) => panic!("expected invalid utf-8 :path to be rejected"),
            Err(err) => err,
        };
        assert_eq!(err.0, http::StatusCode::BAD_REQUEST);
        assert_eq!(err.1, b"invalid :path header\n");
        assert!(!err.2);
    }

    #[test]
    fn rejects_invalid_utf8_authority_header() {
        let resilience = runtime_resilience();
        let headers = vec![
            h3_header(b":method", b"GET"),
            h3_header(b":scheme", b"https"),
            h3_header(b":path", b"/"),
            h3_header(b":authority", b"exa\xffmple.com"),
        ];

        let err = match validate_request_headers(&headers, &resilience) {
            Ok(_) => panic!("expected invalid utf-8 :authority to be rejected"),
            Err(err) => err,
        };
        assert_eq!(err.0, http::StatusCode::BAD_REQUEST);
        assert_eq!(err.1, b"invalid :authority header\n");
        assert!(!err.2);
    }

    #[test]
    fn rejects_invalid_utf8_host_header() {
        let resilience = runtime_resilience();
        let headers = vec![
            h3_header(b":method", b"GET"),
            h3_header(b":scheme", b"https"),
            h3_header(b":path", b"/"),
            h3_header(b"host", b"exa\xffmple.com"),
        ];

        let err = match validate_request_headers(&headers, &resilience) {
            Ok(_) => panic!("expected invalid utf-8 host to be rejected"),
            Err(err) => err,
        };
        assert_eq!(err.0, http::StatusCode::BAD_REQUEST);
        assert_eq!(err.1, b"invalid host header\n");
        assert!(!err.2);
    }

    #[test]
    fn rejects_malformed_authority_header() {
        let resilience = runtime_resilience();
        let headers = vec![
            h3_header(b":method", b"GET"),
            h3_header(b":scheme", b"https"),
            h3_header(b":path", b"/"),
            h3_header(b":authority", b"example.com invalid"),
        ];

        let err = validate_request_headers(&headers, &resilience)
            .expect_err("malformed authority must be rejected");
        assert_eq!(err.0, http::StatusCode::BAD_REQUEST);
        assert_eq!(err.1, b"invalid :authority header\n");
        assert!(!err.2);
    }

    #[test]
    fn rejects_malformed_host_header() {
        let resilience = runtime_resilience();
        let headers = vec![
            h3_header(b":method", b"GET"),
            h3_header(b":scheme", b"https"),
            h3_header(b":path", b"/"),
            h3_header(b"host", b"example.com/path"),
        ];

        let err =
            validate_request_headers(&headers, &resilience).expect_err("malformed host rejected");
        assert_eq!(err.0, http::StatusCode::BAD_REQUEST);
        assert_eq!(err.1, b"invalid host header\n");
        assert!(!err.2);
    }

    #[test]
    fn rejects_http3_upgrade_for_non_websocket_protocols() {
        let resilience = runtime_resilience();
        let headers = vec![
            h3_header(b":method", b"GET"),
            h3_header(b":scheme", b"https"),
            h3_header(b":path", b"/"),
            h3_header(b":authority", b"example.com"),
            h3_header(b"connection", b"Upgrade"),
            h3_header(b"upgrade", b"h2c"),
        ];

        let err = validate_request_headers(&headers, &resilience)
            .expect_err("HTTP/3 Upgrade requests for non-websocket protocols must be rejected");
        assert_eq!(err.0, http::StatusCode::BAD_REQUEST);
        assert_eq!(err.1, b"HTTP/3 does not support Upgrade requests\n");
        assert!(!err.2);
    }

    #[test]
    fn rejects_http3_websocket_legacy_upgrade() {
        let resilience = runtime_resilience();
        let headers = vec![
            h3_header(b":method", b"GET"),
            h3_header(b":scheme", b"https"),
            h3_header(b":path", b"/ws"),
            h3_header(b":authority", b"example.com"),
            h3_header(b"connection", b"keep-alive, Upgrade"),
            h3_header(b"upgrade", b"websocket"),
        ];

        let err = validate_request_headers(&headers, &resilience)
            .expect_err("HTTP/3 WebSocket legacy upgrade must be rejected");
        assert_eq!(err.0, http::StatusCode::BAD_REQUEST);
        assert_eq!(err.1, b"HTTP/3 does not support Upgrade requests\n");
        assert!(!err.2);
    }

    #[test]
    fn rejects_denied_path_for_http3_websocket_connect() {
        let mut config = Resilience::default();
        config.protocol.denied_path_prefixes = vec!["/admin".to_string()];
        config.protocol.allow_connect = true;
        config.protocol.connect_allowed_ports = vec![443];
        config.protocol.connect_allowed_authorities = vec!["example.com:443".to_string()];
        let resilience = RuntimeResilience::from_config(&config, 1024);
        let headers = vec![
            h3_header(b":method", b"CONNECT"),
            h3_header(b":protocol", b"websocket"),
            h3_header(b":scheme", b"https"),
            h3_header(b":path", b"/admin/socket"),
            h3_header(b":authority", b"example.com:443"),
        ];

        let err = validate_request_headers(&headers, &resilience)
            .expect_err("denied WebSocket CONNECT path must be rejected");
        assert_eq!(err.0, http::StatusCode::FORBIDDEN);
        assert_eq!(err.1, b"request path blocked by policy\n");
        assert!(err.2);
    }

    #[test]
    fn accepts_consistent_duplicate_content_length_headers() {
        let resilience = runtime_resilience();
        let headers = vec![
            h3_header(b":method", b"POST"),
            h3_header(b":scheme", b"https"),
            h3_header(b":path", b"/"),
            h3_header(b":authority", b"example.com"),
            h3_header(b"content-length", b"10"),
            h3_header(b"content-length", b"10"),
        ];

        let request = validate_request_headers(&headers, &resilience)
            .expect("consistent duplicate content-length should be accepted");
        assert_eq!(request.content_length, Some(10));
    }

    #[test]
    fn rejects_conflicting_duplicate_content_length_headers() {
        let resilience = runtime_resilience();
        let headers = vec![
            h3_header(b":method", b"POST"),
            h3_header(b":scheme", b"https"),
            h3_header(b":path", b"/"),
            h3_header(b":authority", b"example.com"),
            h3_header(b"content-length", b"10"),
            h3_header(b"content-length", b"11"),
        ];

        let err = validate_request_headers(&headers, &resilience)
            .expect_err("conflicting content-length must be rejected");
        assert_eq!(err.0, http::StatusCode::BAD_REQUEST);
        assert_eq!(err.1, b"conflicting content-length header\n");
        assert!(!err.2);
    }

    #[test]
    fn rejects_invalid_content_length_header() {
        let resilience = runtime_resilience();
        let headers = vec![
            h3_header(b":method", b"POST"),
            h3_header(b":scheme", b"https"),
            h3_header(b":path", b"/"),
            h3_header(b":authority", b"example.com"),
            h3_header(b"content-length", b"ten"),
        ];

        let err = validate_request_headers(&headers, &resilience)
            .expect_err("invalid content-length must be rejected");
        assert_eq!(err.0, http::StatusCode::BAD_REQUEST);
        assert_eq!(err.1, b"invalid content-length header\n");
        assert!(!err.2);
    }

    #[test]
    fn http_header_map_rejects_conflicting_content_length_values() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("8"),
        );
        headers.append(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("9"),
        );

        let err = parse_http_content_length(&headers)
            .expect_err("conflicting content-length must be rejected");
        assert_eq!(err.0, http::StatusCode::BAD_REQUEST);
        assert_eq!(err.1, b"conflicting content-length header\n");
        assert!(!err.2);
    }

    #[test]
    fn authority_host_match_allows_omitted_default_port() {
        let mut cfg = Resilience::default();
        cfg.protocol.enforce_authority_host_match = true;
        let resilience = RuntimeResilience::from_config(&cfg, 1024);
        let headers = vec![
            h3_header(b":method", b"GET"),
            h3_header(b":scheme", b"https"),
            h3_header(b":path", b"/"),
            h3_header(b":authority", b"api.example.com:443"),
            h3_header(b"host", b"api.example.com"),
        ];

        let request = validate_request_headers(&headers, &resilience)
            .expect("default port omission should still match");
        assert_eq!(request.authority.as_deref(), Some("api.example.com:443"));
    }

    #[test]
    fn authority_host_match_rejects_explicit_port_mismatch() {
        let mut cfg = Resilience::default();
        cfg.protocol.enforce_authority_host_match = true;
        let resilience = RuntimeResilience::from_config(&cfg, 1024);
        let headers = vec![
            h3_header(b":method", b"GET"),
            h3_header(b":scheme", b"https"),
            h3_header(b":path", b"/"),
            h3_header(b":authority", b"api.example.com:443"),
            h3_header(b"host", b"api.example.com:8443"),
        ];

        let err = validate_request_headers(&headers, &resilience)
            .expect_err("explicitly different authority and host ports must be rejected");
        assert_eq!(err.0, http::StatusCode::BAD_REQUEST);
        assert_eq!(err.1, b":authority and host headers must match\n");
        assert!(!err.2);
    }

    #[test]
    fn connect_without_path_is_accepted_when_policy_allows_target() {
        let mut cfg = Resilience::default();
        cfg.protocol.allow_connect = true;
        cfg.protocol.connect_allowed_authorities = vec!["proxy.example.com:443".to_string()];
        let resilience = RuntimeResilience::from_config(&cfg, 1024);
        let headers = vec![
            h3_header(b":method", b"CONNECT"),
            h3_header(b":authority", b"proxy.example.com:443"),
        ];

        let request =
            validate_request_headers(&headers, &resilience).expect("CONNECT request should pass");
        assert_eq!(request.method, "CONNECT");
        assert_eq!(request.path, "/");
        assert_eq!(request.authority.as_deref(), Some("proxy.example.com:443"));
    }

    #[test]
    fn connect_missing_authority_is_rejected() {
        let mut cfg = Resilience::default();
        cfg.protocol.allow_connect = true;
        let resilience = RuntimeResilience::from_config(&cfg, 1024);
        let headers = vec![h3_header(b":method", b"CONNECT")];

        let err = validate_request_headers(&headers, &resilience)
            .expect_err("CONNECT without authority must be rejected");
        assert_eq!(err.0, http::StatusCode::BAD_REQUEST);
        assert_eq!(err.1, b"CONNECT requires authority host:port\n");
        assert!(!err.2);
    }

    #[test]
    fn connect_missing_port_is_rejected() {
        let mut cfg = Resilience::default();
        cfg.protocol.allow_connect = true;
        let resilience = RuntimeResilience::from_config(&cfg, 1024);
        let headers = vec![
            h3_header(b":method", b"CONNECT"),
            h3_header(b":authority", b"proxy.example.com"),
        ];

        let err = validate_request_headers(&headers, &resilience)
            .expect_err("CONNECT authority without port must be rejected");
        assert_eq!(err.0, http::StatusCode::BAD_REQUEST);
        assert_eq!(err.1, b"CONNECT requires authority host:port\n");
        assert!(!err.2);
    }

    #[test]
    fn connect_is_denied_when_policy_disables_or_blocks_target() {
        let resilience = runtime_resilience();
        let headers = vec![
            h3_header(b":method", b"CONNECT"),
            h3_header(b":authority", b"proxy.example.com:443"),
        ];
        let err = validate_request_headers(&headers, &resilience)
            .expect_err("CONNECT should be denied by default policy");
        assert_eq!(err.0, http::StatusCode::FORBIDDEN);
        assert_eq!(err.1, b"CONNECT target denied by policy\n");
        assert!(err.2);

        let mut cfg = Resilience::default();
        cfg.protocol.allow_connect = true;
        cfg.protocol.connect_allowed_ports = vec![8443];
        let resilience = RuntimeResilience::from_config(&cfg, 1024);
        let err = validate_request_headers(&headers, &resilience)
            .expect_err("CONNECT should be denied when port is not allowlisted");
        assert_eq!(err.0, http::StatusCode::FORBIDDEN);
        assert_eq!(err.1, b"CONNECT target denied by policy\n");
        assert!(err.2);
    }
}
