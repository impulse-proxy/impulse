use super::*;
use crate::routing::util::{canonical_request_target, request_path_is_ambiguous};

#[derive(Debug)]
pub(crate) struct RequestValidationResult {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) authority: Option<String>,
    pub(super) content_length: Option<usize>,
    pub(super) websocket_tunnel: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RequestBufferError {
    BodySize,
    Stream,
    Global,
}

pub(super) fn validate_request_headers(
    list: &[quiche::h3::Header],
    resilience: &RuntimeResilience,
) -> Result<RequestValidationResult, (http::StatusCode, &'static [u8], bool)> {
    if list.len() > resilience.max_headers_count {
        return Err((
            http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            b"too many request headers
",
            false,
        ));
    }

    let mut header_bytes = 0usize;
    let mut method = None::<String>;
    let mut path = None::<String>;
    let mut authority = None::<String>;
    let mut host = None::<String>;
    let mut scheme = None::<String>;
    let mut protocol = None::<String>;
    let mut h3_upgrade_requested = false;

    for header in list {
        header_bytes = header_bytes.saturating_add(header.name().len() + header.value().len());
        if header_bytes > resilience.max_headers_bytes {
            return Err((
                http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                b"request headers exceed size limit
",
                false,
            ));
        }

        match header.name() {
            b":method" => {
                if method.is_some() {
                    return Err((
                        http::StatusCode::BAD_REQUEST,
                        b"duplicate :method header
",
                        false,
                    ));
                }
                method = Some(strict_header_value(
                    header.value(),
                    b"invalid :method header
",
                )?);
            }
            b":path" => {
                if path.is_some() {
                    return Err((
                        http::StatusCode::BAD_REQUEST,
                        b"duplicate :path header
",
                        false,
                    ));
                }
                path = Some(strict_header_value(
                    header.value(),
                    b"invalid :path header
",
                )?);
            }
            b":authority" => {
                if authority.is_some() {
                    return Err((
                        http::StatusCode::BAD_REQUEST,
                        b"duplicate :authority header
",
                        false,
                    ));
                }
                authority = Some(strict_header_value(
                    header.value(),
                    b"invalid :authority header
",
                )?);
            }
            b"host" => {
                if host.is_some() {
                    return Err((
                        http::StatusCode::BAD_REQUEST,
                        b"duplicate host header
",
                        false,
                    ));
                }
                host = Some(strict_header_value(
                    header.value(),
                    b"invalid host header
",
                )?);
            }
            b"connection" => {
                let value = strict_header_value(
                    header.value(),
                    b"invalid connection header
",
                )?;
                if value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
                {
                    h3_upgrade_requested = true;
                }
            }
            b"upgrade" => {
                let _ = strict_header_value(
                    header.value(),
                    b"invalid upgrade header
",
                )?;
                h3_upgrade_requested = true;
            }
            b":scheme" => {
                if scheme.is_some() {
                    return Err((
                        http::StatusCode::BAD_REQUEST,
                        b"duplicate :scheme header
",
                        false,
                    ));
                }
                let value = strict_header_value(
                    header.value(),
                    b"invalid :scheme header
",
                )?;
                if !value.eq_ignore_ascii_case("http") && !value.eq_ignore_ascii_case("https") {
                    return Err((
                        http::StatusCode::BAD_REQUEST,
                        b"invalid :scheme header
",
                        false,
                    ));
                }
                scheme = Some(value);
            }
            b":protocol" => {
                if protocol.is_some() {
                    return Err((
                        http::StatusCode::BAD_REQUEST,
                        b"duplicate :protocol header
",
                        false,
                    ));
                }
                protocol = Some(strict_header_value(
                    header.value(),
                    b"invalid :protocol header
",
                )?);
            }
            name if name.starts_with(b":") => {
                return Err((
                    http::StatusCode::BAD_REQUEST,
                    b"unsupported pseudo-header
",
                    false,
                ));
            }
            _ => {}
        }
    }

    let content_length = parse_h3_content_length(list)?;

    let method = match method {
        Some(method) => method,
        None => {
            return Err((
                http::StatusCode::BAD_REQUEST,
                b"missing :method header
",
                false,
            ));
        }
    };

    let websocket_tunnel = impulse_bridge::websocket::h3_websocket_tunnel_requested(&method, list);
    if protocol.is_some() && !websocket_tunnel {
        return Err((
            http::StatusCode::BAD_REQUEST,
            b"unsupported pseudo-header
",
            false,
        ));
    }
    if h3_upgrade_requested {
        return Err((
            http::StatusCode::BAD_REQUEST,
            b"HTTP/3 does not support Upgrade requests
",
            false,
        ));
    }

    let is_connect = method.eq_ignore_ascii_case("CONNECT");
    match (is_connect, websocket_tunnel, scheme.is_some()) {
        (false, _, false) | (true, true, false) => {
            return Err((
                http::StatusCode::BAD_REQUEST,
                b"missing :scheme header
",
                false,
            ));
        }
        (true, false, true) => {
            return Err((
                http::StatusCode::BAD_REQUEST,
                b"invalid CONNECT :scheme header
",
                false,
            ));
        }
        _ => {}
    }
    let path = match (is_connect, websocket_tunnel, path) {
        (true, true, Some(path)) => path,
        (true, true, None) => {
            return Err((
                http::StatusCode::BAD_REQUEST,
                b"missing :path header
",
                false,
            ));
        }
        (true, false, Some(path)) if path.is_empty() => {
            return Err((
                http::StatusCode::BAD_REQUEST,
                b"invalid CONNECT :path header
",
                false,
            ));
        }
        (true, false, Some(_)) => {
            return Err((
                http::StatusCode::BAD_REQUEST,
                b"invalid CONNECT :path header
",
                false,
            ));
        }
        (true, false, None) => "/".to_string(),
        (false, _, Some(path)) => path,
        (false, _, None) => {
            return Err((
                http::StatusCode::BAD_REQUEST,
                b"missing :path header
",
                false,
            ));
        }
    };

    validate_request_parts(
        method,
        path,
        authority,
        host,
        content_length,
        websocket_tunnel,
        resilience,
        RequestPartErrors {
            invalid_method: b"invalid :method header
",
            invalid_path: b"invalid :path header
",
            invalid_authority: b"invalid :authority header
",
            invalid_host: b"invalid host header
",
            authority_mismatch: b":authority and host headers must match
",
            connect_path_not_allowed: b"invalid CONNECT :path header
",
            connect_authority_required: b"CONNECT requires authority host:port
",
        },
    )
}

pub(in crate::quic_listener) fn validate_http_request(
    req: &http::Request<Incoming>,
    resilience: &RuntimeResilience,
) -> Result<RequestValidationResult, (http::StatusCode, &'static [u8], bool)> {
    validate_http_request_parts(req.method(), req.uri(), req.headers(), resilience)
}

pub(crate) fn validate_http_request_parts(
    method: &http::Method,
    uri: &http::Uri,
    headers: &http::HeaderMap,
    resilience: &RuntimeResilience,
) -> Result<RequestValidationResult, (http::StatusCode, &'static [u8], bool)> {
    let header_count = headers.len().saturating_add(2);
    if header_count > resilience.max_headers_count {
        return Err((
            http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            b"too many request headers\n",
            false,
        ));
    }

    let mut header_bytes = method.as_str().len() + uri.path().len();
    let authority = uri.authority().map(|a| a.as_str().to_owned());
    let host = headers
        .get(http::header::HOST)
        .map(|v| {
            v.to_str().map(str::to_owned).map_err(|_| {
                (
                    http::StatusCode::BAD_REQUEST,
                    b"invalid host header\n" as &'static [u8],
                    false,
                )
            })
        })
        .transpose()?;

    if let Some(authority_value) = authority.as_deref() {
        header_bytes = header_bytes.saturating_add(authority_value.len());
    }
    if let Some(host_value) = host.as_deref() {
        header_bytes =
            header_bytes.saturating_add(http::header::HOST.as_str().len() + host_value.len());
    }

    for (name, value) in headers {
        header_bytes = header_bytes.saturating_add(name.as_str().len() + value.as_bytes().len());
        if header_bytes > resilience.max_headers_bytes {
            return Err((
                http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                b"request headers exceed size limit\n",
                false,
            ));
        }
    }

    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let content_length = parse_http_content_length(headers)?;

    validate_request_parts(
        method.as_str().to_string(),
        path.to_string(),
        authority,
        host,
        content_length,
        false,
        resilience,
        RequestPartErrors {
            invalid_method: b"invalid method header\n",
            invalid_path: b"invalid path header\n",
            invalid_authority: b"invalid authority\n",
            invalid_host: b"invalid host header\n",
            authority_mismatch: b"authority and host headers must match\n",
            connect_path_not_allowed: b"invalid CONNECT path\n",
            connect_authority_required: b"CONNECT requires authority host:port\n",
        },
    )
}

fn strict_header_value(
    value: &[u8],
    invalid_error: &'static [u8],
) -> Result<String, (http::StatusCode, &'static [u8], bool)> {
    std::str::from_utf8(value)
        .map(str::to_owned)
        .map_err(|_| (http::StatusCode::BAD_REQUEST, invalid_error, false))
}

fn parse_authority_value(value: &str) -> Option<NormalizedAuthority> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed != value
        || trimmed.contains('@')
        || trimmed.chars().any(char::is_whitespace)
    {
        return None;
    }

    let parsed: http::uri::Authority = trimmed.parse().ok()?;
    let host = parsed.host().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }

    Some(NormalizedAuthority {
        original: trimmed.to_string(),
        host,
        port: parsed.port_u16(),
    })
}

fn authorities_match(authority: &NormalizedAuthority, host: &NormalizedAuthority) -> bool {
    authority.host == host.host
        && match (authority.port, host.port) {
            (Some(left), Some(right)) => left == right,
            _ => true,
        }
}

struct RequestPartErrors {
    invalid_method: &'static [u8],
    invalid_path: &'static [u8],
    invalid_authority: &'static [u8],
    invalid_host: &'static [u8],
    authority_mismatch: &'static [u8],
    connect_path_not_allowed: &'static [u8],
    connect_authority_required: &'static [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedAuthority {
    original: String,
    host: String,
    port: Option<u16>,
}

#[allow(clippy::too_many_arguments)]
fn validate_request_parts(
    method: String,
    path: String,
    authority: Option<String>,
    host: Option<String>,
    content_length: Option<usize>,
    websocket_tunnel: bool,
    resilience: &RuntimeResilience,
    errors: RequestPartErrors,
) -> Result<RequestValidationResult, (http::StatusCode, &'static [u8], bool)> {
    let is_connect = method.eq_ignore_ascii_case("CONNECT");
    if method.trim().is_empty() || method.as_bytes().iter().any(|b| b.is_ascii_whitespace()) {
        return Err((http::StatusCode::BAD_REQUEST, errors.invalid_method, false));
    }

    if request_path_is_ambiguous(&path) {
        return Err((
            http::StatusCode::BAD_REQUEST,
            b"ambiguous request path\n",
            false,
        ));
    }
    let path = canonical_request_target(&path);

    if is_connect {
        if websocket_tunnel {
            if path.is_empty() || !path.starts_with('/') {
                return Err((http::StatusCode::BAD_REQUEST, errors.invalid_path, false));
            }
        } else if !path.is_empty() && path != "/" {
            return Err((
                http::StatusCode::BAD_REQUEST,
                errors.connect_path_not_allowed,
                false,
            ));
        }
    } else if path.is_empty() || !path.starts_with('/') {
        return Err((http::StatusCode::BAD_REQUEST, errors.invalid_path, false));
    }

    let parsed_authority = match authority.as_deref() {
        Some(value) => Some(parse_authority_value(value).ok_or((
            http::StatusCode::BAD_REQUEST,
            errors.invalid_authority,
            false,
        ))?),
        None => None,
    };
    let parsed_host = match host.as_deref() {
        Some(value) => Some(parse_authority_value(value).ok_or((
            http::StatusCode::BAD_REQUEST,
            errors.invalid_host,
            false,
        ))?),
        None => None,
    };

    if resilience.enforce_authority_host_match
        && let (Some(authority_value), Some(host_value)) =
            (parsed_authority.as_ref(), parsed_host.as_ref())
        && !authorities_match(authority_value, host_value)
    {
        return Err((
            http::StatusCode::BAD_REQUEST,
            errors.authority_mismatch,
            false,
        ));
    }

    if !resilience.method_allowed(&method) {
        return Err((
            http::StatusCode::METHOD_NOT_ALLOWED,
            b"request method blocked by policy\n",
            true,
        ));
    }

    if is_connect {
        let connect_authority = parsed_authority.as_ref().or(parsed_host.as_ref()).ok_or((
            http::StatusCode::BAD_REQUEST,
            errors.connect_authority_required,
            false,
        ))?;
        if connect_authority.port.is_none() {
            return Err((
                http::StatusCode::BAD_REQUEST,
                errors.connect_authority_required,
                false,
            ));
        }
        if !resilience.connect_allowed(&connect_authority.original) {
            return Err((
                http::StatusCode::FORBIDDEN,
                b"CONNECT target denied by policy\n",
                true,
            ));
        }
    }

    // Extended CONNECT carries a routable request path for WebSocket tunnels,
    // so it must be subject to the same path policy as ordinary requests.
    if (!is_connect || websocket_tunnel) && resilience.path_denied(&path) {
        return Err((
            http::StatusCode::FORBIDDEN,
            b"request path blocked by policy\n",
            true,
        ));
    }

    Ok(RequestValidationResult {
        method,
        path,
        authority: authority.or(host),
        content_length,
        websocket_tunnel,
    })
}

fn parse_content_length_value(raw: &[u8]) -> Option<usize> {
    let value = std::str::from_utf8(raw).ok()?.trim();
    if value.is_empty() || !value.as_bytes().iter().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<usize>().ok()
}

fn merge_content_length(
    current: &mut Option<usize>,
    next: usize,
) -> Result<(), (http::StatusCode, &'static [u8], bool)> {
    match *current {
        None => {
            *current = Some(next);
            Ok(())
        }
        Some(existing) if existing == next => Ok(()),
        Some(_) => Err((
            http::StatusCode::BAD_REQUEST,
            b"conflicting content-length header\n",
            false,
        )),
    }
}

const INVALID_CONTENT_LENGTH_ERROR: (http::StatusCode, &[u8], bool) = (
    http::StatusCode::BAD_REQUEST,
    b"invalid content-length header\n",
    false,
);

fn parse_h3_content_length(
    headers: &[quiche::h3::Header],
) -> Result<Option<usize>, (http::StatusCode, &'static [u8], bool)> {
    let mut content_length = None;
    for header in headers {
        if !header.name().eq_ignore_ascii_case(b"content-length") {
            continue;
        }
        let parsed =
            parse_content_length_value(header.value()).ok_or(INVALID_CONTENT_LENGTH_ERROR)?;
        merge_content_length(&mut content_length, parsed)?;
    }
    Ok(content_length)
}

fn parse_http_content_length(
    headers: &http::HeaderMap,
) -> Result<Option<usize>, (http::StatusCode, &'static [u8], bool)> {
    let mut content_length = None;
    for value in headers.get_all(http::header::CONTENT_LENGTH) {
        let parsed =
            parse_content_length_value(value.as_bytes()).ok_or(INVALID_CONTENT_LENGTH_ERROR)?;
        merge_content_length(&mut content_length, parsed)?;
    }
    Ok(content_length)
}

pub(super) fn extract_header_value<'a>(
    headers: &'a [quiche::h3::Header],
    name: &[u8],
) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name().eq_ignore_ascii_case(name))
        .and_then(|header| std::str::from_utf8(header.value()).ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub(super) fn parse_traceparent(value: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = value.split('-').collect();
    if parts.len() != 4 || parts[0] != "00" {
        return None;
    }
    let trace_id = parts[1];
    let parent_span_id = parts[2];
    let flags = parts[3];

    let trace_valid = trace_id.len() == 32
        && trace_id.chars().all(|c| c.is_ascii_hexdigit())
        && trace_id != "00000000000000000000000000000000";
    let span_valid = parent_span_id.len() == 16
        && parent_span_id.chars().all(|c| c.is_ascii_hexdigit())
        && parent_span_id != "0000000000000000";
    let flags_valid = flags.len() == 2 && flags.chars().all(|c| c.is_ascii_hexdigit());

    if !(trace_valid && span_valid && flags_valid) {
        return None;
    }

    Some((
        trace_id.to_ascii_lowercase(),
        parent_span_id.to_ascii_lowercase(),
    ))
}

pub(super) fn generated_trace_id(conn_trace_id: &str, request_id: u64) -> String {
    let mut seed = conn_trace_id.as_bytes().to_vec();
    seed.extend_from_slice(&request_id.to_be_bytes());
    let lo = crate::stable_hash64(&seed);
    seed.extend_from_slice(b"trace-hi");
    let hi = crate::stable_hash64(&seed);
    format!("{hi:016x}{lo:016x}")
}

pub(super) fn generated_span_id(request_id: u64) -> String {
    format!("{:016x}", crate::stable_hash64(&request_id.to_be_bytes()))
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
