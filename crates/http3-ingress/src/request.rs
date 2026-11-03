use quiche::h3::NameValue;

#[derive(Clone, Copy, Debug)]
pub struct Http3RequestLimits {
    pub max_headers_count: usize,
    pub max_headers_bytes: usize,
}

#[derive(Debug)]
pub struct Http3RequestHead {
    pub method: String,
    pub path: String,
    pub authority: Option<String>,
    pub host: Option<String>,
    pub content_length: Option<usize>,
    pub websocket_tunnel: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3RequestParseError {
    pub status: http::StatusCode,
    pub body: &'static [u8],
}

pub fn parse_request_head(
    headers: &[quiche::h3::Header],
    limits: Http3RequestLimits,
) -> Result<Http3RequestHead, Http3RequestParseError> {
    if headers.len() > limits.max_headers_count {
        return Err(parse_error(
            http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            b"too many request headers\n",
        ));
    }

    let mut header_bytes = 0usize;
    let mut method = None;
    let mut path = None;
    let mut authority = None;
    let mut host = None;
    let mut scheme = None;
    let mut protocol = None;
    let mut upgrade_requested = false;

    for header in headers {
        header_bytes = header_bytes.saturating_add(header.name().len() + header.value().len());
        if header_bytes > limits.max_headers_bytes {
            return Err(parse_error(
                http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                b"request headers exceed size limit\n",
            ));
        }
        match header.name() {
            b":method" => set_once(
                &mut method,
                header.value(),
                b"duplicate :method header\n",
                b"invalid :method header\n",
            )?,
            b":path" => set_once(
                &mut path,
                header.value(),
                b"duplicate :path header\n",
                b"invalid :path header\n",
            )?,
            b":authority" => set_once(
                &mut authority,
                header.value(),
                b"duplicate :authority header\n",
                b"invalid :authority header\n",
            )?,
            b"host" => set_once(
                &mut host,
                header.value(),
                b"duplicate host header\n",
                b"invalid host header\n",
            )?,
            b":scheme" => {
                set_once(
                    &mut scheme,
                    header.value(),
                    b"duplicate :scheme header\n",
                    b"invalid :scheme header\n",
                )?;
                if !scheme.as_deref().is_some_and(|value| {
                    value.eq_ignore_ascii_case("http") || value.eq_ignore_ascii_case("https")
                }) {
                    return Err(parse_error(
                        http::StatusCode::BAD_REQUEST,
                        b"invalid :scheme header\n",
                    ));
                }
            }
            b":protocol" => set_once(
                &mut protocol,
                header.value(),
                b"duplicate :protocol header\n",
                b"invalid :protocol header\n",
            )?,
            b"connection" => {
                let value = strict_header_value(header.value(), b"invalid connection header\n")?;
                upgrade_requested |= value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("upgrade"));
            }
            b"upgrade" => {
                strict_header_value(header.value(), b"invalid upgrade header\n")?;
                upgrade_requested = true;
            }
            name if name.starts_with(b":") => {
                return Err(parse_error(
                    http::StatusCode::BAD_REQUEST,
                    b"unsupported pseudo-header\n",
                ));
            }
            _ => {}
        }
    }

    let content_length = parse_content_length(headers)?;
    let method = method
        .ok_or_else(|| parse_error(http::StatusCode::BAD_REQUEST, b"missing :method header\n"))?;
    let websocket_tunnel = method.eq_ignore_ascii_case("CONNECT")
        && protocol
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    if protocol.is_some() && !websocket_tunnel {
        return Err(parse_error(
            http::StatusCode::BAD_REQUEST,
            b"unsupported pseudo-header\n",
        ));
    }
    if upgrade_requested {
        return Err(parse_error(
            http::StatusCode::BAD_REQUEST,
            b"HTTP/3 does not support Upgrade requests\n",
        ));
    }

    let is_connect = method.eq_ignore_ascii_case("CONNECT");
    match (is_connect, websocket_tunnel, scheme.is_some()) {
        (false, _, false) | (true, true, false) => {
            return Err(parse_error(
                http::StatusCode::BAD_REQUEST,
                b"missing :scheme header\n",
            ));
        }
        (true, false, true) => {
            return Err(parse_error(
                http::StatusCode::BAD_REQUEST,
                b"invalid CONNECT :scheme header\n",
            ));
        }
        _ => {}
    }
    let path = match (is_connect, websocket_tunnel, path) {
        (true, true, Some(path)) => path,
        (true, true, None) => {
            return Err(parse_error(
                http::StatusCode::BAD_REQUEST,
                b"missing :path header\n",
            ));
        }
        (true, false, Some(_)) => {
            return Err(parse_error(
                http::StatusCode::BAD_REQUEST,
                b"invalid CONNECT :path header\n",
            ));
        }
        (true, false, None) => "/".to_string(),
        (false, _, Some(path)) => path,
        (false, _, None) => {
            return Err(parse_error(
                http::StatusCode::BAD_REQUEST,
                b"missing :path header\n",
            ));
        }
    };

    Ok(Http3RequestHead {
        method,
        path,
        authority,
        host,
        content_length,
        websocket_tunnel,
    })
}

fn set_once(
    target: &mut Option<String>,
    value: &[u8],
    duplicate_error: &'static [u8],
    invalid_error: &'static [u8],
) -> Result<(), Http3RequestParseError> {
    if target.is_some() {
        return Err(parse_error(http::StatusCode::BAD_REQUEST, duplicate_error));
    }
    *target = Some(strict_header_value(value, invalid_error)?);
    Ok(())
}

fn strict_header_value(
    value: &[u8],
    invalid_error: &'static [u8],
) -> Result<String, Http3RequestParseError> {
    std::str::from_utf8(value)
        .map(str::to_owned)
        .map_err(|_| parse_error(http::StatusCode::BAD_REQUEST, invalid_error))
}

fn parse_content_length(
    headers: &[quiche::h3::Header],
) -> Result<Option<usize>, Http3RequestParseError> {
    let mut content_length = None;
    for raw in headers
        .iter()
        .filter(|header| header.name().eq_ignore_ascii_case(b"content-length"))
        .map(quiche::h3::Header::value)
    {
        let parsed = std::str::from_utf8(raw)
            .ok()
            .map(str::trim)
            .filter(|value| !value.is_empty() && value.as_bytes().iter().all(u8::is_ascii_digit))
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or_else(|| {
                parse_error(
                    http::StatusCode::BAD_REQUEST,
                    b"invalid content-length header\n",
                )
            })?;
        match content_length {
            None => content_length = Some(parsed),
            Some(existing) if existing == parsed => {}
            Some(_) => {
                return Err(parse_error(
                    http::StatusCode::BAD_REQUEST,
                    b"conflicting content-length header\n",
                ));
            }
        }
    }
    Ok(content_length)
}

fn parse_error(status: http::StatusCode, body: &'static [u8]) -> Http3RequestParseError {
    Http3RequestParseError { status, body }
}

pub fn extract_header_value<'a>(headers: &'a [quiche::h3::Header], name: &[u8]) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name().eq_ignore_ascii_case(name))
        .and_then(|header| std::str::from_utf8(header.value()).ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub fn parse_traceparent(value: &str) -> Option<(String, String)> {
    let mut parts = value.split('-');
    let version = parts.next()?;
    let trace_id = parts.next()?;
    let parent_span_id = parts.next()?;
    let flags = parts.next()?;
    if parts.next().is_some() || version != "00" {
        return None;
    }
    let trace_valid = trace_id.len() == 32
        && trace_id
            .chars()
            .all(|character| character.is_ascii_hexdigit())
        && trace_id != "00000000000000000000000000000000";
    let span_valid = parent_span_id.len() == 16
        && parent_span_id
            .chars()
            .all(|character| character.is_ascii_hexdigit())
        && parent_span_id != "0000000000000000";
    let flags_valid =
        flags.len() == 2 && flags.chars().all(|character| character.is_ascii_hexdigit());
    (trace_valid && span_valid && flags_valid).then(|| {
        (
            trace_id.to_ascii_lowercase(),
            parent_span_id.to_ascii_lowercase(),
        )
    })
}

pub fn generated_trace_id(connection_trace_id: &str, request_id: u64) -> String {
    let mut seed = connection_trace_id.as_bytes().to_vec();
    seed.extend_from_slice(&request_id.to_be_bytes());
    let low = stable_hash64(&seed);
    seed.extend_from_slice(b"trace-hi");
    let high = stable_hash64(&seed);
    format!("{high:016x}{low:016x}")
}

pub fn generated_span_id(request_id: u64) -> String {
    format!("{:016x}", stable_hash64(&request_id.to_be_bytes()))
}

fn stable_hash64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}
