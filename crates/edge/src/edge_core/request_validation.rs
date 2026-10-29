use crate::{
    resilience::runtime::RuntimeResilience,
    routing::util::{canonical_request_target, request_path_is_ambiguous},
};

pub(crate) type RequestValidationError = (http::StatusCode, &'static [u8], bool);

#[derive(Debug)]
pub(crate) struct RequestValidationResult {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) authority: Option<String>,
    pub(crate) content_length: Option<usize>,
    pub(crate) websocket_tunnel: bool,
}

pub(crate) struct RequestPartErrors {
    pub(crate) invalid_method: &'static [u8],
    pub(crate) invalid_path: &'static [u8],
    pub(crate) invalid_authority: &'static [u8],
    pub(crate) invalid_host: &'static [u8],
    pub(crate) authority_mismatch: &'static [u8],
    pub(crate) connect_path_not_allowed: &'static [u8],
    pub(crate) connect_authority_required: &'static [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedAuthority {
    original: String,
    host: String,
    port: Option<u16>,
}

pub(crate) fn validate_http_request_parts(
    method: &http::Method,
    uri: &http::Uri,
    headers: &http::HeaderMap,
    resilience: &RuntimeResilience,
) -> Result<RequestValidationResult, RequestValidationError> {
    let header_count = headers.len().saturating_add(2);
    if header_count > resilience.max_headers_count {
        return Err((
            http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            b"too many request headers\n",
            false,
        ));
    }

    let mut header_bytes = method.as_str().len() + uri.path().len();
    let authority = uri.authority().map(|value| value.as_str().to_owned());
    let host = headers
        .get(http::header::HOST)
        .map(|value| {
            value.to_str().map(str::to_owned).map_err(|_| {
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

    let path = uri.path_and_query().map_or("/", |value| value.as_str());
    let content_length = parse_content_length_values(
        headers
            .get_all(http::header::CONTENT_LENGTH)
            .iter()
            .map(http::HeaderValue::as_bytes),
    )?;

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

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_request_parts(
    method: String,
    path: String,
    authority: Option<String>,
    host: Option<String>,
    content_length: Option<usize>,
    websocket_tunnel: bool,
    resilience: &RuntimeResilience,
    errors: RequestPartErrors,
) -> Result<RequestValidationResult, RequestValidationError> {
    let is_connect = method.eq_ignore_ascii_case("CONNECT");
    if method.trim().is_empty()
        || method
            .as_bytes()
            .iter()
            .any(|byte| byte.is_ascii_whitespace())
    {
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

pub(crate) fn parse_content_length_values<'a>(
    values: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Option<usize>, RequestValidationError> {
    let mut content_length = None;
    for raw in values {
        let value = std::str::from_utf8(raw).ok().map(str::trim);
        let parsed = value
            .filter(|value| !value.is_empty() && value.as_bytes().iter().all(u8::is_ascii_digit))
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or((
                http::StatusCode::BAD_REQUEST,
                b"invalid content-length header\n" as &'static [u8],
                false,
            ))?;
        match content_length {
            None => content_length = Some(parsed),
            Some(existing) if existing == parsed => {}
            Some(_) => {
                return Err((
                    http::StatusCode::BAD_REQUEST,
                    b"conflicting content-length header\n",
                    false,
                ));
            }
        }
    }
    Ok(content_length)
}
