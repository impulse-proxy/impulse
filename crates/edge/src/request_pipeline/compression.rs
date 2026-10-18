use http::{HeaderMap, HeaderValue, StatusCode, header};
use impulse_config::runtime::RuntimeResponseCompressionPolicy;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseCompressionAction {
    Gzip,
    Bypass(ResponseCompressionBypassReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseCompressionBypassReason {
    Disabled,
    Bodyless,
    Status,
    ExistingEncoding,
    NoTransform,
    Range,
    ContentType,
    UnknownLength,
    BelowMinimumSize,
    NotAccepted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResponseCompressionEvaluation {
    pub(crate) action: ResponseCompressionAction,
    pub(crate) vary_accept_encoding: bool,
}

pub(crate) struct ResponseCompressionInput<'a> {
    pub(crate) policy: &'a RuntimeResponseCompressionPolicy,
    pub(crate) request_method: &'a str,
    pub(crate) request_headers: &'a HeaderMap,
    pub(crate) response_status: StatusCode,
    pub(crate) response_headers: &'a HeaderMap,
}

pub(crate) fn evaluate_response_compression(
    input: ResponseCompressionInput<'_>,
) -> ResponseCompressionEvaluation {
    let bypass = |reason| ResponseCompressionEvaluation {
        action: ResponseCompressionAction::Bypass(reason),
        vary_accept_encoding: false,
    };
    let policy = input.policy;
    if !policy.enabled {
        return bypass(ResponseCompressionBypassReason::Disabled);
    }
    if input.request_method.eq_ignore_ascii_case("HEAD")
        || input.request_method.eq_ignore_ascii_case("CONNECT")
        || response_status_forbids_body(input.response_status)
    {
        return bypass(ResponseCompressionBypassReason::Bodyless);
    }
    if !input.response_status.is_success() {
        return bypass(ResponseCompressionBypassReason::Status);
    }
    if input
        .response_headers
        .contains_key(header::CONTENT_ENCODING)
    {
        return bypass(ResponseCompressionBypassReason::ExistingEncoding);
    }
    if header_contains_token(
        input.response_headers,
        header::CACHE_CONTROL,
        "no-transform",
    ) {
        return bypass(ResponseCompressionBypassReason::NoTransform);
    }
    if input.response_status == StatusCode::PARTIAL_CONTENT
        || input.request_headers.contains_key(header::RANGE)
        || input.response_headers.contains_key(header::CONTENT_RANGE)
    {
        return bypass(ResponseCompressionBypassReason::Range);
    }
    if !compressible_content_type(input.response_headers) {
        return bypass(ResponseCompressionBypassReason::ContentType);
    }
    let Some(content_length) = input
        .response_headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
    else {
        return bypass(ResponseCompressionBypassReason::UnknownLength);
    };
    if content_length < policy.minimum_size_bytes {
        return bypass(ResponseCompressionBypassReason::BelowMinimumSize);
    }

    if !accepts_gzip(input.request_headers) {
        return ResponseCompressionEvaluation {
            action: ResponseCompressionAction::Bypass(ResponseCompressionBypassReason::NotAccepted),
            vary_accept_encoding: true,
        };
    }
    ResponseCompressionEvaluation {
        action: ResponseCompressionAction::Gzip,
        vary_accept_encoding: true,
    }
}

pub(crate) fn ensure_vary_accept_encoding(headers: &mut HeaderMap) {
    if header_contains_token(headers, header::VARY, "*")
        || header_contains_token(headers, header::VARY, "accept-encoding")
    {
        return;
    }
    headers.append(header::VARY, HeaderValue::from_static("Accept-Encoding"));
}

fn response_status_forbids_body(status: StatusCode) -> bool {
    status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::RESET_CONTENT
        || status == StatusCode::NOT_MODIFIED
}

fn compressible_content_type(headers: &HeaderMap) -> bool {
    let Some(content_type) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .map(str::to_ascii_lowercase)
    else {
        return false;
    };

    content_type.starts_with("text/")
        || matches!(
            content_type.as_str(),
            "application/json"
                | "application/javascript"
                | "application/x-javascript"
                | "application/xml"
                | "application/wasm"
                | "application/x-www-form-urlencoded"
                | "image/svg+xml"
        )
        || content_type.ends_with("+json")
        || content_type.ends_with("+xml")
}

fn accepts_gzip(headers: &HeaderMap) -> bool {
    let mut gzip = None;
    let mut wildcard = None;
    for value in headers.get_all(header::ACCEPT_ENCODING) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for item in value.split(',') {
            let mut parts = item.split(';');
            let coding = parts.next().unwrap_or_default().trim();
            let quality = parts
                .find_map(|parameter| {
                    let (name, value) = parameter.split_once('=')?;
                    name.trim()
                        .eq_ignore_ascii_case("q")
                        .then(|| parse_quality(value.trim()))
                })
                .unwrap_or(1.0);
            let target = if coding.eq_ignore_ascii_case("gzip") {
                &mut gzip
            } else if coding == "*" {
                &mut wildcard
            } else {
                continue;
            };
            *target = Some((*target).unwrap_or(0.0_f32).max(quality));
        }
    }
    gzip.or(wildcard).is_some_and(|quality| quality > 0.0)
}

fn parse_quality(value: &str) -> f32 {
    value
        .parse::<f32>()
        .ok()
        .filter(|quality| quality.is_finite() && (0.0..=1.0).contains(quality))
        .unwrap_or(0.0)
}

fn header_contains_token(headers: &HeaderMap, name: http::header::HeaderName, token: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
        })
    })
}
