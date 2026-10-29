use http::{HeaderMap, HeaderValue, StatusCode, header};
use impulse_config::runtime::RuntimeResponseCompressionPolicy;
pub use impulse_observability::{ResponseCompressionAction, ResponseCompressionBypassReason};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseCompressionEvaluation {
    pub action: ResponseCompressionAction,
    pub vary_accept_encoding: bool,
}

pub struct ResponseCompressionInput<'a> {
    pub policy: &'a RuntimeResponseCompressionPolicy,
    pub request_method: &'a str,
    pub request_headers: &'a HeaderMap,
    pub response_status: StatusCode,
    pub response_headers: &'a HeaderMap,
}

pub fn evaluate_response_compression(
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

pub fn apply_gzip_response_headers(headers: &mut HeaderMap) {
    headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    headers.remove(header::CONTENT_LENGTH);
    headers.remove(header::ACCEPT_RANGES);
    ensure_vary_accept_encoding(headers);

    let Some(etag) = headers.get(header::ETAG).cloned() else {
        return;
    };
    if etag.as_bytes().starts_with(b"W/") {
        return;
    }
    if etag.as_bytes().starts_with(b"\"") {
        let mut weak = Vec::with_capacity(etag.as_bytes().len() + 2);
        weak.extend_from_slice(b"W/");
        weak.extend_from_slice(etag.as_bytes());
        if let Ok(weak) = HeaderValue::from_bytes(&weak) {
            headers.insert(header::ETAG, weak);
            return;
        }
    }
    headers.remove(header::ETAG);
}

pub fn ensure_vary_accept_encoding(headers: &mut HeaderMap) {
    if header_contains_token(headers, header::VARY, "*")
        || header_contains_token(headers, header::VARY, "accept-encoding")
    {
        return;
    }
    headers.append(header::VARY, HeaderValue::from_static("accept-encoding"));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> RuntimeResponseCompressionPolicy {
        RuntimeResponseCompressionPolicy {
            enabled: true,
            minimum_size_bytes: 64,
        }
    }

    fn response_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("128"));
        headers
    }

    fn evaluate(
        method: &str,
        request_headers: &HeaderMap,
        status: StatusCode,
        response_headers: &HeaderMap,
    ) -> ResponseCompressionEvaluation {
        evaluate_response_compression(ResponseCompressionInput {
            policy: &policy(),
            request_method: method,
            request_headers,
            response_status: status,
            response_headers,
        })
    }

    #[test]
    fn gzip_negotiation_honors_quality_and_wildcards() {
        let response_headers = response_headers();
        for (value, expected) in [
            ("gzip", ResponseCompressionAction::Gzip),
            ("br, *;q=0.5", ResponseCompressionAction::Gzip),
            (
                "gzip;q=0, *;q=1",
                ResponseCompressionAction::Bypass(ResponseCompressionBypassReason::NotAccepted),
            ),
            (
                "br",
                ResponseCompressionAction::Bypass(ResponseCompressionBypassReason::NotAccepted),
            ),
        ] {
            let mut request_headers = HeaderMap::new();
            request_headers.insert(
                header::ACCEPT_ENCODING,
                HeaderValue::from_str(value).expect("accept-encoding"),
            );
            let evaluated = evaluate("GET", &request_headers, StatusCode::OK, &response_headers);
            assert_eq!(evaluated.action, expected, "{value}");
            assert!(evaluated.vary_accept_encoding);
        }
    }

    #[test]
    fn bodyless_range_and_preencoded_responses_bypass_compression() {
        let accepted =
            HeaderMap::from_iter([(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"))]);

        assert_eq!(
            evaluate("HEAD", &accepted, StatusCode::OK, &response_headers()).action,
            ResponseCompressionAction::Bypass(ResponseCompressionBypassReason::Bodyless)
        );
        assert_eq!(
            evaluate(
                "GET",
                &accepted,
                StatusCode::NO_CONTENT,
                &response_headers(),
            )
            .action,
            ResponseCompressionAction::Bypass(ResponseCompressionBypassReason::Bodyless)
        );

        let mut range = accepted.clone();
        range.insert(header::RANGE, HeaderValue::from_static("bytes=0-15"));
        assert_eq!(
            evaluate("GET", &range, StatusCode::OK, &response_headers()).action,
            ResponseCompressionAction::Bypass(ResponseCompressionBypassReason::Range)
        );

        let mut preencoded = response_headers();
        preencoded.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert_eq!(
            evaluate("GET", &accepted, StatusCode::OK, &preencoded).action,
            ResponseCompressionAction::Bypass(ResponseCompressionBypassReason::ExistingEncoding)
        );
    }
}
