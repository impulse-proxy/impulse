//! Canonical request-builder input contracts shared across h1 and h2 outputs.

use http::{
    HeaderMap, HeaderValue,
    header::{CONTENT_LENGTH, HOST},
};
use impulse_bridge::http3::{
    RequestBodyMode, RequestBuildInput, build_h1_request, build_h2_request_for_target,
};
use impulse_config::{
    backend_endpoint::BackendEndpoint,
    config::{ForwardedHeaderPolicy, UpstreamHostPolicy},
};
use quiche::h3::{Header, NameValue};

use crate::common::{
    RequestInputMeta, borrowed_request_input, build_h1_and_h2_requests, request_input,
    request_input_with_body_mode, request_target,
};

#[test]
fn canonical_headers_match_for_translated_http3_and_borrowed_pingora_inputs() {
    let endpoint = BackendEndpoint::parse("backend.internal:443").expect("endpoint");
    let host_policy = UpstreamHostPolicy::default();
    let forwarded_policy = ForwardedHeaderPolicy::default();
    let h3_headers = vec![
        Header::new(b"host", b"spoofed.example.com"),
        Header::new(b"connection", b"keep-alive, x-secret"),
        Header::new(b"x-secret", b"drop-me"),
        Header::new(b"x-keep", b"first"),
        Header::new(b"x-keep", b"second"),
        Header::new(b"x-forwarded-for", b"192.0.2.1"),
    ];
    let mut native_headers = HeaderMap::new();
    for header in &h3_headers {
        native_headers.append(
            http::HeaderName::from_bytes(header.name()).expect("header name"),
            HeaderValue::from_bytes(header.value()).expect("header value"),
        );
    }
    let meta = RequestInputMeta {
        authority: Some("api.example.com"),
        content_length: None,
        request_id: 92,
        traceparent: None,
        client_addr: "203.0.113.22:7002".parse().expect("client"),
    };

    let h1_from_h3 = build_h1_request(
        request_target(&endpoint, &host_policy, &forwarded_policy),
        request_input("GET", "/headers", &h3_headers, meta),
    )
    .expect("h1 request from HTTP/3 headers");
    let h1_from_pingora = build_h1_request(
        request_target(&endpoint, &host_policy, &forwarded_policy),
        borrowed_request_input("GET", "/headers", &native_headers, meta),
    )
    .expect("h1 request from Pingora headers");
    let h2_from_h3 = build_h2_request_for_target(
        request_target(&endpoint, &host_policy, &forwarded_policy),
        request_input("GET", "/headers", &h3_headers, meta),
    )
    .expect("h2 request from HTTP/3 headers");
    let h2_from_pingora = build_h2_request_for_target(
        request_target(&endpoint, &host_policy, &forwarded_policy),
        borrowed_request_input("GET", "/headers", &native_headers, meta),
    )
    .expect("h2 request from Pingora headers");

    assert_eq!(h1_from_h3.headers(), h1_from_pingora.headers());
    assert_eq!(h2_from_h3.headers(), h2_from_pingora.headers());
    for request in [&h1_from_h3, &h1_from_pingora, &h2_from_h3, &h2_from_pingora] {
        assert!(request.headers().get("connection").is_none());
        assert!(request.headers().get("x-secret").is_none());
        assert_eq!(request.headers().get_all("x-keep").iter().count(), 2);
        assert_eq!(
            request
                .headers()
                .get(HOST)
                .and_then(|value| value.to_str().ok()),
            Some("api.example.com")
        );
        assert_eq!(
            request
                .headers()
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok()),
            Some("203.0.113.22")
        );
    }
}

#[test]
fn canonical_known_length_inputs_shape_h1_and_h2_requests_consistently() {
    let endpoint = BackendEndpoint::parse("payments.internal:443").expect("endpoint");
    let headers = vec![
        Header::new(b"host", b"spoofed.example.com"),
        Header::new(b"x-custom", b"ok"),
    ];

    let (h1, h2) = build_h1_and_h2_requests(
        &endpoint,
        &UpstreamHostPolicy::default(),
        &ForwardedHeaderPolicy::default(),
        "POST",
        "/v1/payments",
        &headers,
        RequestInputMeta {
            authority: Some("api.example.com"),
            content_length: Some(16),
            request_id: 77,
            traceparent: Some("00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"),
            client_addr: "198.51.100.44:7000".parse().expect("client"),
        },
    )
    .expect("requests");

    assert_eq!(h1.method(), http::Method::POST);
    assert_eq!(h2.method(), http::Method::POST);
    assert_eq!(
        h1.uri().to_string(),
        "https://payments.internal:443/v1/payments"
    );
    assert_eq!(h1.uri(), h2.uri());

    for name in [
        HOST.as_str(),
        CONTENT_LENGTH.as_str(),
        "x-custom",
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-forwarded-host",
        "forwarded",
        "x-request-id",
        "traceparent",
    ] {
        assert_eq!(
            h1.headers().get(name).and_then(|value| value.to_str().ok()),
            h2.headers().get(name).and_then(|value| value.to_str().ok()),
            "canonical request contract mismatch for header {name}"
        );
    }

    assert_eq!(
        h1.headers().get(HOST).and_then(|value| value.to_str().ok()),
        Some("api.example.com")
    );
    assert_eq!(
        h1.headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok()),
        Some("16")
    );
    assert_eq!(
        h1.headers()
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok()),
        Some("198.51.100.44")
    );
    assert_eq!(
        h1.headers()
            .get("traceparent")
            .and_then(|value| value.to_str().ok()),
        Some("00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01")
    );
    assert_eq!(h1.headers().get_all("x-custom").iter().count(), 1);
    assert_eq!(h2.headers().get_all("x-custom").iter().count(), 1);
}

#[test]
fn passthrough_headers_are_not_duplicated_in_h1_or_h2() {
    let endpoint = BackendEndpoint::parse("payments.internal:443").expect("endpoint");
    let headers = vec![
        Header::new(b"authorization", b"Bearer token"),
        Header::new(b"cookie", b"session=abc"),
        Header::new(b"x-custom-auth", b"opaque"),
    ];

    let (h1, h2) = build_h1_and_h2_requests(
        &endpoint,
        &UpstreamHostPolicy::default(),
        &ForwardedHeaderPolicy::default(),
        "GET",
        "/v1/payments",
        &headers,
        RequestInputMeta {
            authority: Some("api.example.com"),
            content_length: None,
            request_id: 78,
            traceparent: None,
            client_addr: "198.51.100.44:7000".parse().expect("client"),
        },
    )
    .expect("requests");

    for req in [&h1, &h2] {
        assert_eq!(req.headers().get_all("authorization").iter().count(), 1);
        assert_eq!(req.headers().get_all("cookie").iter().count(), 1);
        assert_eq!(req.headers().get_all("x-custom-auth").iter().count(), 1);
    }
}

#[test]
fn canonical_streaming_inputs_preserve_authority_and_forwarded_context_without_content_length() {
    let endpoint = BackendEndpoint::parse("stream.internal:8443").expect("endpoint");

    let (h1, h2) = build_h1_and_h2_requests(
        &endpoint,
        &UpstreamHostPolicy::default(),
        &ForwardedHeaderPolicy::default(),
        "PATCH",
        "/streams/live",
        &[],
        RequestInputMeta {
            authority: Some("stream.example.com"),
            content_length: None,
            request_id: 88,
            traceparent: None,
            client_addr: "203.0.113.9:9443".parse().expect("client"),
        },
    )
    .expect("requests");

    assert_eq!(
        h1.headers().get(HOST).and_then(|value| value.to_str().ok()),
        Some("stream.example.com")
    );
    assert_eq!(
        h2.headers().get(HOST).and_then(|value| value.to_str().ok()),
        Some("stream.example.com")
    );
    assert!(h1.headers().get(CONTENT_LENGTH).is_none());
    assert!(h2.headers().get(CONTENT_LENGTH).is_none());
    assert_eq!(
        h1.headers()
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok()),
        Some("203.0.113.9")
    );
    assert_eq!(
        h1.headers()
            .get("forwarded")
            .and_then(|value| value.to_str().ok()),
        Some("for=203.0.113.9;proto=https;host=\"stream.example.com\"")
    );
    assert_eq!(
        h1.headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
        Some("88")
    );
    assert!(h1.headers().get("traceparent").is_none());
    assert!(h2.headers().get("traceparent").is_none());
}

#[test]
fn canonical_empty_body_inputs_do_not_emit_content_length_for_h1_or_h2() {
    let endpoint = BackendEndpoint::parse("backend.internal:443").expect("endpoint");
    let host_policy = UpstreamHostPolicy::default();
    let forwarded_header_policy = ForwardedHeaderPolicy::default();
    let meta = RequestInputMeta {
        authority: None,
        content_length: Some(0),
        request_id: 91,
        traceparent: None,
        client_addr: "203.0.113.20:7001".parse().expect("client"),
    };

    let h1 = impulse_bridge::http3::build_h1_request(
        request_target(&endpoint, &host_policy, &forwarded_header_policy),
        request_input_with_body_mode("GET", "", &[], meta, RequestBodyMode::Empty),
    )
    .expect("h1 request");
    let h2 = build_h2_request_for_target(
        request_target(&endpoint, &host_policy, &forwarded_header_policy),
        request_input_with_body_mode("GET", "", &[], meta, RequestBodyMode::Empty),
    )
    .expect("h2 request");

    assert_eq!(h1.uri().to_string(), "https://backend.internal:443/");
    assert_eq!(h1.uri(), h2.uri());
    assert_eq!(
        h1.headers().get(HOST).and_then(|value| value.to_str().ok()),
        Some("backend.internal:443")
    );
    assert_eq!(
        h2.headers().get(HOST).and_then(|value| value.to_str().ok()),
        Some("backend.internal:443")
    );
    assert!(h1.headers().get(CONTENT_LENGTH).is_none());
    assert!(h2.headers().get(CONTENT_LENGTH).is_none());
}

#[test]
fn request_body_mode_helper_maps_lengths_to_canonical_modes() {
    assert_eq!(
        RequestBuildInput::<
            http_body_util::combinators::BoxBody<bytes::Bytes, std::convert::Infallible>,
        >::body_mode_for_length(Some(0)),
        RequestBodyMode::Empty
    );
    assert_eq!(
        RequestBuildInput::<
            http_body_util::combinators::BoxBody<bytes::Bytes, std::convert::Infallible>,
        >::body_mode_for_length(Some(12)),
        RequestBodyMode::KnownLength(12)
    );
    assert_eq!(
        RequestBuildInput::<
            http_body_util::combinators::BoxBody<bytes::Bytes, std::convert::Infallible>,
        >::body_mode_for_length(None),
        RequestBodyMode::Streaming
    );
}
