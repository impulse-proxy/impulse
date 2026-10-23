//! h3→h2 request building: scheme, host/forwarded policy, and WebSocket handling.

use http::header::HOST;
use hyper::ext::Protocol;
use impulse_config::config::{
    ForwardedHeaderPolicy, ForwardedHeaderPolicyMode, UpstreamHostPolicy, UpstreamHostPolicyMode,
};
use impulse_errors::BridgeError;
use quiche::h3::Header;

use crate::common::{
    RequestInputMeta, build_h2_request_for_backend, build_h2_request_with_policy,
    parse_backend_endpoint,
};

#[test]
fn defaults_to_https_origin_for_host_port_backend() {
    let req = build_h2_request_for_backend(
        "backend.internal:443",
        "GET",
        "/health",
        &[],
        RequestInputMeta {
            authority: Some("api.example.com"),
            content_length: None,
            request_id: 0,
            traceparent: None,
            client_addr: "203.0.113.10:44321".parse().expect("client"),
        },
    )
    .expect("request");

    assert_eq!(req.uri().to_string(), "https://backend.internal:443/health");
    assert_eq!(
        req.headers().get(HOST).and_then(|h| h.to_str().ok()),
        Some("api.example.com")
    );
    assert_eq!(
        req.headers()
            .get("x-forwarded-proto")
            .and_then(|h| h.to_str().ok()),
        Some("https")
    );
}

#[test]
fn keeps_explicit_http_scheme() {
    let req = build_h2_request_for_backend(
        "http://127.0.0.1:8080",
        "GET",
        "/",
        &[],
        RequestInputMeta {
            authority: None,
            content_length: None,
            request_id: 0,
            traceparent: None,
            client_addr: "198.51.100.3:5555".parse().expect("client"),
        },
    )
    .expect("request");

    assert_eq!(req.uri().to_string(), "http://127.0.0.1:8080/");
    assert_eq!(
        req.headers().get(HOST).and_then(|h| h.to_str().ok()),
        Some("127.0.0.1:8080")
    );
}

#[test]
fn rejects_invalid_backend_endpoint() {
    let err = build_h2_request_for_backend(
        "https://backend.internal:443/path",
        "GET",
        "/",
        &[],
        RequestInputMeta {
            authority: None,
            content_length: None,
            request_id: 0,
            traceparent: None,
            client_addr: "127.0.0.1:12345".parse().expect("client"),
        },
    )
    .expect_err("invalid backend endpoint should fail");

    assert!(matches!(err, BridgeError::InvalidUri));
}

#[test]
fn strips_spoofed_forwarded_headers_and_normalizes() {
    let headers = vec![
        Header::new(b"x-forwarded-for", b"1.2.3.4"),
        Header::new(b"forwarded", b"for=1.2.3.4"),
        Header::new(b"x-forwarded-host", b"evil.example"),
        Header::new(b"x-forwarded-proto", b"http"),
        Header::new(b"host", b"api.example.com"),
        Header::new(b"connection", b"keep-alive, x-secret"),
        Header::new(b"x-secret", b"drop-me"),
        Header::new(b"x-keep", b"ok"),
    ];

    let req = build_h2_request_for_backend(
        "backend.internal:443",
        "GET",
        "/",
        &headers,
        RequestInputMeta {
            authority: Some("api.example.com"),
            content_length: None,
            request_id: 0,
            traceparent: None,
            client_addr: "203.0.113.55:43210".parse().expect("client"),
        },
    )
    .expect("request");

    assert_eq!(
        req.headers()
            .get("x-forwarded-for")
            .and_then(|h| h.to_str().ok()),
        Some("203.0.113.55")
    );
    assert_eq!(
        req.headers()
            .get("x-forwarded-host")
            .and_then(|h| h.to_str().ok()),
        Some("api.example.com")
    );
    assert_eq!(
        req.headers().get("forwarded").and_then(|h| h.to_str().ok()),
        Some("for=203.0.113.55;proto=https;host=\"api.example.com\"")
    );
    assert!(req.headers().get("x-secret").is_none());
    assert_eq!(
        req.headers().get("x-keep").and_then(|h| h.to_str().ok()),
        Some("ok")
    );
}

#[test]
fn forwarded_header_policy_append_and_preserve_behave_as_expected() {
    let endpoint = parse_backend_endpoint("backend.internal:443").expect("endpoint");
    let headers = vec![
        Header::new(b"forwarded", b"for=1.2.3.4;proto=http;host=\"old.example\""),
        Header::new(b"x-forwarded-for", b"1.2.3.4"),
        Header::new(b"x-forwarded-proto", b"http"),
        Header::new(b"x-forwarded-host", b"old.example"),
    ];

    let host_policy = UpstreamHostPolicy::default();
    let append_policy = ForwardedHeaderPolicy {
        mode: ForwardedHeaderPolicyMode::Append,
    };
    let req = build_h2_request_with_policy(
        &endpoint,
        &host_policy,
        &append_policy,
        "GET",
        "/",
        &headers,
        RequestInputMeta {
            authority: Some("api.example.com"),
            content_length: None,
            request_id: 0,
            traceparent: None,
            client_addr: "203.0.113.55:43210".parse().expect("client"),
        },
    )
    .expect("append request");

    assert_eq!(
        req.headers().get("forwarded").and_then(|h| h.to_str().ok()),
        Some(
            "for=1.2.3.4;proto=http;host=\"old.example\", for=203.0.113.55;proto=https;host=\"api.example.com\""
        )
    );
    assert_eq!(
        req.headers()
            .get("x-forwarded-for")
            .and_then(|h| h.to_str().ok()),
        Some("1.2.3.4, 203.0.113.55")
    );
    assert_eq!(
        req.headers()
            .get("x-forwarded-proto")
            .and_then(|h| h.to_str().ok()),
        Some("http, https")
    );
    assert_eq!(
        req.headers()
            .get("x-forwarded-host")
            .and_then(|h| h.to_str().ok()),
        Some("old.example, api.example.com")
    );

    let preserve_policy = ForwardedHeaderPolicy {
        mode: ForwardedHeaderPolicyMode::Preserve,
    };
    let req = build_h2_request_with_policy(
        &endpoint,
        &host_policy,
        &preserve_policy,
        "GET",
        "/",
        &headers,
        RequestInputMeta {
            authority: Some("api.example.com"),
            content_length: None,
            request_id: 0,
            traceparent: None,
            client_addr: "203.0.113.55:43210".parse().expect("client"),
        },
    )
    .expect("preserve request");

    assert_eq!(
        req.headers().get("forwarded").and_then(|h| h.to_str().ok()),
        Some("for=1.2.3.4;proto=http;host=\"old.example\"")
    );
    assert_eq!(
        req.headers()
            .get("x-forwarded-for")
            .and_then(|h| h.to_str().ok()),
        Some("1.2.3.4")
    );
    assert_eq!(
        req.headers()
            .get("x-forwarded-proto")
            .and_then(|h| h.to_str().ok()),
        Some("http")
    );
    assert_eq!(
        req.headers()
            .get("x-forwarded-host")
            .and_then(|h| h.to_str().ok()),
        Some("old.example")
    );
}

#[test]
fn forwarded_header_formats_ipv6_clients() {
    let req = build_h2_request_for_backend(
        "backend.internal:443",
        "GET",
        "/",
        &[],
        RequestInputMeta {
            authority: Some("api.example.com"),
            content_length: None,
            request_id: 0,
            traceparent: None,
            client_addr: "[2001:db8::1]:4444".parse().expect("client"),
        },
    )
    .expect("request");

    assert_eq!(
        req.headers().get("forwarded").and_then(|h| h.to_str().ok()),
        Some("for=\"[2001:db8::1]\";proto=https;host=\"api.example.com\"")
    );
}

#[test]
fn host_policy_rewrite_uses_configured_host() {
    let endpoint = parse_backend_endpoint("backend.internal:443").expect("endpoint");
    let policy = UpstreamHostPolicy {
        mode: UpstreamHostPolicyMode::Rewrite,
        host: Some("origin.example.com".to_string()),
    };
    let req = build_h2_request_with_policy(
        &endpoint,
        &policy,
        &ForwardedHeaderPolicy::default(),
        "GET",
        "/",
        &[],
        RequestInputMeta {
            authority: Some("api.example.com"),
            content_length: None,
            request_id: 0,
            traceparent: None,
            client_addr: "203.0.113.10:44321".parse().expect("client"),
        },
    )
    .expect("request");

    assert_eq!(
        req.headers().get(HOST).and_then(|h| h.to_str().ok()),
        Some("origin.example.com")
    );
    assert_eq!(
        req.headers()
            .get("x-forwarded-host")
            .and_then(|h| h.to_str().ok()),
        Some("origin.example.com")
    );
}

#[test]
fn host_policy_upstream_uses_backend_authority() {
    let endpoint = parse_backend_endpoint("backend.internal:8443").expect("endpoint");
    let policy = UpstreamHostPolicy {
        mode: UpstreamHostPolicyMode::Upstream,
        host: None,
    };
    let req = build_h2_request_with_policy(
        &endpoint,
        &policy,
        &ForwardedHeaderPolicy::default(),
        "GET",
        "/",
        &[],
        RequestInputMeta {
            authority: Some("api.example.com"),
            content_length: None,
            request_id: 0,
            traceparent: None,
            client_addr: "203.0.113.10:44321".parse().expect("client"),
        },
    )
    .expect("request");

    assert_eq!(
        req.headers().get(HOST).and_then(|h| h.to_str().ok()),
        Some("backend.internal:8443")
    );
}

#[test]
fn connect_uses_authority_form_request_target() {
    let req = build_h2_request_for_backend(
        "proxy.internal:8443",
        "CONNECT",
        "/",
        &[],
        RequestInputMeta {
            authority: Some("target.example.com:443"),
            content_length: None,
            request_id: 0,
            traceparent: None,
            client_addr: "203.0.113.8:44321".parse().expect("client"),
        },
    )
    .expect("request");

    assert_eq!(req.method(), http::Method::CONNECT);
    assert_eq!(req.uri().to_string(), "target.example.com:443");
    assert_eq!(
        req.headers().get(HOST).and_then(|h| h.to_str().ok()),
        Some("target.example.com:443")
    );
}

#[test]
fn websocket_requests_are_shaped_as_extended_connect() {
    let endpoint = parse_backend_endpoint("backend.internal:443").expect("endpoint");
    let headers = vec![
        Header::new(b":protocol", b"websocket"),
        Header::new(b"sec-websocket-key", b"dGhlIHNhbXBsZSBub25jZQ=="),
    ];

    let req = build_h2_request_with_policy(
        &endpoint,
        &UpstreamHostPolicy::default(),
        &ForwardedHeaderPolicy::default(),
        "CONNECT",
        "/ws",
        &headers,
        RequestInputMeta {
            authority: Some("socket.example.com"),
            content_length: None,
            request_id: 11,
            traceparent: None,
            client_addr: "203.0.113.33:6000".parse().expect("client"),
        },
    )
    .expect("request");

    assert_eq!(req.method(), http::Method::CONNECT);
    assert_eq!(req.version(), http::Version::HTTP_2);
    assert_eq!(req.uri().to_string(), "https://backend.internal:443/ws");
    assert!(req.extensions().get::<Protocol>().is_some());
    assert!(req.headers().get(HOST).is_none());
    assert!(req.headers().get(http::header::CONTENT_LENGTH).is_none());
    assert!(req.headers().get("connection").is_none());
    assert!(req.headers().get("upgrade").is_none());
    assert_eq!(
        req.headers()
            .get("sec-websocket-key")
            .and_then(|value| value.to_str().ok()),
        Some("dGhlIHNhbXBsZSBub25jZQ==")
    );
    assert_eq!(
        req.headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
        Some("11")
    );
}
