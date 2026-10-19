//! Websocket and upgrade request-shaping contracts for canonical bridge builders.

use http::header::HOST;
use impulse_config::config::{ForwardedHeaderPolicy, UpstreamHostPolicy};
use quiche::h3::Header;

use crate::common::{
    RequestInputMeta, build_h1_request_for_backend, build_h2_request_with_policy,
    parse_backend_endpoint,
};

#[test]
fn incomplete_upgrade_candidates_do_not_trigger_websocket_specific_request_shaping() {
    let endpoint = parse_backend_endpoint("backend.internal:443").expect("endpoint");
    let headers = vec![
        Header::new(b"connection", b"keep-alive"),
        Header::new(b"upgrade", b"websocket"),
        Header::new(b"sec-websocket-key", b"dGhlIHNhbXBsZSBub25jZQ=="),
    ];

    let meta = RequestInputMeta {
        authority: Some("api.example.com"),
        content_length: None,
        request_id: 602,
        traceparent: None,
        client_addr: "203.0.113.17:7004".parse().expect("client"),
    };

    let h1 = build_h1_request_for_backend("backend.internal:443", "GET", "/not-ws", &headers, meta)
        .expect("h1 request");
    let h2 = build_h2_request_with_policy(
        &endpoint,
        &UpstreamHostPolicy::default(),
        &ForwardedHeaderPolicy::default(),
        "GET",
        "/not-ws",
        &headers,
        meta,
    )
    .expect("h2 request");

    assert_eq!(h1.method(), http::Method::GET);
    assert_eq!(h2.method(), http::Method::GET);
    assert_eq!(h1.uri().to_string(), "https://backend.internal:443/not-ws");
    assert_eq!(h2.uri().to_string(), "https://backend.internal:443/not-ws");
    assert!(h1.headers().get("connection").is_none());
    assert!(h1.headers().get("upgrade").is_none());
    assert!(h2.headers().get("connection").is_none());
    assert!(h2.headers().get("upgrade").is_none());
    assert_eq!(
        h1.headers().get(HOST).and_then(|value| value.to_str().ok()),
        Some("api.example.com")
    );
    assert_eq!(
        h2.headers().get(HOST).and_then(|value| value.to_str().ok()),
        Some("api.example.com")
    );
}

#[test]
fn connect_without_websocket_protocol_stays_on_normal_connect_path() {
    let endpoint = parse_backend_endpoint("proxy.internal:8443").expect("endpoint");
    let headers = vec![Header::new(
        b"sec-websocket-key",
        b"dGhlIHNhbXBsZSBub25jZQ==",
    )];

    let request = build_h2_request_with_policy(
        &endpoint,
        &UpstreamHostPolicy::default(),
        &ForwardedHeaderPolicy::default(),
        "CONNECT",
        "/ignored",
        &headers,
        RequestInputMeta {
            authority: Some("target.example.com:443"),
            content_length: None,
            request_id: 603,
            traceparent: None,
            client_addr: "203.0.113.18:7005".parse().expect("client"),
        },
    )
    .expect("h2 request");

    assert_eq!(request.method(), http::Method::CONNECT);
    assert_eq!(request.uri().to_string(), "target.example.com:443");
    assert!(request.extensions().get::<hyper::ext::Protocol>().is_none());
    assert_eq!(
        request
            .headers()
            .get(HOST)
            .and_then(|value| value.to_str().ok()),
        Some("target.example.com:443")
    );
}
