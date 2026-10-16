use std::{
    collections::HashMap,
    convert::Infallible,
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Incoming};
use impulse_config::config::{
    ApiKeyAuth, DistributedQuotaPolicy, DistributedQuotaSelector, DistributedQuotaWindow,
    ExternalAuth, ExternalAuthFailureMode, ExternalAuthRequestHeader, JwtAlgorithm, JwtAuth,
    JwtVerificationKey, LoadBalancing, QuotaCounterBackend, RouteAuth, RouteMatch, ScopedRateLimit,
    ScopedRateLimitScope, Upstream,
};
use serial_test::serial;

mod support;

use support::{
    net::local_listener_bind_available,
    parity::{BootstrapQuicParityHarness, ParityRequestSpec, make_backend, make_upstream},
    request_path::{
        BootstrapRequestSpec, H3RequestSpec, cancel_bootstrap_post_to, cancel_h3_post_to,
        run_bootstrap_authority_host_request_to, run_bootstrap_h1_websocket_handshake_to,
        run_bootstrap_request_to, run_request_to, run_two_chunk_bootstrap_post_to,
        run_two_chunk_post_to,
    },
};

// Routing parity

#[test]
fn bootstrap_and_quic_parity_harness_collects_canonical_response_shape() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_backend(|_req: Request<Incoming>| async move {
        Ok::<_, Infallible>(
            Response::builder()
                .status(200)
                .header("x-parity", "ok")
                .body(Full::new(Bytes::from_static(b"parity ok\n")))
                .expect("response"),
        )
    });

    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        make_upstream(
            "/",
            vec![make_backend("backend-a", backend_addr.to_string())],
            None,
            "round-robin",
        ),
    );

    let config = harness.make_config(upstreams);
    harness
        .start_listener(config)
        .expect("listener with bootstrap");

    let mut request = ParityRequestSpec::get("localhost", "/");
    request.selected_response_headers = &["x-parity"];
    request.capture_metrics_delta = true;

    let pair = harness.run_parity_pair(request).expect("parity pair");

    assert_eq!(pair.quic.response.status, 200);
    assert_eq!(pair.bootstrap.response.status, 200);
    assert_eq!(pair.quic.response.body, pair.bootstrap.response.body);
    assert_eq!(pair.quic.response.body, b"parity ok\n");
    assert_eq!(
        pair.quic.response.selected_headers,
        pair.bootstrap.response.selected_headers
    );
    assert_eq!(
        pair.quic.response.selected_headers,
        vec![(String::from("x-parity"), String::from("ok"))]
    );
    assert!(pair.quic.metrics_delta.is_some());
    assert!(pair.bootstrap.metrics_delta.is_some());
}

#[test]
fn bootstrap_and_quic_route_resolution_choose_the_same_route_and_backend_result() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let payments_get = harness.start_h1_backend(|_req: Request<Incoming>| async move {
        Ok::<_, Infallible>(
            Response::builder()
                .status(200)
                .header("x-backend", "payments-get")
                .body(Full::new(Bytes::from_static(b"payments get\n")))
                .expect("response"),
        )
    });
    let payments_post = harness.start_h1_backend(|_req: Request<Incoming>| async move {
        Ok::<_, Infallible>(
            Response::builder()
                .status(200)
                .header("x-backend", "payments-post")
                .body(Full::new(Bytes::from_static(b"payments post\n")))
                .expect("response"),
        )
    });
    let admin_get = harness.start_h1_backend(|_req: Request<Incoming>| async move {
        Ok::<_, Infallible>(
            Response::builder()
                .status(200)
                .header("x-backend", "admin-get")
                .body(Full::new(Bytes::from_static(b"admin get\n")))
                .expect("response"),
        )
    });

    let upstreams = HashMap::from([
        (
            "payments-get".to_string(),
            routed_upstream(
                Some("api.example.com"),
                "/payments",
                Some("GET"),
                "round-robin",
                vec![make_backend("payments-get-a", payments_get.to_string())],
            ),
        ),
        (
            "payments-post".to_string(),
            routed_upstream(
                Some("api.example.com"),
                "/payments",
                Some("POST"),
                "round-robin",
                vec![make_backend("payments-post-a", payments_post.to_string())],
            ),
        ),
        (
            "admin-get".to_string(),
            routed_upstream(
                Some("admin.example.com"),
                "/admin",
                Some("GET"),
                "round-robin",
                vec![make_backend("admin-get-a", admin_get.to_string())],
            ),
        ),
    ]);

    let config = harness.make_config(upstreams);
    harness
        .start_listener(config)
        .expect("listener with bootstrap");

    let cases = [
        (
            "GET",
            "api.example.com",
            "/payments/charge",
            "payments get\n",
            "payments-get",
        ),
        (
            "POST",
            "api.example.com",
            "/payments/charge",
            "payments post\n",
            "payments-post",
        ),
        (
            "GET",
            "admin.example.com",
            "/admin/audit",
            "admin get\n",
            "admin-get",
        ),
    ];

    for (method, authority, path, expected_body, expected_backend) in cases {
        let request = ParityRequestSpec {
            method,
            authority,
            path,
            headers: &[],
            body: None,
            user_agent: "impulse-bootstrap-quic-parity-test",
            selected_response_headers: &["x-backend"],
            capture_metrics_delta: false,
        };

        let pair = harness.run_parity_pair(request).expect("parity pair");

        assert_eq!(
            pair.quic.response.status, 200,
            "quic route resolution should succeed for {method} {authority}{path}"
        );
        assert_eq!(
            pair.bootstrap.response.status, 200,
            "bootstrap route resolution should succeed for {method} {authority}{path}"
        );
        assert_eq!(
            pair.quic.response.body,
            expected_body.as_bytes(),
            "quic should hit the expected upstream-visible backend result for {method} {authority}{path}"
        );
        assert_eq!(
            pair.bootstrap.response.body,
            expected_body.as_bytes(),
            "bootstrap should hit the expected upstream-visible backend result for {method} {authority}{path}"
        );
        assert_eq!(
            pair.quic.response.selected_headers,
            vec![(String::from("x-backend"), expected_backend.to_string())],
            "quic should surface the selected backend marker for {method} {authority}{path}"
        );
        assert_eq!(
            pair.bootstrap.response.selected_headers, pair.quic.response.selected_headers,
            "bootstrap and quic should expose the same backend-selection result for {method} {authority}{path}"
        );
    }
}

#[test]
fn bootstrap_and_quic_route_precedence_matches() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let default_long = harness.start_h1_static_backend(b"default long\n");
    let wildcard_broad = harness.start_h1_static_backend(b"wildcard broad\n");
    let wildcard_narrow = harness.start_h1_static_backend(b"wildcard narrow\n");
    let exact_generic = harness.start_h1_static_backend(b"exact generic\n");
    let exact_post = harness.start_h1_static_backend(b"exact post\n");

    let upstreams = HashMap::from([
        (
            "default-long".to_string(),
            routed_upstream(
                None,
                "/api/v1",
                None,
                "round-robin",
                vec![make_backend("default-long-a", default_long.to_string())],
            ),
        ),
        (
            "wildcard-broad".to_string(),
            routed_upstream(
                Some("*.example.com"),
                "/api",
                None,
                "round-robin",
                vec![make_backend("wildcard-broad-a", wildcard_broad.to_string())],
            ),
        ),
        (
            "wildcard-narrow".to_string(),
            routed_upstream(
                Some("*.svc.example.com"),
                "/api",
                None,
                "round-robin",
                vec![make_backend(
                    "wildcard-narrow-a",
                    wildcard_narrow.to_string(),
                )],
            ),
        ),
        (
            "exact-generic".to_string(),
            routed_upstream(
                Some("api.svc.example.com"),
                "/api",
                None,
                "round-robin",
                vec![make_backend("exact-generic-a", exact_generic.to_string())],
            ),
        ),
        (
            "exact-post".to_string(),
            routed_upstream(
                Some("api.svc.example.com"),
                "/api",
                Some("POST"),
                "round-robin",
                vec![make_backend("exact-post-a", exact_post.to_string())],
            ),
        ),
    ]);

    let config = harness.make_config(upstreams);
    harness
        .start_listener(config)
        .expect("listener with bootstrap");

    let cases = [
        (
            "GET",
            "api.svc.example.com",
            "/api/orders",
            "exact generic\n",
        ),
        ("POST", "api.svc.example.com", "/api/orders", "exact post\n"),
        (
            "GET",
            "edge.svc.example.com",
            "/api/orders",
            "wildcard narrow\n",
        ),
        ("GET", "edge.example.com", "/api/orders", "wildcard broad\n"),
        (
            "GET",
            "api.svc.example.com",
            "/api/v1/orders",
            "default long\n",
        ),
    ];

    for (method, authority, path, expected_body) in cases {
        let pair = harness
            .run_parity_pair(ParityRequestSpec {
                method,
                authority,
                path,
                headers: &[],
                body: None,
                user_agent: "impulse-bootstrap-quic-parity-test",
                selected_response_headers: &[],
                capture_metrics_delta: false,
            })
            .expect("route precedence parity pair");

        assert_eq!(pair.quic.response.status, 200);
        assert_eq!(pair.bootstrap.response.status, 200);
        assert_eq!(pair.quic.response.body, expected_body.as_bytes());
        assert_eq!(pair.bootstrap.response.body, pair.quic.response.body);
    }
}

#[test]
fn bootstrap_and_quic_route_resolution_share_observable_unrouted_behavior() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_static_backend(b"matched route\n");

    let upstreams = HashMap::from([(
        "api".to_string(),
        routed_upstream(
            Some("api.example.com"),
            "/payments",
            Some("GET"),
            "round-robin",
            vec![make_backend("backend-a", backend_addr.to_string())],
        ),
    )]);

    let config = harness.make_config(upstreams);
    harness
        .start_listener(config)
        .expect("listener with bootstrap");

    for (method, authority, path) in [
        ("GET", "unknown.example.com", "/payments"),
        ("GET", "api.example.com", "/payments-extra"),
        ("POST", "api.example.com", "/payments"),
    ] {
        let pair = harness
            .run_parity_pair(ParityRequestSpec {
                method,
                authority,
                path,
                headers: &[],
                body: None,
                user_agent: "impulse-bootstrap-quic-parity-test",
                selected_response_headers: &[],
                capture_metrics_delta: false,
            })
            .expect("unrouted parity pair");

        assert_eq!(pair.quic.response.status, 502);
        assert_eq!(pair.bootstrap.response.status, 502);
        assert_eq!(pair.quic.response.body, b"no route\n");
        assert_eq!(pair.bootstrap.response.body, pair.quic.response.body);
    }
}

// Authentication and admission parity

#[test]
fn bootstrap_and_quic_local_api_key_auth_decisions_match() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_static_backend(b"api key ok\n");

    let upstreams = HashMap::from([(
        "api".to_string(),
        auth_protected_upstream(
            "/protected",
            vec![make_backend("backend-a", backend_addr.to_string())],
            RouteAuth {
                api_key: Some(ApiKeyAuth {
                    header_name: "x-api-key".to_string(),
                    keys: vec!["edge-key".to_string()],
                }),
                ..RouteAuth::default()
            },
        ),
    )]);

    let config = harness.make_config(upstreams);
    harness
        .start_listener(config)
        .expect("listener with bootstrap");

    let deny_request = ParityRequestSpec {
        method: "GET",
        authority: "localhost",
        path: "/protected",
        headers: &[],
        body: None,
        user_agent: "impulse-bootstrap-quic-parity-test",
        selected_response_headers: &["www-authenticate"],
        capture_metrics_delta: false,
    };
    for (name, headers) in [
        ("missing", &[][..]),
        ("invalid", &[("x-api-key", "wrong-key")][..]),
    ] {
        let deny_pair = harness
            .run_parity_pair(ParityRequestSpec {
                headers,
                ..deny_request
            })
            .unwrap_or_else(|err| panic!("api key {name} parity failed: {err}"));
        assert_eq!(deny_pair.quic.response.status, 401);
        assert_eq!(deny_pair.bootstrap.response.status, 401);
        assert_eq!(
            deny_pair.quic.response.selected_headers,
            vec![(String::from("www-authenticate"), String::from("ApiKey"))]
        );
        assert_eq!(
            deny_pair.bootstrap.response.selected_headers,
            deny_pair.quic.response.selected_headers
        );
        assert_eq!(
            deny_pair.bootstrap.response.body,
            deny_pair.quic.response.body
        );
        assert!(
            String::from_utf8_lossy(&deny_pair.quic.response.body).contains("unauthorized"),
            "expected canonical unauthorized body for api key rejection"
        );
    }

    let allow_request = ParityRequestSpec {
        headers: &[("x-api-key", "edge-key")],
        ..deny_request
    };
    let allow_pair = harness
        .run_parity_pair(allow_request)
        .expect("api key allow");
    assert_eq!(allow_pair.quic.response.status, 200);
    assert_eq!(allow_pair.bootstrap.response.status, 200);
    assert_eq!(allow_pair.quic.response.body, b"api key ok\n");
    assert_eq!(
        allow_pair.bootstrap.response.body,
        allow_pair.quic.response.body
    );
}

#[test]
fn bootstrap_and_quic_rs256_jwt_auth_decisions_match() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_static_backend(b"rs256 ok\n");

    let signing_key =
        boring::pkey::PKey::from_rsa(boring::rsa::Rsa::generate(2048).expect("generate rsa key"))
            .expect("rsa pkey");
    let public_key_pem = String::from_utf8(
        signing_key
            .public_key_to_pem()
            .expect("encode rsa public pem"),
    )
    .expect("utf8 pem");

    let upstreams = HashMap::from([(
        "api".to_string(),
        auth_protected_upstream(
            "/jwt-rs256",
            vec![make_backend("backend-a", backend_addr.to_string())],
            RouteAuth {
                api_key: None,
                jwt: Some(JwtAuth {
                    secret: String::new(),
                    issuer: Some("issuer-1".to_string()),
                    audience: Some("aud-1".to_string()),
                    allowed_algorithms: vec![JwtAlgorithm::Rs256],
                    require_kid: true,
                    static_keys: vec![JwtVerificationKey::Pem {
                        kid: Some("parity-kid".to_string()),
                        alg: Some(JwtAlgorithm::Rs256),
                        public_key_pem,
                    }],
                    clock_skew_secs: 30,
                    ..JwtAuth::default()
                }),
                external_auth: None,
                required_scopes: vec!["read:parity".to_string()],
                required_roles: Vec::new(),
            },
        ),
    )]);

    let config = harness.make_config(upstreams);
    harness
        .start_listener(config)
        .expect("listener with bootstrap");

    let deny_request = ParityRequestSpec {
        method: "GET",
        authority: "localhost",
        path: "/jwt-rs256",
        headers: &[],
        body: None,
        user_agent: "impulse-bootstrap-quic-parity-test",
        selected_response_headers: &["www-authenticate"],
        capture_metrics_delta: false,
    };
    let deny_pair = harness.run_parity_pair(deny_request).expect("rs256 deny");
    assert_eq!(deny_pair.quic.response.status, 401);
    assert_eq!(deny_pair.bootstrap.response.status, 401);
    assert_eq!(
        deny_pair.bootstrap.response.selected_headers,
        deny_pair.quic.response.selected_headers
    );

    let token = encode_test_rs256_jwt(
        &signing_key,
        "parity-kid",
        serde_json::json!({
            "sub": "user-1",
            "iss": "issuer-1",
            "aud": "aud-1",
            "exp": 4_000_000_000u64,
            "scope": "read:parity",
        }),
    );
    let authorization = format!("Bearer {token}");
    let allow_request = ParityRequestSpec {
        headers: &[("authorization", authorization.as_str())],
        ..deny_request
    };
    let allow_pair = harness.run_parity_pair(allow_request).expect("rs256 allow");
    assert_eq!(allow_pair.quic.response.status, 200);
    assert_eq!(allow_pair.bootstrap.response.status, 200);
    assert_eq!(allow_pair.quic.response.body, b"rs256 ok\n");
    assert_eq!(
        allow_pair.bootstrap.response.body,
        allow_pair.quic.response.body
    );
}

#[test]
fn bootstrap_and_quic_local_jwt_auth_decisions_match() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_static_backend(b"jwt ok\n");

    let upstreams = HashMap::from([(
        "api".to_string(),
        auth_protected_upstream(
            "/jwt",
            vec![make_backend("backend-a", backend_addr.to_string())],
            RouteAuth {
                api_key: None,
                jwt: Some(JwtAuth {
                    secret: "jwt-secret".to_string(),
                    issuer: Some("issuer-1".to_string()),
                    audience: Some("aud-1".to_string()),
                    clock_skew_secs: 30,
                    ..JwtAuth::default()
                }),
                external_auth: None,
                required_scopes: vec!["read:parity".to_string()],
                required_roles: Vec::new(),
            },
        ),
    )]);

    let config = harness.make_config(upstreams);
    harness
        .start_listener(config)
        .expect("listener with bootstrap");

    let deny_request = ParityRequestSpec {
        method: "GET",
        authority: "localhost",
        path: "/jwt",
        headers: &[],
        body: None,
        user_agent: "impulse-bootstrap-quic-parity-test",
        selected_response_headers: &["www-authenticate"],
        capture_metrics_delta: false,
    };
    let deny_pair = harness.run_parity_pair(deny_request).expect("jwt deny");
    assert_eq!(deny_pair.quic.response.status, 401);
    assert_eq!(deny_pair.bootstrap.response.status, 401);
    assert_eq!(
        deny_pair.quic.response.selected_headers,
        vec![(String::from("www-authenticate"), String::from("Bearer"))]
    );
    assert_eq!(
        deny_pair.bootstrap.response.selected_headers,
        deny_pair.quic.response.selected_headers
    );
    assert_eq!(
        deny_pair.bootstrap.response.body,
        deny_pair.quic.response.body
    );
    assert!(
        String::from_utf8_lossy(&deny_pair.quic.response.body).contains("unauthorized"),
        "expected canonical unauthorized body for jwt rejection"
    );

    let invalid_authorization = "Bearer invalid.jwt.token";
    let invalid_pair = harness
        .run_parity_pair(ParityRequestSpec {
            headers: &[("authorization", invalid_authorization)],
            ..deny_request
        })
        .expect("invalid jwt deny");
    assert_eq!(invalid_pair.quic.response.status, 401);
    assert_eq!(invalid_pair.bootstrap.response.status, 401);
    assert_eq!(
        invalid_pair.bootstrap.response.selected_headers,
        invalid_pair.quic.response.selected_headers
    );
    assert_eq!(
        invalid_pair.bootstrap.response.body,
        invalid_pair.quic.response.body
    );

    let token = encode_test_hs256_jwt(
        "jwt-secret",
        serde_json::json!({
            "sub": "user-1",
            "iss": "issuer-1",
            "aud": "aud-1",
            "exp": 4_000_000_000u64,
            "scope": "read:parity",
        }),
    );
    let authorization = format!("Bearer {token}");
    let allow_request = ParityRequestSpec {
        headers: &[("authorization", authorization.as_str())],
        ..deny_request
    };
    let allow_pair = harness.run_parity_pair(allow_request).expect("jwt allow");
    assert_eq!(allow_pair.quic.response.status, 200);
    assert_eq!(allow_pair.bootstrap.response.status, 200);
    assert_eq!(allow_pair.quic.response.body, b"jwt ok\n");
    assert_eq!(
        allow_pair.bootstrap.response.body,
        allow_pair.quic.response.body
    );
}

#[test]
fn bootstrap_and_quic_external_auth_decisions_match() {
    if !local_listener_bind_available() {
        return;
    }

    let cases = [
        ExternalAuthParityCase {
            name: "allow",
            auth_status: 204,
            auth_headers: &[("x-user-id", "alice")],
            auth_body: b"",
            allowlist: &["x-user-id"],
            expected_status: 200,
            expected_body: b"backend user=alice",
            expected_headers: &[],
        },
        ExternalAuthParityCase {
            name: "deny",
            auth_status: 403,
            auth_headers: &[("x-auth-reason", "policy")],
            auth_body: b"denied by auth",
            allowlist: &["x-auth-reason"],
            expected_status: 403,
            expected_body: b"denied by auth",
            expected_headers: &[("x-auth-reason", "policy")],
        },
        ExternalAuthParityCase {
            name: "challenge",
            auth_status: 401,
            auth_headers: &[
                ("www-authenticate", "Bearer realm=\"impulse\""),
                ("x-auth-reason", "expired"),
            ],
            auth_body: b"token expired",
            allowlist: &["x-auth-reason"],
            expected_status: 401,
            expected_body: b"token expired",
            expected_headers: &[
                ("www-authenticate", "Bearer realm=\"impulse\""),
                ("x-auth-reason", "expired"),
            ],
        },
        ExternalAuthParityCase {
            name: "redirect",
            auth_status: 302,
            auth_headers: &[("location", "https://login.example.com/")],
            auth_body: b"",
            allowlist: &[],
            expected_status: 302,
            expected_body: b"",
            expected_headers: &[("location", "https://login.example.com/")],
        },
    ];

    for case in cases {
        let mut harness = BootstrapQuicParityHarness::new();
        let backend_addr = harness.start_h1_backend(|req: Request<Incoming>| async move {
            let user = req
                .headers()
                .get("x-user-id")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("missing");
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!(
                "backend user={user}"
            )))))
        });
        let auth_addr = harness.start_h1_backend(move |_req: Request<Incoming>| {
            let case = case;
            async move {
                let mut builder = Response::builder().status(case.auth_status);
                for (name, value) in case.auth_headers {
                    builder = builder.header(*name, *value);
                }
                Ok::<_, Infallible>(
                    builder
                        .body(Full::new(Bytes::from_static(case.auth_body)))
                        .expect("auth response"),
                )
            }
        });

        let config = configure_http_external_auth(
            &harness,
            format!("http://{backend_addr}"),
            format!("http://{auth_addr}/check"),
            250,
            ExternalAuthFailureMode::FailClosed,
            case.allowlist
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
        );
        harness
            .start_listener(config)
            .expect("listener with bootstrap");

        let request = ParityRequestSpec {
            method: "GET",
            authority: "localhost",
            path: "/auth",
            headers: &[],
            body: None,
            user_agent: "impulse-bootstrap-quic-parity-test",
            selected_response_headers: &["www-authenticate", "x-auth-reason", "location"],
            capture_metrics_delta: false,
        };
        let pair = harness.run_parity_pair(request).unwrap_or_else(|err| {
            panic!("external auth parity case `{}` failed: {err}", case.name)
        });

        assert_eq!(
            pair.quic.response.status, case.expected_status,
            "quic external auth status mismatch for case `{}`",
            case.name
        );
        assert_eq!(
            pair.bootstrap.response.status, case.expected_status,
            "bootstrap external auth status mismatch for case `{}`",
            case.name
        );
        assert_eq!(
            pair.quic.response.body, case.expected_body,
            "quic external auth body mismatch for case `{}`",
            case.name
        );
        assert_eq!(
            pair.bootstrap.response.body, case.expected_body,
            "bootstrap external auth body mismatch for case `{}`",
            case.name
        );
        assert_eq!(
            pair.quic.response.selected_headers,
            expected_selected_headers(case.expected_headers),
            "quic external auth headers mismatch for case `{}`",
            case.name
        );
        assert_eq!(
            pair.bootstrap.response.selected_headers, pair.quic.response.selected_headers,
            "bootstrap and quic external auth headers should match for case `{}`",
            case.name
        );
    }
}

#[test]
#[serial]
fn bootstrap_and_quic_external_auth_unavailable_fail_closed_matches() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_static_backend(b"unexpected backend call");
    let unused_listener = TcpListener::bind("127.0.0.1:0").expect("bind unused auth port");
    let unused_addr = unused_listener.local_addr().expect("unused auth addr");
    drop(unused_listener);

    let config = configure_http_external_auth(
        &harness,
        format!("http://{backend_addr}"),
        format!("http://{unused_addr}/check"),
        150,
        ExternalAuthFailureMode::FailClosed,
        Vec::new(),
    );
    harness
        .start_listener(config)
        .expect("listener with bootstrap");

    let pair = harness
        .run_parity_pair(ParityRequestSpec::get("localhost", "/auth"))
        .expect("external auth unavailable parity pair");

    assert_eq!(pair.quic.response.status, 503);
    assert_eq!(pair.bootstrap.response.status, 503);
    assert_eq!(pair.bootstrap.response.body, pair.quic.response.body);
    assert!(
        String::from_utf8_lossy(&pair.quic.response.body).contains("external auth unavailable"),
        "expected canonical external auth unavailable body"
    );
}

#[test]
#[serial]
fn bootstrap_and_quic_admission_rate_limit_rejections_match() {
    if !local_listener_bind_available() {
        return;
    }

    let quic = run_scoped_rate_limit_scenario(IngressKind::Quic);
    let bootstrap = run_scoped_rate_limit_scenario(IngressKind::Bootstrap);

    assert_eq!(quic.status, 429);
    assert_eq!(bootstrap.status, 429);
    assert_eq!(bootstrap.status, quic.status);
    assert_eq!(bootstrap.body, quic.body);
    assert!(
        quic.body.contains("request rate limited"),
        "expected canonical rate-limit rejection body, got `{}`",
        quic.body
    );
    assert_eq!(bootstrap.headers, quic.headers);
    assert_eq!(
        quic.headers,
        vec![(String::from("retry-after"), String::from("1"))]
    );
    assert_eq!(
        quic.upstream_calls, 1,
        "quic rate-limit path should reject before the second upstream dispatch"
    );
    assert_eq!(
        bootstrap.upstream_calls, 1,
        "bootstrap rate-limit path should reject before the second upstream dispatch"
    );
}

#[test]
#[serial]
#[ignore = "bootstrap path does not yet share post-auth distributed quota semantics"]
fn bootstrap_and_quic_distributed_quota_rejections_match() {
    if !local_listener_bind_available() {
        return;
    }

    let quic = run_distributed_quota_scenario(IngressKind::Quic);
    let bootstrap = run_distributed_quota_scenario(IngressKind::Bootstrap);

    assert_eq!(quic.status, 429);
    assert_eq!(bootstrap.status, 429);
    assert_eq!(bootstrap.body, quic.body);
    assert!(
        quic.body.contains("burst quota exhausted"),
        "expected canonical quota rejection body, got `{}`",
        quic.body
    );
    assert_eq!(bootstrap.headers, quic.headers);
    assert_eq!(quic.upstream_calls, 1);
    assert_eq!(bootstrap.upstream_calls, 1);
}

#[test]
#[serial]
#[ignore = "bootstrap path does not yet share post-auth admission overload semantics"]
fn bootstrap_and_quic_admission_overload_shed_contracts_match() {
    if !local_listener_bind_available() {
        return;
    }

    let quic = run_overload_shed_scenario(IngressKind::Quic);
    let bootstrap = run_overload_shed_scenario(IngressKind::Bootstrap);

    assert_eq!(quic.status, 503);
    assert_eq!(bootstrap.status, 503);
    assert_eq!(bootstrap.body, quic.body);
    assert!(
        quic.body.contains("route queue cap exceeded"),
        "expected canonical overload body, got `{}`",
        quic.body
    );
    assert_eq!(bootstrap.headers, quic.headers);
    assert_eq!(
        quic.headers,
        vec![(String::from("retry-after"), String::from("1"))]
    );
    assert_eq!(
        quic.upstream_calls, 1,
        "quic overload shedding should stop the second request before backend dispatch"
    );
    assert_eq!(
        bootstrap.upstream_calls, 1,
        "bootstrap overload shedding should stop the second request before backend dispatch"
    );
}

// Response normalization parity

#[test]
fn bootstrap_and_quic_empty_request_and_response_bodies_match() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_backend(|req: Request<Incoming>| async move {
        let body = req
            .into_body()
            .collect()
            .await
            .expect("collect empty request body")
            .to_bytes();
        Ok::<_, Infallible>(
            Response::builder()
                .header("x-request-body-bytes", body.len().to_string())
                .body(Full::new(Bytes::new()))
                .expect("response"),
        )
    });
    start_single_route_listener(&mut harness, "/empty", backend_addr.to_string());

    let mut request = ParityRequestSpec::get("localhost", "/empty");
    request.selected_response_headers = &["x-request-body-bytes"];
    let pair = harness
        .run_parity_pair(request)
        .expect("empty body parity pair");

    assert_eq!(pair.quic.response.status, 200);
    assert_eq!(pair.bootstrap.response.status, 200);
    assert!(pair.quic.response.body.is_empty());
    assert!(pair.bootstrap.response.body.is_empty());
    assert_eq!(
        pair.bootstrap.response.selected_headers,
        pair.quic.response.selected_headers
    );
    assert_eq!(
        pair.quic.response.selected_headers,
        vec![(String::from("x-request-body-bytes"), String::from("0"))]
    );
}

#[test]
fn bootstrap_and_quic_streaming_request_bodies_match() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_backend(|req: Request<Incoming>| async move {
        let body = req
            .into_body()
            .collect()
            .await
            .expect("collect streamed request body")
            .to_bytes();
        Ok::<_, Infallible>(Response::new(Full::new(body)))
    });
    start_single_route_listener(&mut harness, "/stream-request", backend_addr.to_string());
    let listen_addr = harness.listen_addr();

    let (quic, reset) = run_two_chunk_post_to(
        listen_addr,
        "localhost",
        "/stream-request",
        b"first-".to_vec(),
        b"second".to_vec(),
        Duration::from_millis(25),
    )
    .expect("quic streamed request");
    let bootstrap = run_two_chunk_bootstrap_post_to(
        listen_addr,
        harness.cert_path(),
        "localhost",
        "/stream-request",
        b"first-".to_vec(),
        b"second".to_vec(),
        Duration::from_millis(25),
    )
    .expect("bootstrap streamed request");

    assert!(!reset);
    assert_eq!(quic.status, 200);
    assert_eq!(bootstrap.status, 200);
    assert_eq!(quic.body, b"first-second");
    assert_eq!(bootstrap.body, quic.body);
}

#[test]
fn bootstrap_and_quic_streaming_response_bodies_match() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_chunked_backend(vec![b"first-", b"second", b"-third"]);
    start_single_route_listener(&mut harness, "/stream-response", backend_addr.to_string());

    let pair = harness
        .run_parity_pair(ParityRequestSpec::get("localhost", "/stream-response"))
        .expect("streaming response parity pair");

    assert_eq!(pair.quic.response.status, 200);
    assert_eq!(pair.bootstrap.response.status, 200);
    assert_eq!(pair.quic.response.body, b"first-second-third");
    assert_eq!(pair.bootstrap.response.body, pair.quic.response.body);
}

#[test]
#[ignore = "bootstrap path does not yet preserve upstream response trailers"]
fn bootstrap_and_quic_response_trailers_match() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let mut trailers = http::HeaderMap::new();
    trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
    trailers.insert("grpc-message", http::HeaderValue::from_static("ok"));
    let backend_addr = harness.start_h2_trailer_backend(vec![b"hello\n"], trailers);
    start_single_route_listener(&mut harness, "/trailers", format!("https://{backend_addr}"));

    let pair = harness
        .run_parity_pair(ParityRequestSpec::get("localhost", "/trailers"))
        .expect("trailer parity pair");

    assert_eq!(pair.quic.response.status, 200);
    assert_eq!(pair.bootstrap.response.status, 200);
    assert_eq!(pair.bootstrap.response.body, pair.quic.response.body);
    assert_eq!(
        pair.bootstrap.response.trailers,
        pair.quic.response.trailers
    );
    assert!(
        pair.quic
            .response
            .trailers
            .iter()
            .any(|(name, value)| { name.eq_ignore_ascii_case("grpc-status") && value == "0" })
    );
    assert!(
        pair.quic
            .response
            .trailers
            .iter()
            .any(|(name, value)| { name.eq_ignore_ascii_case("grpc-message") && value == "ok" })
    );
}

#[test]
#[serial]
fn bootstrap_and_quic_early_upstream_eof_reject_incomplete_bodies() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_raw_response_backend(
        b"HTTP/1.1 200 OK\r\ncontent-length: 12\r\nconnection: close\r\n\r\nshort".to_vec(),
    );
    start_single_route_listener(&mut harness, "/early-eof", backend_addr.to_string());
    let request = ParityRequestSpec::get("localhost", "/early-eof");

    assert!(harness.run_quic(request).is_err());
    assert!(harness.run_bootstrap(request).is_err());
}

#[test]
#[serial]
fn bootstrap_and_quic_downstream_cancellation_release_capacity() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_backend(|req: Request<Incoming>| async move {
        let _ = req.into_body().collect().await;
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"complete"))))
    });
    let mut config = harness.make_config(HashMap::from([(
        "api".to_string(),
        make_upstream(
            "/cancel",
            vec![make_backend("backend-a", backend_addr.to_string())],
            None,
            "round-robin",
        ),
    )]));
    config.performance.global_inflight_limit = 1;
    let listen_addr = harness
        .start_listener(config)
        .expect("listener with bootstrap");

    cancel_h3_post_to(listen_addr, "localhost", "/cancel").expect("cancel quic request");
    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        harness
            .run_quic(ParityRequestSpec::get("localhost", "/cancel"))
            .expect("quic request after cancellation")
            .response
            .status,
        200
    );

    cancel_bootstrap_post_to(listen_addr, harness.cert_path(), "localhost", "/cancel")
        .expect("cancel bootstrap request");
    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        harness
            .run_bootstrap(ParityRequestSpec::get("localhost", "/cancel"))
            .expect("bootstrap request after cancellation")
            .response
            .status,
        200
    );
}

#[test]
fn bootstrap_and_quic_response_normalization_strip_same_hop_headers() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_backend(|_req: Request<Incoming>| async move {
        Ok::<_, Infallible>(
            Response::builder()
                .status(200)
                .header("connection", "x-hop-token")
                .header("x-hop-token", "secret")
                .header("content-length", "9")
                .header("content-type", "text/plain")
                .header("cache-control", "max-age=60")
                .header("etag", "\"etag-1\"")
                .body(Full::new(Bytes::from_static(b"strip hop")))
                .expect("response"),
        )
    });

    start_single_route_listener(&mut harness, "/normalize-hop", backend_addr.to_string());

    let request = ParityRequestSpec {
        method: "GET",
        authority: "localhost",
        path: "/normalize-hop",
        headers: &[],
        body: None,
        user_agent: "impulse-bootstrap-quic-parity-test",
        selected_response_headers: &[
            "cache-control",
            "connection",
            "content-length",
            "content-type",
            "etag",
            "x-hop-token",
        ],
        capture_metrics_delta: false,
    };
    let pair = harness
        .run_parity_pair(request)
        .expect("response normalization parity pair");

    assert_eq!(pair.quic.response.status, 200);
    assert_eq!(pair.bootstrap.response.status, 200);
    assert_eq!(pair.quic.response.body, b"strip hop");
    assert_eq!(pair.bootstrap.response.body, pair.quic.response.body);
    assert_eq!(
        selected_header_value(&pair.quic.response, "cache-control"),
        Some("max-age=60")
    );
    assert_eq!(
        selected_header_value(&pair.bootstrap.response, "cache-control"),
        Some("max-age=60")
    );
    assert_eq!(
        selected_header_value(&pair.quic.response, "etag"),
        Some("\"etag-1\"")
    );
    assert_eq!(
        selected_header_value(&pair.bootstrap.response, "etag"),
        Some("\"etag-1\"")
    );
    for stripped in ["connection", "x-hop-token"] {
        assert_eq!(
            selected_header_value(&pair.quic.response, stripped),
            None,
            "quic should strip hop header `{stripped}`"
        );
        assert_eq!(
            selected_header_value(&pair.bootstrap.response, stripped),
            None,
            "bootstrap should strip hop header `{stripped}`"
        );
    }
    assert_eq!(
        selected_header_value(&pair.quic.response, "content-type"),
        Some("text/plain")
    );
    assert_eq!(
        selected_header_value(&pair.bootstrap.response, "content-type"),
        Some("text/plain")
    );
    assert_eq!(
        selected_header_value(&pair.quic.response, "content-length"),
        None,
        "quic should omit downstream content-length under HTTP/3 framing"
    );
    assert_eq!(
        selected_header_value(&pair.bootstrap.response, "content-length"),
        Some("9"),
        "bootstrap should preserve explicit content-length under HTTP compatibility ingress"
    );
}

#[test]
fn bootstrap_and_quic_response_normalization_head_bodyless_contract_matches() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_backend(|_req: Request<Incoming>| async move {
        Ok::<_, Infallible>(
            Response::builder()
                .status(200)
                .body(Full::new(Bytes::from_static(b"hidden head body")))
                .expect("response"),
        )
    });

    start_single_route_listener(&mut harness, "/head", backend_addr.to_string());

    let request = ParityRequestSpec {
        method: "HEAD",
        authority: "localhost",
        path: "/head",
        headers: &[],
        body: None,
        user_agent: "impulse-bootstrap-quic-parity-test",
        selected_response_headers: &["content-length", "content-type"],
        capture_metrics_delta: false,
    };
    let pair = harness.run_parity_pair(request).expect("head parity pair");

    assert_eq!(pair.quic.response.status, 200);
    assert_eq!(pair.bootstrap.response.status, 200);
    assert!(pair.quic.response.body.is_empty());
    assert!(pair.bootstrap.response.body.is_empty());
    assert_eq!(
        selected_header_value(&pair.quic.response, "content-type"),
        None
    );
    assert_eq!(
        selected_header_value(&pair.bootstrap.response, "content-type"),
        None
    );
    assert_eq!(
        selected_header_value(&pair.quic.response, "content-length"),
        None
    );
    assert_eq!(
        selected_header_value(&pair.bootstrap.response, "content-length"),
        Some("16")
    );
}

#[test]
fn bootstrap_and_quic_response_normalization_no_content_contract_matches() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_backend(|_req: Request<Incoming>| async move {
        Ok::<_, Infallible>(
            Response::builder()
                .status(204)
                .body(Full::new(Bytes::new()))
                .expect("response"),
        )
    });

    start_single_route_listener(&mut harness, "/no-content", backend_addr.to_string());

    let request = ParityRequestSpec {
        method: "GET",
        authority: "localhost",
        path: "/no-content",
        headers: &[],
        body: None,
        user_agent: "impulse-bootstrap-quic-parity-test",
        selected_response_headers: &["content-length", "content-type"],
        capture_metrics_delta: false,
    };
    let pair = harness
        .run_parity_pair(request)
        .expect("no content parity pair");

    assert_eq!(pair.quic.response.status, 204);
    assert_eq!(pair.bootstrap.response.status, 204);
    assert!(pair.quic.response.body.is_empty());
    assert!(pair.bootstrap.response.body.is_empty());
    assert_eq!(
        selected_header_value(&pair.quic.response, "content-type"),
        None
    );
    assert_eq!(
        selected_header_value(&pair.bootstrap.response, "content-type"),
        None
    );
    assert_eq!(
        selected_header_value(&pair.quic.response, "content-length"),
        None
    );
    assert_eq!(
        selected_header_value(&pair.bootstrap.response, "content-length"),
        None
    );
}

// Failure and guardrail parity

#[test]
#[serial]
fn bootstrap_and_quic_upstream_timeout_failures_share_observable_bucket() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_calls = Arc::new(AtomicUsize::new(0));
    let backend_observed = Arc::clone(&backend_calls);
    let backend_addr = harness.start_h1_backend(move |_req: Request<Incoming>| {
        let backend_observed = Arc::clone(&backend_observed);
        async move {
            backend_observed.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(300)).await;
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"too late"))))
        }
    });

    let mut config = harness.make_config(HashMap::from([(
        "api".to_string(),
        make_upstream(
            "/timeout",
            vec![make_backend("backend-a", backend_addr.to_string())],
            None,
            "round-robin",
        ),
    )]));
    config.performance.backend_timeout_ms = 150;
    config.performance.backend_connect_timeout_ms = 150;
    harness
        .start_listener(config)
        .expect("listener with bootstrap");

    let request = ParityRequestSpec::get("localhost", "/timeout");
    let pair = harness
        .run_parity_pair(request)
        .expect("timeout parity pair");

    assert_timeout_bucket(&pair.quic.response);
    assert_timeout_bucket(&pair.bootstrap.response);
    assert_eq!(pair.bootstrap.response.body, pair.quic.response.body);
    assert_eq!(backend_calls.load(Ordering::Relaxed), 2);
}

#[test]
#[serial]
fn bootstrap_and_quic_connect_failures_share_observable_bucket() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let unused_listener = TcpListener::bind("127.0.0.1:0").expect("bind unused backend port");
    let unused_addr = unused_listener.local_addr().expect("unused backend addr");
    drop(unused_listener);

    let mut config = harness.make_config(HashMap::from([(
        "api".to_string(),
        make_upstream(
            "/connect-fail",
            vec![make_backend("backend-a", format!("http://{unused_addr}"))],
            None,
            "round-robin",
        ),
    )]));
    config.performance.backend_timeout_ms = 150;
    config.performance.backend_connect_timeout_ms = 150;
    harness
        .start_listener(config)
        .expect("listener with bootstrap");

    let request = ParityRequestSpec::get("localhost", "/connect-fail");
    let pair = harness
        .run_parity_pair(request)
        .expect("connect failure parity pair");

    assert_eq!(pair.quic.response.status, 502);
    assert_eq!(pair.bootstrap.response.status, 502);
    assert_eq!(pair.bootstrap.response.body, pair.quic.response.body);
    assert!(
        String::from_utf8_lossy(&pair.quic.response.body).contains("upstream error"),
        "expected canonical transport failure body"
    );
}

#[test]
#[serial]
fn bootstrap_and_quic_malformed_upstream_responses_share_observable_bucket() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_raw_response_backend(b"NOT_HTTP\r\n\r\n".to_vec());

    let mut config = harness.make_config(HashMap::from([(
        "api".to_string(),
        make_upstream(
            "/malformed",
            vec![make_backend("backend-a", backend_addr.to_string())],
            None,
            "round-robin",
        ),
    )]));
    config.performance.backend_timeout_ms = 150;
    config.performance.backend_connect_timeout_ms = 150;
    harness
        .start_listener(config)
        .expect("listener with bootstrap");

    let request = ParityRequestSpec::get("localhost", "/malformed");
    let pair = harness
        .run_parity_pair(request)
        .expect("malformed upstream parity pair");

    assert_eq!(pair.quic.response.status, 502);
    assert_eq!(pair.bootstrap.response.status, 502);
    assert_eq!(pair.bootstrap.response.body, pair.quic.response.body);
    assert!(
        String::from_utf8_lossy(&pair.quic.response.body).contains("upstream error"),
        "expected canonical malformed-response body"
    );
}

#[test]
#[serial]
fn bootstrap_and_quic_request_body_too_large_guardrail_contract_matches() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_static_backend(b"backend upload");

    let mut config = harness.make_config(HashMap::from([(
        "api".to_string(),
        make_upstream(
            "/upload",
            vec![make_backend("backend-a", backend_addr.to_string())],
            None,
            "round-robin",
        ),
    )]));
    config.performance.max_request_body_bytes = 1024;
    let listen_addr = harness
        .start_listener(config)
        .expect("listener with bootstrap");

    let (quic_response, got_reset) = run_two_chunk_post_to(
        listen_addr,
        "localhost",
        "/upload",
        vec![0u8; 600],
        vec![0u8; 600],
        Duration::ZERO,
    )
    .expect("quic oversized request should complete");
    let bootstrap_response = run_two_chunk_bootstrap_post_to(
        listen_addr,
        harness.cert_path(),
        "localhost",
        "/upload",
        vec![0u8; 600],
        vec![0u8; 600],
        Duration::ZERO,
    )
    .expect("bootstrap oversized request should complete");

    assert_eq!(quic_response.status, 413);
    assert_eq!(bootstrap_response.status, 413);
    assert_eq!(bootstrap_response.body, quic_response.body);
    assert!(
        quic_response.body_text().contains("request body too large"),
        "expected canonical request body cap rejection body"
    );
    assert!(
        !got_reset,
        "quic oversized request should terminate with an HTTP response"
    );
}

#[test]
#[serial]
#[ignore = "bootstrap path does not yet share request-body idle-timeout guardrail semantics"]
fn bootstrap_and_quic_request_body_idle_timeout_guardrail_contract_matches() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_static_backend(b"unexpected backend call");

    let mut config = harness.make_config(HashMap::from([(
        "api".to_string(),
        make_upstream(
            "/upload-idle",
            vec![make_backend("backend-a", backend_addr.to_string())],
            None,
            "round-robin",
        ),
    )]));
    config.performance.client_body_idle_timeout_ms = 120;
    config.performance.backend_body_total_timeout_ms = 10_000;
    config.performance.backend_total_request_timeout_ms = 10_000;
    let listen_addr = harness
        .start_listener(config)
        .expect("listener with bootstrap");

    let (quic_response, got_reset) = run_two_chunk_post_to(
        listen_addr,
        "localhost",
        "/upload-idle",
        vec![0u8; 512],
        vec![0u8; 512],
        Duration::from_millis(250),
    )
    .expect("quic idle-timeout request should complete");
    let bootstrap_response = run_two_chunk_bootstrap_post_to(
        listen_addr,
        harness.cert_path(),
        "localhost",
        "/upload-idle",
        vec![0u8; 512],
        vec![0u8; 512],
        Duration::from_millis(250),
    )
    .expect("bootstrap idle-timeout request should complete");

    assert_eq!(quic_response.status, 408);
    assert_eq!(bootstrap_response.status, 408);
    assert_eq!(bootstrap_response.body, quic_response.body);
    assert!(
        quic_response
            .body_text()
            .contains("request body idle timeout"),
        "expected canonical request body idle-timeout body"
    );
    assert!(
        !got_reset,
        "quic request body idle timeout should return an HTTP response"
    );
}

#[test]
#[serial]
#[ignore = "bootstrap path does not yet share unknown-length response prebuffer guardrail semantics"]
fn bootstrap_and_quic_unknown_length_response_prebuffer_guardrail_contract_matches() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_chunked_backend(vec![b"chunk-1", b"chunk-2"]);

    let mut config = harness.make_config(HashMap::from([(
        "api".to_string(),
        make_upstream(
            "/long-stream",
            vec![make_backend("backend-a", backend_addr.to_string())],
            None,
            "round-robin",
        ),
    )]));
    config.performance.max_response_body_bytes = 64 * 1024;
    config.performance.unknown_length_response_prebuffer_bytes = 8;
    harness
        .start_listener(config)
        .expect("listener with bootstrap");

    let pair = harness
        .run_parity_pair(ParityRequestSpec::get("localhost", "/long-stream"))
        .expect("unknown-length response cap parity pair");

    assert_eq!(pair.quic.response.status, 503);
    assert_eq!(pair.bootstrap.response.status, 503);
    assert_eq!(pair.bootstrap.response.body, pair.quic.response.body);
    assert_eq!(
        pair.quic.response.body,
        b"upstream response body too large\n"
    );
}

#[test]
#[serial]
#[ignore = "bootstrap path does not yet share slow response-body timeout guardrail semantics"]
fn bootstrap_and_quic_slow_response_body_timeout_guardrail_contract_matches() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_delayed_chunked_backend(vec![
        (b"chunk-1".to_vec(), Duration::from_millis(250)),
        (b"chunk-2".to_vec(), Duration::ZERO),
    ]);

    let mut config = harness.make_config(HashMap::from([(
        "api".to_string(),
        make_upstream(
            "/slow-stream",
            vec![make_backend("backend-a", backend_addr.to_string())],
            None,
            "round-robin",
        ),
    )]));
    config.performance.backend_timeout_ms = 100;
    config.performance.backend_connect_timeout_ms = 100;
    config.performance.backend_body_total_timeout_ms = 5_000;
    config.performance.backend_body_idle_timeout_ms = 120;
    harness
        .start_listener(config)
        .expect("listener with bootstrap");

    let pair = harness
        .run_parity_pair(ParityRequestSpec::get("localhost", "/slow-stream"))
        .expect("slow response-body timeout parity pair");

    assert_timeout_bucket(&pair.quic.response);
    assert_timeout_bucket(&pair.bootstrap.response);
    assert_eq!(pair.bootstrap.response.body, pair.quic.response.body);
}

#[test]
#[serial]
fn bootstrap_and_quic_outcome_recording_success_bucket_matches() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_static_backend(b"metrics success");
    start_single_route_listener(&mut harness, "/metrics-success", backend_addr.to_string());

    let request = ParityRequestSpec {
        method: "GET",
        authority: "localhost",
        path: "/metrics-success",
        headers: &[],
        body: None,
        user_agent: "impulse-bootstrap-quic-parity-test",
        selected_response_headers: &[],
        capture_metrics_delta: true,
    };
    let pair = harness
        .run_parity_pair(request)
        .expect("success outcome parity pair");

    assert_eq!(pair.quic.response.status, 200);
    assert_eq!(pair.bootstrap.response.status, 200);

    let quic = OutcomeRecordingDelta::from_snapshot(require_metrics_delta(&pair.quic), "api");
    let bootstrap =
        OutcomeRecordingDelta::from_snapshot(require_metrics_delta(&pair.bootstrap), "api");
    let expected = OutcomeRecordingBuckets {
        success: true,
        failure: false,
        timeout: false,
        overload_shed: false,
        rate_limited: false,
    };
    assert_eq!(quic.coarse_buckets(), expected);
    assert_eq!(bootstrap.coarse_buckets(), expected);
}

#[test]
#[serial]
fn bootstrap_and_quic_outcome_recording_failure_bucket_matches() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let unused_listener = TcpListener::bind("127.0.0.1:0").expect("bind unused backend port");
    let unused_addr = unused_listener.local_addr().expect("unused backend addr");
    drop(unused_listener);

    let mut config = harness.make_config(HashMap::from([(
        "api".to_string(),
        make_upstream(
            "/metrics-failure",
            vec![make_backend("backend-a", format!("http://{unused_addr}"))],
            None,
            "round-robin",
        ),
    )]));
    config.performance.backend_timeout_ms = 150;
    config.performance.backend_connect_timeout_ms = 150;
    harness
        .start_listener(config)
        .expect("listener with bootstrap");

    let request = ParityRequestSpec {
        method: "GET",
        authority: "localhost",
        path: "/metrics-failure",
        headers: &[],
        body: None,
        user_agent: "impulse-bootstrap-quic-parity-test",
        selected_response_headers: &[],
        capture_metrics_delta: true,
    };
    let pair = harness
        .run_parity_pair(request)
        .expect("failure outcome parity pair");

    assert_eq!(pair.quic.response.status, 502);
    assert_eq!(pair.bootstrap.response.status, 502);

    let quic = OutcomeRecordingDelta::from_snapshot(require_metrics_delta(&pair.quic), "api");
    let bootstrap =
        OutcomeRecordingDelta::from_snapshot(require_metrics_delta(&pair.bootstrap), "api");
    let expected = OutcomeRecordingBuckets {
        success: false,
        failure: true,
        timeout: false,
        overload_shed: false,
        rate_limited: false,
    };
    assert_eq!(quic.coarse_buckets(), expected);
    assert_eq!(bootstrap.coarse_buckets(), expected);
}

#[test]
#[serial]
fn bootstrap_and_quic_outcome_recording_timeout_bucket_matches() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_backend(|_req: Request<Incoming>| async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"too late"))))
    });

    let mut config = harness.make_config(HashMap::from([(
        "api".to_string(),
        make_upstream(
            "/metrics-timeout",
            vec![make_backend("backend-a", backend_addr.to_string())],
            None,
            "round-robin",
        ),
    )]));
    config.performance.backend_timeout_ms = 150;
    config.performance.backend_connect_timeout_ms = 150;
    harness
        .start_listener(config)
        .expect("listener with bootstrap");

    let request = ParityRequestSpec {
        method: "GET",
        authority: "localhost",
        path: "/metrics-timeout",
        headers: &[],
        body: None,
        user_agent: "impulse-bootstrap-quic-parity-test",
        selected_response_headers: &[],
        capture_metrics_delta: true,
    };
    let pair = harness
        .run_parity_pair(request)
        .expect("timeout outcome parity pair");

    assert_timeout_bucket(&pair.quic.response);
    assert_timeout_bucket(&pair.bootstrap.response);

    let quic = OutcomeRecordingDelta::from_snapshot(require_metrics_delta(&pair.quic), "api");
    let bootstrap =
        OutcomeRecordingDelta::from_snapshot(require_metrics_delta(&pair.bootstrap), "api");
    let expected = OutcomeRecordingBuckets {
        success: false,
        failure: true,
        timeout: true,
        overload_shed: false,
        rate_limited: false,
    };
    assert_eq!(quic.coarse_buckets(), expected);
    assert_eq!(bootstrap.coarse_buckets(), expected);
}

#[test]
#[serial]
fn bootstrap_and_quic_outcome_recording_rate_limited_bucket_matches() {
    if !local_listener_bind_available() {
        return;
    }

    let quic = run_rate_limit_outcome_recording_scenario(IngressKind::Quic);
    let bootstrap = run_rate_limit_outcome_recording_scenario(IngressKind::Bootstrap);

    assert_eq!(quic.response.status, 429);
    assert_eq!(bootstrap.response.status, 429);
    assert_eq!(bootstrap.response.body, quic.response.body);
    assert_eq!(
        bootstrap.response.selected_headers,
        quic.response.selected_headers
    );
    let expected = OutcomeRecordingBuckets {
        success: true,
        failure: true,
        timeout: false,
        overload_shed: false,
        rate_limited: true,
    };
    assert_eq!(quic.metrics.coarse_buckets(), expected);
    assert_eq!(bootstrap.metrics.coarse_buckets(), expected);
    assert_eq!(quic.upstream_calls, 1);
    assert_eq!(bootstrap.upstream_calls, 1);
}

#[test]
#[serial]
#[ignore = "bootstrap path does not yet share post-auth admission overload semantics"]
fn bootstrap_and_quic_outcome_recording_overload_bucket_matches() {
    if !local_listener_bind_available() {
        return;
    }

    let quic = run_overload_outcome_recording_scenario(IngressKind::Quic);
    let bootstrap = run_overload_outcome_recording_scenario(IngressKind::Bootstrap);

    assert_eq!(quic.rejection.status, 503);
    assert_eq!(bootstrap.rejection.status, 503);
    assert_eq!(bootstrap.rejection.body, quic.rejection.body);
    assert_eq!(
        bootstrap.rejection.selected_headers,
        quic.rejection.selected_headers
    );
    let expected = OutcomeRecordingBuckets {
        success: true,
        failure: true,
        timeout: false,
        overload_shed: true,
        rate_limited: false,
    };
    assert_eq!(quic.metrics.coarse_buckets(), expected);
    assert_eq!(bootstrap.metrics.coarse_buckets(), expected);
    assert_eq!(quic.upstream_calls, 1);
    assert_eq!(bootstrap.upstream_calls, 1);
}

fn routed_upstream(
    host: Option<&str>,
    path_prefix: &str,
    method: Option<&str>,
    lb_type: &str,
    backends: Vec<impulse_config::config::Backend>,
) -> Upstream {
    let mut upstream = make_upstream(path_prefix, backends, None, lb_type);
    upstream.load_balancing = LoadBalancing {
        lb_type: lb_type.to_string(),
        key: None,
    };
    upstream.route = RouteMatch {
        host: host.map(str::to_string),
        path_prefix: Some(path_prefix.to_string()),
        method: method.map(str::to_string),
    };
    upstream
}

fn auth_protected_upstream(
    path_prefix: &str,
    backends: Vec<impulse_config::config::Backend>,
    auth: RouteAuth,
) -> Upstream {
    let mut upstream = make_upstream(path_prefix, backends, None, "round-robin");
    upstream.auth = auth;
    upstream
}

fn start_single_route_listener(
    harness: &mut BootstrapQuicParityHarness,
    path_prefix: &str,
    backend_address: String,
) {
    let config = harness.make_config(HashMap::from([(
        "api".to_string(),
        make_upstream(
            path_prefix,
            vec![make_backend("backend-a", backend_address)],
            None,
            "round-robin",
        ),
    )]));
    harness
        .start_listener(config)
        .expect("listener with bootstrap");
}

fn configure_http_external_auth(
    harness: &BootstrapQuicParityHarness,
    backend_address: String,
    auth_endpoint: String,
    timeout_ms: u64,
    failure_mode: ExternalAuthFailureMode,
    response_header_allowlist: Vec<String>,
) -> impulse_config::config::Config {
    let mut upstream = make_upstream(
        "/auth",
        vec![make_backend("auth-backend", backend_address)],
        None,
        "round-robin",
    );
    upstream.auth.external_auth = Some(ExternalAuth::Http {
        endpoint: auth_endpoint,
        request_headers: vec![ExternalAuthRequestHeader {
            name: "x-auth-static".to_string(),
            value: "1".to_string(),
        }],
        response_header_allowlist,
        timeout_ms,
        failure_mode,
    });

    let mut upstreams = HashMap::new();
    upstreams.insert("api".to_string(), upstream);
    harness.make_config(upstreams)
}

fn encode_test_hs256_jwt(secret: &str, claims: serde_json::Value) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({ "alg": "HS256", "typ": "JWT" }))
            .expect("serialize header"),
    );
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("serialize claims"));
    let signing_input = format!("{header}.{payload}");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("mac");
    mac.update(signing_input.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{signing_input}.{signature}")
}

fn encode_test_rs256_jwt(
    key: &boring::pkey::PKey<boring::pkey::Private>,
    kid: &str,
    claims: serde_json::Value,
) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use boring::{hash::MessageDigest, rsa::Padding, sign::Signer};

    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": kid }))
            .expect("serialize header"),
    );
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("serialize claims"));
    let signing_input = format!("{header}.{payload}");
    let mut signer = Signer::new(MessageDigest::sha256(), key).expect("rsa signer");
    signer.set_rsa_padding(Padding::PKCS1).expect("rsa padding");
    signer
        .update(signing_input.as_bytes())
        .expect("rsa signing input");
    let signature = URL_SAFE_NO_PAD.encode(signer.sign_to_vec().expect("rsa signature"));
    format!("{signing_input}.{signature}")
}

fn expected_selected_headers(headers: &[(&str, &str)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

fn selected_header_value<'a>(
    response: &'a support::parity::ParityResponseSnapshot,
    name: &str,
) -> Option<&'a str> {
    response
        .selected_headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn assert_timeout_bucket(response: &support::parity::ParityResponseSnapshot) {
    assert!(
        matches!(response.status, 503 | 504),
        "expected timeout bucket status, got {}",
        response.status
    );
    assert!(
        String::from_utf8_lossy(&response.body).contains("upstream timeout"),
        "expected canonical timeout body, got `{}`",
        String::from_utf8_lossy(&response.body)
    );
}

fn require_metrics_delta(
    observation: &support::parity::ParityObservation,
) -> &support::parity::MetricsDeltaSnapshot {
    observation
        .metrics_delta
        .as_ref()
        .expect("parity observation should include metrics delta")
}

fn metrics_counter(metrics: &str, prefix: &str) -> u64 {
    metrics
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_else(|| panic!("missing metrics counter `{prefix}` in metrics:\n{metrics}"))
}

fn metrics_delta(before: &str, after: &str, prefix: &str) -> u64 {
    metrics_counter(after, prefix).saturating_sub(metrics_counter(before, prefix))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OutcomeRecordingDelta {
    requests_success: u64,
    requests_failure: u64,
    route_success: u64,
    route_failure: u64,
    route_timeout: u64,
    route_overload_shed: u64,
    route_rate_limited: u64,
}

impl OutcomeRecordingDelta {
    fn from_snapshot(snapshot: &support::parity::MetricsDeltaSnapshot, route: &str) -> Self {
        Self::from_texts(&snapshot.before, &snapshot.after, route)
    }

    fn from_texts(before: &str, after: &str, route: &str) -> Self {
        Self {
            requests_success: metrics_delta(before, after, "impulse_requests_success "),
            requests_failure: metrics_delta(before, after, "impulse_requests_failure "),
            route_success: metrics_delta(
                before,
                after,
                &format!("impulse_route_success_total{{route=\"{route}\"}} "),
            ),
            route_failure: metrics_delta(
                before,
                after,
                &format!("impulse_route_failure_total{{route=\"{route}\"}} "),
            ),
            route_timeout: metrics_delta(
                before,
                after,
                &format!("impulse_route_timeout_total{{route=\"{route}\"}} "),
            ),
            route_overload_shed: metrics_delta(
                before,
                after,
                &format!("impulse_route_overload_shed_total{{route=\"{route}\"}} "),
            ),
            route_rate_limited: metrics_delta(
                before,
                after,
                &format!("impulse_route_rate_limited_total{{route=\"{route}\"}} "),
            ),
        }
    }

    fn saturating_add(self, other: Self) -> Self {
        Self {
            requests_success: self.requests_success.saturating_add(other.requests_success),
            requests_failure: self.requests_failure.saturating_add(other.requests_failure),
            route_success: self.route_success.saturating_add(other.route_success),
            route_failure: self.route_failure.saturating_add(other.route_failure),
            route_timeout: self.route_timeout.saturating_add(other.route_timeout),
            route_overload_shed: self
                .route_overload_shed
                .saturating_add(other.route_overload_shed),
            route_rate_limited: self
                .route_rate_limited
                .saturating_add(other.route_rate_limited),
        }
    }

    fn coarse_buckets(self) -> OutcomeRecordingBuckets {
        OutcomeRecordingBuckets {
            success: self.requests_success > 0 || self.route_success > 0,
            failure: self.requests_failure > 0 || self.route_failure > 0,
            timeout: self.route_timeout > 0,
            overload_shed: self.route_overload_shed > 0,
            rate_limited: self.route_rate_limited > 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OutcomeRecordingBuckets {
    success: bool,
    failure: bool,
    timeout: bool,
    overload_shed: bool,
    rate_limited: bool,
}

#[derive(Clone, Copy)]
struct ExternalAuthParityCase<'a> {
    name: &'a str,
    auth_status: u16,
    auth_headers: &'a [(&'a str, &'a str)],
    auth_body: &'a [u8],
    allowlist: &'a [&'a str],
    expected_status: u16,
    expected_body: &'a [u8],
    expected_headers: &'a [(&'a str, &'a str)],
}

#[derive(Clone, Copy)]
enum IngressKind {
    Quic,
    Bootstrap,
}

struct RejectionObservation {
    status: u16,
    body: String,
    headers: Vec<(String, String)>,
    upstream_calls: usize,
}

struct OutcomeRecordingObservation {
    response: support::parity::ParityResponseSnapshot,
    metrics: OutcomeRecordingDelta,
    upstream_calls: usize,
}

struct OverloadOutcomeRecordingObservation {
    rejection: support::parity::ParityResponseSnapshot,
    metrics: OutcomeRecordingDelta,
    upstream_calls: usize,
}

fn run_scoped_rate_limit_scenario(ingress: IngressKind) -> RejectionObservation {
    let mut harness = BootstrapQuicParityHarness::new();
    let upstream_calls = Arc::new(AtomicUsize::new(0));
    let backend_observed = Arc::clone(&upstream_calls);
    let backend_addr = harness.start_h1_backend(move |_req: Request<Incoming>| {
        let backend_observed = Arc::clone(&backend_observed);
        async move {
            backend_observed.fetch_add(1, Ordering::Relaxed);
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                b"rate-limit ok",
            ))))
        }
    });

    let mut config = harness.make_config(HashMap::from([(
        "api".to_string(),
        make_upstream(
            "/limited",
            vec![make_backend("backend-a", backend_addr.to_string())],
            None,
            "round-robin",
        ),
    )]));
    config.resilience.scoped_rate_limits = vec![ScopedRateLimit {
        name: "route-cap".to_string(),
        scope: ScopedRateLimitScope::Route,
        requests_per_sec: 1,
        burst: 1,
        key: None,
        route_allowlist: vec!["api".to_string()],
        idle_ttl_secs: 300,
    }];

    harness
        .start_listener(config)
        .expect("listener with bootstrap");

    let success = run_parity_ingress_request(
        ingress,
        &harness,
        ParityRequestSpec {
            method: "GET",
            authority: "localhost",
            path: "/limited",
            headers: &[],
            body: None,
            user_agent: "impulse-bootstrap-quic-parity-test",
            selected_response_headers: &[],
            capture_metrics_delta: false,
        },
    )
    .expect("first request should complete");
    assert_eq!(success.status, 200);

    let rejection = run_parity_ingress_request(
        ingress,
        &harness,
        ParityRequestSpec {
            method: "GET",
            authority: "localhost",
            path: "/limited",
            headers: &[],
            body: None,
            user_agent: "impulse-bootstrap-quic-parity-test",
            selected_response_headers: &["retry-after", "www-authenticate"],
            capture_metrics_delta: false,
        },
    )
    .expect("second request should complete");

    RejectionObservation {
        status: rejection.status,
        body: String::from_utf8_lossy(&rejection.body).into_owned(),
        headers: rejection.selected_headers,
        upstream_calls: upstream_calls.load(Ordering::Relaxed),
    }
}

fn run_distributed_quota_scenario(ingress: IngressKind) -> RejectionObservation {
    let mut harness = BootstrapQuicParityHarness::new();
    let upstream_calls = Arc::new(AtomicUsize::new(0));
    let backend_observed = Arc::clone(&upstream_calls);
    let backend_addr = harness.start_h1_backend(move |_req: Request<Incoming>| {
        let backend_observed = Arc::clone(&backend_observed);
        async move {
            backend_observed.fetch_add(1, Ordering::Relaxed);
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"quota ok"))))
        }
    });

    let mut config = harness.make_config(HashMap::from([(
        "api".to_string(),
        make_upstream(
            "/quota",
            vec![make_backend("backend-a", backend_addr.to_string())],
            None,
            "round-robin",
        ),
    )]));
    config.resilience.quota.enabled = true;
    config.resilience.quota.backend = QuotaCounterBackend::InMemory {
        key_prefix: "impulse:test:parity".to_string(),
    };
    config.resilience.quota.policies = vec![DistributedQuotaPolicy {
        name: "route-burst".to_string(),
        route_allowlist: vec!["api".to_string()],
        selector: DistributedQuotaSelector {
            route: true,
            ..DistributedQuotaSelector::default()
        },
        burst: Some(DistributedQuotaWindow {
            requests: 1,
            window_secs: 60,
        }),
        sustained: None,
    }];
    harness
        .start_listener(config)
        .expect("listener with bootstrap");

    let request = ParityRequestSpec::get("localhost", "/quota");
    let success = run_parity_ingress_request(ingress, &harness, request)
        .expect("first request should complete");
    assert_eq!(success.status, 200);

    let rejection = run_parity_ingress_request(
        ingress,
        &harness,
        ParityRequestSpec {
            selected_response_headers: &["retry-after"],
            ..request
        },
    )
    .expect("second request should complete");

    RejectionObservation {
        status: rejection.status,
        body: String::from_utf8_lossy(&rejection.body).into_owned(),
        headers: rejection.selected_headers,
        upstream_calls: upstream_calls.load(Ordering::Relaxed),
    }
}

fn run_overload_shed_scenario(ingress: IngressKind) -> RejectionObservation {
    let mut harness = BootstrapQuicParityHarness::new();
    let upstream_calls = Arc::new(AtomicUsize::new(0));
    let backend_observed = Arc::clone(&upstream_calls);
    let backend_addr = harness.start_h1_backend(move |_req: Request<Incoming>| {
        let backend_observed = Arc::clone(&backend_observed);
        async move {
            backend_observed.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(250)).await;
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"slow ok"))))
        }
    });

    let mut config = harness.make_config(HashMap::from([(
        "api".to_string(),
        make_upstream(
            "/slow",
            vec![make_backend("backend-a", backend_addr.to_string())],
            None,
            "round-robin",
        ),
    )]));
    config.performance.global_inflight_limit = 64;
    config.resilience.route_queue.default_cap = 1;
    config.resilience.route_queue.global_cap = 64;
    harness
        .start_listener(config)
        .expect("listener with bootstrap");
    let listen_addr = harness.listen_addr();
    let cert_path = harness.cert_path().to_string();

    let first_request = thread::spawn({
        let cert_path = cert_path.clone();
        move || {
            execute_ingress_request(
                ingress,
                listen_addr,
                &cert_path,
                ParityRequestSpec::get("localhost", "/slow"),
            )
        }
    });

    for _ in 0..50 {
        if upstream_calls.load(Ordering::Relaxed) > 0 {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let rejection = execute_ingress_request(
        ingress,
        listen_addr,
        &cert_path,
        ParityRequestSpec {
            method: "GET",
            authority: "localhost",
            path: "/slow",
            headers: &[],
            body: None,
            user_agent: "impulse-bootstrap-quic-parity-test",
            selected_response_headers: &["retry-after", "www-authenticate"],
            capture_metrics_delta: false,
        },
    )
    .expect("second request should complete");
    let first_response = first_request
        .join()
        .expect("first request thread")
        .expect("first request should complete");
    assert_eq!(first_response.status, 200);

    RejectionObservation {
        status: rejection.status,
        body: String::from_utf8_lossy(&rejection.body).into_owned(),
        headers: rejection.selected_headers,
        upstream_calls: upstream_calls.load(Ordering::Relaxed),
    }
}

// Protocol edge-case parity

#[test]
fn bootstrap_and_quic_connect_policy_rejections_match() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_static_backend(b"unexpected CONNECT forwarding");
    start_single_route_listener(&mut harness, "/", backend_addr.to_string());

    let request = ParityRequestSpec {
        method: "CONNECT",
        authority: "localhost:443",
        path: "/",
        headers: &[],
        body: None,
        user_agent: "impulse-bootstrap-quic-parity-test",
        selected_response_headers: &[],
        capture_metrics_delta: false,
    };
    let pair = harness
        .run_parity_pair(request)
        .expect("CONNECT parity pair");

    assert_eq!(pair.quic.response.status, 403);
    assert_eq!(pair.bootstrap.response.status, 403);
    assert_eq!(pair.bootstrap.response.body, pair.quic.response.body);
    assert_eq!(
        pair.quic.response.body,
        b"CONNECT target denied by policy\n"
    );
}

#[test]
fn bootstrap_and_quic_malformed_content_length_rejections_match() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_static_backend(b"unexpected malformed forwarding");
    start_single_route_listener(&mut harness, "/malformed-framing", backend_addr.to_string());

    let request = ParityRequestSpec {
        method: "POST",
        authority: "localhost",
        path: "/malformed-framing",
        headers: &[("content-length", "not-a-number")],
        body: None,
        user_agent: "impulse-bootstrap-quic-parity-test",
        selected_response_headers: &[],
        capture_metrics_delta: false,
    };
    let quic = harness
        .run_quic(request)
        .expect("quic malformed framing response");

    assert_eq!(quic.response.status, 400);
    assert_eq!(quic.response.body, b"invalid content-length header\n");
    assert!(
        harness.run_bootstrap(request).is_err(),
        "HTTP/2 must reject an invalid content-length before application dispatch"
    );
}

#[test]
fn bootstrap_and_quic_forwarded_header_normalization_matches() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_backend(|req: Request<Incoming>| async move {
        let value = |name: &str| {
            req.headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("<missing>")
                .to_string()
        };
        let body = format!(
            "forwarded={}\nxff={}\nxfp={}\nxfh={}\nhost={}\n",
            value("forwarded"),
            value("x-forwarded-for"),
            value("x-forwarded-proto"),
            value("x-forwarded-host"),
            value("host"),
        );
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
    });
    start_single_route_listener(&mut harness, "/forwarded", backend_addr.to_string());

    let pair = harness
        .run_parity_pair(ParityRequestSpec {
            method: "GET",
            authority: "public.example.com",
            path: "/forwarded",
            headers: &[
                ("forwarded", "for=1.2.3.4;proto=http;host=evil.example"),
                ("x-forwarded-for", "1.2.3.4"),
                ("x-forwarded-proto", "http"),
                ("x-forwarded-host", "evil.example"),
            ],
            body: None,
            user_agent: "impulse-bootstrap-quic-parity-test",
            selected_response_headers: &[],
            capture_metrics_delta: false,
        })
        .expect("forwarded header parity pair");

    assert_eq!(pair.quic.response.status, 200);
    assert_eq!(pair.bootstrap.response.status, 200);
    assert_eq!(pair.bootstrap.response.body, pair.quic.response.body);
    let body = String::from_utf8_lossy(&pair.quic.response.body);
    assert!(body.contains("forwarded=for=127.0.0.1;proto=https;host=\"public.example.com\"\n"));
    assert!(body.contains("xff=127.0.0.1\n"));
    assert!(body.contains("xfp=https\n"));
    assert!(body.contains("xfh=public.example.com\n"));
    assert!(body.contains("host=public.example.com\n"));
}

#[test]
fn bootstrap_and_quic_authority_host_disagreement_rejections_match() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_static_backend(b"unexpected authority forwarding");
    start_single_route_listener(&mut harness, "/authority", backend_addr.to_string());
    let listen_addr = harness.listen_addr();

    let quic = run_request_to(
        listen_addr,
        H3RequestSpec {
            method: "GET",
            authority: "public.example.com",
            path: "/authority",
            headers: &[("host", "other.example.com")],
            body: None,
            user_agent: "impulse-bootstrap-quic-parity-test",
        },
    )
    .expect("quic authority disagreement response");
    let bootstrap = run_bootstrap_authority_host_request_to(
        listen_addr,
        harness.cert_path(),
        "GET",
        "public.example.com",
        "other.example.com",
        "/authority",
    )
    .expect("bootstrap authority disagreement response");

    assert_eq!(quic.status, 400);
    assert_eq!(bootstrap.status, 400);
    assert_eq!(quic.body, b":authority and host headers must match\n");
    assert_eq!(bootstrap.body, b"authority and host headers must match\n");
}

#[test]
#[serial]
fn bootstrap_websocket_upgrade_is_an_explicit_quic_parity_boundary() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = BootstrapQuicParityHarness::new();
    let backend_addr = harness.start_h1_websocket_upgrade_backend();
    start_single_route_listener(&mut harness, "/ws", backend_addr.to_string());
    let listen_addr = harness.listen_addr();

    let bootstrap = run_bootstrap_h1_websocket_handshake_to(
        listen_addr,
        harness.cert_path(),
        "localhost",
        "/ws",
    )
    .expect("bootstrap websocket handshake");
    let quic = run_request_to(
        listen_addr,
        H3RequestSpec {
            method: "GET",
            authority: "localhost",
            path: "/ws",
            headers: &[
                ("connection", "Upgrade"),
                ("upgrade", "websocket"),
                ("sec-websocket-version", "13"),
            ],
            body: None,
            user_agent: "impulse-bootstrap-quic-parity-test",
        },
    )
    .expect("quic websocket request");

    assert_eq!(
        bootstrap.status, 101,
        "bootstrap keeps HTTP/1.1 upgrade mechanics as a compatibility ingress contract"
    );
    assert!(bootstrap.body.is_empty());
    assert_eq!(bootstrap.header("connection"), Some("upgrade"));
    assert_eq!(bootstrap.header("upgrade"), Some("websocket"));
    assert_eq!(
        bootstrap.header("sec-websocket-accept"),
        Some("test-accept")
    );

    assert_eq!(
        quic.status, 400,
        "HTTP/3 must reject HTTP/1.1 WebSocket upgrade semantics"
    );
    assert_eq!(quic.body, b"HTTP/3 does not support Upgrade requests\n");
    assert_eq!(quic.header("sec-websocket-accept"), None);
    assert_eq!(
        quic.header("connection"),
        None,
        "HTTP/3 websocket tunneling should not expose bootstrap's upgrade header contract"
    );
    assert_eq!(
        quic.header("upgrade"),
        None,
        "HTTP/3 websocket tunneling should not expose bootstrap's upgrade header contract"
    );
    assert_ne!(
        bootstrap.status, quic.status,
        "the parity suite should document websocket/upgrade as an intentional ingress boundary, not a shared contract"
    );
}

// Observability parity

fn run_rate_limit_outcome_recording_scenario(ingress: IngressKind) -> OutcomeRecordingObservation {
    let mut harness = BootstrapQuicParityHarness::new();
    let upstream_calls = Arc::new(AtomicUsize::new(0));
    let backend_observed = Arc::clone(&upstream_calls);
    let backend_addr = harness.start_h1_backend(move |_req: Request<Incoming>| {
        let backend_observed = Arc::clone(&backend_observed);
        async move {
            backend_observed.fetch_add(1, Ordering::Relaxed);
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                b"rate-limit ok",
            ))))
        }
    });

    let mut config = harness.make_config(HashMap::from([(
        "api".to_string(),
        make_upstream(
            "/metrics-rate-limit",
            vec![make_backend("backend-a", backend_addr.to_string())],
            None,
            "round-robin",
        ),
    )]));
    config.resilience.scoped_rate_limits = vec![ScopedRateLimit {
        name: "route-cap".to_string(),
        scope: ScopedRateLimitScope::Route,
        requests_per_sec: 1,
        burst: 1,
        key: None,
        route_allowlist: vec!["api".to_string()],
        idle_ttl_secs: 300,
    }];
    harness
        .start_listener(config)
        .expect("listener with bootstrap");

    let success = run_parity_ingress_observation(
        ingress,
        &harness,
        ParityRequestSpec {
            method: "GET",
            authority: "localhost",
            path: "/metrics-rate-limit",
            headers: &[],
            body: None,
            user_agent: "impulse-bootstrap-quic-parity-test",
            selected_response_headers: &[],
            capture_metrics_delta: true,
        },
    )
    .expect("first request should complete");
    assert_eq!(success.response.status, 200);

    let rejection = run_parity_ingress_observation(
        ingress,
        &harness,
        ParityRequestSpec {
            method: "GET",
            authority: "localhost",
            path: "/metrics-rate-limit",
            headers: &[],
            body: None,
            user_agent: "impulse-bootstrap-quic-parity-test",
            selected_response_headers: &["retry-after"],
            capture_metrics_delta: true,
        },
    )
    .expect("rate-limited request should complete");

    let metrics = OutcomeRecordingDelta::from_snapshot(require_metrics_delta(&success), "api")
        .saturating_add(OutcomeRecordingDelta::from_snapshot(
            require_metrics_delta(&rejection),
            "api",
        ));

    OutcomeRecordingObservation {
        response: rejection.response,
        metrics,
        upstream_calls: upstream_calls.load(Ordering::Relaxed),
    }
}

fn run_overload_outcome_recording_scenario(
    ingress: IngressKind,
) -> OverloadOutcomeRecordingObservation {
    let mut harness = BootstrapQuicParityHarness::new();
    let upstream_calls = Arc::new(AtomicUsize::new(0));
    let backend_observed = Arc::clone(&upstream_calls);
    let backend_addr = harness.start_h1_backend(move |_req: Request<Incoming>| {
        let backend_observed = Arc::clone(&backend_observed);
        async move {
            backend_observed.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(250)).await;
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"slow ok"))))
        }
    });

    let mut config = harness.make_config(HashMap::from([(
        "api".to_string(),
        make_upstream(
            "/metrics-overload",
            vec![make_backend("backend-a", backend_addr.to_string())],
            None,
            "round-robin",
        ),
    )]));
    config.performance.global_inflight_limit = 64;
    config.resilience.route_queue.default_cap = 1;
    config.resilience.route_queue.global_cap = 64;
    harness
        .start_listener(config)
        .expect("listener with bootstrap");

    let before = harness
        .metrics_text()
        .expect("metrics snapshot before overload scenario");
    let listen_addr = harness.listen_addr();
    let cert_path = harness.cert_path().to_string();

    let first_request = thread::spawn({
        let cert_path = cert_path.clone();
        move || {
            execute_ingress_request(
                ingress,
                listen_addr,
                &cert_path,
                ParityRequestSpec::get("localhost", "/metrics-overload"),
            )
        }
    });

    for _ in 0..50 {
        if upstream_calls.load(Ordering::Relaxed) > 0 {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let rejection = execute_ingress_request(
        ingress,
        listen_addr,
        &cert_path,
        ParityRequestSpec {
            method: "GET",
            authority: "localhost",
            path: "/metrics-overload",
            headers: &[],
            body: None,
            user_agent: "impulse-bootstrap-quic-parity-test",
            selected_response_headers: &["retry-after"],
            capture_metrics_delta: false,
        },
    )
    .expect("second request should complete");
    let first_response = first_request
        .join()
        .expect("first request thread")
        .expect("first request should complete");
    assert_eq!(first_response.status, 200);

    let after = harness
        .metrics_text()
        .expect("metrics snapshot after overload scenario");

    OverloadOutcomeRecordingObservation {
        rejection,
        metrics: OutcomeRecordingDelta::from_texts(&before, &after, "api"),
        upstream_calls: upstream_calls.load(Ordering::Relaxed),
    }
}

fn run_parity_ingress_request(
    ingress: IngressKind,
    harness: &BootstrapQuicParityHarness,
    request: ParityRequestSpec<'_>,
) -> Result<support::parity::ParityResponseSnapshot, String> {
    let observation = match ingress {
        IngressKind::Quic => harness.run_quic(request)?,
        IngressKind::Bootstrap => harness.run_bootstrap(request)?,
    };
    Ok(observation.response)
}

fn run_parity_ingress_observation(
    ingress: IngressKind,
    harness: &BootstrapQuicParityHarness,
    request: ParityRequestSpec<'_>,
) -> Result<support::parity::ParityObservation, String> {
    match ingress {
        IngressKind::Quic => harness.run_quic(request),
        IngressKind::Bootstrap => harness.run_bootstrap(request),
    }
}

fn execute_ingress_request(
    ingress: IngressKind,
    listen_addr: std::net::SocketAddr,
    cert_path: &str,
    request: ParityRequestSpec<'_>,
) -> Result<support::parity::ParityResponseSnapshot, String> {
    match ingress {
        IngressKind::Quic => {
            let response = run_request_to(
                listen_addr,
                H3RequestSpec {
                    method: request.method,
                    authority: request.authority,
                    path: request.path,
                    headers: request.headers,
                    body: request.body,
                    user_agent: request.user_agent,
                },
            )?;
            Ok(parity_snapshot_from_response(
                response.status,
                response.body,
                response.headers,
                request.selected_response_headers,
            ))
        }
        IngressKind::Bootstrap => {
            let response = run_bootstrap_request_to(
                listen_addr,
                cert_path,
                BootstrapRequestSpec {
                    method: request.method,
                    authority: request.authority,
                    path: request.path,
                    headers: request.headers,
                    body: request.body,
                    user_agent: request.user_agent,
                },
            )?;
            Ok(parity_snapshot_from_response(
                response.status,
                response.body,
                response.headers,
                request.selected_response_headers,
            ))
        }
    }
}

fn parity_snapshot_from_response(
    status: u16,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
    selected_response_headers: &[&str],
) -> support::parity::ParityResponseSnapshot {
    let mut selected_headers = headers
        .into_iter()
        .filter(|(name, _)| {
            selected_response_headers
                .iter()
                .any(|selected| name.eq_ignore_ascii_case(selected))
        })
        .collect::<Vec<_>>();
    selected_headers.sort_by(|left, right| {
        left.0
            .to_ascii_lowercase()
            .cmp(&right.0.to_ascii_lowercase())
            .then_with(|| left.1.cmp(&right.1))
    });

    support::parity::ParityResponseSnapshot {
        status,
        body,
        selected_headers,
        trailers: Vec::new(),
    }
}
