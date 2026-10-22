use super::*;

#[test]
fn http3_to_http2_preserves_response_trailers() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);

    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let backend_addr = rt.block_on(start_h2_backend_with_trailers(&cert, &key));
    let config = make_h2_config(0, backend_addr, cert, key);
    let listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    let (status, body, trailers) =
        run_h3_client_collect_trailers(listen_addr, "/").expect("client trailer request failed");

    assert_eq!(status, "200");
    assert_eq!(body, b"hello\n");
    assert!(
        trailers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("grpc-status") && value == "0"),
        "expected grpc-status trailer, got {trailers:?}"
    );
    assert!(
        trailers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("grpc-message") && value == "ok"),
        "expected grpc-message trailer, got {trailers:?}"
    );
}

#[test]
fn pingora_http1_websocket_upgrade_preserves_switching_protocols_headers() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);

    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let backend_addr = rt.block_on(start_h1_backend_with_websocket_upgrade());
    let listen_port = find_free_tcp_port();
    let config = make_config(
        u32::from(listen_port),
        format!("http://{backend_addr}"),
        cert.clone(),
        key,
    );
    let (listener, _pingora_listener) = make_listener_with_pingora(&rt, config);
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    let pingora_addr = SocketAddr::new(listen_addr.ip(), listen_port);
    let (status, headers) = rt
        .block_on(run_http1_websocket_handshake(pingora_addr, &cert, "/ws"))
        .expect("Pingora websocket handshake failed");

    assert_eq!(status, StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(
        headers
            .get(http::header::CONNECTION)
            .and_then(|value| value.to_str().ok()),
        Some("upgrade")
    );
    assert_eq!(
        headers
            .get(http::header::UPGRADE)
            .and_then(|value| value.to_str().ok()),
        Some("websocket")
    );
    assert_eq!(
        headers
            .get("sec-websocket-accept")
            .and_then(|value| value.to_str().ok()),
        Some("test-accept")
    );
}

#[test]
fn pingora_h2_preserves_response_trailers() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);

    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let backend_addr = rt.block_on(start_h2_backend_with_trailers(&cert, &key));
    let listen_port = find_free_tcp_port();
    let config = make_h2_config(u32::from(listen_port), backend_addr, cert.clone(), key);
    let (listener, _pingora_listener) = make_listener_with_pingora(&rt, config);
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    let pingora_addr = SocketAddr::new(listen_addr.ip(), listen_port);
    let (status, body, trailers) = rt
        .block_on(run_http2_client_collect_trailers(pingora_addr, &cert, "/"))
        .expect("Pingora trailer request failed");

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"hello\n");
    assert!(
        trailers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("grpc-status") && value == "0"),
        "expected grpc-status trailer, got {trailers:?}"
    );
    assert!(
        trailers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("grpc-message") && value == "ok"),
        "expected grpc-message trailer, got {trailers:?}"
    );
}

#[test]
#[serial_test::serial]
fn http3_sni_selects_exact_and_fallback_certificates_on_real_handshake() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (fallback_cert, fallback_key) =
        write_named_test_cert(&dir, "fallback", &["fallback.example.com"], &[]);
    let (api_cert, api_key) = write_named_test_cert(&dir, "api", &["api.example.com"], &[]);
    let expected_api_der = read_test_leaf_der(&api_cert).expect("api cert der");
    let expected_fallback_der = read_test_leaf_der(&fallback_cert).expect("fallback cert der");
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let backend_addr = rt.block_on(start_h2_backend());

    let listen_port = find_free_tcp_port();
    let mut config = make_config(
        listen_port as u32,
        backend_addr.to_string(),
        fallback_cert.clone(),
        fallback_key,
    );
    config.listen.tls.certificates = vec![TlsCertificate {
        server_name: "api.example.com".to_string(),
        cert: api_cert.clone(),
        key: api_key,
    }];

    let _enter = rt.enter();
    let (listener, _pingora_listener) = make_listener_with_pingora(&rt, config);
    drop(_enter);
    let listen_addr = listener.socket.local_addr().expect("listener addr");
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    let exact = run_h3_client_with_tls(
        listen_addr,
        H3TlsClientOptions {
            server_name: "api.example.com",
            authority: "api.example.com",
            path: "/",
            verify_peer: false,
            root_cert_path: None,
            client_identity: None,
            application_protos: quiche::h3::APPLICATION_PROTOCOL,
            send_request: true,
        },
    )
    .expect("exact sni client request failed");
    assert_eq!(exact.alpn, b"h3");
    assert_eq!(
        exact.peer_cert.as_deref(),
        Some(expected_api_der.as_slice()),
        "exact SNI should select api.example.com certificate"
    );
    assert_eq!(String::from_utf8_lossy(&exact.body), "backend ok\n");

    let fallback = run_h3_client_with_tls(
        listen_addr,
        H3TlsClientOptions {
            server_name: "other.example.com",
            authority: "other.example.com",
            path: "/",
            verify_peer: false,
            root_cert_path: None,
            client_identity: None,
            application_protos: quiche::h3::APPLICATION_PROTOCOL,
            send_request: true,
        },
    )
    .expect("fallback sni client request failed");
    assert_eq!(fallback.alpn, b"h3");
    assert_eq!(
        fallback.peer_cert.as_deref(),
        Some(expected_fallback_der.as_slice()),
        "unmatched SNI should fall back to default certificate"
    );
    assert_eq!(String::from_utf8_lossy(&fallback.body), "backend ok\n");
}

#[test]
#[serial_test::serial]
fn pingora_h2_optional_client_auth_allows_requests_without_certificate() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);
    let (ca_cert, _client_cert, _client_key) =
        write_test_ca_and_client_cert(&dir, "client-ca", "client.example.com");
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let backend_addr = rt.block_on(start_h2_backend());

    let listen_port = find_free_tcp_port();
    let mut config = make_config(
        listen_port as u32,
        backend_addr.to_string(),
        cert.clone(),
        key,
    );
    config.listen.tls.client_auth = ClientAuth {
        enabled: true,
        require_client_cert: false,
        ca_file: Some(ca_cert),
    };

    let _enter = rt.enter();
    let (listener, _pingora_listener) = make_listener_with_pingora(&rt, config);
    drop(_enter);
    let listen_addr = listener.socket.local_addr().expect("listener addr");
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);
    let pingora_addr = SocketAddr::new(listen_addr.ip(), listen_port);

    let response = rt
        .block_on(run_http2_client_request(
            pingora_addr,
            &cert,
            "GET",
            "/",
            &[],
        ))
        .expect("optional client-auth request failed");
    assert_eq!(response.0, StatusCode::OK);
    assert_eq!(String::from_utf8_lossy(&response.1), "backend ok\n");
}

#[test]
#[serial_test::serial]
fn pingora_h2_required_client_auth_rejects_missing_certificate_and_accepts_valid_certificate() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);
    let (ca_cert, client_cert, client_key) =
        write_test_ca_and_client_cert(&dir, "client-ca", "client.example.com");
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let backend_addr = rt.block_on(start_h2_backend());

    let listen_port = find_free_tcp_port();
    let mut config = make_config(
        listen_port as u32,
        backend_addr.to_string(),
        cert.clone(),
        key,
    );
    config.listen.tls.client_auth = ClientAuth {
        enabled: true,
        require_client_cert: true,
        ca_file: Some(ca_cert.clone()),
    };

    let _enter = rt.enter();
    let (listener, _pingora_listener) = make_listener_with_pingora(&rt, config);
    drop(_enter);
    let listen_addr = listener.socket.local_addr().expect("listener addr");
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);
    let pingora_addr = SocketAddr::new(listen_addr.ip(), listen_port);

    let missing_cert_err = rt
        .block_on(run_http2_client_request_with_client_auth(
            pingora_addr,
            &cert,
            "GET",
            "/",
            &[],
            None,
        ))
        .expect_err("missing client certificate should fail");
    assert!(
        missing_cert_err.contains("tls connect")
            || missing_cert_err.contains("sender ready")
            || missing_cert_err.contains("send request"),
        "unexpected missing-client-cert error: {missing_cert_err}"
    );

    let response = rt
        .block_on(run_http2_client_request_with_client_auth(
            pingora_addr,
            &cert,
            "GET",
            "/",
            &[],
            Some((&client_cert, &client_key)),
        ))
        .expect("client-authenticated Pingora request failed");
    assert_eq!(response.0, StatusCode::OK);
    assert_eq!(String::from_utf8_lossy(&response.1), "backend ok\n");
}

#[test]
#[serial_test::serial]
fn quic_tls_metrics_capture_selection_and_failures() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (fallback_cert, fallback_key) =
        write_named_test_cert(&dir, "fallback", &["fallback.example.com"], &[]);
    let (api_cert, api_key) = write_named_test_cert(&dir, "api", &["api.example.com"], &[]);
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let backend_addr = rt.block_on(start_h2_backend());

    let listen_port = find_free_tcp_port();
    let metrics_port = find_free_tcp_port();
    let mut config = make_config(
        listen_port as u32,
        backend_addr.to_string(),
        fallback_cert.clone(),
        fallback_key,
    );
    config.listen.tls.certificates = vec![TlsCertificate {
        server_name: "api.example.com".to_string(),
        cert: api_cert,
        key: api_key,
    }];
    config.observability.metrics.enabled = true;
    config.observability.metrics.address = "127.0.0.1".to_string();
    config.observability.metrics.port = metrics_port;
    config.observability.metrics.path = "/metrics".to_string();

    let _enter = rt.enter();
    let (listener, _pingora_listener) = make_listener_with_pingora(&rt, config);
    drop(_enter);
    let listen_addr = listener.socket.local_addr().expect("listener addr");
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    run_h3_client_with_tls(
        listen_addr,
        H3TlsClientOptions {
            server_name: "api.example.com",
            authority: "api.example.com",
            path: "/",
            verify_peer: false,
            root_cert_path: None,
            client_identity: None,
            application_protos: quiche::h3::APPLICATION_PROTOCOL,
            send_request: true,
        },
    )
    .expect("exact sni request failed");
    run_h3_client_with_tls(
        listen_addr,
        H3TlsClientOptions {
            server_name: "other.example.com",
            authority: "other.example.com",
            path: "/",
            verify_peer: false,
            root_cert_path: None,
            client_identity: None,
            application_protos: quiche::h3::APPLICATION_PROTOCOL,
            send_request: true,
        },
    )
    .expect("fallback sni request failed");
    let metrics = rt
        .block_on(scrape_metrics(
            metrics_port,
            "/metrics",
            Duration::from_secs(20),
        ))
        .expect("metrics endpoint should become reachable");
    assert!(
        metrics
            .contains("impulse_downstream_tls_certificate_selection_total{listener=\"127.0.0.1:")
    );
    assert!(metrics.contains("selection=\"exact_sni\""));
    assert!(metrics.contains("selection=\"fallback_unmatched_sni\""));
    assert!(metrics.contains("impulse_downstream_tls_alpn_total"));
    assert!(metrics.contains("protocol=\"h3\""));
}

#[test]
fn http3_head_suppresses_response_body() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);

    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let backend_addr = rt.block_on(start_h2_backend_with_regression_routes());
    let config = make_config(0, backend_addr.to_string(), cert, key);
    let listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    let response = run_h3_client_collect_response(
        listen_addr,
        vec![
            quiche::h3::Header::new(b":method", b"HEAD"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"localhost"),
            quiche::h3::Header::new(b":path", b"/stream"),
            quiche::h3::Header::new(b"user-agent", b"impulse-regression-test"),
        ],
        true,
        Duration::from_secs(REQUEST_TIMEOUT_SECS),
    )
    .expect("HEAD request failed");

    assert_eq!(response.status, "200");
    assert!(
        response.body.is_empty(),
        "HEAD response must not include a body"
    );
    assert!(!response.reset, "HEAD response should complete cleanly");
}

#[test]
fn http3_websocket_legacy_upgrade_is_rejected() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);

    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let backend_addr = rt.block_on(start_h1_backend_with_websocket_upgrade());
    let config = make_config(0, format!("http://{backend_addr}"), cert, key);
    let listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    let response = run_h3_client_collect_response(
        listen_addr,
        vec![
            quiche::h3::Header::new(b":method", b"GET"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"localhost"),
            quiche::h3::Header::new(b":path", b"/ws"),
            quiche::h3::Header::new(b"connection", b"Upgrade"),
            quiche::h3::Header::new(b"upgrade", b"websocket"),
            quiche::h3::Header::new(b"sec-websocket-version", b"13"),
        ],
        true,
        Duration::from_secs(REQUEST_TIMEOUT_SECS),
    )
    .expect("websocket request failed");

    assert_eq!(response.status, "400");
    assert_eq!(response.body, b"HTTP/3 does not support Upgrade requests\n");
    assert!(!response.reset, "invalid request should receive a response");
}

#[test]
fn http3_websocket_extended_connect_tunnels_to_http1_upstream() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);

    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let backend_addr = rt.block_on(start_h1_backend_with_websocket_upgrade());
    let mut config = make_config(0, format!("http://{backend_addr}"), cert, key);
    config.resilience.protocol.allow_connect = true;
    config.resilience.protocol.connect_allowed_ports = vec![443];
    config.resilience.protocol.connect_allowed_authorities = vec!["localhost:443".to_string()];
    let listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    let response = run_h3_client_collect_response(
        listen_addr,
        vec![
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"localhost:443"),
            quiche::h3::Header::new(b":path", b"/ws"),
            quiche::h3::Header::new(b":protocol", b"websocket"),
            quiche::h3::Header::new(b"sec-websocket-version", b"13"),
        ],
        true,
        Duration::from_secs(REQUEST_TIMEOUT_SECS),
    )
    .expect("extended CONNECT websocket request failed");

    assert_eq!(response.status, "200");
    assert!(response.body.is_empty());
    assert!(
        response.headers.iter().any(|(name, value)| name
            .eq_ignore_ascii_case("sec-websocket-accept")
            && value == "test-accept"),
        "expected sec-websocket-accept header, got {:?}",
        response.headers
    );
    assert!(!response.reset, "websocket tunnel should complete cleanly");
}

#[test]
fn http3_to_http2_preserves_grpc_error_trailers() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);

    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let backend_addr = rt.block_on(start_h2_backend_with_grpc_routes(&cert, &key));
    let config = make_h2_config(0, backend_addr, cert, key);
    let listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    let response = run_h3_client_collect_response(
        listen_addr,
        vec![
            quiche::h3::Header::new(b":method", b"POST"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"localhost"),
            quiche::h3::Header::new(b":path", b"/grpc-error"),
            quiche::h3::Header::new(b"content-type", b"application/grpc"),
            quiche::h3::Header::new(b"content-length", b"0"),
        ],
        true,
        Duration::from_secs(REQUEST_TIMEOUT_SECS),
    )
    .expect("grpc error request failed");

    assert_eq!(response.status, "200");
    assert!(
        response.body.is_empty(),
        "grpc error should be trailer-only"
    );
    assert!(
        response
            .trailers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("grpc-status") && value == "14"),
        "expected grpc-status=14 trailer, got {:?}",
        response.trailers
    );
    assert!(
        response.trailers.iter().any(
            |(name, value)| name.eq_ignore_ascii_case("grpc-message") && value == "unavailable"
        ),
        "expected grpc-message trailer, got {:?}",
        response.trailers
    );
}

#[test]
fn grpc_timeout_returns_recoverable_proxy_error() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);

    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let backend_addr = rt.block_on(start_h2_backend_with_grpc_routes(&cert, &key));
    let mut config = make_h2_config(0, backend_addr, cert, key);
    config.performance.backend_timeout_ms = 150;
    config.performance.backend_connect_timeout_ms = 150;
    let listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    let response = run_h3_client_collect_response(
        listen_addr,
        vec![
            quiche::h3::Header::new(b":method", b"POST"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"localhost"),
            quiche::h3::Header::new(b":path", b"/grpc-timeout"),
            quiche::h3::Header::new(b"content-type", b"application/grpc"),
            quiche::h3::Header::new(b"content-length", b"0"),
        ],
        true,
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 4),
    )
    .expect("grpc timeout request failed");

    assert_eq!(response.status, "503");
    assert!(
        String::from_utf8_lossy(&response.body).contains("upstream timeout"),
        "timeout body should explain the proxy failure"
    );
    assert!(
        !response.reset,
        "grpc timeout should surface as an HTTP response"
    );
}
