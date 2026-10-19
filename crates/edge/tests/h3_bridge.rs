use std::{
    collections::HashMap,
    convert::Infallible,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    thread,
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::{
    HeaderMap, StatusCode,
    header::{CONTENT_LENGTH, HeaderValue},
};
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::{
    Request, Response, Uri,
    body::{Body, Frame, Incoming},
    client::conn::{http1, http2},
    service::service_fn,
};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
};
use quiche::h3::NameValue;
use rand::RngCore;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, SanType,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tempfile::{TempDir, tempdir};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    rustls::{ClientConfig, RootCertStore, ServerConfig, pki_types::ServerName},
};

mod support;

use impulse_config::{
    config::{
        Backend, ClientAuth, Config, HealthCheck, Listen, LoadBalancing, Log, LogFormat,
        RouteMatch, Security, Tls, TlsCertificate, Upstream, UpstreamTls,
    },
    runtime::RuntimeConfig,
};
use impulse_edge::{
    BACKEND_TIMEOUT_SECS, MAX_DATAGRAM_SIZE_BYTES, MAX_STREAMS_PER_CONNECTION,
    MAX_UDP_PAYLOAD_BYTES, PingoraListenerTask, QUIC_IDLE_TIMEOUT_MS, QUIC_INITIAL_MAX_DATA,
    QUIC_INITIAL_MAX_STREAMS_BIDI, QUIC_INITIAL_MAX_STREAMS_UNI, QUIC_INITIAL_STREAM_DATA,
    REQUEST_TIMEOUT_SECS,
    runtime::{bundle::RuntimeBundleHandle, listener::QUICListener},
    spawn_pingora_ingress_listener,
};
use support::{net::local_listener_bind_available, request_path as request_support};

type TrailerPairs = Vec<(String, String)>;
type H3TrailerResponse = (String, Vec<u8>, TrailerPairs);
type HttpResponse = (StatusCode, Vec<u8>, TrailerPairs);

fn write_test_certs(dir: &TempDir) -> (String, String) {
    write_named_test_cert(dir, "cert", &["localhost"], &[IpAddr::from([127, 0, 0, 1])])
}

fn write_named_test_cert(
    dir: &TempDir,
    file_prefix: &str,
    dns_names: &[&str],
    ip_sans: &[IpAddr],
) -> (String, String) {
    let mut params = CertificateParams::new(
        dns_names
            .iter()
            .map(|name| (*name).to_string())
            .collect::<Vec<_>>(),
    );
    for dns_name in dns_names {
        params
            .subject_alt_names
            .push(SanType::DnsName((*dns_name).to_string()));
    }
    for ip in ip_sans {
        params.subject_alt_names.push(SanType::IpAddress(*ip));
    }
    if let Some(common_name) = dns_names.first() {
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, *common_name);
        params.distinguished_name = distinguished_name;
    }
    let cert = Certificate::from_params(params).expect("failed to build cert");

    let cert_path = dir.path().join(format!("{file_prefix}.pem"));
    let key_path = dir.path().join(format!("{file_prefix}.key.pem"));

    std::fs::write(&cert_path, cert.serialize_pem().expect("serialize cert")).expect("write cert");
    std::fs::write(&key_path, cert.serialize_private_key_pem()).expect("write key");

    (
        cert_path.to_string_lossy().to_string(),
        key_path.to_string_lossy().to_string(),
    )
}

fn write_test_ca_and_client_cert(
    dir: &TempDir,
    ca_name: &str,
    client_name: &str,
) -> (String, String, String) {
    let mut ca_params = CertificateParams::new(Vec::new());
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, ca_name);
    ca_params.distinguished_name = ca_dn;
    let ca = Certificate::from_params(ca_params).expect("build ca");

    let ca_cert_path = dir.path().join(format!("{ca_name}.pem"));
    std::fs::write(
        &ca_cert_path,
        ca.serialize_pem().expect("serialize ca cert"),
    )
    .expect("write ca cert");

    let mut client_params = CertificateParams::new(vec![client_name.to_string()]);
    let mut client_dn = DistinguishedName::new();
    client_dn.push(DnType::CommonName, client_name);
    client_params.distinguished_name = client_dn;
    client_params
        .subject_alt_names
        .push(SanType::DnsName(client_name.to_string()));
    let client = Certificate::from_params(client_params).expect("build client cert");

    let client_cert_path = dir.path().join(format!("{client_name}.pem"));
    let client_key_path = dir.path().join(format!("{client_name}.key.pem"));
    std::fs::write(
        &client_cert_path,
        client
            .serialize_pem_with_signer(&ca)
            .expect("serialize client cert"),
    )
    .expect("write client cert");
    std::fs::write(&client_key_path, client.serialize_private_key_pem()).expect("write client key");

    (
        ca_cert_path.to_string_lossy().to_string(),
        client_cert_path.to_string_lossy().to_string(),
        client_key_path.to_string_lossy().to_string(),
    )
}

fn make_config(port: u32, backend_addr: String, cert: String, key: String) -> Config {
    let mut upstream = HashMap::new();
    upstream.insert(
        "test_pool".to_string(),
        Upstream {
            load_balancing: LoadBalancing {
                lb_type: "random".to_string(),
                key: None,
            },
            auth: Default::default(),
            host_policy: Default::default(),
            forwarded_headers: Default::default(),
            compression: Default::default(),
            tls: None,
            route: RouteMatch {
                path_prefix: Some("/".to_string()),
                ..Default::default()
            },
            backends: vec![Backend {
                id: "backend1".to_string(),
                address: normalize_backend_address(backend_addr),
                weight: 1,
                health_check: Some(HealthCheck {
                    path: "/health".to_string(),
                    interval: 1000,
                    timeout_ms: 1000,
                    failure_threshold: 3,
                    success_threshold: 1,
                    cooldown_ms: 0,
                }),
            }],
        },
    );

    make_config_with_upstreams(port, upstream, cert, key)
}

fn make_h2_config(port: u32, backend_addr: SocketAddr, cert: String, key: String) -> Config {
    let mut config = make_config(port, format!("https://{backend_addr}"), cert, key);
    config.upstream_tls.verify_certificates = false;
    config.upstream_tls.strict_sni = false;
    config
}

fn make_config_with_upstreams(
    port: u32,
    upstream: HashMap<String, Upstream>,
    cert: String,
    key: String,
) -> Config {
    Config {
        version: 1,
        listen: Listen {
            protocol: "http3".to_string(),
            port: port as u16,
            address: "127.0.0.1".to_string(),
            tls: Tls {
                cert,
                key,
                certificates: vec![],
                client_auth: ClientAuth::default(),
            },
        },
        listeners: vec![],
        upstream,
        load_balancing: Some(LoadBalancing {
            lb_type: "random".to_string(),
            key: None,
        }),
        upstream_tls: UpstreamTls::default(),
        secrets: Default::default(),
        log: Log {
            level: "info".to_string(),
            file: Default::default(),
            format: LogFormat::Plain,
        },
        performance: impulse_config::config::Performance::default(),
        observability: impulse_config::config::Observability::default(),
        resilience: impulse_config::config::Resilience::default(),
        security: Security::default(),
    }
}

fn normalize_backend_address(address: String) -> String {
    request_support::normalize_backend_address(address)
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

fn quic_read_timeout(conn: &quiche::Connection) -> Duration {
    request_support::quic_read_timeout(conn)
}

type ListenerTaskGuard = request_support::ListenerTaskGuard;

fn make_listener_with_pingora(
    rt: &tokio::runtime::Runtime,
    config: Config,
) -> (QUICListener, PingoraListenerTask) {
    let runtime_config = RuntimeConfig::from_config(&config).expect("runtime config");
    let listener_config = runtime_config
        .listener_runtime_configs()
        .into_iter()
        .next()
        .expect("listener runtime config");
    let bundle = QUICListener::build_runtime_bundle(
        "h3-bridge-test".to_string(),
        config.log.clone(),
        &runtime_config,
    )
    .expect("runtime bundle");
    let shared_state = Arc::clone(&bundle.shared_state);
    QUICListener::spawn_control_plane_tasks(&runtime_config, &shared_state, 1)
        .expect("control plane tasks");
    let runtime_bundle = Arc::new(RuntimeBundleHandle::new(bundle));
    let runtime_guard = rt.enter();
    let pingora_listener = spawn_pingora_ingress_listener(runtime_bundle, listener_config.clone())
        .expect("Pingora listener");
    drop(runtime_guard);
    let socket = QUICListener::bind_socket(&listener_config, false).expect("bind socket");
    let listener =
        QUICListener::new_with_socket_and_shared_state(listener_config, socket, shared_state)
            .expect("listener with shared state");
    (listener, pingora_listener)
}

async fn start_h2_backend() -> SocketAddr {
    let fixture = request_support::start_h1_backend(move |_req: Request<Incoming>| async move {
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from("backend ok\n"))))
    })
    .await;
    let addr = fixture.addr;
    std::mem::forget(fixture);
    addr
}

async fn start_h1_backend_with_websocket_upgrade() -> SocketAddr {
    let fixture = request_support::start_h1_websocket_upgrade_backend().await;
    let addr = fixture.addr;
    std::mem::forget(fixture);
    addr
}

fn run_h3_client_chunked_post(
    addr: SocketAddr,
    path: &str,
    total_len: usize,
    chunk_size: usize,
    inter_chunk_delay: Duration,
    read_delay: Duration,
    timeout: Duration,
) -> Result<(String, Vec<u8>, bool), String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    let local_addr = socket.local_addr().map_err(|e| e.to_string())?;

    let mut config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|e| format!("config: {e:?}"))?;
    config.verify_peer(false);
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|e| format!("alpn: {e:?}"))?;
    config.set_max_idle_timeout(QUIC_IDLE_TIMEOUT_MS);
    config.set_max_recv_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    config.set_max_send_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    config.set_initial_max_data(QUIC_INITIAL_MAX_DATA);
    config.set_initial_max_stream_data_bidi_local(QUIC_INITIAL_STREAM_DATA);
    config.set_initial_max_stream_data_bidi_remote(QUIC_INITIAL_STREAM_DATA);
    config.set_initial_max_stream_data_uni(QUIC_INITIAL_STREAM_DATA);
    config.set_initial_max_streams_bidi(QUIC_INITIAL_MAX_STREAMS_BIDI);
    config.set_initial_max_streams_uni(QUIC_INITIAL_MAX_STREAMS_UNI);
    config.set_disable_active_migration(true);

    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    rand::thread_rng().fill_bytes(&mut scid_bytes);
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
    let mut conn = quiche::connect(Some("localhost"), &scid, local_addr, addr, &mut config)
        .map_err(|e| format!("connect: {e:?}"))?;

    let h3_config = quiche::h3::Config::new().map_err(|e| format!("h3: {e:?}"))?;
    let mut h3: Option<quiche::h3::Connection> = None;

    let mut out = [0u8; MAX_UDP_PAYLOAD_BYTES];
    let mut buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];
    let start = Instant::now();

    let mut req_stream_id: Option<u64> = None;
    let mut remaining = total_len;
    let mut chunk_written = 0usize;
    let mut current_chunk_len = 0usize;
    let mut should_fin_for_chunk = false;
    let mut body_done = total_len == 0;
    let mut request_stream_stopped = false;
    let mut status = String::new();
    let mut body = Vec::new();
    let payload = vec![0u8; chunk_size.max(1)];

    let (w, si) = conn.send(&mut out).map_err(|e| format!("send: {e:?}"))?;
    socket
        .send_to(&out[..w], si.to)
        .map_err(|e| format!("send_to: {e:?}"))?;

    loop {
        loop {
            match conn.send(&mut out) {
                Ok((w, si)) => {
                    let _ = socket.send_to(&out[..w], si.to);
                }
                Err(quiche::Error::Done) => break,
                Err(e) => return Err(format!("send loop: {e:?}")),
            }
        }

        let read_timeout = quic_read_timeout(&conn);
        socket
            .set_read_timeout(Some(read_timeout))
            .map_err(|e| format!("timeout: {e:?}"))?;
        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                conn.recv(
                    &mut buf[..len],
                    quiche::RecvInfo {
                        from,
                        to: local_addr,
                    },
                )
                .map_err(|e| format!("recv: {e:?}"))?;
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                conn.on_timeout();
            }
            Err(e) => return Err(format!("recv: {e:?}")),
        }

        if conn.is_established() && h3.is_none() {
            h3 = Some(
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .map_err(|e| format!("h3 conn: {e:?}"))?,
            );
        }

        if let Some(h3c) = h3.as_mut() {
            if req_stream_id.is_none() && conn.is_established() {
                let content_length = total_len.to_string();
                let req = vec![
                    quiche::h3::Header::new(b":method", b"POST"),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(b":authority", b"localhost"),
                    quiche::h3::Header::new(b":path", path.as_bytes()),
                    quiche::h3::Header::new(b"user-agent", b"impulse-pressure-test"),
                    quiche::h3::Header::new(b"content-length", content_length.as_bytes()),
                ];
                let sid = h3c
                    .send_request(&mut conn, &req, total_len == 0)
                    .map_err(|e| format!("send_request: {e:?}"))?;
                req_stream_id = Some(sid);
            }

            if let Some(sid) = req_stream_id
                && !body_done
                && !request_stream_stopped
                && status.is_empty()
            {
                if current_chunk_len == 0 {
                    current_chunk_len = chunk_size.min(remaining);
                    chunk_written = 0;
                    should_fin_for_chunk = current_chunk_len == remaining;
                }
                let end = current_chunk_len;
                match h3c.send_body(
                    &mut conn,
                    sid,
                    &payload[chunk_written..end],
                    should_fin_for_chunk,
                ) {
                    Ok(written) => {
                        chunk_written += written;
                        if chunk_written == current_chunk_len {
                            remaining -= current_chunk_len;
                            current_chunk_len = 0;
                            if remaining == 0 {
                                body_done = true;
                            } else if !inter_chunk_delay.is_zero() {
                                std::thread::sleep(inter_chunk_delay);
                            }
                        }
                    }
                    Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => {}
                    Err(quiche::h3::Error::TransportError(quiche::Error::StreamStopped(_))) => {
                        request_stream_stopped = true;
                        body_done = true;
                    }
                    Err(e) => return Err(format!("send_body: {e:?}")),
                }
            }

            loop {
                match h3c.poll(&mut conn) {
                    Ok((_sid, quiche::h3::Event::Headers { list, .. })) => {
                        for header in &list {
                            if header.name() == b":status" {
                                status = String::from_utf8_lossy(header.value()).to_string();
                            }
                        }
                    }
                    Ok((sid, quiche::h3::Event::Data)) => loop {
                        if !read_delay.is_zero() {
                            std::thread::sleep(read_delay);
                        }
                        match h3c.recv_body(&mut conn, sid, &mut buf) {
                            Ok(read) => body.extend_from_slice(&buf[..read]),
                            Err(quiche::h3::Error::Done) => break,
                            Err(e) => return Err(format!("recv_body: {e:?}")),
                        }
                    },
                    Ok((_sid, quiche::h3::Event::Finished)) => {
                        return Ok((status, body, false));
                    }
                    Ok((_sid, quiche::h3::Event::Reset(_))) => {
                        return Ok((status, body, true));
                    }
                    Ok((_sid, quiche::h3::Event::PriorityUpdate)) => {}
                    Ok((_sid, quiche::h3::Event::GoAway)) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => return Err(format!("poll: {e:?}")),
                }
            }
        }

        if start.elapsed() > timeout {
            return Err(format!(
                "timeout waiting for response (status='{}', body_len={})",
                status,
                body.len()
            ));
        }
    }
}

fn run_h3_client_collect_trailers(
    addr: SocketAddr,
    path: &str,
) -> Result<H3TrailerResponse, String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    let local_addr = socket.local_addr().map_err(|e| e.to_string())?;

    let mut config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|e| format!("config: {e:?}"))?;
    config.verify_peer(false);
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|e| format!("alpn: {e:?}"))?;
    config.set_max_idle_timeout(QUIC_IDLE_TIMEOUT_MS);
    config.set_max_recv_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    config.set_max_send_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    config.set_initial_max_data(QUIC_INITIAL_MAX_DATA);
    config.set_initial_max_stream_data_bidi_local(QUIC_INITIAL_STREAM_DATA);
    config.set_initial_max_stream_data_bidi_remote(QUIC_INITIAL_STREAM_DATA);
    config.set_initial_max_stream_data_uni(QUIC_INITIAL_STREAM_DATA);
    config.set_initial_max_streams_bidi(QUIC_INITIAL_MAX_STREAMS_BIDI);
    config.set_initial_max_streams_uni(QUIC_INITIAL_MAX_STREAMS_UNI);
    config.set_disable_active_migration(true);

    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    rand::thread_rng().fill_bytes(&mut scid_bytes);
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);

    let mut conn = quiche::connect(Some("localhost"), &scid, local_addr, addr, &mut config)
        .map_err(|e| format!("connect: {e:?}"))?;
    let h3_config = quiche::h3::Config::new().map_err(|e| format!("h3: {e:?}"))?;
    let mut h3_conn: Option<quiche::h3::Connection> = None;

    let mut out = [0u8; MAX_UDP_PAYLOAD_BYTES];
    let mut buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];
    let mut request_sent = false;
    let mut request_stream_id = None;
    let mut status = String::new();
    let mut response_body = Vec::new();
    let mut trailers: TrailerPairs = Vec::new();
    let start = Instant::now();
    let timeout = Duration::from_secs(REQUEST_TIMEOUT_SECS);

    loop {
        while let Ok((write, send_info)) = conn.send(&mut out) {
            socket
                .send_to(&out[..write], send_info.to)
                .map_err(|e| format!("send_to: {e:?}"))?;
        }

        let read_timeout = conn
            .timeout()
            .unwrap_or(Duration::from_millis(50))
            .min(Duration::from_millis(50));
        let read_timeout = if read_timeout.is_zero() {
            Duration::from_millis(1)
        } else {
            read_timeout
        };
        socket
            .set_read_timeout(Some(read_timeout))
            .map_err(|e| format!("timeout: {e:?}"))?;

        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                let recv_info = quiche::RecvInfo {
                    from,
                    to: local_addr,
                };
                conn.recv(&mut buf[..len], recv_info)
                    .map_err(|e| format!("recv: {e:?}"))?;
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                conn.on_timeout();
            }
            Err(e) => return Err(format!("recv: {e:?}")),
        }

        if conn.is_established() && h3_conn.is_none() {
            h3_conn = Some(
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .map_err(|e| format!("h3 conn: {e:?}"))?,
            );
        }

        if let Some(h3c) = h3_conn.as_mut() {
            if conn.is_established() && !request_sent {
                let req = vec![
                    quiche::h3::Header::new(b":method", b"GET"),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(b":authority", b"localhost"),
                    quiche::h3::Header::new(b":path", path.as_bytes()),
                    quiche::h3::Header::new(b"user-agent", b"impulse-regression-test"),
                ];
                let stream_id = h3c
                    .send_request(&mut conn, &req, true)
                    .map_err(|e| format!("send_request: {e:?}"))?;
                request_stream_id = Some(stream_id);
                request_sent = true;
            }

            loop {
                match h3c.poll(&mut conn) {
                    Ok((sid, quiche::h3::Event::Headers { list, .. })) => {
                        if Some(sid) != request_stream_id {
                            continue;
                        }
                        if status.is_empty() {
                            for header in &list {
                                if header.name() == b":status" {
                                    status = String::from_utf8_lossy(header.value()).to_string();
                                }
                            }
                        } else {
                            for header in &list {
                                trailers.push((
                                    String::from_utf8_lossy(header.name()).to_string(),
                                    String::from_utf8_lossy(header.value()).to_string(),
                                ));
                            }
                        }
                    }
                    Ok((sid, quiche::h3::Event::Data)) => {
                        if Some(sid) != request_stream_id {
                            continue;
                        }
                        loop {
                            match h3c.recv_body(&mut conn, sid, &mut buf) {
                                Ok(read) => response_body.extend_from_slice(&buf[..read]),
                                Err(quiche::h3::Error::Done) => break,
                                Err(e) => return Err(format!("recv_body: {e:?}")),
                            }
                        }
                    }
                    Ok((sid, quiche::h3::Event::Finished)) => {
                        if Some(sid) != request_stream_id {
                            continue;
                        }
                        return Ok((status, response_body, trailers));
                    }
                    Ok((sid, quiche::h3::Event::Reset(_))) => {
                        if Some(sid) != request_stream_id {
                            continue;
                        }
                        return Err("stream reset".to_string());
                    }
                    Ok((_sid, quiche::h3::Event::PriorityUpdate)) => {}
                    Ok((_sid, quiche::h3::Event::GoAway)) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => return Err(format!("poll: {e:?}")),
                }
            }
        }

        if start.elapsed() > timeout {
            return Err(format!(
                "timeout waiting for response with trailers (status='{}', body_len={}, trailers={})",
                status,
                response_body.len(),
                trailers.len()
            ));
        }
    }
}

#[derive(Debug, Default)]
struct H3CollectedResponse {
    status: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    trailers: Vec<(String, String)>,
    reset: bool,
}

fn run_h3_client_collect_response(
    addr: SocketAddr,
    req: Vec<quiche::h3::Header>,
    fin: bool,
    timeout: Duration,
) -> Result<H3CollectedResponse, String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    let local_addr = socket.local_addr().map_err(|e| e.to_string())?;

    let mut config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|e| format!("config: {e:?}"))?;
    config.verify_peer(false);
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|e| format!("alpn: {e:?}"))?;
    config.set_max_idle_timeout(QUIC_IDLE_TIMEOUT_MS);
    config.set_max_recv_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    config.set_max_send_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    config.set_initial_max_data(QUIC_INITIAL_MAX_DATA);
    config.set_initial_max_stream_data_bidi_local(QUIC_INITIAL_STREAM_DATA);
    config.set_initial_max_stream_data_bidi_remote(QUIC_INITIAL_STREAM_DATA);
    config.set_initial_max_stream_data_uni(QUIC_INITIAL_STREAM_DATA);
    config.set_initial_max_streams_bidi(QUIC_INITIAL_MAX_STREAMS_BIDI);
    config.set_initial_max_streams_uni(QUIC_INITIAL_MAX_STREAMS_UNI);
    config.set_disable_active_migration(true);

    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    rand::thread_rng().fill_bytes(&mut scid_bytes);
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);

    let mut conn = quiche::connect(Some("localhost"), &scid, local_addr, addr, &mut config)
        .map_err(|e| format!("connect: {e:?}"))?;
    let h3_config = quiche::h3::Config::new().map_err(|e| format!("h3: {e:?}"))?;
    let mut h3_conn: Option<quiche::h3::Connection> = None;

    let mut out = [0u8; MAX_UDP_PAYLOAD_BYTES];
    let mut buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];
    let mut request_sent = false;
    let mut request_stream_id = None;
    let start = Instant::now();
    let mut response = H3CollectedResponse::default();

    loop {
        while let Ok((write, send_info)) = conn.send(&mut out) {
            socket
                .send_to(&out[..write], send_info.to)
                .map_err(|e| format!("send_to: {e:?}"))?;
        }

        let read_timeout = conn
            .timeout()
            .unwrap_or(Duration::from_millis(50))
            .min(Duration::from_millis(50));
        let read_timeout = if read_timeout.is_zero() {
            Duration::from_millis(1)
        } else {
            read_timeout
        };
        socket
            .set_read_timeout(Some(read_timeout))
            .map_err(|e| format!("timeout: {e:?}"))?;

        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                let recv_info = quiche::RecvInfo {
                    from,
                    to: local_addr,
                };
                conn.recv(&mut buf[..len], recv_info)
                    .map_err(|e| format!("recv: {e:?}"))?;
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                conn.on_timeout();
            }
            Err(e) => return Err(format!("recv: {e:?}")),
        }

        if conn.is_established() && h3_conn.is_none() {
            h3_conn = Some(
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .map_err(|e| format!("h3 conn: {e:?}"))?,
            );
        }

        if let Some(h3c) = h3_conn.as_mut() {
            if conn.is_established() && !request_sent {
                let stream_id = h3c
                    .send_request(&mut conn, &req, fin)
                    .map_err(|e| format!("send_request: {e:?}"))?;
                request_stream_id = Some(stream_id);
                request_sent = true;
            }

            loop {
                match h3c.poll(&mut conn) {
                    Ok((sid, quiche::h3::Event::Headers { list, .. })) => {
                        if Some(sid) != request_stream_id {
                            continue;
                        }
                        if response.status.is_empty() {
                            for header in &list {
                                if header.name() == b":status" {
                                    response.status =
                                        String::from_utf8_lossy(header.value()).to_string();
                                } else {
                                    response.headers.push((
                                        String::from_utf8_lossy(header.name()).to_string(),
                                        String::from_utf8_lossy(header.value()).to_string(),
                                    ));
                                }
                            }
                        } else {
                            for header in &list {
                                response.trailers.push((
                                    String::from_utf8_lossy(header.name()).to_string(),
                                    String::from_utf8_lossy(header.value()).to_string(),
                                ));
                            }
                        }
                    }
                    Ok((sid, quiche::h3::Event::Data)) => {
                        if Some(sid) != request_stream_id {
                            continue;
                        }
                        loop {
                            match h3c.recv_body(&mut conn, sid, &mut buf) {
                                Ok(read) => response.body.extend_from_slice(&buf[..read]),
                                Err(quiche::h3::Error::Done) => break,
                                Err(e) => return Err(format!("recv_body: {e:?}")),
                            }
                        }
                    }
                    Ok((sid, quiche::h3::Event::Finished)) => {
                        if Some(sid) != request_stream_id {
                            continue;
                        }
                        return Ok(response);
                    }
                    Ok((sid, quiche::h3::Event::Reset(_))) => {
                        if Some(sid) != request_stream_id {
                            continue;
                        }
                        response.reset = true;
                        return Ok(response);
                    }
                    Ok((_sid, quiche::h3::Event::PriorityUpdate)) => {}
                    Ok((_sid, quiche::h3::Event::GoAway)) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => return Err(format!("poll: {e:?}")),
                }
            }
        }

        if start.elapsed() > timeout {
            return Err(format!(
                "timeout waiting for response (status='{}', body_len={}, trailers={}, reset={})",
                response.status,
                response.body.len(),
                response.trailers.len(),
                response.reset
            ));
        }
    }
}

type TestBody = BoxBody<Bytes, Infallible>;

struct DelayedChunkBody {
    rx: tokio::sync::mpsc::Receiver<Bytes>,
}

impl DelayedChunkBody {
    fn channel(buffer: usize) -> (tokio::sync::mpsc::Sender<Bytes>, Self) {
        let (tx, rx) = tokio::sync::mpsc::channel(buffer);
        (tx, Self { rx })
    }
}

impl Body for DelayedChunkBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(chunk)) => Poll::Ready(Some(Ok(Frame::data(chunk)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

struct TrailerThenEndBody {
    data: Option<Bytes>,
    trailers: Option<HeaderMap>,
}

impl TrailerThenEndBody {
    fn new(data: Bytes, trailers: HeaderMap) -> Self {
        Self {
            data: Some(data),
            trailers: Some(trailers),
        }
    }
}

impl Body for TrailerThenEndBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(data) = self.data.take() {
            return Poll::Ready(Some(Ok(Frame::data(data))));
        }
        if let Some(trailers) = self.trailers.take() {
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
        Poll::Ready(None)
    }
}

async fn start_h2_test_backend<F, Fut>(cert_path: &str, key_path: &str, handler: F) -> SocketAddr
where
    F: Fn(Request<Incoming>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<Response<TestBody>, hyper::Error>> + Send + 'static,
{
    let mut tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            read_test_certificate_chain(cert_path).expect("backend certificate"),
            read_test_private_key(key_path).expect("backend private key"),
        )
        .expect("backend TLS config");
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            let handler = handler.clone();
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(stream).await else {
                    return;
                };
                let service = service_fn(handler);
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    addr
}

async fn start_h2_backend_with_trailers(cert_path: &str, key_path: &str) -> SocketAddr {
    start_h2_test_backend(cert_path, key_path, |_req| async move {
        let mut trailers = HeaderMap::new();
        trailers.insert(
            http::HeaderName::from_static("grpc-status"),
            HeaderValue::from_static("0"),
        );
        trailers.insert(
            http::HeaderName::from_static("grpc-message"),
            HeaderValue::from_static("ok"),
        );

        let body = TrailerThenEndBody::new(Bytes::from_static(b"hello\n"), trailers).boxed();
        Ok::<_, hyper::Error>(
            Response::builder()
                .header("content-type", "application/grpc")
                .header(http::header::TRAILER, "grpc-status, grpc-message")
                .body(body)
                .expect("response"),
        )
    })
    .await
}

async fn start_h2_backend_with_grpc_routes(cert_path: &str, key_path: &str) -> SocketAddr {
    start_h2_test_backend(cert_path, key_path, |req| async move {
        let response: Response<TestBody> = match req.uri().path() {
            "/grpc-ok" => {
                let mut trailers = HeaderMap::new();
                trailers.insert(
                    http::HeaderName::from_static("grpc-status"),
                    HeaderValue::from_static("0"),
                );
                trailers.insert(
                    http::HeaderName::from_static("grpc-message"),
                    HeaderValue::from_static("ok"),
                );
                Response::builder()
                    .header("content-type", "application/grpc")
                    .header(http::header::TRAILER, "grpc-status, grpc-message")
                    .body(
                        TrailerThenEndBody::new(
                            Bytes::from_static(b"\x00\x00\x00\x00\x00"),
                            trailers,
                        )
                        .boxed(),
                    )
                    .expect("grpc ok response")
            }
            "/grpc-error" => {
                let mut trailers = HeaderMap::new();
                trailers.insert(
                    http::HeaderName::from_static("grpc-status"),
                    HeaderValue::from_static("14"),
                );
                trailers.insert(
                    http::HeaderName::from_static("grpc-message"),
                    HeaderValue::from_static("unavailable"),
                );
                Response::builder()
                    .header("content-type", "application/grpc")
                    .header(http::header::TRAILER, "grpc-status, grpc-message")
                    .body(TrailerThenEndBody::new(Bytes::new(), trailers).boxed())
                    .expect("grpc error response")
            }
            "/grpc-timeout" => {
                tokio::time::sleep(Duration::from_secs(BACKEND_TIMEOUT_SECS + 1)).await;
                Response::new(Full::new(Bytes::from_static(b"late\n")).boxed())
            }
            "/health" => Response::new(Full::new(Bytes::from_static(b"ok\n")).boxed()),
            _ => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from_static(b"missing\n")).boxed())
                .expect("not found response"),
        };
        Ok::<_, hyper::Error>(response)
    })
    .await
}

fn read_test_root_store(cert_path: &str) -> Result<RootCertStore, String> {
    let certs = read_test_certificate_chain(cert_path)?;
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .map_err(|err| format!("add root cert: {err}"))?;
    }
    Ok(roots)
}

fn read_test_certificate_chain(cert_path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    CertificateDer::pem_file_iter(cert_path)
        .map_err(|err| format!("open cert file: {err}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("parse certs: {err}"))
}

fn read_test_leaf_der(cert_path: &str) -> Result<Vec<u8>, String> {
    let certs = CertificateDer::pem_file_iter(cert_path)
        .map_err(|err| format!("open cert file: {err}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("parse certs: {err}"))?;
    certs
        .first()
        .map(|cert| cert.as_ref().to_vec())
        .ok_or_else(|| "missing leaf cert".to_string())
}

fn read_test_private_key(
    key_path: &str,
) -> Result<tokio_rustls::rustls::pki_types::PrivateKeyDer<'static>, String> {
    PrivateKeyDer::from_pem_file(key_path).map_err(|err| format!("parse private key: {err}"))
}

#[derive(Clone, Debug)]
struct H3TlsClientOptions<'a> {
    server_name: &'a str,
    authority: &'a str,
    path: &'a str,
    verify_peer: bool,
    root_cert_path: Option<&'a str>,
    client_identity: Option<(&'a str, &'a str)>,
    application_protos: &'a [&'a [u8]],
    send_request: bool,
}

#[derive(Debug)]
struct H3TlsObservation {
    body: Vec<u8>,
    peer_cert: Option<Vec<u8>>,
    alpn: Vec<u8>,
}

async fn connect_http2(
    addr: SocketAddr,
    cert_path: &str,
) -> Result<
    (
        hyper::client::conn::http2::SendRequest<Empty<Bytes>>,
        tokio::task::JoinHandle<()>,
    ),
    String,
> {
    let roots = read_test_root_store(cert_path)?;
    let mut tls_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(tls_config));

    let server_name = ServerName::try_from("localhost")
        .map_err(|err| format!("server name: {err}"))?
        .to_owned();

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                let tls_stream = connector
                    .connect(server_name.clone(), stream)
                    .await
                    .map_err(|err| format!("tls connect: {err}"))?;
                let (sender, conn) =
                    http2::handshake(TokioExecutor::new(), TokioIo::new(tls_stream))
                        .await
                        .map_err(|err| format!("h2 handshake: {err}"))?;
                let conn_task = tokio::spawn(async move {
                    let _ = conn.await;
                });
                return Ok((sender, conn_task));
            }
            Err(err) if Instant::now() < deadline => {
                let _ = err;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(err) => return Err(format!("tcp connect: {err}")),
        }
    }
}

async fn connect_http2_with_client_auth(
    addr: SocketAddr,
    cert_path: &str,
    client_identity: Option<(&str, &str)>,
) -> Result<
    (
        hyper::client::conn::http2::SendRequest<Empty<Bytes>>,
        tokio::task::JoinHandle<()>,
    ),
    String,
> {
    let roots = read_test_root_store(cert_path)?;
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let mut tls_config = if let Some((client_cert_path, client_key_path)) = client_identity {
        let client_chain = {
            CertificateDer::pem_file_iter(client_cert_path)
                .map_err(|err| format!("open cert file: {err}"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| format!("parse certs: {err}"))?
        };
        builder
            .with_client_auth_cert(client_chain, read_test_private_key(client_key_path)?)
            .map_err(|err| format!("client auth cert: {err}"))?
    } else {
        builder.with_no_client_auth()
    };
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(tls_config));

    let server_name = ServerName::try_from("localhost")
        .map_err(|err| format!("server name: {err}"))?
        .to_owned();

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                let tls_stream = connector
                    .connect(server_name.clone(), stream)
                    .await
                    .map_err(|err| format!("tls connect: {err}"))?;
                let (sender, conn) =
                    http2::handshake(TokioExecutor::new(), TokioIo::new(tls_stream))
                        .await
                        .map_err(|err| format!("h2 handshake: {err}"))?;
                let conn_task = tokio::spawn(async move {
                    let _ = conn.await;
                });
                return Ok((sender, conn_task));
            }
            Err(err) if Instant::now() < deadline => {
                let _ = err;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(err) => return Err(format!("tcp connect: {err}")),
        }
    }
}

fn run_h3_client_with_tls(
    addr: SocketAddr,
    options: H3TlsClientOptions<'_>,
) -> Result<H3TlsObservation, String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    let local_addr = socket.local_addr().map_err(|e| e.to_string())?;

    let mut config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|e| format!("config: {e:?}"))?;
    if options.verify_peer {
        let root_cert_path = options
            .root_cert_path
            .ok_or_else(|| "root_cert_path is required when verify_peer=true".to_string())?;
        config.verify_peer(true);
        config
            .load_verify_locations_from_file(root_cert_path)
            .map_err(|e| format!("load verify locations: {e:?}"))?;
    } else {
        config.verify_peer(false);
    }
    if let Some((client_cert_path, client_key_path)) = options.client_identity {
        config
            .load_cert_chain_from_pem_file(client_cert_path)
            .map_err(|e| format!("load client cert: {e:?}"))?;
        config
            .load_priv_key_from_pem_file(client_key_path)
            .map_err(|e| format!("load client key: {e:?}"))?;
    }
    config
        .set_application_protos(options.application_protos)
        .map_err(|e| format!("alpn: {e:?}"))?;
    config.set_max_idle_timeout(QUIC_IDLE_TIMEOUT_MS);
    config.set_max_recv_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    config.set_max_send_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    config.set_initial_max_data(QUIC_INITIAL_MAX_DATA);
    config.set_initial_max_stream_data_bidi_local(QUIC_INITIAL_STREAM_DATA);
    config.set_initial_max_stream_data_bidi_remote(QUIC_INITIAL_STREAM_DATA);
    config.set_initial_max_stream_data_uni(QUIC_INITIAL_STREAM_DATA);
    config.set_initial_max_streams_bidi(QUIC_INITIAL_MAX_STREAMS_BIDI);
    config.set_initial_max_streams_uni(QUIC_INITIAL_MAX_STREAMS_UNI);
    config.set_disable_active_migration(true);

    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    rand::thread_rng().fill_bytes(&mut scid_bytes);
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);

    let mut conn = quiche::connect(
        Some(options.server_name),
        &scid,
        local_addr,
        addr,
        &mut config,
    )
    .map_err(|e| format!("connect: {e:?}"))?;
    let h3_config = quiche::h3::Config::new().map_err(|e| format!("h3: {e:?}"))?;
    let mut h3_conn: Option<quiche::h3::Connection> = None;

    let mut out = [0u8; MAX_UDP_PAYLOAD_BYTES];
    let mut buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];
    let mut request_sent = false;
    let start = Instant::now();
    let timeout = Duration::from_secs(REQUEST_TIMEOUT_SECS);
    let mut body = Vec::new();

    loop {
        while let Ok((write, send_info)) = conn.send(&mut out) {
            socket
                .send_to(&out[..write], send_info.to)
                .map_err(|e| format!("send_to: {e:?}"))?;
        }

        if conn.is_closed() && !conn.is_established() {
            return Err(format!(
                "connection closed before establishment: local_error={:?} peer_error={:?}",
                conn.local_error(),
                conn.peer_error()
            ));
        }

        let read_timeout = quic_read_timeout(&conn);
        socket
            .set_read_timeout(Some(read_timeout))
            .map_err(|e| format!("timeout: {e:?}"))?;

        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                let recv_info = quiche::RecvInfo {
                    from,
                    to: local_addr,
                };
                conn.recv(&mut buf[..len], recv_info)
                    .map_err(|e| format!("recv: {e:?}"))?;
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                conn.on_timeout();
            }
            Err(e) => return Err(format!("recv: {e:?}")),
        }

        if conn.is_established() && !options.send_request {
            return Ok(H3TlsObservation {
                body: Vec::new(),
                peer_cert: conn.peer_cert().map(|cert| cert.to_vec()),
                alpn: conn.application_proto().to_vec(),
            });
        }

        if conn.is_established() && h3_conn.is_none() {
            h3_conn = Some(
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .map_err(|e| format!("h3 conn: {e:?}"))?,
            );
        }

        if let Some(h3) = h3_conn.as_mut() {
            if conn.is_established() && !request_sent {
                let req = vec![
                    quiche::h3::Header::new(b":method", b"GET"),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(b":authority", options.authority.as_bytes()),
                    quiche::h3::Header::new(b":path", options.path.as_bytes()),
                    quiche::h3::Header::new(b"user-agent", b"impulse-tls-integration"),
                ];
                h3.send_request(&mut conn, &req, true)
                    .map_err(|e| format!("send_request: {e:?}"))?;
                request_sent = true;
            }

            loop {
                match h3.poll(&mut conn) {
                    Ok((stream_id, quiche::h3::Event::Data)) => loop {
                        match h3.recv_body(&mut conn, stream_id, &mut buf) {
                            Ok(read) => body.extend_from_slice(&buf[..read]),
                            Err(quiche::h3::Error::Done) => break,
                            Err(e) => return Err(format!("recv_body: {e:?}")),
                        }
                    },
                    Ok((_stream_id, quiche::h3::Event::Headers { .. })) => {}
                    Ok((_stream_id, quiche::h3::Event::Finished)) => {
                        return Ok(H3TlsObservation {
                            body,
                            peer_cert: conn.peer_cert().map(|cert| cert.to_vec()),
                            alpn: conn.application_proto().to_vec(),
                        });
                    }
                    Ok((_stream_id, quiche::h3::Event::Reset(_))) => {
                        return Err("stream reset".to_string());
                    }
                    Ok((_stream_id, quiche::h3::Event::PriorityUpdate)) => {}
                    Ok((_stream_id, quiche::h3::Event::GoAway)) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => return Err(format!("poll: {e:?}")),
                }
            }
        }

        if start.elapsed() > timeout {
            return Err("timeout waiting for QUIC TLS response".to_string());
        }
    }
}

async fn run_http2_client_collect_trailers(
    addr: SocketAddr,
    cert_path: &str,
    path: &str,
) -> Result<HttpResponse, String> {
    let (mut sender, _conn_task) = connect_http2(addr, cert_path).await?;
    sender
        .ready()
        .await
        .map_err(|err| format!("sender ready: {err}"))?;

    let req = Request::builder()
        .method("GET")
        .uri(
            Uri::builder()
                .path_and_query(path)
                .build()
                .map_err(|err| format!("uri build: {err}"))?,
        )
        .header("host", "localhost")
        .body(Empty::<Bytes>::new())
        .map_err(|err| format!("request build: {err}"))?;

    let mut response = sender
        .send_request(req)
        .await
        .map_err(|err| format!("send request: {err}"))?;
    let status = response.status();
    let mut body = Vec::new();
    let mut trailers = Vec::new();

    while let Some(frame) = response.body_mut().frame().await {
        let frame = frame.map_err(|err| format!("read frame: {err}"))?;
        match frame.into_data() {
            Ok(data) => body.extend_from_slice(&data),
            Err(frame) => {
                if let Ok(trailer_map) = frame.into_trailers() {
                    for (name, value) in &trailer_map {
                        trailers.push((
                            name.as_str().to_string(),
                            value
                                .to_str()
                                .map_err(|err| format!("trailer utf8: {err}"))?
                                .to_string(),
                        ));
                    }
                }
            }
        }
    }

    Ok((status, body, trailers))
}

async fn run_http1_websocket_handshake(
    addr: SocketAddr,
    cert_path: &str,
    path: &str,
) -> Result<(StatusCode, HeaderMap), String> {
    let roots = read_test_root_store(cert_path)?;
    let tls_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_config));

    let server_name = ServerName::try_from("localhost")
        .map_err(|err| format!("server name: {err}"))?
        .to_owned();

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                let tls_stream = connector
                    .connect(server_name.clone(), stream)
                    .await
                    .map_err(|err| format!("tls connect: {err}"))?;
                let (mut sender, conn) = http1::handshake(TokioIo::new(tls_stream))
                    .await
                    .map_err(|err| format!("h1 handshake: {err}"))?;
                tokio::spawn(async move {
                    let _ = conn.with_upgrades().await;
                });
                sender
                    .ready()
                    .await
                    .map_err(|err| format!("sender ready: {err}"))?;

                let req = Request::builder()
                    .method("GET")
                    .uri(
                        Uri::builder()
                            .path_and_query(path)
                            .build()
                            .map_err(|err| format!("uri build: {err}"))?,
                    )
                    .header("host", "localhost")
                    .header(http::header::CONNECTION, "Upgrade")
                    .header(http::header::UPGRADE, "websocket")
                    .header("sec-websocket-key", "dGVzdC1rZXktMTIzNDU2Nzg5MA==")
                    .header("sec-websocket-version", "13")
                    .body(Empty::<Bytes>::new())
                    .map_err(|err| format!("request build: {err}"))?;

                let response = sender
                    .send_request(req)
                    .await
                    .map_err(|err| format!("send request: {err}"))?;
                return Ok((response.status(), response.headers().clone()));
            }
            Err(err) if Instant::now() < deadline => {
                let _ = err;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(err) => return Err(format!("tcp connect: {err}")),
        }
    }
}

async fn run_http2_client_request(
    addr: SocketAddr,
    cert_path: &str,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
) -> Result<HttpResponse, String> {
    let (mut sender, _conn_task) = connect_http2(addr, cert_path).await?;
    sender
        .ready()
        .await
        .map_err(|err| format!("sender ready: {err}"))?;

    let mut builder = Request::builder()
        .method(method)
        .uri(
            Uri::builder()
                .path_and_query(path)
                .build()
                .map_err(|err| format!("uri build: {err}"))?,
        )
        .header("host", "localhost");
    for (name, value) in extra_headers {
        builder = builder.header(*name, *value);
    }

    let req = builder
        .body(Empty::<Bytes>::new())
        .map_err(|err| format!("request build: {err}"))?;
    let mut response = sender
        .send_request(req)
        .await
        .map_err(|err| format!("send request: {err}"))?;
    let status = response.status();
    let mut body = Vec::new();
    let mut trailers = Vec::new();

    while let Some(frame) = response.body_mut().frame().await {
        let frame = frame.map_err(|err| format!("read frame: {err}"))?;
        match frame.into_data() {
            Ok(data) => body.extend_from_slice(&data),
            Err(frame) => {
                if let Ok(trailer_map) = frame.into_trailers() {
                    for (name, value) in &trailer_map {
                        trailers.push((
                            name.as_str().to_string(),
                            value
                                .to_str()
                                .map_err(|err| format!("trailer utf8: {err}"))?
                                .to_string(),
                        ));
                    }
                }
            }
        }
    }

    Ok((status, body, trailers))
}

async fn run_http2_client_request_with_client_auth(
    addr: SocketAddr,
    cert_path: &str,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    client_identity: Option<(&str, &str)>,
) -> Result<HttpResponse, String> {
    let (mut sender, _conn_task) =
        connect_http2_with_client_auth(addr, cert_path, client_identity).await?;
    sender
        .ready()
        .await
        .map_err(|err| format!("sender ready: {err}"))?;

    let mut builder = Request::builder()
        .method(method)
        .uri(
            Uri::builder()
                .path_and_query(path)
                .build()
                .map_err(|err| format!("uri build: {err}"))?,
        )
        .header("host", "localhost");
    for (name, value) in extra_headers {
        builder = builder.header(*name, *value);
    }

    let req = builder
        .body(Empty::<Bytes>::new())
        .map_err(|err| format!("request build: {err}"))?;
    let mut response = sender
        .send_request(req)
        .await
        .map_err(|err| format!("send request: {err}"))?;
    let status = response.status();
    let mut body = Vec::new();
    let mut trailers = Vec::new();

    while let Some(frame) = response.body_mut().frame().await {
        let frame = frame.map_err(|err| format!("read frame: {err}"))?;
        match frame.into_data() {
            Ok(data) => body.extend_from_slice(&data),
            Err(frame) => {
                if let Ok(trailer_map) = frame.into_trailers() {
                    for (name, value) in &trailer_map {
                        trailers.push((
                            name.as_str().to_string(),
                            value
                                .to_str()
                                .map_err(|err| format!("trailer utf8: {err}"))?
                                .to_string(),
                        ));
                    }
                }
            }
        }
    }

    Ok((status, body, trailers))
}

#[derive(Debug, Clone)]
struct StreamObservation {
    path: String,
    status: Option<String>,
    body: Vec<u8>,
    data_events: Vec<Duration>,
    finished_at: Option<Duration>,
}

fn observation_for<'a>(observations: &'a [StreamObservation], path: &str) -> &'a StreamObservation {
    observations
        .iter()
        .find(|o| o.path == path)
        .unwrap_or_else(|| panic!("missing observation for path {path}"))
}

fn find_free_tcp_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("local addr").port()
}

async fn scrape_metrics(port: u16, path: &str, timeout: Duration) -> Result<String, String> {
    let start = Instant::now();
    let client: Client<HttpConnector, Empty<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();
    let target: Uri = format!("http://127.0.0.1:{port}{path}")
        .parse()
        .map_err(|err| format!("invalid metrics uri: {err}"))?;
    let mut last_error = String::new();

    while start.elapsed() < timeout {
        match tokio::time::timeout(Duration::from_millis(500), client.get(target.clone())).await {
            Ok(Ok(response)) => {
                let status = response.status();
                if !status.is_success() {
                    last_error = format!("unexpected status: {status}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }

                let collected = match response.into_body().collect().await {
                    Ok(body) => body.to_bytes(),
                    Err(err) => {
                        last_error = format!("read body: {err}");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                if collected.is_empty() {
                    last_error = "empty response body".to_string();
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }

                match String::from_utf8(collected.to_vec()) {
                    Ok(text) => return Ok(text),
                    Err(err) => {
                        last_error = format!("metrics payload not utf8: {err}");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                }
            }
            Ok(Err(err)) => {
                last_error = format!("http request failed: {err}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(_) => {
                last_error = "request timeout".to_string();
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }

    Err(format!(
        "metrics endpoint not reachable within {:?} ({})",
        timeout, last_error
    ))
}

fn run_h3_client_concurrent_get(
    addr: SocketAddr,
    paths: &[&str],
    timeout: Duration,
) -> Result<Vec<StreamObservation>, String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    let local_addr = socket.local_addr().map_err(|e| e.to_string())?;

    let mut config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|e| format!("config: {e:?}"))?;
    config.verify_peer(false);
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|e| format!("alpn: {e:?}"))?;
    config.set_max_idle_timeout(QUIC_IDLE_TIMEOUT_MS);
    config.set_max_recv_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    config.set_max_send_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    config.set_initial_max_data(QUIC_INITIAL_MAX_DATA);
    config.set_initial_max_stream_data_bidi_local(QUIC_INITIAL_STREAM_DATA);
    config.set_initial_max_stream_data_bidi_remote(QUIC_INITIAL_STREAM_DATA);
    config.set_initial_max_stream_data_uni(QUIC_INITIAL_STREAM_DATA);
    config.set_initial_max_streams_bidi(QUIC_INITIAL_MAX_STREAMS_BIDI);
    config.set_initial_max_streams_uni(QUIC_INITIAL_MAX_STREAMS_UNI);
    config.set_disable_active_migration(true);

    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    rand::thread_rng().fill_bytes(&mut scid_bytes);
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);

    let mut conn = quiche::connect(Some("localhost"), &scid, local_addr, addr, &mut config)
        .map_err(|e| format!("connect: {e:?}"))?;

    let h3_config = quiche::h3::Config::new().map_err(|e| format!("h3: {e:?}"))?;
    let mut h3_conn: Option<quiche::h3::Connection> = None;
    let mut out = [0u8; MAX_UDP_PAYLOAD_BYTES];
    let mut buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];
    let mut requests_sent = false;
    let mut finished = 0usize;
    let start = Instant::now();

    let mut stream_to_observation: HashMap<u64, usize> = HashMap::new();
    let mut observations: Vec<StreamObservation> = paths
        .iter()
        .map(|path| StreamObservation {
            path: (*path).to_string(),
            status: None,
            body: Vec::new(),
            data_events: Vec::new(),
            finished_at: None,
        })
        .collect();

    let (write, send_info) = conn.send(&mut out).map_err(|e| format!("send: {e:?}"))?;
    socket
        .send_to(&out[..write], send_info.to)
        .map_err(|e| format!("send_to: {e:?}"))?;

    loop {
        if start.elapsed() > timeout {
            return Err(format!(
                "timeout waiting for responses (done={finished}, expected={})",
                paths.len()
            ));
        }

        loop {
            match conn.send(&mut out) {
                Ok((write, send_info)) => {
                    let _ = socket.send_to(&out[..write], send_info.to);
                }
                Err(quiche::Error::Done) => break,
                Err(e) => return Err(format!("send loop: {e:?}")),
            }
        }

        let remaining = timeout.saturating_sub(start.elapsed());
        let read_timeout = quic_read_timeout(&conn)
            .min(remaining)
            .min(Duration::from_millis(50));
        let read_timeout = if read_timeout.is_zero() {
            Duration::from_millis(1)
        } else {
            read_timeout
        };
        socket
            .set_read_timeout(Some(read_timeout))
            .map_err(|e| format!("timeout: {e:?}"))?;

        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                let recv_info = quiche::RecvInfo {
                    from,
                    to: local_addr,
                };
                conn.recv(&mut buf[..len], recv_info)
                    .map_err(|e| format!("recv: {e:?}"))?;
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                conn.on_timeout();
            }
            Err(e) => return Err(format!("recv: {e:?}")),
        }

        if conn.is_established() && h3_conn.is_none() {
            h3_conn = Some(
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .map_err(|e| format!("h3 conn: {e:?}"))?,
            );
        }

        if let Some(h3) = h3_conn.as_mut() {
            if conn.is_established() && !requests_sent {
                for (idx, path) in paths.iter().enumerate() {
                    let req = vec![
                        quiche::h3::Header::new(b":method", b"GET"),
                        quiche::h3::Header::new(b":scheme", b"https"),
                        quiche::h3::Header::new(b":authority", b"localhost"),
                        quiche::h3::Header::new(b":path", path.as_bytes()),
                        quiche::h3::Header::new(b"user-agent", b"impulse-regression-test"),
                    ];
                    let stream_id = h3
                        .send_request(&mut conn, &req, true)
                        .map_err(|e| format!("send_request: {e:?}"))?;
                    stream_to_observation.insert(stream_id, idx);
                }
                requests_sent = true;
            }

            loop {
                match h3.poll(&mut conn) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        if let Some(idx) = stream_to_observation.get(&stream_id).copied() {
                            for header in &list {
                                if header.name() == b":status" {
                                    observations[idx].status =
                                        Some(String::from_utf8_lossy(header.value()).to_string());
                                }
                            }
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        let Some(idx) = stream_to_observation.get(&stream_id).copied() else {
                            break;
                        };
                        loop {
                            match h3.recv_body(&mut conn, stream_id, &mut buf) {
                                Ok(read) => {
                                    observations[idx].body.extend_from_slice(&buf[..read]);
                                    observations[idx].data_events.push(start.elapsed());
                                }
                                Err(quiche::h3::Error::Done) => break,
                                Err(e) => return Err(format!("recv_body: {e:?}")),
                            }
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Finished)) => {
                        if let Some(idx) = stream_to_observation.get(&stream_id).copied()
                            && observations[idx].finished_at.is_none()
                        {
                            observations[idx].finished_at = Some(start.elapsed());
                            finished += 1;
                        }
                    }
                    Ok((_stream_id, quiche::h3::Event::PriorityUpdate)) => {}
                    Ok((_stream_id, quiche::h3::Event::GoAway)) => {}
                    Ok((stream_id, quiche::h3::Event::Reset(_))) => {
                        return Err(format!("stream reset on id {stream_id}"));
                    }
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => return Err(format!("poll: {e:?}")),
                }
            }
        }

        if finished == paths.len() {
            return Ok(observations);
        }
    }
}

async fn start_h2_backend_with_regression_routes() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };

            let io = TokioIo::new(stream);
            let service = service_fn(|req: Request<Incoming>| async move {
                let path = req.uri().path().to_string();
                let response: Response<TestBody> = match path.as_str() {
                    "/fast" => Response::new(Full::new(Bytes::from_static(b"fast\n")).boxed()),
                    "/slow" => {
                        tokio::time::sleep(Duration::from_millis(700)).await;
                        Response::new(Full::new(Bytes::from_static(b"slow\n")).boxed())
                    }
                    "/status500" => Response::builder()
                        .status(500)
                        .body(Full::new(Bytes::from_static(b"backend 500\n")).boxed())
                        .unwrap(),
                    "/timeout" => {
                        tokio::time::sleep(Duration::from_secs(BACKEND_TIMEOUT_SECS + 1)).await;
                        Response::new(Full::new(Bytes::from_static(b"late\n")).boxed())
                    }
                    "/stream" => {
                        let (tx, body) = DelayedChunkBody::channel(8);
                        tokio::spawn(async move {
                            let _ = tx.send(Bytes::from_static(b"chunk-1")).await;
                            tokio::time::sleep(Duration::from_millis(140)).await;
                            let _ = tx.send(Bytes::from_static(b"chunk-2")).await;
                            tokio::time::sleep(Duration::from_millis(140)).await;
                            let _ = tx.send(Bytes::from_static(b"chunk-3")).await;
                        });
                        let mut response = Response::new(body.boxed());
                        response
                            .headers_mut()
                            .insert(CONTENT_LENGTH, HeaderValue::from_static("21"));
                        response
                    }
                    "/long-stream" => {
                        let (tx, body) = DelayedChunkBody::channel(8);
                        tokio::spawn(async move {
                            let _ = tx.send(Bytes::from_static(b"part-1")).await;
                            tokio::time::sleep(Duration::from_millis(220)).await;
                            let _ = tx.send(Bytes::from_static(b"part-2")).await;
                            tokio::time::sleep(Duration::from_millis(220)).await;
                            let _ = tx.send(Bytes::from_static(b"part-3")).await;
                            tokio::time::sleep(Duration::from_millis(220)).await;
                            let _ = tx.send(Bytes::from_static(b"part-4")).await;
                        });
                        Response::new(body.boxed())
                    }
                    _ => Response::new(Full::new(Bytes::from_static(b"default\n")).boxed()),
                };
                Ok::<_, hyper::Error>(response)
            });

            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    addr
}

async fn start_h2_backend_with_drain_probe(inflight_seen: Arc<AtomicBool>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };

            let io = TokioIo::new(stream);
            let inflight_seen = Arc::clone(&inflight_seen);
            let service = service_fn(move |req: Request<Incoming>| {
                let path = req.uri().path().to_string();
                let inflight_seen = Arc::clone(&inflight_seen);
                async move {
                    let response: Response<TestBody> = match path.as_str() {
                        "/drain-slow" => {
                            inflight_seen.store(true, Ordering::Relaxed);
                            tokio::time::sleep(Duration::from_millis(700)).await;
                            Response::new(Full::new(Bytes::from_static(b"drain-ok\n")).boxed())
                        }
                        _ => Response::new(Full::new(Bytes::from_static(b"default\n")).boxed()),
                    };
                    Ok::<_, hyper::Error>(response)
                }
            });

            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    addr
}

async fn start_h2_backend_with_chaos_routes() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let jitter_counter = Arc::new(AtomicUsize::new(0));
    let flap_counter = Arc::new(AtomicUsize::new(0));

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };

            let io = TokioIo::new(stream);
            let jitter_counter = Arc::clone(&jitter_counter);
            let flap_counter = Arc::clone(&flap_counter);
            let service = service_fn(move |req: Request<Incoming>| {
                let path = req.uri().path().to_string();
                let jitter_counter = Arc::clone(&jitter_counter);
                let flap_counter = Arc::clone(&flap_counter);
                async move {
                    let response: Response<TestBody> = match path.as_str() {
                        "/jitter" => {
                            let jitter =
                                15 + (jitter_counter.fetch_add(1, Ordering::Relaxed) % 120) as u64;
                            tokio::time::sleep(Duration::from_millis(jitter)).await;
                            Response::new(Full::new(Bytes::from_static(b"jitter-ok\n")).boxed())
                        }
                        "/loss" => {
                            tokio::time::sleep(Duration::from_secs(BACKEND_TIMEOUT_SECS + 2)).await;
                            Response::new(Full::new(Bytes::from_static(b"late-loss\n")).boxed())
                        }
                        "/flap" => {
                            if flap_counter
                                .fetch_add(1, Ordering::Relaxed)
                                .is_multiple_of(2)
                            {
                                Response::new(Full::new(Bytes::from_static(b"flap-ok\n")).boxed())
                            } else {
                                Response::builder()
                                    .status(503)
                                    .body(Full::new(Bytes::from_static(b"flap-fail\n")).boxed())
                                    .unwrap()
                            }
                        }
                        "/health" => Response::new(Full::new(Bytes::from_static(b"ok\n")).boxed()),
                        _ => Response::new(Full::new(Bytes::from_static(b"fast-ok\n")).boxed()),
                    };
                    Ok::<_, hyper::Error>(response)
                }
            });

            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    addr
}

#[path = "h3_bridge/protocol.rs"]
mod protocol;

/// While draining, new QUIC Initial packets must be silently dropped so no new
/// connection state is allocated.  The test starts draining before any client
/// connects, then confirms a fresh QUIC connection attempt never reaches the
/// Established state within a short window (the handshake packets are dropped).
#[test]
fn draining_rejects_new_connections() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);

    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let backend_addr = rt.block_on(start_h2_backend());
    let config = make_config(0, backend_addr.to_string(), cert, key);
    let listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();

    let listener = Arc::new(Mutex::new(listener));

    // Start draining immediately — before any client connects.
    listener.lock().unwrap().start_draining();

    let stop = Arc::new(AtomicBool::new(false));
    let listener_thread = {
        let listener = Arc::clone(&listener);
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Ok(mut guard) = listener.lock() {
                    guard.poll();
                }
            }
        })
    };

    // Attempt a fresh QUIC connection.  Initial packets are silently dropped,
    // so the handshake never completes; the connection stays in Initial state.
    let established = {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let local_addr = socket.local_addr().unwrap();

        let mut qconfig = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        qconfig.verify_peer(false);
        qconfig
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .unwrap();
        qconfig.set_max_idle_timeout(QUIC_IDLE_TIMEOUT_MS);
        qconfig.set_max_recv_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
        qconfig.set_max_send_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
        qconfig.set_initial_max_data(QUIC_INITIAL_MAX_DATA);
        qconfig.set_initial_max_stream_data_bidi_local(QUIC_INITIAL_STREAM_DATA);
        qconfig.set_initial_max_stream_data_bidi_remote(QUIC_INITIAL_STREAM_DATA);
        qconfig.set_initial_max_stream_data_uni(QUIC_INITIAL_STREAM_DATA);
        qconfig.set_initial_max_streams_bidi(QUIC_INITIAL_MAX_STREAMS_BIDI);
        qconfig.set_initial_max_streams_uni(QUIC_INITIAL_MAX_STREAMS_UNI);
        qconfig.set_disable_active_migration(true);

        let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
        rand::thread_rng().fill_bytes(&mut scid_bytes);
        let scid = quiche::ConnectionId::from_ref(&scid_bytes);
        let mut conn = quiche::connect(
            Some("localhost"),
            &scid,
            local_addr,
            listen_addr,
            &mut qconfig,
        )
        .unwrap();

        let mut out = [0u8; MAX_UDP_PAYLOAD_BYTES];
        let mut buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];

        // Send the Initial packet.
        let (w, si) = conn.send(&mut out).unwrap();
        socket.send_to(&out[..w], si.to).unwrap();

        // Poll for up to 500 ms; the handshake should never complete.
        let deadline = Instant::now() + Duration::from_millis(500);
        let mut established = false;
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            socket
                .set_read_timeout(Some(remaining.min(Duration::from_millis(50))))
                .unwrap();
            match socket.recv_from(&mut buf) {
                Ok((len, from)) => {
                    let _ = conn.recv(
                        &mut buf[..len],
                        quiche::RecvInfo {
                            from,
                            to: local_addr,
                        },
                    );
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    conn.on_timeout();
                }
                Err(_) => break,
            }
            // Flush any retransmits.
            loop {
                match conn.send(&mut out) {
                    Ok((w, si)) => {
                        let _ = socket.send_to(&out[..w], si.to);
                    }
                    Err(quiche::Error::Done) => break,
                    Err(_) => break,
                }
            }
            if conn.is_established() {
                established = true;
                break;
            }
        }
        established
    };

    stop.store(true, Ordering::Relaxed);
    let _ = listener_thread.join();

    assert!(
        !established,
        "new QUIC connection must not be established while listener is draining"
    );
}

#[test]
fn draining_forces_close_after_configured_timeout() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);

    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let inflight_seen = Arc::new(AtomicBool::new(false));
    let backend_addr = rt.block_on(start_h2_backend_with_drain_probe(Arc::clone(
        &inflight_seen,
    )));
    let mut config = make_config(0, backend_addr.to_string(), cert, key);
    config.performance.shutdown_drain_timeout_ms = 120;
    let mut listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();

    let client_thread = thread::spawn(move || {
        run_h3_client_concurrent_get(
            listen_addr,
            &["/drain-slow"],
            Duration::from_secs(REQUEST_TIMEOUT_SECS + 6),
        )
    });

    let mut drain_started: Option<Instant> = None;
    let drive_start = Instant::now();
    loop {
        listener.poll();

        if drain_started.is_none() && inflight_seen.load(Ordering::Relaxed) {
            listener.start_draining();
            drain_started = Some(Instant::now());
        }

        if drain_started.is_some() && listener.drain_complete() {
            break;
        }

        assert!(
            drive_start.elapsed() < Duration::from_secs(3),
            "drain test did not converge in expected time"
        );
    }
    let drain_elapsed = drain_started
        .expect("drain should start once in-flight request is observed")
        .elapsed();
    assert!(
        drain_elapsed < Duration::from_millis(600),
        "forced close should complete before slow backend success path (elapsed={drain_elapsed:?})"
    );

    let client_result = client_thread.join().expect("client thread join failed");
    if let Ok(observations) = client_result {
        let drained = observation_for(&observations, "/drain-slow");
        let got_full_success =
            drained.status.as_deref() == Some("200") && drained.body == b"drain-ok\n";
        assert!(
            !got_full_success,
            "forced close should prevent full slow-backend success before timeout"
        );
    }
}

#[test]
fn slow_response_consumer_does_not_hang() {
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

    let (status, body, got_reset) = run_h3_client_chunked_post(
        listen_addr,
        "/stream",
        0,
        1,
        Duration::from_millis(0),
        Duration::from_millis(40),
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 8),
    )
    .expect("slow response consumer should complete");

    assert_eq!(status, "200");
    assert_eq!(String::from_utf8_lossy(&body), "chunk-1chunk-2chunk-3");
    assert!(!got_reset, "slow response consumer should not reset stream");
}

#[test]
fn slow_stream_does_not_block_fast_stream() {
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

    let observations = run_h3_client_concurrent_get(
        listen_addr,
        &["/slow", "/fast"],
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 4),
    )
    .expect("client requests failed");

    let slow = observation_for(&observations, "/slow");
    let fast = observation_for(&observations, "/fast");
    assert_eq!(slow.status.as_deref(), Some("200"));
    assert_eq!(fast.status.as_deref(), Some("200"));

    let slow_done = slow.finished_at.expect("slow stream should finish");
    let fast_done = fast.finished_at.expect("fast stream should finish");
    assert!(
        fast_done < slow_done,
        "fast stream should complete before slow stream (fast={fast_done:?}, slow={slow_done:?})"
    );
}

#[test]
fn finished_stream_does_not_block_other_stream_progress() {
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

    let observations = run_h3_client_concurrent_get(
        listen_addr,
        &["/slow", "/stream"],
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 4),
    )
    .expect("client requests failed");

    let slow = observation_for(&observations, "/slow");
    let stream = observation_for(&observations, "/stream");
    let slow_done = slow.finished_at.expect("slow stream should finish");
    let first_stream_data = stream
        .data_events
        .first()
        .copied()
        .expect("stream path should produce at least one data chunk");

    assert!(
        first_stream_data < slow_done,
        "stream data should arrive while slow stream is still pending (first_stream_data={first_stream_data:?}, slow_done={slow_done:?})"
    );
}

#[test]
fn response_body_is_streamed_progressively() {
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

    let observations = run_h3_client_concurrent_get(
        listen_addr,
        &["/stream"],
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 4),
    )
    .expect("stream request failed");

    let stream = observation_for(&observations, "/stream");
    assert_eq!(stream.status.as_deref(), Some("200"));

    let body = String::from_utf8_lossy(&stream.body);
    assert_eq!(body, "chunk-1chunk-2chunk-3");
    assert!(
        stream.data_events.len() >= 2,
        "expected at least two data events, got {}",
        stream.data_events.len()
    );
    let first = stream.data_events.first().copied().unwrap();
    let last = stream.data_events.last().copied().unwrap();
    let span = last.saturating_sub(first);
    assert!(
        span >= Duration::from_millis(200),
        "expected delayed progressive delivery across chunks, got span {span:?}"
    );
}

#[test]
fn error_status_mapping_parity_is_preserved() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    let backend_addr = rt.block_on(start_h2_backend_with_regression_routes());
    let config = make_config(0, backend_addr.to_string(), cert.clone(), key.clone());
    let listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    let status_500 = run_h3_client_concurrent_get(
        listen_addr,
        &["/status500"],
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 4),
    )
    .expect("status500 request failed");
    let status_500_obs = observation_for(&status_500, "/status500");
    assert_eq!(status_500_obs.status.as_deref(), Some("500"));

    let timeout = run_h3_client_concurrent_get(
        listen_addr,
        &["/timeout"],
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 6),
    )
    .expect("timeout request failed");
    let timeout_obs = observation_for(&timeout, "/timeout");
    assert_eq!(timeout_obs.status.as_deref(), Some("503"));
    assert!(
        String::from_utf8_lossy(&timeout_obs.body).contains("upstream timeout"),
        "timeout body should indicate upstream timeout"
    );

    // Separate listener with unreachable backend to validate transport mapping.
    let transport_config = make_config(0, "127.0.0.1:1".to_string(), cert, key);
    let transport_listener =
        QUICListener::new(transport_config).expect("failed to create transport listener");
    let transport_addr = transport_listener.socket.local_addr().unwrap();
    let _transport_task = ListenerTaskGuard::spawn(&rt, transport_listener);

    let transport = run_h3_client_concurrent_get(
        transport_addr,
        &["/"],
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 4),
    )
    .expect("transport error request failed");
    let transport_obs = observation_for(&transport, "/");
    assert_eq!(transport_obs.status.as_deref(), Some("502"));
    assert!(
        String::from_utf8_lossy(&transport_obs.body).contains("upstream error"),
        "transport error body should indicate upstream error"
    );
}

#[test]
#[serial_test::serial]
fn metrics_endpoint_exposes_route_slo_metrics() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    let backend_addr = rt.block_on(start_h2_backend_with_regression_routes());
    let metrics_port = find_free_tcp_port();
    let mut config = make_config(0, backend_addr.to_string(), cert, key);
    config.observability.metrics.enabled = true;
    config.observability.metrics.address = "127.0.0.1".to_string();
    config.observability.metrics.port = metrics_port;
    config.observability.metrics.path = "/metrics".to_string();

    let _enter = rt.enter();
    let listener = QUICListener::new(config).expect("failed to create listener");
    drop(_enter);
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    let observations = rt
        .block_on(async move {
            tokio::task::spawn_blocking(move || {
                run_h3_client_concurrent_get(
                    listen_addr,
                    &["/fast", "/slow"],
                    Duration::from_secs(REQUEST_TIMEOUT_SECS + 4),
                )
            })
            .await
            .expect("join concurrent client task")
        })
        .expect("requests should succeed");
    assert_eq!(observations.len(), 2);

    let metrics = rt
        .block_on(scrape_metrics(
            metrics_port,
            "/metrics",
            Duration::from_secs(20),
        ))
        .expect("metrics endpoint should become reachable");
    assert!(
        metrics.contains("impulse_requests_total"),
        "unexpected metrics payload: {metrics}"
    );
    assert!(metrics.contains("impulse_route_requests_total{route=\"test_pool\"}"));
    assert!(metrics.contains("impulse_route_latency_ms_p50{route=\"test_pool\"}"));
    assert!(metrics.contains("impulse_route_latency_ms_p95{route=\"test_pool\"}"));
    assert!(metrics.contains("impulse_route_latency_ms_p99{route=\"test_pool\"}"));
    assert!(metrics.contains("impulse_overload_shed_by_reason_total"));
    assert!(metrics.contains("impulse_active_connections"));
    assert!(metrics.contains("impulse_connection_cap_rejects"));
    assert!(metrics.contains("impulse_hedge_triggered_total"));
}

#[test]
fn global_inflight_limit_sheds_excess_requests() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    let backend_addr = rt.block_on(start_h2_backend_with_regression_routes());
    let mut config = make_config(0, backend_addr.to_string(), cert, key);
    config.performance.global_inflight_limit = 1;
    config.performance.per_upstream_inflight_limit = 64;

    let listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    let observations = run_h3_client_concurrent_get(
        listen_addr,
        &["/slow", "/slow"],
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 4),
    )
    .expect("concurrent requests should complete");

    let mut status_200 = 0usize;
    let mut status_503 = 0usize;
    let mut shed_body = String::new();
    for obs in &observations {
        match obs.status.as_deref() {
            Some("200") => status_200 += 1,
            Some("503") => {
                status_503 += 1;
                shed_body = String::from_utf8_lossy(&obs.body).to_string();
            }
            other => panic!("unexpected status: {:?}", other),
        }
    }

    assert_eq!(status_200, 1, "expected one successful request");
    assert_eq!(status_503, 1, "expected one shed request");
    assert!(
        shed_body.contains("overloaded"),
        "shed body should mention overload, got: {shed_body}"
    );
}

#[test]
fn route_queue_global_cap_sheds_excess_requests() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    let backend_addr = rt.block_on(start_h2_backend_with_regression_routes());
    let mut config = make_config(0, backend_addr.to_string(), cert, key);
    config.performance.global_inflight_limit = 64;
    config.performance.per_upstream_inflight_limit = 64;
    config.resilience.route_queue.default_cap = 64;
    config.resilience.route_queue.global_cap = 1;

    let listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    let observations = run_h3_client_concurrent_get(
        listen_addr,
        &["/slow", "/slow"],
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 4),
    )
    .expect("concurrent requests should complete");

    let mut status_200 = 0usize;
    let mut status_503 = 0usize;
    let mut shed_body = String::new();
    for obs in &observations {
        match obs.status.as_deref() {
            Some("200") => status_200 += 1,
            Some("503") => {
                status_503 += 1;
                shed_body = String::from_utf8_lossy(&obs.body).to_string();
            }
            other => panic!("unexpected status: {:?}", other),
        }
    }

    assert_eq!(status_200, 1, "expected one successful request");
    assert_eq!(status_503, 1, "expected one shed request");
    assert!(
        shed_body.contains("global queue cap exceeded"),
        "shed body should mention global queue cap, got: {shed_body}"
    );
}

#[test]
fn protocol_policy_denies_disallowed_method() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    let backend_addr = rt.block_on(start_h2_backend_with_regression_routes());
    let mut config = make_config(0, backend_addr.to_string(), cert, key);
    config.resilience.protocol.allowed_methods = vec!["GET".to_string()];

    let listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    let (status, body, _got_reset) = run_h3_client_chunked_post(
        listen_addr,
        "/fast",
        0,
        1,
        Duration::ZERO,
        Duration::ZERO,
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 4),
    )
    .expect("method policy request should complete");
    assert_eq!(status, "405");
    assert!(
        String::from_utf8_lossy(&body).contains("method blocked"),
        "expected policy body in response"
    );
}

#[test]
fn protocol_policy_denies_blocked_path_prefix() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    let backend_addr = rt.block_on(start_h2_backend_with_regression_routes());
    let mut config = make_config(0, backend_addr.to_string(), cert, key);
    config.resilience.protocol.denied_path_prefixes = vec!["/admin".to_string()];

    let listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    let observations = run_h3_client_concurrent_get(
        listen_addr,
        &["/admin/secrets"],
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 4),
    )
    .expect("path policy request should complete");
    let denied = observation_for(&observations, "/admin/secrets");
    assert_eq!(denied.status.as_deref(), Some("403"));
    assert!(
        String::from_utf8_lossy(&denied.body).contains("path blocked"),
        "expected policy body in response"
    );
}

#[test]
fn upstream_api_key_auth_rejects_missing_key_and_allows_valid_key() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    let backend_addr = rt.block_on(start_h2_backend_with_regression_routes());
    let mut config = make_config(0, backend_addr.to_string(), cert, key);
    config.upstream.get_mut("test_pool").expect("upstream").auth =
        impulse_config::config::RouteAuth {
            api_key: Some(impulse_config::config::ApiKeyAuth {
                header_name: "x-api-key".to_string(),
                keys: vec!["edge-key".to_string()],
            }),
            jwt: None,
            external_auth: None,
            required_scopes: Vec::new(),
            required_roles: Vec::new(),
        };

    let listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    let unauthorized = run_h3_client_collect_response(
        listen_addr,
        vec![
            quiche::h3::Header::new(b":method", b"GET"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"localhost"),
            quiche::h3::Header::new(b":path", b"/fast"),
            quiche::h3::Header::new(b"user-agent", b"impulse-auth-test"),
        ],
        true,
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 4),
    )
    .expect("unauthorized request should complete");
    assert_eq!(unauthorized.status, "401");
    assert!(
        unauthorized
            .headers
            .iter()
            .any(|(name, value)| name == "www-authenticate" && value == "ApiKey")
    );
    assert!(
        String::from_utf8_lossy(&unauthorized.body).contains("unauthorized"),
        "expected unauthorized body"
    );

    let authorized = run_h3_client_collect_response(
        listen_addr,
        vec![
            quiche::h3::Header::new(b":method", b"GET"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"localhost"),
            quiche::h3::Header::new(b":path", b"/fast"),
            quiche::h3::Header::new(b"user-agent", b"impulse-auth-test"),
            quiche::h3::Header::new(b"x-api-key", b"edge-key"),
        ],
        true,
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 4),
    )
    .expect("authorized request should complete");
    assert_eq!(authorized.status, "200");
    assert_eq!(authorized.body, b"fast\n");
}

#[test]
fn upstream_jwt_auth_rejects_missing_token_and_allows_valid_token() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    let backend_addr = rt.block_on(start_h2_backend_with_regression_routes());
    let mut config = make_config(0, backend_addr.to_string(), cert, key);
    config.upstream.get_mut("test_pool").expect("upstream").auth =
        impulse_config::config::RouteAuth {
            api_key: None,
            jwt: Some(impulse_config::config::JwtAuth {
                secret: "jwt-secret".to_string(),
                issuer: Some("issuer-1".to_string()),
                audience: Some("aud-1".to_string()),
                clock_skew_secs: 30,
                ..impulse_config::config::JwtAuth::default()
            }),
            external_auth: None,
            required_scopes: vec!["read:fast".to_string()],
            required_roles: Vec::new(),
        };

    let listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    let unauthorized = run_h3_client_collect_response(
        listen_addr,
        vec![
            quiche::h3::Header::new(b":method", b"GET"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"localhost"),
            quiche::h3::Header::new(b":path", b"/fast"),
            quiche::h3::Header::new(b"user-agent", b"impulse-jwt-test"),
        ],
        true,
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 4),
    )
    .expect("unauthorized jwt request should complete");
    assert_eq!(unauthorized.status, "401");
    assert!(
        unauthorized
            .headers
            .iter()
            .any(|(name, value)| name == "www-authenticate" && value == "Bearer")
    );

    let token = encode_test_hs256_jwt(
        "jwt-secret",
        serde_json::json!({
            "sub": "user-1",
            "iss": "issuer-1",
            "aud": "aud-1",
            "exp": 4_000_000_000u64,
            "scope": "read:fast",
        }),
    );
    let authorization = format!("Bearer {token}");
    let authorized = run_h3_client_collect_response(
        listen_addr,
        vec![
            quiche::h3::Header::new(b":method", b"GET"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"localhost"),
            quiche::h3::Header::new(b":path", b"/fast"),
            quiche::h3::Header::new(b"user-agent", b"impulse-jwt-test"),
            quiche::h3::Header::new(b"authorization", authorization.as_bytes()),
        ],
        true,
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 4),
    )
    .expect("authorized jwt request should complete");
    assert_eq!(authorized.status, "200");
    assert_eq!(authorized.body, b"fast\n");
}

#[test]
fn upstream_inflight_limit_sheds_excess_requests() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    let backend_addr = rt.block_on(start_h2_backend_with_regression_routes());
    let mut config = make_config(0, backend_addr.to_string(), cert, key);
    config.performance.global_inflight_limit = 64;
    config.performance.per_upstream_inflight_limit = 1;

    let listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    let observations = run_h3_client_concurrent_get(
        listen_addr,
        &["/slow", "/slow"],
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 4),
    )
    .expect("concurrent requests should complete");

    let mut status_200 = 0usize;
    let mut status_503 = 0usize;
    let mut shed_body = String::new();
    for obs in &observations {
        match obs.status.as_deref() {
            Some("200") => status_200 += 1,
            Some("503") => {
                status_503 += 1;
                shed_body = String::from_utf8_lossy(&obs.body).to_string();
            }
            other => panic!("unexpected status: {:?}", other),
        }
    }

    assert_eq!(status_200, 1, "expected one successful request");
    assert_eq!(status_503, 1, "expected one shed request");
    assert!(
        shed_body.contains("upstream overloaded"),
        "shed body should mention upstream overload, got: {shed_body}"
    );
}

#[test]
fn backend_pool_inflight_limit_sheds_excess_requests() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    let backend_addr = rt.block_on(start_h2_backend_with_regression_routes());
    let mut config = make_config(0, backend_addr.to_string(), cert, key);
    config.performance.global_inflight_limit = 64;
    config.performance.per_upstream_inflight_limit = 64;
    config.performance.per_backend_inflight_limit = 1;

    let listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    let observations = run_h3_client_concurrent_get(
        listen_addr,
        &["/slow", "/slow"],
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 4),
    )
    .expect("concurrent requests should complete");

    let mut status_200 = 0usize;
    let mut status_503 = 0usize;
    let mut shed_body = String::new();
    for obs in &observations {
        match obs.status.as_deref() {
            Some("200") => status_200 += 1,
            Some("503") => {
                status_503 += 1;
                shed_body = String::from_utf8_lossy(&obs.body).to_string();
            }
            other => panic!("unexpected status: {:?}", other),
        }
    }

    assert_eq!(status_200, 1, "expected one successful request");
    assert_eq!(status_503, 1, "expected one shed request");
    assert!(
        shed_body.contains("backend overloaded"),
        "shed body should mention backend overload, got: {shed_body}"
    );
}

#[test]
fn backend_timeout_respects_configured_performance_value() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    let backend_addr = rt.block_on(start_h2_backend_with_regression_routes());
    let mut config = make_config(0, backend_addr.to_string(), cert, key);
    config.performance.backend_timeout_ms = 150;
    config.performance.backend_connect_timeout_ms = 150;

    let listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    let start = Instant::now();
    let observations = run_h3_client_concurrent_get(
        listen_addr,
        &["/timeout"],
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 4),
    )
    .expect("timeout request should complete");
    let elapsed = start.elapsed();

    let timeout_obs = observation_for(&observations, "/timeout");
    assert_eq!(timeout_obs.status.as_deref(), Some("503"));
    assert!(
        String::from_utf8_lossy(&timeout_obs.body).contains("upstream timeout"),
        "timeout body should indicate upstream timeout"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "configured backend timeout should fail fast, observed elapsed={elapsed:?}"
    );
}

#[test]
#[serial_test::serial]
fn chaos_high_jitter_remains_responsive() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    let backend_addr = rt.block_on(start_h2_backend_with_chaos_routes());
    let mut config = make_config(0, backend_addr.to_string(), cert, key);
    config.performance.backend_timeout_ms = 1_500;

    let listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    let paths: Vec<&str> = vec!["/jitter"; 24];
    let observations = run_h3_client_concurrent_get(
        listen_addr,
        &paths,
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 6),
    )
    .expect("jitter workload should complete");

    let success = observations
        .iter()
        .filter(|obs| obs.status.as_deref() == Some("200"))
        .count();
    assert_eq!(
        success,
        observations.len(),
        "all jitter requests should succeed"
    );
}

#[test]
#[serial_test::serial]
fn chaos_packet_loss_like_timeout_maps_to_recoverable_response() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    let backend_addr = rt.block_on(start_h2_backend_with_chaos_routes());
    let mut config = make_config(0, backend_addr.to_string(), cert, key);
    config.performance.backend_timeout_ms = 120;
    config.performance.backend_connect_timeout_ms = 120;

    let listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    let observations = run_h3_client_concurrent_get(
        listen_addr,
        &["/fast", "/loss", "/fast", "/loss"],
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 6),
    )
    .expect("loss-like workload should complete");

    let fast_ok = observations
        .iter()
        .filter(|obs| obs.path == "/fast" && obs.status.as_deref() == Some("200"))
        .count();
    let loss_timeout = observations
        .iter()
        .filter(|obs| obs.path == "/loss" && obs.status.as_deref() == Some("503"))
        .count();
    assert_eq!(fast_ok, 2, "fast paths must remain healthy");
    assert_eq!(
        loss_timeout, 2,
        "loss paths must map to recoverable timeout response"
    );
}

#[test]
#[serial_test::serial]
fn chaos_backend_flapping_is_stable_under_concurrency() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    let backend_addr = rt.block_on(start_h2_backend_with_chaos_routes());
    let mut config = make_config(0, backend_addr.to_string(), cert, key);
    config.performance.backend_timeout_ms = 500;

    let listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    let paths: Vec<&str> = vec!["/flap"; 20];
    let observations = run_h3_client_concurrent_get(
        listen_addr,
        &paths,
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 6),
    )
    .expect("flapping workload should complete");

    let success = observations
        .iter()
        .filter(|obs| obs.status.as_deref() == Some("200"))
        .count();
    let service_unavailable = observations
        .iter()
        .filter(|obs| obs.status.as_deref() == Some("503"))
        .count();
    assert!(
        success > 0,
        "flapping workload should still serve successes"
    );
    assert!(
        service_unavailable > 0,
        "flapping workload should surface recoverable failures without collapse"
    );
}

/// When more than MAX_STREAMS_PER_CONNECTION concurrent streams are opened on a
/// single connection the proxy must reject the excess stream with 503.
#[test]
fn stream_cap_rejects_excess_concurrent_streams() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    // Slow backend so all N+1 streams are in-flight simultaneously.
    let backend_addr = rt.block_on(start_h2_backend_with_regression_routes());
    let mut config = make_config(0, backend_addr.to_string(), cert, key);
    // Raise the QUIC transport stream limit above the app-level cap so the N+1th
    // stream reaches the application guard (rather than being dropped at the
    // QUIC layer with StreamLimit).
    config.performance.quic_initial_max_streams_bidi = (MAX_STREAMS_PER_CONNECTION as u64) + 10;
    let listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    // Send MAX_STREAMS_PER_CONNECTION + 1 slow requests concurrently.
    // The first N must all succeed (200); the N+1th must be shed (503).
    let n = MAX_STREAMS_PER_CONNECTION + 1;
    let paths: Vec<&str> = vec!["/slow"; n];
    let observations = run_h3_client_concurrent_get(
        listen_addr,
        &paths,
        // slow path takes ~700 ms; give plenty of room
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 10),
    )
    .expect("concurrent requests should complete");

    let count_503 = observations
        .iter()
        .filter(|o| o.status.as_deref() == Some("503"))
        .count();
    let count_200 = observations
        .iter()
        .filter(|o| o.status.as_deref() == Some("200"))
        .count();

    assert!(
        count_503 >= 1,
        "expected at least one 503 when stream cap is exceeded, got statuses: {:?}",
        observations.iter().map(|o| &o.status).collect::<Vec<_>>()
    );
    assert!(
        count_200 >= 1,
        "expected at least one successful stream through the cap, got statuses: {:?}",
        observations.iter().map(|o| &o.status).collect::<Vec<_>>()
    );
    assert_eq!(
        count_200 + count_503,
        n,
        "every stream must get a terminal response"
    );
}

/// When the upstream response advertises a `content-length` above
/// `max_response_body_bytes`, the proxy must fail fast with 503 before sending
/// any upstream 200 headers/body to the client.
#[test]
fn response_body_cap_returns_503_on_declared_length_breach() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    // Backend that serves exactly 8 KiB.
    let large_body = Bytes::from(vec![b'x'; 8 * 1024]);
    let listener_tcp = rt.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
    let backend_addr = listener_tcp.local_addr().unwrap();
    rt.spawn(async move {
        loop {
            let (stream, _) = match listener_tcp.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let body_clone = large_body.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |_req: Request<Incoming>| {
                    let body = body_clone.clone();
                    async move {
                        let mut response = Response::new(Full::new(body.clone()).boxed());
                        response.headers_mut().insert(
                            CONTENT_LENGTH,
                            HeaderValue::from_str(&body.len().to_string())
                                .expect("valid content-length"),
                        );
                        Ok::<_, hyper::Error>(response)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    // Cap at 1 KiB — far below the 8 KiB the backend will send.
    let mut config = make_config(0, backend_addr.to_string(), cert, key);
    config.performance.max_response_body_bytes = 1024;
    config.performance.unknown_length_response_prebuffer_bytes = 1024;

    let listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    // Bespoke client loop: expect terminal 503 without reset.
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let local_addr = socket.local_addr().unwrap();

    let mut qconfig = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    qconfig.verify_peer(false);
    qconfig
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();
    qconfig.set_max_idle_timeout(QUIC_IDLE_TIMEOUT_MS);
    qconfig.set_max_recv_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    qconfig.set_max_send_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    qconfig.set_initial_max_data(QUIC_INITIAL_MAX_DATA);
    qconfig.set_initial_max_stream_data_bidi_local(QUIC_INITIAL_STREAM_DATA);
    qconfig.set_initial_max_stream_data_bidi_remote(QUIC_INITIAL_STREAM_DATA);
    qconfig.set_initial_max_stream_data_uni(QUIC_INITIAL_STREAM_DATA);
    qconfig.set_initial_max_streams_bidi(QUIC_INITIAL_MAX_STREAMS_BIDI);
    qconfig.set_initial_max_streams_uni(QUIC_INITIAL_MAX_STREAMS_UNI);
    qconfig.set_disable_active_migration(true);

    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    rand::thread_rng().fill_bytes(&mut scid_bytes);
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
    let mut conn = quiche::connect(
        Some("localhost"),
        &scid,
        local_addr,
        listen_addr,
        &mut qconfig,
    )
    .unwrap();
    let h3_config = quiche::h3::Config::new().unwrap();

    let mut out = [0u8; MAX_UDP_PAYLOAD_BYTES];
    let mut buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];

    let (w, si) = conn.send(&mut out).unwrap();
    socket.send_to(&out[..w], si.to).unwrap();

    let start = Instant::now();
    let mut h3: Option<quiche::h3::Connection> = None;
    let mut req_sent = false;
    let mut got_reset = false;
    let mut status = String::new();
    let mut response_body = Vec::new();

    'outer: loop {
        loop {
            match conn.send(&mut out) {
                Ok((w, si)) => {
                    let _ = socket.send_to(&out[..w], si.to);
                }
                Err(quiche::Error::Done) => break,
                Err(e) => panic!("send: {e:?}"),
            }
        }

        let timeout = quic_read_timeout(&conn);
        socket.set_read_timeout(Some(timeout)).unwrap();

        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                conn.recv(
                    &mut buf[..len],
                    quiche::RecvInfo {
                        from,
                        to: local_addr,
                    },
                )
                .unwrap();
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                conn.on_timeout();
            }
            Err(e) => panic!("recv: {e:?}"),
        }

        if conn.is_established() && h3.is_none() {
            h3 = Some(quiche::h3::Connection::with_transport(&mut conn, &h3_config).unwrap());
        }

        if let Some(h3c) = h3.as_mut() {
            if !req_sent && conn.is_established() {
                let req = vec![
                    quiche::h3::Header::new(b":method", b"GET"),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(b":authority", b"localhost"),
                    quiche::h3::Header::new(b":path", b"/"),
                    quiche::h3::Header::new(b"user-agent", b"impulse-cap-test"),
                ];
                h3c.send_request(&mut conn, &req, true).unwrap();
                req_sent = true;
            }

            loop {
                match h3c.poll(&mut conn) {
                    Ok((_sid, quiche::h3::Event::Headers { list, .. })) => {
                        for h in &list {
                            if h.name() == b":status" {
                                status = String::from_utf8_lossy(h.value()).to_string();
                            }
                        }
                    }
                    Ok((sid, quiche::h3::Event::Data)) => loop {
                        match h3c.recv_body(&mut conn, sid, &mut buf) {
                            Ok(read) => response_body.extend_from_slice(&buf[..read]),
                            Err(quiche::h3::Error::Done) => break,
                            Err(e) => panic!("recv_body: {e:?}"),
                        }
                    },
                    Ok((_sid, quiche::h3::Event::Finished)) => {
                        break 'outer;
                    }
                    Ok((_sid, quiche::h3::Event::Reset(_))) => {
                        got_reset = true;
                        break 'outer;
                    }
                    Ok(_) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => panic!("poll: {e:?}"),
                }
            }
        }

        if start.elapsed() > Duration::from_secs(REQUEST_TIMEOUT_SECS + 4) {
            panic!("timeout waiting for 503 response");
        }
    }

    assert_eq!(status, "503", "expected 503 for response cap breach");
    assert_eq!(
        String::from_utf8_lossy(&response_body),
        "upstream response body too large\n"
    );
    assert!(
        !got_reset,
        "response cap breach should terminate with HTTP error, not stream reset"
    );
}

/// Unknown-length upstream bodies are validated against the cap before the
/// proxy emits downstream headers; breaches must terminate as 503 (no reset).
#[test]
fn response_body_cap_returns_503_on_unknown_length_breach() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    let listener_tcp = rt.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
    let backend_addr = listener_tcp.local_addr().unwrap();
    rt.spawn(async move {
        loop {
            let (stream, _) = match listener_tcp.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |_req: Request<Incoming>| async move {
                    let (tx, body) = DelayedChunkBody::channel(8);
                    tokio::spawn(async move {
                        let chunk = Bytes::from(vec![b'x'; 1024]);
                        for _ in 0..8 {
                            let _ = tx.send(chunk.clone()).await;
                        }
                    });
                    Ok::<_, hyper::Error>(Response::new(body.boxed()))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    let mut config = make_config(0, backend_addr.to_string(), cert, key);
    config.performance.max_response_body_bytes = 1024;
    config.performance.unknown_length_response_prebuffer_bytes = 1024;

    let listener = QUICListener::new(config).expect("failed to create listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _listener_task = ListenerTaskGuard::spawn(&rt, listener);

    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let local_addr = socket.local_addr().unwrap();

    let mut qconfig = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    qconfig.verify_peer(false);
    qconfig
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();
    qconfig.set_max_idle_timeout(QUIC_IDLE_TIMEOUT_MS);
    qconfig.set_max_recv_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    qconfig.set_max_send_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    qconfig.set_initial_max_data(QUIC_INITIAL_MAX_DATA);
    qconfig.set_initial_max_stream_data_bidi_local(QUIC_INITIAL_STREAM_DATA);
    qconfig.set_initial_max_stream_data_bidi_remote(QUIC_INITIAL_STREAM_DATA);
    qconfig.set_initial_max_stream_data_uni(QUIC_INITIAL_STREAM_DATA);
    qconfig.set_initial_max_streams_bidi(QUIC_INITIAL_MAX_STREAMS_BIDI);
    qconfig.set_initial_max_streams_uni(QUIC_INITIAL_MAX_STREAMS_UNI);
    qconfig.set_disable_active_migration(true);

    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    rand::thread_rng().fill_bytes(&mut scid_bytes);
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
    let mut conn = quiche::connect(
        Some("localhost"),
        &scid,
        local_addr,
        listen_addr,
        &mut qconfig,
    )
    .unwrap();
    let h3_config = quiche::h3::Config::new().unwrap();

    let mut out = [0u8; MAX_UDP_PAYLOAD_BYTES];
    let mut buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];

    let (w, si) = conn.send(&mut out).unwrap();
    socket.send_to(&out[..w], si.to).unwrap();

    let start = Instant::now();
    let mut h3: Option<quiche::h3::Connection> = None;
    let mut req_sent = false;
    let mut got_reset = false;
    let mut status = String::new();
    let mut response_body = Vec::new();

    'outer: loop {
        loop {
            match conn.send(&mut out) {
                Ok((w, si)) => {
                    let _ = socket.send_to(&out[..w], si.to);
                }
                Err(quiche::Error::Done) => break,
                Err(e) => panic!("send: {e:?}"),
            }
        }

        let timeout = quic_read_timeout(&conn);
        socket.set_read_timeout(Some(timeout)).unwrap();

        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                conn.recv(
                    &mut buf[..len],
                    quiche::RecvInfo {
                        from,
                        to: local_addr,
                    },
                )
                .unwrap();
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                conn.on_timeout();
            }
            Err(e) => panic!("recv: {e:?}"),
        }

        if conn.is_established() && h3.is_none() {
            h3 = Some(quiche::h3::Connection::with_transport(&mut conn, &h3_config).unwrap());
        }

        if let Some(h3c) = h3.as_mut() {
            if !req_sent && conn.is_established() {
                let req = vec![
                    quiche::h3::Header::new(b":method", b"GET"),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(b":authority", b"localhost"),
                    quiche::h3::Header::new(b":path", b"/"),
                    quiche::h3::Header::new(b"user-agent", b"impulse-cap-test"),
                ];
                h3c.send_request(&mut conn, &req, true).unwrap();
                req_sent = true;
            }

            loop {
                match h3c.poll(&mut conn) {
                    Ok((_sid, quiche::h3::Event::Headers { list, .. })) => {
                        for h in &list {
                            if h.name() == b":status" {
                                status = String::from_utf8_lossy(h.value()).to_string();
                            }
                        }
                    }
                    Ok((sid, quiche::h3::Event::Data)) => loop {
                        match h3c.recv_body(&mut conn, sid, &mut buf) {
                            Ok(read) => response_body.extend_from_slice(&buf[..read]),
                            Err(quiche::h3::Error::Done) => break,
                            Err(e) => panic!("recv_body: {e:?}"),
                        }
                    },
                    Ok((_sid, quiche::h3::Event::Finished)) => break 'outer,
                    Ok((_sid, quiche::h3::Event::Reset(_))) => {
                        got_reset = true;
                        break 'outer;
                    }
                    Ok(_) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => panic!("poll: {e:?}"),
                }
            }
        }

        if start.elapsed() > Duration::from_secs(REQUEST_TIMEOUT_SECS + 4) {
            panic!("timeout waiting for 503 response");
        }
    }

    assert_eq!(status, "503", "expected 503 for unknown-length cap breach");
    assert_eq!(
        String::from_utf8_lossy(&response_body),
        "upstream response body too large\n"
    );
    assert!(
        !got_reset,
        "unknown-length cap breach should terminate with HTTP error, not stream reset"
    );
}

// ── Teardown path integration tests (4.2) ───────────────────────────────────
//
// These tests exercise the three wire-level teardown paths at the real QUIC
// protocol layer.  Each test sends a real QUIC+H3 request, triggers a reset
// or error mid-stream, then verifies the server recovers cleanly by serving a
// subsequent request on the same connection without any stuck-stream symptoms.

/// Helper: build a minimal quiche QUIC client connected to `addr`.
/// Returns (socket, quic conn, h3 conn).  The h3 layer is negotiated inside.
fn make_quic_client(
    addr: SocketAddr,
) -> Result<
    (
        std::net::UdpSocket,
        std::net::SocketAddr,
        quiche::Connection,
        quiche::h3::Connection,
    ),
    String,
> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    let local_addr = socket.local_addr().map_err(|e| e.to_string())?;

    let mut qconfig =
        quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|e| format!("config: {e:?}"))?;
    qconfig.verify_peer(false);
    qconfig
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|e| format!("alpn: {e:?}"))?;
    qconfig.set_max_idle_timeout(QUIC_IDLE_TIMEOUT_MS);
    qconfig.set_max_recv_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    qconfig.set_max_send_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    qconfig.set_initial_max_data(QUIC_INITIAL_MAX_DATA);
    let stream_win = QUIC_INITIAL_STREAM_DATA.saturating_add(128 * 1024);
    qconfig.set_initial_max_stream_data_bidi_local(stream_win);
    qconfig.set_initial_max_stream_data_bidi_remote(stream_win);
    qconfig.set_initial_max_stream_data_uni(stream_win);
    qconfig.set_initial_max_streams_bidi(QUIC_INITIAL_MAX_STREAMS_BIDI);
    qconfig.set_initial_max_streams_uni(QUIC_INITIAL_MAX_STREAMS_UNI);
    qconfig.set_disable_active_migration(true);

    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    rand::thread_rng().fill_bytes(&mut scid_bytes);
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
    let mut conn = quiche::connect(Some("localhost"), &scid, local_addr, addr, &mut qconfig)
        .map_err(|e| format!("connect: {e:?}"))?;

    let h3_config = quiche::h3::Config::new().map_err(|e| format!("h3: {e:?}"))?;
    let mut out = [0u8; MAX_UDP_PAYLOAD_BYTES];
    let mut buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];

    // Initial packet.
    let (w, si) = conn
        .send(&mut out)
        .map_err(|e| format!("initial send: {e:?}"))?;
    socket
        .send_to(&out[..w], si.to)
        .map_err(|e| e.to_string())?;

    let deadline = Instant::now() + Duration::from_secs(REQUEST_TIMEOUT_SECS);
    loop {
        loop {
            match conn.send(&mut out) {
                Ok((w, si)) => {
                    let _ = socket.send_to(&out[..w], si.to);
                }
                Err(quiche::Error::Done) => break,
                Err(e) => return Err(format!("send: {e:?}")),
            }
        }
        if conn.is_established() {
            break;
        }
        socket.set_read_timeout(Some(quic_read_timeout(&conn))).ok();
        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                conn.recv(
                    &mut buf[..len],
                    quiche::RecvInfo {
                        from,
                        to: local_addr,
                    },
                )
                .map_err(|e| format!("recv: {e:?}"))?;
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                conn.on_timeout();
            }
            Err(e) => return Err(e.to_string()),
        }
        if Instant::now() > deadline {
            return Err("handshake timeout".into());
        }
    }

    let h3 = quiche::h3::Connection::with_transport(&mut conn, &h3_config)
        .map_err(|e| format!("h3 layer: {e:?}"))?;
    Ok((socket, local_addr, conn, h3))
}

/// Flush QUIC send buffer to the socket.
fn flush_quic(conn: &mut quiche::Connection, socket: &std::net::UdpSocket, out: &mut [u8]) {
    loop {
        match conn.send(out) {
            Ok((w, si)) => {
                let _ = socket.send_to(&out[..w], si.to);
            }
            Err(quiche::Error::Done) => break,
            Err(_) => break,
        }
    }
}

struct PumpIo<'a> {
    socket: &'a std::net::UdpSocket,
    local_addr: std::net::SocketAddr,
    out: &'a mut [u8],
    buf: &'a mut [u8],
}

/// Pump the QUIC event loop until `target_sid` finishes/resets OR `deadline`
/// passes.  Collects H3 status/finished/reset events.  Returns true if done.
fn pump_h3_until(
    conn: &mut quiche::Connection,
    h3: &mut quiche::h3::Connection,
    io: &mut PumpIo<'_>,
    target_sid: u64,
    deadline: Instant,
    events: &mut Vec<String>,
) -> bool {
    while Instant::now() < deadline {
        flush_quic(conn, io.socket, io.out);
        io.socket
            .set_read_timeout(Some(quic_read_timeout(conn)))
            .ok();
        match io.socket.recv_from(io.buf) {
            Ok((len, from)) => {
                let _ = conn.recv(
                    &mut io.buf[..len],
                    quiche::RecvInfo {
                        from,
                        to: io.local_addr,
                    },
                );
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                conn.on_timeout();
            }
            Err(_) => {}
        }
        loop {
            match h3.poll(conn) {
                Ok((sid, quiche::h3::Event::Headers { list, .. })) if sid == target_sid => {
                    for h in &list {
                        if h.name() == b":status" {
                            events.push(format!("status:{}", String::from_utf8_lossy(h.value())));
                        }
                    }
                }
                Ok((sid, quiche::h3::Event::Data)) if sid == target_sid => {
                    // consume body without storing
                    let mut tmp = [0u8; 4096];
                    while h3.recv_body(conn, sid, &mut tmp).is_ok() {}
                    events.push("data".into());
                }
                Ok((sid, quiche::h3::Event::Finished)) if sid == target_sid => {
                    events.push("finished".into());
                    return true;
                }
                Ok((sid, quiche::h3::Event::Reset(_))) if sid == target_sid => {
                    events.push("reset".into());
                    return true;
                }
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(_) => break,
            }
        }
    }
    false
}

/// Teardown path A: client sends RESET_STREAM before the upstream has responded.
///
/// Uses `global_inflight_limit = 1` so the inflight permit is the only one
/// available.  If `abort_stream` does not release it on reset, the follow-up
/// `/fast` request on a fresh connection is rejected with 503 (inflight full)
/// instead of 200. Passing means the wire-level reset propagated and resources
/// were freed.
#[test]
fn teardown_client_reset_before_upstream_response() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    let backend_addr = rt.block_on(start_h2_backend_with_regression_routes());
    let mut config = make_config(0, backend_addr.to_string(), cert, key);
    // Single inflight slot: a leaked permit means the follow-up is rejected.
    config.performance.global_inflight_limit = 1;

    let listener = QUICListener::new(config).expect("listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _guard = ListenerTaskGuard::spawn(&rt, listener);

    let (socket, local_addr, mut conn, mut h3) =
        make_quic_client(listen_addr).expect("quic client");
    let mut out = [0u8; MAX_UDP_PAYLOAD_BYTES];
    let mut buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];

    // POST to /slow with fin=false so the write side stays open.
    // Then immediately call stream_shutdown(Write) to send RESET_STREAM.
    // The server is in ReceivingRequest at reset time (before it forwards to
    // upstream), which exercises the AwaitingUpstream/ReceivingRequest teardown path.
    let slow_headers = vec![
        quiche::h3::Header::new(b":method", b"POST"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"localhost"),
        quiche::h3::Header::new(b":path", b"/slow"),
        quiche::h3::Header::new(b"content-length", b"100"),
    ];
    let slow_sid = h3
        .send_request(&mut conn, &slow_headers, false) // fin=false: write side stays open
        .expect("send_request /slow");

    // Flush so headers reach the server, then shut down the write side.
    // This sends RESET_STREAM while the server is still in ReceivingRequest.
    flush_quic(&mut conn, &socket, &mut out);
    conn.stream_shutdown(slow_sid, quiche::Shutdown::Write, 0)
        .expect("stream_shutdown");
    flush_quic(&mut conn, &socket, &mut out);

    // Pump briefly so the listener processes the reset and calls abort_stream.
    let pump_end = Instant::now() + Duration::from_millis(200);
    let mut discard = Vec::new();
    let mut io = PumpIo {
        socket: &socket,
        local_addr,
        out: &mut out,
        buf: &mut buf,
    };
    pump_h3_until(
        &mut conn,
        &mut h3,
        &mut io,
        slow_sid,
        pump_end,
        &mut discard,
    );

    // Follow-up /fast on a fresh connection. This avoids coupling the assertion
    // to the original stream state machine on the same connection while still
    // proving the inflight permit was released.
    let followup = run_h3_client_concurrent_get(
        listen_addr,
        &["/fast"],
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 4),
    )
    .expect("follow-up /fast request failed");
    let fast = observation_for(&followup, "/fast");
    assert!(
        fast.status.as_deref() == Some("200"),
        "expected 200 from /fast; 503/timeout means the inflight permit was not released on reset. \
         observed status={:?}",
        fast.status
    );
}

/// Teardown path B: connection dropped while the server is streaming the
/// response body (SendingResponse phase).
///
/// Uses `global_inflight_limit = 1` and `/long-stream` (4×220ms chunks).
/// The first QUIC connection receives response headers (server now in
/// SendingResponse) then drops abruptly — simulating the client disappearing
/// mid-stream.  The server must release the inflight permit via the timeout/
/// connection-close path so a *new* connection can immediately serve a request.
/// If the permit leaks, the second connection's /fast request gets 503.
#[test]
fn teardown_client_reset_during_response_streaming() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    let backend_addr = rt.block_on(start_h2_backend_with_regression_routes());
    let mut config = make_config(0, backend_addr.to_string(), cert, key);
    // Single inflight slot: a leaked permit means the follow-up is rejected.
    config.performance.global_inflight_limit = 1;
    // Short QUIC idle timeout so the server tears down the abandoned stream fast.
    config.performance.quic_max_idle_timeout_ms = 300;

    let listener = QUICListener::new(config).expect("listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _guard = ListenerTaskGuard::spawn(&rt, listener);

    // ── First connection: GET /stream, receive first body chunk, then drop ────
    {
        let (socket, local_addr, mut conn, mut h3) =
            make_quic_client(listen_addr).expect("quic client");
        let mut out = [0u8; MAX_UDP_PAYLOAD_BYTES];
        let mut buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];

        let headers = vec![
            quiche::h3::Header::new(b":method", b"GET"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"localhost"),
            quiche::h3::Header::new(b":path", b"/stream"),
        ];
        let stream_sid = h3
            .send_request(&mut conn, &headers, true)
            .expect("send_request /stream");
        flush_quic(&mut conn, &socket, &mut out);

        // Wait for first response data chunk — this guarantees the server is in
        // SendingResponse and actively streaming.
        let data_deadline = Instant::now() + Duration::from_secs(REQUEST_TIMEOUT_SECS);
        'wait: loop {
            flush_quic(&mut conn, &socket, &mut out);
            socket.set_read_timeout(Some(quic_read_timeout(&conn))).ok();
            match socket.recv_from(&mut buf) {
                Ok((len, from)) => {
                    let _ = conn.recv(
                        &mut buf[..len],
                        quiche::RecvInfo {
                            from,
                            to: local_addr,
                        },
                    );
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    conn.on_timeout();
                }
                Err(_) => {}
            }
            loop {
                match h3.poll(&mut conn) {
                    Ok((sid, quiche::h3::Event::Data)) if sid == stream_sid => {
                        let mut tmp = [0u8; 4096];
                        while h3.recv_body(&mut conn, sid, &mut tmp).is_ok() {}
                        break 'wait;
                    }
                    Ok((sid, quiche::h3::Event::Finished)) if sid == stream_sid => {
                        panic!("stream finished before teardown point");
                    }
                    Ok(_) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(_) => break,
                }
            }
            if Instant::now() > data_deadline {
                panic!("timed out waiting for /stream response data");
            }
        }
        // Connection drops here (socket + conn out of scope) — server is left
        // in SendingResponse with an orphaned body-pump task.
    }

    // Wait for the server to detect the idle timeout and tear down the stream.
    // quic_max_idle_timeout_ms=300ms + some margin for the poll loop.
    std::thread::sleep(Duration::from_millis(600));

    // ── Second connection: /fast must succeed ──────────────────────────────
    // If the inflight permit was not released, this request gets 503.
    let (socket2, local_addr2, mut conn2, mut h3_2) =
        make_quic_client(listen_addr).expect("second quic client");
    let mut out2 = [0u8; MAX_UDP_PAYLOAD_BYTES];
    let mut buf2 = [0u8; MAX_DATAGRAM_SIZE_BYTES];

    let fast_headers = vec![
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"localhost"),
        quiche::h3::Header::new(b":path", b"/fast"),
    ];
    let fast_sid = h3_2
        .send_request(&mut conn2, &fast_headers, true)
        .expect("send_request /fast on second connection");

    let mut events = Vec::new();
    let mut io = PumpIo {
        socket: &socket2,
        local_addr: local_addr2,
        out: &mut out2,
        buf: &mut buf2,
    };
    let done = pump_h3_until(
        &mut conn2,
        &mut h3_2,
        &mut io,
        fast_sid,
        Instant::now() + Duration::from_secs(REQUEST_TIMEOUT_SECS + 2),
        &mut events,
    );

    assert!(
        done,
        "second-connection /fast must complete; timeout means inflight permit leaked \
         from the abandoned SendingResponse stream"
    );
    assert!(
        events.iter().any(|e| e.starts_with("status:200")),
        "expected 200; 503 means the global inflight permit was not released. \
         events={events:?}"
    );
}

/// Teardown path C: upstream connection times out.
///
/// The client requests `/timeout` which sleeps longer than the configured
/// backend timeout.  The server must send a 503 and clean up all stream
/// resources.  A subsequent /fast request on the same connection must succeed.
#[test]
fn teardown_upstream_timeout_cleans_up_stream() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    let backend_addr = rt.block_on(start_h2_backend_with_regression_routes());
    let mut config = make_config(0, backend_addr.to_string(), cert, key);
    // Use a short timeout so the test doesn't wait long.
    config.performance.backend_timeout_ms = 200;
    config.performance.backend_connect_timeout_ms = 200;

    let listener = QUICListener::new(config).expect("listener");
    let listen_addr = listener.socket.local_addr().unwrap();
    let _guard = ListenerTaskGuard::spawn(&rt, listener);

    let (socket, local_addr, mut conn, mut h3) =
        make_quic_client(listen_addr).expect("quic client");
    let mut out = [0u8; MAX_UDP_PAYLOAD_BYTES];
    let mut buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];

    // Step 1: send /timeout request and wait for the 503 error response.
    let timeout_headers = vec![
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"localhost"),
        quiche::h3::Header::new(b":path", b"/timeout"),
    ];
    let timeout_sid = h3
        .send_request(&mut conn, &timeout_headers, true)
        .expect("send_request /timeout");

    let mut timeout_events = Vec::new();
    // backend_timeout_ms=200ms + some margin for the listener to respond
    let mut io = PumpIo {
        socket: &socket,
        local_addr,
        out: &mut out,
        buf: &mut buf,
    };
    let done = pump_h3_until(
        &mut conn,
        &mut h3,
        &mut io,
        timeout_sid,
        Instant::now() + Duration::from_secs(5),
        &mut timeout_events,
    );
    assert!(done, "timeout stream must finish (with 503)");
    assert!(
        timeout_events.iter().any(|e| e.starts_with("status:503")),
        "timeout must produce 503, got: {timeout_events:?}"
    );

    // Step 2: follow-up /fast on the same connection — proves the timeout
    // teardown released all resources and the connection is still alive.
    let fast_headers = vec![
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"localhost"),
        quiche::h3::Header::new(b":path", b"/fast"),
    ];
    let fast_sid = h3
        .send_request(&mut conn, &fast_headers, true)
        .expect("send_request /fast after timeout");

    let mut fast_events = Vec::new();
    let mut io = PumpIo {
        socket: &socket,
        local_addr,
        out: &mut out,
        buf: &mut buf,
    };
    let done = pump_h3_until(
        &mut conn,
        &mut h3,
        &mut io,
        fast_sid,
        Instant::now() + Duration::from_secs(REQUEST_TIMEOUT_SECS + 2),
        &mut fast_events,
    );
    assert!(
        done,
        "follow-up /fast request must complete after timeout teardown"
    );
    assert!(
        fast_events.iter().any(|e| e.starts_with("status:200")),
        "follow-up request must receive 200, got: {fast_events:?}"
    );
}
