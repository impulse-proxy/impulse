use std::{
    convert::Infallible,
    future::Future,
    net::UdpSocket,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use rand::RngCore;
use rcgen::{Certificate, CertificateParams, SanType};
use tempfile::{TempDir, tempdir};
use tokio::net::TcpListener;

mod support;

use impulse_config::config::{
    Backend, ClientAuth, Config, ExternalAuth, ExternalAuthFailureMode, ExternalAuthRequestHeader,
    HealthCheck, Listen, LoadBalancing, Log, LogFormat, Security, Tls, UpstreamTls,
};
use impulse_edge::{
    MAX_DATAGRAM_SIZE_BYTES, MAX_UDP_PAYLOAD_BYTES, QUIC_IDLE_TIMEOUT_MS, QUIC_INITIAL_MAX_DATA,
    QUIC_INITIAL_MAX_STREAMS_BIDI, QUIC_INITIAL_MAX_STREAMS_UNI, QUIC_INITIAL_STREAM_DATA,
    runtime::listener::QUICListener,
};
use support::{net::local_listener_bind_available, request_path as request_support};

fn write_test_certs(dir: &TempDir) -> (String, String) {
    let mut params = CertificateParams::new(vec!["localhost".into()]);
    params
        .subject_alt_names
        .push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
    let cert = Certificate::from_params(params).expect("failed to build cert");

    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");

    std::fs::write(&cert_path, cert.serialize_pem().unwrap()).unwrap();
    std::fs::write(&key_path, cert.serialize_private_key_pem()).unwrap();

    (
        cert_path.to_string_lossy().to_string(),
        key_path.to_string_lossy().to_string(),
    )
}

fn make_config(port: u32, cert: String, key: String, backend_address: String) -> Config {
    use std::collections::HashMap;

    use impulse_config::config::{RouteMatch, Upstream};

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
            cache: Default::default(),
            tls: None,
            route: RouteMatch {
                path_prefix: Some("/".to_string()),
                ..Default::default()
            },
            backends: vec![Backend {
                id: "backend1".to_string(),
                address: normalize_backend_address(backend_address),
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

fn quic_read_timeout(conn: &quiche::Connection) -> Duration {
    request_support::quic_read_timeout(conn)
}

async fn start_h2_backend_service<F, Fut>(handler: F) -> std::net::SocketAddr
where
    F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let io = TokioIo::new(stream);
            let handler = Arc::clone(&handler);
            let service = service_fn(move |req: Request<Incoming>| {
                let handler = Arc::clone(&handler);
                async move { handler(req).await }
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

async fn start_h2_backend(body: &'static str) -> std::net::SocketAddr {
    let fixture = request_support::start_h1_backend(move |_req: Request<Incoming>| async move {
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
    })
    .await;
    let addr = fixture.addr;
    std::mem::forget(fixture);
    addr
}

async fn start_http_auth_server<F, Fut>(handler: F) -> std::net::SocketAddr
where
    F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let io = TokioIo::new(stream);
            let handler = Arc::clone(&handler);
            let service = service_fn(move |req: Request<Incoming>| {
                let handler = Arc::clone(&handler);
                async move { handler(req).await }
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

#[derive(Debug, Clone, Copy)]
struct ListenerLoopReport {
    poll_count: u64,
    remaining_connections: usize,
    remaining_cid_routes: usize,
    remaining_peer_routes: usize,
}

fn spawn_listener_loop(
    mut listener: QUICListener,
) -> (
    std::net::SocketAddr,
    Arc<AtomicBool>,
    thread::JoinHandle<()>,
) {
    let addr = listener.socket.local_addr().expect("local addr");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        while !stop_flag.load(Ordering::Relaxed) {
            listener.poll();
        }
    });
    (addr, stop, handle)
}

fn stop_listener_loop(stop: Arc<AtomicBool>, handle: thread::JoinHandle<()>) {
    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();
}

fn spawn_listener_loop_with_report(
    mut listener: QUICListener,
) -> (
    std::net::SocketAddr,
    Arc<AtomicBool>,
    thread::JoinHandle<()>,
    mpsc::Receiver<ListenerLoopReport>,
) {
    let addr = listener.socket.local_addr().expect("local addr");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);
    let (report_tx, report_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut poll_count = 0u64;
        while !stop_flag.load(Ordering::Relaxed) {
            listener.poll();
            poll_count = poll_count.saturating_add(1);
        }
        let _ = report_tx.send(ListenerLoopReport {
            poll_count,
            remaining_connections: listener.connections().len(),
            remaining_cid_routes: listener.cid_routes().len(),
            remaining_peer_routes: listener.peer_routes().len(),
        });
    });
    (addr, stop, handle, report_rx)
}

fn stop_listener_loop_with_report(
    stop: Arc<AtomicBool>,
    handle: thread::JoinHandle<()>,
    report_rx: mpsc::Receiver<ListenerLoopReport>,
) -> ListenerLoopReport {
    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();
    report_rx.recv().expect("listener loop report")
}

#[derive(Debug)]
struct H3Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl H3Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn run_h3_client(addr: std::net::SocketAddr) -> Result<String, String> {
    run_h3_client_request(addr, "GET", "/", &[], None).map(|response| response.body)
}

fn run_h3_client_request(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Result<H3Response, String> {
    let response = request_support::run_request_to(
        addr,
        request_support::H3RequestSpec {
            method,
            authority: "localhost",
            path,
            headers,
            body,
            user_agent: "impulse-test",
        },
    )?;
    Ok(H3Response {
        status: response.status,
        headers: response.headers,
        body: String::from_utf8_lossy(&response.body).into_owned(),
    })
}

fn run_h3_client_multiple_requests(
    addr: std::net::SocketAddr,
    request_count: usize,
) -> Result<(usize, usize), String> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    let local_addr = socket.local_addr().map_err(|e| e.to_string())?;

    let mut config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|e| format!("config: {e:?}"))?;
    config.verify_peer(false);
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|e| format!("alpn: {e:?}"))?;
    config.set_active_connection_id_limit(8);
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
    let mut requests_sent = 0usize;
    let mut requests_done = 0usize;
    let mut in_flight = false;
    let mut max_spare_dcids = 0usize;

    let (write, send_info) = conn.send(&mut out).map_err(|e| format!("send: {e:?}"))?;
    socket
        .send_to(&out[..write], send_info.to)
        .map_err(|e| format!("send_to: {e:?}"))?;

    let start = Instant::now();

    while requests_done < request_count {
        loop {
            match conn.send(&mut out) {
                Ok((write, send_info)) => {
                    let _ = socket.send_to(&out[..write], send_info.to);
                }
                Err(quiche::Error::Done) => break,
                Err(e) => return Err(format!("send loop: {e:?}")),
            }
        }

        let timeout = quic_read_timeout(&conn);
        socket
            .set_read_timeout(Some(timeout))
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

        if conn.is_closed() {
            if requests_done > 0 {
                return Ok((max_spare_dcids, requests_done));
            }
            return Err(format!(
                "connection closed early (sent={requests_sent}, done={requests_done}, spare={max_spare_dcids})"
            ));
        }

        max_spare_dcids = max_spare_dcids.max(conn.available_dcids());

        if conn.is_established() && h3_conn.is_none() {
            h3_conn = Some(
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .map_err(|e| format!("h3 conn: {e:?}"))?,
            );
        }

        if let Some(h3) = h3_conn.as_mut() {
            if conn.is_established() && !in_flight && requests_sent < request_count {
                let req = vec![
                    quiche::h3::Header::new(b":method", b"GET"),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(b":authority", b"localhost"),
                    quiche::h3::Header::new(b":path", b"/"),
                    quiche::h3::Header::new(b"user-agent", b"impulse-rotation-test"),
                ];
                h3.send_request(&mut conn, &req, true)
                    .map_err(|e| format!("send_request: {e:?}"))?;
                requests_sent += 1;
                in_flight = true;
            }

            loop {
                match h3.poll(&mut conn) {
                    Ok((stream_id, quiche::h3::Event::Data)) => loop {
                        match h3.recv_body(&mut conn, stream_id, &mut buf) {
                            Ok(_) => {}
                            Err(quiche::h3::Error::Done) => break,
                            Err(e) => return Err(format!("recv_body: {e:?}")),
                        }
                    },
                    Ok((_stream_id, quiche::h3::Event::Headers { .. })) => {}
                    Ok((_stream_id, quiche::h3::Event::Finished)) => {
                        requests_done += 1;
                        in_flight = false;
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

        if start.elapsed() > Duration::from_secs(20) {
            if requests_done > 0 {
                return Ok((max_spare_dcids, requests_done));
            }
            return Err(format!(
                "timeout waiting for responses (sent={requests_sent}, done={requests_done}, inflight={in_flight}, spare={max_spare_dcids})"
            ));
        }
    }

    Ok((max_spare_dcids, requests_done))
}

fn assert_cid_sync_invariants(listener: &QUICListener) {
    for (primary_key, connection) in listener.connections() {
        assert_eq!(
            primary_key.as_ref(),
            connection.primary_scid.as_ref(),
            "connection map key must match connection.primary_scid"
        );

        for cid in &connection.routing_scids {
            let matched = listener
                .cid_radix()
                .longest_prefix_match(cid.as_ref())
                .unwrap_or_else(|| panic!("missing CID in radix: {}", hex::encode(cid)));
            assert_eq!(
                matched.as_ref(),
                cid.as_ref(),
                "radix should return exact SCID for stored prefix"
            );

            if cid.as_ref() == connection.primary_scid.as_ref() {
                assert!(
                    !listener.cid_routes().contains_key(cid.as_ref()),
                    "primary SCID must not be present in alias map"
                );
            } else {
                let mapped_primary = listener
                    .cid_routes()
                    .get(cid.as_ref())
                    .unwrap_or_else(|| panic!("alias CID missing mapping: {}", hex::encode(cid)));
                assert_eq!(
                    mapped_primary.as_ref(),
                    connection.primary_scid.as_ref(),
                    "alias must map to connection primary SCID"
                );
            }
        }
    }

    for (alias, primary) in listener.cid_routes() {
        assert_ne!(
            alias.as_ref(),
            primary.as_ref(),
            "alias route must not map a primary to itself"
        );
        let connection = listener.connections().get(primary).unwrap_or_else(|| {
            panic!(
                "alias points to missing primary connection: alias={} primary={}",
                hex::encode(alias),
                hex::encode(primary)
            )
        });
        assert!(
            connection.routing_scids.contains(alias),
            "alias must exist in the owning connection routing SCID set"
        );
    }
}

#[path = "h3_edge/startup.rs"]
mod startup;

#[path = "h3_edge/scid.rs"]
mod scid;

// ---------------------------------------------------------------------------
// Malformed packet hardening tests (task 1.1)
//
// Each test fires one or more invalid UDP datagrams at a fresh listener and
// asserts that:
//  (a) the listener does not panic,
//  (b) all routing maps remain empty / unchanged after the bad traffic.
//
// The listener is driven by a single poll() call per datagram so the test
// stays synchronous and deterministic.
// ---------------------------------------------------------------------------

fn make_listener() -> (QUICListener, std::net::SocketAddr) {
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);
    let config = make_config(0, cert, key, "127.0.0.1:1".to_string());
    let listener = QUICListener::new(config).expect("failed to create listener");
    let addr = listener.socket.local_addr().expect("local_addr");
    (listener, addr)
}

fn send_udp(to: std::net::SocketAddr, payload: &[u8]) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    sock.send_to(payload, to).expect("send_to");
}

fn assert_maps_empty(listener: &QUICListener) {
    assert!(
        listener.connections().is_empty(),
        "connections map must be empty after malformed traffic, had {} entries",
        listener.connections().len()
    );
    assert!(
        listener.cid_routes().is_empty(),
        "cid_routes must be empty after malformed traffic, had {} entries",
        listener.cid_routes().len()
    );
    assert!(
        listener.peer_routes().is_empty(),
        "peer_routes must be empty after malformed traffic, had {} entries",
        listener.peer_routes().len()
    );
}

#[path = "h3_edge/malformed.rs"]
mod malformed;

// ---------------------------------------------------------------------------
// Connection flood / rate-limit tests (task 1.2)
// ---------------------------------------------------------------------------

fn make_config_with_rate_limit(
    port: u32,
    cert: String,
    key: String,
    backend_address: String,
    new_connections_per_sec: u32,
    new_connections_burst: u32,
) -> Config {
    use std::collections::HashMap;

    use impulse_config::config::{Performance, RouteMatch, Upstream};

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
            cache: Default::default(),
            tls: None,
            route: RouteMatch {
                path_prefix: Some("/".to_string()),
                ..Default::default()
            },
            backends: vec![Backend {
                id: "backend1".to_string(),
                address: normalize_backend_address(backend_address),
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
            level: "error".to_string(),
            file: Default::default(),
            format: LogFormat::Plain,
        },
        performance: Performance {
            new_connections_per_sec,
            new_connections_burst,
            ..Performance::default()
        },
        observability: impulse_config::config::Observability::default(),
        resilience: impulse_config::config::Resilience::default(),
        security: Security::default(),
    }
}

/// Build a minimal valid QUIC Initial packet using quiche so the listener can
/// parse the header and attempt `quiche::accept`. Returns the encoded bytes.
fn build_initial_packet(dest_addr: std::net::SocketAddr) -> Vec<u8> {
    let local_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("quiche config");
    config.verify_peer(false);
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .expect("alpn");
    config.set_max_idle_timeout(QUIC_IDLE_TIMEOUT_MS);
    config.set_max_recv_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    config.set_max_send_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    config.set_initial_max_data(QUIC_INITIAL_MAX_DATA);
    config.set_initial_max_stream_data_bidi_local(QUIC_INITIAL_STREAM_DATA);
    config.set_initial_max_stream_data_bidi_remote(QUIC_INITIAL_STREAM_DATA);
    config.set_initial_max_stream_data_uni(QUIC_INITIAL_STREAM_DATA);
    config.set_initial_max_streams_bidi(QUIC_INITIAL_MAX_STREAMS_BIDI);
    config.set_initial_max_streams_uni(QUIC_INITIAL_MAX_STREAMS_UNI);

    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    rand::thread_rng().fill_bytes(&mut scid_bytes);
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);

    let mut conn = quiche::connect(Some("localhost"), &scid, local_addr, dest_addr, &mut config)
        .expect("quiche connect");

    let mut out = vec![0u8; MAX_UDP_PAYLOAD_BYTES];
    let (len, _send_info) = conn.send(&mut out).expect("quiche send");
    out.truncate(len);
    out
}

#[path = "h3_edge/admission.rs"]
mod admission;

#[path = "h3_edge/external_auth.rs"]
mod external_auth;

// ---------------------------------------------------------------------------
// Connection-lifecycle churn stress test (task 4.3)
//
// Runs many connect/request/disconnect cycles and asserts that no orphaned
// entries are left in connections, cid_routes, peer_routes, or the radix trie.
// ---------------------------------------------------------------------------

/// Build a QUIC client config suitable for stress rounds.
fn make_quic_client_config() -> quiche::Config {
    let mut cfg = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("quiche config");
    cfg.verify_peer(false);
    cfg.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .expect("alpn");
    // Use a short idle timeout so dropped sockets get cleaned up quickly.
    cfg.set_max_idle_timeout(500);
    cfg.set_max_recv_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    cfg.set_max_send_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    cfg.set_initial_max_data(QUIC_INITIAL_MAX_DATA);
    cfg.set_initial_max_stream_data_bidi_local(QUIC_INITIAL_STREAM_DATA);
    cfg.set_initial_max_stream_data_bidi_remote(QUIC_INITIAL_STREAM_DATA);
    cfg.set_initial_max_stream_data_uni(QUIC_INITIAL_STREAM_DATA);
    cfg.set_initial_max_streams_bidi(QUIC_INITIAL_MAX_STREAMS_BIDI);
    cfg.set_initial_max_streams_uni(QUIC_INITIAL_MAX_STREAMS_UNI);
    cfg.set_disable_active_migration(true);
    cfg
}

/// Connect to `server_addr` and drive the QUIC handshake until established.
/// Returns `(socket, local_addr, conn, h3)` on success, or an error string.
fn stress_connect(
    server_addr: std::net::SocketAddr,
) -> Result<
    (
        UdpSocket,
        std::net::SocketAddr,
        quiche::Connection,
        quiche::h3::Connection,
    ),
    String,
> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    let local_addr = socket.local_addr().map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(|e| e.to_string())?;

    let mut cfg = make_quic_client_config();
    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    rand::thread_rng().fill_bytes(&mut scid_bytes);
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);

    let mut conn = quiche::connect(Some("localhost"), &scid, local_addr, server_addr, &mut cfg)
        .map_err(|e| format!("connect: {e:?}"))?;

    let mut out = [0u8; MAX_UDP_PAYLOAD_BYTES];
    let mut buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];

    let (w, si) = conn.send(&mut out).map_err(|e| format!("send: {e:?}"))?;
    socket
        .send_to(&out[..w], si.to)
        .map_err(|e| format!("send_to: {e:?}"))?;

    let deadline = Instant::now() + Duration::from_secs(5);
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

        if Instant::now() > deadline {
            return Err("handshake timeout".to_string());
        }
    }

    let h3_cfg = quiche::h3::Config::new().map_err(|e| format!("h3 cfg: {e:?}"))?;
    let h3 = quiche::h3::Connection::with_transport(&mut conn, &h3_cfg)
        .map_err(|e| format!("h3 conn: {e:?}"))?;

    Ok((socket, local_addr, conn, h3))
}

/// Send a graceful QUIC CONNECTION_CLOSE and flush.
fn stress_close_gracefully(socket: &UdpSocket, conn: &mut quiche::Connection) {
    let _ = conn.close(false, 0, b"done");
    let mut out = [0u8; MAX_UDP_PAYLOAD_BYTES];
    while let Ok((w, si)) = conn.send(&mut out) {
        let _ = socket.send_to(&out[..w], si.to);
    }
}

#[path = "h3_edge/lifecycle.rs"]
mod lifecycle;
