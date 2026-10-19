#![allow(dead_code)]

use std::{
    collections::HashMap,
    convert::Infallible,
    future::Future,
    net::{IpAddr, SocketAddr, TcpListener as StdTcpListener, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{
    Request, Response,
    body::{Body, Frame, Incoming},
    client::conn::http2,
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use impulse_config::{
    config::{Backend, Config, LoadBalancing, RouteMatch, Upstream, UpstreamTls},
    runtime::RuntimeBackendTlsPolicy,
    validator::validate,
};
use impulse_edge::{
    MAX_DATAGRAM_SIZE_BYTES, MAX_UDP_PAYLOAD_BYTES, Metrics, QUIC_IDLE_TIMEOUT_MS,
    QUIC_INITIAL_MAX_DATA, QUIC_INITIAL_MAX_STREAMS_BIDI, QUIC_INITIAL_MAX_STREAMS_UNI,
    QUIC_INITIAL_STREAM_DATA, REQUEST_TIMEOUT_SECS, UDP_READ_TIMEOUT_MS,
    runtime::listener::QUICListener,
};
use impulse_lb::pingora_backend::SharedPingoraLoadBalancingRuntimeState;
use impulse_transport::SharedDnsResolver;
use quiche::h3::NameValue;
use rand::RngCore;
use rcgen::{Certificate, CertificateParams, SanType};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tempfile::{TempDir, tempdir};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    rustls::{
        ClientConfig, RootCertStore, ServerConfig, pki_types::ServerName,
        server::WebPkiClientVerifier,
    },
};

use super::{base_quic_test_config, static_full_response};

pub(crate) struct TestTlsMaterial {
    _dir: TempDir,
    pub cert_path: String,
    pub key_path: String,
}

impl TestTlsMaterial {
    pub(crate) fn localhost() -> Self {
        let dir = tempdir().expect("tempdir");
        let mut params = CertificateParams::new(vec!["localhost".into()]);
        params
            .subject_alt_names
            .push(SanType::DnsName("localhost".to_string()));
        params
            .subject_alt_names
            .push(SanType::IpAddress(IpAddr::from([127, 0, 0, 1])));
        let cert = Certificate::from_params(params).expect("failed to build cert");

        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        std::fs::write(&cert_path, cert.serialize_pem().expect("serialize cert"))
            .expect("write cert");
        std::fs::write(&key_path, cert.serialize_private_key_pem()).expect("write key");

        Self {
            _dir: dir,
            cert_path: cert_path.to_string_lossy().to_string(),
            key_path: key_path.to_string_lossy().to_string(),
        }
    }
}

pub(crate) struct BackendFixture {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl Drop for BackendFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.accept_task.abort();
    }
}

pub(crate) struct ListenerTaskGuard {
    stop: Arc<AtomicBool>,
    handle: tokio::task::JoinHandle<()>,
}

impl ListenerTaskGuard {
    pub(crate) fn spawn(rt: &tokio::runtime::Runtime, mut listener: QUICListener) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let runtime_handle = rt.handle().clone();
        let handle = rt.spawn_blocking(move || {
            let _enter = runtime_handle.enter();
            while !stop_flag.load(Ordering::Relaxed) {
                listener.poll();
            }
        });
        Self { stop, handle }
    }
}

impl Drop for ListenerTaskGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.abort();
    }
}

pub(crate) struct QuicRequestPathHarness {
    backends: Vec<BackendFixture>,
    listener_task: Option<ListenerTaskGuard>,
    backend_dns_resolver: Option<SharedDnsResolver>,
    pingora_load_balancing: Option<SharedPingoraLoadBalancingRuntimeState<RuntimeBackendTlsPolicy>>,
    metrics: Option<Arc<Metrics>>,
    rt: tokio::runtime::Runtime,
    pub tls: TestTlsMaterial,
    pub listen_addr: Option<SocketAddr>,
}

impl QuicRequestPathHarness {
    pub(crate) fn new() -> Self {
        Self {
            backends: Vec::new(),
            listener_task: None,
            backend_dns_resolver: None,
            pingora_load_balancing: None,
            metrics: None,
            rt: tokio::runtime::Runtime::new().expect("runtime"),
            tls: TestTlsMaterial::localhost(),
            listen_addr: None,
        }
    }

    pub(crate) fn make_config(&self, upstreams: HashMap<String, Upstream>) -> Config {
        base_quic_test_config(
            reserve_unused_listener_port(),
            &self.tls.cert_path,
            &self.tls.key_path,
            upstreams,
        )
    }

    pub(crate) fn start_listener(&mut self, config: Config) -> Result<SocketAddr, String> {
        validate(&config).map_err(|err| format!("config validation failed: {err}"))?;
        let listener = QUICListener::new(config).map_err(|err| format!("listener: {err}"))?;
        self.backend_dns_resolver = Some(listener.backend_dns_resolver.clone());
        self.pingora_load_balancing = Some(Arc::clone(&listener.pingora_load_balancing));
        self.metrics = Some(Arc::clone(&listener.metrics));
        let listen_addr = listener
            .socket
            .local_addr()
            .map_err(|err| format!("listen addr: {err}"))?;
        self.listener_task = Some(ListenerTaskGuard::spawn(&self.rt, listener));
        self.listen_addr = Some(listen_addr);
        Ok(listen_addr)
    }

    pub(crate) fn start_h1_backend<F, Fut>(&mut self, handler: F) -> SocketAddr
    where
        F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send + 'static,
    {
        let fixture = self.rt.block_on(start_h1_backend(handler));
        let addr = fixture.addr;
        self.backends.push(fixture);
        addr
    }

    pub(crate) fn start_h1_static_backend(&mut self, body: &'static [u8]) -> SocketAddr {
        self.start_h1_backend(
            move |_req| async move { Ok::<_, Infallible>(static_full_response(body)) },
        )
    }

    pub(crate) fn start_h1_websocket_upgrade_backend(&mut self) -> SocketAddr {
        let fixture = self.rt.block_on(start_h1_websocket_upgrade_backend());
        let addr = fixture.addr;
        self.backends.push(fixture);
        addr
    }

    pub(crate) fn start_h1_chunked_backend(&mut self, chunks: Vec<&'static [u8]>) -> SocketAddr {
        let fixture = self.rt.block_on(start_h1_chunked_backend(chunks));
        let addr = fixture.addr;
        self.backends.push(fixture);
        addr
    }

    pub(crate) fn start_h1_delayed_chunked_backend(
        &mut self,
        chunks: Vec<(Vec<u8>, Duration)>,
    ) -> SocketAddr {
        let fixture = self.rt.block_on(start_h1_delayed_chunked_backend(chunks));
        let addr = fixture.addr;
        self.backends.push(fixture);
        addr
    }

    pub(crate) fn start_h2_backend<F, Fut>(&mut self, handler: F) -> SocketAddr
    where
        F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send + 'static,
    {
        let fixture = self.rt.block_on(start_h2_backend(
            &self.tls.cert_path,
            &self.tls.key_path,
            handler,
        ));
        let addr = fixture.addr;
        self.backends.push(fixture);
        addr
    }

    pub(crate) fn start_h2_backend_with_client_auth<F, Fut>(
        &mut self,
        cert_path: &str,
        key_path: &str,
        client_ca_path: &str,
        handler: F,
    ) -> SocketAddr
    where
        F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send + 'static,
    {
        let fixture = self.rt.block_on(start_h2_backend_with_client_auth(
            cert_path,
            key_path,
            client_ca_path,
            handler,
        ));
        let addr = fixture.addr;
        self.backends.push(fixture);
        addr
    }

    pub(crate) fn start_h2_static_backend(&mut self, body: &'static [u8]) -> SocketAddr {
        self.start_h2_backend(
            move |_req| async move { Ok::<_, Infallible>(static_full_response(body)) },
        )
    }

    pub(crate) fn start_h2_streaming_backend(&mut self, chunks: Vec<&'static [u8]>) -> SocketAddr {
        let fixture = self.rt.block_on(start_h2_streaming_backend(
            &self.tls.cert_path,
            &self.tls.key_path,
            chunks,
            None,
        ));
        let addr = fixture.addr;
        self.backends.push(fixture);
        addr
    }

    pub(crate) fn start_h2_trailer_backend(
        &mut self,
        chunks: Vec<&'static [u8]>,
        trailers: http::HeaderMap,
    ) -> SocketAddr {
        let fixture = self.rt.block_on(start_h2_streaming_backend(
            &self.tls.cert_path,
            &self.tls.key_path,
            chunks,
            Some(trailers),
        ));
        let addr = fixture.addr;
        self.backends.push(fixture);
        addr
    }

    pub(crate) fn run_request(&self, request: H3RequestSpec<'_>) -> Result<H3Response, String> {
        let listen_addr = self
            .listen_addr
            .ok_or_else(|| "listener not started".to_string())?;
        run_h3_request(listen_addr, request)
    }

    pub(crate) fn metrics_text(&self) -> Option<String> {
        self.metrics
            .as_ref()
            .map(|metrics| metrics.render_prometheus())
    }

    pub(crate) fn discovery_runtime(
        &self,
    ) -> Option<(
        SharedDnsResolver,
        SharedPingoraLoadBalancingRuntimeState<RuntimeBackendTlsPolicy>,
    )> {
        Some((
            self.backend_dns_resolver.clone()?,
            Arc::clone(self.pingora_load_balancing.as_ref()?),
        ))
    }
}

impl Default for QuicRequestPathHarness {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn make_quic_test_config(
    cert_path: &str,
    key_path: &str,
    upstreams: HashMap<String, Upstream>,
) -> Config {
    make_quic_test_config_with_upstream_tls(cert_path, key_path, upstreams, UpstreamTls::default())
}

pub(crate) fn make_quic_test_config_with_upstream_tls(
    cert_path: &str,
    key_path: &str,
    upstreams: HashMap<String, Upstream>,
    upstream_tls: UpstreamTls,
) -> Config {
    let mut config = base_quic_test_config(
        reserve_unused_listener_port(),
        cert_path,
        key_path,
        upstreams,
    );
    config.upstream_tls = upstream_tls;
    config
}

pub(crate) fn make_upstream(
    path_prefix: &str,
    backends: Vec<Backend>,
    tls: Option<UpstreamTls>,
    lb_type: &str,
) -> Upstream {
    Upstream {
        load_balancing: LoadBalancing {
            lb_type: lb_type.to_string(),
            key: None,
        },
        auth: Default::default(),
        host_policy: Default::default(),
        forwarded_headers: Default::default(),
        compression: Default::default(),
        cache: Default::default(),
        tls,
        route: RouteMatch {
            host: None,
            path_prefix: Some(path_prefix.to_string()),
            method: None,
        },
        backends,
    }
}

pub(crate) fn make_backend(id: &str, address: impl Into<String>) -> Backend {
    Backend {
        id: id.to_string(),
        address: normalize_backend_address(address.into()),
        weight: 1,
        health_check: None,
    }
}

pub(crate) fn normalize_backend_address(address: String) -> String {
    if address.contains("://") {
        address
    } else {
        format!("http://{address}")
    }
}

pub(crate) struct H3RequestSpec<'a> {
    pub method: &'a str,
    pub authority: &'a str,
    pub path: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: Option<&'a [u8]>,
    pub user_agent: &'a str,
}

impl<'a> H3RequestSpec<'a> {
    pub(crate) fn get(authority: &'a str, path: &'a str) -> Self {
        Self {
            method: "GET",
            authority,
            path,
            headers: &[],
            body: None,
            user_agent: "impulse-request-path-test",
        }
    }
}

pub(crate) struct H3Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub trailers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl H3Response {
    pub(crate) fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find_map(|(header_name, value)| {
            header_name
                .eq_ignore_ascii_case(name)
                .then_some(value.as_str())
        })
    }

    pub(crate) fn assert_status(&self, expected: u16) {
        assert_eq!(
            self.status, expected,
            "unexpected H3 response status for request-path integration response"
        );
    }

    pub(crate) fn assert_body_bytes(&self, expected: &[u8]) {
        assert_eq!(
            self.body.as_slice(),
            expected,
            "unexpected H3 response body for request-path integration response"
        );
    }

    pub(crate) fn assert_body_text(&self, expected: &str) {
        assert_eq!(
            self.body_text(),
            expected,
            "unexpected H3 response text body for request-path integration response"
        );
    }
}

#[derive(Clone, Copy)]
pub(crate) struct HttpRequestSpec<'a> {
    pub method: &'a str,
    pub authority: &'a str,
    pub path: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: Option<&'a [u8]>,
    pub user_agent: &'a str,
}

impl<'a> HttpRequestSpec<'a> {
    pub(crate) fn get(authority: &'a str, path: &'a str) -> Self {
        Self {
            method: "GET",
            authority,
            path,
            headers: &[],
            body: None,
            user_agent: "impulse-request-path-test",
        }
    }
}

pub(crate) struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub trailers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub(crate) fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find_map(|(header_name, value)| {
            header_name
                .eq_ignore_ascii_case(name)
                .then_some(value.as_str())
        })
    }
}

pub(crate) fn run_request_to(
    addr: SocketAddr,
    request: H3RequestSpec<'_>,
) -> Result<H3Response, String> {
    run_h3_request(addr, request)
}

pub(crate) fn run_h3_get_to(
    addr: SocketAddr,
    authority: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Result<H3Response, String> {
    run_request_to(
        addr,
        H3RequestSpec {
            method: "GET",
            authority,
            path,
            headers,
            body: None,
            user_agent: "impulse-test",
        },
    )
}

pub(crate) fn run_http2_request_to(
    addr: SocketAddr,
    cert_path: &str,
    request: HttpRequestSpec<'_>,
) -> Result<HttpResponse, String> {
    tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(run_http2_request(addr, cert_path, request))
}

async fn run_http2_request(
    addr: SocketAddr,
    cert_path: &str,
    request: HttpRequestSpec<'_>,
) -> Result<HttpResponse, String> {
    let (mut sender, _conn_task) = connect_http2(addr, cert_path).await?;
    sender
        .ready()
        .await
        .map_err(|err| format!("sender ready: {err}"))?;

    let uri = if request.method.eq_ignore_ascii_case("CONNECT") {
        http::Uri::builder()
            .authority(request.authority)
            .build()
            .map_err(|err| format!("uri build: {err}"))?
    } else {
        http::Uri::builder()
            .path_and_query(request.path)
            .build()
            .map_err(|err| format!("uri build: {err}"))?
    };
    let mut builder = Request::builder()
        .method(request.method)
        .uri(uri)
        .header("host", request.authority)
        .header("user-agent", request.user_agent);
    for (name, value) in request.headers {
        builder = builder.header(*name, *value);
    }

    let body = request.body.unwrap_or_default().to_vec();
    let req = builder
        .body(
            Full::new(Bytes::from(body))
                .map_err(|never| match never {})
                .boxed(),
        )
        .map_err(|err| format!("request build: {err}"))?;
    let response = sender
        .send_request(req)
        .await
        .map_err(|err| format!("send request: {err}"))?;
    read_http2_response(response).await
}

async fn read_http2_response(mut response: Response<Incoming>) -> Result<HttpResponse, String> {
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            Ok::<_, String>((
                name.as_str().to_string(),
                value
                    .to_str()
                    .map_err(|err| format!("header utf8: {err}"))?
                    .to_string(),
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut body = Vec::new();
    let mut trailers = Vec::new();

    while let Some(frame) = response.body_mut().frame().await {
        let frame = frame.map_err(|err| format!("read frame: {err}"))?;
        match frame.into_data() {
            Ok(data) => body.extend_from_slice(&data),
            Err(frame) => {
                if let Ok(values) = frame.into_trailers() {
                    trailers.extend(values.iter().map(|(name, value)| {
                        (
                            name.as_str().to_string(),
                            value.to_str().unwrap_or_default().to_string(),
                        )
                    }));
                }
            }
        }
    }

    Ok(HttpResponse {
        status,
        headers,
        trailers,
        body,
    })
}

async fn connect_http2(
    addr: SocketAddr,
    cert_path: &str,
) -> Result<
    (
        hyper::client::conn::http2::SendRequest<BoxBody<Bytes, Infallible>>,
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

fn read_test_root_store(cert_path: &str) -> Result<RootCertStore, String> {
    let mut roots = RootCertStore::empty();
    let certs = CertificateDer::pem_file_iter(cert_path)
        .map_err(|err| format!("open cert file: {err}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("parse certs: {err}"))?;

    for cert in certs {
        roots
            .add(cert)
            .map_err(|err| format!("add root cert: {err}"))?;
    }

    Ok(roots)
}

pub(crate) fn run_two_chunk_post_to(
    addr: SocketAddr,
    authority: &str,
    path: &str,
    chunk1: Vec<u8>,
    chunk2: Vec<u8>,
    delay_between_chunks: Duration,
) -> Result<(H3Response, bool), String> {
    run_two_chunk_post_to_with_response_timeout(
        addr,
        authority,
        path,
        chunk1,
        chunk2,
        delay_between_chunks,
        Duration::from_secs(REQUEST_TIMEOUT_SECS + 4),
    )
}

pub(crate) fn run_two_chunk_post_to_with_response_timeout(
    addr: SocketAddr,
    authority: &str,
    path: &str,
    chunk1: Vec<u8>,
    chunk2: Vec<u8>,
    delay_between_chunks: Duration,
    response_timeout: Duration,
) -> Result<(H3Response, bool), String> {
    run_two_chunk_post(
        addr,
        authority,
        path,
        chunk1,
        chunk2,
        delay_between_chunks,
        response_timeout,
        false,
    )
}

pub(crate) fn cancel_h3_post_to(
    addr: SocketAddr,
    authority: &str,
    path: &str,
) -> Result<(), String> {
    run_two_chunk_post(
        addr,
        authority,
        path,
        vec![b'a'],
        vec![b'b'],
        Duration::ZERO,
        Duration::from_secs(REQUEST_TIMEOUT_SECS),
        true,
    )
    .map(|_| ())
}

fn run_two_chunk_post(
    addr: SocketAddr,
    authority: &str,
    path: &str,
    chunk1: Vec<u8>,
    chunk2: Vec<u8>,
    delay_between_chunks: Duration,
    response_timeout: Duration,
    cancel_after_first_chunk: bool,
) -> Result<(H3Response, bool), String> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|err| err.to_string())?;
    let local_addr = socket.local_addr().map_err(|err| err.to_string())?;

    let total_len = chunk1.len() + chunk2.len();
    let mut config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|err| format!("config: {err:?}"))?;
    config.verify_peer(false);
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|err| format!("alpn: {err:?}"))?;
    config.set_max_idle_timeout(QUIC_IDLE_TIMEOUT_MS);
    config.set_max_recv_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    config.set_max_send_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    let window = ((total_len as u64 + 1) * 2).max(QUIC_INITIAL_STREAM_DATA);
    config.set_initial_max_data(window * 4);
    config.set_initial_max_stream_data_bidi_local(window);
    config.set_initial_max_stream_data_bidi_remote(window);
    config.set_initial_max_stream_data_uni(window);
    config.set_initial_max_streams_bidi(QUIC_INITIAL_MAX_STREAMS_BIDI);
    config.set_initial_max_streams_uni(QUIC_INITIAL_MAX_STREAMS_UNI);
    config.set_disable_active_migration(true);

    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    rand::thread_rng().fill_bytes(&mut scid_bytes);
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
    let mut conn = quiche::connect(Some("localhost"), &scid, local_addr, addr, &mut config)
        .map_err(|err| format!("connect: {err:?}"))?;
    let h3_config = quiche::h3::Config::new().map_err(|err| format!("h3: {err:?}"))?;
    let mut h3: Option<quiche::h3::Connection> = None;

    let mut out = [0u8; MAX_UDP_PAYLOAD_BYTES];
    let mut buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];
    let start = Instant::now();
    let mut stream_id: Option<u64> = None;
    let mut chunk1_written = 0usize;
    let mut chunk2_written = 0usize;
    let mut delayed_once = false;
    let mut status = 0u16;
    let mut headers = Vec::new();
    let mut body = Vec::new();
    let mut trailers = Vec::new();
    let mut received_response_headers = false;
    let mut got_reset = false;
    let mut request_stream_stopped = false;

    let (write, send_info) = conn
        .send(&mut out)
        .map_err(|err| format!("send: {err:?}"))?;
    socket
        .send_to(&out[..write], send_info.to)
        .map_err(|err| format!("send_to: {err:?}"))?;

    loop {
        loop {
            match conn.send(&mut out) {
                Ok((write, send_info)) => {
                    let _ = socket.send_to(&out[..write], send_info.to);
                }
                Err(quiche::Error::Done) => break,
                Err(err) => return Err(format!("send loop: {err:?}")),
            }
        }

        socket
            .set_read_timeout(Some(quic_read_timeout(&conn)))
            .map_err(|err| format!("timeout: {err:?}"))?;

        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                conn.recv(
                    &mut buf[..len],
                    quiche::RecvInfo {
                        from,
                        to: local_addr,
                    },
                )
                .map_err(|err| format!("recv: {err:?}"))?;
            }
            Err(ref err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                conn.on_timeout();
            }
            Err(err) => return Err(format!("recv: {err:?}")),
        }

        if conn.is_established() && h3.is_none() {
            h3 = Some(
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .map_err(|err| format!("h3 conn: {err:?}"))?,
            );
        }

        if let Some(h3_conn) = h3.as_mut() {
            if stream_id.is_none() && conn.is_established() {
                let content_length = total_len.to_string();
                let headers_list = vec![
                    quiche::h3::Header::new(b":method", b"POST"),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(b":authority", authority.as_bytes()),
                    quiche::h3::Header::new(b":path", path.as_bytes()),
                    quiche::h3::Header::new(b"user-agent", b"impulse-request-path-test"),
                    quiche::h3::Header::new(b"content-length", content_length.as_bytes()),
                ];
                stream_id = Some(
                    h3_conn
                        .send_request(&mut conn, &headers_list, false)
                        .map_err(|err| format!("send_request: {err:?}"))?,
                );
            }

            if let Some(sid) = stream_id {
                if request_stream_stopped {
                    // Keep polling for the terminal response after the server
                    // has stopped accepting request-body bytes.
                } else if status != 0 {
                    request_stream_stopped = true;
                    chunk1_written = chunk1.len();
                    chunk2_written = chunk2.len();
                } else if chunk1_written < chunk1.len() {
                    match h3_conn.send_body(&mut conn, sid, &chunk1[chunk1_written..], false) {
                        Ok(written) => {
                            chunk1_written += written;
                            if cancel_after_first_chunk && chunk1_written == chunk1.len() {
                                conn.stream_shutdown(sid, quiche::Shutdown::Write, 0)
                                    .map_err(|err| format!("cancel request stream: {err:?}"))?;
                                while let Ok((write, send_info)) = conn.send(&mut out) {
                                    socket
                                        .send_to(&out[..write], send_info.to)
                                        .map_err(|err| format!("send cancellation: {err:?}"))?;
                                }
                                return Ok((
                                    H3Response {
                                        status: 0,
                                        headers: Vec::new(),
                                        trailers: Vec::new(),
                                        body: Vec::new(),
                                    },
                                    true,
                                ));
                            }
                        }
                        Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => {}
                        Err(quiche::h3::Error::TransportError(quiche::Error::StreamStopped(_))) => {
                            request_stream_stopped = true;
                            chunk1_written = chunk1.len();
                            chunk2_written = chunk2.len();
                        }
                        Err(err) => return Err(format!("send_body chunk1: {err:?}")),
                    }
                } else {
                    if !delayed_once && !delay_between_chunks.is_zero() {
                        std::thread::sleep(delay_between_chunks);
                        delayed_once = true;
                    }
                    if chunk2_written < chunk2.len() {
                        match h3_conn.send_body(&mut conn, sid, &chunk2[chunk2_written..], true) {
                            Ok(written) => chunk2_written += written,
                            Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => {}
                            Err(quiche::h3::Error::TransportError(
                                quiche::Error::StreamStopped(_),
                            )) => {
                                request_stream_stopped = true;
                                chunk2_written = chunk2.len();
                            }
                            Err(err) => return Err(format!("send_body chunk2: {err:?}")),
                        }
                    }
                }
            }

            loop {
                match h3_conn.poll(&mut conn) {
                    Ok((_stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        let target = if received_response_headers {
                            &mut trailers
                        } else {
                            received_response_headers = true;
                            &mut headers
                        };
                        for header in &list {
                            let name = String::from_utf8_lossy(header.name()).to_string();
                            let value = String::from_utf8_lossy(header.value()).to_string();
                            if name == ":status" {
                                status = value.parse::<u16>().unwrap_or_default();
                            }
                            target.push((name, value));
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Data)) => loop {
                        match h3_conn.recv_body(&mut conn, stream_id, &mut buf) {
                            Ok(read) => body.extend_from_slice(&buf[..read]),
                            Err(quiche::h3::Error::Done) => break,
                            Err(err) => return Err(format!("recv_body: {err:?}")),
                        }
                    },
                    Ok((_stream_id, quiche::h3::Event::Finished)) => {
                        return Ok((
                            H3Response {
                                status,
                                headers,
                                trailers,
                                body,
                            },
                            got_reset,
                        ));
                    }
                    Ok((_stream_id, quiche::h3::Event::Reset(_))) => {
                        got_reset = true;
                        return Ok((
                            H3Response {
                                status,
                                headers,
                                trailers,
                                body,
                            },
                            got_reset,
                        ));
                    }
                    Ok((_stream_id, quiche::h3::Event::PriorityUpdate)) => {}
                    Ok((_stream_id, quiche::h3::Event::GoAway)) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(err) => return Err(format!("poll: {err:?}")),
                }
            }
        }

        if start.elapsed() > response_timeout {
            return Err(format!(
                "timeout waiting for response (status={status}, body_len={}, got_reset={got_reset})",
                body.len()
            ));
        }
    }
}

pub(crate) async fn start_h1_backend<F, Fut>(handler: F) -> BackendFixture
where
    F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send + 'static,
{
    start_h1_backend_on(SocketAddr::from(([127, 0, 0, 1], 0)), handler)
        .await
        .expect("bind h1 test backend listener")
}

pub(crate) async fn start_h1_backend_on<F, Fut>(
    bind_addr: SocketAddr,
    handler: F,
) -> Result<BackendFixture, String>
where
    F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send + 'static,
{
    let listener = bind_tcp_listener_at(bind_addr)?;
    let addr = listener.local_addr().expect("h1 local addr");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);
    let handler = Arc::new(handler);

    let accept_task = tokio::spawn(async move {
        while !stop_flag.load(Ordering::Relaxed) {
            let (stream, _) = match listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let handler = Arc::clone(&handler);
                    async move { handler(req).await }
                });

                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    Ok(BackendFixture {
        addr,
        stop,
        accept_task,
    })
}

pub(crate) async fn start_h1_websocket_upgrade_backend() -> BackendFixture {
    let listener = bind_tcp_listener();
    let addr = listener.local_addr().expect("h1 websocket local addr");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);

    let accept_task = tokio::spawn(async move {
        while !stop_flag.load(Ordering::Relaxed) {
            let (stream, _) = match listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let service = service_fn(|mut req: Request<Incoming>| async move {
                    let is_upgrade = req
                        .headers()
                        .get(http::header::UPGRADE)
                        .and_then(|value| value.to_str().ok())
                        .map(|value| value.eq_ignore_ascii_case("websocket"))
                        .unwrap_or(false)
                        && req
                            .headers()
                            .get(http::header::CONNECTION)
                            .and_then(|value| value.to_str().ok())
                            .map(|value| {
                                value
                                    .split(',')
                                    .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
                            })
                            .unwrap_or(false);

                    if !is_upgrade {
                        return Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(http::StatusCode::BAD_REQUEST)
                                .body(Full::new(Bytes::from_static(b"missing upgrade\n")))
                                .expect("websocket bad request"),
                        );
                    }

                    let on_upgrade = hyper::upgrade::on(&mut req);
                    tokio::spawn(async move {
                        let _ = on_upgrade.await;
                    });

                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(http::StatusCode::SWITCHING_PROTOCOLS)
                            .header(http::header::CONNECTION, "upgrade")
                            .header(http::header::UPGRADE, "websocket")
                            .header("sec-websocket-accept", "test-accept")
                            .body(Full::new(Bytes::new()))
                            .expect("websocket upgrade response"),
                    )
                });

                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades()
                    .await;
            });
        }
    });

    BackendFixture {
        addr,
        stop,
        accept_task,
    }
}

pub(crate) async fn start_h2_backend<F, Fut>(
    cert_path: &str,
    key_path: &str,
    handler: F,
) -> BackendFixture
where
    F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send + 'static,
{
    let mut tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(read_test_chain(cert_path), read_test_key(key_path))
        .expect("server tls config");
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = bind_tcp_listener();
    let addr = listener.local_addr().expect("h2 local addr");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);
    let handler = Arc::new(handler);

    let accept_task = tokio::spawn(async move {
        while !stop_flag.load(Ordering::Relaxed) {
            let (stream, _) = match listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(stream).await {
                    Ok(stream) => stream,
                    Err(_) => return,
                };
                let service = service_fn(move |req: Request<Incoming>| {
                    let handler = Arc::clone(&handler);
                    async move { handler(req).await }
                });

                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls_stream), service)
                    .await;
            });
        }
    });

    BackendFixture {
        addr,
        stop,
        accept_task,
    }
}

pub(crate) async fn start_h2_backend_with_client_auth<F, Fut>(
    cert_path: &str,
    key_path: &str,
    client_ca_path: &str,
    handler: F,
) -> BackendFixture
where
    F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send + 'static,
{
    let verifier = WebPkiClientVerifier::builder(Arc::new(
        read_test_root_store(client_ca_path).expect("client auth root store"),
    ))
    .build()
    .expect("client verifier");
    let mut tls_config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(read_test_chain(cert_path), read_test_key(key_path))
        .expect("server tls config");
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = bind_tcp_listener();
    let addr = listener.local_addr().expect("h2 local addr");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);
    let handler = Arc::new(handler);

    let accept_task = tokio::spawn(async move {
        while !stop_flag.load(Ordering::Relaxed) {
            let (stream, _) = match listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(stream).await {
                    Ok(stream) => stream,
                    Err(_) => return,
                };
                let service = service_fn(move |req: Request<Incoming>| {
                    let handler = Arc::clone(&handler);
                    async move { handler(req).await }
                });

                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls_stream), service)
                    .await;
            });
        }
    });

    BackendFixture {
        addr,
        stop,
        accept_task,
    }
}

pub(crate) async fn start_h2_streaming_backend(
    cert_path: &str,
    key_path: &str,
    chunks: Vec<&'static [u8]>,
    trailers: Option<http::HeaderMap>,
) -> BackendFixture {
    let mut tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(read_test_chain(cert_path), read_test_key(key_path))
        .expect("server tls config");
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = bind_tcp_listener();
    let addr = listener.local_addr().expect("h2 streaming local addr");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);

    let accept_task = tokio::spawn(async move {
        while !stop_flag.load(Ordering::Relaxed) {
            let (stream, _) = match listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            let chunks = chunks.clone();
            let trailers = trailers.clone();
            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(stream).await {
                    Ok(stream) => stream,
                    Err(_) => return,
                };
                let service = service_fn(move |_req: Request<Incoming>| {
                    let body = ChunkSequenceBody::new(
                        chunks
                            .iter()
                            .map(|chunk| Bytes::from_static(chunk))
                            .collect::<Vec<_>>(),
                        trailers.clone(),
                    );
                    async move { Ok::<_, hyper::Error>(Response::new(body)) }
                });

                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls_stream), service)
                    .await;
            });
        }
    });

    BackendFixture {
        addr,
        stop,
        accept_task,
    }
}

pub(crate) async fn start_h1_chunked_backend(chunks: Vec<&'static [u8]>) -> BackendFixture {
    let listener = bind_tcp_listener();
    let addr = listener.local_addr().expect("h1 chunked local addr");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);

    let accept_task = tokio::spawn(async move {
        while !stop_flag.load(Ordering::Relaxed) {
            let (mut stream, _) = match listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            let chunks = chunks.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let mut request = Vec::new();
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => return,
                        Ok(read) => {
                            request.extend_from_slice(&buf[..read]);
                            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => return,
                    }
                }

                if stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n",
                    )
                    .await
                    .is_err()
                {
                    return;
                }

                for chunk in chunks {
                    let prefix = format!("{:x}\r\n", chunk.len());
                    if stream.write_all(prefix.as_bytes()).await.is_err() {
                        return;
                    }
                    if stream.write_all(chunk).await.is_err() {
                        return;
                    }
                    if stream.write_all(b"\r\n").await.is_err() {
                        return;
                    }
                }

                let _ = stream.write_all(b"0\r\n\r\n").await;
                let _ = stream.shutdown().await;
            });
        }
    });

    BackendFixture {
        addr,
        stop,
        accept_task,
    }
}

pub(crate) async fn start_h1_delayed_chunked_backend(
    chunks: Vec<(Vec<u8>, Duration)>,
) -> BackendFixture {
    let listener = bind_tcp_listener();
    let addr = listener
        .local_addr()
        .expect("h1 delayed chunked local addr");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);

    let accept_task = tokio::spawn(async move {
        while !stop_flag.load(Ordering::Relaxed) {
            let (mut stream, _) = match listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            let chunks = chunks.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let mut request = Vec::new();
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => return,
                        Ok(read) => {
                            request.extend_from_slice(&buf[..read]);
                            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => return,
                    }
                }

                if stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n",
                    )
                    .await
                    .is_err()
                {
                    return;
                }

                for (chunk, delay) in chunks {
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    let prefix = format!("{:x}\r\n", chunk.len());
                    if stream.write_all(prefix.as_bytes()).await.is_err() {
                        return;
                    }
                    if stream.write_all(&chunk).await.is_err() {
                        return;
                    }
                    if stream.write_all(b"\r\n").await.is_err() {
                        return;
                    }
                }

                let _ = stream.write_all(b"0\r\n\r\n").await;
                let _ = stream.shutdown().await;
            });
        }
    });

    BackendFixture {
        addr,
        stop,
        accept_task,
    }
}

pub(crate) fn reserve_unused_udp_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("reserve udp port");
    let port = socket.local_addr().expect("udp local addr").port();
    drop(socket);
    port
}

pub(crate) fn reserve_unused_listener_port() -> u16 {
    for _ in 0..32 {
        let tcp = StdTcpListener::bind("127.0.0.1:0").expect("reserve listener tcp port");
        let port = tcp.local_addr().expect("tcp local addr").port();
        if let Ok(udp) = UdpSocket::bind(("127.0.0.1", port)) {
            drop(udp);
            drop(tcp);
            return port;
        }
        drop(tcp);
    }

    reserve_unused_udp_port()
}

pub(crate) fn bind_tcp_listener() -> TcpListener {
    bind_tcp_listener_at(SocketAddr::from(([127, 0, 0, 1], 0))).expect("bind test backend listener")
}

pub(crate) fn bind_tcp_listener_at(bind_addr: SocketAddr) -> Result<TcpListener, String> {
    let listener = StdTcpListener::bind(bind_addr)
        .map_err(|err| format!("bind test backend listener {bind_addr}: {err}"))?;
    listener
        .set_nonblocking(true)
        .expect("set test backend listener nonblocking");
    TcpListener::from_std(listener)
        .map_err(|err| format!("register test backend listener {bind_addr}: {err}"))
}

pub(crate) fn quic_read_timeout(conn: &quiche::Connection) -> Duration {
    conn.timeout()
        .filter(|timeout| !timeout.is_zero())
        .unwrap_or(Duration::from_millis(UDP_READ_TIMEOUT_MS))
}

fn run_h3_request(addr: SocketAddr, request: H3RequestSpec<'_>) -> Result<H3Response, String> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|err| err.to_string())?;
    let local_addr = socket.local_addr().map_err(|err| err.to_string())?;

    let mut config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|err| format!("config: {err:?}"))?;
    config.verify_peer(false);
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|err| format!("alpn: {err:?}"))?;
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
        .map_err(|err| format!("connect: {err:?}"))?;
    let h3_config = quiche::h3::Config::new().map_err(|err| format!("h3: {err:?}"))?;
    let mut h3: Option<quiche::h3::Connection> = None;

    let mut out = [0u8; MAX_UDP_PAYLOAD_BYTES];
    let mut buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];
    let mut status = 0;
    let mut headers = Vec::new();
    let mut trailers = Vec::new();
    let mut body = Vec::new();
    let mut received_response_headers = false;
    let mut request_sent = false;
    let start = Instant::now();

    let (write, send_info) = conn
        .send(&mut out)
        .map_err(|err| format!("send: {err:?}"))?;
    socket
        .send_to(&out[..write], send_info.to)
        .map_err(|err| format!("send_to: {err:?}"))?;

    loop {
        loop {
            match conn.send(&mut out) {
                Ok((write, send_info)) => {
                    let _ = socket.send_to(&out[..write], send_info.to);
                }
                Err(quiche::Error::Done) => break,
                Err(err) => return Err(format!("send loop: {err:?}")),
            }
        }

        socket
            .set_read_timeout(Some(quic_read_timeout(&conn)))
            .map_err(|err| format!("timeout: {err:?}"))?;

        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                conn.recv(
                    &mut buf[..len],
                    quiche::RecvInfo {
                        from,
                        to: local_addr,
                    },
                )
                .map_err(|err| format!("recv: {err:?}"))?;
            }
            Err(ref err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                conn.on_timeout();
            }
            Err(err) => return Err(format!("recv: {err:?}")),
        }

        if conn.is_established() && h3.is_none() {
            h3 = Some(
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .map_err(|err| format!("h3 conn: {err:?}"))?,
            );
        }

        if let Some(h3_conn) = h3.as_mut() {
            if conn.is_established() && !request_sent {
                let mut request_headers = vec![quiche::h3::Header::new(
                    b":method",
                    request.method.as_bytes(),
                )];
                if !request.method.eq_ignore_ascii_case("CONNECT") {
                    request_headers.push(quiche::h3::Header::new(b":scheme", b"https"));
                }
                request_headers.push(quiche::h3::Header::new(
                    b":authority",
                    request.authority.as_bytes(),
                ));
                if !request.method.eq_ignore_ascii_case("CONNECT") {
                    request_headers
                        .push(quiche::h3::Header::new(b":path", request.path.as_bytes()));
                }
                request_headers.push(quiche::h3::Header::new(
                    b"user-agent",
                    request.user_agent.as_bytes(),
                ));
                request_headers.extend(request.headers.iter().map(|(name, value)| {
                    quiche::h3::Header::new(name.as_bytes(), value.as_bytes())
                }));
                if let Some(body) = request.body {
                    request_headers.push(quiche::h3::Header::new(
                        b"content-length",
                        body.len().to_string().as_bytes(),
                    ));
                }
                let stream_id = h3_conn
                    .send_request(&mut conn, &request_headers, request.body.is_none())
                    .map_err(|err| format!("send_request: {err:?}"))?;
                if let Some(body) = request.body {
                    h3_conn
                        .send_body(&mut conn, stream_id, body, true)
                        .map_err(|err| format!("send_body: {err:?}"))?;
                }
                request_sent = true;
            }

            loop {
                match h3_conn.poll(&mut conn) {
                    Ok((_stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        let target = if received_response_headers {
                            &mut trailers
                        } else {
                            received_response_headers = true;
                            &mut headers
                        };
                        for header in &list {
                            let name = String::from_utf8_lossy(header.name()).to_string();
                            let value = String::from_utf8_lossy(header.value()).to_string();
                            if name == ":status" {
                                status = value.parse::<u16>().unwrap_or_default();
                            }
                            target.push((name, value));
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Data)) => loop {
                        match h3_conn.recv_body(&mut conn, stream_id, &mut buf) {
                            Ok(read) => body.extend_from_slice(&buf[..read]),
                            Err(quiche::h3::Error::Done) => break,
                            Err(err) => return Err(format!("recv_body: {err:?}")),
                        }
                    },
                    Ok((_stream_id, quiche::h3::Event::Finished)) => {
                        return Ok(H3Response {
                            status,
                            headers,
                            trailers,
                            body,
                        });
                    }
                    Ok((_stream_id, quiche::h3::Event::Reset(_))) => {
                        return Err("stream reset".to_string());
                    }
                    Ok((_stream_id, quiche::h3::Event::PriorityUpdate)) => {}
                    Ok((_stream_id, quiche::h3::Event::GoAway)) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(err) => return Err(format!("poll: {err:?}")),
                }
            }
        }

        if start.elapsed() > Duration::from_secs(REQUEST_TIMEOUT_SECS) {
            return Err(format!(
                "timeout waiting for response (status={status}, body_len={})",
                body.len()
            ));
        }
    }
}

pub(crate) fn read_test_chain(cert_path: &str) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_file_iter(cert_path)
        .expect("open cert file")
        .collect::<Result<Vec<_>, _>>()
        .expect("parse certs")
}

pub(crate) fn read_test_key(key_path: &str) -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_file(key_path).expect("parse private key")
}

struct ChunkSequenceBody {
    chunks: std::vec::IntoIter<Bytes>,
    trailers: Option<http::HeaderMap>,
}

impl ChunkSequenceBody {
    fn new(chunks: Vec<Bytes>, trailers: Option<http::HeaderMap>) -> Self {
        Self {
            chunks: chunks.into_iter(),
            trailers,
        }
    }
}

impl Body for ChunkSequenceBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(chunk) = self.chunks.next() {
            return std::task::Poll::Ready(Some(Ok(Frame::data(chunk))));
        }
        std::task::Poll::Ready(
            self.trailers
                .take()
                .map(|trailers| Ok(Frame::trailers(trailers))),
        )
    }
}
