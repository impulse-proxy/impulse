#![allow(dead_code)]

use std::{
    collections::HashMap,
    convert::Infallible,
    future::Future,
    net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::{Request, Response, body::Incoming, client::conn::http1};
use hyper_util::rt::TokioIo;
use impulse_config::{
    config::{Config, ControlApi, MetricsEndpoint, Observability, SecretRef, Upstream},
    runtime::RuntimeConfig,
    validator::validate,
};
use impulse_edge::{
    MAX_DATAGRAM_SIZE_BYTES, MAX_UDP_PAYLOAD_BYTES, QUIC_IDLE_TIMEOUT_MS, QUIC_INITIAL_MAX_DATA,
    QUIC_INITIAL_MAX_STREAMS_BIDI, QUIC_INITIAL_MAX_STREAMS_UNI, QUIC_INITIAL_STREAM_DATA,
    runtime::{
        bundle::RuntimeBundleHandle,
        listener::QUICListener as RuntimeListener,
        policy::{LifecycleTransitionResult, RuntimeLifecyclePhase},
    },
};
use rustls_pki_types::{CertificateDer, pem::PemObject};
use serde_json::Value as JsonValue;
use tempfile::{TempDir, tempdir};
use tokio::net::TcpStream;
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, RootCertStore, pki_types::ServerName},
};

use super::{
    base_quic_test_config,
    request_path::{
        BackendFixture, H3RequestSpec, H3Response, ListenerTaskGuard, TestTlsMaterial,
        run_request_to, start_h1_backend, start_h1_backend_on, start_h2_backend_with_client_auth,
    },
    static_full_response,
};

pub(crate) struct RuntimeSwapHarness {
    backends: Vec<BackendFixture>,
    listener_task: Option<ListenerTaskGuard>,
    rt: tokio::runtime::Runtime,
    tls: TestTlsMaterial,
    control_api_initial_cert_pem: String,
    config_dir: TempDir,
    config_path: PathBuf,
    listen_port: u16,
    metrics_port: u16,
    metrics_port_reservation: Option<StdTcpListener>,
    control_api_port: u16,
    control_api_port_reservation: Option<StdTcpListener>,
    current_config: Option<Config>,
    runtime_bundle: Option<Arc<RuntimeBundleHandle>>,
    listen_addr: Option<SocketAddr>,
}

// `ControlApi::auth_token` is `#[serde(skip_serializing)]` so it never survives a
// write-to-disk/reload round trip (the redaction rule that protects live snapshots
// from leaking secrets also strips it from any re-serialized config file). The
// harness reloads by writing `current_config` back out as YAML, so it must carry
// the control-API token via a file-backed `auth_token_ref` instead of the plain
// `auth_token` field to survive that round trip.
const CONTROL_API_TOKEN: &str = "runtime-swap-token";

impl RuntimeSwapHarness {
    pub(crate) fn new() -> Self {
        let config_dir = tempdir().expect("runtime swap tempdir");
        let tls = TestTlsMaterial::localhost();
        let control_api_initial_cert_pem =
            std::fs::read_to_string(&tls.cert_path).expect("read initial control api cert");
        std::fs::write(
            config_dir.path().join("control-api-token"),
            CONTROL_API_TOKEN,
        )
        .expect("write control api token file");
        let metrics_port_reservation = reserve_tcp_port();
        let metrics_port = metrics_port_reservation
            .local_addr()
            .expect("metrics reservation local addr")
            .port();
        let control_api_port_reservation = reserve_tcp_port();
        let control_api_port = control_api_port_reservation
            .local_addr()
            .expect("control API reservation local addr")
            .port();
        Self {
            backends: Vec::new(),
            listener_task: None,
            rt: tokio::runtime::Runtime::new().expect("runtime"),
            tls,
            control_api_initial_cert_pem,
            config_path: config_dir.path().join("impulse-runtime-swap.yaml"),
            config_dir,
            listen_port: reserve_udp_port(),
            metrics_port,
            metrics_port_reservation: Some(metrics_port_reservation),
            control_api_port,
            control_api_port_reservation: Some(control_api_port_reservation),
            current_config: None,
            runtime_bundle: None,
            listen_addr: None,
        }
    }

    pub(crate) fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub(crate) fn make_config(&self, upstreams: HashMap<String, Upstream>) -> Config {
        let mut config = base_quic_test_config(
            self.listen_port,
            &self.tls.cert_path,
            &self.tls.key_path,
            upstreams,
        );
        config.observability = Observability {
            metrics: MetricsEndpoint {
                enabled: true,
                required: true,
                address: "127.0.0.1".to_string(),
                allow_non_loopback: false,
                port: self.metrics_port,
                path: "/metrics".to_string(),
                max_connections: 32,
                connection_timeout_ms: 5_000,
            },
            control_api: ControlApi {
                enabled: true,
                required: true,
                address: "127.0.0.1".to_string(),
                port: self.control_api_port,
                health_path: "/health".to_string(),
                ready_path: "/ready".to_string(),
                runtime_path: "/runtime".to_string(),
                restart_path: "/restart".to_string(),
                reload_path: "/reload".to_string(),
                reload_certs_path: "/reload-certs".to_string(),
                auth_token_ref: Some(SecretRef {
                    reference: format!(
                        "file://{}",
                        self.config_dir.path().join("control-api-token").display()
                    ),
                }),
                max_connections: 32,
                connection_timeout_ms: 5_000,
                ..ControlApi::default()
            },
            ..Observability::default()
        };
        config
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

    pub(crate) fn try_start_h1_backend_at<F, Fut>(
        &mut self,
        bind_addr: SocketAddr,
        handler: F,
    ) -> Result<SocketAddr, String>
    where
        F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send + 'static,
    {
        let fixture = self.rt.block_on(start_h1_backend_on(bind_addr, handler))?;
        let addr = fixture.addr;
        self.backends.push(fixture);
        Ok(addr)
    }

    pub(crate) fn start_h1_static_backend(&mut self, body: &'static [u8]) -> SocketAddr {
        self.start_h1_backend(
            move |_req| async move { Ok::<_, Infallible>(static_full_response(body)) },
        )
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

    pub(crate) fn start_listener(&mut self, config: Config) -> Result<SocketAddr, String> {
        validate(&config).map_err(|err| format!("config validation failed: {err}"))?;
        self.write_config_file(&config)?;

        let runtime_config =
            RuntimeConfig::from_config(&config).map_err(|err| format!("runtime config: {err}"))?;
        let runtime_bundle = RuntimeListener::build_runtime_bundle(
            self.config_path.to_string_lossy().to_string(),
            config.log.clone(),
            &runtime_config,
        )
        .map_err(|err| format!("runtime bundle: {err}"))?;
        let runtime_bundle_handle = Arc::new(RuntimeBundleHandle::new(runtime_bundle.clone()));
        let listener_config = runtime_bundle
            .runtime_config
            .primary_listener_runtime_config()
            .ok_or_else(|| "missing primary listener runtime config".to_string())?;
        let socket = RuntimeListener::bind_socket(&listener_config, false)
            .map_err(|err| format!("bind socket: {err}"))?;

        // Keep both TCP ports exclusively reserved while certificates, config,
        // and the runtime bundle are prepared. Release them together only when
        // the production listeners are ready to bind, closing the large
        // bind-to-port-0/drop/rebind race in this integration harness and
        // preventing both endpoints from receiving the same ephemeral port.
        drop(self.metrics_port_reservation.take());
        drop(self.control_api_port_reservation.take());

        {
            let _enter = self.rt.enter();
            RuntimeListener::spawn_control_plane_tasks_with_runtime_bundle(
                &runtime_bundle.runtime_config,
                runtime_bundle.shared_state.as_ref(),
                Arc::clone(&runtime_bundle_handle),
                1,
            )
            .map_err(|err| format!("control plane tasks: {err}"))?;
        }

        let listener = RuntimeListener::new_with_socket_and_shared_state(
            listener_config,
            socket,
            Arc::clone(&runtime_bundle.shared_state),
        )
        .map_err(|err| format!("listener: {err}"))?
        .with_runtime_bundle(Arc::clone(&runtime_bundle_handle));

        let listen_addr = listener
            .socket
            .local_addr()
            .map_err(|err| format!("listen addr: {err}"))?;

        self.listener_task = Some(ListenerTaskGuard::spawn(&self.rt, listener));
        self.listen_addr = Some(listen_addr);
        self.current_config = Some(config);
        self.runtime_bundle = Some(runtime_bundle_handle);
        Ok(listen_addr)
    }

    pub(crate) fn rewrite_config<F>(&mut self, edit: F) -> Result<(), String>
    where
        F: FnOnce(&mut Config),
    {
        let mut config = self
            .current_config
            .clone()
            .ok_or_else(|| "listener not started".to_string())?;
        edit(&mut config);
        validate(&config).map_err(|err| format!("config validation failed: {err}"))?;
        self.write_config_file(&config)?;
        self.current_config = Some(config);
        Ok(())
    }

    pub(crate) fn runtime_snapshot(&self) -> Result<JsonValue, String> {
        let path = self
            .current_config
            .as_ref()
            .ok_or_else(|| "listener not started".to_string())?
            .observability
            .control_api
            .runtime_path
            .clone();
        let token = self.control_api_token()?;
        self.rt.block_on(self.poll_control_api_json(
            Method::GET,
            path,
            token,
            StatusCode::OK,
            Duration::from_secs(5),
        ))
    }

    pub(crate) fn runtime_history(&self) -> Result<JsonValue, String> {
        let base = self
            .current_config
            .as_ref()
            .ok_or_else(|| "listener not started".to_string())?
            .observability
            .control_api
            .runtime_path
            .clone();
        let path = format!("{}/history", base.trim_end_matches('/'));
        let token = self.control_api_token()?;
        self.rt.block_on(self.poll_control_api_json(
            Method::GET,
            path,
            token,
            StatusCode::OK,
            Duration::from_secs(5),
        ))
    }

    pub(crate) fn runtime_history_generation(&self, generation: u64) -> Result<JsonValue, String> {
        let base = self
            .current_config
            .as_ref()
            .ok_or_else(|| "listener not started".to_string())?
            .observability
            .control_api
            .runtime_path
            .clone();
        let path = format!("{}/history/{generation}", base.trim_end_matches('/'));
        let token = self.control_api_token()?;
        self.rt.block_on(self.poll_control_api_json(
            Method::GET,
            path,
            token,
            StatusCode::OK,
            Duration::from_secs(5),
        ))
    }

    pub(crate) fn ready_snapshot_expect(
        &self,
        expected_status: StatusCode,
    ) -> Result<JsonValue, String> {
        let path = self
            .current_config
            .as_ref()
            .ok_or_else(|| "listener not started".to_string())?
            .observability
            .control_api
            .ready_path
            .clone();
        let token = self.control_api_token()?;
        self.rt.block_on(self.poll_control_api_json(
            Method::GET,
            path,
            token,
            expected_status,
            Duration::from_secs(5),
        ))
    }

    pub(crate) fn trigger_runtime_reload(&self) -> Result<JsonValue, String> {
        self.trigger_runtime_reload_expect(StatusCode::ACCEPTED)
    }

    pub(crate) fn trigger_runtime_activate(&self) -> Result<JsonValue, String> {
        self.trigger_runtime_activate_expect(StatusCode::ACCEPTED)
    }

    pub(crate) fn trigger_runtime_activate_expect(
        &self,
        expected_status: StatusCode,
    ) -> Result<JsonValue, String> {
        let base = self
            .current_config
            .as_ref()
            .ok_or_else(|| "listener not started".to_string())?
            .observability
            .control_api
            .runtime_path
            .clone();
        let path = format!("{}/activate", base.trim_end_matches('/'));
        let token = self.control_api_token()?;
        let body = serde_json::json!({ "expected_generation": self.current_generation()? });
        self.rt.block_on(self.poll_control_api_json_with_body(
            Method::POST,
            path,
            token,
            Some(body),
            expected_status,
            Duration::from_secs(5),
        ))
    }

    pub(crate) fn trigger_runtime_rollback(
        &self,
        target_generation: u64,
    ) -> Result<JsonValue, String> {
        let base = self
            .current_config
            .as_ref()
            .ok_or_else(|| "listener not started".to_string())?
            .observability
            .control_api
            .runtime_path
            .clone();
        let path = format!("{}/rollback", base.trim_end_matches('/'));
        let token = self.control_api_token()?;
        let body = serde_json::json!({
            "target_generation": target_generation,
            "expected_active_generation": self.current_generation()?,
        });
        self.rt.block_on(self.poll_control_api_json_with_body(
            Method::POST,
            path,
            token,
            Some(body),
            StatusCode::ACCEPTED,
            Duration::from_secs(5),
        ))
    }

    pub(crate) fn trigger_runtime_reload_expect(
        &self,
        expected_status: StatusCode,
    ) -> Result<JsonValue, String> {
        let path = self
            .current_config
            .as_ref()
            .ok_or_else(|| "listener not started".to_string())?
            .observability
            .control_api
            .reload_path
            .clone();
        let token = self.control_api_token()?;
        let expected_generation = self.current_generation()?;
        let body = serde_json::json!({ "expected_generation": expected_generation });
        self.rt.block_on(self.poll_control_api_json_with_body(
            Method::POST,
            path,
            token,
            Some(body),
            expected_status,
            Duration::from_secs(5),
        ))
    }

    pub(crate) fn trigger_runtime_reload_certs(&self) -> Result<JsonValue, String> {
        self.trigger_runtime_reload_certs_expect(StatusCode::ACCEPTED)
    }

    pub(crate) fn trigger_runtime_reload_certs_expect(
        &self,
        expected_status: StatusCode,
    ) -> Result<JsonValue, String> {
        let path = self
            .current_config
            .as_ref()
            .ok_or_else(|| "listener not started".to_string())?
            .observability
            .control_api
            .reload_certs_path
            .clone();
        let token = self.control_api_token()?;
        self.rt.block_on(self.poll_control_api_json(
            Method::POST,
            path,
            token,
            expected_status,
            Duration::from_secs(5),
        ))
    }

    pub(crate) fn metrics_text(&self) -> Result<String, String> {
        let path = self
            .current_config
            .as_ref()
            .ok_or_else(|| "listener not started".to_string())?
            .observability
            .metrics
            .path
            .clone();
        self.metrics_text_at(&path)
    }

    pub(crate) fn metrics_text_at(&self, path: &str) -> Result<String, String> {
        self.rt.block_on(self.poll_metrics_text(
            path.to_string(),
            StatusCode::OK,
            Duration::from_secs(5),
        ))
    }

    pub(crate) fn metrics_status_at(&self, path: &str) -> Result<StatusCode, String> {
        self.rt
            .block_on(self.poll_metrics_status(path.to_string(), Duration::from_secs(5)))
    }

    pub(crate) fn run_request(&self, request: H3RequestSpec<'_>) -> Result<H3Response, String> {
        let listen_addr = self
            .listen_addr
            .ok_or_else(|| "listener not started".to_string())?;
        run_request_to(listen_addr, request)
    }

    pub(crate) fn listen_addr(&self) -> Result<SocketAddr, String> {
        self.listen_addr
            .ok_or_else(|| "listener not started".to_string())
    }

    pub(crate) fn listener_tls_paths(&self) -> (&str, &str) {
        (&self.tls.cert_path, &self.tls.key_path)
    }

    pub(crate) fn current_generation(&self) -> Result<u64, String> {
        Ok(self
            .runtime_bundle
            .as_ref()
            .ok_or_else(|| "runtime bundle unavailable".to_string())?
            .current_generation())
    }

    pub(crate) fn runtime_bundle_handle(&self) -> Result<Arc<RuntimeBundleHandle>, String> {
        self.runtime_bundle
            .as_ref()
            .cloned()
            .ok_or_else(|| "runtime bundle unavailable".to_string())
    }

    pub(crate) fn lifecycle_phase(&self) -> Result<RuntimeLifecyclePhase, String> {
        Ok(self
            .runtime_bundle
            .as_ref()
            .ok_or_else(|| "runtime bundle unavailable".to_string())?
            .lifecycle()
            .phase())
    }

    pub(crate) fn begin_lifecycle_drain(&self) -> Result<LifecycleTransitionResult, String> {
        Ok(self
            .runtime_bundle
            .as_ref()
            .ok_or_else(|| "runtime bundle unavailable".to_string())?
            .lifecycle()
            .begin_drain())
    }

    pub(crate) fn request_watchdog_restart(&self, reason: &str) -> Result<bool, String> {
        Ok(self
            .runtime_bundle
            .as_ref()
            .ok_or_else(|| "runtime bundle unavailable".to_string())?
            .current_view()
            .shared_services()
            .watchdog
            .request_restart(reason))
    }

    pub(crate) fn fresh_quic_connection_establishes_within(
        &self,
        timeout: Duration,
    ) -> Result<bool, String> {
        let listen_addr = self.listen_addr()?;
        quic_connection_establishes_within(listen_addr, timeout)
    }

    fn control_api_token(&self) -> Result<String, String> {
        if self.current_config.is_none() {
            return Err("missing control api auth token".to_string());
        }
        Ok(CONTROL_API_TOKEN.to_string())
    }

    fn write_config_file(&self, config: &Config) -> Result<(), String> {
        let rendered =
            serde_yaml::to_string(config).map_err(|err| format!("serialize config: {err}"))?;
        std::fs::write(&self.config_path, rendered)
            .map_err(|err| format!("write config file '{}': {err}", self.config_path.display()))
    }

    async fn poll_metrics_text(
        &self,
        path: String,
        expected_status: StatusCode,
        timeout: Duration,
    ) -> Result<String, String> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.metrics_port));
        let deadline = Instant::now() + timeout;
        let mut last_error = String::new();

        while Instant::now() < deadline {
            match metrics_request_once(addr, &path).await {
                Ok((status, body)) if status == expected_status && !body.is_empty() => {
                    return Ok(body);
                }
                Ok((status, body)) => {
                    last_error = format!("unexpected metrics response {status} body={body:?}");
                }
                Err(err) => {
                    last_error = err;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        Err(format!(
            "metrics endpoint not reachable within {:?} ({})",
            timeout, last_error
        ))
    }

    async fn poll_metrics_status(
        &self,
        path: String,
        timeout: Duration,
    ) -> Result<StatusCode, String> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.metrics_port));
        let deadline = Instant::now() + timeout;
        let mut last_error = String::new();

        while Instant::now() < deadline {
            match metrics_request_once(addr, &path).await {
                Ok((status, _body)) => return Ok(status),
                Err(err) => last_error = err,
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        Err(format!(
            "metrics endpoint status not reachable within {:?} ({})",
            timeout, last_error
        ))
    }

    async fn poll_control_api_json(
        &self,
        method: Method,
        path: String,
        token: String,
        expected_status: StatusCode,
        timeout: Duration,
    ) -> Result<JsonValue, String> {
        self.poll_control_api_json_with_body(method, path, token, None, expected_status, timeout)
            .await
    }

    async fn poll_control_api_json_with_body(
        &self,
        method: Method,
        path: String,
        token: String,
        body: Option<JsonValue>,
        expected_status: StatusCode,
        timeout: Duration,
    ) -> Result<JsonValue, String> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.control_api_port));
        let deadline = Instant::now() + timeout;
        let mut last_error = String::new();

        while Instant::now() < deadline {
            match control_api_request_once(
                addr,
                &self.tls.cert_path,
                &self.control_api_initial_cert_pem,
                method.clone(),
                &path,
                &token,
                body.as_ref(),
            )
            .await
            {
                Ok((status, body)) if status == expected_status => return Ok(body),
                Ok((status, body)) => {
                    last_error = format!("unexpected control api response {status} body={body}");
                }
                Err(err) => {
                    last_error = err;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        Err(format!(
            "control api '{}' not reachable within {:?} ({})",
            path, timeout, last_error
        ))
    }
}

fn reserve_tcp_port() -> StdTcpListener {
    StdTcpListener::bind(("127.0.0.1", 0)).expect("reserve tcp port")
}

fn reserve_udp_port() -> u16 {
    StdUdpSocket::bind(("127.0.0.1", 0))
        .expect("reserve udp port")
        .local_addr()
        .expect("udp local addr")
        .port()
}

fn add_pem_certs_to_root_store(roots: &mut RootCertStore, pem: &str) -> Result<(), String> {
    let certs = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("parse certs: {err}"))?;
    for cert in certs {
        roots
            .add(cert)
            .map_err(|err| format!("add root cert: {err}"))?;
    }

    Ok(())
}

fn read_test_root_store(cert_path: &str, initial_cert_pem: &str) -> Result<RootCertStore, String> {
    let mut roots = RootCertStore::empty();
    add_pem_certs_to_root_store(&mut roots, initial_cert_pem)?;
    let current_pem =
        std::fs::read_to_string(cert_path).map_err(|err| format!("open cert file: {err}"))?;
    if current_pem != initial_cert_pem {
        add_pem_certs_to_root_store(&mut roots, &current_pem)?;
    }
    Ok(roots)
}

async fn metrics_request_once(
    addr: SocketAddr,
    path: &str,
) -> Result<(StatusCode, String), String> {
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|err| format!("metrics connect: {err}"))?;
    let (mut sender, conn) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|err| format!("metrics handshake: {err}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let request = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header("host", "127.0.0.1")
        .body(Empty::<Bytes>::new())
        .map_err(|err| format!("metrics request build: {err}"))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|err| format!("metrics request: {err}"))?;
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|err| format!("metrics read body: {err}"))?
        .to_bytes();
    let body = String::from_utf8(body.to_vec()).map_err(|err| format!("metrics utf8: {err}"))?;
    Ok((status, body))
}

async fn control_api_request_once(
    addr: SocketAddr,
    cert_path: &str,
    initial_cert_pem: &str,
    method: Method,
    path: &str,
    token: &str,
    body: Option<&JsonValue>,
) -> Result<(StatusCode, JsonValue), String> {
    let roots = read_test_root_store(cert_path, initial_cert_pem)?;
    let tls_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = ServerName::try_from("localhost")
        .map_err(|err| format!("server name: {err}"))?
        .to_owned();

    let stream = TcpStream::connect(addr)
        .await
        .map_err(|err| format!("control api connect: {err}"))?;
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|err| format!("control api tls connect: {err}"))?;
    let (mut sender, conn) = http1::handshake(TokioIo::new(tls_stream))
        .await
        .map_err(|err| format!("control api handshake: {err}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let body_bytes = match body {
        Some(value) => {
            serde_json::to_vec(value).map_err(|err| format!("control api body encode: {err}"))?
        }
        None => Vec::new(),
    };
    let mut request_builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost")
        .header("authorization", format!("Bearer {token}"));
    if body.is_some() {
        request_builder = request_builder.header("content-type", "application/json");
    }
    let request = request_builder
        .body(Full::new(Bytes::from(body_bytes)))
        .map_err(|err| format!("control api request build: {err}"))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|err| format!("control api request: {err}"))?;
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|err| format!("control api read body: {err}"))?
        .to_bytes();
    let json = serde_json::from_slice(&body).map_err(|err| {
        format!(
            "control api json parse: {err}; payload={}",
            String::from_utf8_lossy(&body)
        )
    })?;
    Ok((status, json))
}

fn quic_connection_establishes_within(addr: SocketAddr, timeout: Duration) -> Result<bool, String> {
    let socket = StdUdpSocket::bind("0.0.0.0:0").map_err(|err| format!("udp bind: {err}"))?;
    let local_addr = socket
        .local_addr()
        .map_err(|err| format!("udp local addr: {err}"))?;

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

    let scid_bytes = [7u8; quiche::MAX_CONN_ID_LEN];
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
    let mut conn = quiche::connect(Some("localhost"), &scid, local_addr, addr, &mut config)
        .map_err(|err| format!("connect: {err:?}"))?;

    let mut out = [0u8; MAX_UDP_PAYLOAD_BYTES];
    let mut buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];

    let (written, send_info) = conn
        .send(&mut out)
        .map_err(|err| format!("send: {err:?}"))?;
    socket
        .send_to(&out[..written], send_info.to)
        .map_err(|err| format!("send_to: {err}"))?;

    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        socket
            .set_read_timeout(Some(remaining.min(Duration::from_millis(50))))
            .map_err(|err| format!("read timeout: {err}"))?;

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
            Err(ref err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                conn.on_timeout();
            }
            Err(err) => return Err(format!("recv_from: {err}")),
        }

        loop {
            match conn.send(&mut out) {
                Ok((written, send_info)) => {
                    let _ = socket.send_to(&out[..written], send_info.to);
                }
                Err(quiche::Error::Done) => break,
                Err(err) => return Err(format!("send loop: {err:?}")),
            }
        }

        if conn.is_established() {
            return Ok(true);
        }
    }

    Ok(false)
}
