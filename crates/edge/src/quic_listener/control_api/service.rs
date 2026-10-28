use std::sync::atomic::AtomicUsize;

use http_body_util::Full;

use super::{
    context::{ConnectionSlotGuard, ControlApiListenerBinding},
    security::ControlApiSecurityPolicy,
    state::ControlApiState,
    *,
};
use crate::quic_listener::runtime_state::ControlPlaneStartup;

struct ControlApiTlsState {
    primary_listener_label: String,
    listener_tls_generation: u64,
    security: Arc<ControlApiSecurityPolicy>,
    server_config: Arc<RustlsServerConfig>,
}

enum ControlApiTlsAcceptError {
    Handshake(std::io::Error),
    Timeout,
}

impl QUICListener {
    pub(in crate::quic_listener) fn spawn_control_api_endpoint(
        startup: &ControlPlaneStartup<'_>,
    ) -> Result<(), ProxyError> {
        let state = startup.control_api_service_ctx();
        let startup_state = state.current_service_state();
        if startup.runtime_bundle.is_none() && !startup_state.endpoint.enabled {
            return Ok(());
        }
        let required = startup_state.endpoint.required;
        if startup_state.endpoint.enabled
            && let Err(err) = Self::build_control_api_tls_state(&startup_state)
        {
            if required {
                return Err(err);
            }
            error!("failed to initialize control API TLS config: {}", err);
            return Ok(());
        }

        let handle = match runtime_handle() {
            Some(handle) => handle,
            None => {
                let msg = "control API disabled (no Tokio runtime available)".to_string();
                if required {
                    return Err(ProxyError::Transport(msg));
                }
                error!("{}", msg);
                return Ok(());
            }
        };

        let initial_binding = if startup_state.endpoint.enabled {
            let bind = format!(
                "{}:{}",
                startup_state.endpoint.address, startup_state.endpoint.port
            );
            match Self::bind_tcp_listener(&bind, Some(&handle), "control API endpoint") {
                Ok(listener) => Some(ControlApiListenerBinding {
                    bind,
                    listener,
                    active_connections: Arc::new(AtomicUsize::new(0)),
                }),
                Err(msg) => {
                    if required {
                        return Err(ProxyError::Transport(msg));
                    }
                    error!("{}", msg);
                    None
                }
            }
        } else {
            None
        };

        spawn_supervised_async_task(
            &handle,
            "control-api-endpoint",
            Some(startup_state.metrics()),
            async move {
                let mut listener_binding = initial_binding;
                let mut tls_state = if startup_state.endpoint.enabled {
                    match Self::build_control_api_tls_state(&startup_state) {
                        Ok(state) => Some(state),
                        Err(err) => {
                            error!("failed to initialize control API TLS state: {}", err);
                            None
                        }
                    }
                } else {
                    None
                };

                loop {
                    let runtime_state = state.current_service_state();
                    let endpoint = &runtime_state.endpoint;
                    let desired_bind = format!("{}:{}", endpoint.address, endpoint.port);

                    if !endpoint.enabled {
                        if let Some(binding) = listener_binding.take() {
                            info!(
                                "Control API endpoint disabled via runtime reload on {}",
                                binding.bind
                            );
                        }
                        tls_state = None;
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }

                    let needs_rebind = match listener_binding.as_ref() {
                        Some(binding) => binding.bind != desired_bind,
                        None => true,
                    };
                    if needs_rebind {
                        match Self::bind_tcp_listener(&desired_bind, None, "control API endpoint") {
                            Ok(listener) => {
                                info!("Control API endpoint ready bind=https://{}", desired_bind);
                                info!(
                                    "Control API endpoint paths bind={} health={} ready={} runtime={} reload_certs={}",
                                    desired_bind,
                                    runtime_state.paths.health_path,
                                    runtime_state.paths.ready_path,
                                    runtime_state.paths.runtime_path,
                                    runtime_state.paths.reload_certs_path,
                                );
                                info!(
                                    "Control API endpoint limits bind={} max_connections={} connection_timeout_ms={}",
                                    desired_bind,
                                    endpoint.max_connections.max(1),
                                    endpoint.connection_timeout_ms.max(1)
                                );
                                listener_binding = Some(ControlApiListenerBinding {
                                    bind: desired_bind.clone(),
                                    listener,
                                    active_connections: Arc::new(AtomicUsize::new(0)),
                                });
                            }
                            Err(err) => {
                                error!("{}", err);
                                tokio::time::sleep(Duration::from_millis(200)).await;
                                continue;
                            }
                        }
                    }

                    match Self::refresh_control_api_tls_state(&runtime_state, &mut tls_state) {
                        Ok(()) => {}
                        Err(err) => {
                            error!("failed to refresh control API TLS config: {}", err);
                            tokio::time::sleep(Duration::from_millis(200)).await;
                            continue;
                        }
                    }

                    let Some(binding) = listener_binding.as_mut() else {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    };

                    let accept_result = tokio::select! {
                        accept = binding.listener.accept() => Some(accept),
                        _ = tokio::time::sleep(Duration::from_millis(200)) => None,
                    };
                    let Some(accept_result) = accept_result else {
                        continue;
                    };
                    let (stream, peer) = match accept_result {
                        Ok(v) => v,
                        Err(err) => {
                            error!("Control API endpoint accept failed: {}", err);
                            continue;
                        }
                    };
                    let state = state.clone();
                    let active_connections = Arc::clone(&binding.active_connections);
                    let max_connections = endpoint.max_connections.max(1);
                    let server_config = tls_state
                        .as_ref()
                        .map(|state| Arc::clone(&state.server_config));
                    if !Self::try_claim_control_api_connection_slot(
                        &active_connections,
                        max_connections,
                    ) {
                        runtime_state
                            .metrics()
                            .ingress_observations()
                            .inc_control_api_connection_limit_drop();
                        warn!(
                            "Control API endpoint dropped connection from {} due to max connection limit ({})",
                            peer, max_connections
                        );
                        continue;
                    }

                    tokio::spawn(async move {
                        Self::serve_control_api_connection(
                            state,
                            active_connections,
                            stream,
                            peer,
                            server_config,
                        )
                        .await;
                    });
                }
            },
        );
        Ok(())
    }

    fn try_claim_control_api_connection_slot(
        active_connections: &Arc<AtomicUsize>,
        max_connections: usize,
    ) -> bool {
        loop {
            let current = active_connections.load(Ordering::Relaxed);
            if current >= max_connections {
                return false;
            }
            if active_connections
                .compare_exchange(
                    current,
                    current.saturating_add(1),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return true;
            }
        }
    }

    async fn serve_control_api_connection(
        state: ControlApiState,
        active_connections: Arc<AtomicUsize>,
        stream: tokio::net::TcpStream,
        peer: SocketAddr,
        server_config: Option<Arc<RustlsServerConfig>>,
    ) {
        let _connection_guard = ConnectionSlotGuard::new(active_connections);
        let runtime_state = state.current_service_state();
        let timeout = Duration::from_millis(runtime_state.endpoint.connection_timeout_ms.max(1));
        let Some(server_config) = server_config else {
            error!("Control API endpoint missing live TLS config");
            return;
        };
        let tls_stream = match Self::accept_control_api_tls(stream, server_config, timeout).await {
            Ok(stream) => stream,
            Err(ControlApiTlsAcceptError::Handshake(err)) => {
                let detail = err.to_string();
                let reason = Self::classify_downstream_tls_failure_reason(&detail);
                error!(
                    "Control API endpoint TLS handshake failed from {}: reason={} detail={}",
                    peer, reason, detail
                );
                return;
            }
            Err(ControlApiTlsAcceptError::Timeout) => {
                debug!("Control API endpoint TLS handshake timed out from {}", peer);
                return;
            }
        };
        let request_context = Self::build_control_api_request_context(
            peer,
            tls_stream.get_ref().1.peer_certificates(),
            runtime_state.security.identity_source.as_ref(),
            runtime_state.primary_listener_label.clone(),
        );
        let auth_policy_generation = runtime_state.auth_policy_generation();
        let io = TokioIo::new(tls_stream);
        let service = service_fn(move |mut req: Request<Incoming>| {
            let state = state.clone();
            let auth_policy_generation = auth_policy_generation;
            let request_context =
                Self::augment_control_api_request_context(request_context.clone(), &req);
            async move {
                let current_state = state.current_service_state();
                if !current_state.endpoint.enabled
                    || current_state.auth_policy_generation() != auth_policy_generation
                {
                    return Ok::<_, hyper::Error>(Self::stale_control_api_connection_response());
                }
                req.extensions_mut().insert(request_context);
                Ok::<_, hyper::Error>(Self::handle_control_api_request(req, &state).await)
            }
        });

        let serve = http1::Builder::new().serve_connection(io, service);
        match tokio::time::timeout(timeout, serve).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                error!("Control API endpoint connection failed: {}", err);
            }
            Err(_) => {
                debug!("Control API endpoint connection timed out");
            }
        }
    }

    /// Run synchronous, potentially filesystem-touching runtime-reload work
    /// (config reads, TLS/CA material loading) on Tokio's blocking-thread
    /// pool instead of the control API's own async worker.
    ///
    /// `read_file_with_limit` no longer blocks indefinitely on a FIFO
    /// (SEC-08), but arbitrary caller-supplied paths can still be slow to
    /// read (large files, loaded disks, network filesystems); running that
    /// work here keeps one slow request from starving the shared
    /// control-plane async workers.
    ///
    /// Returns `None` if the blocking task panicked; callers should treat
    /// that as an internal error rather than propagating the panic into the
    /// request-handling task.
    pub(super) async fn run_control_api_blocking<F, T>(work: F) -> Option<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        match tokio::task::spawn_blocking(work).await {
            Ok(value) => Some(value),
            Err(err) => {
                error!("control API blocking task panicked: {}", err);
                None
            }
        }
    }

    pub(super) fn control_api_internal_error_response() -> Response<Full<Bytes>> {
        Self::json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "error": "internal_error" }),
        )
    }

    pub(super) fn stale_control_api_connection_response() -> Response<Full<Bytes>> {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("connection", "close")
            .body(Full::new(Bytes::from_static(
                b"control API authentication policy changed\n",
            )))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"unauthorized\n"))))
    }

    async fn accept_control_api_tls(
        stream: tokio::net::TcpStream,
        server_config: Arc<RustlsServerConfig>,
        timeout: Duration,
    ) -> Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, ControlApiTlsAcceptError>
    {
        let accept = TlsAcceptor::from(server_config).accept(stream);
        match tokio::time::timeout(timeout, accept).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(err)) => Err(ControlApiTlsAcceptError::Handshake(err)),
            Err(_) => Err(ControlApiTlsAcceptError::Timeout),
        }
    }

    fn build_control_api_tls_state(
        runtime_state: &super::context::ControlApiServiceState,
    ) -> Result<ControlApiTlsState, ProxyError> {
        let listener_config = runtime_state
            .runtime
            .runtime_config()
            .primary_listener_runtime_config()
            .ok_or_else(|| {
                ProxyError::Transport("no effective listeners configured".to_string())
            })?;
        let primary_listener_label =
            runtime_state
                .primary_listener_label
                .clone()
                .ok_or_else(|| {
                    ProxyError::Transport(
                    "control API endpoint missing live primary listener label for TLS selection"
                        .to_string(),
                )
                })?;
        let listener_tls_generation = runtime_state
            .listener_tls_store()
            .generation(&primary_listener_label)
            .unwrap_or(0);
        let security = Arc::clone(&runtime_state.security);
        let server_config =
            Self::build_control_api_server_tls_config(&listener_config, &security.client_auth)?;

        Ok(ControlApiTlsState {
            primary_listener_label,
            listener_tls_generation,
            security,
            server_config,
        })
    }

    fn refresh_control_api_tls_state(
        runtime_state: &super::context::ControlApiServiceState,
        tls_state: &mut Option<ControlApiTlsState>,
    ) -> Result<(), ProxyError> {
        let Some(primary_listener_label) = runtime_state.primary_listener_label.as_ref() else {
            return Err(ProxyError::Transport(
                "control API endpoint missing live primary listener label for TLS selection"
                    .to_string(),
            ));
        };
        let listener_tls_generation = runtime_state
            .listener_tls_store()
            .generation(primary_listener_label)
            .unwrap_or(0);
        let needs_refresh = tls_state.as_ref().is_none_or(|state| {
            state.primary_listener_label != *primary_listener_label
                || state.listener_tls_generation != listener_tls_generation
                || state.security.as_ref() != runtime_state.security.as_ref()
        });
        if needs_refresh {
            *tls_state = Some(Self::build_control_api_tls_state(runtime_state)?);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rcgen::{Certificate, CertificateParams};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    use super::*;

    #[tokio::test]
    async fn stalled_control_api_tls_handshake_times_out() {
        let certificate =
            Certificate::from_params(CertificateParams::new(vec!["localhost".to_string()]))
                .expect("test certificate");
        let cert_der = CertificateDer::from(certificate.serialize_der().expect("certificate DER"));
        let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
            certificate.serialize_private_key_der(),
        ));
        let server_config = Arc::new(
            RustlsServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .expect("server TLS config"),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener");
        let peer = listener.local_addr().expect("listener address");
        let client = tokio::net::TcpStream::connect(peer);
        let accept = listener.accept();
        let (client_result, server_result) = tokio::join!(client, accept);
        let _client = client_result.expect("client connection");
        let (server, _) = server_result.expect("server connection");

        let result =
            QUICListener::accept_control_api_tls(server, server_config, Duration::from_millis(10))
                .await;

        assert!(matches!(result, Err(ControlApiTlsAcceptError::Timeout)));
    }
}
