use super::*;

#[derive(Clone)]
struct EdgeMetricsSource {
    metrics: Arc<Metrics>,
}

impl MetricsSource for EdgeMetricsSource {
    fn render_prometheus(&self) -> String {
        self.metrics.render_prometheus()
    }
}

pub(super) struct MetricsEndpointBinding {
    bind: String,
    listener: tokio::net::TcpListener,
    active_connections: Arc<AtomicUsize>,
}

pub(in crate::quic_listener) struct MetricsEndpointService;

impl MetricsEndpointService {
    pub(in crate::quic_listener) fn spawn_metrics_endpoint(
        startup: &ControlPlaneStartup<'_>,
    ) -> Result<(), ProxyError> {
        let service_ctx = startup.metrics_service_ctx();
        let task_registry = startup.runtime_view().process_tasks();
        let startup_state = service_ctx.current_state();
        if startup.runtime_bundle.is_none() && !startup_state.endpoint.enabled {
            return Ok(());
        }
        let required = startup_state.endpoint.required;
        if startup_state.endpoint.enabled
            && startup_state.endpoint.allow_non_loopback
            && let Err(err) = service_ctx.current_tls_config()
        {
            if required {
                return Err(err);
            }
            error!("failed to initialize metrics endpoint TLS config: {}", err);
            return Ok(());
        }

        let handle = match runtime_handle() {
            Some(handle) => handle,
            None => {
                let msg = "metrics endpoint disabled (no Tokio runtime available)".to_string();
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
            match Http3Service::bind_tcp_listener(&bind, Some(&handle), "metrics endpoint") {
                Ok(listener) => Some(MetricsEndpointBinding {
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

        task_registry.spawn_supervised(
            &handle,
            "metrics-endpoint",
            Some(Arc::clone(&startup_state.metrics)),
            async move {
                let mut listener_binding = initial_binding;
                let mut tls_state = None;

                loop {
                    let runtime_state = service_ctx.current_state();
                    let endpoint = &runtime_state.endpoint;
                    let desired_bind = format!("{}:{}", endpoint.address, endpoint.port);

                    if !endpoint.enabled {
                        if let Some(binding) = listener_binding.take() {
                            info!(
                                "Metrics endpoint disabled via runtime reload on {}",
                                binding.bind
                            );
                        }
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }

                    let tls_config = match service_ctx.refresh_tls_state(&mut tls_state) {
                        Ok(config) => config,
                        Err(err) => {
                            error!("failed to refresh metrics endpoint TLS config: {}", err);
                            tokio::time::sleep(Duration::from_millis(200)).await;
                            continue;
                        }
                    };

                    let needs_rebind = match listener_binding.as_ref() {
                        Some(binding) => binding.bind != desired_bind,
                        None => true,
                    };
                    if needs_rebind {
                        match Http3Service::bind_tcp_listener(
                            &desired_bind,
                            None,
                            "metrics endpoint",
                        ) {
                            Ok(listener) => {
                                info!(
                                    "Metrics endpoint ready bind=http://{}{}",
                                    desired_bind, endpoint.path,
                                );
                                info!(
                                    "Metrics endpoint limits bind={} max_connections={} connection_timeout_ms={}",
                                    desired_bind,
                                    endpoint.max_connections.max(1),
                                    endpoint.connection_timeout_ms.max(1)
                                );
                                listener_binding = Some(MetricsEndpointBinding {
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
                    let (stream, _peer) = match accept_result {
                        Ok(v) => v,
                        Err(err) => {
                            error!("Metrics endpoint accept failed: {}", err);
                            continue;
                        }
                    };
                    let runtime_state = service_ctx.current_state();
                    let active_connections = Arc::clone(&binding.active_connections);
                    if !try_claim_connection_slot(
                        &active_connections,
                        runtime_state.endpoint.max_connections.max(1),
                    ) {
                        continue;
                    }

                    let metrics = Arc::clone(&runtime_state.metrics);
                    let metrics_path = runtime_state.endpoint.path.clone();
                    let timeout =
                        Duration::from_millis(runtime_state.endpoint.connection_timeout_ms.max(1));
                    let service = MetricsHttpService::new(
                        metrics_path,
                        EdgeMetricsSource { metrics },
                    );

                    tokio::spawn(async move {
                        let _connection_guard = ConnectionSlotGuard::new(active_connections);
                        match service.serve(stream, tls_config, timeout).await {
                            Ok(()) => {}
                            Err(MetricsConnectionError::TlsHandshake(err)) => {
                                debug!("Metrics endpoint mTLS handshake failed: {}", err);
                            }
                            Err(MetricsConnectionError::TlsHandshakeTimeout) => {
                                debug!("Metrics endpoint mTLS handshake timed out");
                            }
                            Err(MetricsConnectionError::Http(err)) => {
                                error!("Metrics endpoint connection failed: {}", err);
                            }
                            Err(MetricsConnectionError::ConnectionTimeout) => {
                                debug!("Metrics endpoint connection timed out");
                            }
                        }
                    });
                }
            },
        );
        Ok(())
    }
}
