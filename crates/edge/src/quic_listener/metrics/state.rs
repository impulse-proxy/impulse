use super::*;

pub(in crate::quic_listener) struct MetricsTlsState {
    primary_listener_label: String,
    runtime_generation: Option<u64>,
    listener_tls_generation: u64,
    server_config: Arc<RustlsServerConfig>,
}
#[derive(Clone)]
pub(in crate::quic_listener) struct MetricsEndpointState {
    pub(in crate::quic_listener) endpoint: MetricsEndpoint,
    pub(in crate::quic_listener) metrics: Arc<Metrics>,
}

impl MetricsServiceCtx {
    pub(in crate::quic_listener) fn current_tls_config(
        &self,
    ) -> Result<Option<Arc<RustlsServerConfig>>, ProxyError> {
        let runtime = self.runtime.current_view();
        if !runtime
            .runtime_config()
            .observability
            .metrics
            .allow_non_loopback
        {
            return Ok(None);
        }
        let listener = runtime
            .runtime_config()
            .primary_listener_runtime_config()
            .ok_or_else(|| {
                ProxyError::Transport("no effective listeners configured".to_string())
            })?;
        let security = runtime.control_api_security();
        Http3Service::build_control_api_server_tls_config(&listener, &security.client_auth)
            .map(Some)
    }

    pub(in crate::quic_listener) fn current_state(&self) -> MetricsEndpointState {
        let runtime = self.runtime.current_view();
        MetricsEndpointState {
            endpoint: runtime.runtime_config().observability.metrics.clone(),
            metrics: runtime.metrics(),
        }
    }

    pub(in crate::quic_listener) fn refresh_tls_state(
        &self,
        tls_state: &mut Option<MetricsTlsState>,
    ) -> Result<Option<Arc<RustlsServerConfig>>, ProxyError> {
        let runtime = self.runtime.current_view();
        if !runtime
            .runtime_config()
            .observability
            .metrics
            .allow_non_loopback
        {
            *tls_state = None;
            return Ok(None);
        }
        let listener = runtime
            .runtime_config()
            .primary_listener_runtime_config()
            .ok_or_else(|| {
                ProxyError::Transport("no effective listeners configured".to_string())
            })?;
        let primary_listener_label = Http3Service::listener_label(&listener);
        let runtime_generation = self.runtime.current_generation().map(|g| g.generation());
        let listener_tls_generation = runtime
            .listener_tls_store()
            .generation(&primary_listener_label)
            .unwrap_or(0);
        let needs_refresh = tls_state.as_ref().is_none_or(|state| {
            state.primary_listener_label != primary_listener_label
                || state.runtime_generation != runtime_generation
                || state.listener_tls_generation != listener_tls_generation
        });
        if needs_refresh {
            let security = runtime.control_api_security();
            let server_config = Http3Service::build_control_api_server_tls_config(
                &listener,
                &security.client_auth,
            )?;
            *tls_state = Some(MetricsTlsState {
                primary_listener_label,
                runtime_generation,
                listener_tls_generation,
                server_config,
            });
        }
        Ok(tls_state
            .as_ref()
            .map(|state| Arc::clone(&state.server_config)))
    }
}
