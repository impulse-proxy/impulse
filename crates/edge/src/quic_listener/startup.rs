use std::{
    collections::HashMap,
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    sync::Arc,
    time::Duration,
};

use impulse_config::runtime::{ListenerRuntimeConfig, RuntimeConfig};
use impulse_errors::ProxyError;
use log::debug;
use socket2::{Domain, Protocol, Socket, Type};

use crate::{
    Metrics,
    constants::UDP_READ_TIMEOUT_MS,
    quic_listener::{ListenerRuntimeSettings, runtime_state::PreparedListenerStartup},
    resilience::quota::QuotaRuntime,
    runtime::{
        builder::RuntimeBuilder,
        bundle::{RuntimeBundle, RuntimeBundleHandle},
        connection::{PerSourceTokenBucket, TokenBucket},
        generation::StartupOwnedRuntimeState,
        listener::{QUICListener, ShutdownSignal},
        shared_state::SharedRuntimeState,
    },
};

impl QUICListener {
    pub(super) fn listener_runtime_settings(
        config: &ListenerRuntimeConfig,
    ) -> ListenerRuntimeSettings {
        let transport_policy = &config.policies.transport;
        let timeout_policy = &config.policies.timeouts;
        ListenerRuntimeSettings {
            backend_timeout: timeout_policy.backend_request,
            backend_body_idle_timeout: timeout_policy.backend_body_idle,
            backend_body_total_timeout: timeout_policy.backend_body_total,
            client_body_idle_timeout: timeout_policy.client_body_idle,
            backend_total_request_timeout: timeout_policy.backend_total_request,
            inflight_acquire_wait: timeout_policy.inflight_acquire_wait,
            drain_timeout: timeout_policy.shutdown_drain,
            max_active_connections: transport_policy
                .connection_limits
                .max_active_connections
                .max(1),
            max_streams_per_connection: usize::try_from(
                transport_policy.quic_initial_max_streams_bidi,
            )
            .unwrap_or(usize::MAX)
            .max(1),
            max_request_body_bytes: transport_policy.max_request_body_bytes,
            max_response_body_bytes: transport_policy.max_response_body_bytes,
            request_buffer_global_cap_bytes: transport_policy.request_buffer_global_cap_bytes,
            unknown_length_response_prebuffer_bytes: transport_policy
                .unknown_length_response_prebuffer_bytes,
            new_connections_per_sec: transport_policy.new_connections_per_sec,
            new_connections_burst: transport_policy.new_connections_burst,
        }
    }

    pub fn new(config: impulse_config::config::Config) -> Result<Self, ProxyError> {
        let prepared = Self::prepare_listener_startup(config)?;
        Self::new_with_socket_and_shared_state(
            prepared.listener_config,
            prepared.socket,
            prepared.shared_state,
        )
    }

    fn prepare_listener_startup(
        config: impulse_config::config::Config,
    ) -> Result<PreparedListenerStartup, ProxyError> {
        let runtime_config = RuntimeConfig::from_config(&config)
            .map_err(|err| ProxyError::Transport(err.to_string()))?;
        let shared_state = Arc::new(Self::build_shared_state(&runtime_config)?);
        Self::register_jwt_jwks_metrics(&Arc::clone(&shared_state.shared_services().metrics));
        QuotaRuntime::register_metrics(&Arc::clone(&shared_state.shared_services().metrics));
        Self::initialize_jwks_startup(&runtime_config)?;
        let listener_config = runtime_config
            .listener_runtime_configs()
            .into_iter()
            .next()
            .ok_or_else(|| {
                ProxyError::Transport("no effective listeners configured".to_string())
            })?;
        Self::spawn_control_plane_tasks(&runtime_config, &shared_state, 1)?;
        let socket = Self::bind_socket(&listener_config, false)?;

        Ok(PreparedListenerStartup {
            listener_config,
            shared_state,
            socket,
        })
    }

    pub fn build_shared_state(config: &RuntimeConfig) -> Result<SharedRuntimeState, ProxyError> {
        Self::build_shared_state_for_generation(config, None, 0)
    }

    /// Build the shared runtime state for a generation.
    ///
    /// On startup, `carried` is `None` and every service is constructed fresh. On
    /// reload, `carried` supplies the process-scoped services (watchdog, DNS
    /// resolver) from the active generation so their runtime state — an in-flight
    /// watchdog restart/drain, the DNS cache — survives the generation swap rather
    /// than being silently reset. All other, config-derived services are rebuilt.
    pub fn build_shared_state_with_carried(
        config: &RuntimeConfig,
        carried: Option<crate::runtime::generation::CarriedProcessSharedServices>,
    ) -> Result<SharedRuntimeState, ProxyError> {
        Self::build_shared_state_for_generation(config, carried, 0)
    }

    pub(crate) fn build_shared_state_for_generation(
        config: &RuntimeConfig,
        carried: Option<crate::runtime::generation::CarriedProcessSharedServices>,
        generation: u64,
    ) -> Result<SharedRuntimeState, ProxyError> {
        let listener_tls_store = match carried.as_ref() {
            Some(carried) => Arc::clone(&carried.listener_tls_store),
            None => Arc::new(Self::build_listener_tls_reload_store(config)?),
        };
        let shared_state =
            RuntimeBuilder::build(config, carried, generation, Arc::clone(&listener_tls_store))?;
        for (listener_label, inventory) in listener_tls_store.snapshot() {
            Self::update_listener_tls_expiry_metrics(
                &shared_state.shared_services().metrics,
                &listener_label,
                &inventory,
            );
        }
        Self::update_runtime_secret_lifecycle_metrics(
            &shared_state.shared_services().metrics,
            config,
        );
        Ok(shared_state)
    }

    pub fn build_runtime_bundle(
        config_path: String,
        log_config: impulse_config::config::Log,
        runtime_config: &RuntimeConfig,
    ) -> Result<RuntimeBundle, ProxyError> {
        let shared_state = Arc::new(Self::build_shared_state(runtime_config)?);
        Ok(RuntimeBundle {
            generation: 0,
            startup: StartupOwnedRuntimeState {
                config_path,
                log_config,
            },
            runtime_config: runtime_config.clone(),
            shared_state,
        })
    }

    pub fn bind_reuseport_sockets(
        config: &ListenerRuntimeConfig,
        workers: usize,
    ) -> Result<Vec<UdpSocket>, ProxyError> {
        let workers = workers.max(1);
        let mut sockets = Vec::with_capacity(workers);
        for _ in 0..workers {
            sockets.push(Self::bind_socket(config, true)?);
        }
        Ok(sockets)
    }

    pub fn bind_socket(
        config: &ListenerRuntimeConfig,
        reuse_port: bool,
    ) -> Result<UdpSocket, ProxyError> {
        let bind_addr = Self::resolve_bind_addr(config)?;
        let transport_policy = &config.policies.transport;
        let socket = Self::create_udp_socket(
            bind_addr,
            reuse_port,
            transport_policy.udp_recv_buffer_bytes,
            transport_policy.udp_send_buffer_bytes,
        )?;
        socket
            .set_read_timeout(Some(Duration::from_millis(UDP_READ_TIMEOUT_MS)))
            .map_err(|err| {
                ProxyError::Transport(format!("failed to set UDP read timeout: {}", err))
            })?;

        Ok(socket)
    }

    pub fn new_with_socket_and_shared_state(
        config: ListenerRuntimeConfig,
        socket: UdpSocket,
        shared_state: Arc<SharedRuntimeState>,
    ) -> Result<Self, ProxyError> {
        Self::new_with_socket_and_shared_state_and_shutdown(
            config,
            socket,
            shared_state,
            ShutdownSignal::new(),
        )
    }

    pub(crate) fn new_with_socket_and_shared_state_and_shutdown(
        config: ListenerRuntimeConfig,
        socket: UdpSocket,
        shared_state: Arc<SharedRuntimeState>,
        shutdown: ShutdownSignal,
    ) -> Result<Self, ProxyError> {
        let local_addr = socket.local_addr().map_err(|err| {
            ProxyError::Transport(format!("failed to read UDP socket local address: {}", err))
        })?;
        debug!("Listening on {}", local_addr);

        let listener_label = Self::listener_label(&config);
        let shared_services = shared_state.shared_services();
        let generation_state = shared_state.generation_state();
        let listener_tls_store = Arc::clone(&shared_services.listener_tls_store);
        let tls_reload_generation =
            listener_tls_store
                .generation(&listener_label)
                .ok_or_else(|| {
                    ProxyError::Transport(format!(
                        "missing TLS reload state for listener '{}'",
                        listener_label
                    ))
                })?;
        let quic_config = Self::build_quic_config(&config)?;
        let h3_config = Arc::new({
            let mut config = quiche::h3::Config::new().map_err(|err| {
                ProxyError::Transport(format!("failed to create h3 config: {err}"))
            })?;
            config.enable_extended_connect(true);
            config
        });
        let settings = Self::listener_runtime_settings(&config);
        let require_client_cert = Self::runtime_listener_tls(&config)?
            .client_auth
            .require_client_cert;
        let conn_rate_limiter = TokenBucket::new(
            settings.new_connections_per_sec,
            settings.new_connections_burst,
        );
        let source_conn_rate_limiter = PerSourceTokenBucket::new(
            settings.new_connections_per_sec,
            settings.new_connections_burst,
        );

        Ok(Self {
            socket,
            local_addr,
            config,
            listener_label,
            listener_tls_store,
            tls_reload_generation,
            quic_config,
            h3_config,
            transport_pool: Arc::clone(&shared_services.transport_pool),
            backend_endpoints: Arc::clone(&generation_state.backend_endpoints),
            backend_dns_resolver: shared_services.backend_dns_resolver.clone(),
            upstream_policies: Arc::clone(&generation_state.upstream_policies),
            pingora_load_balancing: Arc::clone(&generation_state.pingora_load_balancing),
            upstream_inflight: generation_state.upstream_inflight.clone(),
            global_inflight: Arc::clone(&generation_state.global_inflight),
            routing_index: Arc::clone(&generation_state.routing_index),
            metrics: Arc::clone(&shared_services.metrics),
            resilience: Arc::clone(&generation_state.resilience),
            watchdog: Arc::clone(&shared_services.watchdog),
            shutdown,
            draining: false,
            drain_start: None,
            watchdog_worker_drained: false,
            drain_timeout: settings.drain_timeout,
            backend_timeout: settings.backend_timeout,
            backend_body_idle_timeout: settings.backend_body_idle_timeout,
            backend_body_total_timeout: settings.backend_body_total_timeout,
            client_body_idle_timeout: settings.client_body_idle_timeout,
            backend_total_request_timeout: settings.backend_total_request_timeout,
            inflight_acquire_wait: settings.inflight_acquire_wait,
            max_active_connections: settings.max_active_connections,
            max_streams_per_connection: settings.max_streams_per_connection,
            max_request_body_bytes: settings.max_request_body_bytes,
            max_response_body_bytes: settings.max_response_body_bytes,
            request_buffer_global_cap_bytes: settings.request_buffer_global_cap_bytes,
            unknown_length_response_prebuffer_bytes: settings
                .unknown_length_response_prebuffer_bytes,
            require_client_cert,
            runtime_bundle: None,
            runtime_generation: 0,
            response_cache_namespace: 0,
            recv_buf: Box::new([0; crate::constants::MAX_DATAGRAM_SIZE_BYTES]),
            send_buf: Box::new([0; crate::constants::MAX_DATAGRAM_SIZE_BYTES]),
            connections: HashMap::new(),
            cid_routes: HashMap::new(),
            peer_routes: HashMap::new(),
            cid_radix: crate::cid_radix::CidRadix::new(),
            conn_rate_limiter,
            source_conn_rate_limiter,
        })
    }

    pub(crate) fn new_with_socket_and_runtime_bundle_and_shutdown(
        listener_label: &str,
        socket: UdpSocket,
        runtime_bundle: Arc<RuntimeBundleHandle>,
        shutdown: ShutdownSignal,
    ) -> Result<Self, ProxyError> {
        let (runtime, response_cache_namespace) =
            runtime_bundle.current_view_with_response_cache_namespace();
        let listener_config = runtime
            .listener_runtime_config(listener_label)
            .ok_or_else(|| {
                ProxyError::Transport(format!(
                    "runtime reload dropped listener '{}'",
                    listener_label
                ))
            })?;
        let mut listener = Self::new_with_socket_and_shared_state_and_shutdown(
            listener_config,
            socket,
            Arc::clone(&runtime.bundle().shared_state),
            shutdown,
        )?;
        listener.runtime_generation = runtime.generation();
        listener.response_cache_namespace = response_cache_namespace;
        listener.runtime_bundle = Some(runtime_bundle);
        Ok(listener)
    }

    pub fn with_runtime_bundle(mut self, runtime_bundle: Arc<RuntimeBundleHandle>) -> Self {
        let (runtime, response_cache_namespace) =
            runtime_bundle.current_view_with_response_cache_namespace();
        self.runtime_generation = runtime.generation();
        self.response_cache_namespace = response_cache_namespace;
        self.runtime_bundle = Some(runtime_bundle);
        self
    }

    fn resolve_bind_addr(config: &ListenerRuntimeConfig) -> Result<SocketAddr, ProxyError> {
        let socket_address = format!(
            "{}:{}",
            config.listen.listen.address, config.listen.listen.port
        );
        socket_address
            .to_socket_addrs()
            .map_err(|err| {
                ProxyError::Transport(format!(
                    "failed to resolve listen address '{}': {}",
                    socket_address, err
                ))
            })?
            .next()
            .ok_or_else(|| {
                ProxyError::Transport(format!("no socket addresses found for '{socket_address}'"))
            })
    }

    fn create_udp_socket(
        bind_addr: SocketAddr,
        reuse_port: bool,
        udp_recv_buffer_bytes: usize,
        udp_send_buffer_bytes: usize,
    ) -> Result<UdpSocket, ProxyError> {
        let domain = if bind_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(|err| {
            ProxyError::Transport(format!("failed to create UDP socket: {}", err))
        })?;
        socket
            .set_reuse_address(true)
            .map_err(|err| ProxyError::Transport(format!("failed to set SO_REUSEADDR: {}", err)))?;
        socket
            .set_recv_buffer_size(udp_recv_buffer_bytes)
            .map_err(|err| {
                ProxyError::Transport(format!(
                    "failed to set UDP recv buffer size ({}): {}",
                    udp_recv_buffer_bytes, err
                ))
            })?;
        socket
            .set_send_buffer_size(udp_send_buffer_bytes)
            .map_err(|err| {
                ProxyError::Transport(format!(
                    "failed to set UDP send buffer size ({}): {}",
                    udp_send_buffer_bytes, err
                ))
            })?;

        #[cfg(all(
            unix,
            not(target_os = "solaris"),
            not(target_os = "illumos"),
            not(target_os = "cygwin")
        ))]
        {
            socket.set_reuse_port(reuse_port).map_err(|err| {
                ProxyError::Transport(format!("failed to set SO_REUSEPORT: {}", err))
            })?;
        }

        socket.bind(&bind_addr.into()).map_err(|err| {
            ProxyError::Transport(format!(
                "failed to bind UDP socket on '{}': {}",
                bind_addr, err
            ))
        })?;

        match (socket.recv_buffer_size(), socket.send_buffer_size()) {
            (Ok(actual_recv), Ok(actual_send)) => {
                debug!(
                    "UDP socket buffers on {}: recv={} (requested={}) send={} (requested={}) reuseport={}",
                    bind_addr,
                    actual_recv,
                    udp_recv_buffer_bytes,
                    actual_send,
                    udp_send_buffer_bytes,
                    reuse_port
                );
            }
            _ => {
                debug!(
                    "UDP socket bound on {} with requested buffers recv={} send={} reuseport={}",
                    bind_addr, udp_recv_buffer_bytes, udp_send_buffer_bytes, reuse_port
                );
            }
        }

        Ok(socket.into())
    }

    fn update_runtime_secret_lifecycle_metrics(metrics: &Metrics, config: &RuntimeConfig) {
        let mut upstream_client_cert_expiry = Vec::new();
        let mut latest_listener_load_unix_seconds = 0u64;
        let mut latest_upstream_load_unix_seconds = 0u64;

        for listener in config.listener_runtime_configs() {
            let label = Self::listener_label(&listener);
            if let Ok(state) = Self::build_listener_tls_reload_state(&listener) {
                latest_listener_load_unix_seconds =
                    latest_listener_load_unix_seconds.max(state.loaded_at_unix_ms / 1_000);
                Self::update_listener_tls_expiry_metrics(metrics, &label, &state.inventory);
            }
        }

        for (upstream_name, upstream) in &config.upstreams {
            let tls_policy = upstream.backend_tls_policy();

            if let Some(metadata) = tls_policy.client_certificate.as_ref() {
                metrics.runtime_observations().record_secret_resolve(
                    metadata.source_kind.as_str(),
                    "success",
                    "resolved",
                );
                latest_upstream_load_unix_seconds =
                    latest_upstream_load_unix_seconds.max(metadata.loaded_at_unix_ms / 1_000);
            }
            if let Some(metadata) = tls_policy.client_key.as_ref() {
                metrics.runtime_observations().record_secret_resolve(
                    metadata.source_kind.as_str(),
                    "success",
                    "resolved",
                );
                latest_upstream_load_unix_seconds =
                    latest_upstream_load_unix_seconds.max(metadata.loaded_at_unix_ms / 1_000);
            }
            if let Some(not_after_unix_seconds) =
                tls_policy.client_certificate_not_after_unix_seconds
            {
                upstream_client_cert_expiry.push((upstream_name.clone(), not_after_unix_seconds));
            }
        }

        metrics
            .runtime_observations()
            .replace_upstream_client_cert_expiry(upstream_client_cert_expiry);
        if latest_listener_load_unix_seconds > 0 {
            metrics
                .runtime_observations()
                .set_secret_last_success_unixtime("listeners", latest_listener_load_unix_seconds);
        }
        if latest_upstream_load_unix_seconds > 0 {
            metrics
                .runtime_observations()
                .set_secret_last_success_unixtime("upstreams", latest_upstream_load_unix_seconds);
        }
    }
}
