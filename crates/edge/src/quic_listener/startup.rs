use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddr as StdSocketAddr, ToSocketAddrs, UdpSocket},
    sync::{Arc, RwLock},
    time::Duration,
};

use impulse_config::runtime::{ListenerRuntimeConfig, RuntimeBackendAddressKind, RuntimeConfig};
use impulse_errors::ProxyError;
use impulse_lb::{
    pingora_backend::{
        GenerationBackendView, HealthRegistry, PingoraLoadBalancingRuntimeState,
        map_validated_backend,
    },
    upstream_pool::UpstreamPool,
};
use impulse_transport::{PingoraBackendHealthIdentity, UpstreamTransportPool};
use log::{debug, info, warn};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::sync::Semaphore;

use crate::{
    Metrics,
    constants::UDP_READ_TIMEOUT_MS,
    quic_listener::{ListenerRuntimeSettings, runtime_state::PreparedListenerStartup},
    resilience::{quota::QuotaRuntime, runtime::RuntimeResilience},
    routing::index::RouteIndex,
    runtime::{
        backend::{
            lifecycle::BackendLifecycleCoordinator, resolution::RuntimeBackendResolution,
            store::RuntimeBackendResolutionStore,
        },
        bundle::{RuntimeBundle, RuntimeBundleHandle},
        connection::{PerSourceTokenBucket, TokenBucket},
        generation::{RuntimeGenerationState, RuntimeSharedServices, StartupOwnedRuntimeState},
        listener::{QUICListener, ShutdownSignal},
        shared_state::SharedRuntimeState,
        tasks::RuntimeTaskRegistry,
    },
    watchdog::{config::WatchdogRuntimeConfig, coordinator::WatchdogCoordinator},
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
        let transport_policy = &config.policies.transport;
        let timeout_policy = &config.policies.timeouts;
        let worker_threads = transport_policy.worker_threads.max(1);
        let shard_count = transport_policy.packet_shards_per_worker.max(1);
        let active_worker_threads = if worker_threads > 1 && !transport_policy.reuseport {
            1
        } else {
            worker_threads
        };
        let worker_slots = active_worker_threads.saturating_mul(shard_count).max(1);
        let per_upstream_limit = transport_policy
            .connection_limits
            .per_upstream_inflight
            .max(1);
        let global_inflight_limit = transport_policy.connection_limits.global_inflight.max(1);
        info!(
            "Runtime performance concurrency worker_threads={} control_plane_threads={} packet_shards_per_worker={} reuseport={} pin_workers={}",
            worker_threads,
            transport_policy.control_plane_threads.max(1),
            shard_count,
            transport_policy.reuseport,
            transport_policy.pin_workers,
        );
        info!(
            "Runtime performance inflight_limits global_inflight_limit={} per_upstream_inflight_limit={} per_backend_inflight_limit={} max_active_connections={}",
            global_inflight_limit,
            per_upstream_limit,
            transport_policy.connection_limits.per_backend,
            transport_policy.connection_limits.max_active_connections,
        );
        info!(
            "Runtime performance upstream_timeouts backend_connect_timeout_ms={} backend_timeout_ms={} backend_body_idle_timeout_ms={} backend_body_total_timeout_ms={} backend_total_request_timeout_ms={}",
            timeout_policy.backend_connect.as_millis(),
            timeout_policy.backend_request.as_millis(),
            timeout_policy.backend_body_idle.as_millis(),
            timeout_policy.backend_body_total.as_millis(),
            timeout_policy.backend_total_request.as_millis(),
        );
        info!(
            "Runtime performance request_limits client_body_idle_timeout_ms={} max_request_body_bytes={} max_response_body_bytes={} request_buffer_global_cap_bytes={} unknown_length_response_prebuffer_bytes={}",
            timeout_policy.client_body_idle.as_millis(),
            transport_policy.max_request_body_bytes,
            transport_policy.max_response_body_bytes,
            transport_policy.request_buffer_global_cap_bytes,
            transport_policy.unknown_length_response_prebuffer_bytes,
        );
        info!(
            "Runtime performance transport_buffers udp_recv_buffer_bytes={} udp_send_buffer_bytes={} h2_pool_max_idle_per_backend={} h2_pool_idle_timeout_ms={}",
            transport_policy.udp_recv_buffer_bytes,
            transport_policy.udp_send_buffer_bytes,
            transport_policy.backend_connections.max_idle_per_backend,
            transport_policy
                .backend_connections
                .pool_idle_timeout
                .as_millis(),
        );

        let listener_runtime_configs = config
            .listener_runtime_configs()
            .into_iter()
            .map(|listener_config| (Self::listener_label(&listener_config), listener_config))
            .collect::<HashMap<_, _>>();
        let listener_tls_store = match carried.as_ref() {
            Some(carried) => Arc::clone(&carried.listener_tls_store),
            None => Arc::new(Self::build_listener_tls_reload_store(config)?),
        };

        let mut backend_resolutions = Vec::new();
        let mut seen_backend_origins: HashMap<String, (String, String)> = HashMap::new();
        let mut backend_endpoints = HashMap::new();
        let mut backend_health_checks = HashMap::new();
        for (upstream_name, upstream) in &config.upstreams {
            for backend in &upstream.backends {
                let endpoint = backend.endpoint.canonical.clone();
                let origin = backend.endpoint.origin.clone();
                if let Some((existing_upstream, existing_backend)) = seen_backend_origins.insert(
                    origin.clone(),
                    (upstream_name.clone(), backend.backend.id.clone()),
                ) {
                    return Err(ProxyError::Transport(format!(
                        "duplicate backend address '{}' detected while building upstream transport pool: upstream '{}' backend '{}' conflicts with upstream '{}' backend '{}'",
                        origin,
                        upstream_name,
                        backend.backend.id,
                        existing_upstream,
                        existing_backend
                    )));
                }
                let authority_host = backend.endpoint.authority_host.clone();
                let authority_port = backend.endpoint.authority_port;
                let resolution = if matches!(
                    backend.endpoint.address_kind,
                    RuntimeBackendAddressKind::IpLiteral
                ) {
                    let ip_addr = authority_host.parse::<IpAddr>().map_err(|err| {
                        ProxyError::Transport(format!(
                            "failed to parse IP literal backend '{}' in upstream '{}' (backend '{}'): {}",
                            backend.backend.address, upstream_name, backend.backend.id, err
                        ))
                    })?;
                    RuntimeBackendResolution::ip_literal(
                        backend.backend.address.clone(),
                        authority_host,
                        authority_port,
                        vec![StdSocketAddr::new(ip_addr, authority_port)],
                    )
                } else {
                    RuntimeBackendResolution::hostname(
                        backend.backend.address.clone(),
                        authority_host,
                        authority_port,
                    )
                };
                backend_resolutions.push(resolution);
                let authority_kind = match backend.endpoint.address_kind {
                    RuntimeBackendAddressKind::IpLiteral => "ip_literal",
                    RuntimeBackendAddressKind::Hostname => "hostname",
                };
                debug!(
                    "Configured upstream TLS policy backend={} upstream={} verify_certificates={} strict_sni={} ca_file={:?} ca_dir={:?} authority_kind={}",
                    backend.backend.address,
                    upstream_name,
                    upstream.backend_tls_policy().verify_certificates,
                    upstream.backend_tls_policy().strict_sni,
                    upstream.backend_tls_policy().ca_file,
                    upstream.backend_tls_policy().ca_dir,
                    authority_kind
                );
                backend_endpoints.insert(backend.backend.address.clone(), endpoint);
                if let Some(health_check) = backend.health_check.clone() {
                    backend_health_checks.insert(backend.backend.address.clone(), health_check);
                }
            }
        }

        let mut route_labels = config.upstreams.keys().cloned().collect::<Vec<_>>();
        route_labels.push("unrouted".to_string());
        let routing_index = Arc::new(RouteIndex::from_runtime_upstreams(&config.upstreams));
        let metrics = Arc::new(crate::Metrics::new(worker_slots, route_labels));
        // Process-scoped: reuse the active generation's DNS resolver on reload so
        // its cache is preserved; only startup creates a fresh one.
        let backend_dns_resolver = carried
            .as_ref()
            .map(|carried| carried.backend_dns_resolver.clone())
            .unwrap_or_default();
        let backend_resolution_store =
            Arc::new(RuntimeBackendResolutionStore::new(backend_resolutions));
        let backend_lifecycle = Arc::new(BackendLifecycleCoordinator::new(Arc::clone(
            &backend_resolution_store,
        )));
        let transport_pool = Arc::new(
            UpstreamTransportPool::from_runtime_upstreams(
                config.upstreams.values(),
                &transport_policy.backend_connections,
                backend_dns_resolver.clone(),
            )
            .map_err(ProxyError::Tls)?,
        );
        let mut upstream_pools = HashMap::new();
        let mut upstream_inflight = HashMap::new();
        let mut pingora_selectors = Vec::with_capacity(config.upstreams.len());
        let pingora_health_registry = Arc::new(HealthRegistry::with_equivalence(|backend| {
            backend
                .ext
                .get::<PingoraBackendHealthIdentity>()
                .map_or_else(
                    || {
                        let mut hasher = DefaultHasher::new();
                        backend.hash(&mut hasher);
                        hasher.finish()
                    },
                    |identity| identity.equivalence_key(),
                )
        }));
        for (name, runtime_upstream) in &config.upstreams {
            let upstream_pool =
                UpstreamPool::from_runtime_upstream(runtime_upstream).map_err(|err| {
                    ProxyError::Transport(format!(
                        "failed to create upstream pool '{}': {}",
                        name, err
                    ))
                })?;
            upstream_pools.insert(name.clone(), Arc::new(RwLock::new(upstream_pool)));
            upstream_inflight.insert(name.clone(), Arc::new(Semaphore::new(per_upstream_limit)));

            let tls_identity = runtime_upstream.backend_tls_policy().clone();
            let view = GenerationBackendView::from_runtime_upstream(
                generation,
                name,
                runtime_upstream,
                |index, backend| {
                    let endpoint = &runtime_upstream.backends[index].endpoint;
                    // shortcut: hostname membership remains logical until Pingora discovery owns DNS.
                    let address = StdSocketAddr::new(
                        endpoint
                            .authority_host
                            .parse()
                            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                        endpoint.authority_port,
                    );
                    let mut mapped =
                        map_validated_backend(backend, index, address, tls_identity.clone())?;
                    let health_identity = transport_pool
                        .pingora_backend_health_identity(&backend.address)
                        .ok_or_else(|| {
                            format!(
                                "missing Pingora health identity for backend '{}'",
                                backend.address
                            )
                        })?;
                    mapped.ext.insert(health_identity);
                    Ok(mapped)
                },
                Arc::clone(&pingora_health_registry),
            )
            .map_err(|error| {
                metrics.inc_pingora_lb_selector_failure();
                ProxyError::Transport(format!(
                    "failed to create Pingora selector for upstream '{name}': {error}"
                ))
            })?;
            pingora_selectors.push((name.clone(), runtime_upstream.load_balancing.strategy, view));
        }
        let pingora_load_balancing = Arc::new(
            PingoraLoadBalancingRuntimeState::new(
                generation,
                pingora_selectors,
                pingora_health_registry,
            )
            .map_err(|error| {
                metrics.inc_pingora_lb_selector_failure();
                ProxyError::Transport(format!(
                    "failed to create Pingora load-balancing runtime: {error}"
                ))
            })?,
        );
        metrics.record_pingora_lb_selector_rebuild(generation, pingora_load_balancing.len());

        let mut effective_admission = config.policies.admission.clone();
        let default_route_cap_limit = per_upstream_limit.saturating_mul(2).max(1);
        if effective_admission.route_queue.default_cap > default_route_cap_limit {
            warn!(
                "resilience.route_queue.default_cap={} is above tuned limit {}; clamping for steadier timeout/admission behavior",
                effective_admission.route_queue.default_cap, default_route_cap_limit
            );
        }
        let global_route_cap_limit = global_inflight_limit.saturating_mul(2).max(1);
        if effective_admission.route_queue.global_cap > global_route_cap_limit {
            warn!(
                "resilience.route_queue.global_cap={} is above tuned limit {}; clamping for steadier timeout/admission behavior",
                effective_admission.route_queue.global_cap, global_route_cap_limit
            );
        }
        let backend_timeout_ms =
            u64::try_from(timeout_policy.backend_request.as_millis()).unwrap_or(u64::MAX);
        let tuned_high_latency = (backend_timeout_ms.saturating_mul(7) / 10).max(50);
        if effective_admission.adaptive_admission.high_latency
            > Duration::from_millis(tuned_high_latency)
        {
            warn!(
                "resilience.adaptive_admission.high_latency_ms={} is above tuned limit {}; clamping for faster overload reaction",
                effective_admission
                    .adaptive_admission
                    .high_latency
                    .as_millis(),
                tuned_high_latency
            );
        }
        effective_admission = effective_admission.with_runtime_overrides(
            default_route_cap_limit,
            global_route_cap_limit,
            Duration::from_millis(tuned_high_latency),
        );
        let resilience = Arc::new(RuntimeResilience::from_policies(
            &effective_admission,
            &config.policies.rate_limits,
        ));
        // Process-scoped: reuse the active generation's watchdog on reload so an
        // in-flight restart/drain is not silently reset; only startup creates one.
        let watchdog = match &carried {
            Some(carried) => Arc::clone(&carried.watchdog),
            None => Arc::new(WatchdogCoordinator::from_runtime_config(
                &WatchdogRuntimeConfig::from(&config.policies.admission.watchdog),
            )),
        };
        for (listener_label, inventory) in listener_tls_store.snapshot() {
            Self::update_listener_tls_expiry_metrics(&metrics, &listener_label, &inventory);
        }
        Self::update_runtime_secret_lifecycle_metrics(&metrics, config);

        Ok(SharedRuntimeState::from_parts(
            RuntimeSharedServices {
                listener_tls_store,
                transport_pool,
                backend_lifecycle,
                backend_resolution_store,
                backend_dns_resolver,
                metrics,
                watchdog,
            },
            RuntimeGenerationState {
                listener_runtime_configs: Arc::new(listener_runtime_configs),
                backend_endpoints: Arc::new(backend_endpoints),
                backend_health_checks: Arc::new(backend_health_checks),
                upstream_policies: Arc::new(
                    config
                        .upstreams
                        .iter()
                        .map(|(name, upstream)| (name.clone(), upstream.policy.clone()))
                        .collect(),
                ),
                upstream_pools,
                pingora_load_balancing,
                upstream_inflight,
                global_inflight: Arc::new(Semaphore::new(global_inflight_limit)),
                routing_index,
                resilience,
                generation_tasks: Arc::new(RuntimeTaskRegistry::new()),
            },
        ))
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
            upstream_pools: generation_state.upstream_pools.clone(),
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
                metrics.record_secret_resolve(metadata.source_kind.as_str(), "success", "resolved");
                latest_upstream_load_unix_seconds =
                    latest_upstream_load_unix_seconds.max(metadata.loaded_at_unix_ms / 1_000);
            }
            if let Some(metadata) = tls_policy.client_key.as_ref() {
                metrics.record_secret_resolve(metadata.source_kind.as_str(), "success", "resolved");
                latest_upstream_load_unix_seconds =
                    latest_upstream_load_unix_seconds.max(metadata.loaded_at_unix_ms / 1_000);
            }
            if let Some(not_after_unix_seconds) =
                tls_policy.client_certificate_not_after_unix_seconds
            {
                upstream_client_cert_expiry.push((upstream_name.clone(), not_after_unix_seconds));
            }
        }

        metrics.replace_upstream_client_cert_expiry(upstream_client_cert_expiry);
        if latest_listener_load_unix_seconds > 0 {
            metrics
                .set_secret_last_success_unixtime("listeners", latest_listener_load_unix_seconds);
        }
        if latest_upstream_load_unix_seconds > 0 {
            metrics
                .set_secret_last_success_unixtime("upstreams", latest_upstream_load_unix_seconds);
        }
    }
}
