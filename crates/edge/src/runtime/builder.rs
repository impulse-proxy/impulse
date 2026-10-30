use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, SocketAddr as StdSocketAddr},
    sync::{Arc, RwLock},
    time::Duration,
};

use impulse_config::runtime::{ListenerRuntimeConfig, RuntimeBackendAddressKind, RuntimeConfig};
use impulse_errors::ProxyError;
use impulse_lb::pingora_backend::{
    GenerationBackendView, HealthRegistry, PingoraLoadBalancingRuntimeState, map_validated_backend,
};
use impulse_transport::PingoraBackendHealthIdentity;
use log::{debug, info, warn};
use tokio::sync::Semaphore;

use crate::{
    resilience::runtime::RuntimeResilience,
    routing::index::RouteIndex,
    runtime::{
        backend::{
            lifecycle::BackendLifecycleCoordinator, resolution::RuntimeBackendResolution,
            store::RuntimeBackendResolutionStore,
        },
        generation::{CarriedProcessSharedServices, RuntimeGenerationState, RuntimeSharedServices},
        shared_state::SharedRuntimeState,
        subsystem_mapping::{
            load_balancing_backend_inputs, load_balancing_strategy_input,
            upstream_pool_from_runtime, upstream_transport_inputs,
        },
        tasks::RuntimeTaskRegistry,
        tls::store::ListenerTlsReloadStore,
        transport::create_transport_pool,
    },
    watchdog::{config::WatchdogRuntimeConfig, coordinator::WatchdogCoordinator},
};

pub(crate) struct RuntimeBuilder;

impl RuntimeBuilder {
    pub(crate) fn build(
        config: &RuntimeConfig,
        carried: Option<CarriedProcessSharedServices>,
        generation: u64,
        listener_tls_store: Arc<ListenerTlsReloadStore>,
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
            .map(|listener_config| (listener_label(&listener_config), listener_config))
            .collect::<HashMap<_, _>>();
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
        let transport_pool = create_transport_pool(
            upstream_transport_inputs(config),
            backend_dns_resolver.clone(),
        )?;
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
            let upstream_pool = upstream_pool_from_runtime(runtime_upstream).map_err(|err| {
                ProxyError::Transport(format!(
                    "failed to create upstream pool '{}': {}",
                    name, err
                ))
            })?;
            upstream_pools.insert(name.clone(), Arc::new(RwLock::new(upstream_pool)));
            upstream_inflight.insert(name.clone(), Arc::new(Semaphore::new(per_upstream_limit)));

            let tls_identity = runtime_upstream.backend_tls_policy().clone();
            let backend_inputs = load_balancing_backend_inputs(runtime_upstream);
            let view = GenerationBackendView::new(
                generation,
                name,
                &backend_inputs,
                |backend| {
                    let endpoint = &runtime_upstream.backends[backend.index()].endpoint;
                    // shortcut: hostname membership remains logical until Pingora discovery owns DNS.
                    let address = StdSocketAddr::new(
                        endpoint
                            .authority_host
                            .parse()
                            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                        endpoint.authority_port,
                    );
                    let mut mapped = map_validated_backend(backend, address, tls_identity.clone())?;
                    let health_identity = transport_pool
                        .pingora_backend_health_identity(backend.configured_address())
                        .ok_or_else(|| {
                            format!(
                                "missing Pingora health identity for backend '{}'",
                                backend.configured_address()
                            )
                        })?;
                    mapped.ext.insert(health_identity);
                    Ok(mapped)
                },
                Arc::clone(&pingora_health_registry),
            )
            .map_err(|error| {
                metrics
                    .runtime_observations()
                    .inc_pingora_lb_selector_failure();
                ProxyError::Transport(format!(
                    "failed to create Pingora selector for upstream '{name}': {error}"
                ))
            })?;
            pingora_selectors.push((
                name.clone(),
                load_balancing_strategy_input(runtime_upstream.load_balancing.strategy).map_err(
                    |error| {
                        ProxyError::Transport(format!(
                            "failed to create Pingora selector for upstream '{name}': {error}"
                        ))
                    },
                )?,
                view,
            ));
        }
        let pingora_load_balancing = Arc::new(
            PingoraLoadBalancingRuntimeState::new(
                generation,
                upstream_pools,
                pingora_selectors,
                pingora_health_registry,
            )
            .map_err(|error| {
                metrics
                    .runtime_observations()
                    .inc_pingora_lb_selector_failure();
                ProxyError::Transport(format!(
                    "failed to create Pingora load-balancing runtime: {error}"
                ))
            })?,
        );
        metrics
            .runtime_observations()
            .record_pingora_lb_selector_rebuild(generation, pingora_load_balancing.len());

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
                pingora_load_balancing,
                upstream_inflight,
                global_inflight: Arc::new(Semaphore::new(global_inflight_limit)),
                routing_index,
                resilience,
                generation_tasks: Arc::new(RuntimeTaskRegistry::new()),
            },
        ))
    }
}

fn listener_label(config: &ListenerRuntimeConfig) -> String {
    format!(
        "{}:{}",
        config.listen.listen.address, config.listen.listen.port
    )
}
