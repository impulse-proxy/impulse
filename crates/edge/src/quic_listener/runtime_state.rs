use std::{
    collections::HashMap,
    net::UdpSocket,
    sync::{Arc, RwLock},
    time::Instant,
};

use impulse_config::runtime::{ListenerRuntimeConfig, RuntimeBackendTlsPolicy, RuntimeConfig};
use impulse_errors::ProxyError;
use impulse_lb::{
    pingora_backend::SharedPingoraLoadBalancingRuntimeState, upstream_pool::UpstreamPool,
};
use impulse_transport::{SharedDnsResolver, UpstreamTransportPool};

use crate::{
    Metrics,
    quic_listener::control_api::security::{ControlApiAuthThrottle, ControlApiSecurityPolicy},
    resilience::runtime::RuntimeResilience,
    runtime::{
        backend::lifecycle::BackendLifecycleCoordinator,
        bundle::{ActiveRuntimeGeneration, RuntimeBundleHandle},
        generation::RuntimeGenerationView,
        shared_state::SharedRuntimeState,
        tasks::RuntimeTaskRegistry,
        tls::store::ListenerTlsReloadStore,
    },
    watchdog::coordinator::WatchdogCoordinator,
};

#[derive(Clone)]
pub(super) struct ControlPlaneRuntimeView {
    runtime_config: RuntimeConfig,
    metrics: Arc<Metrics>,
    resilience: Arc<RuntimeResilience>,
    watchdog: Arc<WatchdogCoordinator>,
    backend_lifecycle: Arc<BackendLifecycleCoordinator>,
    transport_pool: Arc<UpstreamTransportPool>,
    backend_dns_resolver: SharedDnsResolver,
    upstream_pools: HashMap<String, Arc<RwLock<UpstreamPool>>>,
    pingora_load_balancing: SharedPingoraLoadBalancingRuntimeState<RuntimeBackendTlsPolicy>,
    listener_runtime_configs: Arc<HashMap<String, ListenerRuntimeConfig>>,
    backend_health_checks: Arc<HashMap<String, impulse_config::runtime::RuntimeBackendHealthCheck>>,
    generation_tasks: Arc<RuntimeTaskRegistry>,
    listener_tls_store: Arc<ListenerTlsReloadStore>,
    primary_listener_label: Option<String>,
    control_api_security: Arc<ControlApiSecurityPolicy>,
}

impl ControlPlaneRuntimeView {
    pub(super) fn from_runtime_sources(
        runtime_config: &RuntimeConfig,
        shared_state: &SharedRuntimeState,
    ) -> Self {
        let shared = shared_state.shared_services();
        let generation = shared_state.generation_state();

        Self {
            runtime_config: runtime_config.clone(),
            metrics: Arc::clone(&shared.metrics),
            resilience: Arc::clone(&generation.resilience),
            watchdog: Arc::clone(&shared.watchdog),
            backend_lifecycle: Arc::clone(&shared.backend_lifecycle),
            transport_pool: Arc::clone(&shared.transport_pool),
            backend_dns_resolver: shared.backend_dns_resolver.clone(),
            upstream_pools: generation.upstream_pools.clone(),
            pingora_load_balancing: Arc::clone(&generation.pingora_load_balancing),
            listener_runtime_configs: Arc::clone(&generation.listener_runtime_configs),
            backend_health_checks: Arc::clone(&generation.backend_health_checks),
            generation_tasks: Arc::clone(&generation.generation_tasks),
            listener_tls_store: Arc::clone(&shared.listener_tls_store),
            primary_listener_label: runtime_config
                .primary_listener_runtime_config()
                .map(|listener| crate::quic_listener::QUICListener::listener_label(&listener)),
            control_api_security: Arc::new(ControlApiSecurityPolicy::from_config(
                &runtime_config.observability.control_api,
                Arc::clone(&shared.metrics),
            )),
        }
    }

    pub(super) fn from_generation(view: RuntimeGenerationView<'_>) -> Self {
        Self {
            runtime_config: view.runtime_config.clone(),
            metrics: Arc::clone(&view.shared.metrics),
            resilience: Arc::clone(&view.state.resilience),
            watchdog: Arc::clone(&view.shared.watchdog),
            backend_lifecycle: Arc::clone(&view.shared.backend_lifecycle),
            transport_pool: Arc::clone(&view.shared.transport_pool),
            backend_dns_resolver: view.shared.backend_dns_resolver.clone(),
            upstream_pools: view.state.upstream_pools.clone(),
            pingora_load_balancing: Arc::clone(&view.state.pingora_load_balancing),
            listener_runtime_configs: Arc::clone(&view.state.listener_runtime_configs),
            backend_health_checks: Arc::clone(&view.state.backend_health_checks),
            generation_tasks: Arc::clone(&view.state.generation_tasks),
            listener_tls_store: Arc::clone(&view.shared.listener_tls_store),
            primary_listener_label: view
                .runtime_config
                .primary_listener_runtime_config()
                .map(|listener| crate::quic_listener::QUICListener::listener_label(&listener)),
            control_api_security: Arc::new(ControlApiSecurityPolicy::from_config(
                &view.runtime_config.observability.control_api,
                Arc::clone(&view.shared.metrics),
            )),
        }
    }

    pub(super) fn runtime_config(&self) -> &RuntimeConfig {
        &self.runtime_config
    }

    pub(super) fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.metrics)
    }

    pub(super) fn resilience(&self) -> Arc<RuntimeResilience> {
        Arc::clone(&self.resilience)
    }

    pub(super) fn watchdog(&self) -> Arc<WatchdogCoordinator> {
        Arc::clone(&self.watchdog)
    }

    pub(super) fn backend_lifecycle(&self) -> Arc<BackendLifecycleCoordinator> {
        Arc::clone(&self.backend_lifecycle)
    }

    pub(super) fn transport_pool(&self) -> Arc<UpstreamTransportPool> {
        Arc::clone(&self.transport_pool)
    }

    pub(super) fn backend_dns_resolver(&self) -> SharedDnsResolver {
        self.backend_dns_resolver.clone()
    }

    pub(super) fn upstream_pools(&self) -> &HashMap<String, Arc<RwLock<UpstreamPool>>> {
        &self.upstream_pools
    }

    pub(super) fn pingora_load_balancing(
        &self,
    ) -> SharedPingoraLoadBalancingRuntimeState<RuntimeBackendTlsPolicy> {
        Arc::clone(&self.pingora_load_balancing)
    }

    pub(super) fn listener_runtime_configs(&self) -> Arc<HashMap<String, ListenerRuntimeConfig>> {
        Arc::clone(&self.listener_runtime_configs)
    }

    pub(super) fn backend_health_checks(
        &self,
    ) -> Arc<HashMap<String, impulse_config::runtime::RuntimeBackendHealthCheck>> {
        Arc::clone(&self.backend_health_checks)
    }

    pub(super) fn generation_tasks(&self) -> Arc<RuntimeTaskRegistry> {
        Arc::clone(&self.generation_tasks)
    }

    pub(super) fn listener_tls_store(&self) -> Arc<ListenerTlsReloadStore> {
        Arc::clone(&self.listener_tls_store)
    }

    pub(super) fn primary_listener_label(&self) -> Option<&str> {
        self.primary_listener_label.as_deref()
    }

    pub(super) fn control_api_security(&self) -> Arc<ControlApiSecurityPolicy> {
        Arc::clone(&self.control_api_security)
    }

    pub(super) fn expected_workers(&self) -> usize {
        self.runtime_config
            .policies
            .transport
            .worker_threads
            .max(1)
            .saturating_mul(
                self.runtime_config
                    .policies
                    .transport
                    .packet_shards_per_worker
                    .max(1),
            )
            .max(1)
    }
}

#[derive(Clone)]
pub(super) struct ControlPlaneRuntimeCtx {
    startup_view: ControlPlaneRuntimeView,
    runtime_bundle: Option<Arc<RuntimeBundleHandle>>,
}

impl ControlPlaneRuntimeCtx {
    pub(super) fn from_runtime_sources(
        runtime_config: &RuntimeConfig,
        shared_state: &SharedRuntimeState,
        runtime_bundle: Option<Arc<RuntimeBundleHandle>>,
    ) -> Self {
        Self {
            startup_view: ControlPlaneRuntimeView::from_runtime_sources(
                runtime_config,
                shared_state,
            ),
            runtime_bundle,
        }
    }

    pub(super) fn current_view(&self) -> ControlPlaneRuntimeView {
        self.runtime_bundle
            .as_ref()
            .map(|handle| handle.with_current_view(ControlPlaneRuntimeView::from_generation))
            .unwrap_or_else(|| self.startup_view.clone())
    }

    pub(super) fn current_generation(&self) -> Option<ActiveRuntimeGeneration> {
        self.runtime_bundle
            .as_ref()
            .map(|handle| handle.current_view())
    }

    pub(super) fn runtime_bundle_handle(&self) -> Option<&Arc<RuntimeBundleHandle>> {
        self.runtime_bundle.as_ref()
    }
}

#[derive(Clone)]
pub(crate) struct ControlApiServiceCtx {
    pub(super) runtime: ControlPlaneRuntimeCtx,
    pub(super) started_at: Instant,
    pub(super) auth_throttle: Arc<ControlApiAuthThrottle>,
}

impl ControlApiServiceCtx {
    pub(super) fn new(runtime: ControlPlaneRuntimeCtx) -> Self {
        Self {
            runtime,
            started_at: Instant::now(),
            auth_throttle: Arc::new(ControlApiAuthThrottle::new()),
        }
    }
}

#[derive(Clone)]
pub(super) struct MetricsServiceCtx {
    pub(super) runtime: ControlPlaneRuntimeCtx,
}

impl MetricsServiceCtx {
    pub(super) fn new(runtime: ControlPlaneRuntimeCtx) -> Self {
        Self { runtime }
    }
}

#[derive(Clone)]
pub(super) struct WatchdogServiceCtx {
    pub(super) runtime: ControlPlaneRuntimeView,
    pub(super) task_registry: Arc<RuntimeTaskRegistry>,
}

impl WatchdogServiceCtx {
    pub(super) fn new(
        runtime: ControlPlaneRuntimeView,
        task_registry: Arc<RuntimeTaskRegistry>,
    ) -> Self {
        Self {
            runtime,
            task_registry,
        }
    }
}

pub(super) struct PreparedListenerStartup {
    pub(super) listener_config: ListenerRuntimeConfig,
    pub(super) shared_state: Arc<SharedRuntimeState>,
    pub(super) socket: UdpSocket,
}

pub(super) struct ControlPlaneStartup<'a> {
    pub(super) runtime_config: &'a RuntimeConfig,
    pub(super) shared_state: &'a SharedRuntimeState,
    pub(super) runtime_bundle: Option<Arc<RuntimeBundleHandle>>,
    pub(super) worker_count: usize,
}

impl<'a> ControlPlaneStartup<'a> {
    pub(super) fn runtime_view(&self) -> ControlPlaneRuntimeView {
        self.runtime_bundle
            .as_ref()
            .map(|handle| handle.with_current_view(ControlPlaneRuntimeView::from_generation))
            .unwrap_or_else(|| {
                ControlPlaneRuntimeView::from_runtime_sources(
                    self.runtime_config,
                    self.shared_state,
                )
            })
    }

    pub(super) fn with_runtime_view<R>(&self, f: impl FnOnce(ControlPlaneRuntimeView) -> R) -> R {
        f(self.runtime_view())
    }

    pub(super) fn runtime_ctx(&self) -> ControlPlaneRuntimeCtx {
        ControlPlaneRuntimeCtx::from_runtime_sources(
            self.runtime_config,
            self.shared_state,
            self.runtime_bundle.clone(),
        )
    }

    pub(super) fn control_api_service_ctx(&self) -> ControlApiServiceCtx {
        ControlApiServiceCtx::new(self.runtime_ctx())
    }

    pub(super) fn metrics_service_ctx(&self) -> MetricsServiceCtx {
        MetricsServiceCtx::new(self.runtime_ctx())
    }
}

pub struct ListenerWorkerRuntimeState {
    pub listener_config: ListenerRuntimeConfig,
    pub shared_state: Arc<SharedRuntimeState>,
    pub runtime_bundle: Arc<RuntimeBundleHandle>,
    pub shutdown: crate::runtime::listener::ShutdownSignal,
}

impl ListenerWorkerRuntimeState {
    pub fn listener_label(&self) -> String {
        crate::quic_listener::QUICListener::listener_label(&self.listener_config)
    }
}

pub(super) fn initialize_listener_from_runtime(
    socket: UdpSocket,
    startup_listener_config: &ListenerRuntimeConfig,
    startup_shared_state: Arc<SharedRuntimeState>,
    runtime_bundle: Option<Arc<RuntimeBundleHandle>>,
    shutdown: crate::runtime::listener::ShutdownSignal,
) -> Result<crate::runtime::listener::QUICListener, ProxyError> {
    let listener_label =
        crate::quic_listener::QUICListener::listener_label(startup_listener_config);
    if let Some(runtime_bundle) = runtime_bundle {
        let listener =
            crate::quic_listener::QUICListener::new_with_socket_and_runtime_bundle_and_shutdown(
                &listener_label,
                socket,
                runtime_bundle,
                shutdown,
            )?;
        return Ok(listener);
    }

    let listener =
        crate::quic_listener::QUICListener::new_with_socket_and_shared_state_and_shutdown(
            startup_listener_config.clone(),
            socket,
            startup_shared_state,
            shutdown,
        )?;
    Ok(listener)
}
