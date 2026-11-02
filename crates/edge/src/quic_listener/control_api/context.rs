use std::sync::atomic::AtomicUsize;

use super::{state::ControlApiPaths, *};
use crate::{
    quic_listener::{
        control_api::security::ControlApiSecurityPolicy, runtime_state::ControlApiServiceCtx,
    },
    runtime::{
        backend::state::{BackendLifecycleInventorySnapshot, BackendLifecycleInventorySummary},
        bundle::{ActiveRuntimeGeneration, RuntimeBundleHandle},
        operations::{OperationalObservabilityView, OperationalRuntimeView},
    },
};

#[derive(Clone)]
pub(super) struct ControlApiServiceState {
    pub(super) runtime: OperationalRuntimeView,
    pub(super) observability: OperationalObservabilityView,
    runtime_bundle_handle: Option<Arc<RuntimeBundleHandle>>,
    pub(super) endpoint: ControlApiConfig,
    pub(super) security: Arc<ControlApiSecurityPolicy>,
    pub(super) auth_throttle: Arc<super::security::ControlApiAuthThrottle>,
    pub(super) paths: ControlApiPaths,
    pub(super) primary_listener_label: Option<String>,
}

impl ControlApiServiceState {
    pub(super) fn generation(&self) -> Option<&ActiveRuntimeGeneration> {
        self.runtime.generation()
    }

    pub(super) fn auth_policy_generation(&self) -> (Option<u64>, Option<u64>) {
        let runtime_generation = self.generation().map(|generation| generation.generation());
        let listener_tls_generation = self
            .primary_listener_label
            .as_deref()
            .and_then(|label| self.listener_tls_store().generation(label));
        (runtime_generation, listener_tls_generation)
    }

    pub(super) fn runtime_bundle_handle(&self) -> Option<&Arc<RuntimeBundleHandle>> {
        self.runtime_bundle_handle.as_ref()
    }

    pub(super) fn listener_tls_store(&self) -> Arc<ListenerTlsReloadStore> {
        self.runtime.listener_tls_store()
    }

    pub(super) fn listener_runtime_configs(&self) -> Arc<HashMap<String, ListenerRuntimeConfig>> {
        self.runtime.listener_runtime_configs()
    }

    pub(super) fn metrics(&self) -> Arc<Metrics> {
        self.observability.metrics()
    }

    pub(super) fn watchdog(&self) -> Arc<WatchdogCoordinator> {
        self.observability.watchdog()
    }

    pub(super) fn resilience(&self) -> Arc<RuntimeResilience> {
        self.runtime.resilience()
    }

    pub(super) fn snapshot_backend_inventory(&self) -> BackendLifecycleInventorySnapshot {
        self.observability.backend_inventory()
    }

    pub(super) fn snapshot_backend_health(&self) -> BackendLifecycleInventorySummary {
        self.snapshot_backend_inventory().summary()
    }
}

pub(super) struct ControlApiListenerBinding {
    pub(super) bind: String,
    pub(super) listener: tokio::net::TcpListener,
    pub(super) active_connections: Arc<AtomicUsize>,
}

impl ControlApiServiceCtx {
    pub(super) fn current_service_state(&self) -> ControlApiServiceState {
        let runtime = self.runtime.current_view();
        let generation = self.runtime.current_generation();
        let runtime_bundle_handle = self.runtime.runtime_bundle_handle().cloned();
        let endpoint = runtime.runtime_config().observability.control_api.clone();
        let security = runtime.control_api_security();
        let paths = ControlApiPaths::from_endpoint(&endpoint);
        let backend_inventory = runtime
            .backend_lifecycle()
            .snapshot_inventory(runtime.upstream_pools());
        let runtime_view = OperationalRuntimeView::new(
            runtime.runtime_config().clone(),
            generation,
            runtime.resilience(),
            runtime.listener_runtime_configs(),
            runtime.listener_tls_store(),
            runtime.primary_listener_label().map(ToOwned::to_owned),
            runtime.expected_workers(),
        );
        let observability = OperationalObservabilityView::new(
            runtime.metrics(),
            runtime.watchdog(),
            backend_inventory,
        );
        ControlApiServiceState {
            primary_listener_label: runtime_view.primary_listener_label().map(ToOwned::to_owned),
            runtime: runtime_view,
            observability,
            runtime_bundle_handle,
            endpoint,
            security,
            auth_throttle: Arc::clone(&self.auth_throttle),
            paths,
        }
    }
}
