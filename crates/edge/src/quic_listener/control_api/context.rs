use std::sync::atomic::AtomicUsize;

use super::{state::ControlApiPaths, *};
use crate::{
    quic_listener::{
        control_api::security::ControlApiSecurityPolicy,
        runtime_state::{ControlApiServiceCtx, ControlPlaneRuntimeView},
    },
    runtime::{
        backend::state::{BackendLifecycleInventorySnapshot, BackendLifecycleInventorySummary},
        bundle::{ActiveRuntimeGeneration, RuntimeBundleHandle},
    },
};

#[derive(Clone)]
pub(super) struct ControlApiServiceState {
    pub(super) runtime: ControlPlaneRuntimeView,
    pub(super) generation: Option<ActiveRuntimeGeneration>,
    runtime_bundle_handle: Option<Arc<RuntimeBundleHandle>>,
    pub(super) endpoint: ControlApiConfig,
    pub(super) security: Arc<ControlApiSecurityPolicy>,
    pub(super) auth_throttle: Arc<super::security::ControlApiAuthThrottle>,
    pub(super) paths: ControlApiPaths,
    pub(super) primary_listener_label: Option<String>,
}

impl ControlApiServiceState {
    pub(super) fn auth_policy_generation(&self) -> (Option<u64>, Option<u64>) {
        let runtime_generation = self
            .generation
            .as_ref()
            .map(|generation| generation.generation());
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
        self.runtime.metrics()
    }

    pub(super) fn watchdog(&self) -> Arc<WatchdogCoordinator> {
        self.runtime.watchdog()
    }

    pub(super) fn resilience(&self) -> Arc<RuntimeResilience> {
        self.runtime.resilience()
    }

    pub(super) fn snapshot_backend_inventory(&self) -> BackendLifecycleInventorySnapshot {
        self.runtime
            .backend_lifecycle()
            .snapshot_inventory(self.runtime.upstream_pools())
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
        ControlApiServiceState {
            primary_listener_label: runtime.primary_listener_label().map(ToOwned::to_owned),
            runtime,
            generation,
            runtime_bundle_handle,
            endpoint,
            security,
            auth_throttle: Arc::clone(&self.auth_throttle),
            paths,
        }
    }
}
