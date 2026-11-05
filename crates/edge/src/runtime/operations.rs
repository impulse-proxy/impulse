use std::{collections::HashMap, sync::Arc};

use impulse_config::runtime::{ListenerRuntimeConfig, RuntimeConfig};
use impulse_operations::watchdog::WatchdogCoordinator;
use impulse_plugins::CompiledGenerationPluginPlans;

use crate::{
    Metrics,
    resilience::runtime::RuntimeResilience,
    runtime::{
        backend::state::BackendLifecycleInventorySnapshot, bundle::ActiveRuntimeGeneration,
        tls::store::ListenerTlsReloadStore,
    },
};

#[derive(Clone)]
pub(crate) struct OperationalRuntimeView {
    runtime_config: RuntimeConfig,
    generation: Option<ActiveRuntimeGeneration>,
    resilience: Arc<RuntimeResilience>,
    plugin_plans: Arc<CompiledGenerationPluginPlans>,
    listener_runtime_configs: Arc<HashMap<String, ListenerRuntimeConfig>>,
    listener_tls_store: Arc<ListenerTlsReloadStore>,
    primary_listener_label: Option<String>,
    expected_workers: usize,
}

pub(crate) struct OperationalRuntimeViewInput {
    pub(crate) runtime_config: RuntimeConfig,
    pub(crate) generation: Option<ActiveRuntimeGeneration>,
    pub(crate) resilience: Arc<RuntimeResilience>,
    pub(crate) plugin_plans: Arc<CompiledGenerationPluginPlans>,
    pub(crate) listener_runtime_configs: Arc<HashMap<String, ListenerRuntimeConfig>>,
    pub(crate) listener_tls_store: Arc<ListenerTlsReloadStore>,
    pub(crate) primary_listener_label: Option<String>,
    pub(crate) expected_workers: usize,
}

impl OperationalRuntimeView {
    pub(crate) fn new(input: OperationalRuntimeViewInput) -> Self {
        let OperationalRuntimeViewInput {
            runtime_config,
            generation,
            resilience,
            plugin_plans,
            listener_runtime_configs,
            listener_tls_store,
            primary_listener_label,
            expected_workers,
        } = input;
        Self {
            runtime_config,
            generation,
            resilience,
            plugin_plans,
            listener_runtime_configs,
            listener_tls_store,
            primary_listener_label,
            expected_workers,
        }
    }

    pub(crate) fn runtime_config(&self) -> &RuntimeConfig {
        &self.runtime_config
    }

    pub(crate) fn generation(&self) -> Option<&ActiveRuntimeGeneration> {
        self.generation.as_ref()
    }

    pub(crate) fn resilience(&self) -> Arc<RuntimeResilience> {
        Arc::clone(&self.resilience)
    }

    pub(crate) fn plugin_plans(&self) -> Arc<CompiledGenerationPluginPlans> {
        Arc::clone(&self.plugin_plans)
    }

    pub(crate) fn listener_runtime_configs(&self) -> Arc<HashMap<String, ListenerRuntimeConfig>> {
        Arc::clone(&self.listener_runtime_configs)
    }

    pub(crate) fn listener_tls_store(&self) -> Arc<ListenerTlsReloadStore> {
        Arc::clone(&self.listener_tls_store)
    }

    pub(crate) fn primary_listener_label(&self) -> Option<&str> {
        self.primary_listener_label.as_deref()
    }

    pub(crate) fn expected_workers(&self) -> usize {
        self.expected_workers
    }
}

#[derive(Clone)]
pub(crate) struct OperationalObservabilityView {
    metrics: Arc<Metrics>,
    watchdog: Arc<WatchdogCoordinator>,
    backend_inventory: BackendLifecycleInventorySnapshot,
}

impl OperationalObservabilityView {
    pub(crate) fn new(
        metrics: Arc<Metrics>,
        watchdog: Arc<WatchdogCoordinator>,
        backend_inventory: BackendLifecycleInventorySnapshot,
    ) -> Self {
        Self {
            metrics,
            watchdog,
            backend_inventory,
        }
    }

    pub(crate) fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.metrics)
    }

    pub(crate) fn watchdog(&self) -> Arc<WatchdogCoordinator> {
        Arc::clone(&self.watchdog)
    }

    pub(crate) fn backend_inventory(&self) -> BackendLifecycleInventorySnapshot {
        self.backend_inventory.clone()
    }
}
