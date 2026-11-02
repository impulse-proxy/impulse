use std::sync::Arc;

use impulse_operations::watchdog::{WatchdogCoordinator, WatchdogRuntimeConfig};

use crate::{Metrics, resilience::runtime::RuntimeResilience, runtime::tasks::RuntimeTaskRegistry};

#[derive(Clone)]
pub(crate) struct WatchdogServiceState {
    pub(crate) config: WatchdogRuntimeConfig,
    pub(crate) metrics: Arc<Metrics>,
    pub(crate) resilience: Arc<RuntimeResilience>,
    pub(crate) watchdog: Arc<WatchdogCoordinator>,
}

#[derive(Clone)]
pub(crate) struct WatchdogSpawnState {
    pub(crate) service: WatchdogServiceState,
    pub(crate) task_registry: Arc<RuntimeTaskRegistry>,
}

impl WatchdogServiceState {
    pub(crate) fn is_enabled(&self) -> bool {
        self.config.enabled && self.watchdog.enabled()
    }
}
