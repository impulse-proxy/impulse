use std::sync::Arc;

use impulse_config::runtime::RuntimeConfig;
use impulse_errors::ProxyError;
use log::error;

use super::{
    QUICListener,
    pingora_health::PingoraHealthServiceInput,
    runtime_handle,
    runtime_state::{ControlPlaneStartup, WatchdogServiceCtx},
    spawn_supervised_async_task,
};
use crate::{
    resilience::quota::QuotaRuntime,
    runtime::{
        backend::coordination::spawn_pingora_discovery_refresh, bundle::RuntimeBundleHandle,
        shared_state::SharedRuntimeState,
    },
    watchdog::{
        config::WatchdogRuntimeConfig,
        service::run_watchdog_service,
        state::{WatchdogServiceState, WatchdogSpawnState},
    },
};

impl QUICListener {
    pub fn spawn_control_plane_tasks(
        config: &RuntimeConfig,
        shared_state: &SharedRuntimeState,
        worker_count: usize,
    ) -> Result<(), ProxyError> {
        Self::spawn_control_plane(ControlPlaneStartup {
            runtime_config: config,
            shared_state,
            runtime_bundle: None,
            worker_count,
        })
    }

    pub fn spawn_control_plane_tasks_with_runtime_bundle(
        config: &RuntimeConfig,
        shared_state: &SharedRuntimeState,
        runtime_bundle: Arc<RuntimeBundleHandle>,
        worker_count: usize,
    ) -> Result<(), ProxyError> {
        Self::spawn_control_plane(ControlPlaneStartup {
            runtime_config: config,
            shared_state,
            runtime_bundle: Some(runtime_bundle),
            worker_count,
        })
    }

    fn spawn_control_plane(startup: ControlPlaneStartup<'_>) -> Result<(), ProxyError> {
        startup.with_runtime_view(|runtime| {
            Self::configure_expected_workers(runtime.watchdog().as_ref(), startup.worker_count);
        });
        Self::spawn_generation_background_tasks(&startup);
        Self::spawn_metrics_endpoint(&startup)?;
        Self::spawn_control_api_endpoint(&startup)?;
        Ok(())
    }

    pub(super) fn spawn_generation_background_tasks(startup: &ControlPlaneStartup<'_>) {
        startup.with_runtime_view(|runtime| {
            Self::configure_expected_workers(
                runtime.watchdog().as_ref(),
                runtime.expected_workers(),
            );
            Self::register_jwt_jwks_metrics(&runtime.metrics());
            QuotaRuntime::register_metrics(&runtime.metrics());
            let task_registry = runtime.generation_tasks();
            spawn_pingora_discovery_refresh(
                runtime_handle(),
                runtime.runtime_config(),
                runtime.transport_pool(),
                runtime.backend_dns_resolver(),
                runtime.pingora_load_balancing(),
                runtime.metrics(),
                Arc::clone(&task_registry),
            );
            let pingora_load_balancing = runtime.pingora_load_balancing();
            Self::spawn_jwks_refresh(
                runtime.runtime_config(),
                pingora_load_balancing.generation(),
                Arc::clone(&task_registry),
            );
            Self::spawn_pingora_health_service(PingoraHealthServiceInput {
                generation: pingora_load_balancing.generation(),
                transport_pool: runtime.transport_pool(),
                backend_health_checks: runtime.backend_health_checks(),
                pingora_load_balancing,
                backend_lifecycle: runtime.backend_lifecycle(),
                metrics: runtime.metrics(),
                generation_tasks: Arc::clone(&task_registry),
            });
            Self::spawn_watchdog_service(WatchdogServiceCtx::new(runtime, task_registry));
        });
    }

    pub(crate) fn spawn_generation_background_tasks_for_runtime(
        config: &RuntimeConfig,
        shared_state: &SharedRuntimeState,
    ) {
        Self::spawn_generation_background_tasks(&ControlPlaneStartup {
            runtime_config: config,
            shared_state,
            runtime_bundle: None,
            worker_count: config
                .policies
                .transport
                .worker_threads
                .max(1)
                .saturating_mul(config.policies.transport.packet_shards_per_worker.max(1))
                .max(1),
        });
    }

    fn configure_expected_workers(
        watchdog: &crate::watchdog::coordinator::WatchdogCoordinator,
        worker_count: usize,
    ) {
        watchdog.set_expected_workers(worker_count.max(1));
    }

    fn spawn_watchdog_service(service_ctx: WatchdogServiceCtx) {
        let spawn_state = Self::watchdog_spawn_state(service_ctx);
        if !spawn_state.service.is_enabled() {
            return;
        }

        let handle = match runtime_handle() {
            Some(handle) => handle,
            None => {
                error!("Watchdog disabled: no Tokio runtime available");
                return;
            }
        };

        let registration = spawn_supervised_async_task(
            &handle,
            "watchdog",
            Some(Arc::clone(&spawn_state.service.metrics)),
            run_watchdog_service(spawn_state.service),
        );
        spawn_state.task_registry.register(registration);
    }

    pub(super) fn watchdog_spawn_state(service_ctx: WatchdogServiceCtx) -> WatchdogSpawnState {
        WatchdogSpawnState {
            service: WatchdogServiceState {
                config: WatchdogRuntimeConfig::from(
                    &service_ctx
                        .runtime
                        .runtime_config()
                        .policies
                        .admission
                        .watchdog,
                ),
                metrics: service_ctx.runtime.metrics(),
                resilience: service_ctx.runtime.resilience(),
                watchdog: service_ctx.runtime.watchdog(),
            },
            task_registry: Arc::clone(&service_ctx.task_registry),
        }
    }
}
