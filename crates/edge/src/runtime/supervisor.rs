use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use impulse_config::{config::Log, runtime::RuntimeConfig};
use impulse_errors::ProxyError;
use log::error;

use crate::runtime::{
    activation::{
        ActivationRequest, ActivationResult, ReloadConfigInput, ReloadPlan, RollbackRequest,
        RollbackResult, RuntimeActivationService,
    },
    bundle::RuntimeBundleHandle,
    listener::Http3Service,
    listener_group::{
        IngressServiceHandles, allocate_worker_index_base, collect_finished_listener_groups,
        log_listener_startup, reconcile_listener_groups, shutdown_listener_groups,
        start_ingress_service_handles,
    },
    shared_state::SharedRuntimeState,
};

struct OperationsServiceHandle {
    runtime: Arc<RuntimeBundleHandle>,
}

pub struct RuntimeServiceHandles {
    operations: OperationsServiceHandle,
    ingress: Vec<IngressServiceHandles>,
    worker_failed: bool,
}

pub struct RuntimeSignalHandle {
    runtime: Arc<RuntimeBundleHandle>,
}

impl RuntimeSignalHandle {
    pub fn request_shutdown(&self) {
        self.runtime.lifecycle().begin_shutdown();
    }
}

impl RuntimeServiceHandles {
    pub fn startup_succeeded(&self) -> bool {
        !self.worker_failed
    }
}

impl OperationsServiceHandle {
    pub fn shutdown(self, task_drain_timeout: Duration) {
        self.runtime.retire_background_tasks(task_drain_timeout);
        self.runtime.lifecycle().finish_shutdown();
    }
}

pub struct RuntimeSupervisor {
    runtime: Arc<RuntimeBundleHandle>,
    shared_state: Arc<SharedRuntimeState>,
}

impl RuntimeSupervisor {
    pub fn start(
        config_path: String,
        log_config: Log,
        runtime_config: &RuntimeConfig,
    ) -> Result<Self, ProxyError> {
        let bundle = Http3Service::build_runtime_bundle(config_path, log_config, runtime_config)?;
        let shared_state = Arc::clone(&bundle.shared_state);
        let runtime = Arc::new(RuntimeBundleHandle::new(bundle));
        Ok(Self {
            runtime,
            shared_state,
        })
    }

    fn start_operations(
        &self,
        runtime_config: &RuntimeConfig,
        worker_count: usize,
    ) -> Result<OperationsServiceHandle, ProxyError> {
        Http3Service::spawn_control_plane_tasks_with_runtime_bundle(
            runtime_config,
            &self.shared_state,
            Arc::clone(&self.runtime),
            worker_count,
        )?;
        Ok(OperationsServiceHandle {
            runtime: Arc::clone(&self.runtime),
        })
    }

    async fn start_ingress_services(
        &self,
        listener_config: impulse_config::runtime::ListenerRuntimeConfig,
        worker_index_base: usize,
    ) -> Result<IngressServiceHandles, String> {
        start_ingress_service_handles(
            listener_config,
            Arc::clone(&self.shared_state),
            Arc::clone(&self.runtime),
            worker_index_base,
        )
        .await
    }

    pub async fn start_services(
        &self,
        runtime_config: &RuntimeConfig,
        worker_count: usize,
        shutdown: &AtomicBool,
    ) -> Result<RuntimeServiceHandles, ProxyError> {
        let operations = self.start_operations(runtime_config, worker_count)?;
        let mut ingress = Vec::new();
        let mut worker_failed = false;

        for listener_config in runtime_config.listener_runtime_configs() {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }

            let listener_worker_count = listener_config.performance.worker_threads.max(1);
            let worker_index_base = allocate_worker_index_base(&ingress, listener_worker_count);
            match self
                .start_ingress_services(listener_config, worker_index_base)
                .await
            {
                Ok(handles) => ingress.push(handles),
                Err(err) => {
                    error!("{}", err);
                    worker_failed = true;
                    break;
                }
            }
        }

        if !shutdown.load(Ordering::Relaxed) && !worker_failed {
            log_listener_startup(runtime_config, &ingress);
        }

        Ok(RuntimeServiceHandles {
            operations,
            ingress,
            worker_failed,
        })
    }

    pub fn signal_handle(&self) -> RuntimeSignalHandle {
        RuntimeSignalHandle {
            runtime: Arc::clone(&self.runtime),
        }
    }

    async fn reconcile_listener_groups(
        &self,
        groups: &mut Vec<IngressServiceHandles>,
        worker_failed: &mut bool,
    ) {
        reconcile_listener_groups(&self.runtime, groups, worker_failed).await;
    }

    pub async fn supervise_services(
        &self,
        services: &mut RuntimeServiceHandles,
        shutdown: &AtomicBool,
    ) {
        while !shutdown.load(Ordering::Relaxed) && !services.worker_failed {
            collect_finished_listener_groups(&mut services.ingress, &mut services.worker_failed)
                .await;
            if services.worker_failed {
                break;
            }

            self.reconcile_listener_groups(&mut services.ingress, &mut services.worker_failed)
                .await;

            if self
                .runtime
                .current_view()
                .shared_services()
                .watchdog
                .restart_requested()
            {
                Self::begin_drain(&self.runtime);
            }

            if !services.worker_failed {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }

    pub async fn shutdown_services(&self, mut services: RuntimeServiceHandles) -> bool {
        Self::begin_shutdown(&self.runtime);
        shutdown_listener_groups(&mut services.ingress, &mut services.worker_failed).await;
        services.operations.shutdown(Duration::from_secs(5));
        services.worker_failed
    }

    pub(crate) fn validate_reload(
        runtime: &RuntimeBundleHandle,
        request: ActivationRequest,
        input: ReloadConfigInput,
    ) -> ReloadPlan {
        RuntimeActivationService::validate_reload(runtime, request, input)
    }

    pub(crate) fn preview_reload(
        runtime: &RuntimeBundleHandle,
        request: ActivationRequest,
        input: ReloadConfigInput,
    ) -> ReloadPlan {
        RuntimeActivationService::preview_reload(runtime, request, input)
    }

    pub(crate) fn activate_reload(
        runtime: &RuntimeBundleHandle,
        request: ActivationRequest,
        input: ReloadConfigInput,
    ) -> ActivationResult {
        RuntimeActivationService::activate_reload(runtime, request, input)
    }

    pub(crate) fn rollback_generation(
        runtime: &RuntimeBundleHandle,
        request: RollbackRequest,
    ) -> RollbackResult {
        RuntimeActivationService::rollback_generation(runtime, request)
    }

    fn begin_drain(runtime: &RuntimeBundleHandle) {
        runtime.lifecycle().begin_drain();
    }

    fn begin_shutdown(runtime: &RuntimeBundleHandle) {
        runtime.lifecycle().begin_shutdown();
    }
}
