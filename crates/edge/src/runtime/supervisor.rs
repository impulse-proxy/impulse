use std::{sync::Arc, time::Duration};

use impulse_config::{config::Log, runtime::RuntimeConfig};
use impulse_errors::ProxyError;

use crate::runtime::{
    activation::{
        ActivationRequest, ActivationResult, ReloadConfigInput, ReloadPlan, RollbackRequest,
        RollbackResult, RuntimeActivationService,
    },
    bundle::RuntimeBundleHandle,
    listener::Http3Service,
    listener_group::{
        IngressServiceHandles, reconcile_listener_groups, start_ingress_service_handles,
    },
    shared_state::SharedRuntimeState,
};

pub struct OperationsServiceHandle {
    runtime: Arc<RuntimeBundleHandle>,
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

    pub fn start_operations(
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

    pub async fn start_ingress_services(
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

    pub fn runtime(&self) -> Arc<RuntimeBundleHandle> {
        Arc::clone(&self.runtime)
    }

    pub async fn reconcile_listener_groups(
        &self,
        groups: &mut Vec<IngressServiceHandles>,
        worker_failed: &mut bool,
    ) {
        reconcile_listener_groups(&self.runtime, groups, worker_failed).await;
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

    pub fn begin_drain(runtime: &RuntimeBundleHandle) {
        runtime.lifecycle().begin_drain();
    }

    pub fn begin_shutdown(runtime: &RuntimeBundleHandle) {
        runtime.lifecycle().begin_shutdown();
    }
}
