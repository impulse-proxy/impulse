use std::{sync::Arc, time::Duration};

use impulse_config::{config::Log, runtime::RuntimeConfig};
use impulse_errors::ProxyError;

use crate::{
    quic_listener::QUICListener,
    runtime::{
        activation::{
            ActivationRequest, ActivationResult, ReloadConfigInput, ReloadPlan, RollbackRequest,
            RollbackResult, RuntimeActivationService,
        },
        bundle::RuntimeBundleHandle,
        shared_state::SharedRuntimeState,
    },
};

pub struct RuntimeSupervisor {
    runtime: Arc<RuntimeBundleHandle>,
    shared_state: Arc<SharedRuntimeState>,
}

impl RuntimeSupervisor {
    pub fn start(
        config_path: String,
        log_config: Log,
        runtime_config: &RuntimeConfig,
        worker_count: usize,
    ) -> Result<Self, ProxyError> {
        let bundle = QUICListener::build_runtime_bundle(config_path, log_config, runtime_config)?;
        let shared_state = Arc::clone(&bundle.shared_state);
        let runtime = Arc::new(RuntimeBundleHandle::new(bundle));
        QUICListener::spawn_control_plane_tasks_with_runtime_bundle(
            runtime_config,
            &shared_state,
            Arc::clone(&runtime),
            worker_count,
        )?;
        Ok(Self {
            runtime,
            shared_state,
        })
    }

    pub fn runtime(&self) -> Arc<RuntimeBundleHandle> {
        Arc::clone(&self.runtime)
    }

    pub fn shared_state(&self) -> Arc<SharedRuntimeState> {
        Arc::clone(&self.shared_state)
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

    pub fn complete_shutdown(runtime: &RuntimeBundleHandle, task_drain_timeout: Duration) {
        runtime.retire_background_tasks(task_drain_timeout);
        runtime.lifecycle().finish_shutdown();
    }
}
