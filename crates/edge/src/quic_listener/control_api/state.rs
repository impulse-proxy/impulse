use super::*;
use crate::quic_listener::runtime_state::ControlApiServiceCtx;

#[derive(Clone)]
pub(super) struct ControlApiPaths {
    pub(super) health_path: String,
    pub(super) ready_path: String,
    pub(super) runtime_path: String,
    pub(super) restart_path: String,
    pub(super) reload_path: String,
    pub(super) reload_certs_path: String,
}

impl ControlApiPaths {
    pub(super) fn from_endpoint(endpoint: &ControlApiConfig) -> Self {
        Self {
            health_path: endpoint.health_path.clone(),
            ready_path: endpoint.ready_path.clone(),
            runtime_path: endpoint.runtime_path.clone(),
            restart_path: endpoint.restart_path.clone(),
            reload_path: endpoint.reload_path.clone(),
            reload_certs_path: endpoint.reload_certs_path.clone(),
        }
    }

    pub(super) fn runtime_validate_path(&self) -> String {
        format!("{}/validate", self.runtime_path)
    }

    pub(super) fn runtime_preview_path(&self) -> String {
        format!("{}/preview", self.runtime_path)
    }

    pub(super) fn runtime_activate_path(&self) -> String {
        format!("{}/activate", self.runtime_path)
    }

    pub(super) fn runtime_rollback_path(&self) -> String {
        format!("{}/rollback", self.runtime_path)
    }

    pub(super) fn runtime_history_path(&self) -> String {
        format!("{}/history", self.runtime_path)
    }

    pub(super) fn runtime_history_entry_prefix(&self) -> String {
        format!("{}/", self.runtime_history_path())
    }
}

pub(super) type ControlApiState = ControlApiServiceCtx;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ControlApiAuthorizationGeneration {
    pub(super) runtime: Option<u64>,
    pub(super) listener_tls: Option<u64>,
}

impl ControlApiAuthorizationGeneration {
    pub(super) fn is_current(&self, current: (Option<u64>, Option<u64>)) -> bool {
        self.runtime == current.0 && self.listener_tls == current.1
    }
}

impl ControlApiServiceCtx {
    #[cfg(test)]
    pub(super) fn current_generation(
        &self,
    ) -> Option<crate::runtime::bundle::ActiveRuntimeGeneration> {
        self.current_service_state().runtime.generation().cloned()
    }

    #[cfg(test)]
    pub(super) fn current_control_api(&self) -> ControlApiConfig {
        self.current_service_state().endpoint
    }

    #[cfg(test)]
    pub(super) fn current_paths(&self) -> ControlApiPaths {
        self.current_service_state().paths
    }

    #[cfg(test)]
    pub(super) fn current_security_policy(
        &self,
    ) -> Arc<crate::quic_listener::control_api::security::ControlApiSecurityPolicy> {
        self.current_service_state().security
    }

    #[cfg(test)]
    pub(super) fn current_primary_listener_label(&self) -> Option<String> {
        self.current_service_state().primary_listener_label
    }
}
