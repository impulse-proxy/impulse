use super::{identity::AdminRole, security::ControlApiSecurityPolicy};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlApiRoute {
    Health,
    Ready,
    Runtime,
    RuntimeValidate,
    RuntimePreview,
    RuntimeActivate,
    RuntimeRollback,
    RuntimeHistory,
    RuntimeHistoryGeneration(u64),
    ReloadCerts,
    ReloadRuntime,
    Restart,
}

impl ControlApiRoute {
    pub fn minimum_role(self, security: &ControlApiSecurityPolicy) -> Option<AdminRole> {
        match self {
            Self::Health => security
                .authorization
                .protect_health
                .then_some(AdminRole::from(security.authorization.runtime_read_role)),
            Self::Ready => security
                .authorization
                .protect_ready
                .then_some(AdminRole::from(security.authorization.runtime_read_role)),
            Self::Runtime | Self::RuntimeHistory | Self::RuntimeHistoryGeneration(_) => {
                Some(AdminRole::from(security.authorization.runtime_read_role))
            }
            Self::RuntimeValidate
            | Self::RuntimePreview
            | Self::RuntimeActivate
            | Self::RuntimeRollback
            | Self::ReloadCerts
            | Self::ReloadRuntime => {
                Some(AdminRole::from(security.authorization.runtime_mutate_role))
            }
            Self::Restart => Some(AdminRole::from(security.authorization.restart_role)),
        }
    }
}
