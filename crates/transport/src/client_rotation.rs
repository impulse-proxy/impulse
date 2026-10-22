#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackendClientRotationState {
    MissingBackend,
    Recreated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BackendClientRotation {
    state: BackendClientRotationState,
}

impl BackendClientRotation {
    pub(crate) fn missing_backend() -> Self {
        Self {
            state: BackendClientRotationState::MissingBackend,
        }
    }

    pub(crate) fn recreated() -> Self {
        Self {
            state: BackendClientRotationState::Recreated,
        }
    }

    pub(crate) fn changed(self) -> bool {
        matches!(self.state, BackendClientRotationState::Recreated)
    }
}
