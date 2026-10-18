use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use crate::runtime::backend::{
    lifecycle::RuntimeBackendLifecycleState,
    resolution::RuntimeBackendResolution,
    state::{BackendLifecycleSnapshot, BackendResolutionState},
};

#[derive(Debug, Clone, Default)]
pub struct RuntimeBackendResolutionStore {
    entries: Arc<RwLock<HashMap<String, RuntimeBackendLifecycleState>>>,
}

impl RuntimeBackendResolutionStore {
    pub fn new<I>(entries: I) -> Self
    where
        I: IntoIterator<Item = RuntimeBackendResolution>,
    {
        let entries = entries
            .into_iter()
            .map(|entry| {
                let state = RuntimeBackendLifecycleState::from(&entry);
                (state.identity.backend_addr.clone(), state)
            })
            .collect();
        Self {
            entries: Arc::new(RwLock::new(entries)),
        }
    }

    pub fn backend(&self, backend_addr: &str) -> Option<RuntimeBackendLifecycleState> {
        self.entries
            .read()
            .ok()
            .and_then(|guard| guard.get(backend_addr).cloned())
    }

    pub fn resolution_state(&self, backend_addr: &str) -> Option<BackendResolutionState> {
        self.backend(backend_addr).map(|backend| backend.resolution)
    }

    pub fn snapshot(&self) -> HashMap<String, BackendLifecycleSnapshot> {
        self.entries
            .read()
            .map(|guard| {
                guard
                    .iter()
                    .map(|(backend_addr, state)| (backend_addr.clone(), state.snapshot()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_store_snapshots_backend_resolution_state() {
        let store = RuntimeBackendResolutionStore::new([RuntimeBackendResolution::hostname(
            "https://backend.internal:8443".to_string(),
            "backend.internal".to_string(),
            8443,
        )]);

        let snapshot = store.snapshot();
        let backend = snapshot
            .get("https://backend.internal:8443")
            .expect("backend snapshot");

        assert_eq!(
            backend.identity.backend_addr,
            "https://backend.internal:8443"
        );
        assert!(backend.resolution.is_hostname());
    }
}
