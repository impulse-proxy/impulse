use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use impulse_errors::ProxyError;
use rustls::server::ResolvesServerCert;

use crate::runtime::tls::inventory::ListenerTlsInventory;

#[derive(Clone)]
pub struct ListenerTlsReloadState {
    pub generation: u64,
    pub loaded_at_unix_ms: u64,
    pub last_reload_status: String,
    pub inventory: ListenerTlsInventory,
    pub certificate_resolver: Arc<dyn ResolvesServerCert>,
}

pub struct ListenerTlsReloadStore {
    listeners: RwLock<HashMap<String, ListenerTlsReloadState>>,
}

impl ListenerTlsReloadStore {
    pub fn new(listeners: HashMap<String, ListenerTlsReloadState>) -> Self {
        Self {
            listeners: RwLock::new(listeners),
        }
    }

    pub fn generation(&self, listener: &str) -> Option<u64> {
        self.listeners
            .read()
            .ok()
            .and_then(|listeners| listeners.get(listener).map(|state| state.generation))
    }

    pub fn certificate_resolver(&self, listener: &str) -> Option<Arc<dyn ResolvesServerCert>> {
        self.listeners.read().ok().and_then(|listeners| {
            listeners
                .get(listener)
                .map(|state| Arc::clone(&state.certificate_resolver))
        })
    }

    pub fn inventory(&self, listener: &str) -> Option<ListenerTlsInventory> {
        self.listeners
            .read()
            .ok()
            .and_then(|listeners| listeners.get(listener).map(|state| state.inventory.clone()))
    }

    pub fn replace_listener(
        &self,
        listener: &str,
        inventory: ListenerTlsInventory,
        certificate_resolver: Arc<dyn ResolvesServerCert>,
    ) -> Result<u64, ProxyError> {
        let mut listeners = self.listeners.write().map_err(|_| {
            ProxyError::Transport("listener TLS reload store lock poisoned".to_string())
        })?;
        let state = listeners.get_mut(listener).ok_or_else(|| {
            ProxyError::Transport(format!(
                "listener TLS reload requested for unknown listener '{}'",
                listener
            ))
        })?;
        state.generation = state.generation.saturating_add(1);
        state.loaded_at_unix_ms = crate::watchdog::time::now_millis();
        state.last_reload_status = "cert_reload_applied".to_string();
        state.inventory = inventory;
        state.certificate_resolver = certificate_resolver;
        Ok(state.generation)
    }

    pub fn install_listener(
        &self,
        listener: String,
        mut state: ListenerTlsReloadState,
    ) -> Result<u64, ProxyError> {
        let mut listeners = self.listeners.write().map_err(|_| {
            ProxyError::Transport("listener TLS reload store lock poisoned".to_string())
        })?;
        if let Some(current) = listeners.get(&listener) {
            state.generation = current.generation.saturating_add(1);
        }
        let generation = state.generation;
        listeners.insert(listener, state);
        Ok(generation)
    }

    pub fn replace_listeners(
        &self,
        updates: &[(String, ListenerTlsReloadState)],
    ) -> Result<HashMap<String, u64>, ProxyError> {
        let mut listeners = self.listeners.write().map_err(|_| {
            ProxyError::Transport("listener TLS reload store lock poisoned".to_string())
        })?;

        for (listener, _) in updates {
            if !listeners.contains_key(listener) {
                return Err(ProxyError::Transport(format!(
                    "listener TLS reload requested for unknown listener '{}'",
                    listener
                )));
            }
        }

        let mut generations = HashMap::with_capacity(updates.len());
        for (listener, update) in updates {
            let state = listeners.get_mut(listener).ok_or_else(|| {
                ProxyError::Transport(format!(
                    "listener TLS reload requested for unknown listener '{}'",
                    listener
                ))
            })?;
            state.generation = state.generation.saturating_add(1);
            state.loaded_at_unix_ms = update.loaded_at_unix_ms;
            state.last_reload_status = update.last_reload_status.clone();
            state.inventory = update.inventory.clone();
            state.certificate_resolver = Arc::clone(&update.certificate_resolver);
            generations.insert(listener.clone(), state.generation);
        }
        Ok(generations)
    }

    pub fn snapshot(&self) -> HashMap<String, ListenerTlsInventory> {
        self.listeners
            .read()
            .map(|listeners| {
                listeners
                    .iter()
                    .map(|(listener, state)| (listener.clone(), state.inventory.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn generations(&self) -> HashMap<String, u64> {
        self.listeners
            .read()
            .map(|listeners| {
                listeners
                    .iter()
                    .map(|(listener, state)| (listener.clone(), state.generation))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn snapshot_states(&self) -> HashMap<String, ListenerTlsReloadState> {
        self.listeners
            .read()
            .map(|listeners| {
                listeners
                    .iter()
                    .map(|(listener, state)| (listener.clone(), state.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
}
