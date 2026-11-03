use std::collections::HashMap;

use impulse_config::runtime::{ListenerRuntimeConfig, RuntimeConfig};
use impulse_errors::ProxyError;

use crate::{
    Metrics,
    runtime::tls::{
        inventory::ListenerTlsInventory,
        store::{ListenerTlsReloadState, ListenerTlsReloadStore},
    },
};

pub(crate) fn listener_label(config: &ListenerRuntimeConfig) -> String {
    format!(
        "{}:{}",
        config.listen.listen.address, config.listen.listen.port
    )
}

pub(crate) fn create_listener_tls_store(
    config: &RuntimeConfig,
    resolve: impl Fn(&ListenerRuntimeConfig) -> Result<ListenerTlsReloadState, ProxyError>,
) -> Result<ListenerTlsReloadStore, ProxyError> {
    let mut listeners = HashMap::new();
    for listener_config in config.listener_runtime_configs() {
        let label = listener_label(&listener_config);
        listeners.insert(label, resolve(&listener_config)?);
    }
    Ok(ListenerTlsReloadStore::new(listeners))
}

pub(crate) struct StagedListenerTlsRotation {
    pub(crate) states: Vec<(String, ListenerTlsReloadState)>,
    pub(crate) failures: Vec<(String, ProxyError)>,
}

pub(crate) fn stage_listener_tls_rotation(
    listener_configs: &HashMap<String, ListenerRuntimeConfig>,
    resolve: impl Fn(&ListenerRuntimeConfig) -> Result<ListenerTlsReloadState, ProxyError>,
) -> StagedListenerTlsRotation {
    let mut staged = Vec::with_capacity(listener_configs.len());
    let mut failures = Vec::new();
    for (label, listener_config) in listener_configs {
        match resolve(listener_config) {
            Ok(mut state) => {
                state.last_reload_status = "cert_reload_applied".to_string();
                staged.push((label.clone(), state));
            }
            Err(error) => failures.push((label.clone(), error)),
        }
    }
    StagedListenerTlsRotation {
        states: staged,
        failures,
    }
}

pub(crate) fn rotate_listener_tls_material(
    store: &ListenerTlsReloadStore,
    staged: &[(String, ListenerTlsReloadState)],
) -> Result<HashMap<String, u64>, ProxyError> {
    store.replace_listeners(staged)
}

pub(crate) fn listener_tls_generation_if_changed(
    listener_label: &str,
    current_generation: u64,
    store: &ListenerTlsReloadStore,
) -> Result<Option<u64>, ProxyError> {
    let next_generation = store.generation(listener_label).ok_or_else(|| {
        ProxyError::Transport(format!(
            "missing TLS reload state for listener '{listener_label}'"
        ))
    })?;
    Ok((next_generation != current_generation).then_some(next_generation))
}

pub(crate) fn record_listener_tls_inventory(
    metrics: &Metrics,
    listener_label: &str,
    inventory: &ListenerTlsInventory,
) {
    let mut certificates = Vec::with_capacity(inventory.sni_identities.len() + 1);
    certificates.push((
        "__default__".to_string(),
        inventory.default_identity.metadata.not_after_unix_seconds,
    ));
    certificates.extend(
        inventory
            .sni_identities
            .iter()
            .map(|(server_name, identity)| {
                (
                    server_name.clone(),
                    identity.metadata.not_after_unix_seconds,
                )
            }),
    );
    metrics
        .ingress_observations()
        .replace_downstream_tls_cert_expiry(listener_label, certificates);
}

pub(crate) fn record_listener_tls_store_inventory(
    metrics: &Metrics,
    store: &ListenerTlsReloadStore,
) {
    for (label, inventory) in store.snapshot() {
        record_listener_tls_inventory(metrics, &label, &inventory);
    }
}
