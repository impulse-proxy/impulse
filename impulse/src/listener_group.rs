use std::{
    collections::HashMap,
    sync::{Arc, atomic::Ordering},
    thread,
    time::{Duration, Instant},
};

use impulse_config::runtime::{ListenerRuntimeConfig, RuntimeConfig};
use impulse_edge::runtime::{
    bundle::RuntimeBundleHandle,
    ingress::{
        ListenerWorkerGroupConfig, ListenerWorkerRuntimeState, PingoraListenerTask,
        spawn_listener_worker_group, spawn_pingora_ingress_listener,
    },
    listener::ShutdownSignal,
    shared_state::SharedRuntimeState,
};
use log::{error, info};

use crate::runtime_guard;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ListenerGroupSignature {
    pub(crate) label: String,
    listener_index: usize,
    pub(crate) worker_count: usize,
    shard_count: usize,
    shard_queue_capacity: usize,
    shard_queue_max_bytes: usize,
    pin_workers: bool,
    reuseport: bool,
    udp_recv_buffer_bytes: usize,
    udp_send_buffer_bytes: usize,
    client_auth_enabled: bool,
    require_client_cert: bool,
    client_auth_ca_file: Option<String>,
}

pub(crate) struct ListenerGroupRuntime {
    pub(crate) signature: ListenerGroupSignature,
    pub(crate) shutdown: ShutdownSignal,
    worker_handles: Vec<thread::JoinHandle<Result<(), String>>>,
    pingora_listener: PingoraListenerTask,
    worker_index_base: usize,
    failed_activation_generation: Option<u64>,
    drain_timeout: Duration,
    drain_deadline: Option<Instant>,
}

impl ListenerGroupRuntime {
    pub(crate) fn request_shutdown(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.pingora_listener.request_shutdown();
        self.drain_deadline
            .get_or_insert_with(|| Instant::now() + self.drain_timeout);
    }

    pub(crate) async fn collect_finished(&mut self, worker_failed: &mut bool) {
        let mut idx = 0usize;
        while idx < self.worker_handles.len() {
            if !self.worker_handles[idx].is_finished() {
                idx += 1;
                continue;
            }

            let handle = self.worker_handles.swap_remove(idx);
            join_worker_handle(handle, worker_failed);
        }
        if let Some(result) = self.pingora_listener.collect_finished().await {
            if let Err(err) = result {
                *worker_failed = true;
                error!("{}", err);
            } else if !self.shutdown.load(Ordering::Relaxed) {
                *worker_failed = true;
                error!(
                    "Pingora listener {} exited before listener-group shutdown",
                    self.signature.label
                );
            }
        }
        if self
            .drain_deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
            && !self.pingora_listener.stopped()
        {
            let active = self.pingora_listener.force_drain();
            log::warn!(
                "Pingora listener {} exceeded its drain deadline with {} active request(s)",
                self.signature.label,
                active
            );
        }
    }

    pub(crate) fn retired(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
            && self.worker_handles.is_empty()
            && self.pingora_listener.stopped()
    }

    pub(crate) async fn join_all(mut self, worker_failed: &mut bool) {
        for handle in self.worker_handles.drain(..) {
            join_worker_handle(handle, worker_failed);
        }
        let remaining = self
            .drain_deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
            .unwrap_or(self.drain_timeout);
        match self.pingora_listener.drain(remaining).await {
            Ok(0) => {}
            Ok(active) => log::warn!(
                "Pingora listener {} reached its drain deadline with {} active request(s)",
                self.signature.label,
                active
            ),
            Err(err) => {
                *worker_failed = true;
                error!("{}", err);
            }
        }
    }
}

pub(crate) async fn shutdown_listener_groups(
    listener_groups: &mut Vec<ListenerGroupRuntime>,
    worker_failed: &mut bool,
) {
    for group in listener_groups.iter_mut() {
        group.request_shutdown();
    }

    loop {
        collect_finished_listener_groups(listener_groups, worker_failed).await;
        if listener_groups.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    for group in listener_groups.drain(..) {
        group.join_all(worker_failed).await;
    }
}

pub(crate) fn listener_label(config: &ListenerRuntimeConfig) -> String {
    format!(
        "{}:{}",
        config.listen.listen.address, config.listen.listen.port
    )
}

pub(crate) fn listener_group_signature(config: &ListenerRuntimeConfig) -> ListenerGroupSignature {
    ListenerGroupSignature {
        label: listener_label(config),
        listener_index: config.listen.index,
        worker_count: config.performance.worker_threads.max(1),
        shard_count: config.performance.packet_shards_per_worker.max(1),
        shard_queue_capacity: config.performance.packet_shard_queue_capacity.max(1),
        shard_queue_max_bytes: config.performance.packet_shard_queue_max_bytes.max(1),
        pin_workers: config.performance.pin_workers,
        reuseport: config.performance.reuseport,
        udp_recv_buffer_bytes: config.performance.udp_recv_buffer_bytes,
        udp_send_buffer_bytes: config.performance.udp_send_buffer_bytes,
        client_auth_enabled: config.listen.tls.client_auth.enabled,
        require_client_cert: config.listen.tls.client_auth.require_client_cert,
        client_auth_ca_file: config.listen.tls.client_auth.ca_file.clone(),
    }
}

pub(crate) async fn spawn_managed_listener_group(
    listener_config: ListenerRuntimeConfig,
    worker_shared: Arc<SharedRuntimeState>,
    runtime_bundle: Arc<RuntimeBundleHandle>,
    worker_index_base: usize,
) -> Result<ListenerGroupRuntime, String> {
    let signature = listener_group_signature(&listener_config);
    let shutdown = ShutdownSignal::new();
    let drain_timeout = listener_config.policies.timeouts.shutdown_drain;

    let mut pingora_listener =
        spawn_pingora_ingress_listener(Arc::clone(&runtime_bundle), listener_config.clone())?;
    pingora_listener.wait_until_ready().await?;

    let worker_handles = spawn_listener_worker_group(
        &ListenerWorkerGroupConfig {
            worker_count: signature.worker_count,
            shard_count: signature.shard_count,
            shard_queue_capacity: signature.shard_queue_capacity,
            shard_queue_max_bytes: signature.shard_queue_max_bytes,
            pin_workers: signature.pin_workers,
            worker_index_base,
        },
        ListenerWorkerRuntimeState {
            listener_config: listener_config.clone(),
            shared_state: worker_shared,
            runtime_bundle,
            shutdown: shutdown.clone(),
        },
    )?;

    Ok(ListenerGroupRuntime {
        signature,
        shutdown,
        worker_handles,
        pingora_listener,
        worker_index_base,
        failed_activation_generation: None,
        drain_timeout,
        drain_deadline: None,
    })
}

/// First-fit allocation of a worker-index range of `worker_count` slots that
/// does not overlap any live group's range. Ranges freed when groups retire are
/// reused, so indices stay bounded across reloads instead of growing without
/// limit (which would push worker/metrics slots past the metrics capacity).
pub(crate) fn allocate_worker_index_base(
    groups: &[ListenerGroupRuntime],
    worker_count: usize,
) -> usize {
    let mut ranges: Vec<(usize, usize)> = groups
        .iter()
        .map(|g| {
            (
                g.worker_index_base,
                g.worker_index_base.saturating_add(g.signature.worker_count),
            )
        })
        .collect();
    ranges.sort_unstable();

    let mut base = 0usize;
    for (start, end) in ranges {
        if base.saturating_add(worker_count) <= start {
            return base; // fits in the gap before this range
        }
        base = base.max(end);
    }
    base
}

pub(crate) async fn reconcile_listener_groups(
    runtime_bundle: &Arc<RuntimeBundleHandle>,
    groups: &mut Vec<ListenerGroupRuntime>,
    worker_failed: &mut bool,
) {
    let runtime = runtime_bundle.current();
    let desired_configs = runtime.runtime_config.listener_runtime_configs();
    let desired_signatures = desired_configs
        .iter()
        .map(|config| (listener_label(config), listener_group_signature(config)))
        .collect::<HashMap<_, _>>();

    for listener_config in &desired_configs {
        let signature = listener_group_signature(listener_config);
        let Some(group_index) = groups.iter().position(|group| {
            group.signature.label == signature.label
                && !group.shutdown.load(Ordering::Relaxed)
                && group.signature != signature
                && group.failed_activation_generation != Some(runtime.generation)
        }) else {
            continue;
        };

        if !cfg!(unix) || !groups[group_index].signature.reuseport || !signature.reuseport {
            error!(
                "Cannot replace listener group {} in place for activated runtime generation {} because safe same-bind handoff requires reuseport on both listener generations",
                signature.label, runtime.generation
            );
            groups[group_index].failed_activation_generation = Some(runtime.generation);
            continue;
        }

        let worker_index_base = groups[group_index].worker_index_base;
        info!(
            "Staging replacement listener group {} for activated runtime generation {}",
            signature.label, runtime.generation
        );

        match spawn_managed_listener_group(
            listener_config.clone(),
            Arc::clone(&runtime.shared_state),
            Arc::clone(runtime_bundle),
            worker_index_base,
        )
        .await
        {
            Ok(group) => {
                groups[group_index].request_shutdown();
                groups.push(group);
                info!(
                    "Activated replacement listener group {}; draining the previous group",
                    signature.label
                );
            }
            Err(err) => {
                error!(
                    "Failed to stage replacement listener group {}: {}; keeping the active listener",
                    signature.label, err
                );
                groups[group_index].failed_activation_generation = Some(runtime.generation);
            }
        }
    }

    for listener_config in &desired_configs {
        let signature = listener_group_signature(listener_config);
        let active_match = groups.iter().any(|group| {
            group.signature.label == signature.label && !group.shutdown.load(Ordering::Relaxed)
        });
        let failed_replacement = groups.iter().any(|group| {
            group.signature.listener_index == signature.listener_index
                && group.failed_activation_generation == Some(runtime.generation)
        });
        if active_match || failed_replacement {
            continue;
        }

        let worker_index_base = allocate_worker_index_base(groups, signature.worker_count);
        match spawn_managed_listener_group(
            listener_config.clone(),
            Arc::clone(&runtime.shared_state),
            Arc::clone(runtime_bundle),
            worker_index_base,
        )
        .await
        {
            Ok(group) => {
                info!("Spawned listener group {}", group.signature.label);
                groups.push(group);
            }
            Err(err) => {
                error!("{}", err);
                if let Some(previous) = groups.iter_mut().find(|group| {
                    group.signature.listener_index == signature.listener_index
                        && !group.shutdown.load(Ordering::Relaxed)
                }) {
                    previous.failed_activation_generation = Some(runtime.generation);
                } else {
                    *worker_failed = true;
                }
            }
        }
    }

    let ready_listener_indices = groups
        .iter()
        .filter(|group| {
            desired_signatures.contains_key(&group.signature.label)
                && !group.shutdown.load(Ordering::Relaxed)
        })
        .map(|group| group.signature.listener_index)
        .collect::<Vec<_>>();
    for group in groups.iter_mut() {
        if desired_signatures.contains_key(&group.signature.label)
            || group.shutdown.load(Ordering::Relaxed)
        {
            continue;
        }
        let replaced = ready_listener_indices.contains(&group.signature.listener_index);
        let removed = !desired_configs
            .iter()
            .any(|config| config.listen.index == group.signature.listener_index);
        if replaced || removed {
            if removed {
                info!(
                    "Retiring listener group {} because it is no longer configured",
                    group.signature.label
                );
            } else {
                info!(
                    "Retiring listener group {} after activated listener replacement",
                    group.signature.label
                );
            }
            group.request_shutdown();
        }
    }
}

pub(crate) async fn collect_finished_listener_groups(
    groups: &mut Vec<ListenerGroupRuntime>,
    worker_failed: &mut bool,
) {
    let mut idx = 0usize;
    while idx < groups.len() {
        groups[idx].collect_finished(worker_failed).await;
        if groups[idx].retired() {
            info!("Retired listener group {}", groups[idx].signature.label);
            groups.swap_remove(idx);
            continue;
        }
        idx += 1;
    }
}

fn join_worker_handle(handle: thread::JoinHandle<Result<(), String>>, worker_failed: &mut bool) {
    match handle.join() {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            *worker_failed = true;
            error!("Worker exited with error: {}", err);
        }
        Err(payload) => {
            *worker_failed = true;
            error!(
                "Worker thread panicked: {}",
                runtime_guard::panic_payload_message(payload.as_ref())
            );
        }
    }
}

pub(crate) fn log_listener_startup(
    runtime_config: &RuntimeConfig,
    listener_groups: &[ListenerGroupRuntime],
) {
    let shard_count = runtime_config.performance.packet_shards_per_worker.max(1);
    info!("Impulse startup phase=begin");
    info!(
        "Impulse listener topology listeners={} packet_shards_per_worker={} reuseport={} pin_workers={}",
        runtime_config.listeners.len(),
        shard_count,
        runtime_config.performance.reuseport,
        runtime_config.performance.pin_workers
    );
    for listener in &runtime_config.listeners {
        info!(
            "Listener {} binds udp={}:{} tcp_pingora={}:{}",
            listener.index,
            listener.listen.address,
            listener.listen.port,
            listener.listen.address,
            listener.listen.port,
        );
        info!(
            "Listener {} protocols downstream_quic=true pingora_http1=true pingora_http2=true http3_stability=experimental alt_svc_upgrade=true",
            listener.index,
        );
    }
    info!(
        "Impulse data-plane workers={} packet_shards_per_worker={} reuseport={} pin_workers={}",
        listener_groups
            .iter()
            .map(group_signature_worker_count)
            .sum::<usize>(),
        shard_count,
        runtime_config.performance.reuseport,
        runtime_config.performance.pin_workers
    );
}

fn group_signature_worker_count(group: &ListenerGroupRuntime) -> usize {
    group.signature.worker_count
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::atomic::AtomicUsize};

    use impulse_edge::runtime::ingress::{
        release_shard_queue_bytes, shard_index_for_peer, try_reserve_shard_queue_bytes,
    };

    #[test]
    fn shard_index_is_stable_for_same_peer() {
        let peer: SocketAddr = "127.0.0.1:12345".parse().expect("peer addr");
        let a = shard_index_for_peer(&peer, 8);
        let b = shard_index_for_peer(&peer, 8);
        assert_eq!(a, b);
    }

    #[test]
    fn shard_index_is_within_bounds() {
        let peer: SocketAddr = "10.1.2.3:443".parse().expect("peer addr");
        let idx = shard_index_for_peer(&peer, 16);
        assert!(idx < 16);
    }

    #[test]
    fn shard_queue_byte_reservation_obeys_cap() {
        let counter = AtomicUsize::new(0);
        assert!(try_reserve_shard_queue_bytes(&counter, 10, 16));
        assert!(!try_reserve_shard_queue_bytes(&counter, 7, 16));
        assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 10);
    }

    #[test]
    fn shard_queue_byte_release_is_saturating() {
        let counter = AtomicUsize::new(8);
        release_shard_queue_bytes(&counter, 3);
        assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 5);
        release_shard_queue_bytes(&counter, 10);
        assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 0);
    }
}
