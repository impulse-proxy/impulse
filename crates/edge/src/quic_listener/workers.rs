use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, RecvTimeoutError, SyncSender, TrySendError},
    },
    thread,
    time::Duration,
};

use impulse_config::runtime::ListenerRuntimeConfig;
use log::{error, warn};

use crate::{
    constants::MAX_DATAGRAM_SIZE_BYTES,
    quic_listener::runtime_state::{ListenerWorkerRuntimeState, initialize_listener_from_runtime},
    runtime::{
        bundle::RuntimeBundleHandle, listener::QUICListener, shared_state::SharedRuntimeState,
    },
    stable_hash_socket_addr,
};

struct IngressPacket {
    peer: SocketAddr,
    local_addr: SocketAddr,
    bytes: Vec<u8>,
}

struct WorkerThreadRuntime {
    worker_idx: usize,
    pin_workers: bool,
    listener_config: ListenerRuntimeConfig,
    socket: std::net::UdpSocket,
    shared_state: Arc<SharedRuntimeState>,
    runtime_bundle: Arc<RuntimeBundleHandle>,
    shutdown: crate::runtime::listener::ShutdownSignal,
}

struct ShardedWorkerConfig {
    shard_count: usize,
    shard_queue_capacity: usize,
    shard_queue_max_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListenerWorkerGroupConfig {
    pub worker_count: usize,
    pub shard_count: usize,
    pub shard_queue_capacity: usize,
    pub shard_queue_max_bytes: usize,
    pub pin_workers: bool,
    pub worker_index_base: usize,
}

pub fn spawn_listener_worker_group(
    config: &ListenerWorkerGroupConfig,
    runtime: ListenerWorkerRuntimeState,
) -> Result<Vec<thread::JoinHandle<Result<(), String>>>, String> {
    let sockets = if config.worker_count > 1 || runtime.listener_config.performance.reuseport {
        match QUICListener::bind_reuseport_sockets(&runtime.listener_config, config.worker_count) {
            Ok(sockets) => sockets,
            Err(e) => return Err(format!("Failed to bind SO_REUSEPORT sockets: {}", e)),
        }
    } else {
        match QUICListener::bind_socket(&runtime.listener_config, false) {
            Ok(socket) => vec![socket],
            Err(e) => return Err(format!("Failed to bind UDP socket: {}", e)),
        }
    };

    let mut worker_handles = Vec::with_capacity(sockets.len());
    for (socket_idx, socket) in sockets.into_iter().enumerate() {
        let worker_idx = config.worker_index_base.saturating_add(socket_idx);
        let thread_name = format!("impulse-data-plane-{}", worker_idx);
        let worker_runtime = WorkerThreadRuntime {
            worker_idx,
            pin_workers: config.pin_workers,
            listener_config: runtime.listener_config.clone(),
            socket,
            shared_state: Arc::clone(&runtime.shared_state),
            runtime_bundle: Arc::clone(&runtime.runtime_bundle),
            shutdown: runtime.shutdown.clone(),
        };
        let sharded_config = ShardedWorkerConfig {
            shard_count: config.shard_count,
            shard_queue_capacity: config.shard_queue_capacity,
            shard_queue_max_bytes: config.shard_queue_max_bytes,
        };
        let handle =
            thread::Builder::new()
                .name(thread_name)
                .spawn(move || -> Result<(), String> {
                    if sharded_config.shard_count <= 1 {
                        return run_single_listener_worker(worker_runtime);
                    }

                    run_sharded_listener_worker(worker_runtime, sharded_config)
                });

        match handle {
            Ok(handle) => worker_handles.push(handle),
            Err(err) => {
                return Err(format!(
                    "Failed to spawn worker thread {}: {}",
                    worker_idx, err
                ));
            }
        }
    }

    Ok(worker_handles)
}

fn run_sharded_listener_worker(
    worker_runtime: WorkerThreadRuntime,
    sharded_config: ShardedWorkerConfig,
) -> Result<(), String> {
    maybe_pin_worker(worker_runtime.worker_idx, worker_runtime.pin_workers);
    let dispatcher_slot = worker_runtime
        .worker_idx
        .saturating_mul(sharded_config.shard_count);
    worker_runtime
        .shared_state
        .bind_metrics_worker_slot(dispatcher_slot);

    let local_addr = worker_runtime.socket.local_addr().map_err(|err| {
        format!(
            "worker {} local_addr failed: {}",
            worker_runtime.worker_idx, err
        )
    })?;

    let mut shard_handles = Vec::with_capacity(sharded_config.shard_count);
    let mut shard_txs: Vec<SyncSender<IngressPacket>> =
        Vec::with_capacity(sharded_config.shard_count);
    let mut shard_queue_bytes: Vec<Arc<AtomicUsize>> =
        Vec::with_capacity(sharded_config.shard_count);

    for shard_idx in 0..sharded_config.shard_count {
        let shard_socket = worker_runtime.socket.try_clone().map_err(|err| {
            format!(
                "worker {} shard {} socket clone failed: {}",
                worker_runtime.worker_idx, shard_idx, err
            )
        })?;
        let shard_config = worker_runtime.listener_config.clone();
        let shard_shared = Arc::clone(&worker_runtime.shared_state);
        let shard_shutdown = worker_runtime.shutdown.clone();
        let shard_thread_idx = worker_runtime
            .worker_idx
            .saturating_mul(sharded_config.shard_count)
            .saturating_add(shard_idx);
        let shard_queue_bytes_counter = Arc::new(AtomicUsize::new(0));
        shard_queue_bytes.push(Arc::clone(&shard_queue_bytes_counter));

        let (tx, rx) = mpsc::sync_channel::<IngressPacket>(sharded_config.shard_queue_capacity);
        shard_txs.push(tx);
        let shard_runtime_bundle = Arc::clone(&worker_runtime.runtime_bundle);
        let worker_idx = worker_runtime.worker_idx;
        let pin_workers = worker_runtime.pin_workers;

        let shard_name = format!(
            "impulse-data-plane-{}-shard-{}",
            worker_runtime.worker_idx, shard_idx
        );
        let shard_handle = thread::Builder::new()
            .name(shard_name)
            .spawn(move || -> Result<(), String> {
                maybe_pin_worker(shard_thread_idx, pin_workers);
                shard_shared.bind_metrics_worker_slot(shard_thread_idx);
                let mut listener = initialize_listener_from_runtime(
                    shard_socket,
                    &shard_config,
                    shard_shared,
                    Some(Arc::clone(&shard_runtime_bundle)),
                    shard_shutdown.clone(),
                )
                .map_err(|err| {
                    format!(
                        "worker {} shard {} listener init failed: {}",
                        worker_idx, shard_idx, err
                    )
                })?;

                let idle_timeout = Duration::from_millis(10);
                while !shard_shutdown.load(Ordering::Relaxed) {
                    match rx.recv_timeout(idle_timeout) {
                        Ok(mut packet) => {
                            let packet_bytes = packet.bytes.len();
                            listener.process_datagram(
                                packet.peer,
                                packet.local_addr,
                                &mut packet.bytes,
                            );
                            release_shard_queue_bytes(
                                shard_queue_bytes_counter.as_ref(),
                                packet_bytes,
                            );
                        }
                        Err(RecvTimeoutError::Timeout) => {
                            listener.poll_idle();
                        }
                        Err(RecvTimeoutError::Disconnected) => {
                            break;
                        }
                    }
                }

                listener.drain_with_idle_polls();
                Ok(())
            })
            .map_err(|err| {
                format!(
                    "failed to spawn worker {} shard {}: {}",
                    worker_runtime.worker_idx, shard_idx, err
                )
            })?;
        shard_handles.push(shard_handle);
    }

    let mut recv_buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];
    while !worker_runtime.shutdown.load(Ordering::Relaxed) {
        match worker_runtime.socket.recv_from(&mut recv_buf) {
            Ok((len, peer)) => {
                if len == 0 {
                    continue;
                }
                let shard_idx = shard_index_for_peer(&peer, sharded_config.shard_count);
                let packet_len = len;
                if !try_reserve_shard_queue_bytes(
                    shard_queue_bytes[shard_idx].as_ref(),
                    packet_len,
                    sharded_config.shard_queue_max_bytes,
                ) {
                    worker_runtime.shared_state.inc_ingress_queue_drop();
                    worker_runtime
                        .shared_state
                        .inc_ingress_queue_drop_bytes(packet_len);
                    let total: usize = shard_queue_bytes
                        .iter()
                        .map(|c| c.load(Ordering::Relaxed))
                        .sum();
                    worker_runtime.shared_state.set_ingress_queue_bytes(total);
                    continue;
                }
                let packet = IngressPacket {
                    peer,
                    local_addr,
                    bytes: recv_buf[..len].to_vec(),
                };
                match shard_txs[shard_idx].try_send(packet) {
                    Ok(()) => {
                        let total: usize = shard_queue_bytes
                            .iter()
                            .map(|c| c.load(Ordering::Relaxed))
                            .sum();
                        worker_runtime.shared_state.set_ingress_queue_bytes(total);
                    }
                    Err(TrySendError::Full(packet)) => {
                        release_shard_queue_bytes(
                            shard_queue_bytes[shard_idx].as_ref(),
                            packet.bytes.len(),
                        );
                        worker_runtime.shared_state.inc_ingress_queue_drop();
                        worker_runtime
                            .shared_state
                            .inc_ingress_queue_drop_bytes(packet.bytes.len());
                        let total: usize = shard_queue_bytes
                            .iter()
                            .map(|c| c.load(Ordering::Relaxed))
                            .sum();
                        worker_runtime.shared_state.set_ingress_queue_bytes(total);
                    }
                    Err(TrySendError::Disconnected(packet)) => {
                        release_shard_queue_bytes(
                            shard_queue_bytes[shard_idx].as_ref(),
                            packet.bytes.len(),
                        );
                        return Err(format!(
                            "worker {} shard {} dispatch channel disconnected",
                            worker_runtime.worker_idx, shard_idx
                        ));
                    }
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(err) => {
                return Err(format!(
                    "worker {} ingress recv failed: {}",
                    worker_runtime.worker_idx, err
                ));
            }
        }
    }

    drop(shard_txs);

    let mut shard_failed = false;
    for handle in shard_handles {
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                shard_failed = true;
                error!(
                    "Worker {} shard exited with error: {}",
                    worker_runtime.worker_idx, err
                );
            }
            Err(_) => {
                shard_failed = true;
                error!("Worker {} shard thread panicked", worker_runtime.worker_idx);
            }
        }
    }
    if shard_failed {
        Err(format!(
            "worker {} had failing shard(s)",
            worker_runtime.worker_idx
        ))
    } else {
        Ok(())
    }
}

fn run_single_listener_worker(worker_runtime: WorkerThreadRuntime) -> Result<(), String> {
    maybe_pin_worker(worker_runtime.worker_idx, worker_runtime.pin_workers);
    worker_runtime
        .shared_state
        .bind_metrics_worker_slot(worker_runtime.worker_idx);
    let mut listener = initialize_listener_from_runtime(
        worker_runtime.socket,
        &worker_runtime.listener_config,
        worker_runtime.shared_state,
        Some(Arc::clone(&worker_runtime.runtime_bundle)),
        worker_runtime.shutdown.clone(),
    )
    .map_err(|err| {
        format!(
            "worker {} listener init failed: {}",
            worker_runtime.worker_idx, err
        )
    })?;

    while !worker_runtime.shutdown.load(Ordering::Relaxed) {
        listener.poll();
    }

    listener.drain_with_active_polls();
    Ok(())
}

pub fn shard_index_for_peer(peer: &SocketAddr, shard_count: usize) -> usize {
    (stable_hash_socket_addr(peer) as usize) % shard_count.max(1)
}

pub fn try_reserve_shard_queue_bytes(
    counter: &AtomicUsize,
    packet_bytes: usize,
    cap: usize,
) -> bool {
    loop {
        let current = counter.load(Ordering::Relaxed);
        let next = current.saturating_add(packet_bytes);
        if next > cap {
            return false;
        }
        if counter
            .compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return true;
        }
    }
}

pub fn release_shard_queue_bytes(counter: &AtomicUsize, packet_bytes: usize) {
    loop {
        let current = counter.load(Ordering::Relaxed);
        let next = current.saturating_sub(packet_bytes);
        if counter
            .compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
    }
}

fn maybe_pin_worker(worker_idx: usize, pin_workers: bool) {
    if !pin_workers {
        return;
    }

    let Some(core_ids) = core_affinity::get_core_ids() else {
        warn!("Worker pinning requested but core list is unavailable");
        return;
    };

    if core_ids.is_empty() {
        warn!("Worker pinning requested but no cores were reported");
        return;
    }

    let core_id = core_ids[worker_idx % core_ids.len()];
    if !core_affinity::set_for_current(core_id) {
        warn!("Failed to pin worker {} to core {}", worker_idx, core_id.id);
    }
}
