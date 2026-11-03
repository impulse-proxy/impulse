use std::{
    net::{SocketAddr, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, RecvTimeoutError, SyncSender, TrySendError},
    },
    thread,
    time::Duration,
};

use log::{error, warn};

const MAX_DATAGRAM_SIZE_BYTES: usize = 65_535;
const FNV_OFFSET_BASIS_64: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME_64: u64 = 0x0000_0100_0000_01b3;

#[derive(Clone, Debug, Default)]
pub struct ShutdownSignal(Arc<AtomicBool>);

impl ShutdownSignal {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(&self, ordering: Ordering) -> bool {
        self.0.load(ordering)
    }

    pub fn store(&self, value: bool, ordering: Ordering) {
        self.0.store(value, ordering);
    }
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

pub trait PacketWorker: 'static {
    fn process_datagram(&mut self, peer: SocketAddr, local_addr: SocketAddr, packet: &mut [u8]);
    fn poll(&mut self);
    fn poll_idle(&mut self);
    fn drain_with_active_polls(&mut self);
    fn drain_with_idle_polls(&mut self);
}

pub trait PacketWorkerObserver: Send + Sync + 'static {
    fn bind_worker_slot(&self, worker_slot: usize);
    fn record_queue_drop(&self, packet_bytes: usize);
    fn set_queue_bytes(&self, queued_bytes: usize);
}

struct IngressPacket {
    peer: SocketAddr,
    local_addr: SocketAddr,
    bytes: Vec<u8>,
}

struct WorkerThreadRuntime<F, O> {
    worker_idx: usize,
    pin_workers: bool,
    socket: UdpSocket,
    factory: Arc<F>,
    observer: Arc<O>,
    shutdown: ShutdownSignal,
}

struct ShardedWorkerConfig {
    shard_count: usize,
    shard_queue_capacity: usize,
    shard_queue_max_bytes: usize,
}

pub fn spawn_packet_worker_group<F, W, O>(
    config: &ListenerWorkerGroupConfig,
    sockets: Vec<UdpSocket>,
    factory: F,
    observer: Arc<O>,
    shutdown: ShutdownSignal,
) -> Result<Vec<thread::JoinHandle<Result<(), String>>>, String>
where
    F: Fn(UdpSocket) -> Result<W, String> + Send + Sync + 'static,
    W: PacketWorker,
    O: PacketWorkerObserver,
{
    let factory = Arc::new(factory);
    let mut worker_handles = Vec::with_capacity(sockets.len());
    for (socket_idx, socket) in sockets.into_iter().enumerate() {
        let worker_idx = config.worker_index_base.saturating_add(socket_idx);
        let thread_name = format!("impulse-data-plane-{worker_idx}");
        let worker_runtime = WorkerThreadRuntime {
            worker_idx,
            pin_workers: config.pin_workers,
            socket,
            factory: Arc::clone(&factory),
            observer: Arc::clone(&observer),
            shutdown: shutdown.clone(),
        };
        let sharded_config = ShardedWorkerConfig {
            shard_count: config.shard_count,
            shard_queue_capacity: config.shard_queue_capacity,
            shard_queue_max_bytes: config.shard_queue_max_bytes,
        };
        let handle = thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                if sharded_config.shard_count <= 1 {
                    run_single_packet_worker(worker_runtime)
                } else {
                    run_sharded_packet_worker(worker_runtime, sharded_config)
                }
            })
            .map_err(|error| format!("failed to spawn worker {worker_idx}: {error}"))?;
        worker_handles.push(handle);
    }
    Ok(worker_handles)
}

fn run_sharded_packet_worker<F, W, O>(
    runtime: WorkerThreadRuntime<F, O>,
    config: ShardedWorkerConfig,
) -> Result<(), String>
where
    F: Fn(UdpSocket) -> Result<W, String> + Send + Sync + 'static,
    W: PacketWorker,
    O: PacketWorkerObserver,
{
    maybe_pin_worker(runtime.worker_idx, runtime.pin_workers);
    let dispatcher_slot = runtime.worker_idx.saturating_mul(config.shard_count);
    runtime.observer.bind_worker_slot(dispatcher_slot);
    let local_addr = runtime
        .socket
        .local_addr()
        .map_err(|error| format!("worker {} local_addr failed: {error}", runtime.worker_idx))?;

    let mut shard_handles = Vec::with_capacity(config.shard_count);
    let mut shard_senders: Vec<SyncSender<IngressPacket>> = Vec::with_capacity(config.shard_count);
    let mut shard_queue_bytes = Vec::with_capacity(config.shard_count);

    for shard_idx in 0..config.shard_count {
        let shard_socket = runtime.socket.try_clone().map_err(|error| {
            format!(
                "worker {} shard {} socket clone failed: {error}",
                runtime.worker_idx, shard_idx
            )
        })?;
        let factory = Arc::clone(&runtime.factory);
        let observer = Arc::clone(&runtime.observer);
        let shutdown = runtime.shutdown.clone();
        let shard_thread_idx = runtime
            .worker_idx
            .saturating_mul(config.shard_count)
            .saturating_add(shard_idx);
        let queue_bytes = Arc::new(AtomicUsize::new(0));
        shard_queue_bytes.push(Arc::clone(&queue_bytes));
        let (sender, receiver) = mpsc::sync_channel(config.shard_queue_capacity);
        shard_senders.push(sender);
        let worker_idx = runtime.worker_idx;
        let pin_workers = runtime.pin_workers;

        let handle = thread::Builder::new()
            .name(format!("impulse-data-plane-{worker_idx}-shard-{shard_idx}"))
            .spawn(move || -> Result<(), String> {
                maybe_pin_worker(shard_thread_idx, pin_workers);
                observer.bind_worker_slot(shard_thread_idx);
                let mut worker = factory(shard_socket).map_err(|error| {
                    format!("worker {worker_idx} shard {shard_idx} init failed: {error}")
                })?;
                let idle_timeout = Duration::from_millis(10);
                while !shutdown.load(Ordering::Relaxed) {
                    match receiver.recv_timeout(idle_timeout) {
                        Ok(mut packet) => {
                            let packet_bytes = packet.bytes.len();
                            worker.process_datagram(
                                packet.peer,
                                packet.local_addr,
                                &mut packet.bytes,
                            );
                            release_shard_queue_bytes(queue_bytes.as_ref(), packet_bytes);
                        }
                        Err(RecvTimeoutError::Timeout) => worker.poll_idle(),
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
                worker.drain_with_idle_polls();
                Ok(())
            })
            .map_err(|error| {
                format!("failed to spawn worker {worker_idx} shard {shard_idx}: {error}")
            })?;
        shard_handles.push(handle);
    }

    let mut receive_buffer = [0; MAX_DATAGRAM_SIZE_BYTES];
    while !runtime.shutdown.load(Ordering::Relaxed) {
        match runtime.socket.recv_from(&mut receive_buffer) {
            Ok((0, _)) => {}
            Ok((length, peer)) => {
                let shard_idx = shard_index_for_peer(&peer, config.shard_count);
                if !try_reserve_shard_queue_bytes(
                    shard_queue_bytes[shard_idx].as_ref(),
                    length,
                    config.shard_queue_max_bytes,
                ) {
                    runtime.observer.record_queue_drop(length);
                    runtime
                        .observer
                        .set_queue_bytes(total_queue_bytes(&shard_queue_bytes));
                    continue;
                }
                let packet = IngressPacket {
                    peer,
                    local_addr,
                    bytes: receive_buffer[..length].to_vec(),
                };
                match shard_senders[shard_idx].try_send(packet) {
                    Ok(()) => runtime
                        .observer
                        .set_queue_bytes(total_queue_bytes(&shard_queue_bytes)),
                    Err(TrySendError::Full(packet)) => {
                        release_shard_queue_bytes(
                            shard_queue_bytes[shard_idx].as_ref(),
                            packet.bytes.len(),
                        );
                        runtime.observer.record_queue_drop(packet.bytes.len());
                        runtime
                            .observer
                            .set_queue_bytes(total_queue_bytes(&shard_queue_bytes));
                    }
                    Err(TrySendError::Disconnected(packet)) => {
                        release_shard_queue_bytes(
                            shard_queue_bytes[shard_idx].as_ref(),
                            packet.bytes.len(),
                        );
                        return Err(format!(
                            "worker {} shard {} dispatch channel disconnected",
                            runtime.worker_idx, shard_idx
                        ));
                    }
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => {
                return Err(format!(
                    "worker {} ingress recv failed: {error}",
                    runtime.worker_idx
                ));
            }
        }
    }
    drop(shard_senders);

    let mut shard_failed = false;
    for handle in shard_handles {
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                shard_failed = true;
                error!(
                    "Worker {} shard exited with error: {error}",
                    runtime.worker_idx
                );
            }
            Err(_) => {
                shard_failed = true;
                error!("Worker {} shard thread panicked", runtime.worker_idx);
            }
        }
    }
    if shard_failed {
        Err(format!(
            "worker {} had failing shard(s)",
            runtime.worker_idx
        ))
    } else {
        Ok(())
    }
}

fn run_single_packet_worker<F, W, O>(runtime: WorkerThreadRuntime<F, O>) -> Result<(), String>
where
    F: Fn(UdpSocket) -> Result<W, String> + Send + Sync + 'static,
    W: PacketWorker,
    O: PacketWorkerObserver,
{
    maybe_pin_worker(runtime.worker_idx, runtime.pin_workers);
    runtime.observer.bind_worker_slot(runtime.worker_idx);
    let mut worker = (runtime.factory)(runtime.socket)?;
    while !runtime.shutdown.load(Ordering::Relaxed) {
        worker.poll();
    }
    worker.drain_with_active_polls();
    Ok(())
}

fn total_queue_bytes(counters: &[Arc<AtomicUsize>]) -> usize {
    counters
        .iter()
        .map(|counter| counter.load(Ordering::Relaxed))
        .sum()
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

fn stable_hash_socket_addr(address: &SocketAddr) -> u64 {
    match address {
        SocketAddr::V4(address) => {
            let mut bytes = [0; 7];
            bytes[0] = 4;
            bytes[1..5].copy_from_slice(&address.ip().octets());
            bytes[5..7].copy_from_slice(&address.port().to_be_bytes());
            stable_hash64(&bytes)
        }
        SocketAddr::V6(address) => {
            let mut bytes = [0; 31];
            bytes[0] = 6;
            bytes[1..17].copy_from_slice(&address.ip().octets());
            bytes[17..19].copy_from_slice(&address.port().to_be_bytes());
            bytes[19..23].copy_from_slice(&address.flowinfo().to_be_bytes());
            bytes[23..27].copy_from_slice(&address.scope_id().to_be_bytes());
            stable_hash64(&bytes)
        }
    }
}

fn stable_hash64(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS_64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME_64);
    }
    hash
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
