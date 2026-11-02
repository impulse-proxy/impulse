use std::{sync::Arc, thread};

pub use impulse_http3_ingress::{
    ListenerWorkerGroupConfig, release_shard_queue_bytes, shard_index_for_peer,
    try_reserve_shard_queue_bytes,
};
use impulse_http3_ingress::{PacketWorker, PacketWorkerObserver, spawn_packet_worker_group};

use crate::{
    quic_listener::runtime_state::{ListenerWorkerRuntimeState, initialize_listener_from_runtime},
    runtime::{listener::Http3Service, shared_state::SharedRuntimeState},
};

impl PacketWorker for Http3Service {
    fn process_datagram(
        &mut self,
        peer: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
        packet: &mut [u8],
    ) {
        self.process_datagram(peer, local_addr, packet);
    }

    fn poll(&mut self) {
        self.poll();
    }

    fn poll_idle(&mut self) {
        self.poll_idle();
    }

    fn drain_with_active_polls(&mut self) {
        self.drain_with_active_polls();
    }

    fn drain_with_idle_polls(&mut self) {
        self.drain_with_idle_polls();
    }
}

impl PacketWorkerObserver for SharedRuntimeState {
    fn bind_worker_slot(&self, worker_slot: usize) {
        self.bind_metrics_worker_slot(worker_slot);
    }

    fn record_queue_drop(&self, packet_bytes: usize) {
        self.inc_ingress_queue_drop();
        self.inc_ingress_queue_drop_bytes(packet_bytes);
    }

    fn set_queue_bytes(&self, queued_bytes: usize) {
        self.set_ingress_queue_bytes(queued_bytes);
    }
}

pub fn spawn_listener_worker_group(
    config: &ListenerWorkerGroupConfig,
    runtime: ListenerWorkerRuntimeState,
) -> Result<Vec<thread::JoinHandle<Result<(), String>>>, String> {
    let sockets = if config.worker_count > 1 || runtime.listener_config.performance.reuseport {
        Http3Service::bind_reuseport_sockets(&runtime.listener_config, config.worker_count)
    } else {
        Http3Service::bind_socket(&runtime.listener_config, false).map(|socket| vec![socket])
    }
    .map_err(|error| format!("failed to bind UDP listener sockets: {error}"))?;

    let listener_config = runtime.listener_config;
    let shared_state = runtime.shared_state;
    let runtime_bundle = runtime.runtime_bundle;
    let shutdown = runtime.shutdown;
    let factory_shared_state = Arc::clone(&shared_state);
    let factory_shutdown = shutdown.clone();
    spawn_packet_worker_group(
        config,
        sockets,
        move |socket| {
            initialize_listener_from_runtime(
                socket,
                &listener_config,
                Arc::clone(&factory_shared_state),
                Some(Arc::clone(&runtime_bundle)),
                factory_shutdown.clone(),
            )
            .map_err(|error| error.to_string())
        },
        shared_state,
        shutdown,
    )
}
