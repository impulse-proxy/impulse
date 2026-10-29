//! Protocol listener adapters owned by the runtime host.

pub use crate::{
    pingora_ingress::{PingoraListenerTask, spawn_pingora_ingress_listener},
    quic_listener::{
        ListenerWorkerGroupConfig, ListenerWorkerRuntimeState, configure_async_runtime,
        release_shard_queue_bytes, shard_index_for_peer, spawn_listener_worker_group,
        try_reserve_shard_queue_bytes,
    },
};
