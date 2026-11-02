use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::Instant,
};

pub struct QuicConnection<S> {
    pub quic: quiche::Connection,
    pub h3: Option<quiche::h3::Connection>,
    pub h3_config: Arc<quiche::h3::Config>,
    pub streams: HashMap<u64, S>,
    pub peer_address: SocketAddr,
    pub last_activity: Instant,
    pub primary_scid: Arc<[u8]>,
    pub routing_scids: HashSet<Arc<[u8]>>,
    pub packets_since_rotation: u64,
    pub last_scid_rotation: Instant,
    pub tls_observed: bool,
    pub tls_handshake_failure_recorded: bool,
    pub tls_client_auth_failure_recorded: bool,
    pub last_peer_error_snapshot: Option<QuicConnectionErrorSnapshot>,
    pub last_local_error_snapshot: Option<QuicConnectionErrorSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicConnectionErrorSnapshot {
    pub is_app: bool,
    pub error_code: u64,
    pub reason: Vec<u8>,
}
