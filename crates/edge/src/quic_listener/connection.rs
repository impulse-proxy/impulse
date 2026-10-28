use super::*;

fn is_benign_quic_close(err: &quiche::ConnectionError) -> bool {
    !err.is_app && err.error_code == 0 && err.reason.is_empty()
}

fn log_quic_connection_error(
    source: &str,
    peer: SocketAddr,
    trace_id: &str,
    err: &quiche::ConnectionError,
) {
    if is_benign_quic_close(err) {
        debug!(
            "QUIC {} close without error: peer={} trace_id={} is_app={} error_code={} reason_len={}",
            source,
            peer,
            trace_id,
            err.is_app,
            err.error_code,
            err.reason.len()
        );
        return;
    }

    if err.reason.is_empty() {
        error!(
            "QUIC {} error: peer={} trace_id={} is_app={} error_code={}",
            source, peer, trace_id, err.is_app, err.error_code
        );
    } else {
        error!(
            "QUIC {} error: peer={} trace_id={} is_app={} error_code={} reason={}",
            source,
            peer,
            trace_id,
            err.is_app,
            err.error_code,
            String::from_utf8_lossy(&err.reason)
        );
    }
}

pub(super) fn maybe_log_quic_connection_error(
    source: &str,
    peer: SocketAddr,
    trace_id: &str,
    err: &quiche::ConnectionError,
    last_logged: &mut Option<QuicConnectionErrorSnapshot>,
) {
    let snapshot = QuicConnectionErrorSnapshot {
        is_app: err.is_app,
        error_code: err.error_code,
        reason: err.reason.clone(),
    };

    if last_logged.as_ref() == Some(&snapshot) {
        return;
    }

    *last_logged = Some(snapshot);
    log_quic_connection_error(source, peer, trace_id, err);
}

impl QUICListener {
    pub(super) fn clear_connection_registry(&mut self) {
        self.connections.clear();
        self.cid_routes.clear();
        self.peer_routes.clear();
        self.cid_radix.clear();
        self.refresh_active_connection_metric();
    }

    pub(super) fn acquire_connection_for_packet(
        &mut self,
        peer: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
        packet_type: quiche::Type,
        dcid: &[u8],
        has_token: bool,
    ) -> Option<(crate::runtime::connection::quic::QuicConnection, Arc<[u8]>)> {
        debug!("Looking up connection with DCID: {:?}", hex::encode(dcid));

        if let Some(connection) = self.take_registered_connection(dcid, peer) {
            debug!("Found existing connection for {}", peer);
            return Some(connection);
        }

        if let Some(primary) = self.take_connection_by_alias(dcid, peer) {
            return Some(primary);
        }

        if let Some(primary) = self.take_connection_by_peer(peer) {
            return Some(primary);
        }

        let created =
            self.take_or_create_connection(peer, local_addr, packet_type, dcid, has_token);
        if created.is_some() {
            debug!("Created new connection for {}", peer);
        } else {
            debug!(
                "Dropping packet for unknown connection from {} (DCID: {:?})",
                peer,
                hex::encode(dcid)
            );
        }
        created
    }

    pub(super) fn discard_connection(
        &mut self,
        connection: &crate::runtime::connection::quic::QuicConnection,
    ) {
        self.remove_connection_routes(connection);
        self.refresh_active_connection_metric();
    }

    pub(super) fn store_connection(
        &mut self,
        previous_primary: &Arc<[u8]>,
        mut connection: crate::runtime::connection::quic::QuicConnection,
    ) {
        let new_primary = self.sync_connection_routes(&mut connection);
        debug!(
            "Storing connection with key: {:02x?} (previous: {:02x?})",
            new_primary, previous_primary
        );
        self.peer_routes
            .insert(connection.peer_address, Arc::clone(&new_primary));
        self.connections.insert(new_primary, connection);
        self.refresh_active_connection_metric();
    }

    pub(super) fn take_or_create_connection(
        &mut self,
        peer: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
        packet_type: quiche::Type,
        dcid: &[u8],
        has_token: bool,
    ) -> Option<(crate::runtime::connection::quic::QuicConnection, Arc<[u8]>)> {
        debug!(
            "Packet DCID (len={}): {:02x?}, type: {:?}, active connections: {}",
            dcid.len(),
            dcid,
            packet_type,
            self.connections.len()
        );

        if self.draining {
            self.metrics
                .ingress_observations()
                .inc_ingress_draining_drop();
            return None;
        }

        if packet_type != quiche::Type::Initial {
            debug!("Non-Initial packet for unknown connection, ignoring");
            self.metrics.ingress_observations().inc_ingress_unroutable();
            return None;
        }

        if has_token {
            debug!("Received 0-RTT attempt, will negotiate fresh connection");
        }

        if !self.conn_rate_limiter.try_consume() {
            debug!(
                "New connection rate limit exceeded, dropping Initial packet from {}",
                peer
            );
            self.metrics
                .ingress_observations()
                .inc_ingress_rate_limited();
            return None;
        }

        if !self.source_conn_rate_limiter.try_consume(peer.ip()) {
            debug!(
                "Per-source new connection rate limit exceeded, dropping Initial packet from {}",
                peer
            );
            self.metrics
                .ingress_observations()
                .inc_ingress_rate_limited();
            return None;
        }

        if self.connections.len() >= self.max_active_connections {
            self.metrics
                .ingress_observations()
                .inc_connection_cap_reject();
            self.metrics
                .policy_observations()
                .inc_overload_shed_reason(OverloadShedReason::ConnectionCap);
            debug!(
                "Active connection cap reached (cap={}, active={}), dropping Initial packet from {}",
                self.max_active_connections,
                self.connections.len(),
                peer
            );
            return None;
        }

        if let Err(err) = self.sync_runtime_bundle_if_needed() {
            error!(
                "Failed to reload QUIC TLS configuration for listener {}: {}",
                self.listener_label, err
            );
            self.metrics
                .ingress_observations()
                .inc_ingress_connection_create_failed();
            return None;
        }

        let mut scid_bytes = [0u8; DEFAULT_SCID_LEN_BYTES];
        rand::thread_rng().fill_bytes(&mut scid_bytes);

        let scid = quiche::ConnectionId::from_ref(&scid_bytes);

        let quic_connection =
            match quiche::accept(&scid, None, local_addr, peer, &mut self.quic_config) {
                Ok(conn) => conn,
                Err(e) => {
                    error!("quiche::accept failed: {:?}", e);
                    self.metrics
                        .ingress_observations()
                        .inc_ingress_connection_create_failed();
                    return None;
                }
            };

        let connection = crate::runtime::connection::quic::QuicConnection {
            quic: quic_connection,
            h3: None,
            h3_config: self.h3_config.clone(),
            streams: HashMap::new(),
            peer_address: peer,
            last_activity: Instant::now(),
            primary_scid: Arc::from(&scid_bytes[..]),
            routing_scids: HashSet::from([Arc::from(&scid_bytes[..])]),
            packets_since_rotation: 0,
            last_scid_rotation: Instant::now(),
            tls_observed: false,
            tls_handshake_failure_recorded: false,
            tls_client_auth_failure_recorded: false,
            last_peer_error_snapshot: None,
            last_local_error_snapshot: None,
        };

        debug!(
            "Creating new connection with server SCID: {:02x?}",
            scid_bytes
        );
        Some((connection, Arc::from(&scid_bytes[..])))
    }

    fn take_registered_connection(
        &mut self,
        dcid: &[u8],
        peer: std::net::SocketAddr,
    ) -> Option<(crate::runtime::connection::quic::QuicConnection, Arc<[u8]>)> {
        let mut connection = self.connections.remove(dcid)?;
        debug!("Found existing connection for DCID: {:02x?}", dcid);
        let primary = Arc::clone(&connection.primary_scid);
        self.peer_routes.remove(&connection.peer_address);
        connection.peer_address = peer;
        Some((connection, primary))
    }

    fn take_connection_by_alias(
        &mut self,
        dcid: &[u8],
        peer: std::net::SocketAddr,
    ) -> Option<(crate::runtime::connection::quic::QuicConnection, Arc<[u8]>)> {
        if dcid.len() <= MIN_SCID_LEN_BYTES {
            return None;
        }

        let primary = if let Some(primary) = self.cid_routes.get(dcid).cloned() {
            Some(primary)
        } else {
            resolve_primary_from_radix_prefix(
                dcid,
                &self.connections,
                &mut self.cid_routes,
                &mut self.cid_radix,
            )
        }?;

        debug!(
            "Found connection via SCID alias/prefix {} -> {}",
            hex::encode(dcid),
            hex::encode(&primary)
        );
        if let Some(mut connection) = self.connections.remove(&primary) {
            self.peer_routes.remove(&connection.peer_address);
            connection.peer_address = peer;
            return Some((connection, primary));
        }

        self.cid_routes.remove(dcid);
        None
    }

    fn take_connection_by_peer(
        &mut self,
        peer: std::net::SocketAddr,
    ) -> Option<(crate::runtime::connection::quic::QuicConnection, Arc<[u8]>)> {
        let primary = self.peer_routes.get(&peer).cloned()?;
        if let Some(mut connection) = self.connections.remove(&primary) {
            self.peer_routes.remove(&connection.peer_address);
            connection.peer_address = peer;
            debug!(
                "Found existing connection via peer map {} -> {}",
                peer,
                hex::encode(&primary)
            );
            return Some((connection, primary));
        }

        self.peer_routes.remove(&peer);
        None
    }

    pub(super) fn remove_connection_routes(
        &mut self,
        connection: &crate::runtime::connection::quic::QuicConnection,
    ) {
        purge_connection_routes(
            &mut self.cid_routes,
            &mut self.cid_radix,
            &mut self.peer_routes,
            &connection.primary_scid,
            &connection.routing_scids,
            &connection.peer_address,
        );
    }

    pub(super) fn sync_connection_routes(
        &mut self,
        connection: &mut crate::runtime::connection::quic::QuicConnection,
    ) -> Arc<[u8]> {
        let mut active_scids: HashSet<Arc<[u8]>> = connection
            .quic
            .source_ids()
            .map(|cid| Arc::from(cid.as_ref()))
            .collect();

        if active_scids.is_empty() {
            active_scids.insert(Arc::clone(&connection.primary_scid));
        }

        let active_source_id: Arc<[u8]> = Arc::from(connection.quic.source_id().as_ref());
        let primary = if active_scids.contains(&active_source_id) {
            active_source_id
        } else if active_scids.contains(&connection.primary_scid) {
            Arc::clone(&connection.primary_scid)
        } else {
            active_scids
                .iter()
                .min_by(|left, right| left.as_ref().cmp(right.as_ref()))
                .cloned()
                .unwrap_or_else(|| Arc::clone(&connection.primary_scid))
        };

        let retired_scids: Vec<Arc<[u8]>> = connection
            .routing_scids
            .difference(&active_scids)
            .cloned()
            .collect();

        for cid in &active_scids {
            self.cid_radix.insert(Arc::clone(cid));
        }

        for cid in &connection.routing_scids {
            self.cid_routes.remove(cid.as_ref());
        }

        for cid in &active_scids {
            if *cid == primary {
                continue;
            }
            self.cid_routes
                .insert(Arc::clone(cid), Arc::clone(&primary));
        }

        for retired in retired_scids {
            self.cid_radix.remove(retired.as_ref());
        }

        connection.routing_scids = active_scids;
        connection.primary_scid = Arc::clone(&primary);
        primary
    }

    pub(super) fn refresh_active_connection_metric(&self) {
        self.metrics
            .ingress_observations()
            .set_active_connections(self.connections.len());
    }
}

pub(super) fn resolve_primary_from_radix_prefix<T>(
    dcid: &[u8],
    connections: &HashMap<Arc<[u8]>, T>,
    cid_routes: &mut HashMap<Arc<[u8]>, Arc<[u8]>>,
    cid_radix: &mut CidRadix,
) -> Option<Arc<[u8]>> {
    let matched_cid = cid_radix.longest_prefix_match(dcid)?;

    if connections.contains_key(matched_cid.as_ref()) {
        return Some(matched_cid);
    }

    if let Some(primary) = cid_routes.get(matched_cid.as_ref()).cloned() {
        if connections.contains_key(primary.as_ref()) {
            return Some(primary);
        }
        cid_routes.remove(matched_cid.as_ref());
    }

    cid_radix.remove(matched_cid.as_ref());
    None
}

pub(crate) fn purge_connection_routes(
    cid_routes: &mut HashMap<Arc<[u8]>, Arc<[u8]>>,
    cid_radix: &mut CidRadix,
    peer_routes: &mut HashMap<std::net::SocketAddr, Arc<[u8]>>,
    primary_scid: &Arc<[u8]>,
    routing_scids: &std::collections::HashSet<Arc<[u8]>>,
    peer_address: &std::net::SocketAddr,
) {
    cid_radix.remove(primary_scid.as_ref());
    cid_routes.remove(primary_scid.as_ref());
    for cid in routing_scids {
        cid_radix.remove(cid.as_ref());
        cid_routes.remove(cid.as_ref());
    }
    peer_routes.remove(peer_address);
}

pub(crate) struct ConnectionRoutes {
    pub primary_scid: Arc<[u8]>,
    pub routing_scids: std::collections::HashSet<Arc<[u8]>>,
    pub peer_address: std::net::SocketAddr,
}

impl From<&crate::runtime::connection::quic::QuicConnection> for ConnectionRoutes {
    fn from(c: &crate::runtime::connection::quic::QuicConnection) -> Self {
        Self {
            primary_scid: Arc::clone(&c.primary_scid),
            routing_scids: c.routing_scids.clone(),
            peer_address: c.peer_address,
        }
    }
}

pub(crate) fn sweep_closed_connections<C, F>(
    connections: &mut HashMap<Arc<[u8]>, C>,
    cid_routes: &mut HashMap<Arc<[u8]>, Arc<[u8]>>,
    cid_radix: &mut CidRadix,
    peer_routes: &mut HashMap<std::net::SocketAddr, Arc<[u8]>>,
    to_remove: Vec<Arc<[u8]>>,
    routes_of: F,
) where
    F: Fn(&C) -> ConnectionRoutes,
{
    for scid in to_remove {
        if let Some(connection) = connections.remove(&scid) {
            let routes = routes_of(&connection);
            purge_connection_routes(
                cid_routes,
                cid_radix,
                peer_routes,
                &routes.primary_scid,
                &routes.routing_scids,
                &routes.peer_address,
            );
        }
    }
}
