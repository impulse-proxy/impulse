//! Internal listener subsystem façade.
//!
//! This module owns startup, worker orchestration, request ingress, and
//! control-plane wiring for the QUIC and bootstrap listeners. The crate root
//! re-exports the narrow worker/runtime entrypoints that external callers should
//! depend on.

use core::net::SocketAddr;
use std::{
    collections::{HashMap, HashSet},
    net::UdpSocket,
    sync::{Arc, RwLock, atomic::Ordering},
    time::{Duration, Instant},
};

use boring::{
    pkey::{PKey, Private},
    ssl::{NameType, SelectCertError, SslContextBuilder, SslMethod, SslVerifyMode},
    x509::X509,
};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, combinators::BoxBody};
use hyper::{body::Incoming, upgrade};
use hyper_util::rt::TokioIo;
#[cfg(test)]
use impulse_bridge::response::should_strip_response_header;
use impulse_bridge::response::{
    ResponseBodyMode, ResponseBodyPolicy, ResponseNormalizationInput,
    ResponseNormalizationProtocol, ResponseProtocolConstraints, normalize_response_trailers,
    normalize_upstream_response,
};
use impulse_config::{
    backend_endpoint::{BackendEndpoint, BackendScheme},
    config::ClientAuth,
    runtime::{
        ListenerRuntimeConfig, RuntimeConfig, RuntimeListenerTls, RuntimeTlsIdentity,
        RuntimeUpstreamPolicy,
    },
};
use impulse_errors::{PoolError, ProxyError};
use impulse_lb::{health::HealthFailureReason, upstream_pool::UpstreamPool};
use impulse_transport::{SharedDnsResolver, UpstreamTransportPool};
use log::{debug, error, info, warn};
use quiche::{Config, h3::NameValue};
use rand::RngCore;
use rustls::{
    RootCertStore, ServerConfig as RustlsServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ClientHello, ResolvesServerCert, ResolvesServerCertUsingSni, WebPkiClientVerifier},
    sign::CertifiedKey,
};
use rustls_pki_types::pem::PemObject;
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Semaphore, mpsc, mpsc::error::TrySendError, oneshot},
};
#[cfg(test)]
use tokio_rustls::TlsAcceptor;
use tracing::{Instrument, info_span};

#[cfg(test)]
use crate::runtime::bundle::RuntimeBundleHandle;
use crate::{
    ChannelBody, Metrics, OverloadShedReason, REQUEST_ID_COUNTER, RouteOutcome,
    cid_radix::CidRadix,
    constants::{
        DEFAULT_SCID_LEN_BYTES, MAX_DATAGRAM_SIZE_BYTES, MAX_UDP_PAYLOAD_BYTES, MIN_SCID_LEN_BYTES,
        REQUEST_CHUNK_BYTES_LIMIT, REQUEST_CHUNK_CHANNEL_CAPACITY, RESET_TOKEN_LEN_BYTES,
        RESPONSE_CHUNK_BYTES_LIMIT, RESPONSE_CHUNK_CHANNEL_CAPACITY,
        SCID_ROTATION_PACKET_THRESHOLD, scid_rotation_interval,
    },
    resilience::runtime::RuntimeResilience,
    routing::{decision::RouteDecisionReason, index::RouteIndex},
    runtime::{
        bundle::RuntimeBundle,
        connection::{
            quic::{QuicConnection, QuicConnectionErrorSnapshot},
            request::RequestEnvelope,
            response::{ForwardResult, ForwardSuccess, ResponseChunk, UpstreamResult},
            stream::{CancellationReason, TerminalReason, TunnelMode},
        },
        health::{HealthClassification, outcome_from_status},
        listener::QUICListener,
        tasks::RuntimeTaskRegistry,
        tls::{
            inventory::{
                ListenerTlsInventory, RuntimeLoadedClientAuthCa, RuntimeLoadedTlsIdentity,
                RuntimeTlsCertificateMetadata,
            },
            store::{ListenerTlsReloadState, ListenerTlsReloadStore},
        },
    },
    watchdog::coordinator::WatchdogCoordinator,
};

mod admission;
mod async_runtime;
mod backend_resolution;
mod bootstrap;
mod bootstrap_tls;
mod connection;
mod control_api;
mod control_plane;
mod forwarding;
mod health_check;
mod metrics;
mod protocol;
mod runtime_endpoint;
mod runtime_state;
mod shutdown;
mod startup;
mod tls_runtime;
mod token_bucket;
mod validation;
mod workers;

pub use async_runtime::configure_async_runtime;
pub(in crate::quic_listener) use async_runtime::{
    runtime_handle, spawn_async_task, spawn_supervised_async_task,
};
#[cfg(test)]
use bootstrap::BootstrapStartupState;
use connection::maybe_log_quic_connection_error;
#[cfg(test)]
pub(crate) use connection::purge_connection_routes;
#[cfg(test)]
use connection::resolve_primary_from_radix_prefix;
pub(crate) use connection::{ConnectionRoutes, sweep_closed_connections};
use forwarding::{
    ForwardingExecutionCtx, ForwardingSharedCtx, H3RequestHandlingConfig, StreamProgressConfig,
};
#[cfg(test)]
use health_check::classify_active_health_check_response;
pub(in crate::quic_listener) use protocol::{
    can_poll_upstream_result, collect_h3_trailers, is_connect_method, is_tunnel_response,
};
#[cfg(test)]
pub(in crate::quic_listener) use protocol::{
    connection_header_tokens, is_bodyless_request_mode, is_connect_tunnel_response,
    should_strip_bootstrap_request_header, should_strip_bootstrap_response_header,
    should_strip_h3_response_header,
};
pub use runtime_state::ListenerWorkerRuntimeState;
pub(crate) use token_bucket::{PerSourceTokenBucket, TokenBucket};
use validation::{
    RequestBufferError, extract_header_value, generated_span_id, generated_trace_id,
    parse_traceparent, validate_request_headers,
};
pub use workers::{
    ListenerWorkerGroupConfig, release_shard_queue_bytes, shard_index_for_peer,
    spawn_listener_worker_group, try_reserve_shard_queue_bytes,
};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

struct ListenerRuntimeSettings {
    backend_timeout: Duration,
    backend_body_idle_timeout: Duration,
    backend_body_total_timeout: Duration,
    client_body_idle_timeout: Duration,
    backend_total_request_timeout: Duration,
    inflight_acquire_wait: Duration,
    drain_timeout: Duration,
    max_active_connections: usize,
    max_streams_per_connection: usize,
    max_request_body_bytes: usize,
    max_response_body_bytes: usize,
    request_buffer_global_cap_bytes: usize,
    unknown_length_response_prebuffer_bytes: usize,
    new_connections_per_sec: u32,
    new_connections_burst: u32,
}

type LbHeaderLookup<'a> = crate::request_pipeline::RequestHeaderLookup<'a>;

impl QUICListener {
    fn random_reset_token() -> u128 {
        let mut token = [0u8; RESET_TOKEN_LEN_BYTES];
        rand::thread_rng().fill_bytes(&mut token);
        u128::from_be_bytes(token)
    }

    fn maybe_rotate_scid(connection: &mut QuicConnection, metrics: &Metrics) {
        if !connection.quic.is_established() {
            return;
        }

        let now = Instant::now();
        let elapsed = now.saturating_duration_since(connection.last_scid_rotation);
        if connection.packets_since_rotation < SCID_ROTATION_PACKET_THRESHOLD
            && elapsed < scid_rotation_interval()
        {
            return;
        }

        if connection.quic.scids_left() == 0 {
            return;
        }

        let cid_len = connection
            .quic
            .source_id()
            .as_ref()
            .len()
            .max(MIN_SCID_LEN_BYTES);
        let mut cid_bytes = vec![0u8; cid_len];
        rand::thread_rng().fill_bytes(&mut cid_bytes);

        let new_scid = quiche::ConnectionId::from_ref(&cid_bytes);
        let reset_token = Self::random_reset_token();

        match connection.quic.new_scid(&new_scid, reset_token, true) {
            Ok(seq) => {
                connection.last_scid_rotation = now;
                connection.packets_since_rotation = 0;
                metrics.inc_scid_rotation();
                debug!(
                    "Issued new SCID seq={} cid={}",
                    seq,
                    hex::encode(&cid_bytes)
                );
            }
            Err(e) => {
                debug!("SCID rotation skipped: {:?}", e);
            }
        }
    }

    pub fn poll(&mut self) {
        if !self.poll_preamble() {
            return;
        }

        // Read a UDP datagram and feed it into quiche.
        let (len, peer) = match self.socket.recv_from(self.recv_buf.as_mut_slice()) {
            Ok(v) => v,
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                self.handle_timeouts();
                return;
            }
            Err(_) => return,
        };

        debug!("Received UDP datagram ({} bytes)", len);
        let local_addr = self.local_addr;
        let packet_ptr = self.recv_buf.as_mut_ptr();
        // SAFETY: `packet_ptr` points into `self.recv_buf` and remains valid for this call.
        // We do not access `self.recv_buf` again until `process_datagram_inner` returns.
        let packet = unsafe { std::slice::from_raw_parts_mut(packet_ptr, len) };
        self.process_datagram_inner(peer, local_addr, packet);
    }

    pub fn poll_idle(&mut self) {
        if !self.poll_preamble() {
            return;
        }
        self.handle_timeouts();
    }

    pub fn process_datagram(
        &mut self,
        peer: SocketAddr,
        local_addr: SocketAddr,
        packet: &mut [u8],
    ) {
        if !self.poll_preamble() {
            return;
        }
        self.process_datagram_inner(peer, local_addr, packet);
    }

    fn process_datagram_inner(
        &mut self,
        peer: SocketAddr,
        local_addr: SocketAddr,
        packet: &mut [u8],
    ) {
        self.metrics.inc_ingress_packet();

        let header = match quiche::Header::from_slice(packet, quiche::MAX_CONN_ID_LEN) {
            Ok(hdr) => hdr,
            Err(_) => {
                error!("Failed to parse QUIC packet header");
                self.metrics.inc_ingress_bad_header();
                return;
            }
        };
        let packet_type = header.ty;
        let header_has_token = header.token.is_some();
        let dcid = header.dcid.as_ref();

        if packet_type == quiche::Type::VersionNegotiation {
            let len = match quiche::negotiate_version(
                &header.scid,
                &header.dcid,
                self.send_buf.as_mut_slice(),
            ) {
                Ok(len) => len,
                Err(e) => {
                    error!("Version negotiation failed: {:?}", e);
                    self.metrics.inc_ingress_version_neg_failed();
                    return;
                }
            };

            if let Err(e) = self.socket.send_to(&self.send_buf[..len], peer) {
                error!("Failed to send version negotiation: {:?}", e);
            }
            return;
        }

        // First, try to find existing connection by DCID
        let Some((mut connection, current_primary)) = self.acquire_connection_for_packet(
            peer,
            local_addr,
            packet_type,
            dcid,
            header_has_token,
        ) else {
            return;
        };

        let recv_info = quiche::RecvInfo {
            from: peer,
            to: local_addr,
        };

        if let Err(e) = connection.quic.recv(packet, recv_info) {
            error!("QUIC recv failed: {:?}", e);
            Self::release_connection_streams(&mut connection, &self.metrics);
            self.discard_connection(&connection);
            return;
        }

        if let Some(err) = connection.quic.peer_error() {
            maybe_log_quic_connection_error(
                "peer",
                connection.peer_address,
                connection.quic.trace_id(),
                err,
                &mut connection.last_peer_error_snapshot,
            );
        }

        if let Some(err) = connection.quic.local_error() {
            maybe_log_quic_connection_error(
                "local",
                connection.peer_address,
                connection.quic.trace_id(),
                err,
                &mut connection.last_local_error_snapshot,
            );
        }

        connection.last_activity = Instant::now();
        connection.packets_since_rotation = connection.packets_since_rotation.saturating_add(1);

        // Debug logs
        debug!(
            "QUIC connection state - established: {}, in_early_data: {}, closed: {}",
            connection.quic.is_established(),
            connection.quic.is_in_early_data(),
            connection.quic.is_closed()
        );

        self.maybe_record_quic_tls_observation(&mut connection);
        self.maybe_record_quic_tls_handshake_failure(&mut connection);

        if self.require_client_cert
            && connection.quic.is_established()
            && connection.quic.peer_cert().is_none()
        {
            if !connection.tls_client_auth_failure_recorded {
                self.metrics.record_downstream_tls_handshake_failure(
                    &Self::listener_label(&self.config),
                    "missing_client_cert",
                );
                connection.tls_client_auth_failure_recorded = true;
            }
            warn!(
                "closing connection {}: downstream mTLS requires a client certificate",
                connection.quic.trace_id()
            );
            let _ = connection
                .quic
                .close(true, 0x01A0, b"client certificate required");
        }

        let shared_ctx = ForwardingSharedCtx {
            runtime_generation: self.runtime_generation,
            metrics: Arc::clone(&self.metrics),
            resilience: &self.resilience,
            routing_index: &self.routing_index,
            upstream_pools: &self.upstream_pools,
            upstream_policies: self.upstream_policies.as_ref(),
        };
        let exec_ctx = ForwardingExecutionCtx {
            transport_pool: Arc::clone(&self.transport_pool),
            backend_endpoints: Arc::clone(&self.backend_endpoints),
            upstream_inflight: &self.upstream_inflight,
            global_inflight: Arc::clone(&self.global_inflight),
            inflight_acquire_wait: self.inflight_acquire_wait,
        };
        let progress_config = StreamProgressConfig {
            backend_body_idle_timeout: self.backend_body_idle_timeout,
            backend_body_total_timeout: self.backend_body_total_timeout,
            max_response_body_bytes: self.max_response_body_bytes,
            unknown_length_response_prebuffer_bytes: self.unknown_length_response_prebuffer_bytes,
            client_body_idle_timeout: self.client_body_idle_timeout,
            listen_port: self.config.listen.listen.port,
        };
        let request_config = H3RequestHandlingConfig::new(
            self.config.observability.routing.enabled,
            self.config.observability.routing.include_reason,
            self.backend_total_request_timeout,
            self.max_request_body_bytes,
            self.request_buffer_global_cap_bytes,
            self.config.observability.tracing.enabled,
            self.max_streams_per_connection,
        );

        if !connection.quic.is_closed()
            && (connection.quic.is_established() || connection.quic.is_in_early_data())
            && let Err(e) = Self::handle_h3(
                &mut connection,
                &shared_ctx,
                &exec_ctx,
                &progress_config,
                &request_config,
            )
        {
            error!("HTTP/3 handling failed: {:?}", e);
            let _ = connection
                .quic
                .close(true, 0x1, b"http3 protocol handling error");
        }

        let mut send_buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];

        if !connection.quic.is_closed() {
            Self::advance_connection_streams(
                &self.socket,
                &mut connection,
                &mut send_buf,
                &shared_ctx,
                &exec_ctx,
                &progress_config,
                "packet path",
            );
        }

        Self::maybe_rotate_scid(&mut connection, &self.metrics);

        Self::flush_send(&self.socket, &mut send_buf, &mut connection);
        Self::handle_timeout(&self.socket, &mut send_buf, &mut connection);

        if !connection.quic.is_closed() {
            self.store_connection(&current_primary, connection);
        } else {
            Self::release_connection_streams(&mut connection, &self.metrics);
            self.discard_connection(&connection);
            debug!("Connection closed, not storing");
        }
    }

    fn handle_timeouts(&mut self) {
        if self.connections.is_empty() {
            return;
        }

        let mut send_buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];
        let mut to_remove = Vec::new();
        let shared_ctx = ForwardingSharedCtx {
            runtime_generation: self.runtime_generation,
            metrics: Arc::clone(&self.metrics),
            resilience: &self.resilience,
            routing_index: &self.routing_index,
            upstream_pools: &self.upstream_pools,
            upstream_policies: self.upstream_policies.as_ref(),
        };
        let exec_ctx = ForwardingExecutionCtx {
            transport_pool: Arc::clone(&self.transport_pool),
            backend_endpoints: Arc::clone(&self.backend_endpoints),
            upstream_inflight: &self.upstream_inflight,
            global_inflight: Arc::clone(&self.global_inflight),
            inflight_acquire_wait: self.inflight_acquire_wait,
        };
        let progress_config = StreamProgressConfig {
            backend_body_idle_timeout: self.backend_body_idle_timeout,
            backend_body_total_timeout: self.backend_body_total_timeout,
            max_response_body_bytes: self.max_response_body_bytes,
            unknown_length_response_prebuffer_bytes: self.unknown_length_response_prebuffer_bytes,
            client_body_idle_timeout: self.client_body_idle_timeout,
            listen_port: self.config.listen.listen.port,
        };

        for (scid, connection) in self.connections.iter_mut() {
            let timeout = match connection.quic.timeout() {
                Some(timeout) => timeout,
                None => {
                    if connection.quic.is_closed() {
                        Self::release_connection_streams(connection, &self.metrics);
                        to_remove.push(scid.clone());
                    }
                    continue;
                }
            };

            if connection.last_activity.elapsed() >= timeout {
                connection.quic.on_timeout();
                // Do NOT reset last_activity here: only real packet I/O
                // resets it.  Resetting on timeout would prevent quiche
                // from receiving on_timeout() again during the drain
                // period, causing draining connections to linger.
                Self::flush_send(&self.socket, &mut send_buf, connection);
            }

            if connection.quic.is_closed() {
                Self::release_connection_streams(connection, &self.metrics);
                to_remove.push(scid.clone());
                continue;
            }

            // Advance in-flight streams independent of inbound packets.
            Self::advance_connection_streams(
                &self.socket,
                connection,
                &mut send_buf,
                &shared_ctx,
                &exec_ctx,
                &progress_config,
                "timeout path",
            );
        }

        sweep_closed_connections(
            &mut self.connections,
            &mut self.cid_routes,
            &mut self.cid_radix,
            &mut self.peer_routes,
            to_remove,
            |c| ConnectionRoutes::from(c),
        );
        self.refresh_active_connection_metric();
    }

    fn handle_timeout(socket: &UdpSocket, send_buf: &mut [u8], connection: &mut QuicConnection) {
        let timeout = match connection.quic.timeout() {
            Some(timeout) => timeout,
            None => return,
        };

        if connection.last_activity.elapsed() >= timeout {
            connection.quic.on_timeout();
            connection.last_activity = Instant::now();
            Self::flush_send(socket, send_buf, connection);
        }
    }

    fn advance_connection_streams(
        socket: &UdpSocket,
        connection: &mut QuicConnection,
        send_buf: &mut [u8],
        shared_ctx: &ForwardingSharedCtx<'_>,
        exec_ctx: &ForwardingExecutionCtx<'_>,
        progress_config: &StreamProgressConfig,
        context: &str,
    ) {
        let Some(mut h3) = connection.h3.take() else {
            return;
        };

        if let Err(e) = Self::advance_streams_non_blocking(
            &mut connection.streams,
            &mut connection.quic,
            &mut h3,
            exec_ctx,
            shared_ctx,
            progress_config,
        ) {
            error!("advance_streams_non_blocking in {}: {:?}", context, e);
        }
        connection.h3 = Some(h3);
        Self::flush_send(socket, send_buf, connection);
    }

    fn release_connection_streams(connection: &mut QuicConnection, metrics: &Metrics) {
        for req in connection.streams.values_mut() {
            forwarding::terminalize_stream(
                req,
                TerminalReason::Cancelled(CancellationReason::ConnectionClosed),
                metrics,
            );
        }
        connection.streams.clear();
    }
}

#[cfg(test)]
mod tests;
