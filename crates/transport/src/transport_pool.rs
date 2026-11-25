//! Canonical transport execution façade.
//!
//! This module owns runtime-selected backend protocol dispatch, transport-level
//! timeout application, connection reuse, and backend client rotation. Callers
//! should hand it a backend identity plus a canonical request and avoid
//! reconstructing H1/H2 selection logic themselves.

use std::{collections::HashMap, sync::Arc};

use impulse_errors::{PoolError, ProxyError, RequestFailure};
use impulse_observability::Metrics;
use pingora_core::{
    connectors::http::{Connector, v2::Connector as H2Connector},
    upstreams::peer::HttpPeer,
};
use tokio::sync::{RwLock, Semaphore, TryAcquireError};

use crate::{
    PingoraBackendHealthIdentity, PingoraUpstreamConnectionIdentity, UpstreamProtocol,
    UpstreamTransportInput,
    exchange::{UpstreamExchangeLifecycle, UpstreamInflightPermit},
    http3::{UpstreamExchangeRequest, UpstreamExchangeResponse},
    pingora_failure::{classify_pingora_h1_error, classify_pingora_h2_error},
    pingora_h1::PingoraH1UpstreamSession,
    pingora_h2::PingoraH2UpstreamSession,
    pingora_peer::build_pingora_http_peer,
    runtime_config::SharedDnsResolver,
};

#[derive(Clone)]
struct PingoraBackend {
    host: String,
    port: u16,
    peer: HttpPeer,
    identity: PingoraUpstreamConnectionIdentity,
    h2_acquire_lock: Arc<RwLock<()>>,
}

/// Canonical transport façade used by edge/runtime code for backend execution.
pub struct UpstreamTransportPool {
    backend_entries: HashMap<String, UpstreamProtocol>,
    inflight_limits: HashMap<String, Arc<Semaphore>>,
    pingora_backends: HashMap<String, PingoraBackend>,
    pingora_connector: Arc<Connector>,
    pingora_h2_connector: Arc<H2Connector>,
    metrics: Arc<Metrics>,
    dns_resolver: SharedDnsResolver,
}

impl UpstreamTransportPool {
    pub fn pingora_backend_health_identity(
        &self,
        backend: &str,
    ) -> Option<PingoraBackendHealthIdentity> {
        self.pingora_backends
            .get(backend)
            .map(|backend| backend.identity.health_identity())
    }

    /// Returns the configured ALPN peer for Pingora's native
    /// `ProxyHttp::upstream_peer` path, including HTTP/2 backends. Pingora's
    /// `HttpProxy` owns the exchange; HTTP/3 adapters use the generic
    /// `UpstreamExchangeRequest` contract instead.
    pub fn pingora_proxy_peer(&self, backend: &str) -> Result<HttpPeer, ProxyError> {
        let mut config = self.resolved_pingora_backend(backend)?;
        config.peer.group_key = config.identity.pool_key();
        Ok(config.peer)
    }

    pub async fn execute_http3_exchange(
        &self,
        backend: &str,
        request: UpstreamExchangeRequest,
    ) -> Result<UpstreamExchangeResponse, ProxyError> {
        let UpstreamExchangeRequest { head, body } = request;
        if self.backend_entry(backend) == Some(UpstreamProtocol::Http1)
            && head.headers.contains_key(hyper::header::TRAILER)
        {
            return Err(ProxyError::RequestProtocol(
                RequestFailure::RequestTrailersRequireHttp2,
            ));
        }
        let config = self.resolved_pingora_backend(backend)?;
        let permit = self
            .acquire_exchange_permit(backend)
            .map_err(ProxyError::Pool)?;
        let connector = Arc::clone(&self.pingora_connector);
        let identity = config.identity;
        let lifecycle = UpstreamExchangeLifecycle {
            _inflight_permit: UpstreamInflightPermit { _permit: permit },
        };

        match self.backend_entry(backend) {
            Some(UpstreamProtocol::Http1) => {
                let mut session = match PingoraH1UpstreamSession::acquire(
                    connector,
                    config.peer,
                    &identity,
                )
                .await
                {
                    Ok(session) => session,
                    Err(error) => {
                        return Err(classify_pingora_h1_error(&error));
                    }
                };
                if let Err(error) = session.write_request(&head, body).await {
                    return Err(error);
                }
                session.read_response(lifecycle).await
            }
            Some(UpstreamProtocol::Http2) => {
                let mut session = match PingoraH2UpstreamSession::acquire(
                    Arc::clone(&self.pingora_h2_connector),
                    config.peer,
                    &identity,
                    config.h2_acquire_lock,
                    self.metrics.as_ref(),
                )
                .await
                {
                    Ok(session) => session,
                    Err(error) => {
                        return Err(classify_pingora_h2_error(&error, false));
                    }
                };
                if let Err(error) = session.write_request(&head, body).await {
                    return Err(error);
                }
                session.read_response(lifecycle).await
            }
            None => unreachable!("Pingora backend disappeared after lookup"),
        }
    }

    fn resolved_pingora_backend(&self, backend: &str) -> Result<PingoraBackend, ProxyError> {
        let Some(mut config) = self.pingora_backends.get(backend).cloned() else {
            return Err(if self.backend_entry(backend).is_some() {
                ProxyError::Transport(format!(
                    "Pingora backend '{backend}' has no resolved endpoint"
                ))
            } else {
                ProxyError::Pool(PoolError::UnknownBackend(backend.to_string()))
            });
        };
        if let Some(mut address) = self
            .dns_resolver
            .cached_addrs(&config.host)
            .and_then(|addresses| addresses.into_iter().next())
        {
            address.set_port(config.port);
            config.peer._address = address.into();
            config.identity.address = address;
        } else if config.host.parse::<std::net::IpAddr>().is_err() {
            return Err(ProxyError::Transport(format!(
                "Pingora backend '{backend}' has no resolved endpoint"
            )));
        }
        Ok(config)
    }

    /// Build the canonical transport façade from validated transport-owned inputs.
    pub fn new(
        inputs: impl IntoIterator<Item = UpstreamTransportInput>,
        dns_resolver: SharedDnsResolver,
        generation: u64,
        metrics: Arc<Metrics>,
    ) -> Result<Self, String> {
        let mut backend_entries = HashMap::new();
        let mut inflight_limits = HashMap::new();
        let mut pingora_backends = HashMap::new();

        for input in inputs {
            let backend_addr = input.endpoint.configured_address.clone();
            backend_entries.insert(backend_addr.clone(), input.endpoint.protocol);
            inflight_limits.insert(
                backend_addr.clone(),
                Arc::new(Semaphore::new(input.connection_limits.max_inflight.max(1))),
            );
            let (peer, address) = build_pingora_http_peer(&input)?;
            let identity = PingoraUpstreamConnectionIdentity::new(
                address,
                input.endpoint.protocol,
                peer.sni.clone(),
                input.tls.as_ref(),
                input.proxy.as_ref(),
                generation,
            );
            pingora_backends.insert(
                backend_addr,
                PingoraBackend {
                    host: input.endpoint.authority_host,
                    port: input.endpoint.authority_port,
                    peer,
                    identity,
                    h2_acquire_lock: Arc::new(RwLock::new(())),
                },
            );
        }

        Ok(Self {
            backend_entries,
            inflight_limits,
            pingora_backends,
            pingora_connector: Arc::new(Connector::new(None)),
            pingora_h2_connector: Arc::new(H2Connector::new(None)),
            metrics,
            dns_resolver,
        })
    }

    fn backend_entry(&self, backend: &str) -> Option<UpstreamProtocol> {
        self.backend_entries.get(backend).copied()
    }

    fn acquire_exchange_permit(
        &self,
        backend: &str,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, PoolError> {
        let limiter = self
            .inflight_limits
            .get(backend)
            .ok_or_else(|| PoolError::UnknownBackend(backend.to_string()))?;
        match Arc::clone(limiter).try_acquire_owned() {
            Ok(permit) => Ok(permit),
            Err(TryAcquireError::NoPermits) => {
                Err(PoolError::BackendOverloaded(backend.to_string()))
            }
            Err(TryAcquireError::Closed) => Err(PoolError::InflightLimiterClosed),
        }
    }

    pub fn rotate_backend_client(&self, backend: &str) -> bool {
        self.backend_entry(backend).is_some()
    }
}
