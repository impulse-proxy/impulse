//! Canonical transport execution façade.
//!
//! This module owns runtime-selected backend protocol dispatch, transport-level
//! timeout application, connection reuse, and backend client rotation. Callers
//! should hand it a backend identity plus a canonical request and avoid
//! reconstructing H1/H2 selection logic themselves.

use std::{collections::HashMap, sync::Arc};

use impulse_errors::{PoolError, ProxyError};
use pingora_core::upstreams::peer::HttpPeer;
use tokio::sync::{Semaphore, TryAcquireError};

use crate::{
    PingoraBackendHealthIdentity, PingoraUpstreamConnectionIdentity, UpstreamProtocol,
    UpstreamTransportInput,
    client_rotation::BackendClientRotation,
    exchange::{
        UpstreamConnectionReuse, UpstreamExchangeCompletion, UpstreamExchangeLifecycle,
        UpstreamExchangeOutcome, UpstreamExchangeRequest, UpstreamExchangeResponse,
        UpstreamInflightPermit,
    },
    pingora_failure::{classify_pingora_h1_error, classify_pingora_h2_error},
    pingora_h1::PingoraH1UpstreamSession,
    pingora_h2::PingoraH2UpstreamSession,
    pingora_peer::build_pingora_http_peer,
    pingora_pool::PingoraPool,
    runtime_config::SharedDnsResolver,
};

#[derive(Clone)]
struct PingoraBackend {
    host: String,
    port: u16,
    peer: HttpPeer,
    identity: PingoraUpstreamConnectionIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportClientRotation {
    rotation: BackendClientRotation,
}

impl TransportClientRotation {
    /// Returns true when transport rotated or recreated the backend client.
    pub fn rotated(self) -> bool {
        self.rotation.changed()
    }
}

/// Canonical transport façade used by edge/runtime code for backend execution.
pub struct UpstreamTransportPool {
    backend_entries: HashMap<String, UpstreamProtocol>,
    inflight_limits: HashMap<String, Arc<Semaphore>>,
    pingora_backends: HashMap<String, PingoraBackend>,
    pingora_pool: PingoraPool,
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

    pub fn rotate_pingora_pool(&self, generation: u64) {
        self.pingora_pool.rotate(generation);
    }

    pub fn drain_pingora_pool(&self) {
        self.pingora_pool.drain();
    }

    pub fn pingora_peer(&self, backend: &str, generation: u64) -> Result<HttpPeer, ProxyError> {
        let mut config = self.resolved_pingora_backend(backend)?;
        config.identity.generation = generation;
        config.peer.group_key = config.identity.pool_key();
        Ok(config.peer)
    }

    pub async fn send_exchange(
        &self,
        backend: &str,
        request: UpstreamExchangeRequest,
    ) -> Result<UpstreamExchangeResponse, ProxyError> {
        let UpstreamExchangeRequest {
            head,
            body,
            cancellation,
            completion,
        } = request;
        if self.backend_entry(backend) == Some(UpstreamProtocol::Http1)
            && head.headers.contains_key(hyper::header::TRAILER)
        {
            let error =
                ProxyError::Protocol("request trailers require an HTTP/2 upstream".to_string());
            finish_pingora_dispatch_failure(completion, &error);
            return Err(error);
        }
        let config = match self.resolved_pingora_backend(backend) {
            Ok(config) => config,
            Err(error) => {
                finish_pingora_dispatch_failure(completion, &error);
                return Err(error);
            }
        };
        let permit = self
            .acquire_exchange_permit(backend)
            .map_err(ProxyError::Pool);
        let permit = match permit {
            Ok(permit) => permit,
            Err(error) => {
                finish_pingora_dispatch_failure(completion, &error);
                return Err(error);
            }
        };
        let Some(pool) = self.pingora_pool.acquire() else {
            let error = ProxyError::Transport("Pingora upstream pool is draining".to_string());
            finish_pingora_dispatch_failure(completion, &error);
            return Err(error);
        };
        let mut identity = config.identity;
        identity.generation = pool.generation();
        let lifecycle = UpstreamExchangeLifecycle {
            cancellation,
            completion,
            inflight_permit: UpstreamInflightPermit { _permit: permit },
        };

        match self.backend_entry(backend) {
            Some(UpstreamProtocol::Http1) => {
                let mut session =
                    match PingoraH1UpstreamSession::acquire(pool, config.peer, &identity).await {
                        Ok(session) => session,
                        Err(error) => {
                            let error = classify_pingora_h1_error(&error);
                            finish_pingora_dispatch_failure(lifecycle.completion, &error);
                            return Err(error);
                        }
                    };
                if let Err(error) = session.write_request(&head, body).await {
                    finish_pingora_dispatch_failure(lifecycle.completion, &error);
                    return Err(error);
                }
                session.read_response(lifecycle).await
            }
            Some(UpstreamProtocol::Http2) => {
                let mut session =
                    match PingoraH2UpstreamSession::acquire(pool, config.peer, &identity).await {
                        Ok(session) => session,
                        Err(error) => {
                            let error = classify_pingora_h2_error(&error, false);
                            finish_pingora_dispatch_failure(lifecycle.completion, &error);
                            return Err(error);
                        }
                    };
                if let Err(error) = session.write_request(&head, body).await {
                    finish_pingora_dispatch_failure(lifecycle.completion, &error);
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
                0,
            );
            pingora_backends.insert(
                backend_addr,
                PingoraBackend {
                    host: input.endpoint.authority_host,
                    port: input.endpoint.authority_port,
                    peer,
                    identity,
                },
            );
        }

        Ok(Self {
            backend_entries,
            inflight_limits,
            pingora_backends,
            pingora_pool: PingoraPool::new(0),
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

    pub fn rotate_backend_client(&self, backend: &str) -> Result<TransportClientRotation, String> {
        match self.backend_entry(backend) {
            Some(UpstreamProtocol::Http1 | UpstreamProtocol::Http2) => {
                Ok(TransportClientRotation {
                    rotation: BackendClientRotation::recreated(),
                })
            }
            None => Ok(TransportClientRotation {
                rotation: BackendClientRotation::missing_backend(),
            }),
        }
    }
}

fn finish_pingora_dispatch_failure(
    completion: tokio::sync::oneshot::Sender<UpstreamExchangeCompletion>,
    error: &ProxyError,
) {
    let outcome_error = match error {
        ProxyError::Transport(detail) => ProxyError::Transport(detail.clone()),
        ProxyError::Protocol(detail) => ProxyError::Protocol(detail.clone()),
        ProxyError::Timeout => ProxyError::Timeout,
        ProxyError::Tls(detail) => ProxyError::Tls(detail.clone()),
        ProxyError::Bridge(_) | ProxyError::Pool(_) => ProxyError::Transport(error.to_string()),
    };
    let _ = completion.send(UpstreamExchangeCompletion {
        outcome: UpstreamExchangeOutcome::Failed(outcome_error),
        connection_reuse: UpstreamConnectionReuse::Close,
    });
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::UpstreamTransportPool;
    use crate::{
        SharedDnsResolver, UpstreamConnectionLimitsInput, UpstreamEndpointInput, UpstreamProtocol,
        UpstreamTimeoutInput, UpstreamTlsInput, UpstreamTransportInput,
    };

    fn transport_pool(backends: &[(&str, UpstreamProtocol)]) -> UpstreamTransportPool {
        let inputs = backends.iter().map(|(address, protocol)| {
            let tls = address.starts_with("https://");
            let authority = address
                .strip_prefix("http://")
                .or_else(|| address.strip_prefix("https://"))
                .expect("test backend scheme");
            let (host, port) = authority.split_once(':').expect("test backend authority");
            UpstreamTransportInput {
                endpoint: UpstreamEndpointInput {
                    configured_address: (*address).to_string(),
                    authority_host: host.to_string(),
                    authority_port: port.parse().expect("test backend port"),
                    protocol: *protocol,
                    tls,
                },
                tls: tls.then(UpstreamTlsInput::default),
                timeouts: UpstreamTimeoutInput {
                    connect: Duration::from_secs(1),
                    execution: Duration::from_secs(1),
                    pool_idle: Duration::from_secs(30),
                },
                proxy: None,
                connection_limits: UpstreamConnectionLimitsInput {
                    max_inflight: 32,
                    max_idle: 8,
                },
            }
        });
        UpstreamTransportPool::new(inputs, SharedDnsResolver::new()).expect("transport pool")
    }

    #[test]
    fn transport_inputs_select_backend_protocols_inside_the_transport_facade() {
        let pool = transport_pool(&[
            ("http://127.0.0.1:8080", UpstreamProtocol::Http1),
            ("https://127.0.0.1:8443", UpstreamProtocol::Http2),
        ]);

        assert_eq!(
            pool.backend_entry("http://127.0.0.1:8080"),
            Some(UpstreamProtocol::Http1)
        );
        assert_eq!(
            pool.backend_entry("https://127.0.0.1:8443"),
            Some(UpstreamProtocol::Http2)
        );
    }

    #[test]
    fn callers_can_use_one_rotation_api_without_protocol_specific_branching() {
        let pool = transport_pool(&[
            ("http://127.0.0.1:8080", UpstreamProtocol::Http1),
            ("https://127.0.0.1:8443", UpstreamProtocol::Http2),
        ]);

        let http1_rotation = pool
            .rotate_backend_client("http://127.0.0.1:8080")
            .expect("http1 rotation");
        let h2_rotation = pool
            .rotate_backend_client("https://127.0.0.1:8443")
            .expect("h2 rotation");

        assert!(http1_rotation.rotated());
        assert!(h2_rotation.rotated());
    }

    #[test]
    fn backend_not_found_rotation_is_a_no_op_facade_result() {
        let pool = transport_pool(&[("https://127.0.0.1:8443", UpstreamProtocol::Http2)]);

        let rotation = pool
            .rotate_backend_client("missing-backend")
            .expect("missing backend rotation should not error");

        assert!(!rotation.rotated());
    }
}
