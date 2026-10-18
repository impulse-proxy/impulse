//! Canonical transport execution façade.
//!
//! This module owns runtime-selected backend protocol dispatch, transport-level
//! timeout application, connection reuse, and backend client rotation. Callers
//! should hand it a backend identity plus a canonical request and avoid
//! reconstructing H1/H2 selection logic themselves.

use std::{collections::HashMap, sync::Arc, time::Duration};

use hyper::Method;
use impulse_config::runtime::{
    RuntimeBackendConnectionPolicy, RuntimeBackendTransportKind, RuntimeUpstream,
};
use impulse_errors::{PoolError, ProxyError};
use pingora_core::upstreams::peer::HttpPeer;
use tokio::sync::{Semaphore, TryAcquireError, mpsc};

use crate::{
    PingoraBackendHealthIdentity, PingoraUpstreamConnectionIdentity,
    client_rotation::BackendClientRotation,
    exchange::{
        UpstreamCancellation, UpstreamConnectionReuse, UpstreamExchangeCompletion,
        UpstreamExchangeLifecycle, UpstreamExchangeOutcome, UpstreamExchangeRequest,
        UpstreamExchangeResponse, UpstreamInflightPermit,
    },
    pingora_failure::{classify_pingora_h1_error, classify_pingora_h2_error},
    pingora_h1::PingoraH1UpstreamSession,
    pingora_h2::PingoraH2UpstreamSession,
    pingora_peer::build_pingora_http_peer,
    pingora_pool::PingoraPool,
    runtime_config::{SharedDnsResolver, TlsClientConfig},
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
    backend_entries: HashMap<String, RuntimeBackendTransportKind>,
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
            Some(RuntimeBackendTransportKind::Http1) => {
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
            Some(RuntimeBackendTransportKind::H2) => {
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

    pub async fn send_health_check(
        &self,
        backend: &str,
        uri: hyper::Uri,
        timeout: Duration,
    ) -> Result<hyper::StatusCode, ProxyError> {
        let version = match self.backend_entry(backend) {
            Some(RuntimeBackendTransportKind::Http1) => hyper::Version::HTTP_11,
            Some(RuntimeBackendTransportKind::H2) => hyper::Version::HTTP_2,
            None => {
                return Err(ProxyError::Pool(PoolError::UnknownBackend(
                    backend.to_string(),
                )));
            }
        };
        let mut headers = hyper::HeaderMap::new();
        if let Some(authority) = uri.authority() {
            let host = hyper::header::HeaderValue::from_str(authority.as_str())
                .map_err(|error| ProxyError::Protocol(error.to_string()))?;
            headers.insert(hyper::header::HOST, host);
        }
        let (frames, body) = mpsc::channel(1);
        drop(frames);
        let (cancel, cancellation) = tokio::sync::oneshot::channel();
        let (completed, completion) = tokio::sync::oneshot::channel();
        let request = UpstreamExchangeRequest {
            head: crate::UpstreamRequestHead {
                method: Method::GET,
                uri,
                version,
                headers,
            },
            body,
            cancellation: UpstreamCancellation {
                signal: cancellation,
            },
            completion: completed,
        };
        let exchange = async {
            let mut response = self.send_exchange(backend, request).await?;
            let status = response.head.status;
            while let Some(frame) = response.body.recv().await {
                frame?;
            }
            match completion.await {
                Ok(UpstreamExchangeCompletion {
                    outcome: UpstreamExchangeOutcome::Failed(error),
                    ..
                }) => Err(error),
                Ok(UpstreamExchangeCompletion {
                    outcome: UpstreamExchangeOutcome::Cancelled,
                    ..
                }) => Err(ProxyError::Transport(
                    "upstream health check cancelled".to_string(),
                )),
                Ok(_) => Ok(status),
                Err(_) => Err(ProxyError::Transport(
                    "upstream health check ended without completion".to_string(),
                )),
            }
        };
        match tokio::time::timeout(timeout, exchange).await {
            Ok(result) => result,
            Err(_) => {
                let _ = cancel.send(());
                Err(ProxyError::Timeout)
            }
        }
    }

    /// Build the canonical transport façade directly from runtime upstream definitions.
    pub fn from_runtime_upstreams<'a, I>(
        upstreams: I,
        connection_policy: &RuntimeBackendConnectionPolicy,
        dns_resolver: SharedDnsResolver,
    ) -> Result<Self, String>
    where
        I: IntoIterator<Item = &'a RuntimeUpstream>,
    {
        let mut backend_entries = HashMap::new();
        let mut inflight_limits = HashMap::new();
        let mut pingora_backends = HashMap::new();

        for upstream in upstreams {
            let tls = TlsClientConfig::from_runtime_upstream(upstream);
            for backend in &upstream.backends {
                let backend_addr = backend.backend.address.clone();
                backend_entries.insert(backend_addr.clone(), backend.endpoint.transport_kind);
                inflight_limits.insert(
                    backend_addr.clone(),
                    Arc::new(Semaphore::new(connection_policy.max_inflight.max(1))),
                );
                let (peer, address) =
                    build_pingora_http_peer(&backend.endpoint, connection_policy, &tls)?;
                let identity = PingoraUpstreamConnectionIdentity::new(
                    address,
                    backend.endpoint.transport_kind,
                    peer.sni.clone(),
                    peer.is_tls().then_some(&tls),
                    peer.proxy.as_ref(),
                    0,
                );
                pingora_backends.insert(
                    backend_addr.clone(),
                    PingoraBackend {
                        host: backend.endpoint.authority_host.clone(),
                        port: backend.endpoint.authority_port,
                        peer,
                        identity,
                    },
                );
            }
        }

        Ok(Self {
            backend_entries,
            inflight_limits,
            pingora_backends,
            pingora_pool: PingoraPool::new(0),
            dns_resolver,
        })
    }

    fn backend_entry(&self, backend: &str) -> Option<RuntimeBackendTransportKind> {
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
            Some(RuntimeBackendTransportKind::Http1 | RuntimeBackendTransportKind::H2) => {
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
    use std::collections::HashMap;

    use impulse_config::{
        config::{
            Backend, ClientAuth, Config, ForwardedHeaderPolicy, ForwardedHeaderPolicyMode, Listen,
            LoadBalancing, Log, Observability, Performance, Resilience, RouteMatch, Security, Tls,
            Upstream, UpstreamHostPolicy, UpstreamHostPolicyMode, UpstreamTls,
        },
        runtime::{RuntimeBackendTransportKind, RuntimeConfig},
    };

    use super::UpstreamTransportPool;
    use crate::SharedDnsResolver;

    fn runtime_config_with_backends(backends: &[(&str, &str)]) -> RuntimeConfig {
        let mut upstreams = HashMap::new();
        for (idx, (name, address)) in backends.iter().enumerate() {
            upstreams.insert(
                (*name).to_string(),
                Upstream {
                    load_balancing: LoadBalancing {
                        lb_type: "round-robin".to_string(),
                        key: None,
                    },
                    auth: Default::default(),
                    host_policy: UpstreamHostPolicy {
                        mode: UpstreamHostPolicyMode::Rewrite,
                        host: Some(format!("{name}.internal")),
                    },
                    forwarded_headers: ForwardedHeaderPolicy {
                        mode: ForwardedHeaderPolicyMode::Append,
                    },
                    compression: Default::default(),
                    tls: None,
                    route: RouteMatch {
                        host: Some(format!("{name}.example.com")),
                        path_prefix: Some("/".to_string()),
                        method: None,
                    },
                    backends: vec![Backend {
                        id: format!("backend-{idx}"),
                        address: (*address).to_string(),
                        weight: 100,
                        health_check: None,
                    }],
                },
            );
        }

        RuntimeConfig::from_config(&Config {
            version: 1,
            listen: Listen {
                protocol: "http3".to_string(),
                port: 443,
                address: "0.0.0.0".to_string(),
                tls: Tls {
                    cert: "/tmp/tls/default.pem".to_string(),
                    key: "/tmp/tls/default.key".to_string(),
                    certificates: Vec::new(),
                    client_auth: ClientAuth::default(),
                },
            },
            listeners: Vec::new(),
            upstream: upstreams,
            load_balancing: None,
            upstream_tls: UpstreamTls::default(),
            secrets: Default::default(),
            log: Log::default(),
            performance: Performance::default(),
            observability: Observability::default(),
            resilience: Resilience::default(),
            security: Security::default(),
        })
        .expect("runtime config")
    }

    fn transport_pool(backends: &[(&str, &str)]) -> UpstreamTransportPool {
        let runtime = runtime_config_with_backends(backends);
        UpstreamTransportPool::from_runtime_upstreams(
            runtime.upstreams.values(),
            &runtime.policies.transport.backend_connections,
            SharedDnsResolver::new(),
        )
        .expect("transport pool")
    }

    #[test]
    fn from_runtime_upstreams_selects_backend_protocols_inside_the_transport_facade() {
        let runtime = runtime_config_with_backends(&[
            ("http1-api", "http://127.0.0.1:8080"),
            ("h2-api", "https://127.0.0.1:8443"),
        ]);

        let pool = UpstreamTransportPool::from_runtime_upstreams(
            runtime.upstreams.values(),
            &runtime.policies.transport.backend_connections,
            SharedDnsResolver::new(),
        )
        .expect("transport pool");

        assert_eq!(
            pool.backend_entry("http://127.0.0.1:8080"),
            Some(RuntimeBackendTransportKind::Http1)
        );
        assert_eq!(
            pool.backend_entry("https://127.0.0.1:8443"),
            Some(RuntimeBackendTransportKind::H2)
        );
    }

    #[test]
    fn callers_can_use_one_rotation_api_without_protocol_specific_branching() {
        let pool = transport_pool(&[
            ("http1-api", "http://127.0.0.1:8080"),
            ("h2-api", "https://127.0.0.1:8443"),
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

    #[tokio::test]
    async fn h1_refresh_rotation_stays_effective() {
        let pool = transport_pool(&[("http1-api", "http://127.0.0.1:8080")]);

        let first_rotation = pool
            .rotate_backend_client("http://127.0.0.1:8080")
            .expect("first h1 rotation");
        let second_rotation = pool
            .rotate_backend_client("http://127.0.0.1:8080")
            .expect("second h1 rotation");

        assert!(first_rotation.rotated());
        assert!(second_rotation.rotated());
    }

    #[test]
    fn h2_refresh_rotation_stays_effective() {
        let pool = transport_pool(&[("h2-api", "https://127.0.0.1:8443")]);

        let first_rotation = pool
            .rotate_backend_client("https://127.0.0.1:8443")
            .expect("first h2 rotation");
        let second_rotation = pool
            .rotate_backend_client("https://127.0.0.1:8443")
            .expect("second h2 rotation");

        assert!(first_rotation.rotated());
        assert!(second_rotation.rotated());
    }

    #[test]
    fn backend_not_found_rotation_is_a_no_op_facade_result() {
        let pool = transport_pool(&[("h2-api", "https://127.0.0.1:8443")]);

        let rotation = pool
            .rotate_backend_client("missing-backend")
            .expect("missing backend rotation should not error");

        assert!(!rotation.rotated());
    }
}
