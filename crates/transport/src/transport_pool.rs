//! Canonical transport execution façade.
//!
//! This module owns runtime-selected backend protocol dispatch, transport-level
//! timeout application, connection reuse, and backend client rotation. Callers
//! should hand it a backend identity plus a canonical request and avoid
//! reconstructing H1/H2 selection logic themselves.

use std::{
    collections::HashMap,
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};

use hyper::Method;
use impulse_config::runtime::{
    RuntimeBackendConnectionPolicy, RuntimeBackendTransportKind, RuntimeUpstream,
};
use impulse_errors::{PoolError, ProxyError};
use pingora_core::upstreams::peer::{ALPN, HttpPeer};
use tokio::sync::{Semaphore, TryAcquireError, mpsc};

use crate::{
    PingoraUpstreamConnectionIdentity,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendTransportEntry {
    Http1,
    H2,
}

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
    backend_entries: HashMap<String, BackendTransportEntry>,
    inflight_limits: HashMap<String, Arc<Semaphore>>,
    pingora_backends: HashMap<String, PingoraBackend>,
    pingora_pool: PingoraPool,
    dns_resolver: SharedDnsResolver,
}

impl UpstreamTransportPool {
    pub fn rotate_pingora_pool(&self, generation: u64) {
        self.pingora_pool.rotate(generation);
    }

    pub fn drain_pingora_pool(&self) {
        self.pingora_pool.drain();
    }

    pub async fn send_exchange(
        &self,
        backend: &str,
        request: UpstreamExchangeRequest,
    ) -> Result<UpstreamExchangeResponse, ProxyError> {
        self.send_pingora_exchange(backend, request).await
    }

    async fn send_pingora_exchange(
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
        let Some(mut config) = self.pingora_backends.get(backend).cloned() else {
            let error = if self.backend_entry(backend).is_some() {
                ProxyError::Transport(format!(
                    "Pingora backend '{backend}' has no resolved endpoint"
                ))
            } else {
                ProxyError::Pool(PoolError::UnknownBackend(backend.to_string()))
            };
            finish_pingora_dispatch_failure(completion, &error);
            return Err(error);
        };
        if let Some(mut address) = self
            .dns_resolver
            .cached_addrs(&config.host)
            .and_then(|addresses| addresses.into_iter().next())
        {
            address.set_port(config.port);
            config.peer._address = address.into();
            config.identity.address = address;
        }
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
            Some(BackendTransportEntry::Http1) => {
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
            Some(BackendTransportEntry::H2) => {
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

    pub async fn send_health_check(
        &self,
        backend: &str,
        uri: hyper::Uri,
        timeout: Duration,
    ) -> Result<hyper::StatusCode, ProxyError> {
        let version = match self.backend_entry(backend) {
            Some(BackendTransportEntry::Http1) => hyper::Version::HTTP_11,
            Some(BackendTransportEntry::H2) => hyper::Version::HTTP_2,
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
            body: crate::UpstreamRequestBody { frames: body },
            cancellation: UpstreamCancellation {
                signal: cancellation,
            },
            completion: completed,
        };
        let exchange = async {
            let mut response = self.send_exchange(backend, request).await?;
            let status = response.head.status;
            while let Some(frame) = response.body.frames.recv().await {
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

    /// Build a transport pool from already-interpreted backend transport entries.
    pub fn new_from_runtime_backends<I>(
        backends: I,
        backend_tls: HashMap<String, TlsClientConfig>,
        connection_policy: RuntimeBackendConnectionPolicy,
        dns_resolver: SharedDnsResolver,
    ) -> Result<Self, String>
    where
        I: IntoIterator<Item = (String, RuntimeBackendTransportKind)>,
    {
        Self::new_runtime(backends, backend_tls, connection_policy, dns_resolver, None)
    }

    fn new_runtime<I>(
        backends: I,
        backend_tls: HashMap<String, TlsClientConfig>,
        connection_policy: RuntimeBackendConnectionPolicy,
        dns_resolver: SharedDnsResolver,
        configured_pingora_backends: Option<HashMap<String, PingoraBackend>>,
    ) -> Result<Self, String>
    where
        I: IntoIterator<Item = (String, RuntimeBackendTransportKind)>,
    {
        let mut backend_entries = HashMap::new();
        let mut pingora_backends = configured_pingora_backends.unwrap_or_default();
        let mut inflight_limits = HashMap::new();

        for (backend, runtime_transport) in backends {
            let entry = Self::resolve_runtime_transport(runtime_transport);
            if !pingora_backends.contains_key(&backend) {
                let tls = backend_tls.get(&backend);
                if let Ok(config) = Self::fallback_pingora_backend(
                    &backend,
                    runtime_transport,
                    &connection_policy,
                    tls,
                ) {
                    pingora_backends.insert(backend.clone(), config);
                }
            }
            backend_entries.insert(backend.clone(), entry);
            inflight_limits.insert(
                backend.clone(),
                Arc::new(Semaphore::new(connection_policy.max_inflight.max(1))),
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

    fn resolve_runtime_transport(transport: RuntimeBackendTransportKind) -> BackendTransportEntry {
        match transport {
            RuntimeBackendTransportKind::Http1 => BackendTransportEntry::Http1,
            RuntimeBackendTransportKind::H2 => BackendTransportEntry::H2,
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
        let mut backends = Vec::new();
        let mut pingora_backends = HashMap::new();

        for upstream in upstreams {
            let tls = TlsClientConfig::from_runtime_upstream(upstream);
            for backend in &upstream.backends {
                let backend_addr = backend.backend.address.clone();
                backends.push((backend_addr.clone(), backend.endpoint.transport_kind));
                let (mut peer, address) =
                    build_pingora_http_peer(&backend.endpoint, connection_policy)?;
                if peer.is_tls() {
                    peer.options.verify_cert = tls.verify_certificates;
                    peer.options.verify_hostname = tls.strict_sni;
                }
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

        Self::new_runtime(
            backends,
            HashMap::new(),
            connection_policy.clone(),
            dns_resolver,
            Some(pingora_backends),
        )
    }

    fn fallback_pingora_backend(
        backend: &str,
        protocol: RuntimeBackendTransportKind,
        connection_policy: &RuntimeBackendConnectionPolicy,
        tls: Option<&TlsClientConfig>,
    ) -> Result<PingoraBackend, String> {
        let uri = if backend.contains("://") {
            backend.to_string()
        } else {
            format!("http://{backend}")
        }
        .parse::<hyper::Uri>()
        .map_err(|error| format!("invalid backend '{backend}': {error}"))?;
        let host = uri
            .host()
            .ok_or_else(|| format!("backend '{backend}' is missing a host"))?;
        let tls_enabled = uri.scheme_str() == Some("https");
        let port = uri.port_u16().unwrap_or(if tls_enabled { 443 } else { 80 });
        let address: SocketAddr = (host, port)
            .to_socket_addrs()
            .map_err(|error| format!("failed to resolve backend '{backend}': {error}"))?
            .next()
            .ok_or_else(|| format!("backend '{backend}' resolved without an address"))?;
        let sni = tls_enabled.then(|| host.to_string()).unwrap_or_default();
        let mut peer = HttpPeer::new(address, tls_enabled, sni.clone());
        peer.options.connection_timeout = Some(connection_policy.connect_timeout);
        peer.options.total_connection_timeout = Some(connection_policy.connect_timeout);
        peer.options.read_timeout = Some(connection_policy.execution_timeout);
        peer.options.write_timeout = Some(connection_policy.execution_timeout);
        peer.options.idle_timeout = Some(connection_policy.pool_idle_timeout);
        peer.options.alpn = match protocol {
            RuntimeBackendTransportKind::Http1 => ALPN::H1,
            RuntimeBackendTransportKind::H2 => ALPN::H2,
        };
        peer.options.max_h2_streams = connection_policy.max_inflight;
        if let Some(tls) = tls.filter(|_| tls_enabled) {
            peer.options.verify_cert = tls.verify_certificates;
            peer.options.verify_hostname = tls.strict_sni;
        }
        Ok(PingoraBackend {
            host: host.to_string(),
            port,
            peer,
            identity: PingoraUpstreamConnectionIdentity::new(
                address,
                protocol,
                sni,
                tls.filter(|_| tls_enabled),
                None,
                0,
            ),
        })
    }

    fn backend_entry(&self, backend: &str) -> Option<BackendTransportEntry> {
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
            Some(BackendTransportEntry::Http1 | BackendTransportEntry::H2) => {
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
    use std::{collections::HashMap, time::Duration};

    use impulse_config::{
        config::{
            Backend, ClientAuth, Config, ForwardedHeaderPolicy, ForwardedHeaderPolicyMode, Listen,
            LoadBalancing, Log, Observability, Performance, Resilience, RouteMatch, Security, Tls,
            Upstream, UpstreamHostPolicy, UpstreamHostPolicyMode, UpstreamTls,
        },
        runtime::{RuntimeBackendConnectionPolicy, RuntimeBackendTransportKind, RuntimeConfig},
    };

    use super::{BackendTransportEntry, UpstreamTransportPool};
    use crate::SharedDnsResolver;

    fn connection_policy() -> RuntimeBackendConnectionPolicy {
        RuntimeBackendConnectionPolicy {
            max_inflight: 8,
            max_idle_per_backend: 4,
            pool_idle_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(2),
            execution_timeout: Duration::from_secs(5),
        }
    }

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

    #[test]
    fn from_runtime_upstreams_selects_backend_protocols_inside_the_transport_facade() {
        let runtime = runtime_config_with_backends(&[
            ("http1-api", "http://127.0.0.1:8080"),
            ("h2-api", "https://api.internal:8443"),
        ]);

        let pool = UpstreamTransportPool::from_runtime_upstreams(
            runtime.upstreams.values(),
            &runtime.policies.transport.backend_connections,
            SharedDnsResolver::new(),
        )
        .expect("transport pool");

        assert_eq!(
            pool.backend_entry("http://127.0.0.1:8080"),
            Some(BackendTransportEntry::Http1)
        );
        assert_eq!(
            pool.backend_entry("https://api.internal:8443"),
            Some(BackendTransportEntry::H2)
        );
    }

    #[test]
    fn callers_can_use_one_rotation_api_without_protocol_specific_branching() {
        let pool = UpstreamTransportPool::new_from_runtime_backends(
            [
                (
                    "http://127.0.0.1:8080".to_string(),
                    RuntimeBackendTransportKind::Http1,
                ),
                (
                    "https://api.internal:8443".to_string(),
                    RuntimeBackendTransportKind::H2,
                ),
            ],
            HashMap::new(),
            connection_policy(),
            SharedDnsResolver::new(),
        )
        .expect("transport pool");

        let http1_rotation = pool
            .rotate_backend_client("http://127.0.0.1:8080")
            .expect("http1 rotation");
        let h2_rotation = pool
            .rotate_backend_client("https://api.internal:8443")
            .expect("h2 rotation");

        assert!(http1_rotation.rotated());
        assert!(h2_rotation.rotated());
    }

    #[tokio::test]
    async fn h1_refresh_rotation_stays_effective() {
        let pool = UpstreamTransportPool::new_from_runtime_backends(
            [(
                "http://127.0.0.1:8080".to_string(),
                RuntimeBackendTransportKind::Http1,
            )],
            HashMap::new(),
            connection_policy(),
            SharedDnsResolver::new(),
        )
        .expect("transport pool");

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
        let pool = UpstreamTransportPool::new_from_runtime_backends(
            [(
                "https://api.internal:8443".to_string(),
                RuntimeBackendTransportKind::H2,
            )],
            HashMap::new(),
            connection_policy(),
            SharedDnsResolver::new(),
        )
        .expect("transport pool");

        let first_rotation = pool
            .rotate_backend_client("https://api.internal:8443")
            .expect("first h2 rotation");
        let second_rotation = pool
            .rotate_backend_client("https://api.internal:8443")
            .expect("second h2 rotation");

        assert!(first_rotation.rotated());
        assert!(second_rotation.rotated());
    }

    #[test]
    fn backend_not_found_rotation_is_a_no_op_facade_result() {
        let pool = UpstreamTransportPool::new_from_runtime_backends(
            [(
                "https://api.internal:8443".to_string(),
                RuntimeBackendTransportKind::H2,
            )],
            HashMap::new(),
            connection_policy(),
            SharedDnsResolver::new(),
        )
        .expect("transport pool");

        let rotation = pool
            .rotate_backend_client("missing-backend")
            .expect("missing backend rotation should not error");

        assert!(!rotation.rotated());
    }
}
