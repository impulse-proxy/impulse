#[cfg(test)]
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

use impulse_config::runtime::{RuntimeBackendTlsPolicy, RuntimeUpstreamPolicy};
use impulse_lb::pingora_backend::PingoraLoadBalancingRuntimeState;

use super::{selection::ForwardingSelectionService, *};
use crate::{
    edge_core::request_execution::{RouteResolutionError, resolve_route},
    runtime::connection::outcome::{RouteOutcomeTarget, observe_proxy_error_outcome},
};

#[derive(Clone, Copy)]
pub(crate) struct TargetResolutionRequest<'a> {
    pub(in crate::quic_listener) method: &'a str,
    pub(in crate::quic_listener) path: &'a str,
    pub(in crate::quic_listener) authority: Option<&'a str>,
    pub(in crate::quic_listener) cid_key: Option<&'a str>,
    pub(in crate::quic_listener) header_lookup: Option<&'a LbHeaderLookup<'a>>,
}

impl<'a> TargetResolutionRequest<'a> {
    pub(crate) fn new(
        method: &'a str,
        path: &'a str,
        authority: Option<&'a str>,
        cid_key: Option<&'a str>,
        header_lookup: Option<&'a LbHeaderLookup<'a>>,
    ) -> Self {
        Self {
            method,
            path,
            authority,
            cid_key,
            header_lookup,
        }
    }
}

#[derive(Clone, Copy)]
pub(in crate::quic_listener) struct ResolutionContext<'a> {
    pub(in crate::quic_listener) routing_index: &'a RouteIndex,
    pub(in crate::quic_listener) upstream_pools: &'a HashMap<String, Arc<RwLock<UpstreamPool>>>,
    pub(in crate::quic_listener) upstream_policies: &'a HashMap<String, RuntimeUpstreamPolicy>,
    pingora_load_balancing: &'a PingoraLoadBalancingRuntimeState<RuntimeBackendTlsPolicy>,
    generation: u64,
    metrics: &'a Metrics,
}

impl<'a> ResolutionContext<'a> {
    pub(in crate::quic_listener) fn new(
        routing_index: &'a RouteIndex,
        upstream_pools: &'a HashMap<String, Arc<RwLock<UpstreamPool>>>,
        upstream_policies: &'a HashMap<String, RuntimeUpstreamPolicy>,
        pingora_load_balancing: &'a PingoraLoadBalancingRuntimeState<RuntimeBackendTlsPolicy>,
        generation: u64,
        metrics: &'a Metrics,
    ) -> Self {
        Self {
            routing_index,
            upstream_pools,
            upstream_policies,
            pingora_load_balancing,
            generation,
            metrics,
        }
    }
}

#[cfg(test)]
pub(in crate::quic_listener) fn selectors_for_test(
    runtime: &impulse_config::runtime::RuntimeConfig,
) -> PingoraLoadBalancingRuntimeState<RuntimeBackendTlsPolicy> {
    let generation = 1;
    let health_registry = Arc::new(
        impulse_lb::pingora_backend::HealthRegistry::with_equivalence(|backend| {
            let mut hasher = DefaultHasher::new();
            backend.hash(&mut hasher);
            hasher.finish()
        }),
    );
    let view_health_registry = Arc::clone(&health_registry);
    let upstream_pools = runtime
        .upstreams
        .iter()
        .map(|(name, upstream)| {
            (
                name.clone(),
                Arc::new(RwLock::new(
                    upstream_pool_from_runtime(upstream).expect("validated upstream pool"),
                )),
            )
        })
        .collect();
    let views = runtime.upstreams.iter().map(move |(name, upstream)| {
        let tls_identity = upstream.backend_tls_policy().clone();
        let backend_inputs = load_balancing_backend_inputs(upstream);
        let view = impulse_lb::pingora_backend::GenerationBackendView::new(
            generation,
            name,
            &backend_inputs,
            |backend| {
                let endpoint = &upstream.backends[backend.index()].endpoint;
                let address = std::net::SocketAddr::new(
                    endpoint
                        .authority_host
                        .parse()
                        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                    endpoint.authority_port,
                );
                impulse_lb::pingora_backend::map_validated_backend(
                    backend,
                    address,
                    tls_identity.clone(),
                )
            },
            Arc::clone(&view_health_registry),
        )
        .expect("selector view");
        (
            name.clone(),
            load_balancing_strategy_input(upstream.load_balancing.strategy)
                .expect("validated load balancing strategy"),
            view,
        )
    });
    PingoraLoadBalancingRuntimeState::new(generation, upstream_pools, views, health_registry)
        .expect("selector runtime")
}

#[derive(Clone, Copy)]
pub(in crate::quic_listener) struct ResolutionObservation<'a> {
    pub(in crate::quic_listener) metrics: &'a Metrics,
    pub(in crate::quic_listener) elapsed: Duration,
}

impl<'a> ResolutionObservation<'a> {
    pub(in crate::quic_listener) fn new(metrics: &'a Metrics, elapsed: Duration) -> Self {
        Self { metrics, elapsed }
    }
}

pub(in crate::quic_listener) struct RouteResolution {
    pub(in crate::quic_listener) upstream_name: String,
    pub(in crate::quic_listener) upstream_pool: Arc<RwLock<UpstreamPool>>,
    pub(in crate::quic_listener) upstream_policy: RuntimeUpstreamPolicy,
    pub(in crate::quic_listener) route_path_len: usize,
    pub(in crate::quic_listener) route_host_specific: bool,
    pub(in crate::quic_listener) route_reason: RouteDecisionReason,
}

pub(crate) struct BackendSelection {
    pub(crate) backend_addr: String,
    pub(crate) backend_index: usize,
    pub(in crate::quic_listener) backend_lb: String,
    pub(crate) lb_key: String,
}

pub(in crate::quic_listener) struct TargetResolution {
    pub(in crate::quic_listener) route: RouteResolution,
    pub(in crate::quic_listener) backend: BackendSelection,
}

pub(super) struct ForwardTargetResolution {
    pub(super) upstream_name: String,
    pub(super) upstream_pool: Arc<RwLock<UpstreamPool>>,
    pub(super) upstream_policy: RuntimeUpstreamPolicy,
    pub(super) route_path_len: usize,
    pub(super) route_host_specific: bool,
    pub(super) route_reason: String,
    pub(super) backend_addr: String,
    pub(super) backend_index: usize,
    pub(super) backend_lb: String,
    pub(super) lb_key: String,
}

pub(super) struct ForwardTargetResolutionInput<'a> {
    pub(super) request: TargetResolutionRequest<'a>,
    pub(super) context: ResolutionContext<'a>,
    pub(super) observation: ResolutionObservation<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RouteResolutionFailureKind {
    NoRoute,
    MissingPool,
    PoolLockPoisoned,
    NoServers,
    NoHealthyServers,
    InvalidServerAddress,
    OtherTransport,
    Other,
}

impl QUICListener {
    fn classify_route_resolution_transport_reason(reason: &str) -> RouteResolutionFailureKind {
        if reason.starts_with("no route for ") {
            return RouteResolutionFailureKind::NoRoute;
        }
        if reason.starts_with("pool not found:") {
            return RouteResolutionFailureKind::MissingPool;
        }
        if reason == "upstream pool lock poisoned" {
            return RouteResolutionFailureKind::PoolLockPoisoned;
        }
        if reason == "no servers in upstream" {
            return RouteResolutionFailureKind::NoServers;
        }
        if reason == "no healthy servers" {
            return RouteResolutionFailureKind::NoHealthyServers;
        }
        if reason == "invalid server address" {
            return RouteResolutionFailureKind::InvalidServerAddress;
        }
        RouteResolutionFailureKind::OtherTransport
    }

    fn classify_route_resolution_failure(err: &ProxyError) -> RouteResolutionFailureKind {
        match err {
            ProxyError::Transport(reason) => {
                Self::classify_route_resolution_transport_reason(reason)
            }
            _ => RouteResolutionFailureKind::Other,
        }
    }

    fn log_route_resolution_failure(request: &TargetResolutionRequest<'_>, err: &ProxyError) {
        let authority = request.authority.unwrap_or("-");
        let failure_kind = Self::classify_route_resolution_failure(err);
        let message = format!(
            "route/backend resolution failed method={} path={} authority={} kind={:?}: {}",
            request.method, request.path, authority, failure_kind, err
        );
        match failure_kind {
            RouteResolutionFailureKind::NoRoute => debug!("{}", message),
            _ => warn!("{}", message),
        }
    }

    fn observe_route_resolution_failure(
        request: &TargetResolutionRequest<'_>,
        err: &ProxyError,
        metrics: &Metrics,
        elapsed: Duration,
    ) {
        let _ = observe_proxy_error_outcome(
            metrics,
            RouteOutcomeTarget::UNROUTED,
            None,
            elapsed,
            None,
            err,
            None,
        );
        Self::log_route_resolution_failure(request, err);
    }

    pub(in crate::quic_listener) fn route_resolution_error_response(
        err: &ProxyError,
    ) -> (http::StatusCode, &'static [u8]) {
        match Self::classify_route_resolution_failure(err) {
            RouteResolutionFailureKind::NoRoute => (http::StatusCode::BAD_GATEWAY, b"no route\n"),
            RouteResolutionFailureKind::MissingPool => {
                (http::StatusCode::BAD_GATEWAY, b"no pool\n")
            }
            RouteResolutionFailureKind::PoolLockPoisoned => {
                (http::StatusCode::BAD_GATEWAY, b"pool error\n")
            }
            RouteResolutionFailureKind::NoServers
            | RouteResolutionFailureKind::InvalidServerAddress => {
                (http::StatusCode::SERVICE_UNAVAILABLE, b"no backends\n")
            }
            RouteResolutionFailureKind::NoHealthyServers => (
                http::StatusCode::SERVICE_UNAVAILABLE,
                b"no healthy backends\n",
            ),
            RouteResolutionFailureKind::OtherTransport | RouteResolutionFailureKind::Other => (
                http::StatusCode::BAD_GATEWAY,
                b"route/backend resolution failed\n",
            ),
        }
    }

    pub(super) fn resolve_forwarding_target(
        input: ForwardTargetResolutionInput<'_>,
    ) -> Result<ForwardTargetResolution, ProxyError> {
        let ForwardTargetResolutionInput {
            request,
            context,
            observation,
        } = input;
        let TargetResolution { route, backend } =
            match Self::resolve_backend_internal(&request, &context, false) {
                Ok(resolved) => resolved,
                Err(err) => {
                    Self::observe_route_resolution_failure(
                        &request,
                        &err,
                        observation.metrics,
                        observation.elapsed,
                    );
                    return Err(err);
                }
            };
        let RouteResolution {
            upstream_name,
            upstream_pool,
            upstream_policy,
            route_path_len,
            route_host_specific,
            route_reason,
        } = route;
        let BackendSelection {
            backend_addr,
            backend_index,
            backend_lb,
            lb_key,
        } = backend;

        Ok(ForwardTargetResolution {
            upstream_name,
            upstream_pool,
            upstream_policy,
            route_path_len,
            route_host_specific,
            route_reason: format!("{route_reason:?}"),
            backend_addr,
            backend_index,
            backend_lb,
            lb_key,
        })
    }

    #[allow(clippy::type_complexity)]
    fn resolve_route_target(
        request: &TargetResolutionRequest<'_>,
        context: &ResolutionContext<'_>,
    ) -> Result<RouteResolution, ProxyError> {
        let route_target = resolve_route(
            context.routing_index,
            request.method,
            request.path,
            request.authority,
        )
        .map_err(|error| match error {
            RouteResolutionError::EmptyMethodOrPath => {
                ProxyError::Transport("empty method or path".into())
            }
            RouteResolutionError::NoRoute => {
                ProxyError::Transport(format!("no route for {}", request.path))
            }
        })?;
        let upstream_name = route_target.upstream_name.to_string();
        let upstream_pool = context
            .upstream_pools
            .get(route_target.upstream_name.as_ref())
            .ok_or_else(|| ProxyError::Transport(format!("pool not found: {upstream_name}")))?
            .clone();
        let upstream_policy = context
            .upstream_policies
            .get(route_target.upstream_name.as_ref())
            .cloned()
            .unwrap_or_default();

        Ok(RouteResolution {
            upstream_name,
            upstream_pool,
            upstream_policy,
            route_path_len: route_target.matched_path_len,
            route_host_specific: route_target.host_specific,
            route_reason: route_target.reason,
        })
    }

    fn log_backend_selection(
        request: &TargetResolutionRequest<'_>,
        backend_addr: &str,
        lb_type: &str,
        upstream_name: &str,
        route_path_len: usize,
        route_host_specific: bool,
        route_reason: &RouteDecisionReason,
    ) {
        debug!(
            "Resolved backend method={} path={} authority={} route={} backend={} via={} path_len={} host_specific={} reason={:?}",
            request.method,
            request.path,
            request.authority.unwrap_or("-"),
            upstream_name,
            backend_addr,
            lb_type,
            route_path_len,
            route_host_specific,
            route_reason
        );
    }

    fn resolve_backend_internal(
        request: &TargetResolutionRequest<'_>,
        context: &ResolutionContext<'_>,
        begin_request: bool,
    ) -> Result<TargetResolution, ProxyError> {
        let route = Self::resolve_route_target(request, context)?;
        let selector = context
            .pingora_load_balancing
            .selector(&route.upstream_name)
            .ok_or_else(|| {
                context
                    .metrics
                    .runtime_observations()
                    .inc_pingora_lb_selector_failure();
                ProxyError::Transport(format!(
                    "Pingora selector not found: {}",
                    route.upstream_name
                ))
            })?;
        let backend = ForwardingSelectionService::select_backend(
            request,
            &route.upstream_pool,
            selector,
            context.generation,
            begin_request,
            context.metrics,
        )?;

        Self::log_backend_selection(
            request,
            &backend.backend_addr,
            &backend.backend_lb,
            &route.upstream_name,
            route.route_path_len,
            route.route_host_specific,
            &route.route_reason,
        );
        Ok(TargetResolution { route, backend })
    }

    #[cfg(test)]
    pub(in crate::quic_listener) fn resolve_backend_request_for_test(
        request: &TargetResolutionRequest<'_>,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
        upstream_policies: &HashMap<String, RuntimeUpstreamPolicy>,
        routing_index: &RouteIndex,
        selectors: &PingoraLoadBalancingRuntimeState<RuntimeBackendTlsPolicy>,
        metrics: &Metrics,
    ) -> Result<TargetResolution, ProxyError> {
        let context = ResolutionContext::new(
            routing_index,
            upstream_pools,
            upstream_policies,
            selectors,
            selectors.generation(),
            metrics,
        );
        Self::resolve_backend_internal(request, &context, true)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, RwLock},
    };

    use impulse_config::{
        config::{
            Backend, Config, ForwardedHeaderPolicy, Listen, LoadBalancing, Resilience, RouteAuth,
            RouteMatch, Tls, Upstream, UpstreamHostPolicy,
        },
        runtime::RuntimeConfig,
    };

    use super::*;
    use crate::routing::index::RouteIndex;

    fn upstream(
        path_prefix: &str,
        host: Option<&str>,
        method: Option<&str>,
        backend_addr: &str,
    ) -> Upstream {
        Upstream {
            load_balancing: LoadBalancing {
                lb_type: "round-robin".to_string(),
                key: None,
            },
            auth: RouteAuth::default(),
            host_policy: UpstreamHostPolicy::default(),
            forwarded_headers: ForwardedHeaderPolicy::default(),
            compression: Default::default(),
            cache: Default::default(),
            tls: None,
            route: RouteMatch {
                host: host.map(str::to_string),
                path_prefix: Some(path_prefix.to_string()),
                method: method.map(str::to_string),
            },
            backends: vec![Backend {
                id: "b1".to_string(),
                address: backend_addr.to_string(),
                weight: 1,
                health_check: None,
            }],
        }
    }

    fn runtime_config(upstreams: HashMap<String, Upstream>) -> RuntimeConfig {
        runtime_config_with_connect(upstreams, false)
    }

    fn runtime_config_with_connect(
        upstreams: HashMap<String, Upstream>,
        allow_connect: bool,
    ) -> RuntimeConfig {
        let mut resilience = Resilience::default();
        resilience.protocol.allow_connect = allow_connect;
        RuntimeConfig::from_config(&Config {
            version: 1,
            listen: Listen {
                protocol: "http1".to_string(),
                tls: Tls {
                    cert: "/tmp/test-cert.pem".to_string(),
                    key: "/tmp/test-key.pem".to_string(),
                    ..Tls::default()
                },
                ..Listen::default()
            },
            listeners: Vec::new(),
            upstream: upstreams,
            load_balancing: None,
            upstream_tls: Default::default(),
            secrets: Default::default(),
            log: Default::default(),
            performance: Default::default(),
            observability: Default::default(),
            resilience,
            security: Default::default(),
        })
        .expect("runtime config")
    }

    fn upstream_pools(runtime: &RuntimeConfig) -> HashMap<String, Arc<RwLock<UpstreamPool>>> {
        runtime
            .upstreams
            .iter()
            .map(|(name, upstream)| {
                (
                    name.clone(),
                    Arc::new(RwLock::new(
                        upstream_pool_from_runtime(upstream).expect("pool"),
                    )),
                )
            })
            .collect()
    }

    #[test]
    fn resolve_route_target_prefers_method_specific_host_route_in_overlapping_scenarios() {
        let runtime = runtime_config(HashMap::from([
            (
                "default".to_string(),
                upstream("/api", None, None, "http://127.0.0.1:7001"),
            ),
            (
                "host_only".to_string(),
                upstream(
                    "/api",
                    Some("pay.example.com"),
                    None,
                    "http://127.0.0.1:7002",
                ),
            ),
            (
                "method_host".to_string(),
                upstream(
                    "/api",
                    Some("pay.example.com"),
                    Some("POST"),
                    "http://127.0.0.1:7003",
                ),
            ),
        ]));
        let routing_index = RouteIndex::from_runtime_upstreams(&runtime.upstreams);
        let pools = upstream_pools(&runtime);
        let policies = runtime
            .upstreams
            .iter()
            .map(|(name, upstream)| (name.clone(), upstream.policy.clone()))
            .collect::<HashMap<_, _>>();
        let selectors = selectors_for_test(&runtime);
        let metrics = Metrics::new(1, vec!["route".to_string()]);
        let context = ResolutionContext::new(
            &routing_index,
            &pools,
            &policies,
            &selectors,
            selectors.generation(),
            &metrics,
        );
        let request = TargetResolutionRequest::new(
            "POST",
            "/api/orders",
            Some("pay.example.com"),
            None,
            None,
        );

        let route = QUICListener::resolve_route_target(&request, &context).expect("resolved route");

        assert_eq!(route.upstream_name, "method_host");
        assert!(route.route_host_specific);
        assert_eq!(route.route_path_len, "/api".len());
        assert_eq!(
            route.route_reason,
            RouteDecisionReason::MethodSpecificTieBreak
        );
    }

    #[test]
    fn resolve_route_target_returns_stable_unrouted_error_mapping() {
        let runtime = runtime_config(HashMap::from([(
            "api".to_string(),
            upstream(
                "/api",
                Some("api.example.com"),
                None,
                "http://127.0.0.1:7001",
            ),
        )]));
        let routing_index = RouteIndex::from_runtime_upstreams(&runtime.upstreams);
        let pools = upstream_pools(&runtime);
        let policies = runtime
            .upstreams
            .iter()
            .map(|(name, upstream)| (name.clone(), upstream.policy.clone()))
            .collect::<HashMap<_, _>>();
        let selectors = selectors_for_test(&runtime);
        let metrics = Metrics::new(1, vec!["route".to_string()]);
        let context = ResolutionContext::new(
            &routing_index,
            &pools,
            &policies,
            &selectors,
            selectors.generation(),
            &metrics,
        );

        let request = TargetResolutionRequest::new(
            "GET",
            "/missing",
            Some("unknown.example.com"),
            None,
            None,
        );
        let first = match QUICListener::resolve_route_target(&request, &context) {
            Err(err) => err,
            Ok(_) => panic!("expected unrouted resolution failure"),
        };
        let second = match QUICListener::resolve_route_target(&request, &context) {
            Err(err) => err,
            Ok(_) => panic!("expected unrouted resolution failure"),
        };

        assert_eq!(first.to_string(), second.to_string());
        assert_eq!(first.to_string(), "transport error: no route for /missing");

        let (status, body) = QUICListener::route_resolution_error_response(&first);
        assert_eq!(status, http::StatusCode::BAD_GATEWAY);
        assert_eq!(body, b"no route\n");
    }

    #[test]
    fn resolve_forwarding_target_keeps_connect_method_for_websocket_routes() {
        let runtime = runtime_config_with_connect(
            HashMap::from([
                (
                    "websocket_get".to_string(),
                    upstream(
                        "/chat",
                        Some("ws.example.com"),
                        Some("GET"),
                        "http://127.0.0.1:7001",
                    ),
                ),
                (
                    "websocket_connect".to_string(),
                    upstream(
                        "/chat",
                        Some("ws.example.com"),
                        Some("CONNECT"),
                        "http://127.0.0.1:7002",
                    ),
                ),
            ]),
            true,
        );
        let routing_index = RouteIndex::from_runtime_upstreams(&runtime.upstreams);
        let pools = upstream_pools(&runtime);
        let policies = runtime
            .upstreams
            .iter()
            .map(|(name, upstream)| (name.clone(), upstream.policy.clone()))
            .collect::<HashMap<_, _>>();
        let selectors = selectors_for_test(&runtime);
        let metrics = Metrics::new(1, vec!["route".to_string()]);
        let context = ResolutionContext::new(
            &routing_index,
            &pools,
            &policies,
            &selectors,
            selectors.generation(),
            &metrics,
        );
        let request = TargetResolutionRequest::new(
            "CONNECT",
            "/chat/socket",
            Some("ws.example.com"),
            None,
            None,
        );
        let resolved = QUICListener::resolve_forwarding_target(ForwardTargetResolutionInput {
            request,
            context,
            observation: ResolutionObservation::new(&metrics, Duration::ZERO),
        })
        .expect("resolved target");

        assert_eq!(resolved.upstream_name, "websocket_connect");
        assert_eq!(resolved.backend_addr, "http://127.0.0.1:7002");
    }

    #[test]
    fn route_resolution_error_response_maps_missing_pool_and_empty_request_stably() {
        let missing_pool = ProxyError::Transport("pool not found: payments".to_string());
        let (status, body) = QUICListener::route_resolution_error_response(&missing_pool);
        assert_eq!(status, http::StatusCode::BAD_GATEWAY);
        assert_eq!(body, b"no pool\n");

        let other = ProxyError::Transport("empty method or path".to_string());
        let (status, body) = QUICListener::route_resolution_error_response(&other);
        assert_eq!(status, http::StatusCode::BAD_GATEWAY);
        assert_eq!(body, b"route/backend resolution failed\n");
    }
}
