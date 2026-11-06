use std::{
    convert::Infallible,
    sync::{Arc, RwLock, atomic::Ordering},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{Full, combinators::BoxBody};
use impulse_bridge::response::{
    ResponseBodyMode, ResponseNormalizationProtocol, ResponseProtocolConstraints,
    normalize_response_trailers,
};
use impulse_config::{backend_endpoint::BackendScheme, runtime::ListenerRuntimeConfig};
use impulse_contracts::{
    AlternateBackendFailureReason, HealthFailureReason, IngressProtocol,
    PluginExecutionObservation, PluginExecutionOutcome, PluginHeaderMutation, PluginKind,
    PluginPhase, PluginRejection, PluginRejectionReason, PluginRequestView,
    RequestDecision as AdmissionPolicyDecision, RetryAttemptTelemetryReason, TunnelMode,
};
use impulse_errors::{
    BridgeError, PoolError, ProxyError, RetryPolicyDecision, classify_upstream_proxy_error,
    is_idempotent_method,
};
use impulse_lb::{BackendSelectionInput, upstream_pool::UpstreamPool};
#[cfg(feature = "response-cache")]
use impulse_observability::ResponseCacheOutcome;
#[cfg(feature = "response-compression")]
use impulse_observability::ResponseCompressionAction;
pub use impulse_pingora_ingress::PingoraListenerTask;
use impulse_pingora_ingress::{
    ConnectionAdmission, PingoraDrainState, PingoraIngressAdapter, PingoraListenerConfig,
    PingoraRequestContext as IngressRequestContext, PingoraRequestService, PingoraUpstreamProtocol,
    apply_normalized_request_headers, apply_normalized_response_headers, build_response_header,
    classify_pingora_proxy_error, classify_tunnel, configure_tunnel_peer, configure_tunnel_proxy,
    create_listener_service, pingora_peer_protocol, spawn_listener, tunnel_cache_flags,
    tunnel_response_established, write_downstream_response, write_error_response,
    write_local_response,
};
use impulse_plugins::AsyncRequestPluginExecutionGuard;
#[cfg(feature = "response-cache")]
use impulse_plugins::CachePluginFillDecision;
#[cfg(feature = "response-cache")]
use impulse_plugins::ResponseCacheKeyParts;
#[cfg(feature = "external-auth")]
use impulse_plugins::{AsyncRequestPluginDecision, CompiledAsyncRequestPlugin};
#[cfg(feature = "response-cache")]
use impulse_policy::ResponseCacheRepresentation;
#[cfg(feature = "response-cache")]
use pingora_cache::{CacheKey, CacheMeta, CachePhase, NoCacheReason, RespCacheable};
#[cfg(feature = "response-compression")]
use pingora_core::protocols::http::compression::Algorithm;
use pingora_core::{
    Error, HTTPStatus, InternalError, Result,
    apps::{HttpServerApp, HttpServerOptions, ReusedHttpStream, ServerApp},
    protocols::{Stream, http::ServerSession},
    server::{ShutdownWatch, configuration::ServerConf},
    services::listening::Service,
    upstreams::peer::HttpPeer,
};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{HttpProxy, Session, http_proxy};
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

#[cfg(feature = "external-auth")]
use crate::edge_core::request_execution::execute_compiled_external_auth;
#[cfg(feature = "response-cache")]
use crate::edge_core::response_processing::{CacheLookupProcessingInput, process_cache_lookup};
#[cfg(feature = "connection-rate-limit")]
use crate::runtime::connection::plugin::execute_listener_connection_plan;
use crate::{
    Metrics, REQUEST_ID_COUNTER,
    edge_core::{
        body_guardrails::{
            BodyTimeoutKind, REQUEST_BODY_TOO_LARGE_BODY, RESPONSE_BODY_TOO_LARGE_BODY,
            RequestBodyGuardrailConfig, RequestBodyGuardrailDecision, RequestBodyGuardrailInput,
            ResponseBodyGuardrailConfig, ResponseBodyGuardrailDecision, ResponseBodyGuardrailInput,
            checked_request_body_ingress, checked_response_body_guardrails,
            evaluate_request_body_timeouts,
        },
        request_completion::RequestCompletion,
        request_execution::{
            EdgeRequestService, PluginRequestExecutionInput, PluginRequestExecutionOutcome,
            PluginTerminalObservation, RequestExecutionInput, ResolvedRequestPolicy,
            ResolvedRouteTarget, RouteResolutionError,
        },
        request_validation::validate_http_request_parts,
        response_processing::{
            ResponseProcessingInput, ResponseProcessingResult, process_response,
        },
        retry::RetryCoordinator,
    },
    quic_listener::{BackendCandidate, ForwardingSelectionService, TargetResolutionRequest},
    runtime::{
        bundle::{RuntimeBundle, RuntimeBundleHandle},
        connection::{
            auth::PendingHeaderMutation,
            outcome::{
                AdmissionOutcomeClass, BackendHealthObservationInput, BackendOutcomeTarget,
                ClassifiedBackendFailureInput, RouteOutcomeTarget,
                apply_passive_readiness_to_pingora, observe_admission_outcome,
                observe_backend_response_status_and_log,
                observe_classified_backend_failure_and_log, observe_proxy_error_outcome,
                observe_status_outcome,
            },
        },
        listener::Http3Service,
        tls::store::ListenerTlsReloadStore,
    },
};

#[cfg(feature = "response-compression")]
const RESPONSE_GZIP_LEVEL: u32 = 6;

pub(crate) struct PingoraEdgeRequestState {
    pub(crate) runtime: Arc<RuntimeBundle>,
    pub(crate) route: Option<ResolvedRouteTarget>,
    pub(crate) policy: Option<ResolvedRequestPolicy>,
    auth_header_mutations: Vec<PendingHeaderMutation>,
    pub(crate) completion: RequestCompletion,
    terminal_classification: Option<PingoraTerminalClassification>,
    response_processing: Option<ResponseProcessingResult>,
    #[cfg(feature = "response-cache")]
    response_cache_representation: Option<ResponseCacheRepresentation>,
    #[cfg(feature = "response-cache")]
    response_cache_bypass_recorded: bool,
    selected_backend: Option<PingoraSelectedBackend>,
    plugin_execution: AsyncRequestPluginExecutionGuard,
    drain: Arc<PingoraDrainState>,
}

pub(crate) type PingoraRequestContext = IngressRequestContext<PingoraEdgeRequestState>;

enum PingoraTerminalClassification {
    Admission(AdmissionOutcomeClass),
    Error(ProxyError),
}

impl Drop for PingoraEdgeRequestState {
    fn drop(&mut self) {
        self.completion.complete();
        self.drain.request_finished();
    }
}

struct PingoraSelectedBackend {
    address: String,
    pool: Arc<RwLock<UpstreamPool>>,
    index: usize,
    selected_at: Instant,
    finish_status: Option<u16>,
    failure_handled: bool,
    passive_health_recorded: bool,
}

impl Drop for PingoraSelectedBackend {
    fn drop(&mut self) {
        if let Ok(mut pool) = self.pool.write() {
            pool.finish_request(self.index, self.selected_at.elapsed(), self.finish_status);
        }
    }
}

pub(crate) struct PingoraEdgeRequestService {
    runtime: RuntimeBundleHandle,
    drain: Arc<PingoraDrainState>,
}

impl PingoraEdgeRequestService {
    fn process_response_head(
        session: &Session,
        upstream_response: &ResponseHeader,
        ctx: &PingoraRequestContext,
    ) -> Result<ResponseProcessingResult> {
        #[cfg(not(any(feature = "response-cache", feature = "response-compression")))]
        let _ = session;
        #[cfg(any(feature = "response-cache", feature = "response-compression"))]
        let policy = ctx.policy.as_ref().ok_or_else(|| {
            Error::explain(
                InternalError,
                "Pingora ingress request filter did not resolve a request policy",
            )
        })?;
        let method = ctx.method.as_deref().ok_or_else(|| {
            Error::explain(
                InternalError,
                "Pingora ingress request filter did not validate a method",
            )
        })?;
        #[cfg(any(feature = "response-cache", feature = "response-compression"))]
        let request_headers = &session.req_header().headers;
        #[cfg(any(feature = "response-cache", feature = "response-compression"))]
        let request_header =
            |name: &str| request_headers.get(name).map(http::HeaderValue::as_bytes);
        #[cfg(any(feature = "response-cache", feature = "response-compression"))]
        let has_response_plugins = !policy.plugin_plan.cache_policy().is_empty()
            || !policy.plugin_plan.response_policy().is_empty();
        #[cfg(any(feature = "response-cache", feature = "response-compression"))]
        let plugin_request = if has_response_plugins {
            let path = ctx.path.as_deref().ok_or_else(|| {
                Error::explain(
                    InternalError,
                    "Pingora ingress request filter did not validate a path",
                )
            })?;
            let route = ctx.route.as_ref().ok_or_else(|| {
                Error::explain(
                    InternalError,
                    "Pingora ingress request filter did not resolve a route",
                )
            })?;
            let peer_address = session
                .client_addr()
                .and_then(|address| address.as_inet())
                .copied()
                .unwrap_or_else(|| ([0, 0, 0, 0], 0).into());
            Some(PluginRequestView {
                request_id: ctx.request_id,
                generation: policy.plugin_plan.generation(),
                route_id: Some(route.upstream_name.as_ref()),
                upstream_name: route.upstream_name.as_ref(),
                method,
                path,
                authority: ctx.authority.as_deref(),
                peer_address,
                headers: Some(&request_header),
                has_body: ctx.content_length.is_some_and(|length| length > 0)
                    || ctx.body_bytes_received > 0,
                body_replayable: ctx.request_body_replayable,
                ingress_protocol: if session.downstream_session.is_http2() {
                    IngressProtocol::Http2
                } else {
                    IngressProtocol::Http1
                },
            })
        } else {
            None
        };
        let tunnel_response =
            tunnel_response_established(ctx.tunnel_mode, method, upstream_response.status);
        let body_mode = if tunnel_response {
            ResponseBodyMode::TunnelSuccess
        } else if method.eq_ignore_ascii_case("HEAD") {
            ResponseBodyMode::HeadRequest
        } else {
            ResponseBodyMode::Normal
        };
        Ok(process_response(ResponseProcessingInput {
            #[cfg(any(feature = "response-cache", feature = "response-compression"))]
            metrics: &ctx.runtime.shared_state.shared_services().metrics,
            #[cfg(any(feature = "response-cache", feature = "response-compression"))]
            plugin_plan: &policy.plugin_plan,
            #[cfg(any(feature = "response-cache", feature = "response-compression"))]
            plugin_request,
            status: upstream_response.status,
            upstream_headers: &upstream_response.headers,
            body_mode,
            constraints: pingora_response_constraints(tunnel_response),
            #[cfg(feature = "response-compression")]
            request_method: method,
            #[cfg(feature = "response-compression")]
            request_headers: has_response_plugins.then_some(request_headers),
            #[cfg(feature = "response-cache")]
            cache_fill_enabled: ctx.response_cache_representation.is_some(),
            #[cfg(feature = "response-cache")]
            cache_representation: ctx.response_cache_representation.map(|representation| {
                match representation {
                    ResponseCacheRepresentation::Get => "get",
                    ResponseCacheRepresentation::Head => "head",
                }
            }),
            #[cfg(feature = "response-cache")]
            now: std::time::SystemTime::now(),
        }))
    }

    fn select_backend(
        &self,
        session: &Session,
        ctx: &mut PingoraRequestContext,
    ) -> Result<PingoraSelectedBackend> {
        let upstream_name = ctx
            .route
            .as_ref()
            .map(|route| Arc::clone(&route.upstream_name))
            .ok_or_else(|| {
                Error::explain(
                    InternalError,
                    "Pingora ingress request filter did not resolve a route",
                )
            })?;
        let method = ctx.method.clone().ok_or_else(|| {
            Error::explain(
                InternalError,
                "Pingora ingress request filter did not validate a method",
            )
        })?;
        let path = ctx.path.clone().ok_or_else(|| {
            Error::explain(
                InternalError,
                "Pingora ingress request filter did not validate a path",
            )
        })?;
        let authority = ctx.authority.clone();
        let retry_backend = ctx.retry_backend.take();
        let state = ctx.runtime.shared_state.generation_state();
        let pool = state
            .pingora_load_balancing
            .upstream_pool(upstream_name.as_ref())
            .cloned()
            .ok_or_else(|| {
                Error::explain(
                    InternalError,
                    format!("Pingora ingress upstream pool is missing: {upstream_name}"),
                )
            })?;
        let (backend_addr, backend_index) = if let Some((address, index)) = retry_backend {
            let pool = pool.read().map_err(|_| {
                Error::explain(InternalError, "Pingora ingress upstream pool lock poisoned")
            })?;
            if pool.backend_address(index) != Some(address.as_str())
                || !pool.begin_request_if_healthy(index)
            {
                return Error::e_explain(
                    InternalError,
                    "Pingora ingress retry backend is no longer available",
                );
            }
            (address, index)
        } else {
            let request = session.req_header();
            let header_lookup = |name: &str| {
                request
                    .headers
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned)
            };
            let selection_request = TargetResolutionRequest::new(
                &method,
                &path,
                authority.as_deref(),
                None,
                Some(&header_lookup),
            );
            let selector = state
                .pingora_load_balancing
                .selector(upstream_name.as_ref())
                .ok_or_else(|| {
                    ctx.runtime
                        .shared_state
                        .shared_services()
                        .metrics
                        .runtime_observations()
                        .inc_pingora_lb_selector_failure();
                    Error::explain(
                        InternalError,
                        format!("Pingora ingress selector is missing: {upstream_name}"),
                    )
                })?;
            let selected = ForwardingSelectionService::select_backend(
                &selection_request,
                &pool,
                selector,
                ctx.runtime.generation,
                true,
                ctx.runtime.shared_state.shared_services().metrics.as_ref(),
            )
            .map_err(|error| Error::because(InternalError, "backend selection failed", error))?;
            ctx.lb_key = Some(selected.lb_key);
            ctx.runtime
                .shared_state
                .generation_state()
                .resilience
                .retry_budget
                .mark_primary(upstream_name.as_ref());
            (selected.backend_addr, selected.backend_index)
        };
        Ok(PingoraSelectedBackend {
            address: backend_addr,
            pool,
            index: backend_index,
            selected_at: Instant::now(),
            finish_status: None,
            failure_handled: false,
            passive_health_recorded: false,
        })
    }
}

pub(crate) struct PingoraConnectionLimitedApp {
    proxy: Arc<PingoraRequestDeadlineApp>,
    runtime: RuntimeBundleHandle,
    listener_label: String,
    drain: Arc<PingoraDrainState>,
}

struct PingoraRequestDeadlineApp {
    proxy: Arc<HttpProxy<PingoraIngressAdapter<PingoraEdgeRequestService>>>,
    runtime: RuntimeBundleHandle,
    listener_label: String,
}

pub(crate) struct PingoraRuntimeConnectionAdmission {
    runtime: RuntimeBundleHandle,
    listener_label: String,
}

impl std::fmt::Debug for PingoraRuntimeConnectionAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PingoraRuntimeConnectionAdmission")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl ConnectionAdmission for PingoraRuntimeConnectionAdmission {
    async fn should_accept(&self, addr: Option<&std::net::SocketAddr>) -> bool {
        let current = self.runtime.current();
        let metrics = &current.shared_state.shared_services().metrics;
        if current
            .listener_runtime_config(&self.listener_label)
            .is_none()
        {
            metrics.ingress_observations().inc_ingress_rate_limited();
            return false;
        }
        #[cfg(feature = "connection-rate-limit")]
        let admitted = execute_listener_connection_plan(
            current
                .shared_state
                .generation_state()
                .plugin_plans
                .connection(),
            current.generation,
            &self.listener_label,
            addr.copied(),
            metrics,
        )
        .is_ok();
        #[cfg(not(feature = "connection-rate-limit"))]
        let admitted = true;
        if !admitted {
            metrics.ingress_observations().inc_ingress_rate_limited();
        }
        admitted
    }
}

#[async_trait]
impl HttpServerApp for PingoraRequestDeadlineApp {
    async fn process_new_http(
        self: &Arc<Self>,
        session: ServerSession,
        shutdown: &ShutdownWatch,
    ) -> Option<ReusedHttpStream> {
        let current = self.runtime.current();
        let listener = current.listener_runtime_config(&self.listener_label)?;
        tokio::time::timeout(
            listener.policies.timeouts.backend_total_request,
            self.proxy.process_new_http(session, shutdown),
        )
        .await
        .ok()
        .flatten()
    }

    fn server_options(&self) -> Option<&HttpServerOptions> {
        self.proxy.server_options()
    }

    fn h2_options(&self) -> Option<pingora_core::protocols::http::v2::server::H2Options> {
        self.proxy.h2_options()
    }

    async fn http_cleanup(&self) {
        self.proxy.http_cleanup().await;
    }
}

#[async_trait]
impl ServerApp for PingoraConnectionLimitedApp {
    async fn process_new(
        self: &Arc<Self>,
        stream: Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        let current = self.runtime.current();
        let listener = current.listener_runtime_config(&self.listener_label)?;
        let permit = self.drain.try_acquire_connection(
            listener
                .policies
                .transport
                .connection_limits
                .max_active_connections,
        );
        let Some(_permit) = permit else {
            current
                .shared_state
                .shared_services()
                .metrics
                .ingress_observations()
                .inc_connection_cap_reject();
            return None;
        };
        self.proxy.process_new(stream, shutdown).await
    }

    async fn cleanup(&self) {
        self.proxy.cleanup().await;
    }
}

struct RotatingServerCertResolver {
    listener: String,
    store: Arc<ListenerTlsReloadStore>,
}

impl std::fmt::Debug for RotatingServerCertResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RotatingServerCertResolver")
            .field("listener", &self.listener)
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for RotatingServerCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.store
            .certificate_resolver(&self.listener)?
            .resolve(client_hello)
    }
}

pub fn spawn_pingora_ingress_listener(
    runtime: Arc<RuntimeBundleHandle>,
    listener: ListenerRuntimeConfig,
) -> std::result::Result<PingoraListenerTask, String> {
    let address = format!(
        "{}:{}",
        listener.listen.listen.address, listener.listen.listen.port
    );
    let (service, drain) = pingora_ingress_service_for_listener(
        &Arc::new(ServerConf::default()),
        runtime.as_ref().clone(),
        listener,
    )
    .map_err(|error| format!("Failed to create Pingora listener {address}: {error}"))?;
    Ok(spawn_listener(address, service, drain))
}

#[cfg(test)]
pub(crate) fn pingora_ingress_services(
    configuration: &Arc<ServerConf>,
    runtime: RuntimeBundleHandle,
) -> Result<Vec<Service<PingoraConnectionLimitedApp>>> {
    let current = runtime.current();
    let listeners = current.runtime_config.listener_runtime_configs();
    if listeners.is_empty() {
        return Error::e_explain(
            InternalError,
            "Pingora ingress requires a configured listener",
        );
    }
    listeners
        .into_iter()
        .map(|listener| {
            pingora_ingress_service_for_listener(configuration, runtime.clone(), listener)
                .map(|(service, _)| service)
        })
        .collect()
}

fn pingora_ingress_service_for_listener(
    configuration: &Arc<ServerConf>,
    runtime: RuntimeBundleHandle,
    listener: ListenerRuntimeConfig,
) -> Result<(Service<PingoraConnectionLimitedApp>, Arc<PingoraDrainState>)> {
    let listener_label = format!(
        "{}:{}",
        listener.listen.listen.address, listener.listen.listen.port
    );
    let current = runtime.current();
    let tls_store = Arc::clone(&current.shared_state.shared_services().listener_tls_store);
    let connection_admission = Arc::new(PingoraRuntimeConnectionAdmission {
        runtime: runtime.clone(),
        listener_label: listener_label.clone(),
    });
    let tls_state = Http3Service::build_listener_tls_reload_state(&listener).map_err(|error| {
        Error::because(
            InternalError,
            format!("failed to prepare Pingora ingress TLS for '{listener_label}'"),
            error,
        )
    })?;
    tls_store
        .install_listener(listener_label.clone(), tls_state)
        .map_err(|error| {
            Error::because(
                InternalError,
                format!("failed to activate Pingora ingress TLS for '{listener_label}'"),
                error,
            )
        })?;
    let client_certificate_verifier = Http3Service::build_listener_client_cert_verifier(
        &listener.listen.tls,
    )
    .map_err(|error| {
        Error::because(
            InternalError,
            format!(
                "failed to configure Pingora ingress client authentication for '{listener_label}'"
            ),
            error,
        )
    })?;
    let identity = &listener.listen.tls.default_identity;
    let listener_config = PingoraListenerConfig {
        address: listener_label.clone(),
        certificate_path: identity.cert_path.clone(),
        private_key_path: identity.key_path.clone(),
        reuse_port: listener.performance.reuseport,
        certificate_resolver: Arc::new(RotatingServerCertResolver {
            listener: listener_label.clone(),
            store: tls_store,
        }),
        client_certificate_verifier,
    };

    let drain = Arc::new(PingoraDrainState::default());
    let mut proxy = http_proxy(
        configuration,
        PingoraIngressAdapter::new(PingoraEdgeRequestService {
            runtime: runtime.clone(),
            drain: Arc::clone(&drain),
        }),
    );
    configure_tunnel_proxy(&mut proxy);
    let service = create_listener_service(
        PingoraConnectionLimitedApp {
            proxy: Arc::new(PingoraRequestDeadlineApp {
                proxy: Arc::new(proxy),
                runtime: runtime.clone(),
                listener_label: listener_label.clone(),
            }),
            runtime,
            listener_label: listener_label.clone(),
            drain: Arc::clone(&drain),
        },
        listener_config,
        connection_admission,
    )?;
    Ok((service, drain))
}

#[async_trait]
impl PingoraRequestService for PingoraEdgeRequestService {
    type Context = PingoraRequestContext;

    fn new_context(&self) -> Self::Context {
        self.drain.request_started();
        let runtime = self.runtime.current();
        IngressRequestContext::new(
            PingoraEdgeRequestState {
                runtime,
                route: None,
                policy: None,
                auth_header_mutations: Vec::new(),
                completion: RequestCompletion::default(),
                terminal_classification: None,
                response_processing: None,
                #[cfg(feature = "response-cache")]
                response_cache_representation: None,
                #[cfg(feature = "response-cache")]
                response_cache_bypass_recorded: false,
                selected_backend: None,
                plugin_execution: AsyncRequestPluginExecutionGuard::default(),
                drain: Arc::clone(&self.drain),
            },
            REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed),
        )
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::Context) -> Result<bool> {
        let runtime = Arc::clone(&ctx.runtime);
        let state = runtime.shared_state.generation_state();
        let shared = runtime.shared_state.shared_services();
        let client_body_idle = runtime.runtime_config.policies.timeouts.client_body_idle;
        session
            .downstream_session
            .set_read_timeout(Some(client_body_idle));
        session
            .downstream_session
            .set_total_drain_timeout(Some(client_body_idle));
        let request_body_replayable = session.is_body_empty();
        let ingress_protocol = if session.downstream_session.is_http2() {
            IngressProtocol::Http2
        } else {
            IngressProtocol::Http1
        };
        let request = session.req_header();
        let validated = match validate_http_request_parts(
            &request.method,
            &request.uri,
            &request.headers,
            &state.resilience,
        ) {
            Ok(validated) => validated,
            Err((status, body, is_policy)) => {
                ctx.terminal_classification = Some(PingoraTerminalClassification::Error(
                    ProxyError::Bridge(BridgeError::InvalidHeader),
                ));
                shared
                    .metrics
                    .request_observations()
                    .inc_request_validation_reject();
                if is_policy {
                    shared.metrics.policy_observations().inc_policy_denied();
                }
                write_local_response(session, status, body, None, None).await?;
                return Ok(true);
            }
        };

        let Some(peer_address) = session
            .client_addr()
            .and_then(|address| address.as_inet())
            .copied()
        else {
            write_local_response(
                session,
                http::StatusCode::INTERNAL_SERVER_ERROR,
                b"internal proxy error\n",
                None,
                None,
            )
            .await?;
            return Ok(true);
        };
        let request_headers = &request.headers;
        let plugin_header_lookup =
            |name: &str| request_headers.get(name).map(http::HeaderValue::as_bytes);
        let request_service = EdgeRequestService::new(
            &state.routing_index,
            &state.upstream_policies,
            &state.plugin_plans,
            &state.resilience,
            &shared.metrics,
        );
        let execution = match request_service
            .execute_ingress_plugins(
                PluginRequestExecutionInput {
                    request: RequestExecutionInput {
                        method: &validated.method,
                        path: &validated.path,
                        authority: validated.authority.as_deref(),
                        peer_address,
                    },
                    request_id: ctx.request_id,
                    generation: runtime.generation,
                    ingress_protocol,
                    headers: Some(&plugin_header_lookup),
                    #[cfg(feature = "external-auth")]
                    external_auth_headers: None,
                    has_body: !request_body_replayable,
                    body_replayable: request_body_replayable,
                },
                &mut ctx.plugin_execution,
            )
            .await
        {
            Ok(execution) => execution,
            Err(RouteResolutionError::EmptyMethodOrPath) => {
                write_local_response(
                    session,
                    http::StatusCode::BAD_REQUEST,
                    b"invalid request\n",
                    None,
                    None,
                )
                .await?;
                return Ok(true);
            }
            Err(
                RouteResolutionError::NoRoute
                | RouteResolutionError::MissingUpstreamPolicy
                | RouteResolutionError::MissingUpstreamPluginPlan,
            ) => {
                write_local_response(
                    session,
                    http::StatusCode::BAD_GATEWAY,
                    b"no route\n",
                    None,
                    None,
                )
                .await?;
                return Ok(true);
            }
        };
        let route = execution.route;
        let policy = execution.policy;
        shared
            .metrics
            .policy_observations()
            .set_brownout_active(state.resilience.brownout.is_active());
        let tunnel_mode = classify_tunnel(&validated.method, validated.websocket_tunnel);
        ctx.route = Some(route.clone());
        ctx.method = Some(validated.method);
        ctx.path = Some(validated.path);
        ctx.authority = validated.authority;
        ctx.content_length = validated.content_length;
        ctx.tunnel_mode = tunnel_mode;

        let (admission, mut plugin_mutations) = match execution.outcome {
            PluginRequestExecutionOutcome::Admitted {
                admission,
                mutations,
            } => (admission, mutations),
            PluginRequestExecutionOutcome::Rejected {
                rejection,
                observation,
            } => {
                let external_auth_timed_out = rejection.reason()
                    == PluginRejectionReason::ExternalAuthUnavailable
                    && rejection.status() == http::StatusCode::GATEWAY_TIMEOUT;
                match rejection.reason() {
                    PluginRejectionReason::ExternalAuthDenied => shared
                        .metrics
                        .policy_observations()
                        .inc_external_auth_denied(),
                    PluginRejectionReason::ExternalAuthUnavailable if external_auth_timed_out => {
                        shared
                            .metrics
                            .policy_observations()
                            .inc_external_auth_timeout();
                    }
                    PluginRejectionReason::ExternalAuthUnavailable => shared
                        .metrics
                        .policy_observations()
                        .inc_external_auth_error(),
                    _ => {}
                }
                apply_plugin_terminal_observation(
                    ctx,
                    &shared.metrics,
                    observation,
                    external_auth_timed_out,
                );
                write_plugin_rejection_response(session, &rejection).await?;
                return Ok(true);
            }
            PluginRequestExecutionOutcome::AlreadyExecuted => {
                ctx.terminal_classification = Some(PingoraTerminalClassification::Error(
                    ProxyError::Transport("request plugins executed more than once".into()),
                ));
                write_local_response(
                    session,
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                    b"internal proxy error\n",
                    None,
                    None,
                )
                .await?;
                return Ok(true);
            }
        };

        #[cfg(feature = "external-auth")]
        if let Some(external_auth) =
            policy
                .plugin_plan
                .async_request_gate()
                .iter()
                .find_map(|plugin| match plugin {
                    CompiledAsyncRequestPlugin::ExternalAuth(input) => Some(input.clone()),
                    #[cfg(feature = "quota")]
                    CompiledAsyncRequestPlugin::Quota(_) => None,
                })
        {
            let selected = self.select_backend(session, ctx)?;
            let backend_addr = selected.address.clone();
            ctx.selected_backend = Some(selected);
            let method = ctx.method.clone().ok_or_else(|| {
                Error::explain(
                    InternalError,
                    "Pingora ingress request filter did not validate a method",
                )
            })?;
            let path = ctx.path.clone().ok_or_else(|| {
                Error::explain(
                    InternalError,
                    "Pingora ingress request filter did not validate a path",
                )
            })?;
            let started_at = Instant::now();
            let decision = execute_compiled_external_auth(
                crate::runtime::connection::auth::ExternalAuthRequest {
                    method,
                    path,
                    authority: ctx.authority.clone(),
                    headers: request_headers.clone(),
                    upstream_name: route.upstream_name.to_string(),
                    backend_addr: Some(backend_addr),
                },
                &external_auth,
            )
            .await;
            shared
                .metrics
                .plugin_observations()
                .record_execution(PluginExecutionObservation {
                    kind: PluginKind::ExternalAuth,
                    phase: PluginPhase::AsyncRequestGate,
                    outcome: match &decision {
                        AsyncRequestPluginDecision::Continue
                        | AsyncRequestPluginDecision::Mutate(_) => PluginExecutionOutcome::Continue,
                        AsyncRequestPluginDecision::Reject(rejection)
                            if rejection.reason() == PluginRejectionReason::ExternalAuthDenied =>
                        {
                            PluginExecutionOutcome::Reject
                        }
                        AsyncRequestPluginDecision::Reject(_) => PluginExecutionOutcome::Fail,
                    },
                    async_duration: Some(started_at.elapsed()),
                });
            match decision {
                AsyncRequestPluginDecision::Continue => {}
                AsyncRequestPluginDecision::Mutate(mutations) => {
                    plugin_mutations.extend(mutations);
                }
                AsyncRequestPluginDecision::Reject(rejection) => {
                    let external_auth_timed_out = rejection.reason()
                        == PluginRejectionReason::ExternalAuthUnavailable
                        && rejection.status() == http::StatusCode::GATEWAY_TIMEOUT;
                    match rejection.reason() {
                        PluginRejectionReason::ExternalAuthDenied => shared
                            .metrics
                            .policy_observations()
                            .inc_external_auth_denied(),
                        PluginRejectionReason::ExternalAuthUnavailable
                            if external_auth_timed_out =>
                        {
                            shared
                                .metrics
                                .policy_observations()
                                .inc_external_auth_timeout();
                        }
                        PluginRejectionReason::ExternalAuthUnavailable => shared
                            .metrics
                            .policy_observations()
                            .inc_external_auth_error(),
                        _ => {}
                    }
                    apply_plugin_terminal_observation(
                        ctx,
                        &shared.metrics,
                        PluginTerminalObservation::from_rejection_reason(rejection.reason()),
                        external_auth_timed_out,
                    );
                    write_plugin_rejection_response(session, &rejection).await?;
                    return Ok(true);
                }
            }
            shared
                .metrics
                .policy_observations()
                .inc_external_auth_allowed();
        }
        ctx.auth_header_mutations = plugin_mutations
            .iter()
            .map(pending_header_mutation)
            .collect();

        if let Some(response) = admission.rejection_response() {
            match admission {
                AdmissionPolicyDecision::Unauthorized(_) => {
                    ctx.terminal_classification = Some(PingoraTerminalClassification::Admission(
                        AdmissionOutcomeClass::AuthDenied,
                    ));
                    shared.metrics.policy_observations().inc_policy_denied();
                }
                AdmissionPolicyDecision::RateLimited(_) => {
                    ctx.terminal_classification = Some(PingoraTerminalClassification::Admission(
                        AdmissionOutcomeClass::RateLimited,
                    ));
                    shared
                        .metrics
                        .policy_observations()
                        .inc_request_rate_limited()
                }
                AdmissionPolicyDecision::Overloaded(_) => {
                    ctx.terminal_classification = Some(PingoraTerminalClassification::Admission(
                        AdmissionOutcomeClass::OverloadShed { reason: None },
                    ));
                }
                AdmissionPolicyDecision::AdmitReady => {}
            }
            write_local_response(
                session,
                response.status,
                response.body,
                response.www_authenticate,
                response.retry_after_seconds,
            )
            .await?;
            return Ok(true);
        }

        let max_request_body_bytes = runtime
            .runtime_config
            .policies
            .transport
            .max_request_body_bytes;
        if checked_request_body_ingress(
            RequestBodyGuardrailConfig {
                idle_timeout: client_body_idle,
                total_timeout: runtime
                    .runtime_config
                    .policies
                    .timeouts
                    .backend_total_request,
                max_body_bytes: max_request_body_bytes,
                max_buffered_bytes: usize::MAX,
            },
            RequestBodyGuardrailInput {
                elapsed: Duration::ZERO,
                idle_for: Duration::ZERO,
                bytes_received: 0,
                buffered_bytes: 0,
                next_chunk_bytes: 0,
                declared_content_length: ctx.content_length,
                exempt_from_body_size_cap: tunnel_mode.is_tunnel(),
            },
        )
        .is_err()
        {
            write_local_response(
                session,
                http::StatusCode::PAYLOAD_TOO_LARGE,
                REQUEST_BODY_TOO_LARGE_BODY,
                None,
                None,
            )
            .await?;
            return Ok(true);
        }

        #[cfg(feature = "response-compression")]
        if !policy.plugin_plan.response_policy().is_empty() {
            session.upstream_compression.adjust_level(0);
            session
                .upstream_compression
                .adjust_algorithm_level(Algorithm::Gzip, RESPONSE_GZIP_LEVEL);
        }
        ctx.policy = Some(policy);
        ctx.request_body_replayable = request_body_replayable;
        Ok(false)
    }

    #[cfg(feature = "response-cache")]
    fn request_cache_filter(&self, session: &mut Session, ctx: &mut Self::Context) -> Result<()> {
        let (Some(cache), Some(policy), Some(method), Some(path)) = (
            self.runtime.response_cache(),
            ctx.policy.as_ref(),
            ctx.method.as_deref(),
            ctx.path.as_deref(),
        ) else {
            return Ok(());
        };
        let Some(compiled_cache) = policy.plugin_plan.response_cache() else {
            return Ok(());
        };
        let (is_upgrade, is_tunnel) = tunnel_cache_flags(ctx.tunnel_mode);
        let has_body = !session.is_body_empty();
        let Some(route) = ctx.route.as_ref() else {
            return Error::e_explain(
                InternalError,
                "Pingora ingress cache lookup is missing its resolved route",
            );
        };
        let peer_address = session
            .client_addr()
            .and_then(|address| address.as_inet())
            .copied()
            .unwrap_or_else(|| ([0, 0, 0, 0], 0).into());
        let ingress_protocol = if session.downstream_session.is_http2() {
            IngressProtocol::Http2
        } else {
            IngressProtocol::Http1
        };
        let request_headers = &session.req_header().headers;
        let request_header =
            |name: &str| request_headers.get(name).map(http::HeaderValue::as_bytes);
        let representation = process_cache_lookup(CacheLookupProcessingInput {
            metrics: &ctx.runtime.shared_state.shared_services().metrics,
            plugin_plan: &policy.plugin_plan,
            plugin_request: PluginRequestView {
                request_id: ctx.request_id,
                generation: policy.plugin_plan.generation(),
                route_id: Some(route.upstream_name.as_ref()),
                upstream_name: route.upstream_name.as_ref(),
                method,
                path,
                authority: ctx.authority.as_deref(),
                peer_address,
                headers: Some(&request_header),
                has_body,
                body_replayable: ctx.request_body_replayable,
                ingress_protocol,
            },
            headers: request_headers,
            is_upgrade,
            is_tunnel,
        });
        let Ok(representation) = representation else {
            ctx.runtime
                .shared_state
                .shared_services()
                .metrics
                .ingress_observations()
                .record_response_cache_outcome(ResponseCacheOutcome::Bypass);
            ctx.response_cache_bypass_recorded = true;
            return Ok(());
        };
        cache.enable(&mut session.cache, compiled_cache.max_object_bytes());
        ctx.response_cache_representation = Some(representation);
        Ok(())
    }

    #[cfg(feature = "response-cache")]
    fn cache_key_callback(&self, session: &Session, ctx: &mut Self::Context) -> Result<CacheKey> {
        let representation = ctx.response_cache_representation.ok_or_else(|| {
            Error::explain(InternalError, "response cache representation is missing")
        })?;
        let authority = ctx
            .authority
            .as_deref()
            .ok_or_else(|| Error::explain(InternalError, "response cache authority is missing"))?;
        let path = ctx.path.as_deref().ok_or_else(|| {
            Error::explain(InternalError, "response cache request target is missing")
        })?;
        let compiled_cache = ctx
            .policy
            .as_ref()
            .and_then(|policy| policy.plugin_plan.response_cache())
            .ok_or_else(|| Error::explain(InternalError, "response cache plugin is missing"))?;
        let accept_encoding = session
            .req_header()
            .headers
            .get_all(http::header::ACCEPT_ENCODING)
            .iter()
            .map(|value| value.to_str())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| {
                Error::because(
                    InternalError,
                    "response cache Accept-Encoding is invalid",
                    error,
                )
            })?
            .join(",");
        compiled_cache
            .key(ResponseCacheKeyParts {
                scheme: "https",
                authority,
                path_and_query: path,
                representation,
                accept_encoding: (!accept_encoding.is_empty()).then_some(accept_encoding.as_str()),
            })
            .map(|primary| CacheKey::new(primary, ""))
            .ok_or_else(|| Error::explain(InternalError, "response cache key is invalid"))
    }

    #[cfg(feature = "response-cache")]
    fn response_cache_filter(
        &self,
        session: &Session,
        response: &ResponseHeader,
        ctx: &mut Self::Context,
    ) -> Result<RespCacheable> {
        let processed = match ctx.response_processing.clone() {
            Some(processed) => processed,
            None => Self::process_response_head(session, response, ctx)?,
        };
        let CachePluginFillDecision::Store {
            stored_at,
            fresh_until,
        } = processed.cache
        else {
            ctx.runtime
                .shared_state
                .shared_services()
                .metrics
                .ingress_observations()
                .record_response_cache_outcome(ResponseCacheOutcome::Rejection);
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                "impulse_policy",
            )));
        };
        let normalized = build_response_header(response.status, &processed.headers)?;
        Ok(RespCacheable::Cacheable(CacheMeta::new(
            fresh_until,
            stored_at,
            0,
            0,
            normalized,
        )))
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::Context,
    ) -> Result<()> {
        let now = Instant::now();
        let timeouts = &ctx.runtime.runtime_config.policies.timeouts;
        let timeout = evaluate_request_body_timeouts(
            RequestBodyGuardrailConfig {
                idle_timeout: timeouts.client_body_idle,
                total_timeout: timeouts.backend_total_request,
                max_body_bytes: usize::MAX,
                max_buffered_bytes: usize::MAX,
            },
            RequestBodyGuardrailInput {
                elapsed: ctx.started_at.elapsed(),
                idle_for: now.saturating_duration_since(ctx.request_body_last_progress_at),
                bytes_received: ctx.body_bytes_received,
                buffered_bytes: 0,
                next_chunk_bytes: body.as_ref().map_or(0, Bytes::len),
                declared_content_length: ctx.content_length,
                exempt_from_body_size_cap: ctx.tunnel_mode.is_tunnel(),
            },
        );
        if let RequestBodyGuardrailDecision::Timeout { kind } = timeout {
            ctx.terminal_classification =
                Some(PingoraTerminalClassification::Error(ProxyError::Timeout));
            let detail = match kind {
                BodyTimeoutKind::Idle => "request body idle timeout",
                BodyTimeoutKind::Total => "request body total timeout",
            };
            write_error_response(
                session,
                http::StatusCode::REQUEST_TIMEOUT,
                Bytes::from(format!("{detail}\n")),
            )
            .await?;
            return Error::e_explain(HTTPStatus(408), detail);
        }
        let max_request_body_bytes = ctx
            .runtime
            .runtime_config
            .policies
            .transport
            .max_request_body_bytes;
        let next = checked_request_body_ingress(
            RequestBodyGuardrailConfig {
                idle_timeout: timeouts.client_body_idle,
                total_timeout: timeouts.backend_total_request,
                max_body_bytes: max_request_body_bytes,
                max_buffered_bytes: usize::MAX,
            },
            RequestBodyGuardrailInput {
                elapsed: Duration::ZERO,
                idle_for: Duration::ZERO,
                bytes_received: ctx.body_bytes_received,
                buffered_bytes: 0,
                next_chunk_bytes: body.as_ref().map_or(0, Bytes::len),
                declared_content_length: ctx.content_length,
                exempt_from_body_size_cap: ctx.tunnel_mode.is_tunnel(),
            },
        );
        match next {
            Ok(next) => {
                ctx.body_bytes_received = next.bytes_received;
                if body.as_ref().is_some_and(|body| !body.is_empty()) {
                    ctx.request_body_last_progress_at = now;
                }
                Ok(())
            }
            Err(_) => {
                write_error_response(
                    session,
                    http::StatusCode::PAYLOAD_TOO_LARGE,
                    Bytes::from_static(REQUEST_BODY_TOO_LARGE_BODY),
                )
                .await?;
                Error::e_explain(HTTPStatus(413), "request body too large")
            }
        }
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::Context,
    ) -> Result<Box<HttpPeer>> {
        if ctx.retry_backend.is_some() || ctx.selected_backend.is_none() {
            ctx.selected_backend = Some(self.select_backend(session, ctx)?);
        }
        let backend_addr = ctx
            .selected_backend
            .as_ref()
            .ok_or_else(|| Error::explain(InternalError, "backend selection is missing"))?
            .address
            .clone();
        let mut peer = ctx
            .runtime
            .shared_state
            .shared_services()
            .transport_pool
            .pingora_peer(&backend_addr, ctx.runtime.generation)
            .map_err(|error| {
                Error::because(InternalError, "backend peer creation failed", error)
            })?;
        configure_tunnel_peer(ctx.tunnel_mode, &mut peer);
        let body_idle = ctx
            .runtime
            .runtime_config
            .policies
            .timeouts
            .backend_body_idle;
        peer.options.read_timeout = Some(
            peer.options
                .read_timeout
                .map_or(body_idle, |timeout| timeout.min(body_idle)),
        );
        Ok(Box::new(peer))
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        peer: &HttpPeer,
        ctx: &mut Self::Context,
        error: Box<Error>,
    ) -> Box<Error> {
        handle_pingora_proxy_failure(ctx, error, pingora_peer_protocol(peer), false, true)
    }

    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        error: Box<Error>,
        ctx: &mut Self::Context,
        reused: bool,
    ) -> Box<Error> {
        handle_pingora_proxy_failure(
            ctx,
            error,
            pingora_peer_protocol(peer),
            reused,
            session.response_written().is_none(),
        )
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::Context,
    ) -> Result<()> {
        let policy = ctx.policy.as_ref().ok_or_else(|| {
            Error::explain(
                InternalError,
                "Pingora ingress request filter did not resolve request policy",
            )
        })?;
        let selected = ctx.selected_backend.as_ref().ok_or_else(|| {
            Error::explain(
                InternalError,
                "Pingora ingress upstream peer did not select a backend",
            )
        })?;
        let method = ctx.method.as_deref().ok_or_else(|| {
            Error::explain(
                InternalError,
                "Pingora ingress request filter did not validate a method",
            )
        })?;
        let path = ctx.path.as_deref().ok_or_else(|| {
            Error::explain(
                InternalError,
                "Pingora ingress request filter did not validate a path",
            )
        })?;
        let endpoint = ctx
            .runtime
            .shared_state
            .generation_state()
            .backend_endpoints
            .get(&selected.address)
            .ok_or_else(|| {
                Error::explain(
                    InternalError,
                    format!(
                        "Pingora ingress backend endpoint is missing: {}",
                        selected.address
                    ),
                )
            })?;
        let client_addr = session
            .client_addr()
            .and_then(|address| address.as_inet())
            .copied()
            .ok_or_else(|| {
                Error::explain(InternalError, "Pingora ingress client address is missing")
            })?;
        let downstream_request = session.req_header();
        let headers = bridge_headers(&downstream_request.headers);
        let traceparent = downstream_request
            .headers
            .get("traceparent")
            .and_then(|value| value.to_str().ok());
        let target = crate::runtime::subsystem_mapping::bridge_request_target(
            endpoint,
            &policy.host_policy,
            &policy.forwarded_header_policy,
        );
        let auth_header_mutations = ctx
            .auth_header_mutations
            .iter()
            .map(|mutation| match mutation {
                PendingHeaderMutation::Upsert { name, value } => {
                    impulse_bridge::request::RequestHeaderMutationRef {
                        name: name.as_slice(),
                        value: Some(value.as_slice()),
                    }
                }
                PendingHeaderMutation::Remove { name } => {
                    impulse_bridge::request::RequestHeaderMutationRef {
                        name: name.as_slice(),
                        value: None,
                    }
                }
            })
            .collect::<Vec<_>>();
        let input = impulse_bridge::request::RequestBuildInput {
            method,
            path,
            authority: ctx.authority.as_deref(),
            headers: &headers,
            auth_header_mutations: &auth_header_mutations,
            body: BoxBody::new(Full::<Bytes>::new(Bytes::new())),
            body_mode: impulse_bridge::request::RequestBuildInput::<
                BoxBody<Bytes, Infallible>,
            >::body_mode_for_length(ctx.content_length),
            trace: impulse_bridge::request::RequestTraceContext {
                request_id: ctx.request_id,
                traceparent,
            },
            forwarded: impulse_bridge::request::RequestForwardedContext { client_addr },
        };
        let normalized = match endpoint.scheme() {
            BackendScheme::Http => impulse_bridge::request::build_h1_request(target, input),
            BackendScheme::Https => {
                impulse_bridge::request::build_h2_request_for_target(target, input)
            }
        }
        .map_err(|error| {
            Error::because(
                InternalError,
                "upstream request normalization failed",
                error,
            )
        })?;

        apply_normalized_request_headers(upstream_request, normalized.headers())
    }

    async fn adjust_upstream_modules(
        &self,
        session: &mut Session,
        upstream_response: &ResponseHeader,
        _end_of_stream: bool,
        ctx: &mut Self::Context,
    ) -> Result<()> {
        if upstream_response.status.is_informational() {
            return Ok(());
        }
        ctx.response_content_length = upstream_response
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());
        let processed = Self::process_response_head(session, upstream_response, ctx)?;
        #[cfg(feature = "response-compression")]
        {
            ctx.runtime
                .shared_state
                .shared_services()
                .metrics
                .ingress_observations()
                .record_response_compression_outcome(processed.compression.action);
            session.upstream_compression.adjust_level(0);
            if matches!(
                processed.compression.action,
                ResponseCompressionAction::Gzip
            ) {
                session
                    .upstream_compression
                    .adjust_algorithm_level(Algorithm::Gzip, RESPONSE_GZIP_LEVEL);
            }
        }
        ctx.response_processing = Some(processed);
        Ok(())
    }

    async fn upstream_response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::Context,
    ) -> Result<()> {
        let now = Instant::now();
        let timeouts = &ctx.runtime.runtime_config.policies.timeouts;
        let backend_total_request = timeouts.backend_total_request;
        let backend_body_idle = timeouts.backend_body_idle;
        let backend_body_total = timeouts.backend_body_total;
        if ctx
            .selected_backend
            .as_ref()
            .is_some_and(|selected| selected.selected_at.elapsed() >= backend_total_request)
        {
            ctx.terminal_classification =
                Some(PingoraTerminalClassification::Error(ProxyError::Timeout));
            return Error::e_explain(HTTPStatus(504), "upstream request total timeout");
        }
        let method = ctx.method.as_deref().ok_or_else(|| {
            Error::explain(
                InternalError,
                "Pingora ingress request filter did not validate a method",
            )
        })?;
        let tunnel_response =
            tunnel_response_established(ctx.tunnel_mode, method, upstream_response.status);
        let content_length = ctx.response_content_length.or_else(|| {
            upstream_response
                .headers
                .get(http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<usize>().ok())
        });
        let current_response = Self::process_response_head(session, upstream_response, ctx)?;
        let mut processed = ctx
            .response_processing
            .clone()
            .unwrap_or_else(|| current_response.clone());
        processed.headers = current_response.headers;
        if upstream_response.status != http::StatusCode::NOT_MODIFIED {
            ctx.response_processing = Some(processed.clone());
        }
        let body_suppressed = !processed.body_forwarding_enabled;
        let max_response_body_bytes = ctx
            .runtime
            .runtime_config
            .policies
            .transport
            .max_response_body_bytes;
        if checked_response_body_guardrails(
            ResponseBodyGuardrailConfig {
                idle_timeout: backend_body_idle,
                total_timeout: backend_body_total,
                max_body_bytes: max_response_body_bytes,
                unknown_length_prebuffer_bytes: max_response_body_bytes,
                chunk_bytes: usize::MAX,
            },
            ResponseBodyGuardrailInput {
                elapsed: Duration::ZERO,
                idle_for: Duration::ZERO,
                bytes_received: 0,
                prebuffered_bytes: 0,
                next_chunk_bytes: 0,
                declared_content_length: content_length,
                headers_emitted: false,
                progressive_emission_allowed: !processed.emit_end_stream_on_headers,
                body_forwarding_enabled: !body_suppressed,
                exempt_from_body_size_cap: tunnel_response,
            },
        )
        .is_err()
        {
            ctx.terminal_classification =
                Some(PingoraTerminalClassification::Error(ProxyError::Pool(
                    PoolError::BackendOverloaded("response body limit exceeded".into()),
                )));
            write_error_response(
                session,
                http::StatusCode::SERVICE_UNAVAILABLE,
                Bytes::from_static(RESPONSE_BODY_TOO_LARGE_BODY),
            )
            .await?;
            return Error::e_explain(HTTPStatus(503), "upstream response body too large");
        }

        apply_normalized_response_headers(upstream_response, &processed.headers)?;
        ctx.response_body_bytes_received = 0;
        ctx.response_body_started_at = Some(now);
        ctx.response_body_last_progress_at = Some(now);
        ctx.response_body_suppressed = body_suppressed;
        ctx.response_body_limit_exempt = tunnel_response;
        ctx.response_content_length = content_length;
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        response: &mut ResponseHeader,
        ctx: &mut Self::Context,
    ) -> Result<()> {
        if response.status == http::StatusCode::SWITCHING_PROTOCOLS
            && ctx.tunnel_mode == TunnelMode::Websocket
        {
            response.insert_header(http::header::CONNECTION, "upgrade")?;
            response.insert_header(http::header::UPGRADE, "websocket")?;
        }
        Ok(())
    }

    fn upstream_response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::Context,
    ) -> Result<Option<Duration>> {
        if ctx.response_body_suppressed {
            *body = None;
            return Ok(None);
        }

        let now = Instant::now();
        let timeouts = &ctx.runtime.runtime_config.policies.timeouts;
        if ctx.selected_backend.as_ref().is_some_and(|selected| {
            selected.selected_at.elapsed() >= timeouts.backend_total_request
        }) {
            *body = None;
            ctx.terminal_classification =
                Some(PingoraTerminalClassification::Error(ProxyError::Timeout));
            return Error::e_explain(HTTPStatus(504), "upstream request total timeout");
        }
        let response_started_at = ctx.response_body_started_at.ok_or_else(|| {
            Error::explain(
                InternalError,
                "upstream response body started without headers",
            )
        })?;
        let response_last_progress_at = ctx.response_body_last_progress_at.ok_or_else(|| {
            Error::explain(InternalError, "upstream response body progress is missing")
        })?;
        let response_elapsed = now.saturating_duration_since(response_started_at);
        if response_elapsed >= timeouts.backend_body_total {
            *body = None;
            ctx.terminal_classification =
                Some(PingoraTerminalClassification::Error(ProxyError::Timeout));
            return Error::e_explain(HTTPStatus(504), "upstream response body total timeout");
        }
        let next = checked_response_body_guardrails(
            ResponseBodyGuardrailConfig {
                idle_timeout: timeouts.backend_body_idle,
                total_timeout: timeouts.backend_body_total,
                max_body_bytes: ctx
                    .runtime
                    .runtime_config
                    .policies
                    .transport
                    .max_response_body_bytes,
                unknown_length_prebuffer_bytes: usize::MAX,
                chunk_bytes: usize::MAX,
            },
            ResponseBodyGuardrailInput {
                elapsed: response_elapsed,
                idle_for: now.saturating_duration_since(response_last_progress_at),
                bytes_received: ctx.response_body_bytes_received,
                prebuffered_bytes: 0,
                next_chunk_bytes: body.as_ref().map_or(0, Bytes::len),
                declared_content_length: ctx.response_content_length,
                headers_emitted: true,
                progressive_emission_allowed: true,
                body_forwarding_enabled: true,
                exempt_from_body_size_cap: ctx.response_body_limit_exempt,
            },
        );
        match next {
            Ok(next) => {
                ctx.response_body_bytes_received = next.next_state.bytes_received;
                if body.as_ref().is_some_and(|body| !body.is_empty()) {
                    ctx.response_body_last_progress_at = Some(now);
                }
                Ok(None)
            }
            Err(ResponseBodyGuardrailDecision::Timeout { kind }) => {
                *body = None;
                ctx.terminal_classification =
                    Some(PingoraTerminalClassification::Error(ProxyError::Timeout));
                let detail = match kind {
                    BodyTimeoutKind::Idle => "upstream response body idle timeout",
                    BodyTimeoutKind::Total => "upstream response body total timeout",
                };
                Error::e_explain(HTTPStatus(504), detail)
            }
            Err(_) => {
                *body = None;
                ctx.terminal_classification =
                    Some(PingoraTerminalClassification::Error(ProxyError::Pool(
                        PoolError::BackendOverloaded("response body limit exceeded".into()),
                    )));
                Error::e_explain(HTTPStatus(503), "upstream response body too large")
            }
        }
    }

    fn upstream_response_trailer_filter(
        &self,
        _session: &mut Session,
        upstream_trailers: &mut http::HeaderMap,
        ctx: &mut Self::Context,
    ) -> Result<()> {
        let normalized = normalize_response_trailers(
            upstream_trailers,
            pingora_response_constraints(ctx.response_body_limit_exempt),
        );
        upstream_trailers.clear();
        for trailer in normalized {
            upstream_trailers.append(trailer.name, trailer.value);
        }
        Ok(())
    }

    async fn logging(&self, session: &mut Session, error: Option<&Error>, ctx: &mut Self::Context) {
        if !ctx.completion.complete() {
            return;
        }

        let status = session.response_written().map(|response| response.status);
        if let Some(selected) = ctx.selected_backend.as_mut() {
            selected.finish_status = status.map(|status| status.as_u16());
        }
        if ctx.terminal_classification.is_none()
            && let Some(status) = status
        {
            record_pingora_backend_response(ctx, status);
        }
        let route = ctx
            .route
            .as_ref()
            .map_or(RouteOutcomeTarget::UNROUTED, |route| RouteOutcomeTarget {
                route: route.upstream_name.as_ref(),
            });
        let backend = ctx
            .selected_backend
            .as_ref()
            .map(|selected| BackendOutcomeTarget {
                upstream: route.route,
                backend_addr: Some(selected.address.as_str()),
                backend_index: Some(selected.index),
            });
        let metrics = &ctx.runtime.shared_state.shared_services().metrics;
        #[cfg(feature = "response-cache")]
        match session.cache.phase() {
            CachePhase::Hit | CachePhase::Revalidated => {
                metrics
                    .ingress_observations()
                    .record_response_cache_outcome(ResponseCacheOutcome::Hit);
            }
            CachePhase::Miss => {
                metrics
                    .ingress_observations()
                    .record_response_cache_outcome(ResponseCacheOutcome::Miss);
            }
            CachePhase::Expired => {
                metrics
                    .ingress_observations()
                    .record_response_cache_outcome(ResponseCacheOutcome::Expiry);
                metrics
                    .ingress_observations()
                    .record_response_cache_outcome(ResponseCacheOutcome::Miss);
            }
            CachePhase::Stale | CachePhase::StaleUpdating => {
                metrics
                    .ingress_observations()
                    .record_response_cache_outcome(ResponseCacheOutcome::Expiry);
                metrics
                    .ingress_observations()
                    .record_response_cache_outcome(ResponseCacheOutcome::Hit);
            }
            CachePhase::Bypass if !ctx.response_cache_bypass_recorded => {
                metrics
                    .ingress_observations()
                    .record_response_cache_outcome(ResponseCacheOutcome::Bypass);
            }
            CachePhase::Disabled(_)
            | CachePhase::Uninit
            | CachePhase::CacheKey
            | CachePhase::Bypass
            | CachePhase::RevalidatedNoCache(_) => {}
        }
        #[cfg(feature = "response-cache")]
        if session.cache.lock_duration().is_some() {
            metrics
                .ingress_observations()
                .record_response_cache_outcome(ResponseCacheOutcome::LockWait);
        }
        #[cfg(feature = "response-compression")]
        if let Some(("gzip", input, output, _duration)) = session.upstream_compression.get_info() {
            metrics
                .ingress_observations()
                .add_response_compression_bytes(input, output);
        }
        match (&ctx.terminal_classification, status) {
            (Some(PingoraTerminalClassification::Admission(outcome)), Some(status)) => {
                let _ = observe_admission_outcome(
                    metrics,
                    route,
                    backend,
                    ctx.started_at.elapsed(),
                    status,
                    *outcome,
                );
            }
            (Some(PingoraTerminalClassification::Error(proxy_error)), status) => {
                let _ = observe_proxy_error_outcome(
                    metrics,
                    route,
                    backend,
                    ctx.started_at.elapsed(),
                    status,
                    proxy_error,
                    None,
                );
            }
            (None, Some(status)) => {
                let _ = observe_status_outcome(
                    metrics,
                    route,
                    backend,
                    ctx.started_at.elapsed(),
                    status,
                );
            }
            (None, None) => {
                let proxy_error = ProxyError::Transport(error.map_or_else(
                    || "request completed without a response".to_string(),
                    ToString::to_string,
                ));
                let _ = observe_proxy_error_outcome(
                    metrics,
                    route,
                    backend,
                    ctx.started_at.elapsed(),
                    None,
                    &proxy_error,
                    None,
                );
            }
            (Some(PingoraTerminalClassification::Admission(_)), None) => {
                let proxy_error = ProxyError::Transport(
                    "admission response did not reach the downstream".to_string(),
                );
                let _ = observe_proxy_error_outcome(
                    metrics,
                    route,
                    backend,
                    ctx.started_at.elapsed(),
                    None,
                    &proxy_error,
                    None,
                );
            }
        }

        log::info!(
            "request_id={} method={} path={} status={} backend={} upstream={} latency_ms={} retries={} error={}",
            ctx.request_id,
            ctx.method.as_deref().unwrap_or("-"),
            ctx.path.as_deref().unwrap_or("-"),
            status.map_or(0, |status| status.as_u16()),
            ctx.selected_backend
                .as_ref()
                .map_or("-", |selected| selected.address.as_str()),
            route.route,
            ctx.started_at.elapsed().as_millis(),
            ctx.retry_count,
            error.map_or_else(|| "-".to_string(), ToString::to_string),
        );
        ctx.selected_backend.take();
    }
}

fn handle_pingora_proxy_failure(
    ctx: &mut PingoraRequestContext,
    mut error: Box<Error>,
    protocol: PingoraUpstreamProtocol,
    reused: bool,
    retry_safe: bool,
) -> Box<Error> {
    let Some(selected) = ctx.selected_backend.as_mut() else {
        error.set_retry(false);
        return error;
    };
    if selected.failure_handled {
        error.set_retry(false);
        return error;
    }
    selected.failure_handled = true;
    let proxy_error = classify_pingora_proxy_error(&error, protocol, reused);
    if let Some(selected) = ctx.selected_backend.as_mut() {
        selected.finish_status = Some(if matches!(proxy_error, ProxyError::Timeout) {
            http::StatusCode::SERVICE_UNAVAILABLE.as_u16()
        } else {
            http::StatusCode::BAD_GATEWAY.as_u16()
        });
    }
    record_pingora_backend_failure(ctx, &proxy_error);

    let Some(selected) = ctx.selected_backend.as_ref() else {
        error.set_retry(false);
        return error;
    };
    let route_name = ctx
        .route
        .as_ref()
        .map(|route| route.upstream_name.as_ref())
        .unwrap_or("unrouted");
    let selector = ctx
        .runtime
        .shared_state
        .generation_state()
        .pingora_load_balancing
        .selector(route_name);
    let metrics = ctx.runtime.shared_state.shared_services().metrics.as_ref();
    let selection = match selector {
        Some(selector) => Some(ForwardingSelectionService::select_backend_excluding(
            selector,
            &selected.pool,
            BackendSelectionInput::new(
                ctx.runtime.generation,
                ctx.lb_key.as_deref().unwrap_or_default(),
                &[selected.index],
                false,
            ),
            metrics,
        )),
        None => {
            metrics
                .runtime_observations()
                .inc_pingora_lb_selector_failure();
            None
        }
    };
    let (retry_backend, alternate_failure) = match selection {
        Some(Ok(Some(BackendCandidate { address, index }))) => (Some((address, index)), None),
        Some(Ok(None)) => match selected.pool.read() {
            Ok(pool) if pool.membership_summary().healthy_backends == 0 => {
                (None, Some(AlternateBackendFailureReason::NoHealthyBackends))
            }
            Ok(_) => (
                None,
                Some(AlternateBackendFailureReason::OnlyExcludedBackendsHealthy),
            ),
            Err(_) => (None, Some(AlternateBackendFailureReason::PoolUnavailable)),
        },
        Some(Err(_)) | None => (None, Some(AlternateBackendFailureReason::PoolUnavailable)),
    };
    let retry = RetryCoordinator::new(
        ctx.method.as_deref().is_some_and(is_idempotent_method),
        ctx.request_body_replayable && retry_safe,
        false,
        false,
        ctx.tunnel_mode.is_tunnel(),
    );
    let decision = retry.retry_after_error(
        &proxy_error,
        ctx.retry_count,
        route_name,
        &ctx.runtime
            .shared_state
            .generation_state()
            .resilience
            .retry_budget,
        retry_backend.is_some(),
        alternate_failure,
    );
    let metrics = &ctx.runtime.shared_state.shared_services().metrics;
    let retrying = match decision {
        RetryPolicyDecision::Retry { reason } => {
            metrics
                .policy_observations()
                .inc_retry_attempt(RetryAttemptTelemetryReason::from(reason));
            ctx.retry_count = ctx.retry_count.saturating_add(1);
            ctx.retry_backend = retry_backend;
            error.set_retry(true);
            true
        }
        RetryPolicyDecision::DoNotRetry { denial } => {
            if let Some(denial) = denial {
                metrics.policy_observations().inc_retry_denied(denial);
            }
            error.set_retry(false);
            false
        }
    };
    if retrying {
        ctx.terminal_classification = None;
    } else {
        ctx.terminal_classification = Some(PingoraTerminalClassification::Error(proxy_error));
    }
    error
}

fn record_pingora_backend_failure(ctx: &mut PingoraRequestContext, error: &ProxyError) {
    let Some(selected) = ctx.selected_backend.as_ref() else {
        return;
    };
    if selected.passive_health_recorded {
        return;
    }
    let Some(route) = ctx.route.as_ref() else {
        return;
    };
    let Some(classified) = classify_upstream_proxy_error(error) else {
        return;
    };
    let upstream_name = Arc::clone(&route.upstream_name);
    let backend_addr = selected.address.clone();
    let backend_index = selected.index;
    let upstream_pool = Arc::clone(&selected.pool);
    if let Some(selected) = ctx.selected_backend.as_mut() {
        selected.passive_health_recorded = true;
    }
    let shared = ctx.runtime.shared_state.shared_services();
    let transition = observe_classified_backend_failure_and_log(ClassifiedBackendFailureInput {
        metrics_phase: "pingora_ingress",
        upstream_name: upstream_name.as_ref(),
        backend_addr: &backend_addr,
        backend_index,
        upstream_pool: Some(&upstream_pool),
        metrics: shared.metrics.as_ref(),
        classified: &classified,
    });
    apply_passive_readiness_to_pingora(
        ctx.runtime
            .shared_state
            .generation_state()
            .pingora_load_balancing
            .as_ref(),
        &backend_addr,
        transition,
    );
}

fn record_pingora_backend_response(ctx: &mut PingoraRequestContext, status: http::StatusCode) {
    let Some(selected) = ctx.selected_backend.as_ref() else {
        return;
    };
    if selected.passive_health_recorded {
        return;
    }
    let backend_addr = selected.address.clone();
    let backend_index = selected.index;
    let upstream_pool = Arc::clone(&selected.pool);
    if let Some(selected) = ctx.selected_backend.as_mut() {
        selected.passive_health_recorded = true;
    }
    if status.is_server_error() {
        ctx.runtime
            .shared_state
            .shared_services()
            .metrics
            .policy_observations()
            .inc_health_failure(HealthFailureReason::HttpStatus5xx);
    }
    let transition = observe_backend_response_status_and_log(BackendHealthObservationInput {
        backend_addr: &backend_addr,
        backend_index,
        upstream_pool: Some(&upstream_pool),
        status,
    });
    apply_passive_readiness_to_pingora(
        ctx.runtime
            .shared_state
            .generation_state()
            .pingora_load_balancing
            .as_ref(),
        &backend_addr,
        transition,
    );
}

fn pingora_response_constraints(preserve_upgrade: bool) -> ResponseProtocolConstraints {
    ResponseProtocolConstraints {
        protocol: ResponseNormalizationProtocol::Http1,
        preserve_upgrade,
    }
}

fn bridge_headers(headers: &http::HeaderMap) -> Vec<quiche::h3::Header> {
    headers
        .iter()
        .map(|(name, value)| quiche::h3::Header::new(name.as_str().as_bytes(), value.as_bytes()))
        .collect()
}

fn pending_header_mutation(mutation: &PluginHeaderMutation) -> PendingHeaderMutation {
    match mutation.value() {
        Some(value) => PendingHeaderMutation::Upsert {
            name: mutation.name().as_str().as_bytes().to_vec(),
            value: value.as_bytes().to_vec(),
        },
        None => PendingHeaderMutation::Remove {
            name: mutation.name().as_str().as_bytes().to_vec(),
        },
    }
}

fn apply_plugin_terminal_observation(
    ctx: &mut PingoraRequestContext,
    metrics: &Metrics,
    observation: PluginTerminalObservation,
    timed_out: bool,
) {
    let outcome = match observation {
        PluginTerminalObservation::AuthDenied => {
            metrics.policy_observations().inc_policy_denied();
            AdmissionOutcomeClass::AuthDenied
        }
        PluginTerminalObservation::RateLimited => {
            metrics.policy_observations().inc_request_rate_limited();
            AdmissionOutcomeClass::RateLimited
        }
        PluginTerminalObservation::QuotaDenied => {
            metrics.policy_observations().inc_request_rate_limited();
            AdmissionOutcomeClass::QuotaDenied
        }
        PluginTerminalObservation::Failed => AdmissionOutcomeClass::Failed { timed_out },
    };
    ctx.terminal_classification = Some(PingoraTerminalClassification::Admission(outcome));
}

async fn write_plugin_rejection_response(
    session: &mut Session,
    rejection: &PluginRejection,
) -> Result<()> {
    let headers = rejection
        .headers()
        .iter()
        .filter_map(|header| {
            header
                .value()
                .to_str()
                .ok()
                .map(|value| (header.name().as_str().to_string(), value.to_string()))
        })
        .collect::<Vec<_>>();
    write_downstream_response(
        session,
        rejection.status(),
        &headers,
        rejection.body(),
        None,
    )
    .await
}

#[cfg(test)]
mod tests;
