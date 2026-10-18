use std::{
    convert::Infallible,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{Full, combinators::BoxBody};
use impulse_bridge::response::{
    ResponseBodyMode, ResponseBodyPolicy, ResponseNormalizationInput,
    ResponseNormalizationProtocol, ResponseProtocolConstraints, UpstreamResponseView,
    normalize_response_trailers, normalize_upstream_response,
};
use impulse_config::{backend_endpoint::BackendScheme, runtime::ListenerRuntimeConfig};
use impulse_errors::{
    BridgeError, PoolError, ProxyError, RetryAttemptTelemetryReason, RetryPolicyDecision,
    RetryPolicyDenialReason, classify_upstream_proxy_error, is_idempotent_method,
};
use impulse_lb::{alternate_backend::AlternateBackendFailureReason, upstream_pool::UpstreamPool};
use impulse_transport::{classify_pingora_h1_error, classify_pingora_h2_error};
use pingora_core::{
    Error, HTTPStatus, InternalError, Result,
    apps::HttpServerOptions,
    listeners::{ConnectionFilter, tls::TlsSettings},
    protocols::http::compression::Algorithm,
    server::configuration::ServerConf,
    services::{Service as PingoraServiceLifecycle, listening::Service},
    upstreams::peer::{ALPN, HttpPeer},
};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{HttpProxy, ProxyHttp, Session, http_proxy_service_with_name};
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

use crate::{
    REQUEST_ID_COUNTER,
    quic_listener::{
        AdmissionPolicyDecision, ForwardingSelectionService, MAX_UPSTREAM_RETRY_ATTEMPTS,
        RetryCoordinator, StableBackendSelection, TargetResolutionRequest,
        admission_rejection_response, validate_http_request_parts,
    },
    request_pipeline::{
        PipelineRequest, PipelineRoute, ResolvedRequestPolicy, ResolvedRouteTarget,
        ResponseCompressionAction, ResponseCompressionInput, RouteResolutionError,
        TerminalOutcomeGuard, ensure_vary_accept_encoding, evaluate_pipeline,
        evaluate_response_compression, resolve_route,
    },
    runtime::{
        bundle::{RuntimeBundle, RuntimeBundleHandle},
        connection::{
            PerSourceTokenBucket, TokenBucket,
            guardrails::{
                REQUEST_BODY_TOO_LARGE_BODY, RESPONSE_BODY_TOO_LARGE_BODY,
                RequestBodyGuardrailConfig, RequestBodyGuardrailInput, ResponseBodyGuardrailConfig,
                ResponseBodyGuardrailInput, checked_request_body_ingress,
                checked_response_body_guardrails,
            },
            outcome::{
                AdmissionOutcomeClass, BackendHealthObservationInput, BackendOutcomeTarget,
                ClassifiedBackendFailureInput, RouteOutcomeTarget,
                apply_passive_readiness_to_pingora, observe_admission_outcome,
                observe_backend_response_status_and_log,
                observe_classified_backend_failure_and_log, observe_proxy_error_outcome,
                observe_status_outcome,
            },
        },
        listener::QUICListener,
        tls::store::ListenerTlsReloadStore,
    },
};

const RESPONSE_GZIP_LEVEL: u32 = 6;

pub(crate) struct PingoraRequestContext {
    pub(crate) runtime: Arc<RuntimeBundle>,
    pub(crate) route: Option<ResolvedRouteTarget>,
    pub(crate) policy: Option<ResolvedRequestPolicy>,
    pub(crate) terminal_outcome: TerminalOutcomeGuard,
    started_at: Instant,
    terminal_classification: Option<PingoraTerminalClassification>,
    method: Option<String>,
    path: Option<String>,
    authority: Option<String>,
    content_length: Option<usize>,
    body_bytes_received: usize,
    body_limit_exempt: bool,
    response_body_bytes_received: usize,
    response_body_suppressed: bool,
    response_body_limit_exempt: bool,
    response_content_length: Option<usize>,
    request_body_replayable: bool,
    retry_count: u8,
    retry_backend: Option<(String, usize)>,
    lb_key: Option<String>,
    request_id: u64,
    selected_backend: Option<PingoraSelectedBackend>,
    drain: Arc<PingoraDrainState>,
}

enum PingoraTerminalClassification {
    Admission(AdmissionOutcomeClass),
    Error(ProxyError),
}

impl Drop for PingoraRequestContext {
    fn drop(&mut self) {
        self.terminal_outcome.record();
        self.drain.active_requests.fetch_sub(1, Ordering::AcqRel);
    }
}

struct PingoraSelectedBackend {
    address: String,
    pool: Arc<RwLock<UpstreamPool>>,
    index: usize,
    selected_at: Instant,
    finish_status: Option<u16>,
}

impl Drop for PingoraSelectedBackend {
    fn drop(&mut self) {
        if let Ok(mut pool) = self.pool.write() {
            pool.finish_request(self.index, self.selected_at.elapsed(), self.finish_status);
        }
    }
}

pub(crate) struct PingoraIngressService {
    runtime: RuntimeBundleHandle,
    drain: Arc<PingoraDrainState>,
}

struct PingoraConnectionFilter {
    runtime: RuntimeBundleHandle,
    listener_label: String,
    state: Mutex<PingoraConnectionAdmissionState>,
}

struct PingoraConnectionAdmissionState {
    generation: u64,
    rate_per_sec: u32,
    burst: u32,
    global: TokenBucket,
    per_source: PerSourceTokenBucket,
}

impl std::fmt::Debug for PingoraConnectionFilter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PingoraConnectionFilter")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl ConnectionFilter for PingoraConnectionFilter {
    async fn should_accept(&self, addr: Option<&std::net::SocketAddr>) -> bool {
        let current = self.runtime.current();
        let metrics = &current.shared_state.shared_services().metrics;
        let Some(listener) = current.listener_runtime_config(&self.listener_label) else {
            metrics.inc_ingress_rate_limited();
            return false;
        };
        let policy = &listener.policies.transport;
        let Ok(mut state) = self.state.lock() else {
            metrics.inc_ingress_rate_limited();
            return false;
        };
        if state.generation != current.generation {
            if state.rate_per_sec != policy.new_connections_per_sec
                || state.burst != policy.new_connections_burst
            {
                state
                    .global
                    .reconfigure(policy.new_connections_per_sec, policy.new_connections_burst);
                state
                    .per_source
                    .reconfigure(policy.new_connections_per_sec, policy.new_connections_burst);
                state.rate_per_sec = policy.new_connections_per_sec;
                state.burst = policy.new_connections_burst;
            }
            state.generation = current.generation;
        }
        if !state.global.try_consume() {
            metrics.inc_ingress_rate_limited();
            return false;
        }
        let source_allowed = addr.is_none_or(|addr| state.per_source.try_consume(addr.ip()));
        if !source_allowed {
            metrics.inc_ingress_rate_limited();
        }
        source_allowed
    }
}

#[derive(Default)]
struct PingoraDrainState {
    active_requests: AtomicUsize,
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

pub struct PingoraListenerTask {
    address: String,
    shutdown: tokio::sync::watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<()>>,
    drain: Arc<PingoraDrainState>,
    forced_drained: bool,
}

impl PingoraListenerTask {
    pub async fn wait_until_ready(&mut self) -> std::result::Result<(), String> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if self
                .task
                .as_ref()
                .is_some_and(tokio::task::JoinHandle::is_finished)
            {
                return match self.collect_finished().await {
                    Some(Err(error)) => Err(error),
                    _ => Err(format!(
                        "Pingora listener {} stopped during startup",
                        self.address
                    )),
                };
            }
            if tokio::time::timeout(
                Duration::from_millis(50),
                tokio::net::TcpStream::connect(&self.address),
            )
            .await
            .is_ok_and(|result| result.is_ok())
            {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "Timed out waiting for Pingora listener {}",
                    self.address
                ));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub fn request_shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    pub fn active_requests(&self) -> usize {
        self.drain.active_requests.load(Ordering::Acquire)
    }

    pub async fn collect_finished(&mut self) -> Option<std::result::Result<(), String>> {
        if !self
            .task
            .as_ref()
            .is_some_and(tokio::task::JoinHandle::is_finished)
        {
            return None;
        }
        let task = self.task.take()?;
        Some(
            task.await
                .map_err(|error| format!("Pingora listener {} failed: {error}", self.address)),
        )
    }

    pub fn stopped(&self) -> bool {
        self.forced_drained || (self.task.is_none() && self.active_requests() == 0)
    }

    pub fn force_drain(&mut self) -> usize {
        self.forced_drained = true;
        self.active_requests()
    }

    pub async fn drain(mut self, timeout: Duration) -> std::result::Result<usize, String> {
        self.request_shutdown();
        let deadline = tokio::time::Instant::now() + timeout;
        if let Some(mut task) = self.task.take() {
            match tokio::time::timeout_at(deadline, &mut task).await {
                Ok(result) => result.map_err(|error| {
                    format!("Pingora listener {} failed: {error}", self.address)
                })?,
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    return Ok(self.active_requests());
                }
            }
        }
        loop {
            let active = self.active_requests();
            if active == 0 {
                return Ok(0);
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(active);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

impl Drop for PingoraListenerTask {
    fn drop(&mut self) {
        self.request_shutdown();
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
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
    let (mut service, drain) = pingora_ingress_service_for_listener(
        &Arc::new(ServerConf::default()),
        runtime.as_ref().clone(),
        listener,
    )
    .map_err(|error| format!("Failed to create Pingora listener {address}: {error}"))?;
    let (shutdown, shutdown_watch) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        #[cfg(unix)]
        service.start_service(None, shutdown_watch, 1).await;
        #[cfg(not(unix))]
        service.start_service(shutdown_watch, 1).await;
    });
    Ok(PingoraListenerTask {
        address,
        shutdown,
        task: Some(task),
        drain,
        forced_drained: false,
    })
}

#[cfg(test)]
pub(crate) fn pingora_ingress_services(
    configuration: &Arc<ServerConf>,
    runtime: RuntimeBundleHandle,
) -> Result<Vec<Service<HttpProxy<PingoraIngressService>>>> {
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
) -> Result<(
    Service<HttpProxy<PingoraIngressService>>,
    Arc<PingoraDrainState>,
)> {
    let listener_label = format!(
        "{}:{}",
        listener.listen.listen.address, listener.listen.listen.port
    );
    let current = runtime.current();
    let tls_store = Arc::clone(&current.shared_state.shared_services().listener_tls_store);
    let transport_policy = &listener.policies.transport;
    let connection_filter = Arc::new(PingoraConnectionFilter {
        runtime: runtime.clone(),
        listener_label: listener_label.clone(),
        state: Mutex::new(PingoraConnectionAdmissionState {
            generation: current.generation,
            rate_per_sec: transport_policy.new_connections_per_sec,
            burst: transport_policy.new_connections_burst,
            global: TokenBucket::new(
                transport_policy.new_connections_per_sec,
                transport_policy.new_connections_burst,
            ),
            per_source: PerSourceTokenBucket::new(
                transport_policy.new_connections_per_sec,
                transport_policy.new_connections_burst,
            ),
        }),
    });
    let tls_state = QUICListener::build_listener_tls_reload_state(&listener).map_err(|error| {
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
    let identity = &listener.listen.tls.default_identity;
    let mut tls = TlsSettings::intermediate(&identity.cert_path, &identity.key_path)?;
    tls.set_cert_resolver(Arc::new(RotatingServerCertResolver {
        listener: listener_label.clone(),
        store: tls_store,
    }));
    if let Some(verifier) = QUICListener::build_listener_client_cert_verifier(&listener.listen.tls)
        .map_err(|error| {
            Error::because(
                InternalError,
                format!(
                    "failed to configure Pingora ingress client authentication for '{listener_label}'"
                ),
                error,
            )
        })?
    {
        tls.set_client_cert_verifier(verifier);
    }
    tls.enable_h2();

    let drain = Arc::new(PingoraDrainState::default());
    let mut service = http_proxy_service_with_name(
        configuration,
        PingoraIngressService {
            runtime,
            drain: Arc::clone(&drain),
        },
        &format!("Impulse Pingora Ingress {listener_label}"),
    );
    if let Some(proxy) = service.app_logic_mut() {
        let mut options = HttpServerOptions::default();
        options.allow_connect_method_proxying = true;
        proxy.server_options = Some(options);
    }
    service.set_connection_filter(connection_filter);
    service.add_tls_with_settings(&listener_label, None, tls);
    Ok((service, drain))
}

#[async_trait]
impl ProxyHttp for PingoraIngressService {
    type CTX = PingoraRequestContext;

    fn new_ctx(&self) -> Self::CTX {
        self.drain.active_requests.fetch_add(1, Ordering::AcqRel);
        PingoraRequestContext {
            runtime: self.runtime.current(),
            route: None,
            policy: None,
            terminal_outcome: TerminalOutcomeGuard::default(),
            started_at: Instant::now(),
            terminal_classification: None,
            method: None,
            path: None,
            authority: None,
            content_length: None,
            body_bytes_received: 0,
            body_limit_exempt: false,
            response_body_bytes_received: 0,
            response_body_suppressed: false,
            response_body_limit_exempt: false,
            response_content_length: None,
            request_body_replayable: false,
            retry_count: 0,
            retry_backend: None,
            lb_key: None,
            request_id: REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed),
            selected_backend: None,
            drain: Arc::clone(&self.drain),
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let runtime = Arc::clone(&ctx.runtime);
        let state = runtime.shared_state.generation_state();
        let shared = runtime.shared_state.shared_services();
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
                shared.metrics.inc_request_validation_reject();
                if is_policy {
                    shared.metrics.inc_policy_denied();
                }
                write_local_response(session, status, body, None, None).await?;
                return Ok(true);
            }
        };

        let route = match resolve_route(
            &state.routing_index,
            &validated.method,
            &validated.path,
            validated.authority.as_deref(),
        ) {
            Ok(route) => route,
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
            Err(RouteResolutionError::NoRoute) => {
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
        let Some(upstream_policy) = state.upstream_policies.get(route.upstream_name.as_ref())
        else {
            write_local_response(
                session,
                http::StatusCode::BAD_GATEWAY,
                b"no route\n",
                None,
                None,
            )
            .await?;
            return Ok(true);
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
        let header_lookup = |name: &str| {
            request
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let pipeline = evaluate_pipeline(
            &state.resilience,
            PipelineRoute::new(route.upstream_name.as_ref(), upstream_policy),
            PipelineRequest {
                method: &validated.method,
                path: &validated.path,
                authority: validated.authority.as_deref(),
                peer_address,
                headers: Some(&header_lookup),
            },
        );
        shared
            .metrics
            .set_brownout_active(state.resilience.brownout.is_active());
        let body_limit_exempt = validated.method.eq_ignore_ascii_case("CONNECT")
            || impulse_bridge::websocket::legacy_websocket_upgrade_requested(
                &validated.method,
                &bridge_headers(&request.headers),
            );
        ctx.route = Some(route.clone());
        ctx.method = Some(validated.method);
        ctx.path = Some(validated.path);
        ctx.authority = validated.authority;
        ctx.content_length = validated.content_length;
        ctx.body_limit_exempt = body_limit_exempt;

        if let Some(response) = admission_rejection_response(&pipeline.admission) {
            match pipeline.admission {
                AdmissionPolicyDecision::Unauthorized(_) => {
                    ctx.terminal_classification = Some(PingoraTerminalClassification::Admission(
                        AdmissionOutcomeClass::AuthDenied,
                    ));
                    shared.metrics.inc_policy_denied();
                }
                AdmissionPolicyDecision::RateLimited(_) => {
                    ctx.terminal_classification = Some(PingoraTerminalClassification::Admission(
                        AdmissionOutcomeClass::RateLimited,
                    ));
                    shared.metrics.inc_request_rate_limited()
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
                idle_timeout: Duration::ZERO,
                total_timeout: Duration::ZERO,
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
                exempt_from_body_size_cap: body_limit_exempt,
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

        if pipeline.policy.response_compression.enabled {
            session.upstream_compression.adjust_level(0);
            session
                .upstream_compression
                .adjust_algorithm_level(Algorithm::Gzip, RESPONSE_GZIP_LEVEL);
        }
        ctx.policy = Some(pipeline.policy);
        ctx.request_body_replayable = session.is_body_empty();
        Ok(false)
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let max_request_body_bytes = ctx
            .runtime
            .runtime_config
            .policies
            .transport
            .max_request_body_bytes;
        let next = checked_request_body_ingress(
            RequestBodyGuardrailConfig {
                idle_timeout: Duration::ZERO,
                total_timeout: Duration::ZERO,
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
                exempt_from_body_size_cap: ctx.body_limit_exempt,
            },
        );
        match next {
            Ok(next) => {
                ctx.body_bytes_received = next.bytes_received;
                Ok(())
            }
            Err(_) => {
                session
                    .respond_error_with_body(
                        http::StatusCode::PAYLOAD_TOO_LARGE.as_u16(),
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
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let route = ctx.route.as_ref().ok_or_else(|| {
            Error::explain(
                InternalError,
                "Pingora ingress request filter did not resolve a route",
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
        let state = ctx.runtime.shared_state.generation_state();
        let pool = state
            .upstream_pools
            .get(route.upstream_name.as_ref())
            .cloned()
            .ok_or_else(|| {
                Error::explain(
                    InternalError,
                    format!(
                        "Pingora ingress upstream pool is missing: {}",
                        route.upstream_name
                    ),
                )
            })?;
        let retry_backend = ctx.retry_backend.take();
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
                method,
                path,
                ctx.authority.as_deref(),
                None,
                Some(&header_lookup),
            );
            let selector = state
                .pingora_load_balancing
                .selector(route.upstream_name.as_ref())
                .ok_or_else(|| {
                    ctx.runtime
                        .shared_state
                        .shared_services()
                        .metrics
                        .inc_pingora_lb_selector_failure();
                    Error::explain(
                        InternalError,
                        format!(
                            "Pingora ingress selector is missing: {}",
                            route.upstream_name
                        ),
                    )
                })?;
            let selected = ForwardingSelectionService::select_backend_with_selector(
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
                .mark_primary(route.upstream_name.as_ref());
            (selected.backend_addr, selected.backend_index)
        };
        let selected_backend = PingoraSelectedBackend {
            address: backend_addr.clone(),
            pool,
            index: backend_index,
            selected_at: Instant::now(),
            finish_status: None,
        };
        let mut peer = ctx
            .runtime
            .shared_state
            .shared_services()
            .transport_pool
            .pingora_peer(&backend_addr, ctx.runtime.generation)
            .map_err(|error| {
                Error::because(InternalError, "backend peer creation failed", error)
            })?;
        if ctx.body_limit_exempt {
            peer.options.alpn = ALPN::H1;
        }
        ctx.selected_backend = Some(selected_backend);
        Ok(Box::new(peer))
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        peer: &HttpPeer,
        ctx: &mut Self::CTX,
        error: Box<Error>,
    ) -> Box<Error> {
        handle_pingora_proxy_failure(
            ctx,
            error,
            matches!(peer.options.alpn, ALPN::H2),
            false,
            true,
        )
    }

    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        error: Box<Error>,
        ctx: &mut Self::CTX,
        reused: bool,
    ) -> Box<Error> {
        handle_pingora_proxy_failure(
            ctx,
            error,
            matches!(peer.options.alpn, ALPN::H2),
            reused,
            session.response_written().is_none(),
        )
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
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
        let target = impulse_bridge::request::RequestBuildTarget {
            endpoint,
            policies: impulse_bridge::request::RequestBuildPolicies {
                host_policy: &policy.host_policy,
                forwarded_header_policy: &policy.forwarded_header_policy,
            },
        };
        let input = impulse_bridge::request::RequestBuildInput {
            method,
            path,
            authority: ctx.authority.as_deref(),
            headers: &headers,
            auth_header_mutations: &[],
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

        let existing_headers = upstream_request.headers.keys().cloned().collect::<Vec<_>>();
        for name in existing_headers {
            upstream_request.remove_header(&name);
        }
        for (name, value) in normalized.headers() {
            upstream_request.append_header(name.clone(), value.clone())?;
        }
        Ok(())
    }

    async fn upstream_response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if let Some(selected) = ctx.selected_backend.as_ref() {
            if upstream_response.status.is_server_error() {
                ctx.runtime
                    .shared_state
                    .shared_services()
                    .metrics
                    .inc_health_failure(impulse_lb::health::HealthFailureReason::HttpStatus5xx);
            }
            let _ = observe_backend_response_status_and_log(BackendHealthObservationInput {
                backend_addr: &selected.address,
                backend_index: selected.index,
                upstream_pool: Some(&selected.pool),
                status: upstream_response.status,
            });
            apply_passive_readiness_to_pingora(
                ctx.runtime
                    .shared_state
                    .generation_state()
                    .pingora_load_balancing
                    .as_ref(),
                &selected.address,
                selected.index,
                Some(&selected.pool),
            );
        }
        let method = ctx.method.as_deref().ok_or_else(|| {
            Error::explain(
                InternalError,
                "Pingora ingress request filter did not validate a method",
            )
        })?;
        let tunnel_response = ctx.body_limit_exempt
            && (upstream_response.status == http::StatusCode::SWITCHING_PROTOCOLS
                || (method.eq_ignore_ascii_case("CONNECT")
                    && upstream_response.status.is_success()));
        let body_mode = if tunnel_response {
            ResponseBodyMode::TunnelSuccess
        } else if method.eq_ignore_ascii_case("HEAD") {
            ResponseBodyMode::HeadRequest
        } else {
            ResponseBodyMode::Normal
        };
        let content_length = upstream_response
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());
        let normalized = normalize_upstream_response(ResponseNormalizationInput {
            upstream: UpstreamResponseView {
                status: upstream_response.status,
                headers: &upstream_response.headers,
            },
            body_mode,
            constraints: pingora_response_constraints(tunnel_response),
        });
        let body_suppressed = matches!(normalized.emission.body, ResponseBodyPolicy::Suppress);
        let max_response_body_bytes = ctx
            .runtime
            .runtime_config
            .policies
            .transport
            .max_response_body_bytes;
        if checked_response_body_guardrails(
            ResponseBodyGuardrailConfig {
                idle_timeout: Duration::MAX,
                total_timeout: Duration::MAX,
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
                progressive_emission_allowed: !normalized.emission.emit_end_stream_on_headers,
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
            session
                .respond_error_with_body(
                    http::StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                    Bytes::from_static(RESPONSE_BODY_TOO_LARGE_BODY),
                )
                .await?;
            return Error::e_explain(HTTPStatus(503), "upstream response body too large");
        }

        let existing_headers = upstream_response
            .headers
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for name in existing_headers {
            upstream_response.remove_header(&name);
        }
        for header in normalized.headers {
            upstream_response.append_header(header.name, header.value)?;
        }
        let policy = ctx.policy.as_ref().ok_or_else(|| {
            Error::explain(
                InternalError,
                "Pingora ingress request filter did not resolve a request policy",
            )
        })?;
        let compression = evaluate_response_compression(ResponseCompressionInput {
            policy: &policy.response_compression,
            request_method: method,
            request_headers: &session.req_header().headers,
            response_status: upstream_response.status,
            response_headers: &upstream_response.headers,
        });
        match compression.action {
            ResponseCompressionAction::Gzip => session
                .upstream_compression
                .adjust_algorithm_level(Algorithm::Gzip, RESPONSE_GZIP_LEVEL),
            ResponseCompressionAction::Bypass(_) => {
                session.upstream_compression.adjust_level(0);
            }
        }
        if compression.vary_accept_encoding {
            ensure_vary_accept_encoding(&mut upstream_response.headers);
        }
        ctx.response_body_bytes_received = 0;
        ctx.response_body_suppressed = body_suppressed;
        ctx.response_body_limit_exempt = tunnel_response;
        ctx.response_content_length = content_length;
        Ok(())
    }

    fn upstream_response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>> {
        if ctx.response_body_suppressed {
            *body = None;
            return Ok(None);
        }

        let next = checked_response_body_guardrails(
            ResponseBodyGuardrailConfig {
                idle_timeout: Duration::MAX,
                total_timeout: Duration::MAX,
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
                elapsed: Duration::ZERO,
                idle_for: Duration::ZERO,
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
                Ok(None)
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
        ctx: &mut Self::CTX,
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

    async fn logging(&self, session: &mut Session, error: Option<&Error>, ctx: &mut Self::CTX) {
        if !ctx.terminal_outcome.record() {
            return;
        }

        let status = session.response_written().map(|response| response.status);
        if let Some(selected) = ctx.selected_backend.as_mut() {
            selected.finish_status = status.map(|status| status.as_u16());
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
    h2: bool,
    reused: bool,
    retry_safe: bool,
) -> Box<Error> {
    if ctx.selected_backend.is_none() {
        error.set_retry(false);
        return error;
    }
    let proxy_error = if h2 {
        classify_pingora_h2_error(&error, reused)
    } else {
        classify_pingora_h1_error(&error)
    };
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
    let stable_selection = match selector {
        Some(selector) => Some(ForwardingSelectionService::select_stable_backend(
            selector,
            &selected.pool,
            ctx.runtime.generation,
            ctx.lb_key.as_deref().unwrap_or_default(),
            &[selected.index],
            false,
            metrics,
        )),
        None => {
            metrics.inc_pingora_lb_selector_failure();
            None
        }
    };
    let (retry_backend, alternate_failure) = match stable_selection {
        Some(Ok(StableBackendSelection::Selected { address, index })) => {
            (Some((address, index)), None)
        }
        Some(Ok(StableBackendSelection::NoCandidate)) => match selected.pool.read() {
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
        ctx.body_limit_exempt,
    );
    let decision = retry.retry_after_error(
        &proxy_error,
        ctx.retry_count,
        MAX_UPSTREAM_RETRY_ATTEMPTS,
        true,
        retry_backend.is_some(),
        alternate_failure,
    );
    let metrics = &ctx.runtime.shared_state.shared_services().metrics;
    let retrying = match decision {
        RetryPolicyDecision::Retry { reason }
            if ctx
                .runtime
                .shared_state
                .generation_state()
                .resilience
                .retry_budget
                .allow_retry(route_name)
                .is_ok() =>
        {
            metrics.inc_retry_attempt(RetryAttemptTelemetryReason::from(reason));
            ctx.retry_count = ctx.retry_count.saturating_add(1);
            ctx.retry_backend = retry_backend;
            error.set_retry(true);
            true
        }
        RetryPolicyDecision::Retry { .. } => {
            metrics.inc_retry_denied(RetryPolicyDenialReason::BudgetDenied);
            error.set_retry(false);
            false
        }
        RetryPolicyDecision::DoNotRetry { denial } => {
            if let Some(denial) = denial {
                metrics.inc_retry_denied(denial);
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

fn record_pingora_backend_failure(ctx: &PingoraRequestContext, error: &ProxyError) {
    let (Some(selected), Some(route), Some(classified)) = (
        ctx.selected_backend.as_ref(),
        ctx.route.as_ref(),
        classify_upstream_proxy_error(error),
    ) else {
        return;
    };
    let shared = ctx.runtime.shared_state.shared_services();
    let _ = observe_classified_backend_failure_and_log(ClassifiedBackendFailureInput {
        metrics_phase: "pingora_ingress",
        upstream_name: route.upstream_name.as_ref(),
        backend_addr: &selected.address,
        backend_index: selected.index,
        upstream_pool: Some(&selected.pool),
        metrics: shared.metrics.as_ref(),
        classified: &classified,
    });
    apply_passive_readiness_to_pingora(
        ctx.runtime
            .shared_state
            .generation_state()
            .pingora_load_balancing
            .as_ref(),
        &selected.address,
        selected.index,
        Some(&selected.pool),
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

async fn write_local_response(
    session: &mut Session,
    status: http::StatusCode,
    body: &'static [u8],
    www_authenticate: Option<&'static str>,
    retry_after_seconds: Option<u32>,
) -> Result<()> {
    let mut response = ResponseHeader::build(status, Some(3))?;
    response.insert_header(http::header::CONTENT_LENGTH, body.len().to_string())?;
    if let Some(challenge) = www_authenticate {
        response.insert_header(http::header::WWW_AUTHENTICATE, challenge)?;
    }
    if let Some(seconds) = retry_after_seconds {
        response.insert_header(http::header::RETRY_AFTER, seconds.to_string())?;
    }
    session
        .write_response_header(Box::new(response), false)
        .await?;
    session
        .write_response_body(Some(Bytes::from_static(body)), true)
        .await
}

#[cfg(test)]
mod tests;
