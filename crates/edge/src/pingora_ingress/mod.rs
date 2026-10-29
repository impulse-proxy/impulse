use std::{
    convert::Infallible,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime},
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
use pingora_cache::{CacheKey, CacheMeta, CachePhase, NoCacheReason, RespCacheable};
#[cfg(unix)]
use pingora_core::server::{Fds, ListenFds};
use pingora_core::{
    Error, HTTPStatus, InternalError, Result,
    apps::{HttpServerApp, HttpServerOptions, ReusedHttpStream, ServerApp},
    listeners::{ConnectionFilter, TcpSocketOptions, tls::TlsSettings},
    protocols::{
        Stream,
        http::{ServerSession, compression::Algorithm},
    },
    server::{ShutdownWatch, configuration::ServerConf},
    services::{Service as PingoraServiceLifecycle, listening::Service},
    upstreams::peer::{ALPN, HttpPeer},
};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{HttpProxy, ProxyHttp, Session, http_proxy};
use quiche::h3::NameValue;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

use crate::{
    REQUEST_ID_COUNTER,
    edge_core::{
        request_execution::{
            RequestExecutionInput, RequestExecutionRoute, ResolvedRequestPolicy,
            ResolvedRouteTarget, ResponseCompressionAction, ResponseCompressionInput,
            ResponseCompressionPolicyInput, RouteResolutionError, TerminalOutcomeGuard,
            ensure_vary_accept_encoding, evaluate_response_compression, execute_request,
            resolve_route,
        },
        request_validation::validate_http_request_parts,
    },
    metrics::ResponseCacheOutcome,
    quic_listener::{
        AdmissionPolicyDecision, BackendCandidate, ForwardingSelectionService,
        MAX_UPSTREAM_RETRY_ATTEMPTS, RetryCoordinator, TargetResolutionRequest,
        admission_rejection_response, evaluate_post_auth_quota_policy,
        execute_external_auth_request,
    },
    resilience::quota::QuotaIdentityContext,
    runtime::{
        bundle::{RuntimeBundle, RuntimeBundleHandle},
        cache::{
            BoundedPingoraMemoryCache, ResponseCacheAuthInput, ResponseCacheKeyInput,
            ResponseCachePolicyInput, ResponseCacheRepresentation,
            ResponseCacheRequestEligibilityInput, ResponseCacheResponseEligibilityInput,
            canonical_response_cache_key, evaluate_cache_request_eligibility,
            evaluate_cache_response_eligibility, response_cache_ttl,
            route_auth_requires_cache_bypass,
        },
        connection::{
            PerSourceTokenBucket, TokenBucket,
            auth::{
                ExternalAuthDecision, ExternalAuthRequest, ExternalAuthStateTransition,
                PendingHeaderMutation, apply_auth_request_mutations,
                resolve_external_auth_state_transition,
            },
            guardrails::{
                BodyTimeoutKind, REQUEST_BODY_TOO_LARGE_BODY, RESPONSE_BODY_TOO_LARGE_BODY,
                RequestBodyGuardrailConfig, RequestBodyGuardrailDecision,
                RequestBodyGuardrailInput, ResponseBodyGuardrailConfig,
                ResponseBodyGuardrailDecision, ResponseBodyGuardrailInput,
                checked_request_body_ingress, checked_response_body_guardrails,
                evaluate_request_body_timeouts,
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
    response_cache_namespace: u64,
    pub(crate) route: Option<ResolvedRouteTarget>,
    pub(crate) policy: Option<ResolvedRequestPolicy>,
    auth_header_mutations: Vec<PendingHeaderMutation>,
    pub(crate) terminal_outcome: TerminalOutcomeGuard,
    started_at: Instant,
    terminal_classification: Option<PingoraTerminalClassification>,
    method: Option<String>,
    path: Option<String>,
    authority: Option<String>,
    content_length: Option<usize>,
    body_bytes_received: usize,
    request_body_last_progress_at: Instant,
    body_limit_exempt: bool,
    response_body_bytes_received: usize,
    response_body_started_at: Option<Instant>,
    response_body_last_progress_at: Option<Instant>,
    response_body_suppressed: bool,
    response_body_limit_exempt: bool,
    response_content_length: Option<usize>,
    response_compression_vary: bool,
    response_cache_representation: Option<ResponseCacheRepresentation>,
    response_cache_bypass_recorded: bool,
    request_body_replayable: bool,
    retry_count: u8,
    retry_backend: Option<(String, usize)>,
    lb_key: Option<String>,
    request_id: impulse_contracts::RequestId,
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

pub(crate) struct PingoraIngressService {
    runtime: RuntimeBundleHandle,
    response_cache: Option<&'static BoundedPingoraMemoryCache>,
    drain: Arc<PingoraDrainState>,
}

impl PingoraIngressService {
    fn select_backend(
        &self,
        session: &Session,
        ctx: &mut PingoraRequestContext,
    ) -> Result<PingoraSelectedBackend> {
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
            .pingora_load_balancing
            .upstream_pool(route.upstream_name.as_ref())
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
                        .runtime_observations()
                        .inc_pingora_lb_selector_failure();
                    Error::explain(
                        InternalError,
                        format!(
                            "Pingora ingress selector is missing: {}",
                            route.upstream_name
                        ),
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
                .mark_primary(route.upstream_name.as_ref());
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
    proxy: Arc<HttpProxy<PingoraIngressService>>,
    runtime: RuntimeBundleHandle,
    listener_label: String,
}

struct PingoraConnectionFilter {
    runtime: RuntimeBundleHandle,
    listener_label: String,
    state: Mutex<PingoraConnectionAdmissionState>,
    per_source: PerSourceTokenBucket,
}

struct PingoraConnectionAdmissionState {
    generation: u64,
    rate_per_sec: u32,
    burst: u32,
    global: TokenBucket,
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
            metrics.ingress_observations().inc_ingress_rate_limited();
            return false;
        };
        let policy = &listener.policies.transport;
        let Ok(mut state) = self.state.lock() else {
            metrics.ingress_observations().inc_ingress_rate_limited();
            return false;
        };
        if state.generation != current.generation {
            if state.rate_per_sec != policy.new_connections_per_sec
                || state.burst != policy.new_connections_burst
            {
                state
                    .global
                    .reconfigure(policy.new_connections_per_sec, policy.new_connections_burst);
                self.per_source
                    .reconfigure(policy.new_connections_per_sec, policy.new_connections_burst);
                state.rate_per_sec = policy.new_connections_per_sec;
                state.burst = policy.new_connections_burst;
            }
            state.generation = current.generation;
        }
        if !state.global.try_consume() {
            metrics.ingress_observations().inc_ingress_rate_limited();
            return false;
        }
        drop(state);
        let source_allowed = addr.is_none_or(|addr| self.per_source.try_consume(addr.ip()));
        if !source_allowed {
            metrics.ingress_observations().inc_ingress_rate_limited();
        }
        source_allowed
    }
}

#[derive(Default)]
struct PingoraDrainState {
    active_requests: AtomicUsize,
    active_connections: AtomicUsize,
}

struct PingoraConnectionPermit {
    drain: Arc<PingoraDrainState>,
}

impl PingoraConnectionPermit {
    fn try_acquire(drain: &Arc<PingoraDrainState>, limit: usize) -> Option<Self> {
        drain
            .active_connections
            .try_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < limit).then_some(active + 1)
            })
            .ok()?;
        Some(Self {
            drain: Arc::clone(drain),
        })
    }
}

impl Drop for PingoraConnectionPermit {
    fn drop(&mut self) {
        self.drain.active_connections.fetch_sub(1, Ordering::AcqRel);
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
        let permit = PingoraConnectionPermit::try_acquire(
            &self.drain,
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

pub struct PingoraListenerTask {
    address: String,
    #[cfg(unix)]
    listen_fds: ListenFds,
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
            #[cfg(unix)]
            if self.listen_fds.lock().get(&self.address).is_some() {
                return Ok(());
            }
            #[cfg(not(unix))]
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
    #[cfg(unix)]
    let listen_fds: ListenFds = Arc::new(Fds::new().into());
    #[cfg(unix)]
    let service_listen_fds = Arc::clone(&listen_fds);
    let task = tokio::spawn(async move {
        #[cfg(unix)]
        service
            .start_service(Some(service_listen_fds), shutdown_watch, 1)
            .await;
        #[cfg(not(unix))]
        service.start_service(shutdown_watch, 1).await;
    });
    Ok(PingoraListenerTask {
        address,
        #[cfg(unix)]
        listen_fds,
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
    let response_cache = runtime.response_cache();
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
        }),
        per_source: PerSourceTokenBucket::new(
            transport_policy.new_connections_per_sec,
            transport_policy.new_connections_burst,
        ),
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
    let mut proxy = http_proxy(
        configuration,
        PingoraIngressService {
            runtime: runtime.clone(),
            response_cache,
            drain: Arc::clone(&drain),
        },
    );
    let mut options = HttpServerOptions::default();
    options.allow_connect_method_proxying = true;
    proxy.server_options = Some(options);
    let mut service = Service::new(
        format!("Impulse Pingora Ingress {listener_label}"),
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
    );
    service.set_connection_filter(connection_filter);
    let socket_options = listener.performance.reuseport.then(|| {
        let mut options = TcpSocketOptions::default();
        options.so_reuseport = Some(true);
        options
    });
    service.add_tls_with_settings(&listener_label, socket_options, tls);
    Ok((service, drain))
}

#[async_trait]
impl ProxyHttp for PingoraIngressService {
    type CTX = PingoraRequestContext;

    fn new_ctx(&self) -> Self::CTX {
        self.drain.active_requests.fetch_add(1, Ordering::AcqRel);
        let (runtime, response_cache_namespace) =
            self.runtime.current_with_response_cache_namespace();
        PingoraRequestContext {
            runtime,
            response_cache_namespace,
            route: None,
            policy: None,
            auth_header_mutations: Vec::new(),
            terminal_outcome: TerminalOutcomeGuard::default(),
            started_at: Instant::now(),
            terminal_classification: None,
            method: None,
            path: None,
            authority: None,
            content_length: None,
            body_bytes_received: 0,
            request_body_last_progress_at: Instant::now(),
            body_limit_exempt: false,
            response_body_bytes_received: 0,
            response_body_started_at: None,
            response_body_last_progress_at: None,
            response_body_suppressed: false,
            response_body_limit_exempt: false,
            response_content_length: None,
            response_compression_vary: false,
            response_cache_representation: None,
            response_cache_bypass_recorded: false,
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
        let client_body_idle = runtime.runtime_config.policies.timeouts.client_body_idle;
        session
            .downstream_session
            .set_read_timeout(Some(client_body_idle));
        session
            .downstream_session
            .set_total_drain_timeout(Some(client_body_idle));
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
        let execution = execute_request(
            &state.resilience,
            RequestExecutionRoute::new(route.upstream_name.as_ref(), upstream_policy),
            RequestExecutionInput {
                method: &validated.method,
                path: &validated.path,
                authority: validated.authority.as_deref(),
                peer_address,
                headers: Some(&header_lookup),
            },
        );
        shared
            .metrics
            .policy_observations()
            .set_brownout_active(state.resilience.brownout.is_active());
        let body_limit_exempt = validated.method.eq_ignore_ascii_case("CONNECT")
            || impulse_bridge::websocket::legacy_websocket_upgrade_requested(
                &validated.method,
                &bridge_headers(&request.headers),
            );
        let external_auth_request =
            execution
                .policy
                .external_auth
                .as_ref()
                .map(|_| ExternalAuthRequest {
                    method: validated.method.clone(),
                    path: validated.path.clone(),
                    authority: validated.authority.clone(),
                    headers: request.headers.clone(),
                    upstream_name: route.upstream_name.to_string(),
                    backend_addr: None,
                });
        ctx.route = Some(route.clone());
        ctx.method = Some(validated.method);
        ctx.path = Some(validated.path);
        ctx.authority = validated.authority;
        ctx.content_length = validated.content_length;
        ctx.body_limit_exempt = body_limit_exempt;

        if let Some(response) = admission_rejection_response(&execution.admission) {
            match execution.admission {
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

        if let (Some(external_auth), Some(mut auth_request)) = (
            execution.policy.external_auth.as_ref(),
            external_auth_request,
        ) {
            let selected = self.select_backend(session, ctx)?;
            auth_request.backend_addr = Some(selected.address.clone());
            ctx.selected_backend = Some(selected);
            let result =
                execute_external_auth_request(auth_request, external_auth.policy.clone()).await;
            match resolve_external_auth_state_transition(result, external_auth.disposition) {
                ExternalAuthStateTransition::Admitted {
                    request_header_mutations,
                } => {
                    shared
                        .metrics
                        .policy_observations()
                        .inc_external_auth_allowed();
                    ctx.auth_header_mutations = request_header_mutations;
                }
                ExternalAuthStateTransition::RejectedAuthDenied { decision } => {
                    shared.metrics.policy_observations().inc_policy_denied();
                    shared
                        .metrics
                        .policy_observations()
                        .inc_external_auth_denied();
                    ctx.terminal_classification = Some(PingoraTerminalClassification::Admission(
                        AdmissionOutcomeClass::AuthDenied,
                    ));
                    write_external_auth_decision_response(session, &decision).await?;
                    return Ok(true);
                }
                ExternalAuthStateTransition::RejectedAuthUnavailable { status, body, .. } => {
                    shared
                        .metrics
                        .policy_observations()
                        .inc_external_auth_error();
                    ctx.terminal_classification = Some(PingoraTerminalClassification::Admission(
                        AdmissionOutcomeClass::Failed { timed_out: false },
                    ));
                    write_local_response(session, status, body, None, None).await?;
                    return Ok(true);
                }
                ExternalAuthStateTransition::TimedOutAuth { status, body } => {
                    shared
                        .metrics
                        .policy_observations()
                        .inc_external_auth_timeout();
                    ctx.terminal_classification = Some(PingoraTerminalClassification::Admission(
                        AdmissionOutcomeClass::Failed { timed_out: true },
                    ));
                    write_local_response(session, status, body, None, None).await?;
                    return Ok(true);
                }
            }
        }

        let (Some(method), Some(path)) = (ctx.method.as_deref(), ctx.path.as_deref()) else {
            return Error::e_explain(
                InternalError,
                "Pingora ingress quota evaluation is missing validated request metadata",
            );
        };
        let mut effective_headers = bridge_headers(&session.req_header().headers);
        apply_auth_request_mutations(&mut effective_headers, &ctx.auth_header_mutations);
        let quota_header_lookup = |name: &str| {
            effective_headers
                .iter()
                .find(|header| header.name().eq_ignore_ascii_case(name.as_bytes()))
                .and_then(|header| std::str::from_utf8(header.value()).ok())
                .map(str::to_string)
        };
        let quota_context = QuotaIdentityContext::new(
            Some(route.upstream_name.as_ref()),
            method,
            path,
            ctx.authority.as_deref(),
            None,
            Some(peer_address),
            Some(&quota_header_lookup),
        );
        if let Some(rejection) =
            evaluate_post_auth_quota_policy(&state.resilience, &quota_context).await
        {
            let response = rejection.as_response();
            if response.status == http::StatusCode::TOO_MANY_REQUESTS {
                shared
                    .metrics
                    .policy_observations()
                    .inc_request_rate_limited();
            }
            ctx.terminal_classification = Some(PingoraTerminalClassification::Admission(
                AdmissionOutcomeClass::QuotaDenied,
            ));
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

        if execution.policy.response_compression.enabled {
            session.upstream_compression.adjust_level(0);
            session
                .upstream_compression
                .adjust_algorithm_level(Algorithm::Gzip, RESPONSE_GZIP_LEVEL);
        }
        ctx.policy = Some(execution.policy);
        ctx.request_body_replayable = session.is_body_empty();
        Ok(false)
    }

    fn request_cache_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()> {
        let (Some(cache), Some(policy), Some(method)) = (
            self.response_cache,
            ctx.policy.as_ref(),
            ctx.method.as_deref(),
        ) else {
            return Ok(());
        };
        let cache_policy = &policy.local_auth_policy.response_cache;
        let is_tunnel = method.eq_ignore_ascii_case("CONNECT");
        let has_body = !session.is_body_empty();
        let representation =
            evaluate_cache_request_eligibility(ResponseCacheRequestEligibilityInput {
                policy: ResponseCachePolicyInput {
                    enabled: cache_policy.enabled,
                },
                route_auth_enabled: route_auth_requires_cache_bypass(ResponseCacheAuthInput {
                    api_key: policy.local_auth_policy.upstream_auth.api_key.is_some(),
                    jwt: policy.local_auth_policy.upstream_auth.jwt.is_some(),
                    external_auth: policy
                        .local_auth_policy
                        .upstream_auth
                        .external_auth
                        .is_some(),
                    required_scopes: !policy
                        .local_auth_policy
                        .upstream_auth
                        .required_scopes
                        .is_empty(),
                    required_roles: !policy
                        .local_auth_policy
                        .upstream_auth
                        .required_roles
                        .is_empty(),
                }),
                method,
                headers: &session.req_header().headers,
                has_body,
                is_upgrade: ctx.body_limit_exempt && !is_tunnel,
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
        cache.enable(&mut session.cache, cache_policy.max_object_bytes);
        ctx.response_cache_representation = Some(representation);
        Ok(())
    }

    fn cache_key_callback(&self, session: &Session, ctx: &mut Self::CTX) -> Result<CacheKey> {
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
        canonical_response_cache_key(ResponseCacheKeyInput {
            scheme: "https",
            authority,
            path_and_query: path,
            representation,
            accept_encoding: (!accept_encoding.is_empty()).then_some(accept_encoding.as_str()),
            namespace: ctx.response_cache_namespace,
        })
        .ok_or_else(|| Error::explain(InternalError, "response cache key is invalid"))
    }

    fn response_cache_filter(
        &self,
        _session: &Session,
        response: &ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<RespCacheable> {
        let Some(policy) = ctx.policy.as_ref() else {
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
        if response.status != http::StatusCode::OK
            || evaluate_cache_response_eligibility(ResponseCacheResponseEligibilityInput {
                headers: &response.headers,
            })
            .is_err()
        {
            ctx.runtime
                .shared_state
                .shared_services()
                .metrics
                .ingress_observations()
                .record_response_cache_outcome(ResponseCacheOutcome::Rejection);
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                "impulse_policy",
            )));
        }
        let now = SystemTime::now();
        let Some(ttl) = response_cache_ttl(
            response,
            policy.local_auth_policy.response_cache.max_ttl_secs,
            now,
        ) else {
            ctx.runtime
                .shared_state
                .shared_services()
                .metrics
                .ingress_observations()
                .record_response_cache_outcome(ResponseCacheOutcome::Rejection);
            return Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache));
        };
        let Some(fresh_until) = now.checked_add(ttl) else {
            ctx.runtime
                .shared_state
                .shared_services()
                .metrics
                .ingress_observations()
                .record_response_cache_outcome(ResponseCacheOutcome::Rejection);
            return Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache));
        };
        Ok(RespCacheable::Cacheable(CacheMeta::new(
            fresh_until,
            now,
            0,
            0,
            response.clone(),
        )))
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
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
                exempt_from_body_size_cap: ctx.body_limit_exempt,
            },
        );
        if let RequestBodyGuardrailDecision::Timeout { kind } = timeout {
            ctx.terminal_classification =
                Some(PingoraTerminalClassification::Error(ProxyError::Timeout));
            let detail = match kind {
                BodyTimeoutKind::Idle => "request body idle timeout",
                BodyTimeoutKind::Total => "request body total timeout",
            };
            session
                .respond_error_with_body(
                    http::StatusCode::REQUEST_TIMEOUT.as_u16(),
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
                exempt_from_body_size_cap: ctx.body_limit_exempt,
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
        if ctx.body_limit_exempt {
            peer.options.alpn = ALPN::H1;
        }
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
            endpoint: impulse_bridge::UpstreamTargetInput {
                scheme: match endpoint.scheme() {
                    BackendScheme::Http => impulse_bridge::UpstreamScheme::Http,
                    BackendScheme::Https => impulse_bridge::UpstreamScheme::Https,
                },
                authority: endpoint.authority(),
            },
            policies: impulse_bridge::request::RequestBuildPolicies {
                host_policy: impulse_bridge::HostPolicyInput {
                    mode: match policy.host_policy.mode {
                        impulse_config::config::UpstreamHostPolicyMode::PassThrough => {
                            impulse_bridge::HostPolicyMode::PassThrough
                        }
                        impulse_config::config::UpstreamHostPolicyMode::Rewrite => {
                            impulse_bridge::HostPolicyMode::Rewrite
                        }
                        impulse_config::config::UpstreamHostPolicyMode::Upstream => {
                            impulse_bridge::HostPolicyMode::Upstream
                        }
                    },
                    rewrite_host: policy.host_policy.host.as_deref(),
                },
                forwarded_header_policy: impulse_bridge::ForwardingPolicyInput {
                    mode: match policy.forwarded_header_policy.mode {
                        impulse_config::config::ForwardedHeaderPolicyMode::Preserve => {
                            impulse_bridge::ForwardedHeaderMode::Preserve
                        }
                        impulse_config::config::ForwardedHeaderPolicyMode::Append => {
                            impulse_bridge::ForwardedHeaderMode::Append
                        }
                        impulse_config::config::ForwardedHeaderPolicyMode::Overwrite => {
                            impulse_bridge::ForwardedHeaderMode::Overwrite
                        }
                    },
                },
            },
        };
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

        let existing_headers = upstream_request.headers.keys().cloned().collect::<Vec<_>>();
        for name in existing_headers {
            upstream_request.remove_header(&name);
        }
        for (name, value) in normalized.headers() {
            upstream_request.append_header(name.clone(), value.clone())?;
        }
        Ok(())
    }

    async fn adjust_upstream_modules(
        &self,
        session: &mut Session,
        upstream_response: &ResponseHeader,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if upstream_response.status.is_informational() {
            return Ok(());
        }
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
        ctx.response_content_length = upstream_response
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());
        let compression = evaluate_response_compression(ResponseCompressionInput {
            policy: ResponseCompressionPolicyInput {
                enabled: policy.response_compression.enabled,
                minimum_size_bytes: policy.response_compression.minimum_size_bytes,
            },
            request_method: method,
            request_headers: &session.req_header().headers,
            response_status: upstream_response.status,
            response_headers: &upstream_response.headers,
        });
        ctx.runtime
            .shared_state
            .shared_services()
            .metrics
            .ingress_observations()
            .record_response_compression_outcome(compression.action);
        ctx.response_compression_vary = compression.vary_accept_encoding;
        session.upstream_compression.adjust_level(0);
        if matches!(compression.action, ResponseCompressionAction::Gzip) {
            session
                .upstream_compression
                .adjust_algorithm_level(Algorithm::Gzip, RESPONSE_GZIP_LEVEL);
        }
        Ok(())
    }

    async fn upstream_response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let now = Instant::now();
        let timeouts = &ctx.runtime.runtime_config.policies.timeouts;
        if ctx.selected_backend.as_ref().is_some_and(|selected| {
            selected.selected_at.elapsed() >= timeouts.backend_total_request
        }) {
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
        let content_length = ctx.response_content_length.or_else(|| {
            upstream_response
                .headers
                .get(http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<usize>().ok())
        });
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
                idle_timeout: timeouts.backend_body_idle,
                total_timeout: timeouts.backend_body_total,
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
        if ctx.response_compression_vary {
            let mut vary_headers = http::HeaderMap::new();
            for value in upstream_response.headers.get_all(http::header::VARY).iter() {
                vary_headers.append(http::header::VARY, value.clone());
            }
            ensure_vary_accept_encoding(&mut vary_headers);
            upstream_response.remove_header(&http::header::VARY);
            for value in vary_headers.get_all(http::header::VARY).iter() {
                upstream_response.append_header(http::header::VARY, value.clone())?;
            }
        }
        ctx.response_body_bytes_received = 0;
        ctx.response_body_started_at = Some(now);
        ctx.response_body_last_progress_at = Some(now);
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
        if session.cache.lock_duration().is_some() {
            metrics
                .ingress_observations()
                .record_response_cache_outcome(ResponseCacheOutcome::LockWait);
        }
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
    h2: bool,
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
    let selection = match selector {
        Some(selector) => Some(ForwardingSelectionService::select_backend_excluding(
            selector,
            &selected.pool,
            ctx.runtime.generation,
            ctx.lb_key.as_deref().unwrap_or_default(),
            &[selected.index],
            false,
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
            metrics
                .policy_observations()
                .inc_retry_attempt(RetryAttemptTelemetryReason::from(reason));
            ctx.retry_count = ctx.retry_count.saturating_add(1);
            ctx.retry_backend = retry_backend;
            error.set_retry(true);
            true
        }
        RetryPolicyDecision::Retry { .. } => {
            metrics
                .policy_observations()
                .inc_retry_denied(RetryPolicyDenialReason::BudgetDenied);
            error.set_retry(false);
            false
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
    let Some(selected) = ctx.selected_backend.as_mut() else {
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
    selected.passive_health_recorded = true;
    let shared = ctx.runtime.shared_state.shared_services();
    let transition = observe_classified_backend_failure_and_log(ClassifiedBackendFailureInput {
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
        transition,
    );
}

fn record_pingora_backend_response(ctx: &mut PingoraRequestContext, status: http::StatusCode) {
    let Some(selected) = ctx.selected_backend.as_mut() else {
        return;
    };
    if selected.passive_health_recorded {
        return;
    }
    selected.passive_health_recorded = true;
    if status.is_server_error() {
        ctx.runtime
            .shared_state
            .shared_services()
            .metrics
            .policy_observations()
            .inc_health_failure(impulse_lb::health::HealthFailureReason::HttpStatus5xx);
    }
    let transition = observe_backend_response_status_and_log(BackendHealthObservationInput {
        backend_addr: &selected.address,
        backend_index: selected.index,
        upstream_pool: Some(&selected.pool),
        status,
    });
    apply_passive_readiness_to_pingora(
        ctx.runtime
            .shared_state
            .generation_state()
            .pingora_load_balancing
            .as_ref(),
        &selected.address,
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

async fn write_external_auth_decision_response(
    session: &mut Session,
    decision: &ExternalAuthDecision,
) -> Result<()> {
    let (status, headers, body, extra_header) = match decision {
        ExternalAuthDecision::Allow { .. } => return Ok(()),
        ExternalAuthDecision::Deny(response) => (
            response.status,
            response.headers.as_slice(),
            response.body.as_slice(),
            None,
        ),
        ExternalAuthDecision::Redirect(response) => (
            response.status,
            response.headers.as_slice(),
            &[][..],
            Some((http::header::LOCATION.as_str(), response.location.as_str())),
        ),
        ExternalAuthDecision::Challenge(response) => (
            response.status,
            response.headers.as_slice(),
            response.body.as_slice(),
            Some((
                http::header::WWW_AUTHENTICATE.as_str(),
                response.www_authenticate.as_str(),
            )),
        ),
    };
    let mut response = ResponseHeader::build(status, Some(headers.len() + 3))?;
    let mut has_content_type = false;
    let mut has_content_length = false;
    for (name, value) in headers {
        let (Ok(name), Ok(value)) = (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            http::header::HeaderValue::from_str(value),
        ) else {
            continue;
        };
        has_content_type |= name == http::header::CONTENT_TYPE;
        has_content_length |= name == http::header::CONTENT_LENGTH;
        response.append_header(name, value)?;
    }
    if let Some((name, value)) = extra_header {
        response.append_header(name, value)?;
    }
    if !has_content_type {
        response.insert_header(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("text/plain"),
        )?;
    }
    if !has_content_length {
        response.insert_header(http::header::CONTENT_LENGTH, body.len().to_string())?;
    }
    session
        .write_response_header(Box::new(response), false)
        .await?;
    session
        .write_response_body(Some(Bytes::copy_from_slice(body)), true)
        .await
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
