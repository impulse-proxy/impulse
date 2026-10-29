use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, Mutex as StdMutex, OnceLock, RwLock},
    time::Instant,
};

use http_body_util::Full;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use impulse_policy::{ExternalAuthPolicy, ExternalAuthRequestHeader};
use serde_json::Value;
use tokio::{sync::Mutex, task::AbortHandle};

use super::*;
use crate::runtime::connection::{
    auth::{
        ExternalAuthDecision, ExternalAuthDenyResponse, ExternalAuthExecutionPolicy,
        ExternalAuthRequest, ExternalAuthResponseMetadata, ExternalAuthResult,
        ExternalAuthStateTransition, ExternalAuthTaskConfig, OidcAuthorizationCheck,
        oidc_audience_matches, oidc_authorization_check, oidc_discovery_target,
        oidc_scope_satisfied, resolve_external_auth_state_transition,
        validate_oidc_provider_metadata,
    },
    outcome::{
        AdmissionOutcomeClass, BackendOutcomeTarget, RouteOutcomeTarget, observe_admission_outcome,
    },
    request::PendingForward,
    stream::{RejectionReason, RequestExecutionState, TerminalReason, TimeoutReason},
};

const MAX_AUTH_BODY_BYTES: usize = 64 * 1024;
const OIDC_METADATA_REFRESH_AFTER: Duration = Duration::from_secs(60);
const OIDC_METADATA_CACHE_TTL: Duration = Duration::from_secs(300);
const OIDC_METADATA_CACHE_MAX_ENTRIES: usize = 256;

struct OidcMetadataCacheEntry {
    metadata: RwLock<
        Option<(
            Instant,
            crate::runtime::connection::auth::OidcProviderMetadata,
        )>,
    >,
    refresh_lock: Arc<Mutex<()>>,
}

struct CachedOidcMetadataEntry {
    entry: Arc<OidcMetadataCacheEntry>,
    last_access: u64,
}

#[derive(Default)]
struct OidcMetadataCache {
    entries: HashMap<String, CachedOidcMetadataEntry>,
    access_sequence: u64,
}

impl OidcMetadataCache {
    fn entry(&mut self, url: &str) -> Arc<OidcMetadataCacheEntry> {
        self.access_sequence = self.access_sequence.saturating_add(1);
        let last_access = self.access_sequence;

        if let Some(cached) = self.entries.get_mut(url) {
            cached.last_access = last_access;
            return Arc::clone(&cached.entry);
        }

        if self.entries.len() >= OIDC_METADATA_CACHE_MAX_ENTRIES
            && let Some(evicted_url) = self
                .entries
                .iter()
                .min_by(|(left_url, left), (right_url, right)| {
                    left.last_access
                        .cmp(&right.last_access)
                        .then_with(|| left_url.cmp(right_url))
                })
                .map(|(url, _)| url.clone())
        {
            self.entries.remove(&evicted_url);
        }

        let entry = Arc::new(OidcMetadataCacheEntry {
            metadata: RwLock::new(None),
            refresh_lock: Arc::new(Mutex::new(())),
        });
        self.entries.insert(
            url.to_string(),
            CachedOidcMetadataEntry {
                entry: Arc::clone(&entry),
                last_access,
            },
        );
        entry
    }
}

static OIDC_METADATA_CACHE: OnceLock<StdMutex<OidcMetadataCache>> = OnceLock::new();

fn oidc_metadata_cache() -> &'static StdMutex<OidcMetadataCache> {
    OIDC_METADATA_CACHE.get_or_init(|| StdMutex::new(OidcMetadataCache::default()))
}

fn oidc_metadata_cache_entry(url: &str) -> Arc<OidcMetadataCacheEntry> {
    oidc_metadata_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .entry(url)
}

async fn refresh_oidc_metadata(
    url: String,
    entry: Arc<OidcMetadataCacheEntry>,
    timeout: Duration,
) -> Result<crate::runtime::connection::auth::OidcProviderMetadata, ProxyError> {
    let _guard = entry.refresh_lock.lock().await;
    let now = Instant::now();
    if let Some((fetched_at, metadata)) = entry
        .metadata
        .read()
        .ok()
        .and_then(|metadata| metadata.clone())
        && now.duration_since(fetched_at) < OIDC_METADATA_CACHE_TTL
    {
        return Ok(metadata);
    }
    let document = fetch_json_document(url, timeout).await?;
    let metadata = validate_oidc_provider_metadata(&document)?;
    if let Ok(mut cached) = entry.metadata.write() {
        *cached = Some((Instant::now(), metadata.clone()));
    }
    Ok(metadata)
}

async fn oidc_provider_metadata(
    url: String,
    timeout: Duration,
) -> Result<crate::runtime::connection::auth::OidcProviderMetadata, ProxyError> {
    let entry = oidc_metadata_cache_entry(&url);
    if let Some((fetched_at, metadata)) = entry
        .metadata
        .read()
        .ok()
        .and_then(|metadata| metadata.clone())
    {
        let age = Instant::now().duration_since(fetched_at);
        if age < OIDC_METADATA_REFRESH_AFTER {
            return Ok(metadata);
        }
        if age < OIDC_METADATA_CACHE_TTL {
            if let Ok(guard) = Arc::clone(&entry.refresh_lock).try_lock_owned() {
                let refresh_entry = Arc::clone(&entry);
                let refresh_url = url.clone();
                if let Some(handle) = runtime_handle() {
                    handle.spawn(async move {
                        let _guard = guard;
                        match fetch_json_document(refresh_url, timeout)
                            .await
                            .and_then(|document| validate_oidc_provider_metadata(&document))
                        {
                            Ok(metadata) => {
                                if let Ok(mut cached) = refresh_entry.metadata.write() {
                                    *cached = Some((Instant::now(), metadata));
                                }
                            }
                            Err(error) => {
                                log::warn!("OIDC discovery background refresh failed: {error}");
                            }
                        }
                    });
                }
            }
            return Ok(metadata);
        }
    }
    refresh_oidc_metadata(url, entry, timeout).await
}

pub(super) struct AuthStart {
    pub(super) rx: oneshot::Receiver<ExternalAuthResult>,
    pub(super) abort: AbortHandle,
    pub(super) deadline: Instant,
}

struct OidcExternalAuthInput {
    request: Arc<ExternalAuthRequest>,
    discovery_url: Option<String>,
    issuer_url: Option<String>,
    client_id: String,
    client_secret: Option<String>,
    audience: Option<String>,
    scopes: Vec<String>,
    request_headers: Vec<ExternalAuthRequestHeader>,
    timeout: Duration,
}

struct AuthHttpClient {
    client: Client<hyper_rustls::HttpsConnector<HttpConnector>, BoxBody<Bytes, Infallible>>,
}

static AUTH_HTTP_CLIENT: OnceLock<AuthHttpClient> = OnceLock::new();

impl AuthHttpClient {
    fn shared() -> &'static Self {
        AUTH_HTTP_CLIENT.get_or_init(|| {
            let https = HttpsConnectorBuilder::new()
                .with_webpki_roots()
                .https_or_http()
                .enable_http1()
                .enable_http2()
                .build();
            let client = Client::builder(hyper_util::rt::TokioExecutor::new())
                .pool_max_idle_per_host(32)
                .pool_idle_timeout(Duration::from_secs(30))
                .build(https);
            Self { client }
        })
    }

    async fn send(
        &self,
        request: Request<BoxBody<Bytes, Infallible>>,
    ) -> Result<Response<Incoming>, ProxyError> {
        self.client
            .request(request)
            .await
            .map_err(|err| ProxyError::Transport(err.to_string()))
    }
}

fn is_unsafe_forwarded_auth_request_header(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(http::header::HOST.as_str().as_bytes())
        || name.eq_ignore_ascii_case(http::header::CONNECTION.as_str().as_bytes())
        || name.eq_ignore_ascii_case(http::header::CONTENT_LENGTH.as_str().as_bytes())
        || name.eq_ignore_ascii_case(http::header::TRANSFER_ENCODING.as_str().as_bytes())
        || name.eq_ignore_ascii_case(http::header::UPGRADE.as_str().as_bytes())
        || name.eq_ignore_ascii_case(http::header::TE.as_str().as_bytes())
        || name.eq_ignore_ascii_case(http::header::TRAILER.as_str().as_bytes())
        || name.eq_ignore_ascii_case(http::header::EXPECT.as_str().as_bytes())
        || name.eq_ignore_ascii_case(b"keep-alive")
        || name.eq_ignore_ascii_case(b"proxy-connection")
}

#[cfg(test)]
pub(super) fn append_auth_request_headers(
    builder: &mut http::request::Builder,
    pending_forward: &PendingForward,
    configured_headers: &[ExternalAuthRequestHeader],
) {
    let request = external_auth_request_from_pending_forward(pending_forward);
    append_external_auth_request_headers(builder, &request, configured_headers);
}

fn append_external_auth_request_headers(
    builder: &mut http::request::Builder,
    request: &ExternalAuthRequest,
    configured_headers: &[ExternalAuthRequestHeader],
) {
    for (name, value) in &request.headers {
        if is_unsafe_forwarded_auth_request_header(name.as_str().as_bytes()) {
            continue;
        }
        if let Some(headers) = builder.headers_mut() {
            headers.append(name.clone(), value.clone());
        }
    }
    for header in configured_headers {
        builder.headers_mut().into_iter().for_each(|headers| {
            if let (Ok(name), Ok(value)) = (
                http::header::HeaderName::from_bytes(header.name.as_bytes()),
                http::header::HeaderValue::from_str(&header.value),
            ) {
                headers.insert(name, value);
            }
        });
    }
    if let Some(headers) = builder.headers_mut() {
        if let Ok(value) = http::header::HeaderValue::from_str(&request.method) {
            headers.insert(
                http::header::HeaderName::from_static("x-impulse-original-method"),
                value,
            );
        }
        if let Ok(value) = http::header::HeaderValue::from_str(&request.path) {
            headers.insert(
                http::header::HeaderName::from_static("x-impulse-original-path"),
                value,
            );
        }
        if let Some(authority) = request.authority.as_deref()
            && let Ok(value) = http::header::HeaderValue::from_str(authority)
        {
            headers.insert(
                http::header::HeaderName::from_static("x-impulse-original-authority"),
                value,
            );
        }
        if let Ok(value) = http::header::HeaderValue::from_str(&request.upstream_name) {
            headers.insert(
                http::header::HeaderName::from_static("x-impulse-route-upstream"),
                value,
            );
        }
        if let Some(backend_addr) = request.backend_addr.as_deref()
            && let Ok(value) = http::header::HeaderValue::from_str(backend_addr)
        {
            headers.insert(
                http::header::HeaderName::from_static("x-impulse-backend-address"),
                value,
            );
        }
    }
}

fn external_auth_request_from_pending_forward(
    pending_forward: &PendingForward,
) -> ExternalAuthRequest {
    let mut headers = http::HeaderMap::new();
    for header in pending_forward.request_headers_read_only().iter() {
        if let (Ok(name), Ok(value)) = (
            http::header::HeaderName::from_bytes(header.name()),
            http::header::HeaderValue::from_bytes(header.value()),
        ) {
            headers.append(name, value);
        }
    }
    ExternalAuthRequest {
        method: pending_forward.method.to_string(),
        path: pending_forward.path.to_string(),
        authority: pending_forward.authority.as_deref().map(str::to_string),
        headers,
        upstream_name: pending_forward.upstream_name.to_string(),
        backend_addr: Some(pending_forward.backend_addr.to_string()),
    }
}

async fn collect_auth_body(mut body: Incoming) -> Result<Vec<u8>, ProxyError> {
    use http_body_util::BodyExt as _;

    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|err| ProxyError::Transport(err.to_string()))?;
        let Ok(chunk) = frame.into_data() else {
            continue;
        };
        let next_len = bytes.len().saturating_add(chunk.len());
        if next_len > MAX_AUTH_BODY_BYTES {
            return Err(ProxyError::Transport(format!(
                "external auth body exceeded {MAX_AUTH_BODY_BYTES} bytes"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn authorization_header_from_request(request: &ExternalAuthRequest) -> Option<String> {
    request
        .headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn percent_encode_component(raw: &str) -> String {
    let mut encoded = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push('%');
                encoded.push(char::from(b"0123456789ABCDEF"[(byte >> 4) as usize]));
                encoded.push(char::from(b"0123456789ABCDEF"[(byte & 0x0F) as usize]));
            }
        }
    }
    encoded
}

async fn send_auth_request(
    request: Request<BoxBody<Bytes, Infallible>>,
    timeout: Duration,
) -> Result<Response<Incoming>, ProxyError> {
    tokio::time::timeout(timeout, AuthHttpClient::shared().send(request))
        .await
        .map_err(|_| ProxyError::Timeout)?
}

async fn run_external_auth_with_timeout(
    request: Arc<ExternalAuthRequest>,
    external_auth: ExternalAuthPolicy,
    timeout: Duration,
) -> ExternalAuthResult {
    tokio::time::timeout(timeout, run_external_auth(request, external_auth))
        .await
        .map_err(|_| ProxyError::Timeout)?
}

async fn run_http_external_auth(
    request: Arc<ExternalAuthRequest>,
    endpoint: String,
    request_headers: Vec<ExternalAuthRequestHeader>,
    response_header_allowlist: Vec<String>,
    timeout: Duration,
) -> ExternalAuthResult {
    let mut builder = Request::builder().method(http::Method::GET).uri(endpoint);
    append_external_auth_request_headers(&mut builder, &request, &request_headers);
    let request = builder
        .body(BoxBody::new(Full::new(Bytes::new())))
        .map_err(|err| ProxyError::Transport(err.to_string()))?;
    let response = send_auth_request(request, timeout).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = if status.is_success() || status.is_redirection() {
        Vec::new()
    } else {
        collect_auth_body(response.into_body()).await?
    };
    crate::runtime::connection::auth::map_http_external_auth_response(
        ExternalAuthResponseMetadata {
            status,
            headers: &headers,
            body: &body,
        },
        &response_header_allowlist,
    )
}

async fn fetch_json_document(uri: String, timeout: Duration) -> Result<Value, ProxyError> {
    tokio::time::timeout(timeout, fetch_json_document_inner(uri, timeout))
        .await
        .map_err(|_| ProxyError::Timeout)?
}

async fn fetch_json_document_inner(uri: String, timeout: Duration) -> Result<Value, ProxyError> {
    let request = Request::builder()
        .method(http::Method::GET)
        .uri(uri)
        .body(BoxBody::new(Full::new(Bytes::new())))
        .map_err(|err| ProxyError::Transport(err.to_string()))?;
    let response = send_auth_request(request, timeout).await?;
    if !response.status().is_success() {
        return Err(ProxyError::Transport(format!(
            "oidc discovery returned {}",
            response.status()
        )));
    }
    let body = collect_auth_body(response.into_body()).await?;
    serde_json::from_slice(&body).map_err(|err| ProxyError::Transport(err.to_string()))
}

async fn run_oidc_external_auth(input: OidcExternalAuthInput) -> ExternalAuthResult {
    let OidcExternalAuthInput {
        request,
        discovery_url,
        issuer_url,
        client_id,
        client_secret,
        audience,
        scopes,
        request_headers,
        timeout,
    } = input;
    let token =
        match oidc_authorization_check(authorization_header_from_request(&request).as_deref()) {
            OidcAuthorizationCheck::Token(token) => token,
            OidcAuthorizationCheck::Challenge(response) => {
                return Ok(ExternalAuthDecision::Challenge(response));
            }
        };
    let discovery = oidc_discovery_target(discovery_url.as_deref(), issuer_url.as_deref())?;
    let metadata = oidc_provider_metadata(discovery.url, timeout).await?;

    let mut body = format!(
        "token={}&client_id={}",
        percent_encode_component(&token),
        percent_encode_component(&client_id)
    );
    if let Some(secret) = client_secret.as_deref() {
        body.push_str("&client_secret=");
        body.push_str(&percent_encode_component(secret));
    }
    if let Some(audience) = audience.as_deref() {
        body.push_str("&audience=");
        body.push_str(&percent_encode_component(audience));
    }

    let mut builder = Request::builder()
        .method(http::Method::POST)
        .uri(metadata.introspection_endpoint)
        .header(
            http::header::CONTENT_TYPE,
            http::header::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
    append_external_auth_request_headers(&mut builder, &request, &request_headers);
    let request = builder
        .body(BoxBody::new(Full::new(Bytes::from(body))))
        .map_err(|err| ProxyError::Transport(err.to_string()))?;
    let response = send_auth_request(request, timeout).await?;
    if !response.status().is_success() {
        if response.status().is_client_error() {
            return Ok(ExternalAuthDecision::Deny(ExternalAuthDenyResponse {
                status: http::StatusCode::FORBIDDEN,
                headers: Vec::new(),
                body: b"oidc token rejected\n".to_vec(),
            }));
        }
        return Err(ProxyError::Transport(format!(
            "oidc introspection returned {}",
            response.status()
        )));
    }
    let payload = collect_auth_body(response.into_body()).await?;
    let value: Value =
        serde_json::from_slice(&payload).map_err(|err| ProxyError::Transport(err.to_string()))?;
    if !value
        .get("active")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(ExternalAuthDecision::Deny(ExternalAuthDenyResponse {
            status: http::StatusCode::FORBIDDEN,
            headers: Vec::new(),
            body: b"inactive oidc token\n".to_vec(),
        }));
    }
    if let Some(issuer_url) = issuer_url.as_deref()
        && value.get("iss").and_then(Value::as_str) != Some(issuer_url)
    {
        return Ok(ExternalAuthDecision::Deny(ExternalAuthDenyResponse {
            status: http::StatusCode::FORBIDDEN,
            headers: Vec::new(),
            body: b"unexpected oidc issuer\n".to_vec(),
        }));
    }
    if !oidc_audience_matches(audience.as_deref(), value.get("aud")) {
        return Ok(ExternalAuthDecision::Deny(ExternalAuthDenyResponse {
            status: http::StatusCode::FORBIDDEN,
            headers: Vec::new(),
            body: b"unexpected oidc audience\n".to_vec(),
        }));
    }
    if !scopes.is_empty() {
        let Some(scope_value) = value.get("scope").and_then(Value::as_str) else {
            return Ok(ExternalAuthDecision::Deny(ExternalAuthDenyResponse {
                status: http::StatusCode::FORBIDDEN,
                headers: Vec::new(),
                body: b"missing oidc scopes\n".to_vec(),
            }));
        };
        if !oidc_scope_satisfied(&scopes, scope_value) {
            return Ok(ExternalAuthDecision::Deny(ExternalAuthDenyResponse {
                status: http::StatusCode::FORBIDDEN,
                headers: Vec::new(),
                body: b"missing oidc scopes\n".to_vec(),
            }));
        }
    }

    Ok(ExternalAuthDecision::Allow {
        request_header_mutations: Vec::new(),
    })
}

async fn run_external_auth(
    request: Arc<ExternalAuthRequest>,
    external_auth: ExternalAuthPolicy,
) -> ExternalAuthResult {
    let timeout = ExternalAuthExecutionPolicy::from_external_auth(&external_auth).timeout;
    match external_auth {
        ExternalAuthPolicy::Http {
            endpoint,
            request_headers,
            response_header_allowlist,
            ..
        } => {
            run_http_external_auth(
                request,
                endpoint,
                request_headers,
                response_header_allowlist,
                timeout,
            )
            .await
        }
        ExternalAuthPolicy::Oidc {
            discovery_url,
            issuer_url,
            client_id,
            client_secret,
            audience,
            scopes,
            request_headers,
            ..
        } => {
            run_oidc_external_auth(OidcExternalAuthInput {
                request,
                discovery_url,
                issuer_url,
                client_id,
                client_secret,
                audience,
                scopes,
                request_headers,
                timeout,
            })
            .await
        }
    }
}

pub(crate) async fn execute_external_auth_request(
    request: ExternalAuthRequest,
    external_auth: ExternalAuthPolicy,
) -> ExternalAuthResult {
    let timeout = ExternalAuthExecutionPolicy::from_external_auth(&external_auth).timeout;
    run_external_auth_with_timeout(Arc::new(request), external_auth, timeout).await
}

pub(super) fn start_external_auth_task(
    pending_forward: Arc<PendingForward>,
    external_auth: ExternalAuthPolicy,
) -> Result<AuthStart, ProxyError> {
    let task_config = ExternalAuthTaskConfig::from_external_auth(&external_auth);
    let request = external_auth_request_from_pending_forward(&pending_forward);
    let (tx, rx) = oneshot::channel();
    let fut = async move {
        let result = execute_external_auth_request(request, external_auth).await;
        let _ = tx.send(result);
    };
    let Some(handle) = runtime_handle() else {
        return Err(ProxyError::Transport(
            "dropping external auth task: no runtime available".into(),
        ));
    };
    let join = handle.spawn(fut);
    Ok(AuthStart {
        rx,
        abort: join.abort_handle(),
        deadline: Instant::now() + task_config.timeout,
    })
}

impl QUICListener {
    pub(super) fn complete_auth_result(
        stream_id: u64,
        req: &mut RequestEnvelope,
        result: ExternalAuthResult,
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        exec_ctx: &ForwardingExecutionCtx<'_>,
        shared_ctx: &ForwardingSharedCtx<'_>,
    ) -> Result<bool, quiche::h3::Error> {
        let metrics = shared_ctx.metrics.as_ref();
        let RequestExecutionState::AwaitingAuth(awaiting_auth) = &req.execution else {
            Self::send_simple_response(
                h3,
                quic,
                stream_id,
                http::StatusCode::INTERNAL_SERVER_ERROR,
                b"missing awaiting auth state\n",
            )?;
            return Ok(false);
        };
        let transition =
            resolve_external_auth_state_transition(result, awaiting_auth.auth_disposition);
        match transition {
            ExternalAuthStateTransition::Admitted {
                request_header_mutations,
            } => {
                metrics.policy_observations().inc_external_auth_allowed();
                if let Err(state_err) =
                    req.transition_awaiting_auth_to_dispatch_ready(request_header_mutations)
                {
                    let proxy_err = ProxyError::Transport(format!(
                        "invalid request execution transition: {} from {:?}",
                        state_err.attempted(),
                        req.phase(),
                    ));
                    let _ = crate::runtime::connection::outcome::observe_proxy_error_outcome(
                        metrics,
                        RouteOutcomeTarget {
                            route: req.upstream_name.as_deref().unwrap_or("unrouted"),
                        },
                        Some(BackendOutcomeTarget {
                            upstream: req.upstream_name.as_deref().unwrap_or("unrouted"),
                            backend_addr: req.backend_addr.as_deref(),
                            backend_index: req.backend_index,
                        }),
                        req.start.elapsed(),
                        Some(http::StatusCode::INTERNAL_SERVER_ERROR),
                        &proxy_err,
                        None,
                    );
                    error!("auth completion state transition failed: {:?}", state_err);
                    Self::send_simple_response(
                        h3,
                        quic,
                        stream_id,
                        http::StatusCode::INTERNAL_SERVER_ERROR,
                        b"internal server error\n",
                    )?;
                    req.transition_to_terminal_with_cleanup(
                        TerminalReason::Rejected(RejectionReason::ValidationFailed),
                        metrics,
                    );
                    return Ok(false);
                }
                Self::materialize_forward_after_auth(stream_id, req, h3, quic, exec_ctx, shared_ctx)
            }
            ExternalAuthStateTransition::RejectedAuthDenied { decision } => {
                req.response_status = Some(decision.status().as_u16());
                metrics.policy_observations().inc_policy_denied();
                metrics.policy_observations().inc_external_auth_denied();
                let _ = observe_admission_outcome(
                    metrics,
                    RouteOutcomeTarget {
                        route: req.upstream_name.as_deref().unwrap_or("unrouted"),
                    },
                    Some(BackendOutcomeTarget {
                        upstream: req.upstream_name.as_deref().unwrap_or("unrouted"),
                        backend_addr: req.backend_addr.as_deref(),
                        backend_index: req.backend_index,
                    }),
                    req.start.elapsed(),
                    decision.status(),
                    AdmissionOutcomeClass::AuthDenied,
                );
                warn!(
                    "admission denied: request_id={} upstream={} reason=auth_denied status={}",
                    req.request_id,
                    req.upstream_name.as_deref().unwrap_or("unrouted"),
                    req.response_status.unwrap_or(0)
                );
                Self::send_external_auth_decision_response(h3, quic, stream_id, &decision)?;
                req.mark_terminal_outcome_recorded();
                req.transition_to_terminal_with_cleanup(
                    TerminalReason::Rejected(RejectionReason::AuthDenied),
                    metrics,
                );
                Ok(false)
            }
            ExternalAuthStateTransition::RejectedAuthUnavailable {
                status,
                body,
                error,
            } => {
                metrics.policy_observations().inc_external_auth_error();
                if let Some(error) = &error {
                    debug!(
                        "admission denied: request_id={} upstream={} reason=auth_unavailable detail={:?}",
                        req.request_id,
                        req.upstream_name.as_deref().unwrap_or("unrouted"),
                        error
                    );
                }
                req.response_status = Some(status.as_u16());
                let _ = observe_admission_outcome(
                    metrics,
                    RouteOutcomeTarget {
                        route: req.upstream_name.as_deref().unwrap_or("unrouted"),
                    },
                    Some(BackendOutcomeTarget {
                        upstream: req.upstream_name.as_deref().unwrap_or("unrouted"),
                        backend_addr: req.backend_addr.as_deref(),
                        backend_index: req.backend_index,
                    }),
                    req.start.elapsed(),
                    status,
                    AdmissionOutcomeClass::Failed { timed_out: false },
                );
                Self::send_simple_response(h3, quic, stream_id, status, body)?;
                req.mark_terminal_outcome_recorded();
                req.transition_to_terminal_with_cleanup(
                    TerminalReason::Rejected(RejectionReason::AuthUnavailable),
                    metrics,
                );
                Ok(false)
            }
            ExternalAuthStateTransition::TimedOutAuth { status, body } => {
                metrics.policy_observations().inc_external_auth_timeout();
                req.response_status = Some(status.as_u16());
                let _ = observe_admission_outcome(
                    metrics,
                    RouteOutcomeTarget {
                        route: req.upstream_name.as_deref().unwrap_or("unrouted"),
                    },
                    Some(BackendOutcomeTarget {
                        upstream: req.upstream_name.as_deref().unwrap_or("unrouted"),
                        backend_addr: req.backend_addr.as_deref(),
                        backend_index: req.backend_index,
                    }),
                    req.start.elapsed(),
                    status,
                    AdmissionOutcomeClass::Failed { timed_out: true },
                );
                Self::send_simple_response(h3, quic, stream_id, status, body)?;
                req.mark_terminal_outcome_recorded();
                req.transition_to_terminal_with_cleanup(
                    TerminalReason::TimedOut(TimeoutReason::ExternalAuth),
                    metrics,
                );
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use impulse_config::runtime::{
        RuntimeApiKeyAuth, RuntimeAuthPolicy, RuntimeExternalAuth, RuntimeExternalAuthFailureMode,
        RuntimeForwardedHeaderPolicy, RuntimeHostPolicy, RuntimeProtocolPolicy,
        RuntimeUpstreamPolicy,
    };

    use super::*;

    #[test]
    fn oidc_metadata_cache_has_a_hard_entry_cap() {
        for index in 0..(OIDC_METADATA_CACHE_MAX_ENTRIES + 16) {
            let url = format!("https://issuer-{index}.example/.well-known/openid-configuration");
            let _ = oidc_metadata_cache_entry(&url);
        }

        let cache = oidc_metadata_cache()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(cache.entries.len() <= OIDC_METADATA_CACHE_MAX_ENTRIES);
    }

    #[test]
    fn oidc_metadata_cache_evicts_the_least_recently_used_issuer() {
        let mut cache = OidcMetadataCache::default();
        let hot_url = "https://hot.example/.well-known/openid-configuration";
        let hot_entry = cache.entry(hot_url);

        for index in 1..OIDC_METADATA_CACHE_MAX_ENTRIES {
            let url = format!("https://issuer-{index}.example/.well-known/openid-configuration");
            let _ = cache.entry(&url);
        }

        assert!(Arc::ptr_eq(&hot_entry, &cache.entry(hot_url)));
        let _ = cache.entry("https://new.example/.well-known/openid-configuration");

        assert!(cache.entries.contains_key(hot_url));
        assert!(
            !cache
                .entries
                .contains_key("https://issuer-1.example/.well-known/openid-configuration")
        );
        assert_eq!(cache.entries.len(), OIDC_METADATA_CACHE_MAX_ENTRIES);
    }

    /// Runs a raw TCP server that sends full HTTP headers advertising
    /// `body_len` bytes, then either stalls forever without writing the body
    /// (`stall = true`) or completes normally (`stall = false`). Returns the
    /// bound address; the listener task is detached and exits when the
    /// process/test ends.
    async fn spawn_http_response_server(body_len: usize, stall: bool) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock discovery server");
        let addr = listener.local_addr().expect("mock server addr");
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 1024];
                    // Drain the request so the client isn't blocked writing it.
                    let _ = stream.read(&mut buf).await;
                    let headers = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {body_len}\r\n\r\n"
                    );
                    if stream.write_all(headers.as_bytes()).await.is_err() {
                        return;
                    }
                    if stall {
                        // Never write the body; hold the connection open.
                        std::future::pending::<()>().await;
                    } else {
                        let body = "{}".as_bytes();
                        let _ = stream.write_all(body).await;
                        let _ = stream.shutdown().await;
                    }
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn fetch_json_document_times_out_when_discovery_stalls_after_headers() {
        let addr = spawn_http_response_server(2, true).await;
        let uri = format!("http://{addr}/.well-known/openid-configuration");

        let started = std::time::Instant::now();
        let result = fetch_json_document(uri, Duration::from_millis(200)).await;
        let elapsed = started.elapsed();

        assert!(
            matches!(result, Err(ProxyError::Timeout)),
            "expected a timeout error, got: {result:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "fetch_json_document must not hang past its deadline, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn fetch_json_document_recovers_once_discovery_becomes_healthy() {
        // Reproduces the fix direction's exact scenario: a discovery server
        // that stalls after headers, then later serves a normal response —
        // confirms the lock/timeout path doesn't leave anything wedged.
        let stalled_addr = spawn_http_response_server(2, true).await;
        let stalled_uri = format!("http://{stalled_addr}/.well-known/openid-configuration");
        let stalled_result = fetch_json_document(stalled_uri, Duration::from_millis(200)).await;
        assert!(matches!(stalled_result, Err(ProxyError::Timeout)));

        let healthy_addr = spawn_http_response_server(2, false).await;
        let healthy_uri = format!("http://{healthy_addr}/.well-known/openid-configuration");
        let healthy_result = fetch_json_document(healthy_uri, Duration::from_millis(200)).await;
        assert!(
            healthy_result.is_ok(),
            "a subsequent healthy discovery server must succeed: {healthy_result:?}"
        );
    }

    use crate::{
        quic_listener::admission::{
            AdmissionPolicyDecision, UnauthorizedDecision, evaluate_forwarding_pre_admission_policy,
        },
        resilience::{brownout::BrownoutController, scoped_rate_limit::ScopedRateLimiters},
    };

    #[test]
    fn append_auth_request_headers_strips_unsafe_headers_and_overrides_with_configured_values() {
        let pending_forward = PendingForward::sample_for_test(vec![
            quiche::h3::Header::new(b":method", b"GET"),
            quiche::h3::Header::new(b"host", b"client.example.com"),
            quiche::h3::Header::new(b"connection", b"keep-alive"),
            quiche::h3::Header::new(b"content-length", b"42"),
            quiche::h3::Header::new(b"x-forwarded-for", b"1.2.3.4"),
            quiche::h3::Header::new(b"x-auth-user", b"alice"),
            quiche::h3::Header::new(b"x-role", b"stale"),
        ]);
        let mut builder = http::Request::builder()
            .method(http::Method::GET)
            .uri("https://auth.internal/check");

        append_auth_request_headers(
            &mut builder,
            &pending_forward,
            &[ExternalAuthRequestHeader {
                name: "x-role".to_string(),
                value: "admin".to_string(),
            }],
        );

        let headers = builder.headers_ref().expect("headers");
        assert!(!headers.contains_key(http::header::HOST));
        assert!(!headers.contains_key(http::header::CONNECTION));
        assert!(!headers.contains_key(http::header::CONTENT_LENGTH));
        assert_eq!(
            headers
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok()),
            Some("1.2.3.4")
        );
        assert_eq!(
            headers
                .get("x-auth-user")
                .and_then(|value| value.to_str().ok()),
            Some("alice")
        );
        assert_eq!(
            headers.get("x-role").and_then(|value| value.to_str().ok()),
            Some("admin")
        );
        assert_eq!(
            headers
                .get("x-impulse-original-method")
                .and_then(|value| value.to_str().ok()),
            Some("GET")
        );
        assert_eq!(
            headers
                .get("x-impulse-original-path")
                .and_then(|value| value.to_str().ok()),
            Some("/v1/chat")
        );
        assert_eq!(
            headers
                .get("x-impulse-original-authority")
                .and_then(|value| value.to_str().ok()),
            Some("api.example.com")
        );
    }

    #[test]
    fn percent_encode_component_preserves_safe_bytes_and_encodes_reserved_bytes() {
        assert_eq!(percent_encode_component("AZaz09-_.~"), "AZaz09-_.~");
        assert_eq!(
            percent_encode_component("token value+/=?&%"),
            "token%20value%2B%2F%3D%3F%26%25"
        );
        assert_eq!(percent_encode_component("\n"), "%0A");
    }

    #[test]
    fn local_auth_precedence_is_explicit_before_external_auth_candidates_are_relevant() {
        let policy = RuntimeUpstreamPolicy {
            upstream_auth: RuntimeAuthPolicy {
                api_key: Some(RuntimeApiKeyAuth {
                    header_name: "x-api-key".to_string(),
                    keys: vec!["secret".to_string()],
                }),
                jwt: None,
                external_auth: Some(RuntimeExternalAuth::Http {
                    endpoint: "http://127.0.0.1:9000/auth".to_string(),
                    request_headers: Vec::new(),
                    response_header_allowlist: Vec::new(),
                    timeout: Duration::from_millis(250),
                    failure_mode: RuntimeExternalAuthFailureMode::FailClosed,
                }),
                required_scopes: Vec::new(),
                required_roles: Vec::new(),
            },
            host: RuntimeHostPolicy::default(),
            forwarded_headers: RuntimeForwardedHeaderPolicy::default(),
            response_cache: Default::default(),
            response_compression: Default::default(),
            protocol: RuntimeProtocolPolicy::default(),
        };
        let brownout = BrownoutController::new(false, 100, 90, Vec::new());
        let scoped_rate_limits = ScopedRateLimiters::new(&[]);

        let decision = evaluate_forwarding_pre_admission_policy(
            &policy,
            None,
            &brownout,
            0,
            "api",
            "GET",
            "/resource",
            Some("api.example.com"),
            "198.51.100.10:443".parse().expect("client addr"),
            1,
            &scoped_rate_limits,
        );

        assert!(matches!(
            decision,
            AdmissionPolicyDecision::Unauthorized(UnauthorizedDecision {
                status: http::StatusCode::UNAUTHORIZED,
                body: b"unauthorized\n",
                ..
            })
        ));
    }
}
