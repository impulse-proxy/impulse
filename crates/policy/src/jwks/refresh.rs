use super::*;

pub(super) struct JwtJwksHttpClient {
    client: Client<hyper_rustls::HttpsConnector<HttpConnector>, BoxBody<Bytes, Infallible>>,
}

#[allow(dead_code)]
impl JwtJwksHttpClient {
    fn shared() -> &'static Self {
        JWT_JWKS_HTTP_CLIENT.get_or_init(|| {
            let https = HttpsConnectorBuilder::new()
                .with_webpki_roots()
                .https_only()
                .enable_http1()
                .enable_http2()
                .build();
            let client = Client::builder(hyper_util::rt::TokioExecutor::new())
                .pool_max_idle_per_host(8)
                .pool_idle_timeout(Duration::from_secs(30))
                .build(https);
            Self { client }
        })
    }

    async fn send(
        &self,
        request: Request<BoxBody<Bytes, Infallible>>,
    ) -> Result<Response<Incoming>, JwtJwksFetchFailure> {
        self.client
            .request(request)
            .await
            .map_err(|err| JwtJwksFetchFailure::request_failed(err.to_string()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtJwksFetchFailureReason {
    RequestFailed,
    HttpStatus,
    MalformedDocument,
    AmbiguousDuplicateKid,
}

impl JwtJwksFetchFailureReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RequestFailed => "request_failed",
            Self::HttpStatus => "http_status",
            Self::MalformedDocument => "malformed_document",
            Self::AmbiguousDuplicateKid => "ambiguous_duplicate_kid",
        }
    }
}

#[derive(Debug, Clone)]
pub struct JwtJwksFetchFailure {
    pub reason: JwtJwksFetchFailureReason,
    detail: String,
}

#[allow(dead_code)]
impl JwtJwksFetchFailure {
    pub fn request_failed(detail: String) -> Self {
        Self {
            reason: JwtJwksFetchFailureReason::RequestFailed,
            detail,
        }
    }

    pub(super) fn http_status(status: StatusCode) -> Self {
        Self {
            reason: JwtJwksFetchFailureReason::HttpStatus,
            detail: format!("jwks endpoint returned {status}"),
        }
    }

    pub fn malformed_document(detail: impl Into<String>) -> Self {
        Self {
            reason: JwtJwksFetchFailureReason::MalformedDocument,
            detail: detail.into(),
        }
    }

    fn ambiguous_duplicate_kid(kid: &str) -> Self {
        Self {
            reason: JwtJwksFetchFailureReason::AmbiguousDuplicateKid,
            detail: format!("duplicate jwks kid '{kid}'"),
        }
    }
}

impl std::fmt::Display for JwtJwksFetchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.reason.as_str(), self.detail)
    }
}

#[derive(Debug, Clone)]
struct NormalizedJwksDocument {
    keys: Vec<RuntimeJwtVerificationKey>,
}
pub fn maybe_spawn_jwks_on_demand_refresh(source: &JwtJwksSourceConfig) {
    let now = Instant::now();
    let Some(source) =
        JwtJwksSharedCache::shared().schedule_on_demand_refresh(&source.source_identity, now)
    else {
        return;
    };
    let Some(handle) = runtime_handle() else {
        return;
    };
    handle.spawn(async move {
        let _ = refresh_jwks_source_inflight(source, "on_demand_unknown_kid").await;
    });
}
pub(super) fn jwt_verification_keys_equivalent(
    left: &RuntimeJwtVerificationKey,
    right: &RuntimeJwtVerificationKey,
) -> bool {
    match (left, right) {
        (
            RuntimeJwtVerificationKey::Pem {
                kid: left_kid,
                alg: left_alg,
                public_key_pem: left_pem,
            },
            RuntimeJwtVerificationKey::Pem {
                kid: right_kid,
                alg: right_alg,
                public_key_pem: right_pem,
            },
        ) => left_kid == right_kid && left_alg == right_alg && left_pem == right_pem,
        (
            RuntimeJwtVerificationKey::Jwk {
                kid: left_kid,
                alg: left_alg,
                jwk: left_jwk,
            },
            RuntimeJwtVerificationKey::Jwk {
                kid: right_kid,
                alg: right_alg,
                jwk: right_jwk,
            },
        ) => left_kid == right_kid && left_alg == right_alg && left_jwk == right_jwk,
        _ => false,
    }
}

pub async fn refresh_jwks_source_once(
    source: JwtJwksSourceConfig,
    trigger: &'static str,
) -> Result<(), JwtJwksFetchFailure> {
    let cache = JwtJwksSharedCache::shared();
    let started_at = Instant::now();
    if !cache.begin_refresh(&source, started_at) {
        return Ok(());
    }
    if let Some(metrics) = current_jwt_jwks_metrics() {
        metrics
            .runtime_observations()
            .record_jwks_refresh_started(&source.source_identity, SystemTime::now());
    }
    log::debug!(
        "JWKS refresh started source_id={} endpoint={} trigger={} configured_algorithms={:?}",
        source.source_identity,
        source.public_endpoint(),
        trigger,
        source
            .allowed_algorithms
            .iter()
            .map(|algorithm| jwt_algorithm_name(*algorithm))
            .collect::<Vec<_>>()
    );
    refresh_jwks_source_inflight(source, trigger).await
}

pub async fn refresh_jwks_source_inflight(
    source: JwtJwksSourceConfig,
    trigger: &'static str,
) -> Result<(), JwtJwksFetchFailure> {
    let cache = JwtJwksSharedCache::shared();
    let previous = cache.snapshot(&source.source_identity, Instant::now());
    match fetch_and_normalize_jwks(
        &source.jwks_url,
        &source.allowed_algorithms,
        source.request_timeout,
    )
    .await
    {
        Ok(keys) => {
            cache.complete_refresh_success(&source, Instant::now(), keys);
            if let Some(snapshot) = cache.snapshot(&source.source_identity, Instant::now()) {
                if let Some(metrics) = current_jwt_jwks_metrics() {
                    metrics.runtime_observations().record_jwks_refresh_success(
                        &source.source_identity,
                        jwt_jwks_cache_state_name(snapshot.state),
                        snapshot.active_keys.len(),
                        SystemTime::now(),
                        snapshot.last_success_wall,
                    );
                }
                log::info!(
                    "JWKS key-set replacement source_id={} endpoint={} trigger={} previous_active_keys={} active_keys={} state={}",
                    source.source_identity,
                    source.public_endpoint(),
                    trigger,
                    previous
                        .as_ref()
                        .map(|entry| entry.active_keys.len())
                        .unwrap_or_default(),
                    snapshot.active_keys.len(),
                    jwt_jwks_cache_state_name(snapshot.state)
                );
                match snapshot.state {
                    JwtJwksCacheState::Fresh | JwtJwksCacheState::Stale => {
                        log::debug!(
                            "JWKS refresh published usable key set source_id={} endpoint={} trigger={} state={} active_keys={}",
                            source.source_identity,
                            source.public_endpoint(),
                            trigger,
                            jwt_jwks_cache_state_name(snapshot.state),
                            snapshot.active_keys.len()
                        );
                    }
                    JwtJwksCacheState::QuarantinedRetained => {
                        log::warn!(
                            "JWKS refresh quarantined replacement and retained last-known-good keys source_id={} endpoint={} trigger={} state={} active_keys={} detail={}",
                            source.source_identity,
                            source.public_endpoint(),
                            trigger,
                            jwt_jwks_cache_state_name(snapshot.state),
                            snapshot.active_keys.len(),
                            snapshot
                                .last_error
                                .as_deref()
                                .unwrap_or("replacement produced no usable keys")
                        );
                    }
                    JwtJwksCacheState::EmptyUnusable => {
                        log::warn!(
                            "JWKS refresh left source unusable; JWT requests will be rejected source_id={} endpoint={} trigger={} state={} detail={}",
                            source.source_identity,
                            source.public_endpoint(),
                            trigger,
                            jwt_jwks_cache_state_name(snapshot.state),
                            snapshot
                                .last_error
                                .as_deref()
                                .unwrap_or("replacement produced no usable keys")
                        );
                    }
                    JwtJwksCacheState::NeverFetched | JwtJwksCacheState::RefreshFailedRetained => {
                        log::warn!(
                            "JWKS refresh ended in unexpected cache state source_id={} endpoint={} trigger={} state={}",
                            source.source_identity,
                            source.public_endpoint(),
                            trigger,
                            jwt_jwks_cache_state_name(snapshot.state)
                        );
                    }
                }
            }
            Ok(())
        }
        Err(failure) => {
            cache.complete_refresh_failure(&source, Instant::now(), &failure);
            let snapshot = cache.snapshot(&source.source_identity, Instant::now());
            if let Some(metrics) = current_jwt_jwks_metrics() {
                metrics.runtime_observations().record_jwks_refresh_failure(
                    &source.source_identity,
                    snapshot
                        .as_ref()
                        .map(|entry| jwt_jwks_cache_state_name(entry.state))
                        .unwrap_or("missing"),
                    snapshot
                        .as_ref()
                        .map(|entry| entry.active_keys.len())
                        .unwrap_or_default(),
                    SystemTime::now(),
                    snapshot.as_ref().and_then(|entry| entry.last_success_wall),
                    Some(failure.reason.as_str()),
                );
            }
            let state = snapshot
                .as_ref()
                .map(|entry| jwt_jwks_cache_state_name(entry.state))
                .unwrap_or("missing");
            let retained_keys = snapshot
                .as_ref()
                .map(|entry| entry.active_keys.len())
                .unwrap_or(0);
            let action = if snapshot
                .as_ref()
                .is_some_and(|entry| jwt_jwks_cache_state_usable(entry.state))
            {
                "retain_last_known_good"
            } else {
                "reject_tokens"
            };
            log::warn!(
                "JWKS refresh failed source_id={} endpoint={} trigger={} state={} active_keys={} action={} detail={}",
                source.source_identity,
                source.public_endpoint(),
                trigger,
                state,
                retained_keys,
                action,
                failure
            );
            Err(failure)
        }
    }
}
pub async fn fetch_and_normalize_jwks(
    jwks_url: &str,
    allowed_algorithms: &[JwtAlgorithm],
    timeout: Duration,
) -> Result<Vec<RuntimeJwtVerificationKey>, JwtJwksFetchFailure> {
    let document = fetch_jwks_document(jwks_url, timeout).await?;
    let normalized = normalize_jwks_document(
        &jwt_jwks_public_endpoint(jwks_url),
        &document,
        allowed_algorithms,
    )?;
    Ok(normalized.keys)
}

pub fn normalize_jwks_document_for_test(
    jwks_url: &str,
    document: &Value,
    allowed_algorithms: &[JwtAlgorithm],
) -> Result<Vec<RuntimeJwtVerificationKey>, JwtJwksFetchFailure> {
    normalize_jwks_document(
        &jwt_jwks_public_endpoint(jwks_url),
        document,
        allowed_algorithms,
    )
    .map(|normalized| normalized.keys)
}

#[allow(dead_code)]
async fn fetch_jwks_document(
    jwks_url: &str,
    timeout: Duration,
) -> Result<Value, JwtJwksFetchFailure> {
    if let Some(result) = take_scripted_jwks_fetch_for_test(jwks_url) {
        return result;
    }

    let request = Request::builder()
        .method(http::Method::GET)
        .uri(jwks_url)
        .body(BoxBody::new(Full::new(Bytes::new())))
        .map_err(|err| JwtJwksFetchFailure::request_failed(err.to_string()))?;
    let response = tokio::time::timeout(timeout, JwtJwksHttpClient::shared().send(request))
        .await
        .map_err(|_| JwtJwksFetchFailure::request_failed("jwks request timed out".to_string()))??;
    if !response.status().is_success() {
        return Err(JwtJwksFetchFailure::http_status(response.status()));
    }
    let body = collect_jwks_body(response.into_body()).await?;
    serde_json::from_slice::<Value>(&body)
        .map_err(|err| JwtJwksFetchFailure::malformed_document(err.to_string()))
}

fn take_scripted_jwks_fetch_for_test(jwks_url: &str) -> Option<Result<Value, JwtJwksFetchFailure>> {
    JWT_JWKS_FETCH_SCRIPT
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("jwks fetch script lock")
        .get_mut(jwks_url)
        .and_then(VecDeque::pop_front)
}

pub fn script_jwks_fetches_for_test(
    jwks_url: &str,
    responses: Vec<Result<Value, JwtJwksFetchFailure>>,
) {
    JWT_JWKS_FETCH_SCRIPT
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("jwks fetch script lock")
        .insert(jwks_url.to_string(), VecDeque::from(responses));
}

#[allow(dead_code)]
async fn collect_jwks_body(body: Incoming) -> Result<Vec<u8>, JwtJwksFetchFailure> {
    collect_jwks_body_bounded(body).await
}

pub async fn collect_jwks_body_bounded<B>(mut body: B) -> Result<Vec<u8>, JwtJwksFetchFailure>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|err| JwtJwksFetchFailure::request_failed(err.to_string()))?;
        let Ok(chunk) = frame.into_data() else {
            continue;
        };
        let next_len = bytes.len().saturating_add(chunk.len());
        if next_len > MAX_JWKS_BODY_BYTES {
            return Err(JwtJwksFetchFailure::malformed_document(format!(
                "jwks document exceeded {} bytes",
                MAX_JWKS_BODY_BYTES
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// `endpoint` must already be sanitized (see [`jwt_jwks_public_endpoint`]); this
/// function logs it, so a raw configured URL would leak query credentials.
fn normalize_jwks_document(
    endpoint: &str,
    document: &Value,
    allowed_algorithms: &[JwtAlgorithm],
) -> Result<NormalizedJwksDocument, JwtJwksFetchFailure> {
    let keys = document
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| JwtJwksFetchFailure::malformed_document("jwks document missing keys[]"))?;
    let allowed_algorithms = allowed_algorithms.iter().copied().collect::<HashSet<_>>();
    let mut normalized = Vec::new();
    let mut seen_kids = HashSet::new();

    for (index, jwk) in keys.iter().enumerate() {
        let Some(key) = (match normalize_jwks_key(jwk, &allowed_algorithms) {
            Ok(key) => key,
            Err(detail) => {
                log::warn!(
                    "Ignoring suspicious JWKS key endpoint={} index={} reason={}",
                    endpoint,
                    index,
                    detail
                );
                None
            }
        }) else {
            continue;
        };
        let effective_kid = static_key_metadata(&key)
            .map_err(|failure| JwtJwksFetchFailure::malformed_document(failure.reason.as_str()))?
            .kid;
        if let Some(kid) = effective_kid.as_deref()
            && !seen_kids.insert(kid.to_string())
        {
            return Err(JwtJwksFetchFailure::ambiguous_duplicate_kid(kid));
        }
        normalized.push(key);
    }

    let configured_algorithms = allowed_algorithms
        .iter()
        .copied()
        .map(jwt_algorithm_name)
        .collect::<Vec<_>>()
        .join(",");
    log::debug!(
        "JWKS fetch normalized endpoint={} accepted_keys={} configured_algorithms={}",
        endpoint,
        normalized.len(),
        configured_algorithms
    );

    Ok(NormalizedJwksDocument { keys: normalized })
}

fn normalize_jwks_key(
    jwk: &Value,
    allowed_algorithms: &HashSet<JwtAlgorithm>,
) -> Result<Option<RuntimeJwtVerificationKey>, String> {
    let Some(jwk_object) = jwk.as_object() else {
        return Err("must be a JSON object".to_string());
    };

    if let Some(use_value) = jwk_object.get("use").and_then(Value::as_str)
        && use_value != "sig"
    {
        log::debug!("Ignoring JWKS key: key use '{}' is not accepted", use_value);
        return Ok(None);
    }

    if let Some(key_ops) = jwk_object.get("key_ops").and_then(Value::as_array)
        && !key_ops
            .iter()
            .filter_map(Value::as_str)
            .any(|operation| operation == "verify")
    {
        log::debug!("Ignoring JWKS key: key_ops does not include verify");
        return Ok(None);
    }

    let algorithm = match jwk_object.get("alg").and_then(Value::as_str) {
        Some(alg) => parse_jwt_alg_str(alg)
            .map_err(|_| format!("declares unsupported alg '{alg}' for jwks normalization"))?,
        None => infer_jwk_algorithm(jwk)?,
    };
    if !matches!(algorithm, JwtAlgorithm::Rs256 | JwtAlgorithm::Es256) {
        log::debug!(
            "Ignoring JWKS key: algorithm '{}' is not an asymmetric signing algorithm",
            jwt_algorithm_name(algorithm)
        );
        return Ok(None);
    }
    if !allowed_algorithms.contains(&algorithm) {
        log::debug!(
            "Ignoring JWKS key: algorithm '{}' is not enabled by policy",
            jwt_algorithm_name(algorithm)
        );
        return Ok(None);
    }

    let kid = jwk_object
        .get("kid")
        .and_then(Value::as_str)
        .map(str::to_string);
    let jwk_string =
        serde_json::to_string(jwk).map_err(|err| format!("failed to serialize jwk: {err}"))?;
    let normalized = RuntimeJwtVerificationKey::Jwk {
        kid,
        alg: Some(algorithm),
        jwk: jwk_string,
    };
    parse_static_verification_key(&normalized, algorithm).map_err(|failure| {
        format!(
            "cannot be used for {} verification: {}",
            jwt_algorithm_name(algorithm),
            failure.reason.as_str()
        )
    })?;
    Ok(Some(normalized))
}

fn infer_jwk_algorithm(jwk: &Value) -> Result<JwtAlgorithm, String> {
    let Some(kty) = jwk.get("kty").and_then(Value::as_str) else {
        return Err("is missing kty".to_string());
    };
    match kty {
        "RSA" => Ok(JwtAlgorithm::Rs256),
        "EC" => match jwk.get("crv").and_then(Value::as_str) {
            Some("P-256") => Ok(JwtAlgorithm::Es256),
            Some(other) => Err(format!("declares unsupported EC curve '{other}'")),
            None => Err("is missing crv for EC key".to_string()),
        },
        other => Err(format!("declares unsupported kty '{other}'")),
    }
}

fn jwt_algorithm_name(algorithm: JwtAlgorithm) -> &'static str {
    match algorithm {
        JwtAlgorithm::Hs256 => "HS256",
        JwtAlgorithm::Rs256 => "RS256",
        JwtAlgorithm::Es256 => "ES256",
    }
}
