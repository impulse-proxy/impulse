use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum JwtJwksCacheState {
    NeverFetched,
    Fresh,
    Stale,
    RefreshFailedRetained,
    QuarantinedRetained,
    EmptyUnusable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct JwtJwksSourceConfig {
    pub(super) source_identity: String,
    pub(super) jwks_url: String,
    pub(super) allowed_algorithms: Vec<JwtAlgorithm>,
    pub(super) refresh_interval: Duration,
    pub(super) request_timeout: Duration,
    pub(super) cache_ttl: Duration,
    pub(super) stale_if_error: Duration,
    pub(super) startup_behavior: JwksStartupBehavior,
}

impl JwtJwksSourceConfig {
    pub(super) fn from_jwt(jwt: &RuntimeJwtAuth) -> Option<Self> {
        let jwks_url = jwt.jwks_url.as_ref()?.to_string();
        let mut allowed_algorithms = jwt
            .allowed_algorithms
            .iter()
            .copied()
            .filter(|algorithm| matches!(algorithm, JwtAlgorithm::Rs256 | JwtAlgorithm::Es256))
            .collect::<Vec<_>>();
        allowed_algorithms.sort_by_key(|algorithm| jwt_algorithm_name(*algorithm));
        allowed_algorithms.dedup();
        Some(Self {
            source_identity: jwt_jwks_source_identity(&jwks_url, &allowed_algorithms),
            jwks_url,
            allowed_algorithms,
            refresh_interval: jwt.jwks_refresh_interval,
            request_timeout: jwt.jwks_request_timeout,
            cache_ttl: jwt.jwks_cache_ttl,
            stale_if_error: jwt.jwks_stale_if_error,
            startup_behavior: jwt.jwks_startup_behavior.clone(),
        })
    }

    pub(super) fn on_demand_refresh_cooldown(&self) -> Duration {
        self.refresh_interval
            .min(Duration::from_secs(30))
            .max(Duration::from_secs(5))
    }

    pub(super) fn public_endpoint(&self) -> String {
        jwt_jwks_public_endpoint(&self.jwks_url)
    }
}

#[derive(Debug, Clone)]
pub(super) struct JwtJwksCacheEntry {
    pub(super) source: JwtJwksSourceConfig,
    pub(super) state: JwtJwksCacheState,
    pub(super) active_keys: Vec<JwtJwksActiveKey>,
    pub(super) refresh_in_flight: bool,
    pub(super) last_refresh_started_at: Option<Instant>,
    pub(super) last_refresh_started_wall: Option<SystemTime>,
    pub(super) last_refresh_completed_at: Option<Instant>,
    pub(super) last_refresh_completed_wall: Option<SystemTime>,
    pub(super) last_success_at: Option<Instant>,
    pub(super) last_success_wall: Option<SystemTime>,
    pub(super) last_failure_at: Option<Instant>,
    pub(super) last_failure_wall: Option<SystemTime>,
    pub(super) last_error: Option<String>,
    pub(super) last_failure_reason: Option<JwtJwksFetchFailureReason>,
    pub(super) next_on_demand_refresh_at: Option<Instant>,
}

#[derive(Debug, Clone)]
pub(super) struct JwtJwksCacheSnapshot {
    pub(super) source: JwtJwksSourceConfig,
    pub(super) state: JwtJwksCacheState,
    pub(super) active_keys: Vec<RuntimeJwtVerificationKey>,
    pub(super) last_error: Option<String>,
    pub(super) last_failure_reason: Option<JwtJwksFetchFailureReason>,
    pub(super) last_success_at: Option<Instant>,
    pub(super) last_refresh_started_wall: Option<SystemTime>,
    pub(super) last_success_wall: Option<SystemTime>,
}

#[derive(Debug, Clone)]
pub(super) struct JwtJwksActiveKey {
    pub(super) key: RuntimeJwtVerificationKey,
    pub(super) retained_until: Option<Instant>,
}

pub(super) struct JwtJwksSharedCache {
    pub(super) entries: RwLock<HashMap<String, JwtJwksCacheEntry>>,
}

static JWT_JWKS_SHARED_CACHE: OnceLock<JwtJwksSharedCache> = OnceLock::new();
pub(super) static JWT_JWKS_HTTP_CLIENT: OnceLock<JwtJwksHttpClient> = OnceLock::new();
static JWT_JWKS_METRICS_SINK: OnceLock<RwLock<Weak<crate::Metrics>>> = OnceLock::new();
#[cfg(test)]
type JwtJwksFetchScript = Mutex<HashMap<String, VecDeque<Result<Value, JwtJwksFetchFailure>>>>;
#[cfg(test)]
pub(super) static JWT_JWKS_FETCH_SCRIPT: OnceLock<JwtJwksFetchScript> = OnceLock::new();

#[allow(dead_code)]
pub(super) const MAX_JWKS_BODY_BYTES: usize = 256 * 1024;

impl JwtJwksSharedCache {
    pub(super) fn shared() -> &'static Self {
        JWT_JWKS_SHARED_CACHE.get_or_init(|| Self {
            entries: RwLock::new(HashMap::new()),
        })
    }

    pub(super) fn register_source(&self, source: JwtJwksSourceConfig) {
        let Ok(mut entries) = self.entries.write() else {
            log::error!(
                "JWKS cache lock poisoned; skipping source registration source_id={}",
                source.source_identity
            );
            return;
        };
        entries
            .entry(source.source_identity.clone())
            .and_modify(|entry| {
                merge_jwks_source_config(&mut entry.source, &source);
            })
            .or_insert_with(|| new_jwks_cache_entry(source));
    }

    pub(super) fn register_sources<'a, I>(&self, sources: I)
    where
        I: IntoIterator<Item = &'a JwtJwksSourceConfig>,
    {
        let Ok(mut entries) = self.entries.write() else {
            log::error!("JWKS cache lock poisoned; skipping source registration");
            return;
        };

        for source in sources {
            entries
                .entry(source.source_identity.clone())
                .and_modify(|entry| {
                    merge_jwks_source_config(&mut entry.source, source);
                })
                .or_insert_with(|| new_jwks_cache_entry(source.clone()));
        }
    }

    pub(super) fn reconcile_sources<'a, I>(&self, active_sources: I)
    where
        I: IntoIterator<Item = &'a JwtJwksSourceConfig>,
    {
        let active_sources = active_sources
            .into_iter()
            .map(|source| (source.source_identity.clone(), source.clone()))
            .collect::<HashMap<_, _>>();
        let active_source_ids = active_sources.keys().cloned().collect::<HashSet<_>>();

        let Ok(mut entries) = self.entries.write() else {
            log::error!("JWKS cache lock poisoned; skipping source reconciliation");
            return;
        };

        let before = entries.len();
        entries.retain(|source_identity, _| active_source_ids.contains(source_identity));
        for (source_identity, source) in active_sources {
            entries
                .entry(source_identity)
                .and_modify(|entry| {
                    merge_jwks_source_config(&mut entry.source, &source);
                })
                .or_insert_with(|| new_jwks_cache_entry(source));
        }
        let removed = before.saturating_sub(entries.len());
        drop(entries);

        if let Some(metrics) = current_jwt_jwks_metrics() {
            metrics
                .runtime_observations()
                .reconcile_jwks_sources(active_source_ids.iter().map(String::as_str));
        }

        if removed > 0 {
            log::debug!("JWKS cache reconciled removed_sources={removed}");
        }
    }

    pub(super) fn snapshot(
        &self,
        source_identity: &str,
        now: Instant,
    ) -> Option<JwtJwksCacheSnapshot> {
        // A poisoned lock yields `None`, which callers already treat as an
        // unavailable key source and reject rather than admit.
        self.entries
            .read()
            .ok()?
            .get(source_identity)
            .map(|entry| JwtJwksCacheSnapshot {
                source: entry.source.clone(),
                state: entry.effective_state(now),
                active_keys: entry
                    .active_keys(now)
                    .into_iter()
                    .map(|active| active.key)
                    .collect(),
                last_error: entry.last_error.clone(),
                last_failure_reason: entry.last_failure_reason,
                last_success_at: entry.last_success_at,
                last_refresh_started_wall: entry.last_refresh_started_wall,
                last_success_wall: entry.last_success_wall,
            })
    }

    pub(super) fn begin_refresh(&self, source: &JwtJwksSourceConfig, now: Instant) -> bool {
        let Ok(mut entries) = self.entries.write() else {
            log::error!(
                "JWKS cache lock poisoned; skipping refresh source_id={}",
                source.source_identity
            );
            return false;
        };
        let Some(entry) = entries.get_mut(&source.source_identity) else {
            return false;
        };
        if entry.refresh_in_flight {
            return false;
        }
        entry.refresh_in_flight = true;
        entry.last_refresh_started_at = Some(now);
        entry.last_refresh_started_wall = Some(SystemTime::now());
        true
    }

    pub(super) fn complete_refresh_success(
        &self,
        source_identity: &str,
        now: Instant,
        keys: Vec<RuntimeJwtVerificationKey>,
    ) {
        let Ok(mut entries) = self.entries.write() else {
            log::error!(
                "JWKS cache lock poisoned; dropping refresh result source={source_identity}"
            );
            return;
        };
        let Some(entry) = entries.get_mut(source_identity) else {
            return;
        };
        entry.refresh_in_flight = false;
        entry.last_refresh_completed_at = Some(now);
        entry.last_refresh_completed_wall = Some(SystemTime::now());
        entry.last_error = None;
        entry.last_failure_reason = None;
        entry.last_failure_at = None;
        entry.last_failure_wall = None;
        if keys.is_empty() {
            if entry.active_keys(now).is_empty() {
                entry.active_keys.clear();
                entry.state = JwtJwksCacheState::EmptyUnusable;
            } else {
                entry.state = JwtJwksCacheState::QuarantinedRetained;
                entry.prune_expired_keys(now);
                entry.last_failure_at = Some(now);
                entry.last_failure_wall = Some(SystemTime::now());
                entry.last_error =
                    Some("empty_jwks: replacement produced no usable keys".to_string());
                entry.last_failure_reason = Some(JwtJwksFetchFailureReason::MalformedDocument);
            }
            return;
        }
        entry.active_keys = entry.rollover_keys(keys, now);
        entry.last_success_at = Some(now);
        entry.last_success_wall = Some(SystemTime::now());
        entry.state = JwtJwksCacheState::Fresh;
    }

    pub(super) fn complete_refresh_failure(
        &self,
        source_identity: &str,
        now: Instant,
        failure: &JwtJwksFetchFailure,
    ) {
        let Ok(mut entries) = self.entries.write() else {
            log::error!(
                "JWKS cache lock poisoned; dropping refresh failure source={source_identity}"
            );
            return;
        };
        let Some(entry) = entries.get_mut(source_identity) else {
            return;
        };
        entry.refresh_in_flight = false;
        entry.last_refresh_completed_at = Some(now);
        entry.last_refresh_completed_wall = Some(SystemTime::now());
        entry.last_failure_at = Some(now);
        entry.last_failure_wall = Some(SystemTime::now());
        entry.last_error = Some(failure.to_string());
        entry.last_failure_reason = Some(failure.reason);
        if entry.active_keys(now).is_empty() {
            entry.state = JwtJwksCacheState::EmptyUnusable;
        } else {
            entry.state = JwtJwksCacheState::RefreshFailedRetained;
        }
    }

    pub(super) fn schedule_on_demand_refresh(
        &self,
        source_identity: &str,
        now: Instant,
    ) -> Option<JwtJwksSourceConfig> {
        // A poisoned lock means no on-demand refresh is scheduled; the periodic
        // refresh remains the recovery path.
        let mut entries = self.entries.write().ok()?;
        let entry = entries.get_mut(source_identity)?;
        if entry.refresh_in_flight {
            return None;
        }
        if let Some(next_allowed) = entry.next_on_demand_refresh_at
            && now < next_allowed
        {
            return None;
        }
        entry.refresh_in_flight = true;
        entry.last_refresh_started_at = Some(now);
        entry.last_refresh_started_wall = Some(SystemTime::now());
        entry.next_on_demand_refresh_at = Some(now + entry.source.on_demand_refresh_cooldown());
        Some(entry.source.clone())
    }

    #[cfg(test)]
    pub(super) fn upsert(&self, source_identity: &str, entry: JwtJwksCacheEntry) {
        self.entries
            .write()
            .expect("jwks shared cache write lock")
            .insert(source_identity.to_string(), entry);
    }

    #[cfg(test)]
    pub(super) fn remove(&self, source_identity: &str) {
        self.entries
            .write()
            .expect("jwks shared cache write lock")
            .remove(source_identity);
    }
}

fn new_jwks_cache_entry(source: JwtJwksSourceConfig) -> JwtJwksCacheEntry {
    JwtJwksCacheEntry {
        source,
        state: JwtJwksCacheState::NeverFetched,
        active_keys: Vec::new(),
        refresh_in_flight: false,
        last_refresh_started_at: None,
        last_refresh_started_wall: None,
        last_refresh_completed_at: None,
        last_refresh_completed_wall: None,
        last_success_at: None,
        last_success_wall: None,
        last_failure_at: None,
        last_failure_wall: None,
        last_error: None,
        last_failure_reason: None,
        next_on_demand_refresh_at: None,
    }
}

pub(super) fn jwt_jwks_metrics_sink() -> &'static RwLock<Weak<crate::Metrics>> {
    JWT_JWKS_METRICS_SINK.get_or_init(|| RwLock::new(Weak::new()))
}

pub(super) fn current_jwt_jwks_metrics() -> Option<Arc<crate::Metrics>> {
    jwt_jwks_metrics_sink()
        .read()
        .ok()
        .and_then(|metrics| metrics.upgrade())
}

impl JwtJwksCacheEntry {
    pub(super) fn active_keys(&self, now: Instant) -> Vec<JwtJwksActiveKey> {
        self.active_keys
            .iter()
            .filter(|active| active.retained_until.is_none_or(|until| now <= until))
            .cloned()
            .collect()
    }

    pub(super) fn prune_expired_keys(&mut self, now: Instant) {
        self.active_keys
            .retain(|active| active.retained_until.is_none_or(|until| now <= until));
    }

    pub(super) fn rollover_keys(
        &self,
        new_keys: Vec<RuntimeJwtVerificationKey>,
        now: Instant,
    ) -> Vec<JwtJwksActiveKey> {
        let overlap_until = now + self.source.stale_if_error;
        let mut merged = new_keys
            .into_iter()
            .map(|key| JwtJwksActiveKey {
                key,
                retained_until: None,
            })
            .collect::<Vec<_>>();

        for existing in self.active_keys(now) {
            if merged
                .iter()
                .any(|candidate| jwt_verification_keys_equivalent(&candidate.key, &existing.key))
            {
                continue;
            }
            let existing_kid = static_key_metadata(&existing.key)
                .ok()
                .and_then(|metadata| metadata.kid);
            let same_kid_replaced = existing_kid.as_deref().is_some_and(|kid| {
                merged.iter().any(|candidate| {
                    static_key_metadata(&candidate.key)
                        .ok()
                        .and_then(|metadata| metadata.kid)
                        .as_deref()
                        == Some(kid)
                })
            });
            if same_kid_replaced {
                continue;
            }
            merged.push(JwtJwksActiveKey {
                key: existing.key,
                retained_until: Some(overlap_until),
            });
        }
        merged
    }

    pub(super) fn effective_state(&self, now: Instant) -> JwtJwksCacheState {
        if self.active_keys(now).is_empty() {
            return match self.state {
                JwtJwksCacheState::NeverFetched => JwtJwksCacheState::NeverFetched,
                _ => JwtJwksCacheState::EmptyUnusable,
            };
        }
        let Some(last_success_at) = self.last_success_at else {
            return self.state;
        };
        let age = now.saturating_duration_since(last_success_at);
        if age <= self.source.cache_ttl {
            return match self.state {
                JwtJwksCacheState::RefreshFailedRetained => {
                    JwtJwksCacheState::RefreshFailedRetained
                }
                JwtJwksCacheState::QuarantinedRetained => JwtJwksCacheState::QuarantinedRetained,
                _ => JwtJwksCacheState::Fresh,
            };
        }
        if age
            <= self
                .source
                .cache_ttl
                .saturating_add(self.source.stale_if_error)
        {
            return match self.state {
                JwtJwksCacheState::RefreshFailedRetained => {
                    JwtJwksCacheState::RefreshFailedRetained
                }
                JwtJwksCacheState::QuarantinedRetained => JwtJwksCacheState::QuarantinedRetained,
                _ => JwtJwksCacheState::Stale,
            };
        }
        JwtJwksCacheState::EmptyUnusable
    }
}
#[cfg(test)]
pub(crate) fn prime_jwks_cache_for_test(
    source_identity: &str,
    stale: bool,
    keys: Vec<RuntimeJwtVerificationKey>,
) {
    let cache_key = jwks_test_cache_key(source_identity);
    let source = JwtJwksSourceConfig {
        source_identity: cache_key.clone(),
        jwks_url: source_identity.to_string(),
        allowed_algorithms: vec![JwtAlgorithm::Rs256, JwtAlgorithm::Es256],
        refresh_interval: Duration::from_secs(60),
        request_timeout: Duration::from_secs(5),
        cache_ttl: Duration::from_secs(60),
        stale_if_error: Duration::from_secs(60),
        startup_behavior: JwksStartupBehavior::AllowDegraded,
    };
    JwtJwksSharedCache::shared().upsert(
        &cache_key,
        JwtJwksCacheEntry {
            source,
            state: if stale {
                JwtJwksCacheState::Stale
            } else {
                JwtJwksCacheState::Fresh
            },
            active_keys: keys
                .into_iter()
                .map(|key| JwtJwksActiveKey {
                    key,
                    retained_until: None,
                })
                .collect(),
            refresh_in_flight: false,
            last_refresh_started_at: None,
            last_refresh_started_wall: None,
            last_refresh_completed_at: None,
            last_refresh_completed_wall: None,
            last_success_at: Some(Instant::now()),
            last_success_wall: Some(SystemTime::now()),
            last_failure_at: None,
            last_failure_wall: None,
            last_error: None,
            last_failure_reason: None,
            next_on_demand_refresh_at: None,
        },
    );
}

#[cfg(test)]
pub(crate) fn mark_jwks_source_unavailable_for_test(source_identity: &str) {
    let cache_key = jwks_test_cache_key(source_identity);
    let source = JwtJwksSourceConfig {
        source_identity: cache_key.clone(),
        jwks_url: source_identity.to_string(),
        allowed_algorithms: vec![JwtAlgorithm::Rs256, JwtAlgorithm::Es256],
        refresh_interval: Duration::from_secs(60),
        request_timeout: Duration::from_secs(5),
        cache_ttl: Duration::from_secs(60),
        stale_if_error: Duration::from_secs(60),
        startup_behavior: JwksStartupBehavior::AllowDegraded,
    };
    JwtJwksSharedCache::shared().upsert(
        &cache_key,
        JwtJwksCacheEntry {
            source,
            state: JwtJwksCacheState::NeverFetched,
            active_keys: Vec::new(),
            refresh_in_flight: false,
            last_refresh_started_at: None,
            last_refresh_started_wall: None,
            last_refresh_completed_at: None,
            last_refresh_completed_wall: None,
            last_success_at: None,
            last_success_wall: None,
            last_failure_at: Some(Instant::now()),
            last_failure_wall: Some(SystemTime::now()),
            last_error: Some("request_failed: scripted unavailable jwks source".to_string()),
            last_failure_reason: Some(JwtJwksFetchFailureReason::RequestFailed),
            next_on_demand_refresh_at: None,
        },
    );
}

#[cfg(test)]
pub(crate) fn mark_jwks_source_invalid_for_test(source_identity: &str) {
    let cache_key = jwks_test_cache_key(source_identity);
    let source = JwtJwksSourceConfig {
        source_identity: cache_key.clone(),
        jwks_url: source_identity.to_string(),
        allowed_algorithms: vec![JwtAlgorithm::Rs256, JwtAlgorithm::Es256],
        refresh_interval: Duration::from_secs(60),
        request_timeout: Duration::from_secs(5),
        cache_ttl: Duration::from_secs(60),
        stale_if_error: Duration::from_secs(60),
        startup_behavior: JwksStartupBehavior::AllowDegraded,
    };
    JwtJwksSharedCache::shared().upsert(
        &cache_key,
        JwtJwksCacheEntry {
            source,
            state: JwtJwksCacheState::EmptyUnusable,
            active_keys: Vec::new(),
            refresh_in_flight: false,
            last_refresh_started_at: None,
            last_refresh_started_wall: None,
            last_refresh_completed_at: None,
            last_refresh_completed_wall: None,
            last_success_at: None,
            last_success_wall: None,
            last_failure_at: Some(Instant::now()),
            last_failure_wall: Some(SystemTime::now()),
            last_error: Some("malformed_document: scripted invalid jwks source".to_string()),
            last_failure_reason: Some(JwtJwksFetchFailureReason::MalformedDocument),
            next_on_demand_refresh_at: None,
        },
    );
}

#[cfg(test)]
pub(crate) fn clear_jwks_cache_for_test(source_identity: &str) {
    JwtJwksSharedCache::shared().remove(&jwks_test_cache_key(source_identity));
}

#[cfg(test)]
pub(crate) fn jwks_source_identity_for_test(jwks_url: &str) -> String {
    jwt_jwks_source_identity(jwks_url, &[])
}

#[cfg(test)]
fn jwks_test_cache_key(source_identity: &str) -> String {
    if source_identity.starts_with("https://") {
        jwks_source_identity_for_test(source_identity)
    } else {
        source_identity.to_string()
    }
}

pub(crate) fn runtime_jwks_source_identity(jwt: &RuntimeJwtAuth) -> Option<String> {
    JwtJwksSourceConfig::from_jwt(jwt).map(|source| source.source_identity)
}

pub(super) fn jwt_jwks_source_identity(
    jwks_url: &str,
    allowed_algorithms: &[JwtAlgorithm],
) -> String {
    let _ = allowed_algorithms;
    let digest = Sha256::digest(jwks_url.as_bytes());
    format!("jwks:{}", hex::encode(&digest[..12]))
}

pub(super) fn jwt_jwks_public_endpoint(jwks_url: &str) -> String {
    jwks_url
        .split(['?', '#'])
        .next()
        .unwrap_or(jwks_url)
        .to_string()
}

pub(super) fn merge_jwks_source_config(
    existing: &mut JwtJwksSourceConfig,
    incoming: &JwtJwksSourceConfig,
) {
    let mut merged_algorithms = existing.allowed_algorithms.clone();
    for algorithm in &incoming.allowed_algorithms {
        if !merged_algorithms.contains(algorithm) {
            merged_algorithms.push(*algorithm);
        }
    }
    merged_algorithms.sort_by_key(|algorithm| jwt_algorithm_name(*algorithm));
    existing.allowed_algorithms = merged_algorithms;
    existing.refresh_interval = existing.refresh_interval.min(incoming.refresh_interval);
    existing.request_timeout = existing.request_timeout.max(incoming.request_timeout);
    existing.cache_ttl = existing.cache_ttl.min(incoming.cache_ttl);
    existing.stale_if_error = existing.stale_if_error.max(incoming.stale_if_error);
    existing.startup_behavior = match (&existing.startup_behavior, &incoming.startup_behavior) {
        (JwksStartupBehavior::RequireReady, _) | (_, JwksStartupBehavior::RequireReady) => {
            JwksStartupBehavior::RequireReady
        }
        _ => JwksStartupBehavior::AllowDegraded,
    };
}

pub(super) fn runtime_jwks_sources(config: &RuntimeConfig) -> Vec<JwtJwksSourceConfig> {
    let mut sources = HashMap::<String, JwtJwksSourceConfig>::new();
    for upstream in config.upstreams.values() {
        let Some(jwt) = upstream.policy.upstream_auth.jwt.as_ref() else {
            continue;
        };
        let Some(source) = JwtJwksSourceConfig::from_jwt(jwt) else {
            continue;
        };
        sources
            .entry(source.source_identity.clone())
            .and_modify(|existing| merge_jwks_source_config(existing, &source))
            .or_insert(source);
    }
    let mut sources = sources.into_values().collect::<Vec<_>>();
    sources.sort_by(|left, right| left.source_identity.cmp(&right.source_identity));
    sources
}
pub(super) fn jwt_jwks_cache_state_name(state: JwtJwksCacheState) -> &'static str {
    match state {
        JwtJwksCacheState::NeverFetched => "never_fetched",
        JwtJwksCacheState::Fresh => "fresh",
        JwtJwksCacheState::Stale => "stale",
        JwtJwksCacheState::RefreshFailedRetained => "refresh_failed_retained",
        JwtJwksCacheState::QuarantinedRetained => "quarantined_retained",
        JwtJwksCacheState::EmptyUnusable => "empty_unusable",
    }
}

pub(super) fn jwt_jwks_cache_state_usable(state: JwtJwksCacheState) -> bool {
    matches!(
        state,
        JwtJwksCacheState::Fresh
            | JwtJwksCacheState::Stale
            | JwtJwksCacheState::RefreshFailedRetained
            | JwtJwksCacheState::QuarantinedRetained
    )
}

pub(super) fn jwt_jwks_cache_stale_window_expired(snapshot: &JwtJwksCacheSnapshot) -> bool {
    matches!(snapshot.state, JwtJwksCacheState::EmptyUnusable) && snapshot.last_success_at.is_some()
}

#[derive(Debug, Clone)]
pub(crate) struct JwtJwksRuntimeSnapshot {
    pub(crate) source_id: String,
    pub(crate) allowed_algorithms: Vec<String>,
    pub(crate) startup_behavior: &'static str,
    pub(crate) state: &'static str,
    pub(crate) active_key_count: usize,
    pub(crate) age_seconds: Option<u64>,
    pub(crate) last_refresh_attempt_unix_seconds: Option<u64>,
    pub(crate) last_refresh_success_unix_seconds: Option<u64>,
    pub(crate) last_failure_reason: Option<String>,
    pub(crate) last_error: Option<String>,
}

pub(crate) fn snapshot_runtime_jwks_sources(config: &RuntimeConfig) -> Vec<JwtJwksRuntimeSnapshot> {
    let now = Instant::now();
    let mut snapshots = runtime_jwks_sources(config)
        .into_iter()
        .map(|source| {
            let entry = JwtJwksSharedCache::shared().snapshot(&source.source_identity, now);
            let state = entry
                .as_ref()
                .map(|entry| jwt_jwks_cache_state_name(entry.state))
                .unwrap_or("never_fetched");
            let active_key_count = entry
                .as_ref()
                .map(|entry| entry.active_keys.len())
                .unwrap_or_default();
            let age_seconds = entry.as_ref().and_then(|entry| {
                entry
                    .last_success_wall
                    .and_then(system_time_to_unix_seconds)
                    .and_then(|last_success| {
                        system_time_to_unix_seconds(SystemTime::now())
                            .map(|now| now.saturating_sub(last_success))
                    })
            });
            JwtJwksRuntimeSnapshot {
                source_id: source.source_identity.clone(),
                allowed_algorithms: source
                    .allowed_algorithms
                    .iter()
                    .map(|algorithm| jwt_algorithm_name(*algorithm).to_string())
                    .collect(),
                startup_behavior: match source.startup_behavior {
                    JwksStartupBehavior::RequireReady => "require_ready",
                    JwksStartupBehavior::AllowDegraded => "allow_degraded",
                },
                state,
                active_key_count,
                age_seconds,
                last_refresh_attempt_unix_seconds: entry
                    .as_ref()
                    .and_then(|entry| entry.last_refresh_started_wall)
                    .and_then(system_time_to_unix_seconds),
                last_refresh_success_unix_seconds: entry
                    .as_ref()
                    .and_then(|entry| entry.last_success_wall)
                    .and_then(system_time_to_unix_seconds),
                last_failure_reason: entry
                    .as_ref()
                    .and_then(|entry| entry.last_failure_reason)
                    .map(|reason| reason.as_str().to_string()),
                last_error: entry.as_ref().and_then(|entry| entry.last_error.clone()),
            }
        })
        .collect::<Vec<_>>();
    snapshots.sort_by(|left, right| left.source_id.cmp(&right.source_id));
    snapshots
}

fn system_time_to_unix_seconds(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}
