#[cfg(feature = "scoped-rate-limit")]
use std::collections::HashSet;
#[cfg(feature = "connection-rate-limit")]
use std::net::IpAddr;
use std::{
    collections::{HashMap, hash_map::RandomState},
    hash::BuildHasher,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

#[cfg(feature = "scoped-rate-limit")]
use impulse_contracts::PluginRequestView;
#[cfg(feature = "scoped-rate-limit")]
use impulse_policy::{
    RequestKeySpec, ScopedRateLimitIdentity, ScopedRateLimitKeyExtraction,
    extract_scoped_rate_limit_key,
};
#[cfg(feature = "scoped-rate-limit")]
use sha2::{Digest, Sha256};

#[cfg(feature = "connection-rate-limit")]
use crate::ConnectionRateLimitInput;
#[cfg(feature = "scoped-rate-limit")]
use crate::{ScopedRateLimitInput, ScopedRateLimitScopeInput};

#[cfg(feature = "connection-rate-limit")]
const PER_SOURCE_RATE_DIVISOR: u32 = 10;
#[cfg(feature = "connection-rate-limit")]
const MAX_TRACKED_SOURCES: usize = 4_096;
#[cfg(feature = "scoped-rate-limit")]
const MAX_SCOPED_IDENTITY_BYTES: usize = 256;
#[cfg(feature = "connection-rate-limit")]
const SOURCE_IDLE_TTL: Duration = Duration::from_secs(300);
#[cfg(feature = "connection-rate-limit")]
const SOURCE_PRUNE_INTERVAL: Duration = Duration::from_secs(1);
#[cfg(feature = "connection-rate-limit")]
const SOURCE_BUCKET_SHARDS: usize = 16;
#[cfg(feature = "scoped-rate-limit")]
const MAX_SCOPED_IDENTITIES_PER_RULE: usize = 1_024;
#[cfg(feature = "scoped-rate-limit")]
const SCOPED_IDENTITY_PRUNE_INTERVAL: Duration = Duration::from_secs(1);
#[cfg(feature = "scoped-rate-limit")]
const SCOPED_IDENTITY_BUCKET_SHARDS: usize = 16;

#[cfg(feature = "connection-rate-limit")]
pub(crate) enum ConnectionRateLimitRejection {
    Global,
    Source,
}

#[cfg(feature = "connection-rate-limit")]
pub(crate) struct ConnectionRateLimitRuntime {
    input: ConnectionRateLimitInput,
    global: Mutex<TokenBucket>,
    per_source: PerSourceTokenBucket,
}

#[cfg(feature = "connection-rate-limit")]
impl ConnectionRateLimitRuntime {
    pub(crate) fn new(input: ConnectionRateLimitInput) -> Self {
        Self {
            input,
            global: Mutex::new(TokenBucket::new(input.requests_per_second, input.burst)),
            per_source: PerSourceTokenBucket::new(input.requests_per_second, input.burst),
        }
    }

    pub(crate) const fn input(&self) -> ConnectionRateLimitInput {
        self.input
    }

    pub(crate) fn admit(&self, source: Option<IpAddr>) -> Result<(), ConnectionRateLimitRejection> {
        let mut global = self
            .global
            .lock()
            .map_err(|_| ConnectionRateLimitRejection::Global)?;
        if !global.try_consume() {
            return Err(ConnectionRateLimitRejection::Global);
        }
        drop(global);

        if source.is_some_and(|source| !self.per_source.try_consume(source)) {
            return Err(ConnectionRateLimitRejection::Source);
        }
        Ok(())
    }
}

#[cfg(any(feature = "connection-rate-limit", feature = "scoped-rate-limit"))]
struct TokenBucket {
    burst: f64,
    rate_per_sec: f64,
    tokens: f64,
    last_refill: Instant,
}

#[cfg(any(feature = "connection-rate-limit", feature = "scoped-rate-limit"))]
impl TokenBucket {
    fn new(rate_per_sec: u32, burst: u32) -> Self {
        let burst = burst.max(1) as f64;
        Self {
            burst,
            rate_per_sec: rate_per_sec.max(1) as f64,
            tokens: burst,
            last_refill: Instant::now(),
        }
    }

    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let refill = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64()
            * self.rate_per_sec;
        self.last_refill = now;

        if refill.is_finite() && refill > 0.0 {
            self.tokens = (self.tokens + refill).min(self.burst);
        } else if !refill.is_finite() {
            self.tokens = self.burst;
        }

        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

#[cfg(feature = "connection-rate-limit")]
struct PerSourceTokenBucket {
    hash_builder: RandomState,
    shards: Box<[Mutex<PerSourceTokenBucketShard>]>,
    live_buckets: AtomicUsize,
    prune_state: Mutex<PerSourcePruneState>,
    rate_per_sec: u32,
    burst: u32,
}

#[cfg(feature = "connection-rate-limit")]
#[derive(Default)]
struct PerSourceTokenBucketShard {
    buckets: HashMap<IpAddr, (TokenBucket, Instant)>,
}

#[cfg(any(feature = "connection-rate-limit", feature = "scoped-rate-limit"))]
struct PerSourcePruneState {
    last_pruned_at: Instant,
    next_shard: usize,
}

#[cfg(feature = "connection-rate-limit")]
impl PerSourceTokenBucket {
    fn new(rate_per_sec: u32, burst: u32) -> Self {
        Self {
            hash_builder: RandomState::new(),
            shards: (0..SOURCE_BUCKET_SHARDS)
                .map(|_| Mutex::new(PerSourceTokenBucketShard::default()))
                .collect(),
            live_buckets: AtomicUsize::new(0),
            prune_state: Mutex::new(PerSourcePruneState {
                last_pruned_at: Instant::now(),
                next_shard: 0,
            }),
            rate_per_sec: (rate_per_sec / PER_SOURCE_RATE_DIVISOR).max(1),
            burst: (burst / PER_SOURCE_RATE_DIVISOR).max(1),
        }
    }

    fn try_consume(&self, source: IpAddr) -> bool {
        let now = Instant::now();
        self.prune_expired_if_due(now);
        let shard_index = (self.hash_builder.hash_one(source) as usize) % self.shards.len();
        let mut shard = self.shards[shard_index]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((bucket, last_seen)) = shard.buckets.get_mut(&source) {
            *last_seen = now;
            return bucket.try_consume();
        }
        if self
            .live_buckets
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_TRACKED_SOURCES).then_some(count + 1)
            })
            .is_err()
        {
            return false;
        }
        let (bucket, _) = shard
            .buckets
            .entry(source)
            .or_insert_with(|| (TokenBucket::new(self.rate_per_sec, self.burst), now));
        bucket.try_consume()
    }

    fn prune_expired_if_due(&self, now: Instant) {
        let shard_index = {
            let Ok(mut state) = self.prune_state.try_lock() else {
                return;
            };
            if now.saturating_duration_since(state.last_pruned_at) < SOURCE_PRUNE_INTERVAL {
                return;
            }
            state.last_pruned_at = now;
            let shard_index = state.next_shard;
            state.next_shard = (state.next_shard + 1) % self.shards.len();
            shard_index
        };
        let Ok(mut shard) = self.shards[shard_index].try_lock() else {
            return;
        };
        let before = shard.buckets.len();
        shard.buckets.retain(|_, (_, last_seen)| {
            now.saturating_duration_since(*last_seen) < SOURCE_IDLE_TTL
        });
        self.live_buckets.fetch_sub(
            before.saturating_sub(shard.buckets.len()),
            Ordering::Relaxed,
        );
    }
}

#[cfg(feature = "scoped-rate-limit")]
pub(crate) enum ScopedRateLimitDecision {
    Admit,
    Deny { retry_after_seconds: u32 },
}

#[cfg(feature = "scoped-rate-limit")]
pub(crate) struct ScopedRateLimitRuntime {
    inputs: std::sync::Arc<[ScopedRateLimitInput]>,
    rules: Box<[ScopedRateLimitRule]>,
}

#[cfg(feature = "scoped-rate-limit")]
impl ScopedRateLimitRuntime {
    pub(crate) fn new(inputs: std::sync::Arc<[ScopedRateLimitInput]>) -> Self {
        let rules = inputs
            .iter()
            .cloned()
            .map(ScopedRateLimitRule::new)
            .collect();
        Self { inputs, rules }
    }

    pub(crate) fn inputs(&self) -> &[ScopedRateLimitInput] {
        &self.inputs
    }

    pub(crate) fn evaluate(&self, request: PluginRequestView<'_>) -> ScopedRateLimitDecision {
        let header_lookup = |name: &str| {
            request
                .header(name)
                .and_then(|value| std::str::from_utf8(value).ok())
                .map(str::to_string)
        };
        let identity = ScopedRateLimitIdentity::new(
            request.route_id,
            request.method,
            request.path,
            request.authority,
            None,
            Some(request.peer_address),
            Some(&header_lookup),
        );

        for rule in &self.rules {
            if !rule.applies_to(request.upstream_name) {
                continue;
            }
            let key = match rule.identity_key(&identity) {
                ScopedRateLimitKeyExtraction::Found(key) => key,
                ScopedRateLimitKeyExtraction::Missing | ScopedRateLimitKeyExtraction::Invalid => {
                    return ScopedRateLimitDecision::Deny {
                        retry_after_seconds: rule.retry_after_seconds,
                    };
                }
            };
            if rule
                .store
                .try_consume(&rule.storage_key(&key), rule.idle_ttl)
                != Some(true)
            {
                return ScopedRateLimitDecision::Deny {
                    retry_after_seconds: rule.retry_after_seconds,
                };
            }
        }
        ScopedRateLimitDecision::Admit
    }
}

#[cfg(feature = "scoped-rate-limit")]
struct ScopedRateLimitRule {
    scope: ScopedRateLimitScopeInput,
    key: Option<RequestKeySpec>,
    route_allowlist: HashSet<String>,
    idle_ttl: Duration,
    retry_after_seconds: u32,
    store: ScopedIdentityStore,
}

#[cfg(feature = "scoped-rate-limit")]
impl ScopedRateLimitRule {
    fn new(input: ScopedRateLimitInput) -> Self {
        Self {
            scope: input.scope,
            key: input.key.as_deref().map(request_key_spec),
            route_allowlist: input.route_allowlist.into_vec().into_iter().collect(),
            idle_ttl: input.idle_ttl,
            retry_after_seconds: 1,
            store: ScopedIdentityStore::new(input.requests_per_second, input.burst),
        }
    }

    fn applies_to(&self, route: &str) -> bool {
        self.route_allowlist.is_empty() || self.route_allowlist.contains(route)
    }

    fn identity_key(&self, context: &ScopedRateLimitIdentity<'_>) -> ScopedRateLimitKeyExtraction {
        if matches!(self.scope, ScopedRateLimitScopeInput::Route) {
            return context
                .route
                .map_or(ScopedRateLimitKeyExtraction::Missing, |route| {
                    ScopedRateLimitKeyExtraction::Found(route.to_string())
                });
        }

        let default = match self.scope {
            ScopedRateLimitScopeInput::Client => RequestKeySpec::PeerIp,
            ScopedRateLimitScopeInput::Tenant => RequestKeySpec::Authority,
            ScopedRateLimitScopeInput::Token => RequestKeySpec::BearerToken,
            ScopedRateLimitScopeInput::Route => unreachable!(),
        };
        match extract_scoped_rate_limit_key(self.key.as_ref().unwrap_or(&default), context) {
            found @ ScopedRateLimitKeyExtraction::Found(_) => found,
            ScopedRateLimitKeyExtraction::Invalid => ScopedRateLimitKeyExtraction::Invalid,
            ScopedRateLimitKeyExtraction::Missing => legacy_identity_key(context),
        }
    }

    fn storage_key(&self, identity: &str) -> String {
        if matches!(self.scope, ScopedRateLimitScopeInput::Route) {
            return identity.to_string();
        }
        let digest = Sha256::digest(identity.as_bytes());
        format!("sha256:{digest:x}")
    }
}

#[cfg(feature = "scoped-rate-limit")]
fn legacy_identity_key(context: &ScopedRateLimitIdentity<'_>) -> ScopedRateLimitKeyExtraction {
    if let Some(authority) = context
        .authority
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return bounded_legacy_identity(authority.to_string());
    }
    let path = context.path.trim();
    if !path.is_empty() {
        return bounded_legacy_identity(path.to_string());
    }
    let method = context.method.trim();
    if !method.is_empty() {
        return bounded_legacy_identity(method.to_ascii_uppercase());
    }
    ScopedRateLimitKeyExtraction::Missing
}

#[cfg(feature = "scoped-rate-limit")]
fn bounded_legacy_identity(value: String) -> ScopedRateLimitKeyExtraction {
    if value.len() > MAX_SCOPED_IDENTITY_BYTES {
        ScopedRateLimitKeyExtraction::Invalid
    } else {
        ScopedRateLimitKeyExtraction::Found(value)
    }
}

#[cfg(feature = "scoped-rate-limit")]
fn request_key_spec(raw: &str) -> RequestKeySpec {
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "path" => RequestKeySpec::Path,
        "authority" => RequestKeySpec::Authority,
        "method" => RequestKeySpec::Method,
        "cid" => RequestKeySpec::Cid,
        "sticky-cid" => RequestKeySpec::StickyCid,
        "peer_ip" => RequestKeySpec::PeerIp,
        "client_ip" => RequestKeySpec::ClientIp,
        "bearer_token" => RequestKeySpec::BearerToken,
        _ => match normalized.split_once(':') {
            Some(("cookie", name)) => RequestKeySpec::Cookie(name.to_string()),
            Some(("query", name)) => RequestKeySpec::Query(name.to_string()),
            Some(("header", name)) => RequestKeySpec::Header(name.to_string()),
            _ => RequestKeySpec::Header(normalized),
        },
    }
}

#[cfg(feature = "scoped-rate-limit")]
type ScopedIdentityBuckets = HashMap<String, (TokenBucket, Instant)>;
#[cfg(feature = "scoped-rate-limit")]
type ScopedIdentityShard = Mutex<ScopedIdentityBuckets>;

#[cfg(feature = "scoped-rate-limit")]
struct ScopedIdentityStore {
    hash_builder: RandomState,
    shards: Box<[ScopedIdentityShard]>,
    live_buckets: AtomicUsize,
    prune_state: Mutex<PerSourcePruneState>,
    rate_per_sec: u32,
    burst: u32,
}

#[cfg(feature = "scoped-rate-limit")]
impl ScopedIdentityStore {
    fn new(rate_per_sec: u32, burst: u32) -> Self {
        Self {
            hash_builder: RandomState::new(),
            shards: (0..SCOPED_IDENTITY_BUCKET_SHARDS)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
            live_buckets: AtomicUsize::new(0),
            prune_state: Mutex::new(PerSourcePruneState {
                last_pruned_at: Instant::now(),
                next_shard: 0,
            }),
            rate_per_sec: rate_per_sec.max(1),
            burst: burst.max(1),
        }
    }

    fn try_consume(&self, key: &str, idle_ttl: Duration) -> Option<bool> {
        let now = Instant::now();
        self.prune_expired_if_due(now, idle_ttl);
        let shard_index = (self.hash_builder.hash_one(key) as usize) % self.shards.len();
        let mut shard = self.shards[shard_index].lock().ok()?;
        if let Some((bucket, last_seen)) = shard.get_mut(key) {
            *last_seen = now;
            return Some(bucket.try_consume());
        }
        if self
            .live_buckets
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_SCOPED_IDENTITIES_PER_RULE).then_some(count + 1)
            })
            .is_err()
        {
            return None;
        }
        let (bucket, _) = shard
            .entry(key.to_string())
            .or_insert_with(|| (TokenBucket::new(self.rate_per_sec, self.burst), now));
        Some(bucket.try_consume())
    }

    fn prune_expired_if_due(&self, now: Instant, idle_ttl: Duration) {
        let shard_index = {
            let Ok(mut state) = self.prune_state.try_lock() else {
                return;
            };
            if now.saturating_duration_since(state.last_pruned_at) < SCOPED_IDENTITY_PRUNE_INTERVAL
            {
                return;
            }
            state.last_pruned_at = now;
            let shard_index = state.next_shard;
            state.next_shard = (state.next_shard + 1) % self.shards.len();
            shard_index
        };
        let Ok(mut shard) = self.shards[shard_index].try_lock() else {
            return;
        };
        let before = shard.len();
        shard.retain(|_, (_, last_seen)| now.saturating_duration_since(*last_seen) < idle_ttl);
        self.live_buckets
            .fetch_sub(before.saturating_sub(shard.len()), Ordering::Relaxed);
    }
}
