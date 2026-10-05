use std::{
    collections::{HashMap, HashSet, hash_map::RandomState},
    hash::BuildHasher,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use impulse_config::config::{ScopedRateLimit as ScopedRateLimitConfig, ScopedRateLimitScope};
use sha2::{Digest, Sha256};

use super::quota::{
    DistributedQuotaCounterBackend, QuotaBackendFailurePolicy, QuotaCounterBackend,
    QuotaCounterBackendError, QuotaCounterBackendErrorKind, QuotaCounterBackendMetadata,
    QuotaCounterEvalFuture, QuotaCounterEvaluationDecision, QuotaCounterEvaluationOutcome,
    QuotaCounterEvaluationRequest, QuotaCounterResult, QuotaDenyReason, QuotaEnforcementMode,
    QuotaPolicyRuntime, QuotaRuntime, QuotaSelectorKeySpec, QuotaSelectorMatcher,
    QuotaWindowPolicy, QuotaWindowUsage,
};

const LEGACY_SCOPED_RATE_LIMIT_PROTOCOL_VERSION: &str = "legacy-scoped-token-bucket/v1";
const LEGACY_SCOPED_BACKEND_KIND: &str = "legacy_scoped_rate_limit";
const LEGACY_SCOPED_KEY_PREFIX: &str = "impulse:legacy-scoped-rate-limit";
const MAX_SCOPED_RATE_LIMIT_BUCKETS_PER_RULE: usize = 1024;
const SCOPED_RATE_LIMIT_PRUNE_INTERVAL: Duration = Duration::from_secs(1);
const SCOPED_RATE_LIMIT_BUCKET_SHARDS: usize = 16;

struct ScopedRateLimitBucketAccess {
    storage_key: String,
    evaluation: ScopedRateLimitBucketEvaluation,
}

struct ScopedRateLimitBucketStore {
    hash_builder: RandomState,
    shards: Box<[Mutex<ScopedRateLimitBucketShard>]>,
    live_buckets: AtomicUsize,
    prune_state: Mutex<ScopedRateLimitPruneState>,
}

impl ScopedRateLimitBucketStore {
    fn new() -> Self {
        Self {
            hash_builder: RandomState::new(),
            shards: (0..SCOPED_RATE_LIMIT_BUCKET_SHARDS)
                .map(|_| Mutex::new(ScopedRateLimitBucketShard::default()))
                .collect(),
            live_buckets: AtomicUsize::new(0),
            prune_state: Mutex::new(ScopedRateLimitPruneState::new()),
        }
    }

    fn prune_expired_if_due(&self, now: Instant, idle_ttl: Duration) {
        let Some(shard_index) = self.claim_prune_shard(now) else {
            return;
        };

        let Ok(mut shard) = self.shards[shard_index].lock() else {
            return;
        };
        let before = shard.buckets.len();
        shard
            .buckets
            .retain(|_, bucket| now.saturating_duration_since(bucket.last_seen) < idle_ttl);
        let removed = before.saturating_sub(shard.buckets.len());
        if removed != 0 {
            self.live_buckets.fetch_sub(removed, Ordering::Relaxed);
        }
    }

    fn claim_prune_shard(&self, now: Instant) -> Option<usize> {
        let mut prune_state = self.prune_state.lock().ok()?;
        if now.saturating_duration_since(prune_state.last_pruned_at)
            < SCOPED_RATE_LIMIT_PRUNE_INTERVAL
        {
            return None;
        }
        prune_state.last_pruned_at = now;
        let shard_index = prune_state.next_shard;
        prune_state.next_shard = (prune_state.next_shard + 1) % self.shards.len();
        Some(shard_index)
    }

    fn shard_index(&self, storage_key: &str) -> usize {
        (self.hash_builder.hash_one(storage_key) as usize) % self.shards.len()
    }

    fn reserve_bucket_slot(&self) -> bool {
        self.live_buckets
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_SCOPED_RATE_LIMIT_BUCKETS_PER_RULE).then_some(count + 1)
            })
            .is_ok()
    }

    #[cfg(test)]
    fn bucket_count(&self) -> usize {
        self.live_buckets.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn insert_for_test(&self, storage_key: String, bucket: ScopedRateLimitBucket) {
        let shard_index = self.shard_index(&storage_key);
        let mut shard = self.shards[shard_index].lock().expect("bucket shard lock");
        if shard.buckets.insert(storage_key, bucket).is_none() {
            self.live_buckets.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Default)]
struct ScopedRateLimitBucketShard {
    buckets: HashMap<String, ScopedRateLimitBucket>,
}

struct ScopedRateLimitPruneState {
    last_pruned_at: Instant,
    next_shard: usize,
}

impl ScopedRateLimitPruneState {
    fn new() -> Self {
        Self {
            last_pruned_at: Instant::now(),
            next_shard: 0,
        }
    }
}

struct ScopedRateLimitBucket {
    burst: f64,
    rate_per_sec: f64,
    tokens: f64,
    last_refill: Instant,
    last_seen: Instant,
}

impl ScopedRateLimitBucket {
    fn new(rate_per_sec: u32, burst: u32) -> Self {
        let now = Instant::now();
        let burst = burst.max(1) as f64;
        Self {
            burst,
            rate_per_sec: rate_per_sec.max(1) as f64,
            tokens: burst,
            last_refill: now,
            last_seen: now,
        }
    }

    fn evaluate(&mut self, cost: u64) -> ScopedRateLimitBucketEvaluation {
        let now = Instant::now();
        let refill = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64()
            * self.rate_per_sec;
        self.last_refill = now;
        self.last_seen = now;

        if refill.is_finite() && refill > 0.0 {
            self.tokens = (self.tokens + refill).min(self.burst);
        } else if !refill.is_finite() {
            self.tokens = self.burst;
        }

        let requested = cost.max(1) as f64;
        if self.tokens >= requested {
            self.tokens -= requested;
            ScopedRateLimitBucketEvaluation {
                allowed: true,
                remaining_tokens: self.tokens.max(0.0),
                retry_after: None,
            }
        } else {
            let deficit = (requested - self.tokens).max(0.0);
            let retry_after = if self.rate_per_sec.is_finite() && self.rate_per_sec > 0.0 {
                Some(Duration::from_secs_f64(deficit / self.rate_per_sec))
            } else {
                Some(Duration::from_secs(1))
            };
            ScopedRateLimitBucketEvaluation {
                allowed: false,
                remaining_tokens: self.tokens.max(0.0),
                retry_after,
            }
        }
    }
}

struct ScopedRateLimitBucketEvaluation {
    allowed: bool,
    remaining_tokens: f64,
    retry_after: Option<Duration>,
}

pub struct ScopedRateLimitRule {
    name: String,
    scope: ScopedRateLimitScope,
    key_spec: Option<String>,
    route_allowlist: HashSet<String>,
    idle_ttl: Duration,
    retry_after_seconds: u32,
    rate_per_sec: u32,
    burst: u32,
    buckets: ScopedRateLimitBucketStore,
}

impl ScopedRateLimitRule {
    pub(crate) fn from_config(config: &ScopedRateLimitConfig) -> Self {
        Self {
            name: config.name.clone(),
            scope: config.scope,
            key_spec: config.key.clone(),
            route_allowlist: config.route_allowlist.iter().cloned().collect(),
            idle_ttl: Duration::from_secs(config.idle_ttl_secs.max(1)),
            retry_after_seconds: ((1.0 / config.requests_per_sec.max(1) as f64).ceil() as u32)
                .max(1),
            rate_per_sec: config.requests_per_sec.max(1),
            burst: config.burst.max(1),
            buckets: ScopedRateLimitBucketStore::new(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn scope(&self) -> ScopedRateLimitScope {
        self.scope
    }

    pub fn key_spec(&self) -> Option<&str> {
        self.key_spec.as_deref()
    }

    fn applies_to_route(&self, route: &str) -> bool {
        self.route_allowlist.is_empty() || self.route_allowlist.contains(route)
    }

    fn allow(&self, key: &str) -> bool {
        self.evaluate_bucket(key, 1)
            .is_some_and(|bucket| bucket.evaluation.allowed)
    }

    fn evaluate_request(
        &self,
        request: QuotaCounterEvaluationRequest,
    ) -> Result<QuotaCounterEvaluationOutcome, QuotaCounterBackendError> {
        let Some(bucket) = self.evaluate_bucket(&request.composite_key.key, request.cost) else {
            return Err(QuotaCounterBackendError {
                policy_name: Some(request.policy_name),
                composite_key: Some(request.composite_key.key),
                kind: QuotaCounterBackendErrorKind::Unavailable,
                detail: Some(
                    "scoped rate-limit bucket store is unavailable or saturated".to_string(),
                ),
            });
        };

        let limit = u64::from(self.burst.max(1));
        let remaining = bucket
            .evaluation
            .remaining_tokens
            .floor()
            .clamp(0.0, limit as f64) as u64;
        let consumed = limit.saturating_sub(remaining);
        let counter = QuotaCounterResult {
            burst: Some(QuotaWindowUsage {
                limit,
                consumed,
                remaining,
                window: Duration::from_secs(1),
                reset_after: bucket.evaluation.retry_after,
                bucket_started_at_unix_ms: None,
                reset_at_unix_ms: None,
                storage_key: Some(bucket.storage_key.clone()),
            }),
            sustained: None,
        };

        Ok(QuotaCounterEvaluationOutcome {
            matched_policy: request.policy_name,
            composite_key: request.composite_key,
            decision: if bucket.evaluation.allowed {
                QuotaCounterEvaluationDecision::Allowed
            } else {
                QuotaCounterEvaluationDecision::Denied(QuotaDenyReason::BurstQuotaExhausted)
            },
            counter,
            backend_metadata: QuotaCounterBackendMetadata {
                backend_kind: LEGACY_SCOPED_BACKEND_KIND.to_string(),
                protocol_version: LEGACY_SCOPED_RATE_LIMIT_PROTOCOL_VERSION.to_string(),
                evaluated_at_unix_ms: None,
            },
        })
    }

    fn evaluate_bucket(&self, key: &str, cost: u64) -> Option<ScopedRateLimitBucketAccess> {
        let now = Instant::now();
        let storage_key = self.canonical_bucket_storage_key(key);
        self.buckets.prune_expired_if_due(now, self.idle_ttl);

        let shard_index = self.buckets.shard_index(&storage_key);
        let mut shard = match self.buckets.shards[shard_index].lock() {
            Ok(guard) => guard,
            Err(_) => return None,
        };
        if let Some(bucket) = shard.buckets.get_mut(&storage_key) {
            return Some(ScopedRateLimitBucketAccess {
                storage_key,
                evaluation: bucket.evaluate(cost),
            });
        }
        if !self.buckets.reserve_bucket_slot() {
            return None;
        }

        let bucket = shard
            .buckets
            .entry(storage_key.clone())
            .or_insert_with(|| ScopedRateLimitBucket::new(self.rate_per_sec, self.burst));
        Some(ScopedRateLimitBucketAccess {
            storage_key,
            evaluation: bucket.evaluate(cost),
        })
    }

    fn canonical_bucket_storage_key(&self, key: &str) -> String {
        let normalized = key.trim();
        if normalized.is_empty() {
            return "sha256:empty".to_string();
        }
        if matches!(self.scope, ScopedRateLimitScope::Route) {
            return normalized.to_string();
        }

        let mut output = String::new();
        if let Some(route) = extract_quota_key_component(normalized, "route") {
            append_bucket_key_component(&mut output, "route", route);
        }
        append_bucket_key_component(&mut output, "selector", &sha256_storage_key(normalized));
        output
    }

    fn quota_policy(&self) -> QuotaPolicyRuntime {
        let default_or_configured = |fallback: QuotaSelectorKeySpec, configured: Option<&str>| {
            configured
                .map(QuotaSelectorKeySpec::from_raw_key)
                .unwrap_or(fallback)
                .with_legacy_default_fallback()
        };
        let selector = match self.scope {
            ScopedRateLimitScope::Route => QuotaSelectorMatcher {
                route: true,
                tenant: None,
                token: None,
                client: None,
            },
            ScopedRateLimitScope::Client => QuotaSelectorMatcher {
                route: false,
                tenant: None,
                token: None,
                client: Some(default_or_configured(
                    QuotaSelectorKeySpec::PeerIp,
                    self.key_spec(),
                )),
            },
            ScopedRateLimitScope::Tenant => QuotaSelectorMatcher {
                route: false,
                tenant: Some(default_or_configured(
                    QuotaSelectorKeySpec::Authority,
                    self.key_spec(),
                )),
                token: None,
                client: None,
            },
            ScopedRateLimitScope::Token => QuotaSelectorMatcher {
                route: false,
                tenant: None,
                token: Some(default_or_configured(
                    QuotaSelectorKeySpec::BearerToken,
                    self.key_spec(),
                )),
                client: None,
            },
        };

        QuotaPolicyRuntime {
            name: self.name.clone(),
            route_allowlist: self.route_allowlist.clone(),
            selector,
            burst: Some(QuotaWindowPolicy {
                requests: u64::from(self.burst.max(1)),
                window: Duration::from_secs(1),
            }),
            sustained: None,
        }
    }
}

fn extract_quota_key_component<'a>(key: &'a str, label: &str) -> Option<&'a str> {
    let mut cursor = key;
    while !cursor.is_empty() {
        let (component, rest) = cursor.split_once('|').unwrap_or((cursor, ""));
        cursor = rest;

        let Some((component_label, value)) = component.split_once('=') else {
            continue;
        };
        if component_label != label {
            continue;
        }

        let Some((declared_len, payload)) = value.split_once(':') else {
            continue;
        };
        let Some(declared_len) = declared_len.parse::<usize>().ok() else {
            continue;
        };
        if payload.len() != declared_len {
            return None;
        }
        return Some(payload);
    }

    None
}

fn append_bucket_key_component(output: &mut String, label: &str, value: &str) {
    output.push_str(label);
    output.push('=');
    output.push_str(&value.len().to_string());
    output.push(':');
    output.push_str(value);
    output.push('|');
}

fn sha256_storage_key(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    format!("sha256:{digest:x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_rule(scope: ScopedRateLimitScope) -> ScopedRateLimitRule {
        ScopedRateLimitRule::from_config(&ScopedRateLimitConfig {
            name: "test".to_string(),
            scope,
            requests_per_sec: 10,
            burst: 10,
            key: None,
            route_allowlist: Vec::new(),
            idle_ttl_secs: 60,
        })
    }

    #[test]
    fn evaluate_bucket_prunes_expired_entries_on_deterministic_cadence() {
        let rule = test_rule(ScopedRateLimitScope::Route);
        {
            let now = Instant::now();
            rule.buckets.insert_for_test(
                "expired".to_string(),
                ScopedRateLimitBucket {
                    burst: 1.0,
                    rate_per_sec: 1.0,
                    tokens: 1.0,
                    last_refill: now,
                    last_seen: now - Duration::from_secs(120),
                },
            );
            rule.buckets.insert_for_test(
                "live".to_string(),
                ScopedRateLimitBucket {
                    burst: 1.0,
                    rate_per_sec: 1.0,
                    tokens: 1.0,
                    last_refill: now,
                    last_seen: now,
                },
            );
            let mut prune_state = rule.buckets.prune_state.lock().expect("prune state lock");
            prune_state.last_pruned_at = now - SCOPED_RATE_LIMIT_PRUNE_INTERVAL;
            prune_state.next_shard = rule.buckets.shard_index("expired");
        }

        let _ = rule.evaluate_bucket("live", 1).expect("bucket evaluation");

        let expired_shard = rule.buckets.shard_index("expired");
        let live_shard = rule.buckets.shard_index("live");
        let expired_present = rule.buckets.shards[expired_shard]
            .lock()
            .expect("bucket shard lock")
            .buckets
            .contains_key("expired");
        let live_present = rule.buckets.shards[live_shard]
            .lock()
            .expect("bucket shard lock")
            .buckets
            .contains_key("live");
        assert!(!expired_present);
        assert!(live_present);
    }

    #[test]
    fn evaluate_bucket_rejects_new_entry_when_cap_is_reached_without_expiry() {
        let rule = test_rule(ScopedRateLimitScope::Route);
        {
            let now = Instant::now();
            let mut prune_state = rule.buckets.prune_state.lock().expect("prune state lock");
            prune_state.last_pruned_at = now;
            drop(prune_state);
            for index in 0..MAX_SCOPED_RATE_LIMIT_BUCKETS_PER_RULE {
                rule.buckets.insert_for_test(
                    format!("bucket-{index}"),
                    ScopedRateLimitBucket {
                        burst: 1.0,
                        rate_per_sec: 1.0,
                        tokens: 1.0,
                        last_refill: now,
                        last_seen: now + Duration::from_millis(index as u64),
                    },
                );
            }
        }

        let inserted = rule.evaluate_bucket("fresh-bucket", 1);
        let existing = rule.evaluate_bucket("bucket-0", 1);

        assert!(inserted.is_none());
        assert!(existing.is_some());
        assert_eq!(
            rule.buckets.bucket_count(),
            MAX_SCOPED_RATE_LIMIT_BUCKETS_PER_RULE
        );
        let fresh_shard = rule.buckets.shard_index("fresh-bucket");
        let existing_shard = rule.buckets.shard_index("bucket-0");
        assert!(
            !rule.buckets.shards[fresh_shard]
                .lock()
                .expect("bucket shard lock")
                .buckets
                .contains_key("fresh-bucket")
        );
        assert!(
            rule.buckets.shards[existing_shard]
                .lock()
                .expect("bucket shard lock")
                .buckets
                .contains_key("bucket-0")
        );
    }

    #[test]
    fn evaluate_bucket_hashes_non_route_storage_keys_for_untrusted_identities() {
        let rule = test_rule(ScopedRateLimitScope::Token);
        let first_value = "a".repeat(2048);
        let second_value = "b".repeat(2048);
        let first_key = format!("route=4:/api|token={}:{}|", first_value.len(), first_value);
        let second_key = format!(
            "route=4:/api|token={}:{}|",
            second_value.len(),
            second_value
        );

        let _ = rule
            .evaluate_bucket(&first_key, 1)
            .expect("first bucket evaluation");
        let _ = rule
            .evaluate_bucket(&second_key, 1)
            .expect("second bucket evaluation");

        let keys = rule
            .buckets
            .shards
            .iter()
            .flat_map(|shard| {
                shard
                    .lock()
                    .expect("bucket shard lock")
                    .buckets
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(keys.len(), 2);
        assert_ne!(keys[0], keys[1]);
        for key in keys {
            assert!(key.starts_with("route=4:/api|selector="));
            assert!(key.contains("sha256:"));
            assert!(!key.contains(&first_value[..128]));
            assert!(!key.contains(&second_value[..128]));
            assert!(key.len() < first_key.len());
            assert!(key.len() < second_key.len());
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScopedRateLimitRejection {
    pub rule_name: String,
    pub route: String,
    pub retry_after_seconds: u32,
}

pub struct ScopedRateLimiters {
    rules: Vec<Arc<ScopedRateLimitRule>>,
    rules_by_name: HashMap<String, Arc<ScopedRateLimitRule>>,
    quota_runtime: Arc<QuotaRuntime>,
}

impl ScopedRateLimiters {
    pub fn new(rules: &[ScopedRateLimitConfig]) -> Self {
        let rules = rules
            .iter()
            .map(|rule| Arc::new(ScopedRateLimitRule::from_config(rule)))
            .collect::<Vec<_>>();
        let rules_by_name = rules
            .iter()
            .map(|rule| (rule.name.clone(), Arc::clone(rule)))
            .collect::<HashMap<_, _>>();
        let quota_runtime = Arc::new(if rules.is_empty() {
            QuotaRuntime::disabled()
        } else {
            QuotaRuntime {
                enabled: true,
                enforcement: QuotaEnforcementMode::Enforce,
                backend_failure_policy: QuotaBackendFailurePolicy::FailOpen,
                backend: QuotaCounterBackend::InMemory {
                    key_prefix: LEGACY_SCOPED_KEY_PREFIX.to_string(),
                },
                local_fallback: None,
                policies: rules.iter().map(|rule| rule.quota_policy()).collect(),
            }
        });
        Self {
            rules,
            rules_by_name,
            quota_runtime,
        }
    }

    pub fn quota_runtime(&self) -> &QuotaRuntime {
        self.quota_runtime.as_ref()
    }

    pub fn check<F>(&self, route: &str, mut key_for_rule: F) -> Option<ScopedRateLimitRejection>
    where
        F: FnMut(&ScopedRateLimitRule) -> Option<String>,
    {
        for rule in &self.rules {
            if !rule.applies_to_route(route) {
                continue;
            }
            let Some(key) = key_for_rule(rule) else {
                continue;
            };
            if key.is_empty() || rule.allow(&key) {
                continue;
            }
            return Some(ScopedRateLimitRejection {
                rule_name: rule.name.clone(),
                route: route.to_string(),
                retry_after_seconds: rule.retry_after_seconds,
            });
        }
        None
    }
}

impl DistributedQuotaCounterBackend for ScopedRateLimiters {
    fn evaluate<'a>(
        &'a self,
        request: QuotaCounterEvaluationRequest,
    ) -> QuotaCounterEvalFuture<'a> {
        Box::pin(async move {
            let Some(rule) = self.rules_by_name.get(&request.policy_name).cloned() else {
                return Err(QuotaCounterBackendError {
                    policy_name: Some(request.policy_name),
                    composite_key: Some(request.composite_key.key),
                    kind: QuotaCounterBackendErrorKind::Error,
                    detail: Some("unknown scoped rate-limit policy".to_string()),
                });
            };
            rule.evaluate_request(request)
        })
    }
}
