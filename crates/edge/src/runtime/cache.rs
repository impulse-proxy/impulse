use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use impulse_config::runtime::{RuntimeConfig, RuntimeResponseCachePolicy};
pub use impulse_policy::{
    ResponseCacheAuthInput, ResponseCacheBypassReason, ResponseCacheKeyInput,
    ResponseCachePolicyInput, ResponseCacheRepresentation, ResponseCacheRequestEligibilityInput,
    ResponseCacheResponseEligibilityInput, evaluate_cache_request_eligibility,
    evaluate_cache_response_eligibility, route_auth_requires_cache_bypass,
};
use pingora_cache::{
    HttpCache, MemCache,
    eviction::{
        CacheEntryKey, CacheEntryKeyRef, EvictionManager, simple_lru::Manager as LruEvictionManager,
    },
    key::CacheKey,
    lock::CacheLock,
};
use pingora_http::ResponseHeader;

use crate::{Metrics, metrics::ResponseCacheOutcome};

const CACHE_LOCK_AGE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub(crate) struct RuntimeCacheStorage {
    cache: Option<&'static BoundedPingoraMemoryCache>,
    namespace: Arc<AtomicU64>,
}

impl RuntimeCacheStorage {
    pub(crate) fn new(config: &RuntimeConfig, generation: u64, metrics: Arc<Metrics>) -> Self {
        let cache = combined_storage_policy(config).map(|policy| {
            Box::leak(Box::new(BoundedPingoraMemoryCache::new(&policy, metrics)))
                as &'static BoundedPingoraMemoryCache
        });
        Self {
            cache,
            namespace: Arc::new(AtomicU64::new(generation)),
        }
    }

    pub(crate) fn cache(&self) -> Option<&'static BoundedPingoraMemoryCache> {
        self.cache
    }

    pub(crate) fn namespace(&self) -> u64 {
        self.namespace.load(Ordering::Acquire)
    }

    pub(crate) fn namespaces_compatible(
        &self,
        current: &RuntimeConfig,
        next: &RuntimeConfig,
    ) -> bool {
        let current = current
            .upstreams
            .iter()
            .filter(|(_, upstream)| upstream.policy.response_cache.enabled)
            .collect::<Vec<_>>();
        let next_count = next
            .upstreams
            .values()
            .filter(|upstream| upstream.policy.response_cache.enabled)
            .count();

        current.len() == next_count
            && current.into_iter().all(|(name, upstream)| {
                next.upstreams
                    .get(name)
                    .filter(|candidate| candidate.policy.response_cache.enabled)
                    .is_some_and(|candidate| {
                        upstream.route == candidate.route && upstream.policy == candidate.policy
                    })
            })
    }

    pub(crate) fn rotate_namespace(&self, generation: u64) {
        self.namespace.store(generation, Ordering::Release);
    }
}

pub(crate) fn response_cache_storage_limits(config: &RuntimeConfig) -> Option<(usize, usize)> {
    combined_storage_policy(config).map(|policy| (policy.max_bytes, policy.max_entries))
}

fn combined_storage_policy(config: &RuntimeConfig) -> Option<RuntimeResponseCachePolicy> {
    let mut policies = config
        .upstreams
        .values()
        .map(|upstream| upstream.policy.response_cache.clone());
    let mut storage_policy = policies.next()?;
    for policy in policies {
        storage_policy.max_bytes = storage_policy.max_bytes.max(policy.max_bytes);
        storage_policy.max_entries = storage_policy.max_entries.max(policy.max_entries);
        storage_policy.max_object_bytes =
            storage_policy.max_object_bytes.max(policy.max_object_bytes);
    }
    Some(storage_policy)
}

pub struct BoundedPingoraMemoryCache {
    storage: MemCache,
    eviction: ObservedEvictionManager,
    lock: CacheLock,
    max_object_bytes: usize,
}

impl BoundedPingoraMemoryCache {
    pub fn new(policy: &RuntimeResponseCachePolicy, metrics: Arc<Metrics>) -> Self {
        Self {
            storage: MemCache::new(),
            eviction: ObservedEvictionManager {
                inner: LruEvictionManager::new_with_watermark(
                    policy.max_bytes,
                    Some(policy.max_entries),
                ),
                metrics,
            },
            lock: CacheLock::new(CACHE_LOCK_AGE_TIMEOUT),
            max_object_bytes: policy.max_object_bytes,
        }
    }

    pub fn enable(&'static self, cache: &mut HttpCache, max_object_bytes: usize) {
        cache.enable(
            &self.storage,
            Some(&self.eviction),
            None,
            Some(&self.lock),
            None,
        );
        cache.set_max_file_size_bytes(max_object_bytes.min(self.max_object_bytes));
    }
}

struct ObservedEvictionManager {
    inner: LruEvictionManager,
    metrics: Arc<Metrics>,
}

impl ObservedEvictionManager {
    fn record(&self, evicted: Vec<CacheEntryKey>) -> Vec<CacheEntryKey> {
        self.metrics
            .ingress_observations()
            .add_response_cache_outcomes(ResponseCacheOutcome::Eviction, evicted.len());
        evicted
    }
}

#[async_trait]
impl EvictionManager for ObservedEvictionManager {
    fn total_size(&self) -> usize {
        self.inner.total_size()
    }
    fn total_items(&self) -> usize {
        self.inner.total_items()
    }
    fn evicted_size(&self) -> usize {
        self.inner.evicted_size()
    }
    fn evicted_items(&self) -> usize {
        self.inner.evicted_items()
    }

    fn admit(
        &self,
        item: CacheEntryKey,
        size: usize,
        fresh_until: SystemTime,
    ) -> Vec<CacheEntryKey> {
        self.record(self.inner.admit(item, size, fresh_until))
    }

    fn increment_weight(
        &self,
        item: &CacheEntryKey,
        delta: usize,
        max_weight: Option<usize>,
    ) -> Vec<CacheEntryKey> {
        self.record(self.inner.increment_weight(item, delta, max_weight))
    }

    fn remove(&self, item: CacheEntryKeyRef<'_>) {
        self.inner.remove(item);
    }

    fn access(&self, item: &CacheEntryKey, size: usize, fresh_until: SystemTime) -> bool {
        self.inner.access(item, size, fresh_until)
    }

    fn peek(&self, item: &CacheEntryKey) -> bool {
        self.inner.peek(item)
    }

    async fn save(&self, dir_path: &str) -> pingora_core::Result<()> {
        self.inner.save(dir_path).await
    }

    async fn load(&self, dir_path: &str) -> pingora_core::Result<()> {
        self.inner.load(dir_path).await
    }
}

pub fn response_cache_ttl(
    response: &ResponseHeader,
    max_ttl_secs: u64,
    now: SystemTime,
) -> Option<Duration> {
    impulse_policy::response_cache_ttl(&response.headers, max_ttl_secs, now)
}

pub fn canonical_response_cache_key(input: ResponseCacheKeyInput<'_>) -> Option<CacheKey> {
    impulse_policy::canonical_response_cache_key(input)
        .map(|key| CacheKey::new(key.into_primary(), ""))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(max_bytes: usize, max_entries: usize) -> RuntimeResponseCachePolicy {
        RuntimeResponseCachePolicy {
            enabled: true,
            max_bytes,
            max_entries,
            max_object_bytes: max_bytes,
            max_ttl_secs: 60,
        }
    }

    #[test]
    fn eviction_keeps_cache_within_memory_and_entry_bounds() {
        let metrics = Arc::new(Metrics::default());
        let cache = BoundedPingoraMemoryCache::new(&policy(8, 2), Arc::clone(&metrics));
        let first = CacheEntryKey::key_only(CacheKey::new("first", "").to_compact());
        let second = CacheEntryKey::key_only(CacheKey::new("second", "").to_compact());
        let third = CacheEntryKey::key_only(CacheKey::new("third", "").to_compact());

        assert!(cache.eviction.admit(first, 4, SystemTime::now()).is_empty());
        assert!(
            cache
                .eviction
                .admit(second, 4, SystemTime::now())
                .is_empty()
        );
        assert_eq!(cache.eviction.admit(third, 4, SystemTime::now()).len(), 1);
        assert!(cache.eviction.total_size() <= 8);
        assert!(cache.eviction.total_items() <= 2);
        assert!(
            metrics
                .render_prometheus()
                .contains("impulse_response_cache_outcomes_total{outcome=\"eviction\"} 1\n")
        );
    }
}
