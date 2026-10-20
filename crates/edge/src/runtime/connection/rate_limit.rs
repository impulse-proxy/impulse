use std::{
    collections::{HashMap, hash_map::RandomState},
    hash::BuildHasher,
    net::IpAddr,
    sync::{
        Mutex, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

/// A leaky token-bucket rate limiter for new ingress connections.
///
/// Tokens refill at `rate_per_sec` tokens/second up to a cap of `burst`.
/// Each accepted connection consumes one token.
pub(crate) struct TokenBucket {
    /// Maximum tokens the bucket can hold (burst capacity).
    burst: f64,
    /// Tokens added per second.
    rate_per_sec: f64,
    /// Current available tokens.
    tokens: f64,
    /// Last time tokens were refilled.
    last_refill: Instant,
}

const PER_SOURCE_RATE_DIVISOR: u32 = 10;
const MAX_TRACKED_SOURCES: usize = 4_096;
const SOURCE_IDLE_TTL: Duration = Duration::from_secs(300);
const SOURCE_PRUNE_INTERVAL: Duration = Duration::from_secs(1);
const SOURCE_BUCKET_SHARDS: usize = 16;

pub(crate) struct PerSourceTokenBucket {
    hash_builder: RandomState,
    shards: Box<[Mutex<PerSourceTokenBucketShard>]>,
    live_buckets: AtomicUsize,
    prune_state: Mutex<PerSourcePruneState>,
    config: RwLock<PerSourceTokenBucketConfig>,
}

#[derive(Clone, Copy)]
struct PerSourceTokenBucketConfig {
    rate_per_sec: u32,
    burst: u32,
}

#[derive(Default)]
struct PerSourceTokenBucketShard {
    buckets: HashMap<IpAddr, (TokenBucket, Instant)>,
}

struct PerSourcePruneState {
    last_pruned_at: Instant,
    next_shard: usize,
}

impl PerSourceTokenBucket {
    pub(crate) fn new(rate_per_sec: u32, burst: u32) -> Self {
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
            config: RwLock::new(PerSourceTokenBucketConfig {
                rate_per_sec: per_source_rate(rate_per_sec),
                burst: per_source_burst(burst),
            }),
        }
    }

    pub(crate) fn reconfigure(&self, rate_per_sec: u32, burst: u32) {
        let mut config = self
            .config
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        config.rate_per_sec = per_source_rate(rate_per_sec);
        config.burst = per_source_burst(burst);
        for shard in &self.shards {
            let mut shard = shard
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for (bucket, _) in shard.buckets.values_mut() {
                bucket.reconfigure(config.rate_per_sec, config.burst);
            }
        }
    }

    pub(crate) fn try_consume(&self, source: IpAddr) -> bool {
        let now = Instant::now();
        self.prune_expired_if_due(now);
        let config = *self
            .config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_TRACKED_SOURCES).then_some(count + 1)
            })
            .is_err()
        {
            return false;
        }
        let (bucket, _) = shard
            .buckets
            .entry(source)
            .or_insert_with(|| (TokenBucket::new(config.rate_per_sec, config.burst), now));
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

fn per_source_rate(rate_per_sec: u32) -> u32 {
    (rate_per_sec / PER_SOURCE_RATE_DIVISOR).max(1)
}

fn per_source_burst(burst: u32) -> u32 {
    (burst / PER_SOURCE_RATE_DIVISOR).max(1)
}

impl TokenBucket {
    pub(crate) fn new(rate_per_sec: u32, burst: u32) -> Self {
        let burst = (burst.max(1)) as f64;
        let rate_per_sec = rate_per_sec.max(1) as f64;
        Self {
            burst,
            rate_per_sec,
            tokens: burst,
            last_refill: Instant::now(),
        }
    }

    pub(crate) fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        // Refill is intentionally bounded by `burst`: after long idle periods, precision
        // beyond "enough to fill the bucket" is irrelevant and we clamp to capacity.
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

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub(crate) fn reconfigure(&mut self, rate_per_sec: u32, burst: u32) {
        let burst = burst.max(1) as f64;
        let rate_per_sec = rate_per_sec.max(1) as f64;
        self.burst = burst;
        self.rate_per_sec = rate_per_sec;
        self.tokens = self.tokens.min(self.burst);
        self.last_refill = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, time::Duration};

    use super::{PerSourceTokenBucket, TokenBucket};

    #[test]
    fn long_idle_refill_is_capped_to_burst() {
        let mut tb = TokenBucket::new(1_000, 3);
        assert!(tb.try_consume());
        assert!(tb.try_consume());
        assert!(tb.try_consume());
        assert!(!tb.try_consume());

        tb.last_refill = tb
            .last_refill
            .checked_sub(Duration::from_secs(60))
            .expect("time subtraction");

        assert!(tb.try_consume(), "long idle should refill bucket");
        assert!(tb.tokens.is_finite());
        assert!(tb.tokens <= tb.burst);
    }

    #[test]
    fn reconfigure_clamps_tokens_to_new_burst() {
        let mut tb = TokenBucket::new(100, 5);
        assert!(tb.try_consume());
        assert!(tb.try_consume());
        tb.reconfigure(200, 2);

        assert_eq!(tb.burst, 2.0);
        assert_eq!(tb.rate_per_sec, 200.0);
        assert!(tb.tokens <= tb.burst);
    }

    #[test]
    fn per_source_buckets_keep_clients_on_independent_budgets() {
        let limiter = PerSourceTokenBucket::new(10, 2);
        let first: IpAddr = "192.0.2.1".parse().expect("test address");
        let second: IpAddr = "192.0.2.2".parse().expect("test address");

        assert!(limiter.try_consume(first));
        assert!(!limiter.try_consume(first));
        assert!(limiter.try_consume(second));
        assert!(!limiter.try_consume(second));
    }
}
