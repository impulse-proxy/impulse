use std::{
    collections::{HashMap, hash_map::RandomState},
    hash::BuildHasher,
    net::IpAddr,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use crate::ConnectionRateLimitInput;

const PER_SOURCE_RATE_DIVISOR: u32 = 10;
const MAX_TRACKED_SOURCES: usize = 4_096;
const SOURCE_IDLE_TTL: Duration = Duration::from_secs(300);
const SOURCE_PRUNE_INTERVAL: Duration = Duration::from_secs(1);
const SOURCE_BUCKET_SHARDS: usize = 16;

pub(crate) enum ConnectionRateLimitRejection {
    Global,
    Source,
}

pub(crate) struct ConnectionRateLimitRuntime {
    input: ConnectionRateLimitInput,
    global: Mutex<TokenBucket>,
    per_source: PerSourceTokenBucket,
}

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

struct TokenBucket {
    burst: f64,
    rate_per_sec: f64,
    tokens: f64,
    last_refill: Instant,
}

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

struct PerSourceTokenBucket {
    hash_builder: RandomState,
    shards: Box<[Mutex<PerSourceTokenBucketShard>]>,
    live_buckets: AtomicUsize,
    prune_state: Mutex<PerSourcePruneState>,
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
