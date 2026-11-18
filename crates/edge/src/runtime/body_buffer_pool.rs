use std::{
    mem,
    sync::{Arc, Mutex, TryLockError},
};

use bytes::Bytes;

/// Buffer capacities handed out by the pool, smallest first. A request chunk is
/// served from the smallest tier that fits it; anything larger bypasses the pool.
const BODY_BUFFER_TIERS: [usize; 3] = [4 * 1024, 16 * 1024, 64 * 1024];
/// Idle buffers kept per tier, which bounds idle memory at
/// `MAX_BUFFERS_PER_TIER * sum(BODY_BUFFER_TIERS)` (672 KiB) per pool.
const MAX_BUFFERS_PER_TIER: usize = 8;

#[derive(Default)]
struct PoolState {
    buffers: [Vec<Vec<u8>>; BODY_BUFFER_TIERS.len()],
}

/// Bounded, size-tiered pool of request-body buffers.
///
/// One pool belongs to one listener worker, so contention is rare. Even so, the
/// pool never blocks the data path: a buffer that cannot be taken or returned
/// without waiting for the lock is simply allocated or freed instead.
#[derive(Default)]
pub(crate) struct BodyBufferPool {
    state: Arc<Mutex<PoolState>>,
}

impl BodyBufferPool {
    /// Copy `source` into pooled storage and return it as `Bytes`.
    ///
    /// The returned `Bytes` owns its buffer. When the last handle to it (including
    /// clones and slices) is dropped, the buffer returns to the pool if there is
    /// room, from whichever thread drops it.
    pub(crate) fn copy_bytes(&self, source: &[u8]) -> Bytes {
        if source.is_empty() {
            return Bytes::new();
        }
        let Some(tier) = BODY_BUFFER_TIERS
            .iter()
            .position(|size| source.len() <= *size)
        else {
            return Bytes::copy_from_slice(source);
        };

        let mut buffer = self.checkout(tier);
        buffer.extend_from_slice(source);
        Bytes::from_owner(PooledBodyBuffer {
            pool: Arc::clone(&self.state),
            tier,
            buffer,
        })
    }

    fn checkout(&self, tier: usize) -> Vec<u8> {
        let pooled = match self.state.try_lock() {
            Ok(mut state) => state.buffers[tier].pop(),
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner().buffers[tier].pop(),
            Err(TryLockError::WouldBlock) => None,
        };
        pooled.unwrap_or_else(|| Vec::with_capacity(BODY_BUFFER_TIERS[tier]))
    }
}

struct PooledBodyBuffer {
    pool: Arc<Mutex<PoolState>>,
    tier: usize,
    buffer: Vec<u8>,
}

impl AsRef<[u8]> for PooledBodyBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.buffer
    }
}

impl Drop for PooledBodyBuffer {
    fn drop(&mut self) {
        let mut buffer = mem::take(&mut self.buffer);
        buffer.clear();
        if buffer.capacity() > BODY_BUFFER_TIERS[self.tier] {
            return;
        }
        let mut state = match self.pool.try_lock() {
            Ok(state) => state,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            // Contended: free the buffer instead of waiting on the data path.
            Err(TryLockError::WouldBlock) => return,
        };
        if state.buffers[self.tier].len() < MAX_BUFFERS_PER_TIER {
            state.buffers[self.tier].push(buffer);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::mpsc, thread, time::Duration};

    use super::*;

    fn pooled(pool: &BodyBufferPool, tier: usize) -> usize {
        pool.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .buffers[tier]
            .len()
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|index| (index % 251) as u8).collect()
    }

    #[test]
    fn empty_source_returns_empty_bytes_without_touching_the_pool() {
        let pool = BodyBufferPool::default();
        let bytes = pool.copy_bytes(&[]);
        assert!(bytes.is_empty());
        drop(bytes);
        assert!((0..BODY_BUFFER_TIERS.len()).all(|tier| pooled(&pool, tier) == 0));
    }

    #[test]
    fn copies_preserve_content_across_tier_boundaries() {
        let pool = BodyBufferPool::default();
        for len in [
            1,
            4 * 1024,
            4 * 1024 + 1,
            16 * 1024,
            16 * 1024 + 1,
            64 * 1024,
            64 * 1024 + 1,
        ] {
            let source = pattern(len);
            let bytes = pool.copy_bytes(&source);
            assert_eq!(bytes.len(), len);
            assert_eq!(&bytes[..], &source[..], "content differs at len {len}");
        }
    }

    #[test]
    fn smallest_fitting_tier_is_used() {
        let pool = BodyBufferPool::default();
        drop(pool.copy_bytes(&pattern(100)));
        drop(pool.copy_bytes(&pattern(5_000)));
        drop(pool.copy_bytes(&pattern(20_000)));
        assert_eq!(pooled(&pool, 0), 1);
        assert_eq!(pooled(&pool, 1), 1);
        assert_eq!(pooled(&pool, 2), 1);
    }

    #[test]
    fn oversized_chunks_bypass_the_pool() {
        let pool = BodyBufferPool::default();
        let source = pattern(BODY_BUFFER_TIERS[2] + 1);
        let bytes = pool.copy_bytes(&source);
        assert_eq!(&bytes[..], &source[..]);
        drop(bytes);
        assert!((0..BODY_BUFFER_TIERS.len()).all(|tier| pooled(&pool, tier) == 0));
    }

    #[test]
    fn dropped_buffers_are_reused() {
        let pool = BodyBufferPool::default();
        let first = pool.copy_bytes(&pattern(100));
        assert_eq!(pooled(&pool, 0), 0);
        drop(first);
        assert_eq!(pooled(&pool, 0), 1);

        let second = pool.copy_bytes(&pattern(200));
        assert_eq!(
            pooled(&pool, 0),
            0,
            "second copy should take the pooled buffer"
        );
        assert_eq!(&second[..], &pattern(200)[..]);
        drop(second);
        assert_eq!(pooled(&pool, 0), 1);
    }

    #[test]
    fn idle_buffers_per_tier_are_bounded() {
        let pool = BodyBufferPool::default();
        let held: Vec<Bytes> = (0..MAX_BUFFERS_PER_TIER + 5)
            .map(|_| pool.copy_bytes(&pattern(100)))
            .collect();
        drop(held);
        assert_eq!(pooled(&pool, 0), MAX_BUFFERS_PER_TIER);
    }

    #[test]
    fn buffer_returns_only_after_the_last_clone_or_slice_is_dropped() {
        let pool = BodyBufferPool::default();
        let bytes = pool.copy_bytes(&pattern(100));
        let slice = bytes.slice(..10);
        let clone = bytes.clone();
        drop(bytes);
        drop(clone);
        assert_eq!(pooled(&pool, 0), 0, "slice still references the buffer");
        assert_eq!(&slice[..], &pattern(100)[..10]);
        drop(slice);
        assert_eq!(pooled(&pool, 0), 1);
    }

    #[test]
    fn buffers_dropped_on_another_thread_return_to_the_pool() {
        let pool = BodyBufferPool::default();
        let bytes = pool.copy_bytes(&pattern(100));
        thread::spawn(move || drop(bytes))
            .join()
            .expect("dropping thread");
        assert_eq!(pooled(&pool, 0), 1);
    }

    #[test]
    fn contended_pool_never_blocks_the_data_path() {
        let pool = Arc::new(BodyBufferPool::default());
        let guard = pool.state.lock().expect("pool lock");

        let (tx, rx) = mpsc::channel();
        let worker_pool = Arc::clone(&pool);
        let worker = thread::spawn(move || {
            let bytes = worker_pool.copy_bytes(&pattern(100));
            let matches = bytes[..] == pattern(100)[..];
            drop(bytes);
            let _ = tx.send(matches);
        });
        let matches = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("copy_bytes and drop must not block on a held pool lock");
        assert!(matches);
        worker.join().expect("worker thread");
        drop(guard);
        assert_eq!(
            pooled(&pool, 0),
            0,
            "a buffer released while the lock was held is discarded, not queued"
        );
    }

    #[test]
    fn poisoned_pool_keeps_working() {
        let pool = Arc::new(BodyBufferPool::default());
        let poisoner = Arc::clone(&pool);
        let _ = thread::spawn(move || {
            let _guard = poisoner.state.lock().expect("pool lock");
            panic!("poison the pool lock");
        })
        .join();
        assert!(pool.state.is_poisoned());

        let bytes = pool.copy_bytes(&pattern(100));
        assert_eq!(&bytes[..], &pattern(100)[..]);
        drop(bytes);
        assert_eq!(pooled(&pool, 0), 1);
    }
}
