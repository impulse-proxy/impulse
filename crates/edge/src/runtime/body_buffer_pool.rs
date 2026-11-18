use std::{
    mem,
    sync::{Arc, Mutex},
};

use bytes::Bytes;

const BODY_BUFFER_TIERS: [usize; 3] = [4 * 1024, 16 * 1024, 64 * 1024];
const MAX_BUFFERS_PER_TIER: usize = 8;

#[derive(Default)]
struct PoolState {
    buffers: [Vec<Vec<u8>>; BODY_BUFFER_TIERS.len()],
}

#[derive(Default)]
pub(crate) struct BodyBufferPool {
    state: Arc<Mutex<PoolState>>,
}

impl BodyBufferPool {
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

        let mut buffer = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .buffers[tier]
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(BODY_BUFFER_TIERS[tier]));
        buffer.extend_from_slice(source);
        Bytes::from_owner(PooledBodyBuffer {
            pool: Arc::clone(&self.state),
            tier,
            buffer,
        })
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
        let mut state = self
            .pool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.buffers[self.tier].len() < MAX_BUFFERS_PER_TIER {
            state.buffers[self.tier].push(buffer);
        }
    }
}
