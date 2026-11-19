use std::sync::{Arc, atomic::Ordering};

use crate::{
    REQUEST_ID_COUNTER, constants::MAX_DATAGRAM_SIZE_BYTES,
    runtime::body_buffer_pool::BodyBufferPool,
};

const REQUEST_ID_BLOCK_SIZE: u64 = 1024;

/// State reused on a data-plane worker's hot packet and body paths.
///
/// Each `Http3Service` owns one context, keeping scratch buffers and pooled
/// body storage local to that worker.
pub(crate) struct DataPlaneWorkerContext {
    pub(crate) body_buffer_pool: Arc<BodyBufferPool>,
    pub(crate) recv_buf: Box<[u8; MAX_DATAGRAM_SIZE_BYTES]>,
    pub(crate) send_buf: Box<[u8; MAX_DATAGRAM_SIZE_BYTES]>,
    next_request_id: u64,
    request_id_block_end: u64,
}

impl DataPlaneWorkerContext {
    pub(crate) fn next_request_id(&mut self) -> u64 {
        if self.next_request_id == self.request_id_block_end {
            self.next_request_id =
                REQUEST_ID_COUNTER.fetch_add(REQUEST_ID_BLOCK_SIZE, Ordering::Relaxed);
            self.request_id_block_end = self.next_request_id + REQUEST_ID_BLOCK_SIZE;
        }

        let request_id = self.next_request_id;
        self.next_request_id += 1;
        request_id
    }
}

impl Default for DataPlaneWorkerContext {
    fn default() -> Self {
        Self {
            body_buffer_pool: Arc::new(BodyBufferPool::default()),
            recv_buf: Box::new([0; MAX_DATAGRAM_SIZE_BYTES]),
            send_buf: Box::new([0; MAX_DATAGRAM_SIZE_BYTES]),
            next_request_id: 0,
            request_id_block_end: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn request_ids_are_sequential_within_a_block() {
        let mut context = DataPlaneWorkerContext::default();
        let first = context.next_request_id();
        for offset in 1..REQUEST_ID_BLOCK_SIZE {
            assert_eq!(context.next_request_id(), first + offset);
        }
    }

    #[test]
    fn request_ids_stay_unique_across_blocks_and_workers() {
        let mut workers = [
            DataPlaneWorkerContext::default(),
            DataPlaneWorkerContext::default(),
            DataPlaneWorkerContext::default(),
        ];
        let per_worker = (REQUEST_ID_BLOCK_SIZE * 3 + 17) as usize;
        let mut seen = HashSet::new();
        // Interleave workers so their blocks are drawn alternately.
        for _ in 0..per_worker {
            for worker in &mut workers {
                assert!(
                    seen.insert(worker.next_request_id()),
                    "duplicate request id"
                );
            }
        }
        assert_eq!(seen.len(), per_worker * 3);
    }

    #[test]
    fn a_new_block_is_drawn_when_the_current_one_is_exhausted() {
        let mut context = DataPlaneWorkerContext::default();
        let first = context.next_request_id();
        // Another worker takes the next block while this one is still mid-block.
        let mut other = DataPlaneWorkerContext::default();
        let other_first = other.next_request_id();
        assert_ne!(
            first / REQUEST_ID_BLOCK_SIZE,
            other_first / REQUEST_ID_BLOCK_SIZE
        );

        for _ in 1..REQUEST_ID_BLOCK_SIZE {
            context.next_request_id();
        }
        let after_block = context.next_request_id();
        assert!(
            after_block < first || after_block >= first + REQUEST_ID_BLOCK_SIZE,
            "id {after_block} should come from a fresh block"
        );
    }
}
