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
