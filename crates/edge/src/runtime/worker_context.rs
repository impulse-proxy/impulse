use std::sync::Arc;

use crate::{constants::MAX_DATAGRAM_SIZE_BYTES, runtime::body_buffer_pool::BodyBufferPool};

/// State reused on a data-plane worker's hot packet and body paths.
///
/// Each `Http3Service` owns one context, keeping scratch buffers and pooled
/// body storage local to that worker.
pub(crate) struct DataPlaneWorkerContext {
    pub(crate) body_buffer_pool: Arc<BodyBufferPool>,
    pub(crate) recv_buf: Box<[u8; MAX_DATAGRAM_SIZE_BYTES]>,
    pub(crate) send_buf: Box<[u8; MAX_DATAGRAM_SIZE_BYTES]>,
}

impl Default for DataPlaneWorkerContext {
    fn default() -> Self {
        Self {
            body_buffer_pool: Arc::new(BodyBufferPool::default()),
            recv_buf: Box::new([0; MAX_DATAGRAM_SIZE_BYTES]),
            send_buf: Box::new([0; MAX_DATAGRAM_SIZE_BYTES]),
        }
    }
}
