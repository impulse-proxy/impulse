use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use impulse_lb::upstream_pool::UpstreamPool;
use tokio::sync::Semaphore;

use super::{
    PendingForward, PostAuthAdmissionExecution, RuntimeResilience,
    execute_forwarding_post_auth_admission,
};

/// Executes post-auth admission using the existing resilience state.
#[derive(Clone, Copy)]
pub(in crate::quic_listener) struct RequestAdmissionService<'a> {
    resilience: &'a RuntimeResilience,
}

impl<'a> RequestAdmissionService<'a> {
    pub(in crate::quic_listener) const fn new(resilience: &'a RuntimeResilience) -> Self {
        Self { resilience }
    }

    pub(in crate::quic_listener) fn execute_post_auth(
        self,
        pending_forward: &PendingForward,
        upstream_pool: Option<&Arc<RwLock<UpstreamPool>>>,
        backend_index: Option<usize>,
        upstream_inflight: &HashMap<String, Arc<Semaphore>>,
        global_inflight: Arc<Semaphore>,
        inflight_acquire_wait: Duration,
    ) -> PostAuthAdmissionExecution {
        execute_forwarding_post_auth_admission(
            self.resilience,
            pending_forward,
            upstream_pool,
            backend_index,
            upstream_inflight,
            global_inflight,
            inflight_acquire_wait,
        )
    }
}
