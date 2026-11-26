//! Generation-owned backend accounting and passive-health policy state.
//!
//! Pingora owns backend membership, readiness, and request-time selection.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    BackendInput,
    backend::{BackendSelectionState, BackendState},
    backend_pool::BackendPool,
    health::{HealthFailureReason, HealthTransition},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpstreamPoolStateSummary {
    pub total_backends: usize,
    pub healthy_backends: usize,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct UpstreamBackendRuntimeState {
    pub healthy: bool,
    pub active_requests: usize,
    pub ewma_latency_ms: Option<f64>,
}

pub struct UpstreamPool {
    pool: BackendPool,
}

impl UpstreamPool {
    pub fn new(backends: impl IntoIterator<Item = BackendInput>) -> Self {
        let backends = backends
            .into_iter()
            .map(|backend| BackendState::new(&backend))
            .collect();
        Self {
            pool: BackendPool::new_from_states(backends),
        }
    }

    pub fn finish_request(&mut self, index: usize, latency: Duration, status: Option<u16>) {
        self.pool.finish_request(index, latency, status);
    }

    pub fn mark_backend_healthy(&mut self, index: usize) -> Option<HealthTransition> {
        self.pool.mark_success(index)
    }

    pub fn mark_backend_request_success(&mut self, index: usize) -> Option<HealthTransition> {
        self.pool.mark_request_success(index)
    }

    pub fn mark_backend_failure_from_active_check(
        &mut self,
        index: usize,
    ) -> Option<HealthTransition> {
        self.pool.mark_failure(index)
    }

    pub fn mark_backend_request_failure(
        &mut self,
        index: usize,
        reason: HealthFailureReason,
    ) -> Option<HealthTransition> {
        self.pool.mark_request_failure(index, reason)
    }

    pub fn observe_backend_request_failure(
        &mut self,
        index: usize,
        latency: Duration,
        reason: Option<HealthFailureReason>,
    ) -> Option<HealthTransition> {
        self.pool.observe_request_failure(index, latency, reason)
    }

    pub fn backend_address(&self, index: usize) -> Option<&str> {
        self.pool.address(index)
    }

    pub fn backend_indices(&self) -> Vec<usize> {
        self.pool.all_indices()
    }

    pub fn backend_selection_state(&self, index: usize) -> Option<Arc<BackendSelectionState>> {
        self.pool.backend(index).map(BackendState::selection_state)
    }

    pub fn is_backend_healthy(&self, index: usize) -> bool {
        self.pool.is_healthy_index(index)
    }

    pub fn reconcile_passive_health(&mut self, now: Instant) {
        self.pool.reconcile_readmit_at(now);
    }

    pub fn try_acquire_probe(&mut self, index: usize) -> bool {
        self.pool.try_acquire_probe(index)
    }

    pub fn begin_request_for_accounting(&self, index: usize) {
        self.pool.begin_request(index);
    }

    pub fn backend_runtime_state(&self, index: usize) -> Option<UpstreamBackendRuntimeState> {
        let backend = self.pool.backend(index)?;
        Some(UpstreamBackendRuntimeState {
            healthy: backend.is_healthy(),
            active_requests: backend.active_requests(),
            ewma_latency_ms: backend.ewma_latency_ms(),
        })
    }

    pub fn state_summary(&self) -> UpstreamPoolStateSummary {
        UpstreamPoolStateSummary {
            total_backends: self.pool.len(),
            healthy_backends: self.pool.healthy_len(),
        }
    }
}
