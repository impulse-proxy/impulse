use std::time::{Duration, Instant};

use crate::{
    backend::BackendState,
    health::{HealthFailureReason, HealthTransition},
};

pub struct BackendPool {
    backends: Vec<BackendState>,
    // Earliest cooldown expiry among passively-ejected backends (no active
    // health check), driving time-based re-admission. `None` when none pending.
    earliest_readmit: Option<Instant>,
}

impl BackendPool {
    pub fn new_from_states(backends: Vec<BackendState>) -> Self {
        Self {
            backends,
            earliest_readmit: None,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.backends.len()
    }

    pub fn address(&self, index: usize) -> Option<&str> {
        self.backends.get(index).map(|b| b.address())
    }

    pub fn mark_success(&mut self, index: usize) -> Option<HealthTransition> {
        if index >= self.backends.len() {
            return None;
        }

        self.backends[index].record_success()
    }

    /// Mark a success from the request path (passive).
    /// When active health checks are configured, only the active loop may drive
    /// recovery from probing/unhealthy back into healthy.
    pub fn mark_request_success(&mut self, index: usize) -> Option<HealthTransition> {
        if index >= self.backends.len() {
            return None;
        }

        if self.backends[index].has_active_health_check() {
            return None;
        }

        self.mark_success(index)
    }

    /// Mark a failure from the active health-check loop — always recorded.
    pub fn mark_failure(&mut self, index: usize) -> Option<HealthTransition> {
        self.mark_failure_with_reason(index, HealthFailureReason::HttpStatus5xx)
    }

    /// Mark a failure from the request path (passive).
    /// Skipped when an active health-check loop is running for this backend,
    /// because the loop is the sole authority on consecutive_failures in that case.
    pub fn mark_request_failure(
        &mut self,
        index: usize,
        reason: HealthFailureReason,
    ) -> Option<HealthTransition> {
        if index < self.backends.len() && self.backends[index].has_active_health_check() {
            return None;
        }
        self.mark_failure_with_reason(index, reason)
    }

    /// Observe a failed request from the passive request path.
    ///
    /// A degraded latency sample is recorded even when active health checks own
    /// health-state transitions for the backend. This keeps latency-aware
    /// selection from repeatedly treating a failing backend as unsampled.
    pub fn observe_request_failure(
        &mut self,
        index: usize,
        latency: Duration,
        reason: Option<HealthFailureReason>,
    ) -> Option<HealthTransition> {
        self.record_failure_latency_penalty(index, latency);
        reason.and_then(|reason| self.mark_request_failure(index, reason))
    }

    pub fn mark_failure_with_reason(
        &mut self,
        index: usize,
        reason: HealthFailureReason,
    ) -> Option<HealthTransition> {
        if index >= self.backends.len() {
            return None;
        }

        let (was_healthy, was_probing, is_healthy, is_probing, transition) = {
            let backend = &mut self.backends[index];
            let was_healthy = backend.is_healthy();
            let was_probing = backend.is_probing();
            let transition = backend.record_failure(reason);
            let is_healthy = backend.is_healthy();
            let is_probing = backend.is_probing();
            (was_healthy, was_probing, is_healthy, is_probing, transition)
        };

        if was_healthy
            && !is_healthy
            && !self.backends[index].has_active_health_check()
            && let Some(until) = self.backends[index].cooldown_until()
        {
            self.earliest_readmit = Some(self.earliest_readmit.map_or(until, |e| e.min(until)));
        }

        if !self.backends[index].has_active_health_check()
            && was_probing != is_probing
            && let Some(until) = self.backends[index].cooldown_until()
        {
            self.earliest_readmit = Some(self.earliest_readmit.map_or(until, |e| e.min(until)));
        }

        transition
    }

    /// Advance passively-ejected backends into probe eligibility once their
    /// cooldown has elapsed. Recomputes the next pending expiry and returns
    /// early while the soonest cooldown is unmet.
    pub fn reconcile_readmit_at(&mut self, now: Instant) {
        let Some(earliest) = self.earliest_readmit else {
            return;
        };
        if now < earliest {
            return;
        }
        let mut next: Option<Instant> = None;
        for index in 0..self.backends.len() {
            if self.backends[index].has_active_health_check() {
                continue;
            }
            if !self.backends[index].readmit_if_expired(now)
                && let Some(until) = self.backends[index].cooldown_until()
            {
                next = Some(next.map_or(until, |e| e.min(until)));
            }
        }
        self.earliest_readmit = next;
    }

    #[must_use]
    pub fn healthy_len(&self) -> usize {
        self.backends
            .iter()
            .filter(|backend| backend.is_healthy())
            .count()
    }

    pub fn all_indices(&self) -> Vec<usize> {
        (0..self.backends.len()).collect()
    }

    pub fn backend(&self, index: usize) -> Option<&BackendState> {
        self.backends.get(index)
    }

    pub fn is_healthy_index(&self, index: usize) -> bool {
        self.backends
            .get(index)
            .is_some_and(BackendState::is_healthy)
    }

    pub fn try_acquire_probe(&mut self, index: usize) -> bool {
        self.backends
            .get_mut(index)
            .is_some_and(BackendState::try_acquire_probe_permit)
    }

    pub fn begin_request(&self, index: usize) {
        if let Some(backend) = self.backends.get(index) {
            backend.begin_request();
        }
    }

    pub fn finish_request(&mut self, index: usize, latency: Duration, status: Option<u16>) {
        let Some(backend) = self.backends.get(index) else {
            return;
        };
        backend.finish_request(latency, status);
    }

    fn record_failure_latency_penalty(&mut self, index: usize, latency: Duration) {
        let Some(backend) = self.backends.get(index) else {
            return;
        };
        backend.record_failure_latency_penalty(latency);
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use impulse_config::config::{Backend, HealthCheck};

    use super::BackendPool;
    use crate::{
        backend::BackendState,
        health::{HealthFailureReason, HealthTransition},
    };

    fn create_backend_state(address: &str) -> BackendState {
        crate::test_support::backend_state(&Backend {
            id: format!("backend-{address}"),
            address: address.to_string(),
            protocol: Default::default(),
            weight: 1,
            health_check: Some(HealthCheck {
                path: "/health".to_string(),
                interval: 1000,
                timeout_ms: 1000,
                failure_threshold: 3,
                success_threshold: 1,
                cooldown_ms: 0,
            }),
        })
    }

    #[test]
    fn backend_recovers_after_success_threshold() {
        let mut pool = BackendPool::new_from_states(vec![create_backend_state("10.0.0.1:1")]);
        pool.mark_failure(0);
        pool.mark_failure(0);
        pool.mark_failure(0);

        assert_eq!(pool.healthy_len(), 0);
        pool.mark_success(0);
        assert_eq!(pool.healthy_len(), 1);
    }

    #[test]
    fn passively_ejected_backend_enters_probing_after_cooldown() {
        let backend = Backend {
            id: "b1".to_string(),
            address: "10.0.0.1:1".to_string(),
            protocol: Default::default(),
            weight: 1,
            health_check: Some(HealthCheck {
                path: "/health".to_string(),
                interval: 0,
                timeout_ms: 1000,
                failure_threshold: 2,
                success_threshold: 1,
                cooldown_ms: 10_000,
            }),
        };
        let mut pool =
            BackendPool::new_from_states(vec![crate::test_support::backend_state(&backend)]);
        assert_eq!(pool.healthy_len(), 1);

        pool.mark_request_failure(0, HealthFailureReason::Transport);
        let transition = pool.mark_request_failure(0, HealthFailureReason::Transport);
        assert!(matches!(
            transition,
            Some(HealthTransition::BecameUnhealthy)
        ));
        assert_eq!(pool.healthy_len(), 0);
        assert!(pool.earliest_readmit.is_some());

        pool.reconcile_readmit_at(Instant::now());
        assert_eq!(pool.healthy_len(), 0);
        assert!(pool.earliest_readmit.is_some());

        pool.reconcile_readmit_at(Instant::now() + Duration::from_millis(10_001));
        assert_eq!(pool.healthy_len(), 0);
        assert!(pool.earliest_readmit.is_none());
        assert!(pool.backend(0).is_some_and(BackendState::is_probing));

        let transition = pool.mark_success(0);
        assert_eq!(pool.healthy_len(), 1);
        assert!(matches!(transition, Some(HealthTransition::BecameHealthy)));
    }

    #[test]
    fn probing_backend_probe_budget_is_bounded() {
        let backend = Backend {
            id: "b1".to_string(),
            address: "10.0.0.1:1".to_string(),
            protocol: Default::default(),
            weight: 1,
            health_check: Some(HealthCheck {
                path: "/health".to_string(),
                interval: 0,
                timeout_ms: 1000,
                failure_threshold: 1,
                success_threshold: 2,
                cooldown_ms: 10_000,
            }),
        };
        let mut pool =
            BackendPool::new_from_states(vec![crate::test_support::backend_state(&backend)]);

        assert!(matches!(
            pool.mark_request_failure(0, HealthFailureReason::Transport),
            Some(HealthTransition::BecameUnhealthy)
        ));
        pool.reconcile_readmit_at(Instant::now() + Duration::from_millis(10_001));

        assert!(pool.try_acquire_probe(0));
        assert!(pool.try_acquire_probe(0));
        assert!(!pool.try_acquire_probe(0));
    }

    #[test]
    fn probing_backend_requires_full_success_threshold_before_becoming_healthy() {
        let backend = Backend {
            id: "b1".to_string(),
            address: "10.0.0.1:1".to_string(),
            protocol: Default::default(),
            weight: 1,
            health_check: Some(HealthCheck {
                path: "/health".to_string(),
                interval: 0,
                timeout_ms: 1000,
                failure_threshold: 1,
                success_threshold: 2,
                cooldown_ms: 10_000,
            }),
        };
        let mut pool =
            BackendPool::new_from_states(vec![crate::test_support::backend_state(&backend)]);

        assert!(matches!(
            pool.mark_request_failure(0, HealthFailureReason::Transport),
            Some(HealthTransition::BecameUnhealthy)
        ));
        pool.reconcile_readmit_at(Instant::now() + Duration::from_millis(10_001));

        assert!(pool.backend(0).is_some_and(BackendState::is_probing));
        assert!(pool.mark_success(0).is_none());
        assert_eq!(pool.healthy_len(), 0);
        assert!(pool.backend(0).is_some_and(BackendState::is_probing));

        let transition = pool.mark_success(0);
        assert!(matches!(transition, Some(HealthTransition::BecameHealthy)));
        assert_eq!(pool.healthy_len(), 1);
    }

    #[test]
    fn probing_backend_failure_rearms_passive_readmit() {
        let backend = Backend {
            id: "b1".to_string(),
            address: "10.0.0.1:1".to_string(),
            protocol: Default::default(),
            weight: 1,
            health_check: Some(HealthCheck {
                path: "/health".to_string(),
                interval: 0,
                timeout_ms: 1000,
                failure_threshold: 1,
                success_threshold: 2,
                cooldown_ms: 10_000,
            }),
        };
        let mut pool =
            BackendPool::new_from_states(vec![crate::test_support::backend_state(&backend)]);

        assert!(matches!(
            pool.mark_request_failure(0, HealthFailureReason::Transport),
            Some(HealthTransition::BecameUnhealthy)
        ));
        pool.reconcile_readmit_at(Instant::now() + Duration::from_millis(10_001));

        assert!(pool.backend(0).is_some_and(BackendState::is_probing));
        assert!(pool.earliest_readmit.is_none());

        assert!(
            pool.mark_request_failure(0, HealthFailureReason::Transport)
                .is_none()
        );
        assert!(!pool.backend(0).is_some_and(BackendState::is_probing));
        assert!(pool.earliest_readmit.is_some());
    }

    #[test]
    fn request_failure_records_penalty_sample_for_unsampled_backend() {
        let mut pool = BackendPool::new_from_states(vec![create_backend_state("10.0.0.1:1")]);

        let transition = pool.observe_request_failure(
            0,
            Duration::from_millis(25),
            Some(HealthFailureReason::Transport),
        );

        assert!(transition.is_none());
        assert_eq!(
            pool.backend(0).and_then(BackendState::ewma_latency_ms),
            Some(1_000.0)
        );
    }

    #[test]
    fn request_failure_penalty_overrides_fast_transport_sample() {
        let mut pool = BackendPool::new_from_states(vec![create_backend_state("10.0.0.1:1")]);

        pool.finish_request(0, Duration::from_millis(20), None);
        pool.observe_request_failure(
            0,
            Duration::from_millis(20),
            Some(HealthFailureReason::Transport),
        );

        assert_eq!(
            pool.backend(0).and_then(BackendState::ewma_latency_ms),
            Some(1_000.0)
        );
    }

    #[test]
    fn request_failure_with_active_health_check_still_records_penalty_sample() {
        let mut pool = BackendPool::new_from_states(vec![create_backend_state("10.0.0.1:1")]);

        let transition = pool.observe_request_failure(
            0,
            Duration::from_millis(10),
            Some(HealthFailureReason::HttpStatus5xx),
        );

        assert!(transition.is_none());
        assert!(pool.is_healthy_index(0));
        assert_eq!(
            pool.backend(0).and_then(BackendState::ewma_latency_ms),
            Some(1_000.0)
        );
    }
}
