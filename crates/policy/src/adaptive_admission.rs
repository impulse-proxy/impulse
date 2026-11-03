use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use http::StatusCode;
use impulse_contracts::{OverloadDecision, OverloadDecisionReason};

pub struct AdaptiveAdmission {
    enabled: bool,
    min_limit: usize,
    max_limit: usize,
    increase_step: usize,
    decrease_step: usize,
    high_latency_ms: u64,
    current_limit: AtomicUsize,
    inflight: AtomicUsize,
}

impl AdaptiveAdmission {
    pub fn new(
        enabled: bool,
        min_limit: usize,
        max_limit: usize,
        increase_step: usize,
        decrease_step: usize,
        high_latency_ms: u64,
    ) -> Self {
        let max_limit = max_limit.max(1);
        let min_limit = min_limit.max(1).min(max_limit);
        Self {
            enabled,
            min_limit,
            max_limit,
            increase_step: increase_step.max(1),
            decrease_step: decrease_step.max(1),
            high_latency_ms: high_latency_ms.max(1),
            current_limit: AtomicUsize::new(max_limit),
            inflight: AtomicUsize::new(0),
        }
    }

    pub fn try_acquire(self: &Arc<Self>) -> Option<AdaptivePermit> {
        if !self.enabled {
            self.inflight.fetch_add(1, Ordering::Relaxed);
            return Some(AdaptivePermit {
                admission: Arc::clone(self),
            });
        }

        loop {
            let current = self.inflight.load(Ordering::Relaxed);
            let limit = self.current_limit.load(Ordering::Relaxed).max(1);
            if current >= limit {
                return None;
            }
            if self
                .inflight
                .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Some(AdaptivePermit {
                    admission: Arc::clone(self),
                });
            }
        }
    }

    pub fn observe(&self, latency: Duration, overloaded: bool) {
        if !self.enabled {
            return;
        }
        let latency_ms = latency.as_millis() as u64;
        let decrease = overloaded || latency_ms >= self.high_latency_ms;
        loop {
            let cur = self.current_limit.load(Ordering::Relaxed);
            let next = if decrease {
                cur.saturating_sub(self.decrease_step).max(self.min_limit)
            } else {
                cur.saturating_add(self.increase_step).min(self.max_limit)
            };

            if next == cur {
                return;
            }

            if self
                .current_limit
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
        }
    }

    pub fn current_limit(&self) -> usize {
        self.current_limit.load(Ordering::Relaxed)
    }

    pub fn inflight(&self) -> usize {
        self.inflight.load(Ordering::Relaxed)
    }

    pub fn inflight_percent(&self) -> u8 {
        let limit = self.current_limit().max(1);
        ((self.inflight() * 100) / limit).min(100) as u8
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }
}

pub fn evaluate_adaptive_admission(
    admission: &Arc<AdaptiveAdmission>,
    retry_after_seconds: u32,
) -> Result<AdaptivePermit, OverloadDecision> {
    admission.try_acquire().ok_or(OverloadDecision {
        reason: OverloadDecisionReason::AdaptiveAdmission,
        status: StatusCode::SERVICE_UNAVAILABLE,
        body: OverloadDecisionReason::AdaptiveAdmission.response_body(),
        retry_after_seconds: retry_after_seconds.max(1),
    })
}

pub struct AdaptivePermit {
    admission: Arc<AdaptiveAdmission>,
}

impl Drop for AdaptivePermit {
    fn drop(&mut self) {
        self.admission.inflight.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use super::AdaptiveAdmission;

    #[test]
    fn try_acquire_rejects_when_inflight_reaches_current_limit() {
        let admission = Arc::new(AdaptiveAdmission::new(true, 1, 2, 1, 1, 10));

        let first = admission.try_acquire().expect("first permit");
        let second = admission.try_acquire().expect("second permit");

        assert!(admission.try_acquire().is_none());
        assert_eq!(admission.inflight(), 2);

        drop(first);
        assert_eq!(admission.inflight(), 1);

        drop(second);
        assert_eq!(admission.inflight(), 0);
    }

    #[test]
    fn observe_overload_and_recovery_respect_min_and_max_limits() {
        let admission = AdaptiveAdmission::new(true, 2, 5, 2, 3, 50);

        admission.observe(Duration::from_millis(60), false);
        assert_eq!(admission.current_limit(), 2);

        admission.observe(Duration::from_millis(10), false);
        assert_eq!(admission.current_limit(), 4);

        admission.observe(Duration::from_millis(10), false);
        assert_eq!(admission.current_limit(), 5);

        admission.observe(Duration::from_millis(10), true);
        assert_eq!(admission.current_limit(), 2);
    }

    #[test]
    fn disabled_admission_does_not_enforce_configured_limit() {
        let admission = Arc::new(AdaptiveAdmission::new(false, 1, 1, 1, 1, 10));

        let first = admission.try_acquire().expect("first permit");
        let second = admission
            .try_acquire()
            .expect("disabled admission must not reject");

        assert_eq!(admission.current_limit(), 1);
        assert_eq!(admission.inflight(), 2);

        drop((first, second));
        assert_eq!(admission.inflight(), 0);
    }
}
