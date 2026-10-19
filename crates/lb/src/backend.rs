use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use impulse_config::config::{Backend, HealthCheck};

use crate::health::{HealthFailureReason, HealthTransition};

#[derive(Clone)]
pub struct BackendState {
    pub address: String,
    pub health_check: Option<HealthCheck>,
    pub consecutive_failures: u32,
    health_state: HealthState,
    pub active_requests: Arc<AtomicUsize>,
    pub ewma_latency_ms: Option<f64>,
}

impl BackendState {
    pub fn new(backend: &Backend) -> Self {
        Self {
            address: backend.address.clone(),
            health_check: backend.health_check.clone(),
            consecutive_failures: 0,
            health_state: HealthState::Healthy,
            active_requests: Arc::new(AtomicUsize::new(0)),
            ewma_latency_ms: None,
        }
    }

    #[must_use = "this returns a bool, it does not modify the backend state"]
    pub fn is_healthy(&self) -> bool {
        matches!(self.health_state, HealthState::Healthy)
    }

    #[must_use = "this returns a bool, it does not modify the backend state"]
    pub fn is_probing(&self) -> bool {
        matches!(self.health_state, HealthState::Probing { .. })
    }

    /// Returns true when an active health-check loop is running for this backend.
    /// When active checks are present, only the health-check loop should drive
    /// consecutive_failures — request-path failures should not contribute.
    pub fn has_active_health_check(&self) -> bool {
        self.health_check.as_ref().is_some_and(|hc| hc.interval > 0)
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn active_requests(&self) -> usize {
        self.active_requests.load(Ordering::Relaxed)
    }

    pub fn ewma_latency_ms(&self) -> Option<f64> {
        self.ewma_latency_ms
    }

    pub fn record_success(&mut self) -> Option<HealthTransition> {
        let success_threshold = self
            .health_check
            .as_ref()
            .map_or(1, |hc| hc.success_threshold)
            .max(1);

        match self.health_state.clone() {
            HealthState::Healthy => {
                self.consecutive_failures = 0;
                None
            }
            HealthState::Unhealthy { until } => {
                if Instant::now() < until {
                    return None;
                }

                self.consecutive_failures = 0;
                self.health_state = HealthState::Probing {
                    successes: 0,
                    remaining_budget: self.probe_budget(),
                };
                self.record_probing_success(success_threshold)
            }
            HealthState::Probing { .. } => self.record_probing_success(success_threshold),
        }
    }

    pub fn record_failure(&mut self, _reason: HealthFailureReason) -> Option<HealthTransition> {
        if matches!(self.health_state, HealthState::Probing { .. }) {
            self.consecutive_failures = 0;
            self.health_state = HealthState::Unhealthy {
                until: Instant::now() + self.cooldown_duration(),
            };
            return None;
        }

        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let threshold = self
            .health_check
            .as_ref()
            .map_or(3, |hc| hc.failure_threshold);
        if self.consecutive_failures < threshold {
            return None;
        }

        self.consecutive_failures = 0;
        self.health_state = HealthState::Unhealthy {
            until: Instant::now() + self.cooldown_duration(),
        };
        Some(HealthTransition::BecameUnhealthy)
    }

    /// Cooldown expiry, if this backend is currently unhealthy.
    pub fn cooldown_until(&self) -> Option<Instant> {
        if let HealthState::Unhealthy { until } = self.health_state {
            Some(until)
        } else {
            None
        }
    }

    /// Move an ejected backend into probing once its cooldown has elapsed.
    /// Returns true when the backend becomes probe-eligible.
    pub fn readmit_if_expired(&mut self, now: Instant) -> bool {
        if let HealthState::Unhealthy { until } = self.health_state
            && now >= until
        {
            self.consecutive_failures = 0;
            self.health_state = HealthState::Probing {
                successes: 0,
                remaining_budget: self.probe_budget(),
            };
            return true;
        }
        false
    }

    pub fn try_acquire_probe_permit(&mut self) -> bool {
        match &mut self.health_state {
            HealthState::Probing {
                remaining_budget, ..
            } if *remaining_budget > 0 => {
                *remaining_budget -= 1;
                true
            }
            HealthState::Healthy | HealthState::Unhealthy { .. } | HealthState::Probing { .. } => {
                false
            }
        }
    }

    fn cooldown_duration(&self) -> Duration {
        Duration::from_millis(
            self.health_check
                .as_ref()
                .map_or(10_000, |hc| hc.cooldown_ms),
        )
    }

    fn probe_budget(&self) -> u32 {
        self.health_check
            .as_ref()
            .map_or(1, |hc| hc.success_threshold.max(1))
    }

    fn record_probing_success(&mut self, success_threshold: u32) -> Option<HealthTransition> {
        let (successes, remaining_budget) = match &self.health_state {
            HealthState::Probing {
                successes,
                remaining_budget,
            } => (*successes, *remaining_budget),
            HealthState::Healthy | HealthState::Unhealthy { .. } => return None,
        };

        let next_successes = successes.saturating_add(1);
        if next_successes >= success_threshold {
            self.consecutive_failures = 0;
            self.health_state = HealthState::Healthy;
            return Some(HealthTransition::BecameHealthy);
        }

        self.health_state = HealthState::Probing {
            successes: next_successes,
            remaining_budget,
        };
        None
    }
}

#[derive(Clone)]
enum HealthState {
    Healthy,
    // Half-open recovery state: a backend has served enough cooldown time to
    // be probe-eligible, but it is not healthy again until probe successes
    // reach the configured threshold.
    Probing {
        successes: u32,
        remaining_budget: u32,
    },
    Unhealthy {
        until: Instant,
    },
}
