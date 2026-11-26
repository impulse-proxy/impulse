use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use crate::{
    BackendHealthInput,
    health::{HealthFailureReason, HealthTransition},
};

const EWMA_ALPHA: f64 = 0.2;
const FAILURE_PENALTY_LATENCY_MS: f64 = 1_000.0;
const MIN_LATENCY_SAMPLE_MS: f64 = 1.0;
const MAX_LATENCY_SAMPLE_MS: f64 = 60_000.0;
const UNSAMPLED_LATENCY: u64 = u64::MAX;

#[derive(Debug)]
pub struct BackendSelectionState {
    active_requests: AtomicUsize,
    ewma_latency_ms: AtomicU64,
}

impl Default for BackendSelectionState {
    fn default() -> Self {
        Self {
            active_requests: AtomicUsize::new(0),
            ewma_latency_ms: AtomicU64::new(UNSAMPLED_LATENCY),
        }
    }
}

impl BackendSelectionState {
    pub fn active_requests(&self) -> usize {
        self.active_requests.load(Ordering::Relaxed)
    }

    pub fn ewma_latency_ms(&self) -> Option<f64> {
        let bits = self.ewma_latency_ms.load(Ordering::Relaxed);
        if bits == UNSAMPLED_LATENCY {
            None
        } else {
            Some(f64::from_bits(bits))
        }
    }

    pub(crate) fn begin_request(&self) {
        self.active_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn finish_request(&self, latency: Duration, status: Option<u16>) {
        let _ =
            self.active_requests
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    Some(current.saturating_sub(1))
                });

        if status.is_some_and(|code| (500..=599).contains(&code)) {
            return;
        }

        let observed_ms =
            (latency.as_secs_f64() * 1_000.0).clamp(MIN_LATENCY_SAMPLE_MS, MAX_LATENCY_SAMPLE_MS);
        let _ = self
            .ewma_latency_ms
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |bits| {
                let next = if bits == UNSAMPLED_LATENCY {
                    observed_ms
                } else {
                    EWMA_ALPHA * observed_ms + (1.0 - EWMA_ALPHA) * f64::from_bits(bits)
                };
                Some(next.to_bits())
            });
    }

    pub(crate) fn record_failure_latency_penalty(&self, latency: Duration) {
        let penalty_ms = latency
            .as_secs_f64()
            .mul_add(1_000.0, 0.0)
            .max(FAILURE_PENALTY_LATENCY_MS);
        let _ = self
            .ewma_latency_ms
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |bits| {
                Some(if bits == UNSAMPLED_LATENCY {
                    penalty_ms.to_bits()
                } else {
                    f64::from_bits(bits).max(penalty_ms).to_bits()
                })
            });
    }
}

#[derive(Clone)]
pub struct BackendState {
    pub address: String,
    pub health_check: Option<BackendHealthInput>,
    pub consecutive_failures: u32,
    health_state: HealthState,
    selection_state: Arc<BackendSelectionState>,
}

impl BackendState {
    pub fn new(backend: &crate::BackendInput) -> Self {
        Self {
            address: backend.configured_address().to_string(),
            health_check: backend.health().copied(),
            consecutive_failures: 0,
            health_state: HealthState::Healthy,
            selection_state: Arc::default(),
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
        self.health_check
            .is_some_and(BackendHealthInput::active_checks)
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn active_requests(&self) -> usize {
        self.selection_state.active_requests()
    }

    pub fn ewma_latency_ms(&self) -> Option<f64> {
        self.selection_state.ewma_latency_ms()
    }

    pub(crate) fn selection_state(&self) -> Arc<BackendSelectionState> {
        Arc::clone(&self.selection_state)
    }

    pub(crate) fn begin_request(&self) {
        self.selection_state.begin_request();
    }

    pub(crate) fn finish_request(&self, latency: Duration, status: Option<u16>) {
        self.selection_state.finish_request(latency, status);
    }

    pub(crate) fn record_failure_latency_penalty(&self, latency: Duration) {
        self.selection_state.record_failure_latency_penalty(latency);
    }

    pub fn record_success(&mut self) -> Option<HealthTransition> {
        let success_threshold = self
            .health_check
            .map_or(1, BackendHealthInput::success_threshold)
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
            .map_or(3, BackendHealthInput::failure_threshold);
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
        self.health_check
            .map_or(Duration::from_secs(10), BackendHealthInput::cooldown)
    }

    fn probe_budget(&self) -> u32 {
        self.health_check
            .map_or(1, BackendHealthInput::success_threshold)
            .max(1)
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
