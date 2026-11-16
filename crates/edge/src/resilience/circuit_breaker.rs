use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use impulse_contracts::BackendId;

#[derive(Default)]
struct BreakerState {
    consecutive_failures: u32,
    open_until: Option<Instant>,
    half_open_inflight: u32,
    half_open: bool,
    half_open_generation: u64,
}

pub struct CircuitBreakers {
    enabled: bool,
    failure_threshold: u32,
    open_for: Duration,
    half_open_max_probes: u32,
    states: Mutex<HashMap<BackendId, BreakerState>>,
}

impl CircuitBreakers {
    pub fn new(
        enabled: bool,
        failure_threshold: u32,
        open_for: Duration,
        half_open_max_probes: u32,
    ) -> Self {
        Self {
            enabled,
            failure_threshold: failure_threshold.max(1),
            open_for,
            half_open_max_probes: half_open_max_probes.max(1),
            states: Mutex::new(HashMap::new()),
        }
    }

    pub fn allow_request(&self, backend: BackendId) -> Option<CircuitBreakerPermit<'_>> {
        if !self.enabled {
            return Some(CircuitBreakerPermit::new(self, backend, None));
        }
        let now = Instant::now();
        let mut states = match self.states.lock() {
            Ok(guard) => guard,
            Err(_) => return Some(CircuitBreakerPermit::new(self, backend, None)),
        };
        let state = states.entry(backend).or_default();

        if let Some(until) = state.open_until {
            if now < until {
                return None;
            }
            state.open_until = None;
            state.half_open = true;
            state.half_open_inflight = 0;
            state.half_open_generation = state.half_open_generation.wrapping_add(1);
            state.consecutive_failures = 0;
        }

        let probe_generation = if state.half_open {
            if state.half_open_inflight >= self.half_open_max_probes {
                return None;
            }
            state.half_open_inflight += 1;
            Some(state.half_open_generation)
        } else {
            None
        };

        Some(CircuitBreakerPermit::new(self, backend, probe_generation))
    }

    fn record_success(&self, backend: BackendId, probe_generation: Option<u64>) {
        if !self.enabled {
            return;
        }
        let mut states = match self.states.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        let state = states.entry(backend).or_default();
        if let Some(generation) = probe_generation {
            if !state.half_open || state.half_open_generation != generation {
                return;
            }
            if state.half_open_inflight > 0 {
                state.half_open_inflight -= 1;
            }
        } else if state.half_open || state.open_until.is_some() {
            return;
        }
        state.consecutive_failures = 0;
        state.open_until = None;
        state.half_open = false;
        state.half_open_inflight = 0;
    }

    fn record_failure(&self, backend: BackendId, probe_generation: Option<u64>) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        let mut states = match self.states.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        let state = states.entry(backend).or_default();

        if let Some(generation) = probe_generation {
            if !state.half_open || state.half_open_generation != generation {
                return;
            }
            state.open_until = Some(now + self.open_for);
            state.half_open = false;
            state.half_open_inflight = 0;
            state.consecutive_failures = 0;
            return;
        } else if state.half_open || state.open_until.is_some() {
            return;
        }

        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        if state.consecutive_failures >= self.failure_threshold {
            state.open_until = Some(now + self.open_for);
            state.half_open = false;
            state.consecutive_failures = 0;
        }
    }

    fn release_half_open_probe(&self, backend: BackendId, generation: u64) {
        let mut states = match self.states.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        let Some(state) = states.get_mut(&backend) else {
            return;
        };
        if state.half_open
            && state.half_open_generation == generation
            && state.half_open_inflight > 0
        {
            state.half_open_inflight -= 1;
        }
    }
}

#[must_use = "the circuit-breaker permit must be held until the request outcome is known"]
pub struct CircuitBreakerPermit<'a> {
    breakers: &'a CircuitBreakers,
    backend: BackendId,
    probe_generation: Option<u64>,
    resolved: bool,
}

impl<'a> CircuitBreakerPermit<'a> {
    fn new(
        breakers: &'a CircuitBreakers,
        backend: BackendId,
        probe_generation: Option<u64>,
    ) -> Self {
        Self {
            breakers,
            backend,
            probe_generation,
            resolved: false,
        }
    }

    pub fn record_success(mut self) {
        self.breakers
            .record_success(self.backend, self.probe_generation);
        self.resolved = true;
    }

    pub fn record_failure(mut self) {
        self.breakers
            .record_failure(self.backend, self.probe_generation);
        self.resolved = true;
    }
}

impl Drop for CircuitBreakerPermit<'_> {
    fn drop(&mut self) {
        if self.resolved {
            return;
        }
        if let Some(generation) = self.probe_generation {
            self.breakers
                .release_half_open_probe(self.backend, generation);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::oneshot;

    use super::*;

    #[tokio::test]
    async fn cancelled_half_open_probe_releases_its_slot() {
        let breakers = Arc::new(CircuitBreakers::new(true, 1, Duration::ZERO, 1));
        let backend = BackendId::new(0);
        breakers
            .allow_request(backend)
            .expect("closed breaker request")
            .record_failure();

        let task_breakers = Arc::clone(&breakers);
        let (probe_started_tx, probe_started_rx) = oneshot::channel();
        let probe_task = tokio::spawn(async move {
            let _probe_permit = task_breakers
                .allow_request(backend)
                .expect("first half-open probe");
            probe_started_tx.send(()).expect("signal probe start");
            std::future::pending::<()>().await;
        });
        probe_started_rx.await.expect("probe start");
        assert!(breakers.allow_request(backend).is_none());

        probe_task.abort();
        assert!(
            probe_task
                .await
                .expect_err("cancelled probe task")
                .is_cancelled()
        );

        assert!(breakers.allow_request(backend).is_some());
    }
}
