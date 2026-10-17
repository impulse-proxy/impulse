use crate::backend_pool::BackendPool;

const ACTIVE_REQUEST_PENALTY_MS: f64 = 10.0;
const UNSAMPLED_PROBE_INTERVAL: u64 = 16;
const EXPLORATION_INTERVAL: u64 = 32;

#[derive(Clone, Copy)]
struct SampledCandidate {
    score: f64,
    active: usize,
    idx: usize,
}

#[derive(Clone, Copy)]
struct UnsampledCandidate {
    score: f64,
    active: usize,
    idx: usize,
}

pub struct LatencyAware {
    unsampled_probe_cursor: u64,
    exploration_cursor: usize,
    selections: u64,
}

impl LatencyAware {
    pub fn new() -> Self {
        Self {
            unsampled_probe_cursor: 0,
            exploration_cursor: 0,
            selections: 0,
        }
    }

    pub fn pick(&mut self, pool: &BackendPool) -> Option<usize> {
        if let Some(index) = self.periodic_exploration(pool) {
            return Some(index);
        }

        let (sampled_best, unsampled_best) = Self::rank_candidates(pool);
        let Some(sampled_best) = sampled_best else {
            return unsampled_best.map(|candidate| candidate.idx);
        };

        // When sampled backends exist, treat unsampled backends as probe-only:
        // they get bounded exploration traffic instead of inheriting the full
        // request stream before they have any measured latency.
        if let Some(unsampled_best) = unsampled_best
            && self.should_probe_unsampled(unsampled_best.active)
        {
            return Some(unsampled_best.idx);
        }

        Some(sampled_best.idx)
    }

    fn periodic_exploration(&mut self, pool: &BackendPool) -> Option<usize> {
        self.selections = self.selections.wrapping_add(1);
        if pool.healthy.len() < 2 || !self.selections.is_multiple_of(EXPLORATION_INTERVAL) {
            return None;
        }

        let position = self.exploration_cursor % pool.healthy.len();
        self.exploration_cursor = self.exploration_cursor.wrapping_add(1);
        pool.healthy.get(position).copied()
    }

    pub fn pick_readonly(&self, pool: &BackendPool) -> Option<usize> {
        let (sampled_best, unsampled_best) = Self::rank_candidates(pool);

        match (sampled_best, unsampled_best) {
            (Some(sampled_best), Some(unsampled_best))
                if unsampled_best.score < sampled_best.score =>
            {
                Some(unsampled_best.idx)
            }
            (Some(sampled_best), _) => Some(sampled_best.idx),
            (None, Some(unsampled_best)) => Some(unsampled_best.idx),
            (None, None) => None,
        }
    }

    fn rank_candidates(
        pool: &BackendPool,
    ) -> (Option<SampledCandidate>, Option<UnsampledCandidate>) {
        let mut unsampled_best: Option<(usize, usize)> = None;
        let mut sampled_best: Option<SampledCandidate> = None;
        let mut sampled_latency_sum = 0.0_f64;
        let mut sampled_count = 0_usize;

        for &idx in &pool.healthy {
            let backend = &pool.backends[idx];
            let active = backend.active_requests();
            if let Some(ewma) = backend.ewma_latency_ms() {
                let score = ewma + (active as f64 * ACTIVE_REQUEST_PENALTY_MS);
                sampled_latency_sum += ewma;
                sampled_count += 1;
                match sampled_best {
                    Some(best) => {
                        if score < best.score
                            || (score == best.score
                                && (active < best.active
                                    || (active == best.active && idx < best.idx)))
                        {
                            sampled_best = Some(SampledCandidate { score, active, idx });
                        }
                    }
                    None => sampled_best = Some(SampledCandidate { score, active, idx }),
                }
            } else {
                match unsampled_best {
                    Some((best_active, best_idx)) => {
                        if active < best_active || (active == best_active && idx < best_idx) {
                            unsampled_best = Some((active, idx));
                        }
                    }
                    None => unsampled_best = Some((active, idx)),
                }
            }
        }

        if sampled_count == 0 {
            return (
                None,
                unsampled_best.map(|(active, idx)| UnsampledCandidate {
                    score: 0.0,
                    active,
                    idx,
                }),
            );
        }

        let Some(sampled_best) = sampled_best else {
            return (
                None,
                unsampled_best.map(|(active, idx)| UnsampledCandidate {
                    score: 0.0,
                    active,
                    idx,
                }),
            );
        };

        let neutral_baseline = sampled_latency_sum / sampled_count as f64;
        let unsampled_best = unsampled_best.map(|(active, idx)| UnsampledCandidate {
            score: neutral_baseline + (active as f64 * ACTIVE_REQUEST_PENALTY_MS),
            active,
            idx,
        });

        (Some(sampled_best), unsampled_best)
    }

    fn should_probe_unsampled(&mut self, unsampled_active: usize) -> bool {
        self.unsampled_probe_cursor = self.unsampled_probe_cursor.wrapping_add(1);
        unsampled_active == 0
            && self
                .unsampled_probe_cursor
                .is_multiple_of(UNSAMPLED_PROBE_INTERVAL)
    }
}

impl Default for LatencyAware {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use impulse_config::config::{Backend, HealthCheck};

    use super::{EXPLORATION_INTERVAL, LatencyAware, UNSAMPLED_PROBE_INTERVAL};
    use crate::{backend::BackendState, backend_pool::BackendPool, health::HealthFailureReason};

    fn create_backend_state(
        address: &str,
        interval: u64,
        failure_threshold: u32,
        cooldown_ms: u64,
    ) -> BackendState {
        BackendState::new(&Backend {
            id: format!("backend-{address}"),
            address: address.to_string(),
            weight: 1,
            health_check: Some(HealthCheck {
                path: "/health".to_string(),
                interval,
                timeout_ms: 1000,
                failure_threshold,
                success_threshold: 1,
                cooldown_ms,
            }),
        })
    }

    #[test]
    fn latency_aware_prefers_lower_ewma() {
        let mut pool = BackendPool::new_from_states(vec![
            create_backend_state("10.0.0.1:1", 1000, 3, 0),
            create_backend_state("10.0.0.2:1", 1000, 3, 0),
        ]);

        pool.finish_request(0, Duration::from_millis(150), Some(200));
        pool.finish_request(1, Duration::from_millis(20), Some(200));

        let mut lb = LatencyAware::new();
        assert_eq!(lb.pick(&pool), Some(1));
    }

    #[test]
    fn latency_aware_periodically_explores_all_sampled_backends() {
        let mut pool = BackendPool::new_from_states(vec![
            create_backend_state("10.0.0.1:1", 1000, 3, 0),
            create_backend_state("10.0.0.2:1", 1000, 3, 0),
        ]);
        pool.finish_request(0, Duration::from_millis(1), Some(200));
        pool.finish_request(1, Duration::from_millis(1_000), Some(200));

        let mut lb = LatencyAware::new();
        let picks: Vec<_> = (0..(EXPLORATION_INTERVAL * 2))
            .map(|_| lb.pick(&pool).expect("backend selection"))
            .collect();

        assert!(picks.contains(&0));
        assert!(picks.contains(&1));
    }

    #[test]
    fn latency_aware_prefers_sampled_backend_over_unsampled_backend() {
        let mut pool = BackendPool::new_from_states(vec![
            create_backend_state("10.0.0.1:1", 1000, 3, 0),
            create_backend_state("10.0.0.2:1", 1000, 3, 0),
        ]);

        pool.finish_request(0, Duration::from_millis(25), Some(200));

        let mut lb = LatencyAware::new();
        assert_eq!(lb.pick_readonly(&pool), Some(0));
        assert_eq!(lb.pick(&pool), Some(0));
    }

    #[test]
    fn latency_aware_excludes_readmitted_probing_backend_from_general_selection() {
        let mut pool = BackendPool::new_from_states(vec![
            create_backend_state("10.0.0.1:1", 0, 1, 10_000),
            create_backend_state("10.0.0.2:1", 1000, 3, 0),
        ]);

        pool.finish_request(1, Duration::from_millis(20), Some(200));
        assert!(
            pool.observe_request_failure(
                0,
                Duration::from_millis(5),
                Some(HealthFailureReason::Transport),
            )
            .is_some()
        );
        pool.reconcile_readmit_at(Instant::now() + Duration::from_millis(10_001));
        assert!(pool.backend(0).is_some_and(BackendState::is_probing));

        let mut lb = LatencyAware::new();
        let total_picks = UNSAMPLED_PROBE_INTERVAL * 2;

        for _ in 0..total_picks {
            assert_eq!(lb.pick(&pool), Some(1));
        }

        assert_eq!(lb.pick_readonly(&pool), Some(1));
    }

    #[test]
    fn latency_aware_fast_5xx_failures_do_not_keep_backend_preferred() {
        let mut pool = BackendPool::new_from_states(vec![
            create_backend_state("10.0.0.1:1", 1000, 3, 0),
            create_backend_state("10.0.0.2:1", 1000, 3, 0),
        ]);
        pool.finish_request(0, Duration::from_millis(20), Some(200));

        let mut lb = LatencyAware::new();
        let mut failing_backend_picks = 0;

        for _ in 0..(UNSAMPLED_PROBE_INTERVAL * 2) {
            let selected = lb.pick(&pool).expect("backend selection");
            if selected == 1 {
                failing_backend_picks += 1;
                pool.finish_request(1, Duration::from_millis(5), Some(503));
                let _ = pool.observe_request_failure(
                    1,
                    Duration::from_millis(5),
                    Some(HealthFailureReason::HttpStatus5xx),
                );
            } else {
                pool.finish_request(0, Duration::from_millis(20), Some(200));
            }
        }

        assert_eq!(failing_backend_picks, 1);
        assert_eq!(lb.pick_readonly(&pool), Some(0));
    }

    #[test]
    fn latency_aware_preserves_startup_behavior_when_all_backends_are_unsampled() {
        let pool = BackendPool::new_from_states(vec![
            create_backend_state("10.0.0.1:1", 1000, 3, 0),
            create_backend_state("10.0.0.2:1", 1000, 3, 0),
        ]);

        let mut lb = LatencyAware::new();
        assert_eq!(lb.pick_readonly(&pool), Some(0));
        assert_eq!(lb.pick(&pool), Some(0));
    }
}
