use crate::backend_pool::BackendPool;

pub struct LeastConnections;

impl LeastConnections {
    pub fn new() -> Self {
        Self
    }

    pub fn pick(&mut self, pool: &BackendPool) -> Option<usize> {
        self.pick_readonly(pool)
    }

    pub fn pick_readonly(&self, pool: &BackendPool) -> Option<usize> {
        let mut best: Option<(usize, usize)> = None;
        for &idx in &pool.healthy {
            let active = pool.backends[idx].active_requests();
            match best {
                Some((best_active, best_idx)) => {
                    if active < best_active || (active == best_active && idx < best_idx) {
                        best = Some((active, idx));
                    }
                }
                None => best = Some((active, idx)),
            }
        }
        best.map(|(_, idx)| idx)
    }
}

impl Default for LeastConnections {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use impulse_config::config::{Backend, HealthCheck};

    use super::LeastConnections;
    use crate::{backend::BackendState, backend_pool::BackendPool};

    fn create_backend_state(address: &str) -> BackendState {
        BackendState::from_config(&Backend {
            id: format!("backend-{address}"),
            address: address.to_string(),
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
    fn least_connections_picks_lowest_active() {
        let pool = BackendPool::new_from_states(vec![
            create_backend_state("10.0.0.1:1"),
            create_backend_state("10.0.0.2:1"),
            create_backend_state("10.0.0.3:1"),
        ]);
        pool.begin_request(0);
        pool.begin_request(0);
        pool.begin_request(1);

        let mut lb = LeastConnections::new();
        assert_eq!(lb.pick(&pool), Some(2));
    }
}
