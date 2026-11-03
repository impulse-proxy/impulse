//! Impulse-owned fallback load-balancing strategies.

use crate::{
    LoadBalancingStrategy,
    algorithms::{latency_aware::LatencyAware, least_connections::LeastConnections},
    backend_pool::BackendPool,
};

pub enum LoadBalancing {
    LeastConnections(LeastConnections),
    LatencyAware(LatencyAware),
}

impl LoadBalancing {
    pub fn from_strategy(strategy: LoadBalancingStrategy) -> Option<Self> {
        match strategy {
            LoadBalancingStrategy::RoundRobin
            | LoadBalancingStrategy::ConsistentHash
            | LoadBalancingStrategy::Random
            | LoadBalancingStrategy::StickyCid => None,
            LoadBalancingStrategy::LeastConnections => {
                Some(Self::LeastConnections(LeastConnections::new()))
            }
            LoadBalancingStrategy::LatencyAware => Some(Self::LatencyAware(LatencyAware::new())),
        }
    }

    pub fn pick(&mut self, pool: &BackendPool) -> Option<usize> {
        match self {
            Self::LeastConnections(selector) => selector.pick(pool),
            Self::LatencyAware(selector) => selector.pick(pool),
        }
    }

    pub fn pick_readonly(&self, pool: &BackendPool) -> Option<usize> {
        match self {
            Self::LeastConnections(selector) => selector.pick_readonly(pool),
            Self::LatencyAware(selector) => selector.pick_readonly(pool),
        }
    }
}
