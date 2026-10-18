//! Impulse-owned fallback load-balancing strategies.

use impulse_config::runtime::RuntimeLoadBalancingStrategy;

use crate::{
    algorithms::{latency_aware::LatencyAware, least_connections::LeastConnections},
    backend_pool::BackendPool,
};

pub enum LoadBalancing {
    LeastConnections(LeastConnections),
    LatencyAware(LatencyAware),
}

impl LoadBalancing {
    pub fn from_runtime_strategy(
        strategy: RuntimeLoadBalancingStrategy,
    ) -> Result<Option<Self>, String> {
        match strategy {
            RuntimeLoadBalancingStrategy::RoundRobin
            | RuntimeLoadBalancingStrategy::ConsistentHash
            | RuntimeLoadBalancingStrategy::Random
            | RuntimeLoadBalancingStrategy::StickyCid => Ok(None),
            RuntimeLoadBalancingStrategy::LeastConnections => {
                Ok(Some(Self::LeastConnections(LeastConnections::new())))
            }
            RuntimeLoadBalancingStrategy::LatencyAware => {
                Ok(Some(Self::LatencyAware(LatencyAware::new())))
            }
            RuntimeLoadBalancingStrategy::Other => {
                Err("unsupported load balancing strategy".to_string())
            }
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
