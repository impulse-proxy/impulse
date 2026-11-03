use std::collections::HashMap;

use impulse_config::{
    config::{Backend, Config, Listen, LoadBalancing, RouteMatch, Tls, Upstream},
    runtime::{RuntimeConfig, RuntimeUpstream},
};
use impulse_lb::{BackendInput, BackendWeight, LoadBalancingStrategy, upstream_pool::UpstreamPool};

pub const BACKEND_COUNTS: [usize; 4] = [1, 10, 100, 1_000];
pub const STRATEGIES: [(&str, &str); 2] = [
    ("least_connections", "least-connections"),
    ("latency_aware", "latency-aware"),
];

pub fn runtime_upstream(backend_count: usize, strategy: &str) -> RuntimeUpstream {
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "benchmark".to_string(),
        Upstream {
            load_balancing: LoadBalancing {
                lb_type: strategy.to_string(),
                key: None,
            },
            auth: Default::default(),
            host_policy: Default::default(),
            forwarded_headers: Default::default(),
            compression: Default::default(),
            cache: Default::default(),
            tls: None,
            route: RouteMatch {
                host: None,
                path_prefix: Some("/".to_string()),
                method: None,
            },
            backends: (0..backend_count)
                .map(|index| Backend {
                    id: format!("backend-{index:05}"),
                    address: format!("127.0.0.1:{}", 10_000 + index),
                    weight: 100,
                    health_check: None,
                })
                .collect(),
        },
    );

    RuntimeConfig::from_config(&Config {
        version: 1,
        listen: Listen {
            protocol: "http1".to_string(),
            tls: Tls {
                cert: "/tmp/benchmark-cert.pem".to_string(),
                key: "/tmp/benchmark-key.pem".to_string(),
                ..Tls::default()
            },
            ..Listen::default()
        },
        listeners: Vec::new(),
        upstream: upstreams,
        load_balancing: None,
        upstream_tls: Default::default(),
        secrets: Default::default(),
        log: Default::default(),
        performance: Default::default(),
        observability: Default::default(),
        resilience: Default::default(),
        security: Default::default(),
    })
    .expect("benchmark upstream configuration must normalize")
    .upstreams
    .remove("benchmark")
    .expect("benchmark upstream must exist")
}

pub fn upstream_pool(backend_count: usize, strategy: &str) -> UpstreamPool {
    upstream_pool_from_runtime(&runtime_upstream(backend_count, strategy))
}

pub fn upstream_pool_from_runtime(upstream: &RuntimeUpstream) -> UpstreamPool {
    let strategy = match upstream.load_balancing.strategy {
        impulse_config::runtime::RuntimeLoadBalancingStrategy::LeastConnections => {
            LoadBalancingStrategy::LeastConnections
        }
        impulse_config::runtime::RuntimeLoadBalancingStrategy::LatencyAware => {
            LoadBalancingStrategy::LatencyAware
        }
        _ => panic!("benchmark strategy must use a custom dynamic selector"),
    };
    let backends = upstream
        .backends
        .iter()
        .enumerate()
        .map(|(index, backend)| {
            BackendInput::new(
                backend.backend.id.clone(),
                backend.backend.address.clone(),
                index,
                BackendWeight::new(backend.backend.weight),
                None,
            )
        });
    UpstreamPool::new(backends, strategy, None)
}
