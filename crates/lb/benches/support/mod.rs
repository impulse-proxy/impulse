use std::{collections::HashMap, time::Duration};

use impulse_config::{
    config::{Backend, Config, HealthCheck, Listen, LoadBalancing, RouteMatch, Tls, Upstream},
    runtime::{RuntimeConfig, RuntimeUpstream},
};
use impulse_lb::{
    BackendHealthInput, BackendInput, BackendWeight, LoadBalancingStrategy,
    upstream_pool::UpstreamPool,
};

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
                    protocol: Default::default(),
                    weight: 100,
                    health_check: Some(HealthCheck {
                        path: "/health".to_string(),
                        interval: 1_000,
                        timeout_ms: 1_000,
                        failure_threshold: 1,
                        success_threshold: 1,
                        cooldown_ms: 10_000,
                    }),
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
    let mut pool = upstream_pool_from_runtime(&runtime_upstream(backend_count, strategy));
    seed_runtime_state(&mut pool, backend_count);
    pool
}

fn seed_runtime_state(pool: &mut UpstreamPool, backend_count: usize) {
    const LATENCY_OFFSETS_MS: [u64; 4] = [0, 7, 3, 11];

    for index in 0..backend_count {
        let baseline_latency_ms = 8 + (index * 37 % 120) as u64;
        for offset_ms in LATENCY_OFFSETS_MS {
            pool.begin_request_for_accounting(index);
            pool.finish_request(
                index,
                Duration::from_millis(baseline_latency_ms + offset_ms),
                Some(200),
            );
        }

        let active_requests = (index * 5 + 3) % 8;
        for _ in 0..active_requests {
            pool.begin_request_for_accounting(index);
        }
    }

    for index in (7..backend_count).step_by(8) {
        let _ = pool.mark_backend_failure_from_active_check(index);
    }
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
                backend.health_check.as_ref().map(|health| {
                    BackendHealthInput::new(
                        health.failure_threshold,
                        health.success_threshold,
                        health.cooldown,
                        true,
                    )
                }),
            )
        });
    UpstreamPool::new(backends, strategy, None)
}
