use std::collections::HashMap;

use impulse_config::{
    config::{Backend, Config, HealthCheck, Listen, LoadBalancing, RouteMatch, Tls, Upstream},
    runtime::{
        RuntimeConfig, RuntimeLoadBalancingStrategy, RuntimeRequestKeySpec, RuntimeUpstream,
    },
};

use crate::{
    BackendHealthInput, BackendInput, BackendWeight, LoadBalancingStrategy, RequestKeyInput,
};

pub(crate) fn backend_input(index: usize, backend: &Backend) -> BackendInput {
    BackendInput::new(
        backend.id.clone(),
        backend.address.clone(),
        index,
        BackendWeight::new(backend.weight),
        backend.health_check.as_ref().map(|health| {
            BackendHealthInput::new(
                health.failure_threshold,
                health.success_threshold,
                std::time::Duration::from_millis(health.cooldown_ms),
                health.interval > 0,
            )
        }),
    )
}

pub(crate) fn health_input(health: &HealthCheck) -> BackendHealthInput {
    BackendHealthInput::new(
        health.failure_threshold,
        health.success_threshold,
        std::time::Duration::from_millis(health.cooldown_ms),
        health.interval > 0,
    )
}

pub(crate) fn backend_inputs(upstream: &RuntimeUpstream) -> Vec<BackendInput> {
    upstream
        .backends
        .iter()
        .enumerate()
        .map(|(index, backend)| backend_input(index, &backend.backend))
        .collect()
}

pub(crate) fn strategy_input(strategy: RuntimeLoadBalancingStrategy) -> LoadBalancingStrategy {
    match strategy {
        RuntimeLoadBalancingStrategy::RoundRobin => LoadBalancingStrategy::RoundRobin,
        RuntimeLoadBalancingStrategy::ConsistentHash => LoadBalancingStrategy::ConsistentHash,
        RuntimeLoadBalancingStrategy::Random => LoadBalancingStrategy::Random,
        RuntimeLoadBalancingStrategy::LeastConnections => LoadBalancingStrategy::LeastConnections,
        RuntimeLoadBalancingStrategy::LatencyAware => LoadBalancingStrategy::LatencyAware,
        RuntimeLoadBalancingStrategy::StickyCid => LoadBalancingStrategy::StickyCid,
        RuntimeLoadBalancingStrategy::Other => panic!("test runtime strategy must be supported"),
    }
}

pub(crate) fn request_key_input(input: &RuntimeRequestKeySpec) -> RequestKeyInput {
    match input {
        RuntimeRequestKeySpec::Path => RequestKeyInput::Path,
        RuntimeRequestKeySpec::Authority => RequestKeyInput::Authority,
        RuntimeRequestKeySpec::Method => RequestKeyInput::Method,
        RuntimeRequestKeySpec::Cid => RequestKeyInput::Cid,
        RuntimeRequestKeySpec::StickyCid => RequestKeyInput::StickyCid,
        RuntimeRequestKeySpec::PeerIp => RequestKeyInput::PeerIp,
        RuntimeRequestKeySpec::ClientIp => RequestKeyInput::ClientIp,
        RuntimeRequestKeySpec::BearerToken => RequestKeyInput::BearerToken,
        RuntimeRequestKeySpec::Header(name) => RequestKeyInput::Header(name.clone()),
        RuntimeRequestKeySpec::Cookie(name) => RequestKeyInput::Cookie(name.clone()),
        RuntimeRequestKeySpec::Query(name) => RequestKeyInput::Query(name.clone()),
    }
}

pub(crate) fn runtime_upstream_from_addresses(
    lb_type: &str,
    key: Option<&str>,
    addresses: &[&str],
) -> RuntimeUpstream {
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        Upstream {
            tls: None,
            load_balancing: LoadBalancing {
                lb_type: lb_type.to_string(),
                key: key.map(str::to_string),
            },
            auth: Default::default(),
            host_policy: Default::default(),
            forwarded_headers: Default::default(),
            compression: Default::default(),
            cache: Default::default(),
            route: RouteMatch {
                host: None,
                path_prefix: Some("/".to_string()),
                method: None,
            },
            backends: addresses
                .iter()
                .enumerate()
                .map(|(index, address)| Backend {
                    id: format!("backend-{index}"),
                    address: (*address).to_string(),
                    weight: 1,
                    health_check: Some(default_health_check(1000)),
                })
                .collect(),
        },
    );

    RuntimeConfig::from_config(&Config {
        version: 1,
        listen: Listen {
            protocol: "http1".to_string(),
            tls: Tls {
                cert: "/tmp/test-cert.pem".to_string(),
                key: "/tmp/test-key.pem".to_string(),
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
    .expect("runtime config fixture should normalize")
    .upstreams
    .remove("api")
    .expect("runtime upstream fixture should exist")
}

fn default_health_check(cooldown_ms: u64) -> HealthCheck {
    HealthCheck {
        path: "/health".to_string(),
        interval: 1,
        timeout_ms: 1000,
        failure_threshold: 1,
        success_threshold: 1,
        cooldown_ms,
    }
}
