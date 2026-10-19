mod coordinator;
mod health;

pub(crate) use self::{
    coordinator::{BackendLifecycleCoordinator, RuntimeBackendLifecycleState},
    health::{
        ActiveHealthCheckEvaluation, apply_backend_health_observation,
        apply_backend_request_accounting, apply_backend_request_feedback,
        evaluate_active_health_check,
    },
};

#[cfg(test)]
mod test_support {
    use std::{
        collections::HashMap,
        sync::{Arc, RwLock},
    };

    use impulse_config::{
        config::{Backend, Config, HealthCheck, Listen, LoadBalancing, RouteMatch, Tls, Upstream},
        runtime::RuntimeConfig,
    };
    use impulse_lb::upstream_pool::UpstreamPool;

    fn test_runtime_config(interval: u64, backend_addr: &str) -> RuntimeConfig {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "api".to_string(),
            Upstream {
                tls: None,
                load_balancing: LoadBalancing {
                    lb_type: "round-robin".to_string(),
                    key: None,
                },
                auth: Default::default(),
                host_policy: Default::default(),
                forwarded_headers: Default::default(),
                compression: Default::default(),
                route: RouteMatch {
                    host: Some("api.example.com".to_string()),
                    path_prefix: None,
                    method: None,
                },
                backends: vec![Backend {
                    id: "backend-a".to_string(),
                    address: backend_addr.to_string(),
                    weight: 1,
                    health_check: (interval > 0).then_some(HealthCheck {
                        path: "/health".to_string(),
                        interval,
                        timeout_ms: 1000,
                        failure_threshold: 1,
                        success_threshold: 1,
                        cooldown_ms: 0,
                    }),
                }],
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
        .expect("runtime config")
    }

    pub(crate) fn test_upstream_pool_with_interval(interval: u64) -> Arc<RwLock<UpstreamPool>> {
        let runtime = test_runtime_config(interval, "127.0.0.1:8080");

        Arc::new(RwLock::new(
            UpstreamPool::from_runtime_upstream(runtime.upstreams.get("api").expect("upstream"))
                .expect("pool"),
        ))
    }

    pub(crate) fn test_upstream_pool() -> Arc<RwLock<UpstreamPool>> {
        test_upstream_pool_with_interval(0)
    }

    pub(crate) fn test_active_health_upstream_pool() -> Arc<RwLock<UpstreamPool>> {
        test_upstream_pool_with_interval(1000)
    }
}
