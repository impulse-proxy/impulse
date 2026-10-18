//! Runtime-upstream pool contract tests.

mod common;

use common::{runtime_upstream, weighted_backend};
use impulse_config::config::HealthCheck;
use impulse_lb::upstream_pool::UpstreamPool;

#[test]
fn runtime_upstream_lowers_into_a_pool_with_canonical_lb_contract() {
    let health_check = HealthCheck {
        path: "/health".to_string(),
        interval: 5000,
        timeout_ms: 2000,
        failure_threshold: 3,
        success_threshold: 2,
        cooldown_ms: 10000,
    };
    let runtime_upstream = runtime_upstream(
        "round-robin",
        vec![
            weighted_backend("backend1", "127.0.0.1:8001", 100, health_check.clone()),
            weighted_backend("backend2", "127.0.0.1:8002", 200, health_check),
        ],
    );

    let upstream_pool = UpstreamPool::from_runtime_upstream(&runtime_upstream).unwrap();
    assert_eq!(upstream_pool.load_balancer_name(), "round-robin");
    assert_eq!(upstream_pool.backend_count(), 2);
    assert_eq!(upstream_pool.backend_address(0), Some("127.0.0.1:8001"));
    assert_eq!(upstream_pool.backend_address(1), Some("127.0.0.1:8002"));
}
