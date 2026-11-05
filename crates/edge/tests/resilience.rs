use std::{collections::HashMap, sync::Arc, time::Duration};

use impulse_config::config::Resilience as ResilienceConfig;
use impulse_edge::resilience::{
    adaptive_admission::AdaptiveAdmission,
    brownout::BrownoutController,
    circuit_breaker::CircuitBreakers,
    retry_budget::RetryBudget,
    route_queue::{RouteQueueLimiter, RouteQueueRejection},
    runtime::RuntimeResilience,
};

#[test]
fn adaptive_admission_adjusts_limit() {
    let admission = AdaptiveAdmission::new(true, 2, 10, 2, 3, 100);
    assert_eq!(admission.current_limit(), 10);
    admission.observe(Duration::from_millis(150), false);
    assert_eq!(admission.current_limit(), 7);
    admission.observe(Duration::from_millis(10), false);
    assert_eq!(admission.current_limit(), 9);
}

#[test]
fn runtime_resilience_honors_adaptive_max_limit_override() {
    let mut cfg = ResilienceConfig::default();
    cfg.adaptive_admission.max_limit = Some(256);
    let runtime = RuntimeResilience::from_config(&cfg, 4096);
    assert_eq!(runtime.adaptive_admission.current_limit(), 256);
}

#[test]
fn route_queue_cap_enforced() {
    let limiter = Arc::new(RouteQueueLimiter::new(1, 10, HashMap::new()));
    let _p1 = limiter.try_acquire("api").expect("first permit");
    assert!(matches!(
        limiter.try_acquire("api"),
        Err(RouteQueueRejection::RouteCap)
    ));
}

#[test]
fn route_queue_global_cap_enforced() {
    let limiter = Arc::new(RouteQueueLimiter::new(10, 2, HashMap::new()));
    let _p1 = limiter.try_acquire("api").expect("first permit");
    let _p2 = limiter.try_acquire("admin").expect("second permit");
    assert!(matches!(
        limiter.try_acquire("api"),
        Err(RouteQueueRejection::GlobalCap)
    ));
}

#[test]
fn circuit_breaker_opens_after_threshold() {
    let cb = CircuitBreakers::new(true, 2, Duration::from_secs(1), 1);
    cb.allow_request("b1")
        .expect("first request")
        .record_failure();
    cb.allow_request("b1")
        .expect("second request")
        .record_failure();
    assert!(cb.allow_request("b1").is_none());
}

#[test]
fn retry_budget_respects_ratio() {
    let rb = RetryBudget::new(true, 50, HashMap::new());
    rb.mark_primary("api");
    assert!(rb.allow_retry("api").is_ok());
    assert!(rb.allow_retry("api").is_err());
}

#[test]
fn retry_budget_disabled_allows_retries() {
    let rb = RetryBudget::new(false, 0, HashMap::new());
    assert!(rb.allow_retry("api").is_ok());
    assert!(rb.allow_retry("api").is_ok());
}

#[test]
fn brownout_preserves_core_routes() {
    let controller = BrownoutController::new(true, 90, 60, vec!["core".to_string()]);
    controller.observe_admission_pressure(95);
    assert!(controller.is_active());
    assert!(controller.route_allowed("core"));
    assert!(!controller.route_allowed("non_core"));
}

#[test]
fn runtime_resilience_method_and_path_policy_checks() {
    let mut cfg = ResilienceConfig::default();
    cfg.protocol.allowed_methods = vec!["GET".to_string()];
    cfg.protocol.denied_path_prefixes = vec!["/admin".to_string()];
    cfg.protocol.allow_0rtt = true;
    cfg.protocol.early_data_safe_methods = vec!["GET".to_string()];
    cfg.protocol.allow_connect = true;
    cfg.protocol.connect_allowed_ports = vec![443];
    cfg.protocol.connect_allowed_authorities = vec!["proxy.example.com:443".to_string()];

    let runtime = RuntimeResilience::from_config(&cfg, 64);
    assert!(runtime.method_allowed("GET"));
    assert!(!runtime.method_allowed("POST"));
    assert!(runtime.path_denied("/admin/secret"));
    assert!(!runtime.path_denied("/api"));
    assert!(runtime.early_data_allowed_for("GET"));
    assert!(!runtime.early_data_allowed_for("POST"));
    assert!(runtime.connect_allowed("proxy.example.com:443"));
    assert!(!runtime.connect_allowed("proxy.example.com:8443"));
    assert!(!runtime.connect_allowed("other.example.com:443"));
}
