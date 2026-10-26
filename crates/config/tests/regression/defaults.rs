//! Default-lowering regressions for omitted config fields.

use std::time::Duration;

use impulse_config::{
    config::{
        CURRENT_CONFIG_VERSION, ControlApi, ForwardedHeaderPolicyMode, MetricsEndpoint,
        Performance, Resilience, RoutingTransparency, Tracing, UpstreamHostPolicyMode, UpstreamTls,
    },
    runtime::RuntimeLoadBalancingStrategy,
};

use crate::common::{
    api_runtime_upstream, primary_listener_runtime_config, runtime_config_from_yaml,
};

fn sparse_config_yaml() -> &'static str {
    r#"
listen:
  tls:
    cert: "/tmp/tls/default.pem"
    key: "/tmp/tls/default.key"
upstream:
  api:
    route:
      host: "api.example.com"
      path_prefix: "/"
    backends:
      - id: "api-1"
        address: "https://api.internal:8443"
"#
}

#[test]
fn runtime_lowering_preserves_effective_defaults_for_sparse_configs() {
    let runtime = runtime_config_from_yaml(sparse_config_yaml());
    let listener = primary_listener_runtime_config(&runtime);
    let api = api_runtime_upstream(&runtime);

    assert_eq!(runtime.version, CURRENT_CONFIG_VERSION);
    assert_eq!(listener.listen.listen.protocol, "http3");
    assert_eq!(listener.listen.listen.port, 9889);
    assert_eq!(listener.listen.listen.address, "0.0.0.0");

    assert_eq!(
        listener.policies.timeouts.backend_request,
        Duration::from_millis(Performance::default().backend_timeout_ms)
    );
    assert_eq!(
        listener.policies.timeouts.backend_connect,
        Duration::from_millis(Performance::default().backend_connect_timeout_ms)
    );
    assert_eq!(
        listener
            .policies
            .transport
            .connection_limits
            .global_inflight,
        Performance::default().global_inflight_limit
    );
    assert_eq!(
        listener.policies.transport.quic_initial_max_data,
        Performance::default().quic_initial_max_data
    );
    assert_eq!(
        runtime.policies.admission.route_queue.default_cap,
        Resilience::default().route_queue.default_cap
    );
    assert_eq!(
        runtime.policies.admission.watchdog.check_interval,
        Duration::from_millis(Resilience::default().watchdog.check_interval_ms)
    );

    assert_eq!(
        api.load_balancing.strategy,
        RuntimeLoadBalancingStrategy::RoundRobin
    );
    assert_eq!(api.load_balancing.key, None);
    assert!(api.policy.upstream_auth.api_key.is_none());
    assert!(api.policy.upstream_auth.jwt.is_none());
    assert!(api.policy.upstream_auth.external_auth.is_none());
    assert!(api.policy.upstream_auth.required_scopes.is_empty());
    assert!(api.policy.upstream_auth.required_roles.is_empty());
    assert_eq!(api.policy.host.0.mode, UpstreamHostPolicyMode::PassThrough);
    assert_eq!(api.policy.host.0.host, None);
    assert_eq!(
        api.policy.forwarded_headers.0.mode,
        ForwardedHeaderPolicyMode::Overwrite
    );

    assert_eq!(
        api.effective_tls.verify_certificates,
        UpstreamTls::default().verify_certificates
    );
    assert_eq!(
        api.effective_tls.strict_sni,
        UpstreamTls::default().strict_sni
    );
    assert_eq!(api.backends[0].backend.weight, 100);
    assert!(api.backends[0].health_check.is_none());

    assert_eq!(
        runtime.observability.metrics.port,
        MetricsEndpoint::default().port
    );
    assert_eq!(
        runtime.observability.control_api.port,
        ControlApi::default().port
    );
    assert_eq!(
        runtime.observability.tracing.service_name,
        Tracing::default().service_name
    );
    assert_eq!(
        runtime.observability.routing.header_name,
        RoutingTransparency::default().header_name
    );
}
