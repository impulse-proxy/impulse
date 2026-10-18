//! Shared fixtures for the runtime-config regression suite.

use std::collections::HashMap;

use impulse_config::{
    config::{
        Backend, ClientAuth, Config, ForwardedHeaderPolicy, ForwardedHeaderPolicyMode, Listen,
        LoadBalancing, Log, Observability, Performance, Resilience, RouteMatch, Security, Tls,
        Upstream, UpstreamHostPolicy, UpstreamHostPolicyMode, UpstreamTls,
    },
    runtime::{ListenerRuntimeConfig, RuntimeConfig, RuntimeConfigError, RuntimeUpstream},
};

const API_UPSTREAM: &str = "api";

/// A minimal, valid single-upstream config used as the base for regression cases.
pub(crate) fn sample_config() -> Config {
    let mut config = Config {
        version: 1,
        listen: Listen {
            protocol: "http3".to_string(),
            port: 443,
            address: "0.0.0.0".to_string(),
            tls: Tls {
                cert: "/tmp/tls/default.pem".to_string(),
                key: "/tmp/tls/default.key".to_string(),
                certificates: Vec::new(),
                client_auth: ClientAuth::default(),
            },
        },
        listeners: Vec::new(),
        upstream: HashMap::new(),
        load_balancing: None,
        upstream_tls: UpstreamTls::default(),
        secrets: Default::default(),
        log: Log::default(),
        performance: Performance::default(),
        observability: Observability::default(),
        resilience: Resilience::default(),
        security: Security::default(),
    };

    config.upstream.insert(
        "api".to_string(),
        Upstream {
            load_balancing: LoadBalancing {
                lb_type: "round-robin".to_string(),
                key: None,
            },
            auth: Default::default(),
            host_policy: UpstreamHostPolicy {
                mode: UpstreamHostPolicyMode::Rewrite,
                host: Some("api.internal".to_string()),
            },
            forwarded_headers: ForwardedHeaderPolicy {
                mode: ForwardedHeaderPolicyMode::Append,
            },
            compression: Default::default(),
            tls: None,
            route: RouteMatch {
                host: Some("api.example.com".to_string()),
                path_prefix: Some("/".to_string()),
                method: None,
            },
            backends: vec![Backend {
                id: "api-1".to_string(),
                address: "https://api.internal:8443".to_string(),
                weight: 100,
                health_check: None,
            }],
        },
    );

    config
}

pub(crate) fn parse_config(yaml: &str) -> Config {
    serde_yaml::from_str(yaml)
        .unwrap_or_else(|err| panic!("regression fixture yaml should parse: {err}"))
}

pub(crate) fn sample_config_with(edit: impl FnOnce(&mut Config)) -> Config {
    let mut config = sample_config();
    edit(&mut config);
    config
}

pub(crate) fn sample_config_with_api_upstream(edit: impl FnOnce(&mut Upstream)) -> Config {
    sample_config_with(|config| edit(api_upstream_mut(config)))
}

pub(crate) fn sample_runtime_config_with_api_upstream(
    edit: impl FnOnce(&mut Upstream),
) -> RuntimeConfig {
    runtime_config(&sample_config_with_api_upstream(edit))
}

pub(crate) fn api_upstream_mut(config: &mut Config) -> &mut Upstream {
    config
        .upstream
        .get_mut(API_UPSTREAM)
        .expect("shared regression fixture must include the 'api' upstream")
}

pub(crate) fn api_backend_mut(config: &mut Config) -> &mut Backend {
    api_upstream_mut(config)
        .backends
        .first_mut()
        .expect("shared regression fixture must include an 'api' backend")
}

pub(crate) fn duplicate_api_upstream(config: &mut Config, name: &str) {
    let duplicate = config
        .upstream
        .get(API_UPSTREAM)
        .expect("shared regression fixture must include the 'api' upstream")
        .clone();
    config.upstream.insert(name.to_string(), duplicate);
}

pub(crate) fn runtime_config(config: &Config) -> RuntimeConfig {
    RuntimeConfig::from_config(config)
        .unwrap_or_else(|err| panic!("shared regression fixture should lower successfully: {err}"))
}

pub(crate) fn runtime_config_from_yaml(yaml: &str) -> RuntimeConfig {
    runtime_config(&parse_config(yaml))
}

pub(crate) fn sample_runtime_config_with(edit: impl FnOnce(&mut Config)) -> RuntimeConfig {
    runtime_config(&sample_config_with(edit))
}

pub(crate) fn runtime_config_err(config: &Config) -> RuntimeConfigError {
    RuntimeConfig::from_config(config)
        .expect_err("regression case must reject the runtime lowering input")
}

pub(crate) fn sample_runtime_config_err_with(edit: impl FnOnce(&mut Config)) -> RuntimeConfigError {
    runtime_config_err(&sample_config_with(edit))
}

pub(crate) fn api_runtime_upstream(runtime: &RuntimeConfig) -> &RuntimeUpstream {
    runtime
        .upstreams
        .get(API_UPSTREAM)
        .expect("runtime lowering output must include the 'api' upstream")
}

pub(crate) fn primary_listener_runtime_config(runtime: &RuntimeConfig) -> ListenerRuntimeConfig {
    runtime
        .primary_listener_runtime_config()
        .expect("primary listener")
}

pub(crate) fn assert_config_error_contains(err: &RuntimeConfigError, category: &str, needle: &str) {
    assert_eq!(
        err.category(),
        category,
        "unexpected runtime error category"
    );
    let message = err.to_string();
    assert!(
        message.contains(needle),
        "expected runtime error to contain '{needle}', got '{message}'"
    );
}
