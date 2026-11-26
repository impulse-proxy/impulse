use std::collections::HashMap;

use impulse_config::{
    config::{Backend, Config, Listen, RouteMatch, Tls, Upstream},
    runtime::{RuntimeConfig, RuntimeUpstream},
};
use impulse_edge::routing::index::RouteIndex;

pub const ROUTE_SCALES: [usize; 4] = [10, 100, 1_000, 10_000];

pub struct RouteIndexFixture {
    pub runtime_upstreams: HashMap<String, RuntimeUpstream>,
    pub index: RouteIndex,
    pub default_hit: String,
    pub default_miss: String,
    pub exact_host_path: String,
    pub exact_host: String,
    pub exact_host_miss: String,
    pub wildcard_host_path: String,
    pub wildcard_host: String,
    pub wildcard_host_miss: String,
    pub method_path: String,
    pub method: String,
    pub method_miss: String,
}

impl RouteIndexFixture {
    pub fn new(route_count: usize) -> Self {
        assert!(
            route_count >= 4,
            "route benchmark needs at least four routes"
        );

        let mut config_upstreams = HashMap::with_capacity(route_count);
        for index in 0..route_count {
            let name = format!("route-{index:05}");
            config_upstreams.insert(
                name.clone(),
                upstream(
                    name,
                    index,
                    RouteMatch {
                        host: None,
                        path_prefix: Some(format!("/routes/{index:05}")),
                        method: None,
                    },
                ),
            );
        }

        let exact_host = "routes.bench.example".to_string();
        let exact_host_path = "/exact/constrained".to_string();
        let wildcard_host = "tenant.wildcard.bench.example".to_string();
        let wildcard_host_path = "/wildcard/constrained".to_string();
        let method_path = "/method/constrained".to_string();
        let exact_index = route_count - 1;
        let wildcard_index = route_count - 2;
        let method_index = route_count - 3;

        replace_route(
            &mut config_upstreams,
            exact_index,
            RouteMatch {
                host: Some(exact_host.clone()),
                path_prefix: Some(exact_host_path.clone()),
                method: None,
            },
        );
        replace_route(
            &mut config_upstreams,
            wildcard_index,
            RouteMatch {
                host: Some("*.wildcard.bench.example".to_string()),
                path_prefix: Some(wildcard_host_path.clone()),
                method: None,
            },
        );
        replace_route(
            &mut config_upstreams,
            method_index,
            RouteMatch {
                host: None,
                path_prefix: Some(method_path.clone()),
                method: Some("POST".to_string()),
            },
        );

        let runtime_config = match RuntimeConfig::from_config(&Config {
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
            upstream: config_upstreams,
            load_balancing: None,
            upstream_tls: Default::default(),
            secrets: Default::default(),
            log: Default::default(),
            performance: Default::default(),
            observability: Default::default(),
            resilience: Default::default(),
            security: Default::default(),
        }) {
            Ok(runtime_config) => runtime_config,
            Err(error) => panic!("benchmark route configuration must normalize: {error}"),
        };
        let runtime_upstreams = runtime_config.upstreams;
        let index = RouteIndex::from_runtime_upstreams(&runtime_upstreams);

        Self {
            runtime_upstreams,
            index,
            default_hit: "/routes/00000/resource".to_string(),
            default_miss: "/not-found".to_string(),
            exact_host_path,
            exact_host,
            exact_host_miss: "other.bench.example".to_string(),
            wildcard_host_path,
            wildcard_host,
            wildcard_host_miss: "wildcard.bench.example".to_string(),
            method_path,
            method: "POST".to_string(),
            method_miss: "GET".to_string(),
        }
    }
}

fn replace_route(upstreams: &mut HashMap<String, Upstream>, index: usize, route: RouteMatch) {
    let name = format!("route-{index:05}");
    upstreams.insert(name.clone(), upstream(name, index, route));
}

fn upstream(id: String, index: usize, route: RouteMatch) -> Upstream {
    Upstream {
        load_balancing: Default::default(),
        auth: Default::default(),
        host_policy: Default::default(),
        forwarded_headers: Default::default(),
        compression: Default::default(),
        cache: Default::default(),
        tls: None,
        route,
        backends: vec![Backend {
            id,
            address: format!("127.0.0.1:{}", 10_000 + index),
            protocol: Default::default(),
            weight: 100,
            health_check: None,
        }],
    }
}
