use std::collections::HashMap;

use impulse_config::config::{Backend, RouteMatch, Upstream};
use impulse_edge::routing::index::RouteIndex;

pub const ROUTE_SCALES: [usize; 4] = [10, 100, 1_000, 10_000];

pub struct RouteIndexFixture {
    pub upstreams: HashMap<String, Upstream>,
    pub index: RouteIndex,
    pub path_hit: String,
    pub path_miss: String,
    pub host_hit_path: String,
    pub host_miss_path: String,
    pub host: String,
    pub method_path: String,
    pub method: String,
}

impl RouteIndexFixture {
    pub fn new(route_count: usize) -> Self {
        assert!(
            route_count >= 3,
            "route benchmark needs at least three routes"
        );

        let mut upstreams = HashMap::with_capacity(route_count);
        for index in 0..route_count {
            let name = format!("route-{index:05}");
            upstreams.insert(
                name.clone(),
                upstream(
                    name,
                    RouteMatch {
                        host: None,
                        path_prefix: Some(format!("/routes/{index:05}")),
                        method: None,
                    },
                ),
            );
        }

        let host = "routes.bench.example".to_string();
        let host_hit_path = "/host/constrained".to_string();
        let method_path = "/method/constrained".to_string();
        let host_route = format!("route-{:05}", route_count - 1);
        let method_route = format!("route-{:05}", route_count - 2);

        upstreams.insert(
            host_route.clone(),
            upstream(
                host_route,
                RouteMatch {
                    host: Some(host.clone()),
                    path_prefix: Some(host_hit_path.clone()),
                    method: None,
                },
            ),
        );
        upstreams.insert(
            method_route.clone(),
            upstream(
                method_route,
                RouteMatch {
                    host: None,
                    path_prefix: Some(method_path.clone()),
                    method: Some("POST".to_string()),
                },
            ),
        );

        let index = RouteIndex::from_upstreams(&upstreams);
        Self {
            upstreams,
            index,
            path_hit: "/routes/00000/resource".to_string(),
            path_miss: "/not-found".to_string(),
            host_hit_path,
            host_miss_path: "/host/not-found".to_string(),
            host,
            method_path,
            method: "POST".to_string(),
        }
    }
}

fn upstream(id: String, route: RouteMatch) -> Upstream {
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
            address: "127.0.0.1:1".to_string(),
            weight: 100,
            health_check: None,
        }],
    }
}
