use std::sync::Arc;

use crate::{edge_core::request_pipeline::ResolvedRouteTarget, routing::index::RouteIndex};

/// Resolves a validated HTTP method, path, and authority through the existing route index.
pub(crate) fn resolve_route(
    routing_index: &RouteIndex,
    method: &str,
    path: &str,
    authority: Option<&str>,
) -> Result<ResolvedRouteTarget, RouteResolutionError> {
    if method.is_empty() || path.is_empty() {
        return Err(RouteResolutionError::EmptyMethodOrPath);
    }

    let route = routing_index
        .lookup_with_decision_for_method(path, authority, Some(method))
        .ok_or(RouteResolutionError::NoRoute)?;

    Ok(ResolvedRouteTarget {
        upstream_name: Arc::from(route.upstream),
        matched_path_len: route.matched_path_len,
        host_specific: route.host_specific,
        method_specific: route.method_specific,
        reason: route.reason,
    })
}

/// Route-lookup failures that ingress adapters map to their existing responses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouteResolutionError {
    EmptyMethodOrPath,
    NoRoute,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use impulse_config::config::{Backend, LoadBalancing, RouteMatch, Upstream};

    use super::*;

    fn upstream(path_prefix: &str, host: Option<&str>, method: Option<&str>) -> Upstream {
        Upstream {
            load_balancing: LoadBalancing {
                lb_type: "round-robin".to_string(),
                key: None,
            },
            auth: Default::default(),
            host_policy: Default::default(),
            forwarded_headers: Default::default(),
            compression: Default::default(),
            cache: Default::default(),
            tls: None,
            route: RouteMatch {
                path_prefix: Some(path_prefix.to_string()),
                host: host.map(str::to_string),
                method: method.map(str::to_string),
            },
            backends: vec![Backend {
                id: "backend".to_string(),
                address: "http://127.0.0.1:7001".to_string(),
                weight: 1,
                health_check: None,
            }],
        }
    }

    #[test]
    fn shared_route_service_matches_index_host_and_method_resolution() {
        let mut upstreams = HashMap::new();
        upstreams.insert("default".to_string(), upstream("/v1", None, Some("GET")));
        upstreams.insert(
            "host-post".to_string(),
            upstream("/v1", Some("api.example.com"), Some("POST")),
        );
        let index = RouteIndex::from_upstreams(&upstreams);

        let expected = index
            .lookup_with_decision_for_method("/v1/messages", Some("api.example.com"), Some("POST"))
            .expect("indexed route");
        let resolved = resolve_route(&index, "POST", "/v1/messages", Some("api.example.com"))
            .expect("shared route");

        assert_eq!(resolved.upstream_name.as_ref(), expected.upstream);
        assert_eq!(resolved.matched_path_len, expected.matched_path_len);
        assert_eq!(resolved.host_specific, expected.host_specific);
        assert_eq!(resolved.method_specific, expected.method_specific);
        assert_eq!(resolved.reason, expected.reason);
    }

    #[test]
    fn shared_route_service_preserves_index_miss_contract() {
        let index = RouteIndex::from_upstreams(&HashMap::new());

        assert_eq!(
            resolve_route(&index, "GET", "/missing", None),
            Err(RouteResolutionError::NoRoute)
        );
        assert_eq!(
            resolve_route(&index, "", "/missing", None),
            Err(RouteResolutionError::EmptyMethodOrPath)
        );
    }
}
