use crate::{
    edge_core::request_execution::ResolvedRouteTarget,
    routing::index::RouteIndex,
    runtime::generation::{RuntimeGenerationState, RuntimeIdentities},
};

/// Resolves a route match and pins it to the runtime compiled for its generation.
pub(crate) fn resolve_route(
    generation: &RuntimeGenerationState,
    method: &str,
    path: &str,
    authority: Option<&str>,
) -> Result<ResolvedRouteTarget, RouteResolutionError> {
    let matched = resolve_route_match(
        &generation.routing_index,
        &generation.identities,
        method,
        path,
        authority,
    )?;
    let runtime = generation
        .route_runtime(matched.upstream_id)
        .cloned()
        .ok_or(RouteResolutionError::MissingRouteRuntime)?;
    Ok(ResolvedRouteTarget {
        route_id: matched.route_id,
        upstream_id: matched.upstream_id,
        upstream_name: matched.upstream_name,
        matched_path_len: matched.matched_path_len,
        host_specific: matched.host_specific,
        reason: matched.reason,
        runtime,
    })
}

/// Resolves route-match metadata without generation-owned execution state.
pub(crate) fn resolve_route_match(
    routing_index: &RouteIndex,
    identities: &RuntimeIdentities,
    method: &str,
    path: &str,
    authority: Option<&str>,
) -> Result<ResolvedRouteMatch, RouteResolutionError> {
    if method.is_empty() || path.is_empty() {
        return Err(RouteResolutionError::EmptyMethodOrPath);
    }

    let route = routing_index
        .lookup_with_decision_for_method(path, authority, Some(method))
        .ok_or(RouteResolutionError::NoRoute)?;

    Ok(ResolvedRouteMatch {
        route_id: route.route_id,
        upstream_id: route.upstream_id,
        upstream_name: identities
            .upstream_display_name(route.upstream_id)
            .ok_or(RouteResolutionError::MissingUpstreamDisplayName)?,
        matched_path_len: route.matched_path_len,
        host_specific: route.host_specific,
        #[cfg(test)]
        method_specific: route.method_specific,
        reason: route.reason,
    })
}

pub(crate) struct ResolvedRouteMatch {
    pub(crate) route_id: impulse_contracts::RouteId,
    pub(crate) upstream_id: impulse_contracts::UpstreamId,
    pub(crate) upstream_name: std::sync::Arc<str>,
    pub(crate) matched_path_len: usize,
    pub(crate) host_specific: bool,
    #[cfg(test)]
    pub(crate) method_specific: bool,
    pub(crate) reason: crate::routing::decision::RouteDecisionReason,
}

/// Route-lookup failures that ingress adapters map to their existing responses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouteResolutionError {
    EmptyMethodOrPath,
    NoRoute,
    MissingUpstreamDisplayName,
    MissingRouteRuntime,
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
                protocol: Default::default(),
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
        let identities = RuntimeIdentities::for_upstream_names(upstreams.keys().cloned());

        let expected = index
            .lookup_with_decision_for_method("/v1/messages", Some("api.example.com"), Some("POST"))
            .expect("indexed route");
        let resolved = resolve_route_match(
            &index,
            &identities,
            "POST",
            "/v1/messages",
            Some("api.example.com"),
        )
        .expect("shared route");

        assert_eq!(resolved.upstream_id, expected.upstream_id);
        assert_eq!(resolved.matched_path_len, expected.matched_path_len);
        assert_eq!(resolved.host_specific, expected.host_specific);
        assert_eq!(resolved.method_specific, expected.method_specific);
        assert_eq!(resolved.reason, expected.reason);
    }

    #[test]
    fn shared_route_service_preserves_index_miss_contract() {
        let index = RouteIndex::from_upstreams(&HashMap::new());
        let identities = RuntimeIdentities::for_upstream_names([]);

        assert!(matches!(
            resolve_route_match(&index, &identities, "GET", "/missing", None),
            Err(RouteResolutionError::NoRoute)
        ));
        assert!(matches!(
            resolve_route_match(&index, &identities, "", "/missing", None),
            Err(RouteResolutionError::EmptyMethodOrPath)
        ));
    }
}
