use std::collections::HashMap;

use impulse_config::{
    config::Upstream,
    runtime::{RuntimeRouteHostPattern, RuntimeUpstream},
};

use crate::routing::{
    decision::{RouteDecision, RouteDecisionReason, RoutePreference},
    host::{ConfiguredHostPattern, normalize_host_for_routing, parse_configured_host_pattern},
    matcher::{compare_route_candidate, prefer_host_lookup_result, prefer_route_candidate},
    route::{HostLookupResult, HostMatchKind, IndexedRoute, RouteCandidate},
    trie::RouteTrie,
};
pub struct RouteIndex {
    host_tries: HashMap<String, RouteTrie>,
    pub wildcard_host_tries: HashMap<String, RouteTrie>,
    pub default_trie: RouteTrie,
    pub default_max_path_len: usize,
    pub upstream_names: Vec<String>,
    pub upstream_methods: Vec<Option<String>>,
}

impl RouteIndex {
    pub fn from_upstreams(upstreams: &HashMap<String, Upstream>) -> Self {
        let mut ordered: Vec<(&String, &Upstream)> = upstreams.iter().collect();
        ordered.sort_by_key(|(left, _)| *left);
        Self::from_ordered_routes(ordered.into_iter().enumerate().map(
            |(order, (name, upstream))| {
                IndexedRouteSource {
                    name: name.clone(),
                    method: upstream
                        .route
                        .method
                        .as_deref()
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(|value| value.to_ascii_uppercase()),
                    path_prefix: upstream.route.path_prefix.clone(),
                    path_len: upstream
                        .route
                        .path_prefix
                        .as_ref()
                        .map(|prefix| prefix.len())
                        .unwrap_or(0),
                    host_specific: upstream.route.host.is_some(),
                    method_specific: upstream.route.method.is_some(),
                    host_pattern: upstream
                        .route
                        .host
                        .as_deref()
                        .and_then(parse_configured_host_pattern)
                        .map(RuntimeRouteHostPattern::from),
                    order,
                }
            },
        ))
    }

    pub fn from_runtime_upstreams(upstreams: &HashMap<String, RuntimeUpstream>) -> Self {
        let mut ordered: Vec<(&String, &RuntimeUpstream)> = upstreams.iter().collect();
        ordered.sort_by_key(|(left, _)| *left);
        Self::from_ordered_routes(ordered.into_iter().enumerate().map(
            |(order, (name, upstream))| IndexedRouteSource {
                name: name.clone(),
                method: upstream.route.method.clone(),
                path_prefix: upstream.route.path_prefix.clone(),
                path_len: upstream.route.path_len,
                host_specific: upstream.route.host_specific,
                method_specific: upstream.route.method_specific,
                host_pattern: upstream.route.host_pattern.clone(),
                order,
            },
        ))
    }

    fn from_ordered_routes(routes: impl IntoIterator<Item = IndexedRouteSource>) -> Self {
        let mut host_tries = HashMap::new();
        let mut wildcard_host_tries = HashMap::new();
        let mut default_trie = RouteTrie::default();
        let mut default_max_path_len = 0usize;
        let mut upstream_names = Vec::new();
        let mut upstream_methods = Vec::new();
        for route_source in routes {
            let path_prefix = route_source.path_prefix.as_deref();
            let upstream_idx = upstream_names.len();
            upstream_names.push(route_source.name);
            upstream_methods.push(route_source.method);

            let route = IndexedRoute {
                upstream_idx,
                path_len: route_source.path_len,
                host_specific: route_source.host_specific,
                method_specific: route_source.method_specific,
                order: route_source.order,
            };

            match route_source.host_pattern {
                Some(RuntimeRouteHostPattern::WildcardSuffix(suffix)) => wildcard_host_tries
                    .entry(suffix)
                    .or_insert_with(RouteTrie::default)
                    .insert(path_prefix, route),
                Some(RuntimeRouteHostPattern::Exact(normalized_host)) => host_tries
                    .entry(normalized_host)
                    .or_insert_with(RouteTrie::default)
                    .insert(path_prefix, route),
                None => {
                    default_max_path_len = default_max_path_len.max(route_source.path_len);
                    default_trie.insert(path_prefix, route);
                }
            }
        }

        Self {
            host_tries,
            wildcard_host_tries,
            default_trie,
            default_max_path_len,
            upstream_names,
            upstream_methods,
        }
    }

    pub fn lookup<'a>(&'a self, path: &str, host: Option<&str>) -> Option<&'a str> {
        self.lookup_for_method(path, host, None)
    }

    pub fn lookup_for_method<'a>(
        &'a self,
        path: &str,
        host: Option<&str>,
        method: Option<&str>,
    ) -> Option<&'a str> {
        let host_best = host
            .and_then(normalize_host_for_routing)
            .and_then(|normalized_host| {
                self.lookup_host_candidate(path, normalized_host.as_ref(), method)
            });

        if let Some(best) = host_best
            && best.candidate.route.path_len >= self.default_max_path_len
        {
            return Some(self.upstream_names[best.candidate.route.upstream_idx].as_str());
        }

        let best = prefer_route_candidate(
            self.default_trie
                .longest_prefix(path, method, &self.upstream_methods)
                .map(|route| RouteCandidate {
                    route,
                    host_match_kind: HostMatchKind::Default,
                    wildcard_suffix_len: 0,
                }),
            host_best.map(|value| value.candidate),
        );
        best.map(|candidate| self.upstream_names[candidate.route.upstream_idx].as_str())
    }

    #[cfg(test)]
    pub fn lookup_with_decision<'a>(
        &'a self,
        path: &str,
        host: Option<&str>,
    ) -> Option<RouteDecision<'a>> {
        self.lookup_with_decision_for_method(path, host, None)
    }

    pub fn lookup_with_decision_for_method<'a>(
        &'a self,
        path: &str,
        host: Option<&str>,
        method: Option<&str>,
    ) -> Option<RouteDecision<'a>> {
        let host_best = host
            .and_then(normalize_host_for_routing)
            .and_then(|normalized_host| {
                self.lookup_host_candidate(path, normalized_host.as_ref(), method)
            });

        let default_best = self
            .default_trie
            .longest_prefix_with_reason(path, method, &self.upstream_methods)
            .map(|(route, decision_reason)| HostLookupResult {
                candidate: RouteCandidate {
                    route,
                    host_match_kind: HostMatchKind::Default,
                    wildcard_suffix_len: 0,
                },
                decision_reason,
            });
        if let Some(best) = host_best
            && best.candidate.route.path_len >= self.default_max_path_len
        {
            let fallback_reason = match default_best {
                None => RouteDecisionReason::HostTrieNoDefault,
                Some(default_route) => {
                    match compare_route_candidate(default_route.candidate, best.candidate) {
                        RoutePreference::TakeCandidateHostSpecific => {
                            RouteDecisionReason::HostSpecificTieBreak
                        }
                        RoutePreference::TakeCandidateExactHost => {
                            RouteDecisionReason::ExactHostTieBreak
                        }
                        RoutePreference::TakeCandidateWildcardSpecificity => {
                            RouteDecisionReason::WildcardSpecificityTieBreak
                        }
                        RoutePreference::TakeCandidateMethodSpecific => {
                            RouteDecisionReason::MethodSpecificTieBreak
                        }
                        RoutePreference::TakeCandidateLexicalOrder => {
                            RouteDecisionReason::LexicalTieBreak
                        }
                        _ => RouteDecisionReason::HostPathLongerOrEqual,
                    }
                }
            };
            return Some(RouteDecision {
                upstream: self.upstream_names[best.candidate.route.upstream_idx].as_str(),
                matched_path_len: best.candidate.route.path_len,
                host_specific: best.candidate.route.host_specific,
                method_specific: best.candidate.route.method_specific,
                reason: best.decision_reason.unwrap_or(fallback_reason),
            });
        }

        match (default_best, host_best) {
            (Some(default_route), None) => Some(RouteDecision {
                upstream: self.upstream_names[default_route.candidate.route.upstream_idx].as_str(),
                matched_path_len: default_route.candidate.route.path_len,
                host_specific: default_route.candidate.route.host_specific,
                method_specific: default_route.candidate.route.method_specific,
                reason: default_route
                    .decision_reason
                    .unwrap_or(RouteDecisionReason::DefaultPathLonger),
            }),
            (None, Some(host_route)) => Some(RouteDecision {
                upstream: self.upstream_names[host_route.candidate.route.upstream_idx].as_str(),
                matched_path_len: host_route.candidate.route.path_len,
                host_specific: host_route.candidate.route.host_specific,
                method_specific: host_route.candidate.route.method_specific,
                reason: host_route
                    .decision_reason
                    .unwrap_or(RouteDecisionReason::HostTrieNoDefault),
            }),
            (Some(current), Some(candidate)) => {
                let preference = compare_route_candidate(current.candidate, candidate.candidate);
                let fallback_reason = match preference {
                    RoutePreference::TakeCandidatePathLen => {
                        RouteDecisionReason::HostPathLongerOrEqual
                    }
                    RoutePreference::TakeCandidateHostSpecific => {
                        RouteDecisionReason::HostSpecificTieBreak
                    }
                    RoutePreference::TakeCandidateExactHost => {
                        RouteDecisionReason::ExactHostTieBreak
                    }
                    RoutePreference::TakeCandidateWildcardSpecificity => {
                        RouteDecisionReason::WildcardSpecificityTieBreak
                    }
                    RoutePreference::TakeCandidateMethodSpecific => {
                        RouteDecisionReason::MethodSpecificTieBreak
                    }
                    RoutePreference::TakeCandidateLexicalOrder => {
                        RouteDecisionReason::LexicalTieBreak
                    }
                    RoutePreference::KeepCurrent => RouteDecisionReason::DefaultPathLonger,
                };
                let selected = match preference {
                    RoutePreference::KeepCurrent => current.candidate,
                    _ => candidate.candidate,
                };
                Some(RouteDecision {
                    upstream: self.upstream_names[selected.route.upstream_idx].as_str(),
                    matched_path_len: selected.route.path_len,
                    host_specific: selected.route.host_specific,
                    method_specific: selected.route.method_specific,
                    reason: if selected == candidate.candidate {
                        candidate.decision_reason.unwrap_or(fallback_reason)
                    } else {
                        current.decision_reason.unwrap_or(fallback_reason)
                    },
                })
            }
            (None, None) => None,
        }
    }

    fn lookup_host_candidate(
        &self,
        path: &str,
        normalized_host: &str,
        method: Option<&str>,
    ) -> Option<HostLookupResult> {
        let exact_best = self
            .host_tries
            .get(normalized_host)
            .and_then(|host_trie| {
                host_trie.longest_prefix_with_reason(path, method, &self.upstream_methods)
            })
            .map(|(route, decision_reason)| HostLookupResult {
                candidate: RouteCandidate {
                    route,
                    host_match_kind: HostMatchKind::Exact,
                    wildcard_suffix_len: 0,
                },
                decision_reason,
            });

        let mut wildcard_best: Option<HostLookupResult> = None;
        let mut remaining = normalized_host;
        while let Some(dot_idx) = remaining.find('.') {
            let suffix = &remaining[dot_idx + 1..];
            if suffix.is_empty() {
                break;
            }

            if let Some(trie) = self.wildcard_host_tries.get(suffix) {
                let candidate = trie
                    .longest_prefix_with_reason(path, method, &self.upstream_methods)
                    .map(|(route, decision_reason)| HostLookupResult {
                        candidate: RouteCandidate {
                            route,
                            host_match_kind: HostMatchKind::Wildcard,
                            wildcard_suffix_len: suffix.len(),
                        },
                        decision_reason,
                    });
                wildcard_best = prefer_host_lookup_result(wildcard_best, candidate);
            }
            remaining = suffix;
        }

        prefer_host_lookup_result(wildcard_best, exact_best)
    }
}

struct IndexedRouteSource {
    name: String,
    method: Option<String>,
    path_prefix: Option<String>,
    path_len: usize,
    host_specific: bool,
    method_specific: bool,
    host_pattern: Option<RuntimeRouteHostPattern>,
    order: usize,
}

impl From<ConfiguredHostPattern> for RuntimeRouteHostPattern {
    fn from(value: ConfiguredHostPattern) -> Self {
        match value {
            ConfiguredHostPattern::Exact(host) => Self::Exact(host),
            ConfiguredHostPattern::WildcardSuffix(suffix) => Self::WildcardSuffix(suffix),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use impulse_config::config::{Backend, LoadBalancing, RouteMatch, Upstream};

    use crate::routing::{decision::RouteDecisionReason, index::RouteIndex};

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
                id: "b1".to_string(),
                address: "http://127.0.0.1:7001".to_string(),
                weight: 1,
                health_check: None,
            }],
        }
    }

    #[test]
    fn lookup_prefers_host_specific_route_over_default() {
        let upstreams = HashMap::from([
            ("default".to_string(), upstream("/api", None, None)),
            (
                "payments".to_string(),
                upstream("/api", Some("pay.example.com"), None),
            ),
        ]);
        let index = RouteIndex::from_upstreams(&upstreams);

        assert_eq!(
            index.lookup("/api", Some("pay.example.com")),
            Some("payments")
        );

        let decision = index
            .lookup_with_decision("/api", Some("pay.example.com"))
            .expect("route decision");
        assert_eq!(decision.upstream, "payments");
        assert_eq!(decision.reason, RouteDecisionReason::HostSpecificTieBreak);
    }

    #[test]
    fn lookup_prefers_exact_host_over_wildcard() {
        let upstreams = HashMap::from([
            (
                "wildcard".to_string(),
                upstream("/api", Some("*.example.com"), None),
            ),
            (
                "exact".to_string(),
                upstream("/api", Some("api.example.com"), None),
            ),
        ]);
        let index = RouteIndex::from_upstreams(&upstreams);

        assert_eq!(index.lookup("/api", Some("api.example.com")), Some("exact"));

        let decision = index
            .lookup_with_decision("/api", Some("api.example.com"))
            .expect("route decision");
        assert_eq!(decision.upstream, "exact");
        assert_eq!(decision.reason, RouteDecisionReason::ExactHostTieBreak);
    }

    #[test]
    fn lookup_prefers_more_specific_wildcard_suffix() {
        let upstreams = HashMap::from([
            (
                "broad".to_string(),
                upstream("/api", Some("*.example.com"), None),
            ),
            (
                "narrow".to_string(),
                upstream("/api", Some("*.svc.example.com"), None),
            ),
        ]);
        let index = RouteIndex::from_upstreams(&upstreams);

        assert_eq!(
            index.lookup("/api", Some("edge.svc.example.com")),
            Some("narrow")
        );

        let decision = index
            .lookup_with_decision("/api", Some("edge.svc.example.com"))
            .expect("route decision");
        assert_eq!(decision.upstream, "narrow");
        assert_eq!(
            decision.reason,
            RouteDecisionReason::WildcardSpecificityTieBreak
        );
    }

    #[test]
    fn lookup_for_method_prefers_method_specific_route() {
        let upstreams = HashMap::from([
            ("generic".to_string(), upstream("/transfer", None, None)),
            (
                "post_only".to_string(),
                upstream("/transfer", None, Some("POST")),
            ),
        ]);
        let index = RouteIndex::from_upstreams(&upstreams);

        assert_eq!(
            index.lookup_for_method("/transfer", None, Some("POST")),
            Some("post_only")
        );

        let decision = index
            .lookup_with_decision_for_method("/transfer", None, Some("POST"))
            .expect("route decision");
        assert_eq!(decision.upstream, "post_only");
        assert_eq!(decision.reason, RouteDecisionReason::MethodSpecificTieBreak);
    }

    #[test]
    fn lookup_for_method_preserves_connect_matches_for_websocket_routes() {
        let upstreams = HashMap::from([
            ("get_only".to_string(), upstream("/chat", None, Some("GET"))),
            (
                "connect_only".to_string(),
                upstream("/chat", None, Some("CONNECT")),
            ),
        ]);
        let index = RouteIndex::from_upstreams(&upstreams);

        assert_eq!(
            index.lookup_for_method("/chat/socket", None, Some("CONNECT")),
            Some("connect_only")
        );

        let decision = index
            .lookup_with_decision_for_method("/chat/socket", None, Some("CONNECT"))
            .expect("route decision");
        assert_eq!(decision.upstream, "connect_only");
        assert_eq!(decision.reason, RouteDecisionReason::DefaultPathLonger);
    }

    #[test]
    fn lookup_with_decision_prefers_longer_default_path_when_host_route_is_shorter() {
        let upstreams = HashMap::from([
            (
                "host_short".to_string(),
                upstream("/api", Some("pay.example.com"), None),
            ),
            (
                "default_long".to_string(),
                upstream("/api/v1/payments", None, None),
            ),
        ]);
        let index = RouteIndex::from_upstreams(&upstreams);

        assert_eq!(
            index.lookup("/api/v1/payments", Some("pay.example.com")),
            Some("default_long")
        );

        let decision = index
            .lookup_with_decision("/api/v1/payments", Some("pay.example.com"))
            .expect("route decision");
        assert_eq!(decision.upstream, "default_long");
        assert_eq!(decision.reason, RouteDecisionReason::DefaultPathLonger);
    }
}
