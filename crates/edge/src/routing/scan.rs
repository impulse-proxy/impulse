use std::collections::HashMap;

use impulse_config::config::Upstream;

use crate::routing::{
    host::{
        ConfiguredHostPatternRef, normalize_host_for_routing, parse_configured_host_pattern_ref,
    },
    route::HostMatchKind,
    util::{canonical_uri_path, prefix_boundary_matches},
};

pub fn scan_lookup<'a>(
    upstreams: &'a HashMap<String, Upstream>,
    path: &str,
    host: Option<&str>,
) -> Option<&'a str> {
    scan_lookup_for_method(upstreams, path, host, None)
}

pub fn scan_lookup_for_method<'a>(
    upstreams: &'a HashMap<String, Upstream>,
    path: &str,
    host: Option<&str>,
    method: Option<&str>,
) -> Option<&'a str> {
    let path = canonical_uri_path(path);
    let path_bytes = path.as_bytes();
    let normalized_request_host = host.and_then(normalize_host_for_routing);
    let mut best_match: Option<(&str, usize, bool, HostMatchKind, usize, bool)> = None;

    for (upstream_name, upstream) in upstreams {
        let has_method_match = match (
            upstream.route.method.as_deref().map(str::trim),
            method.map(str::trim),
        ) {
            (Some(route_method), Some(request_method)) => {
                route_method.eq_ignore_ascii_case(request_method)
            }
            (Some(_), None) => true,
            (None, _) => true,
        };
        if !has_method_match {
            continue;
        }

        let (has_host_match, host_match_kind, wildcard_suffix_len) =
            match (&upstream.route.host, normalized_request_host.as_deref()) {
                (None, _) => (true, HostMatchKind::Default, 0usize),
                (Some(_), None) => (false, HostMatchKind::Default, 0usize),
                (Some(route_host), Some(request_host)) => {
                    match parse_configured_host_pattern_ref(route_host) {
                        Some(ConfiguredHostPatternRef::Exact(route_host_exact)) => (
                            route_host_exact.eq_ignore_ascii_case(request_host),
                            HostMatchKind::Exact,
                            0,
                        ),
                        Some(ConfiguredHostPatternRef::WildcardSuffix(suffix)) => {
                            let suffix_start = request_host.len().saturating_sub(suffix.len());
                            (
                                request_host.len() > suffix.len() + 1
                                    && request_host
                                        .get(suffix_start..)
                                        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
                                    && request_host.as_bytes()[suffix_start - 1] == b'.',
                                HostMatchKind::Wildcard,
                                suffix.len(),
                            )
                        }
                        None => (false, HostMatchKind::Default, 0usize),
                    }
                }
            };

        let path_match_len = match &upstream.route.path_prefix {
            Some(path_prefix) => {
                let prefix = path_prefix.as_bytes();
                if prefix.len() > path_bytes.len() {
                    continue;
                }
                // Fast reject for same-length-ish prefixes before full starts_with.
                if let Some((&last, idx)) = prefix.last().zip(prefix.len().checked_sub(1))
                    && path_bytes[idx] != last
                {
                    continue;
                }
                if !path_bytes.starts_with(prefix) {
                    continue;
                }
                if !prefix_boundary_matches(&path, prefix.len()) {
                    continue;
                }
                prefix.len()
            }
            None => 0,
        };

        if !has_host_match {
            continue;
        }
        let host_specific = upstream.route.host.is_some();
        let method_specific = upstream
            .route
            .method
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());

        match best_match {
            Some((
                best_name,
                best_len,
                best_host_specific,
                best_host_match_kind,
                best_wildcard_suffix_len,
                best_method_specific,
            )) => {
                if path_match_len > best_len
                    || (path_match_len == best_len && host_specific && !best_host_specific)
                    || (path_match_len == best_len
                        && host_specific == best_host_specific
                        && host_match_kind > best_host_match_kind)
                    || (path_match_len == best_len
                        && host_specific == best_host_specific
                        && host_match_kind == HostMatchKind::Wildcard
                        && best_host_match_kind == HostMatchKind::Wildcard
                        && wildcard_suffix_len > best_wildcard_suffix_len)
                    || (path_match_len == best_len
                        && host_specific == best_host_specific
                        && host_match_kind == best_host_match_kind
                        && method_specific
                        && !best_method_specific)
                    || (path_match_len == best_len
                        && host_specific == best_host_specific
                        && host_match_kind == best_host_match_kind
                        && method_specific == best_method_specific
                        && upstream_name.as_str() < best_name)
                {
                    best_match = Some((
                        upstream_name.as_str(),
                        path_match_len,
                        host_specific,
                        host_match_kind,
                        wildcard_suffix_len,
                        method_specific,
                    ));
                }
            }
            None => {
                best_match = Some((
                    upstream_name.as_str(),
                    path_match_len,
                    host_specific,
                    host_match_kind,
                    wildcard_suffix_len,
                    method_specific,
                ));
            }
        }
    }

    best_match.map(|(name, _, _, _, _, _)| name)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use impulse_config::config::{Backend, LoadBalancing, RouteMatch, Upstream};

    use crate::routing::{
        index::RouteIndex,
        scan::{scan_lookup, scan_lookup_for_method},
    };

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
    fn scan_lookup_matches_route_index_lookup_for_reference_inputs() {
        let upstreams = HashMap::from([
            ("default".to_string(), upstream("/api", None, None)),
            (
                "exact".to_string(),
                upstream("/api", Some("pay.example.com"), None),
            ),
            (
                "wildcard".to_string(),
                upstream("/api/private", Some("*.example.com"), None),
            ),
            (
                "method".to_string(),
                upstream("/transfer", None, Some("POST")),
            ),
        ]);
        let index = RouteIndex::from_upstreams(&upstreams);

        let cases = [
            ("/api", Some("pay.example.com")),
            ("/api/private", Some("team.example.com")),
            ("/api/other", Some("unknown.example.net")),
            ("/unmatched", Some("pay.example.com")),
        ];

        for (path, host) in cases {
            assert_eq!(
                scan_lookup(&upstreams, path, host),
                index.lookup(path, host)
            );
        }
    }

    #[test]
    fn scan_lookup_for_method_matches_route_index_lookup_for_method() {
        let upstreams = HashMap::from([
            ("generic".to_string(), upstream("/transfer", None, None)),
            (
                "post_only".to_string(),
                upstream("/transfer", None, Some("POST")),
            ),
        ]);
        let index = RouteIndex::from_upstreams(&upstreams);

        let cases = [
            ("/transfer", None, Some("POST")),
            ("/transfer", None, Some("GET")),
            ("/transfer", None, None),
        ];

        for (path, host, method) in cases {
            assert_eq!(
                scan_lookup_for_method(&upstreams, path, host, method),
                index.lookup_for_method(path, host, method)
            );
        }
    }
}
