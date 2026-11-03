use crate::routing::{
    decision::{RouteDecisionReason, RoutePreference, route_preference_reason},
    route::{HostLookupResult, HostMatchKind, IndexedRoute, RouteCandidate},
    util::prefix_boundary_matches,
};

#[inline(always)]
fn compare_route(current: IndexedRoute, candidate: IndexedRoute) -> RoutePreference {
    if candidate.path_len > current.path_len {
        RoutePreference::TakeCandidatePathLen
    } else if candidate.path_len == current.path_len
        && candidate.host_specific
        && !current.host_specific
    {
        RoutePreference::TakeCandidateHostSpecific
    } else if candidate.path_len == current.path_len
        && candidate.host_specific == current.host_specific
        && candidate.method_specific
        && !current.method_specific
    {
        RoutePreference::TakeCandidateMethodSpecific
    } else if candidate.path_len == current.path_len
        && candidate.host_specific == current.host_specific
        && candidate.method_specific == current.method_specific
        && candidate.order < current.order
    {
        RoutePreference::TakeCandidateLexicalOrder
    } else {
        RoutePreference::KeepCurrent
    }
}

#[inline(always)]
pub fn compare_route_candidate(
    current: RouteCandidate,
    candidate: RouteCandidate,
) -> RoutePreference {
    let wildcard_specificity_equal = candidate.host_match_kind != HostMatchKind::Wildcard
        || current.host_match_kind != HostMatchKind::Wildcard
        || candidate.wildcard_suffix_len == current.wildcard_suffix_len;

    if candidate.route.path_len > current.route.path_len {
        RoutePreference::TakeCandidatePathLen
    } else if candidate.route.path_len == current.route.path_len
        && candidate.route.host_specific
        && !current.route.host_specific
    {
        RoutePreference::TakeCandidateHostSpecific
    } else if candidate.route.path_len == current.route.path_len
        && candidate.host_match_kind > current.host_match_kind
    {
        RoutePreference::TakeCandidateExactHost
    } else if candidate.route.path_len == current.route.path_len
        && candidate.host_match_kind == HostMatchKind::Wildcard
        && current.host_match_kind == HostMatchKind::Wildcard
        && candidate.wildcard_suffix_len > current.wildcard_suffix_len
    {
        RoutePreference::TakeCandidateWildcardSpecificity
    } else if candidate.route.path_len == current.route.path_len
        && candidate.host_match_kind == current.host_match_kind
        && wildcard_specificity_equal
        && candidate.route.method_specific
        && !current.route.method_specific
    {
        RoutePreference::TakeCandidateMethodSpecific
    } else if candidate.route.path_len == current.route.path_len
        && candidate.host_match_kind == current.host_match_kind
        && wildcard_specificity_equal
        && candidate.route.method_specific == current.route.method_specific
        && candidate.route.order < current.route.order
    {
        RoutePreference::TakeCandidateLexicalOrder
    } else {
        RoutePreference::KeepCurrent
    }
}

#[inline(always)]
pub fn prefer_route_candidate(
    current: Option<RouteCandidate>,
    candidate: Option<RouteCandidate>,
) -> Option<RouteCandidate> {
    match (current, candidate) {
        (None, None) => None,
        (Some(route), None) | (None, Some(route)) => Some(route),
        (Some(current), Some(candidate)) => match compare_route_candidate(current, candidate) {
            RoutePreference::KeepCurrent => Some(current),
            RoutePreference::TakeCandidatePathLen
            | RoutePreference::TakeCandidateHostSpecific
            | RoutePreference::TakeCandidateExactHost
            | RoutePreference::TakeCandidateWildcardSpecificity
            | RoutePreference::TakeCandidateMethodSpecific
            | RoutePreference::TakeCandidateLexicalOrder => Some(candidate),
        },
    }
}

#[inline(always)]
pub fn prefer_host_lookup_result(
    current: Option<HostLookupResult>,
    candidate: Option<HostLookupResult>,
) -> Option<HostLookupResult> {
    match (current, candidate) {
        (None, None) => None,
        (Some(route), None) => Some(route),
        (None, Some(candidate)) => Some(candidate),
        (Some(current), Some(candidate)) => {
            match compare_route_candidate(current.candidate, candidate.candidate) {
                RoutePreference::KeepCurrent => {
                    let decision_reason = current
                        .decision_reason
                        .or(candidate.decision_reason)
                        .or_else(|| {
                            route_preference_reason(compare_route_candidate(
                                candidate.candidate,
                                current.candidate,
                            ))
                        });
                    Some(HostLookupResult {
                        candidate: current.candidate,
                        decision_reason,
                    })
                }
                preference => Some(HostLookupResult {
                    candidate: candidate.candidate,
                    decision_reason: candidate
                        .decision_reason
                        .or_else(|| route_preference_reason(preference)),
                }),
            }
        }
    }
}

fn route_matches_method(
    route: IndexedRoute,
    method: Option<&str>,
    upstream_methods: &[Option<String>],
) -> bool {
    let Some(method) = method else {
        return true;
    };
    match upstream_methods
        .get(route.upstream_idx)
        .and_then(|value| value.as_deref())
    {
        Some(expected) => expected.eq_ignore_ascii_case(method),
        None => true,
    }
}

pub fn best_matching_route_with_reason(
    routes: &[IndexedRoute],
    path: &str,
    method: Option<&str>,
    upstream_methods: &[Option<String>],
    current: Option<(IndexedRoute, Option<RouteDecisionReason>)>,
) -> Option<(IndexedRoute, Option<RouteDecisionReason>)> {
    let mut best = current;
    for route in routes.iter().copied() {
        if !prefix_boundary_matches(path, route.path_len) {
            continue;
        }
        if !route_matches_method(route, method, upstream_methods) {
            continue;
        }
        best = match best {
            None => Some((route, None)),
            Some((current_route, current_reason)) => match compare_route(current_route, route) {
                RoutePreference::KeepCurrent => Some((
                    current_route,
                    current_reason
                        .or_else(|| route_preference_reason(compare_route(route, current_route))),
                )),
                preference => Some((route, route_preference_reason(preference))),
            },
        };
    }
    best
}

#[cfg(test)]
mod tests {
    use crate::routing::{
        decision::{RouteDecisionReason, RoutePreference},
        matcher::{compare_route_candidate, prefer_host_lookup_result, prefer_route_candidate},
        route::{HostLookupResult, HostMatchKind, IndexedRoute, RouteCandidate},
    };

    fn indexed_route(
        upstream_idx: usize,
        path_len: usize,
        host_specific: bool,
        method_specific: bool,
        order: usize,
    ) -> IndexedRoute {
        IndexedRoute {
            upstream_idx,
            path_len,
            host_specific,
            method_specific,
            order,
        }
    }

    fn candidate(
        upstream_idx: usize,
        path_len: usize,
        host_specific: bool,
        host_match_kind: HostMatchKind,
        wildcard_suffix_len: usize,
        method_specific: bool,
        order: usize,
    ) -> RouteCandidate {
        RouteCandidate {
            route: indexed_route(
                upstream_idx,
                path_len,
                host_specific,
                method_specific,
                order,
            ),
            host_match_kind,
            wildcard_suffix_len,
        }
    }

    #[test]
    fn compare_route_candidate_prefers_longer_path() {
        let current = candidate(0, 4, false, HostMatchKind::Default, 0, false, 0);
        let candidate = candidate(1, 7, false, HostMatchKind::Default, 0, false, 1);

        assert_eq!(
            compare_route_candidate(current, candidate),
            RoutePreference::TakeCandidatePathLen
        );
    }

    #[test]
    fn compare_route_candidate_prefers_host_specific_route() {
        let current = candidate(0, 4, false, HostMatchKind::Default, 0, false, 0);
        let candidate = candidate(1, 4, true, HostMatchKind::Wildcard, 11, false, 1);

        assert_eq!(
            compare_route_candidate(current, candidate),
            RoutePreference::TakeCandidateHostSpecific
        );
    }

    #[test]
    fn compare_route_candidate_prefers_exact_host_over_wildcard() {
        let current = candidate(0, 4, true, HostMatchKind::Wildcard, 11, false, 0);
        let candidate = candidate(1, 4, true, HostMatchKind::Exact, 0, false, 1);

        assert_eq!(
            compare_route_candidate(current, candidate),
            RoutePreference::TakeCandidateExactHost
        );
    }

    #[test]
    fn compare_route_candidate_prefers_more_specific_wildcard_suffix() {
        let current = candidate(0, 4, true, HostMatchKind::Wildcard, 11, false, 0);
        let candidate = candidate(1, 4, true, HostMatchKind::Wildcard, 15, false, 1);

        assert_eq!(
            compare_route_candidate(current, candidate),
            RoutePreference::TakeCandidateWildcardSpecificity
        );
    }

    #[test]
    fn compare_route_candidate_prefers_method_specific_route() {
        let current = candidate(0, 4, true, HostMatchKind::Exact, 0, false, 0);
        let candidate = candidate(1, 4, true, HostMatchKind::Exact, 0, true, 1);

        assert_eq!(
            compare_route_candidate(current, candidate),
            RoutePreference::TakeCandidateMethodSpecific
        );
    }

    #[test]
    fn compare_route_candidate_prefers_lexical_order_on_full_tie() {
        let current = candidate(0, 4, true, HostMatchKind::Exact, 0, true, 2);
        let candidate = candidate(1, 4, true, HostMatchKind::Exact, 0, true, 1);

        assert_eq!(
            compare_route_candidate(current, candidate),
            RoutePreference::TakeCandidateLexicalOrder
        );
    }

    #[test]
    fn prefer_route_candidate_returns_preferred_candidate() {
        let current = candidate(0, 4, false, HostMatchKind::Default, 0, false, 0);
        let better = candidate(1, 7, false, HostMatchKind::Default, 0, false, 1);

        assert_eq!(
            prefer_route_candidate(Some(current), Some(better)),
            Some(better)
        );
    }

    #[test]
    fn prefer_host_lookup_result_carries_tiebreak_reason() {
        let current = HostLookupResult {
            candidate: candidate(0, 4, true, HostMatchKind::Wildcard, 11, false, 0),
            decision_reason: None,
        };
        let better = HostLookupResult {
            candidate: candidate(1, 4, true, HostMatchKind::Exact, 0, false, 1),
            decision_reason: None,
        };

        assert_eq!(
            prefer_host_lookup_result(Some(current), Some(better)),
            Some(HostLookupResult {
                candidate: better.candidate,
                decision_reason: Some(RouteDecisionReason::ExactHostTieBreak),
            })
        );
    }
}
