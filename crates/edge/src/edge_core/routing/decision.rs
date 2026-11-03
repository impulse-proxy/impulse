use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutePreference {
    KeepCurrent,
    TakeCandidatePathLen,
    TakeCandidateHostSpecific,
    TakeCandidateExactHost,
    TakeCandidateWildcardSpecificity,
    TakeCandidateMethodSpecific,
    TakeCandidateLexicalOrder,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteDecisionReason {
    HostTrieNoDefault,
    HostPathLongerOrEqual,
    DefaultPathLonger,
    HostSpecificTieBreak,
    ExactHostTieBreak,
    WildcardSpecificityTieBreak,
    MethodSpecificTieBreak,
    LexicalTieBreak,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteDecision<'a> {
    /// Name of the upstream selected by route matching; auth/policy stays attached to that upstream.
    pub upstream: &'a str,
    pub matched_path_len: usize,
    pub host_specific: bool,
    pub method_specific: bool,
    pub reason: RouteDecisionReason,
}

#[inline(always)]
pub fn route_preference_reason(preference: RoutePreference) -> Option<RouteDecisionReason> {
    match preference {
        RoutePreference::KeepCurrent => None,
        RoutePreference::TakeCandidatePathLen => Some(RouteDecisionReason::HostPathLongerOrEqual),
        RoutePreference::TakeCandidateHostSpecific => {
            Some(RouteDecisionReason::HostSpecificTieBreak)
        }
        RoutePreference::TakeCandidateExactHost => Some(RouteDecisionReason::ExactHostTieBreak),
        RoutePreference::TakeCandidateWildcardSpecificity => {
            Some(RouteDecisionReason::WildcardSpecificityTieBreak)
        }
        RoutePreference::TakeCandidateMethodSpecific => {
            Some(RouteDecisionReason::MethodSpecificTieBreak)
        }
        RoutePreference::TakeCandidateLexicalOrder => Some(RouteDecisionReason::LexicalTieBreak),
    }
}

impl fmt::Display for RouteDecisionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::HostTrieNoDefault => "host-trie-no-default",
            Self::HostPathLongerOrEqual => "host-path-longer-or-equal",
            Self::DefaultPathLonger => "default-path-longer",
            Self::HostSpecificTieBreak => "host-specific-tie-break",
            Self::ExactHostTieBreak => "exact-host-tie-break",
            Self::WildcardSpecificityTieBreak => "wildcard-specificity-tie-break",
            Self::MethodSpecificTieBreak => "method-specific-tie-break",
            Self::LexicalTieBreak => "lexical-tie-break",
        };

        f.write_str(value)
    }
}

#[cfg(test)]
mod tests {
    use super::{RouteDecisionReason, RoutePreference, route_preference_reason};

    #[test]
    fn route_preference_reason_maps_each_preference() {
        assert_eq!(route_preference_reason(RoutePreference::KeepCurrent), None);
        assert_eq!(
            route_preference_reason(RoutePreference::TakeCandidatePathLen),
            Some(RouteDecisionReason::HostPathLongerOrEqual)
        );
        assert_eq!(
            route_preference_reason(RoutePreference::TakeCandidateHostSpecific),
            Some(RouteDecisionReason::HostSpecificTieBreak)
        );
        assert_eq!(
            route_preference_reason(RoutePreference::TakeCandidateExactHost),
            Some(RouteDecisionReason::ExactHostTieBreak)
        );
        assert_eq!(
            route_preference_reason(RoutePreference::TakeCandidateWildcardSpecificity),
            Some(RouteDecisionReason::WildcardSpecificityTieBreak)
        );
        assert_eq!(
            route_preference_reason(RoutePreference::TakeCandidateMethodSpecific),
            Some(RouteDecisionReason::MethodSpecificTieBreak)
        );
        assert_eq!(
            route_preference_reason(RoutePreference::TakeCandidateLexicalOrder),
            Some(RouteDecisionReason::LexicalTieBreak)
        );
    }

    #[test]
    fn route_decision_reason_display_uses_lowercase_hyphenated_tokens() {
        assert_eq!(
            format!("{}", RouteDecisionReason::HostTrieNoDefault),
            "host-trie-no-default"
        );
        assert_eq!(
            format!("{}", RouteDecisionReason::HostPathLongerOrEqual),
            "host-path-longer-or-equal"
        );
        assert_eq!(
            format!("{}", RouteDecisionReason::DefaultPathLonger),
            "default-path-longer"
        );
        assert_eq!(
            format!("{}", RouteDecisionReason::HostSpecificTieBreak),
            "host-specific-tie-break"
        );
        assert_eq!(
            format!("{}", RouteDecisionReason::ExactHostTieBreak),
            "exact-host-tie-break"
        );
        assert_eq!(
            format!("{}", RouteDecisionReason::WildcardSpecificityTieBreak),
            "wildcard-specificity-tie-break"
        );
        assert_eq!(
            format!("{}", RouteDecisionReason::MethodSpecificTieBreak),
            "method-specific-tie-break"
        );
        assert_eq!(
            format!("{}", RouteDecisionReason::LexicalTieBreak),
            "lexical-tie-break"
        );
    }
}
