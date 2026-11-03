use crate::routing::decision::RouteDecisionReason;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexedRoute {
    pub upstream_idx: usize,
    pub path_len: usize,
    pub host_specific: bool,
    pub method_specific: bool,
    pub order: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum HostMatchKind {
    Default,
    Wildcard,
    Exact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteCandidate {
    pub route: IndexedRoute,
    pub host_match_kind: HostMatchKind,
    pub wildcard_suffix_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostLookupResult {
    pub candidate: RouteCandidate,
    pub decision_reason: Option<RouteDecisionReason>,
}
