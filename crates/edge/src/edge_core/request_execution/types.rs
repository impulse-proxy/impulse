use std::{net::SocketAddr, sync::Arc};

use impulse_contracts::RequestDecision;

use super::{policy::ResolvedRequestPolicy, routing::RouteResolutionError};
use crate::routing::decision::RouteDecisionReason;

pub(crate) type RequestHeaderLookup<'a> = dyn Fn(&str) -> Option<String> + Sync + 'a;

/// Protocol-neutral request data supplied to shared edge execution.
pub(crate) struct RequestExecutionInput<'a> {
    pub(crate) method: &'a str,
    pub(crate) path: &'a str,
    pub(crate) authority: Option<&'a str>,
    pub(crate) peer_address: SocketAddr,
    pub(crate) headers: Option<&'a RequestHeaderLookup<'a>>,
}

pub(crate) type RequestExecutionResult =
    Result<RequestExecutionState<ResolvedRouteTarget>, RouteResolutionError>;

/// Protocol-neutral execution state paired with its resolved route.
pub(crate) struct RequestExecutionState<Route> {
    pub(crate) route: Route,
    pub(crate) policy: ResolvedRequestPolicy,
    pub(crate) admission: RequestDecision,
}

/// The route selected by the shared routing service before backend selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedRouteTarget {
    pub(crate) upstream_name: Arc<str>,
    pub(crate) matched_path_len: usize,
    pub(crate) host_specific: bool,
    pub(crate) method_specific: bool,
    pub(crate) reason: RouteDecisionReason,
}
