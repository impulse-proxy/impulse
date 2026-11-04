use std::{net::SocketAddr, sync::Arc};

use impulse_contracts::{
    IngressProtocol, PluginHeaderLookup, PluginHeaderMutation, PluginRejection, RequestDecision,
    RequestId,
};

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

/// Request metadata required by the shared compiled-plugin path.
pub(crate) struct PluginRequestExecutionInput<'a> {
    pub(crate) request: RequestExecutionInput<'a>,
    pub(crate) request_id: RequestId,
    pub(crate) generation: u64,
    pub(crate) ingress_protocol: IngressProtocol,
    pub(crate) headers: Option<&'a PluginHeaderLookup<'a>>,
    pub(crate) has_body: bool,
    pub(crate) body_replayable: bool,
}

pub(crate) type RequestExecutionResult =
    Result<RequestExecutionState<ResolvedRouteTarget>, RouteResolutionError>;

/// Protocol-neutral execution state paired with its resolved route.
pub(crate) struct RequestExecutionState<Route> {
    pub(crate) route: Route,
    pub(crate) policy: ResolvedRequestPolicy,
    pub(crate) admission: RequestDecision,
}

pub(crate) struct PluginRequestExecutionState<Route> {
    pub(crate) route: Route,
    pub(crate) policy: ResolvedRequestPolicy,
    pub(crate) outcome: PluginRequestExecutionOutcome,
}

pub(crate) enum PluginRequestExecutionOutcome {
    Admitted {
        admission: RequestDecision,
        mutations: Vec<PluginHeaderMutation>,
    },
    Rejected(PluginRejection),
    AlreadyExecuted,
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
