use std::{net::SocketAddr, sync::Arc};

use impulse_config::runtime::RuntimeUpstreamPolicy;
use impulse_errors::ProxyError;

use super::{outcome::TerminalOutcomeGuard, policy::ResolvedRequestPolicy};
use crate::{
    quic_listener::AdmissionPolicyDecision, routing::decision::RouteDecisionReason,
    runtime::activation::GenerationId,
};

pub(crate) type RequestHeaderLookup<'a> = dyn Fn(&str) -> Option<String> + 'a;

/// Protocol-neutral request data supplied to the shared policy pipeline.
pub(crate) struct PipelineRequest<'a> {
    pub(crate) method: &'a str,
    pub(crate) path: &'a str,
    pub(crate) authority: Option<&'a str>,
    pub(crate) peer_address: SocketAddr,
    pub(crate) headers: Option<&'a RequestHeaderLookup<'a>>,
    pub(crate) runtime_generation: GenerationId,
    pub(crate) terminal_outcome: TerminalOutcomeGuard,
}

#[derive(Clone, Copy)]
pub(crate) struct PipelineRoute<'a> {
    pub(super) upstream_name: &'a str,
    pub(super) upstream_policy: &'a RuntimeUpstreamPolicy,
}

impl<'a> PipelineRoute<'a> {
    pub(crate) const fn new(
        upstream_name: &'a str,
        upstream_policy: &'a RuntimeUpstreamPolicy,
    ) -> Self {
        Self {
            upstream_name,
            upstream_policy,
        }
    }
}

pub(crate) type PipelineResult<Route> = Result<PipelineResolution<Route>, ProxyError>;

/// Protocol-neutral policy evaluation paired with its resolved route.
pub(crate) struct PipelineResolution<Route> {
    pub(crate) route: Route,
    pub(crate) policy: ResolvedRequestPolicy,
    pub(crate) admission: AdmissionPolicyDecision,
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
