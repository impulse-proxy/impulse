use std::{net::SocketAddr, sync::Arc};

use impulse_contracts::{
    IngressProtocol, PluginHeaderLookup, PluginHeaderMutation, PluginRejection,
    PluginRejectionReason, RequestDecision, RequestId,
};

use super::policy::ResolvedRequestPolicy;
use crate::routing::decision::RouteDecisionReason;

pub(crate) type RequestHeaderLookup<'a> = dyn Fn(&str) -> Option<String> + Sync + 'a;

/// Protocol-neutral request data supplied to shared edge execution.
pub(crate) struct RequestExecutionInput<'a> {
    pub(crate) method: &'a str,
    pub(crate) path: &'a str,
    pub(crate) authority: Option<&'a str>,
    pub(crate) peer_address: SocketAddr,
}

/// Request metadata required by the shared compiled-plugin path.
pub(crate) struct PluginRequestExecutionInput<'a> {
    pub(crate) request: RequestExecutionInput<'a>,
    pub(crate) request_id: RequestId,
    pub(crate) generation: u64,
    pub(crate) ingress_protocol: IngressProtocol,
    pub(crate) headers: Option<&'a PluginHeaderLookup<'a>>,
    pub(crate) external_auth_headers: Option<&'a http::HeaderMap>,
    pub(crate) has_body: bool,
    pub(crate) body_replayable: bool,
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
    Rejected {
        rejection: PluginRejection,
        observation: PluginTerminalObservation,
    },
    AlreadyExecuted,
}

/// Metadata returned by plugin execution; only the edge completion owner may
/// record it as a terminal request outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PluginTerminalObservation {
    AuthDenied,
    RateLimited,
    QuotaDenied,
    Failed,
}

impl PluginTerminalObservation {
    pub(crate) const fn from_rejection_reason(reason: PluginRejectionReason) -> Self {
        match reason {
            PluginRejectionReason::ApiKeyMissing
            | PluginRejectionReason::ApiKeyInvalid
            | PluginRejectionReason::JwtMissing
            | PluginRejectionReason::JwtInvalid
            | PluginRejectionReason::JwtClaimsRejected
            | PluginRejectionReason::ExternalAuthDenied => Self::AuthDenied,
            PluginRejectionReason::RateLimited => Self::RateLimited,
            PluginRejectionReason::QuotaDenied => Self::QuotaDenied,
            PluginRejectionReason::JwksUnavailable
            | PluginRejectionReason::ExternalAuthUnavailable
            | PluginRejectionReason::QuotaUnavailable => Self::Failed,
        }
    }
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
