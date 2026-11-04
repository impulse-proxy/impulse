//! Protocol-neutral request execution shared by ingress adapters.

mod admission;
mod compression;
mod execution;
mod policy;
mod routing;
mod types;

pub(crate) use admission::{QuotaRejectedDecision, evaluate_post_auth_quota_policy};
pub(crate) use compression::{
    ResponseCompressionAction, ResponseCompressionPolicyInput, apply_gzip_response_headers,
};
pub(crate) use execution::EdgeRequestService;
pub(crate) use policy::ResolvedRequestPolicy;
pub(crate) use routing::RouteResolutionError;
#[cfg(test)]
pub(crate) use routing::resolve_route;
pub(crate) use types::{
    PluginRequestExecutionInput, PluginRequestExecutionOutcome, PluginRequestExecutionState,
    RequestExecutionInput, RequestExecutionResult, RequestExecutionState, RequestHeaderLookup,
    ResolvedRouteTarget,
};
