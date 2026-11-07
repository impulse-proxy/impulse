//! Protocol-neutral request execution shared by ingress adapters.

mod admission;
mod execution;
mod policy;
mod routing;
mod types;

#[cfg(feature = "quota")]
pub(crate) use admission::{QuotaRejectedDecision, execute_compiled_quota_plugin};
pub(crate) use execution::EdgeRequestService;
#[cfg(feature = "external-auth")]
pub(crate) use execution::execute_compiled_external_auth;
pub(crate) use policy::ResolvedRequestPolicy;
pub(crate) use routing::RouteResolutionError;
#[cfg(test)]
pub(crate) use routing::resolve_route;
pub(crate) use types::{
    PluginRequestExecutionInput, PluginRequestExecutionOutcome, PluginRequestExecutionState,
    PluginTerminalObservation, RequestExecutionInput, RequestHeaderLookup, ResolvedRouteTarget,
};
