//! Protocol-neutral request execution shared by ingress adapters.

mod admission;
mod compression;
mod execution;
mod policy;
mod routing;
mod types;

pub(crate) use admission::QuotaRejectedDecision;
pub(crate) use compression::{ResponseCompressionAction, apply_gzip_response_headers};
pub(crate) use execution::EdgeRequestService;
pub(crate) use policy::ResolvedRequestPolicy;
pub(crate) use routing::RouteResolutionError;
#[cfg(test)]
pub(crate) use routing::resolve_route;
pub(crate) use types::{
    PluginRequestExecutionInput, PluginRequestExecutionOutcome, PluginRequestExecutionState,
    PluginTerminalObservation, RequestExecutionInput, RequestHeaderLookup, ResolvedRouteTarget,
};
