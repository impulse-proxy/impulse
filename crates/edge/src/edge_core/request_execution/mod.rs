//! Protocol-neutral request execution shared by ingress adapters.

mod admission;
mod compression;
mod execution;
mod outcome;
mod policy;
mod routing;
mod types;

pub(crate) use compression::{
    ResponseCompressionAction, ResponseCompressionInput, ResponseCompressionPolicyInput,
    apply_gzip_response_headers, ensure_vary_accept_encoding, evaluate_response_compression,
};
pub(crate) use execution::execute_request;
pub(crate) use outcome::TerminalOutcomeGuard;
pub(crate) use policy::ResolvedRequestPolicy;
pub(crate) use routing::RouteResolutionError;
#[cfg(test)]
pub(crate) use routing::resolve_route;
pub(crate) use types::{
    RequestExecutionInput, RequestExecutionResult, RequestExecutionState, RequestHeaderLookup,
    ResolvedRouteTarget,
};
