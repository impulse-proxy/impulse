//! Protocol-neutral contracts shared by ingress adapters and request services.

mod admission;
mod outcome;
mod pipeline;
mod policy;
mod routing;
mod types;

pub(crate) use outcome::TerminalOutcomeGuard;
pub(crate) use pipeline::evaluate_pipeline;
pub(crate) use policy::ResolvedRequestPolicy;
#[cfg(test)]
pub(crate) use policy::resolve_policy;
pub(crate) use routing::{RouteResolutionError, resolve_route};
pub(crate) use types::{
    PipelineRequest, PipelineResolution, PipelineResult, PipelineRoute, RequestHeaderLookup,
    ResolvedRouteTarget,
};
