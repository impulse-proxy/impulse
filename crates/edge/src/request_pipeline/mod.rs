//! Protocol-neutral contracts shared by ingress adapters and request services.

mod admission;
mod compression;
mod outcome;
mod pipeline;
mod policy;
mod routing;
mod types;

pub(crate) use compression::{
    ResponseCompressionAction, ResponseCompressionBypassReason, ResponseCompressionEvaluation,
    ResponseCompressionInput, ensure_vary_accept_encoding, evaluate_response_compression,
};
pub(crate) use outcome::TerminalOutcomeGuard;
pub(crate) use pipeline::evaluate_pipeline;
pub(crate) use policy::ResolvedRequestPolicy;
pub(crate) use routing::{RouteResolutionError, resolve_route};
pub(crate) use types::{
    PipelineRequest, PipelineResolution, PipelineResult, PipelineRoute, RequestHeaderLookup,
    ResolvedRouteTarget,
};
