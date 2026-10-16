//! Protocol-neutral contracts shared by ingress adapters and request services.

mod outcome;
mod policy;
mod routing;
mod types;

pub(crate) use policy::{ResolvedRequestPolicy, resolve_policy};
pub(crate) use routing::{RouteResolutionError, resolve_route};
pub(crate) use types::{PipelineRequest, RequestHeaderLookup, ResolvedRouteTarget};
