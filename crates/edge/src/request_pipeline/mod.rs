//! Protocol-neutral contracts shared by ingress adapters and request services.

mod outcome;
mod policy;
mod routing;
mod types;

pub(crate) use policy::{RequestPolicyService, ResolvedRequestPolicy};
pub(crate) use routing::{RouteResolutionError, RouteResolutionService};
pub(crate) use types::{PipelineRequest, RequestHeaderLookup, ResolvedRouteTarget};
