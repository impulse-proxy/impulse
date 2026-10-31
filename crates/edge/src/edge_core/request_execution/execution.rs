use std::collections::HashMap;

use impulse_config::runtime::RuntimeUpstreamPolicy;

use super::{
    RequestExecutionInput, RequestExecutionResult, RequestExecutionState,
    admission::evaluate_admission, policy::resolve_policy, routing::resolve_route,
};
use crate::{resilience::runtime::RuntimeResilience, routing::index::RouteIndex};

/// Borrowed protocol-neutral request executor for one runtime generation.
pub(crate) struct EdgeRequestService<'a> {
    routing_index: &'a RouteIndex,
    upstream_policies: &'a HashMap<String, RuntimeUpstreamPolicy>,
    resilience: &'a RuntimeResilience,
}

impl<'a> EdgeRequestService<'a> {
    pub(crate) fn new(
        routing_index: &'a RouteIndex,
        upstream_policies: &'a HashMap<String, RuntimeUpstreamPolicy>,
        resilience: &'a RuntimeResilience,
    ) -> Self {
        Self {
            routing_index,
            upstream_policies,
            resilience,
        }
    }

    /// Resolves routing, policy, and admission for a protocol-neutral request.
    pub(crate) fn execute(&self, request: RequestExecutionInput<'_>) -> RequestExecutionResult {
        let route = resolve_route(
            self.routing_index,
            request.method,
            request.path,
            request.authority,
        )?;
        let upstream_policy = self
            .upstream_policies
            .get(route.upstream_name.as_ref())
            .ok_or(super::RouteResolutionError::MissingUpstreamPolicy)?;
        let policy = resolve_policy(upstream_policy);
        let admission = evaluate_admission(
            self.resilience,
            &policy,
            route.upstream_name.as_ref(),
            &request,
        );

        Ok(RequestExecutionState {
            route,
            policy,
            admission,
        })
    }
}
