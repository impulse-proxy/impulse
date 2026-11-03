use std::collections::HashMap;

use impulse_config::runtime::RuntimeUpstreamPolicy;
use impulse_plugins::CompiledGenerationPluginPlans;

use super::{
    RequestExecutionInput, RequestExecutionResult, RequestExecutionState,
    admission::evaluate_admission, policy::resolve_policy, routing::resolve_route,
};
use crate::{resilience::runtime::RuntimeResilience, routing::index::RouteIndex};

/// Borrowed protocol-neutral request executor for one runtime generation.
pub(crate) struct EdgeRequestService<'a> {
    routing_index: &'a RouteIndex,
    upstream_policies: &'a HashMap<String, RuntimeUpstreamPolicy>,
    plugin_plans: &'a CompiledGenerationPluginPlans,
    resilience: &'a RuntimeResilience,
}

impl<'a> EdgeRequestService<'a> {
    pub(crate) fn new(
        routing_index: &'a RouteIndex,
        upstream_policies: &'a HashMap<String, RuntimeUpstreamPolicy>,
        plugin_plans: &'a CompiledGenerationPluginPlans,
        resilience: &'a RuntimeResilience,
    ) -> Self {
        Self {
            routing_index,
            upstream_policies,
            plugin_plans,
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
        let plugin_plan = self
            .plugin_plans
            .upstream_plan(route.upstream_name.as_ref())
            .ok_or(super::RouteResolutionError::MissingUpstreamPluginPlan)?;
        let policy = resolve_policy(upstream_policy, plugin_plan);
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

impl impulse_http3_ingress::Http3RequestService for EdgeRequestService<'_> {
    type Output = RequestExecutionState<super::ResolvedRouteTarget>;
    type Error = super::RouteResolutionError;

    fn execute_http3(
        &self,
        request: impulse_http3_ingress::Http3RequestExecutionInput<'_>,
    ) -> Result<Self::Output, Self::Error> {
        self.execute(RequestExecutionInput {
            method: request.method,
            path: request.path,
            authority: request.authority,
            peer_address: request.peer_address,
            headers: request.headers,
        })
    }
}
