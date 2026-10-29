use std::collections::HashMap;

use impulse_config::runtime::RuntimeUpstreamPolicy;

use super::{
    RequestExecutionInput, RequestExecutionResult, RequestExecutionState,
    admission::evaluate_admission, policy::resolve_policy, routing::resolve_route,
};
use crate::{resilience::runtime::RuntimeResilience, routing::index::RouteIndex};

/// Resolves routing, policy, and admission for a protocol-neutral request.
pub(crate) fn execute_request(
    routing_index: &RouteIndex,
    upstream_policies: &HashMap<String, RuntimeUpstreamPolicy>,
    resilience: &RuntimeResilience,
    request: RequestExecutionInput<'_>,
) -> RequestExecutionResult {
    let route = resolve_route(
        routing_index,
        request.method,
        request.path,
        request.authority,
    )?;
    let upstream_policy = upstream_policies
        .get(route.upstream_name.as_ref())
        .ok_or(super::RouteResolutionError::MissingUpstreamPolicy)?;
    let policy = resolve_policy(upstream_policy);
    let admission = evaluate_admission(resilience, &policy, route.upstream_name.as_ref(), &request);

    Ok(RequestExecutionState {
        route,
        policy,
        admission,
    })
}
