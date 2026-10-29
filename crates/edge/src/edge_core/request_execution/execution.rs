use super::{
    RequestExecutionInput, RequestExecutionRoute, RequestExecutionState,
    admission::evaluate_admission, policy::resolve_policy,
};
use crate::resilience::runtime::RuntimeResilience;

/// Resolves policy and admission for a protocol-neutral request and route.
pub(crate) fn execute_request<'route>(
    resilience: &RuntimeResilience,
    route: RequestExecutionRoute<'route>,
    request: RequestExecutionInput<'_>,
) -> RequestExecutionState<RequestExecutionRoute<'route>> {
    let policy = resolve_policy(route.upstream_policy);
    let admission = evaluate_admission(resilience, &policy, route.upstream_name, &request);

    RequestExecutionState {
        route,
        policy,
        admission,
    }
}
