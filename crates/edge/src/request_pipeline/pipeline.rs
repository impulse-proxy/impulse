use super::{
    PipelineRequest, PipelineResolution, PipelineRoute, admission::evaluate_admission,
    policy::resolve_policy,
};
use crate::resilience::runtime::RuntimeResilience;

/// Resolves policy and admission for a protocol-neutral request and route.
pub(crate) fn evaluate_pipeline<'route>(
    resilience: &RuntimeResilience,
    route: PipelineRoute<'route>,
    request: PipelineRequest<'_>,
) -> PipelineResolution<PipelineRoute<'route>> {
    let policy = resolve_policy(route.upstream_policy);
    let admission = evaluate_admission(resilience, &policy, route.upstream_name, &request);

    PipelineResolution {
        route,
        policy,
        admission,
    }
}
