use super::resolve::ForwardTargetResolution;
use crate::{
    request_pipeline::{
        PipelineRequest, PipelineResolution, PipelineResult, evaluate_admission, resolve_policy,
    },
    resilience::runtime::RuntimeResilience,
};

/// Shared route-policy-admission pipeline used by protocol ingress adapters.
///
/// Protocol adapters supply their route/selection result and retain ownership
/// of parsing, response writing, and connection lifecycle state.
#[derive(Clone, Copy)]
pub(in crate::quic_listener) struct ForwardingRequestPipeline<'a> {
    resilience: &'a RuntimeResilience,
}

#[derive(Clone, Copy)]
pub(in crate::quic_listener) struct PipelineRoute<'a> {
    upstream_name: &'a str,
    upstream_policy: &'a impulse_config::runtime::RuntimeUpstreamPolicy,
}

impl<'a> PipelineRoute<'a> {
    pub(in crate::quic_listener) const fn new(
        upstream_name: &'a str,
        upstream_policy: &'a impulse_config::runtime::RuntimeUpstreamPolicy,
    ) -> Self {
        Self {
            upstream_name,
            upstream_policy,
        }
    }
}

impl<'a> ForwardingRequestPipeline<'a> {
    pub(in crate::quic_listener) const fn new(resilience: &'a RuntimeResilience) -> Self {
        Self { resilience }
    }

    pub(super) fn resolve(
        self,
        target: PipelineResult<ForwardTargetResolution>,
        request: PipelineRequest<'_>,
    ) -> PipelineResult<ForwardTargetResolution> {
        let target = target?;
        let evaluation = self.evaluate(
            PipelineRoute::new(&target.upstream_name, &target.upstream_policy),
            request,
        );

        Ok(PipelineResolution {
            route: target,
            policy: evaluation.policy,
            admission: evaluation.admission,
        })
    }

    pub(in crate::quic_listener) fn evaluate<'route>(
        self,
        route: PipelineRoute<'route>,
        request: PipelineRequest<'_>,
    ) -> PipelineResolution<PipelineRoute<'route>> {
        let policy = resolve_policy(route.upstream_policy);
        let admission = evaluate_admission(self.resilience, &policy, route.upstream_name, &request);

        PipelineResolution {
            route,
            policy,
            admission,
        }
    }
}
