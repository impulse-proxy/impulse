use crate::{
    request_pipeline::{PipelineRequest, PipelineResolution, PipelineRoute, evaluate_pipeline},
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

impl<'a> ForwardingRequestPipeline<'a> {
    pub(in crate::quic_listener) const fn new(resilience: &'a RuntimeResilience) -> Self {
        Self { resilience }
    }

    pub(in crate::quic_listener) fn evaluate<'route>(
        self,
        route: PipelineRoute<'route>,
        request: PipelineRequest<'_>,
    ) -> PipelineResolution<PipelineRoute<'route>> {
        evaluate_pipeline(self.resilience, route, request)
    }
}
