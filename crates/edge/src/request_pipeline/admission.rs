use crate::{
    quic_listener::admission::{AdmissionPolicyDecision, evaluate_forwarding_pre_admission_policy},
    request_pipeline::{PipelineRequest, ResolvedRequestPolicy},
    resilience::runtime::RuntimeResilience,
};

/// Evaluates admission for a resolved request using the active resilience state.
pub(super) fn evaluate_admission(
    resilience: &RuntimeResilience,
    policy: &ResolvedRequestPolicy,
    route: &str,
    request: &PipelineRequest<'_>,
) -> AdmissionPolicyDecision {
    evaluate_forwarding_pre_admission_policy(
        &policy.local_auth_policy,
        request.headers,
        &resilience.brownout,
        resilience.adaptive_admission.inflight_percent(),
        route,
        request.method,
        request.path,
        request.authority,
        request.peer_address,
        resilience.shed_retry_after_seconds,
        &resilience.scoped_rate_limits,
    )
}
