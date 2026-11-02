use http::StatusCode;
use impulse_contracts::{BoundedRejectionResponse, RequestDecision};
use impulse_policy::evaluate_brownout_admission;

use crate::{
    edge_core::request_execution::{RequestExecutionInput, ResolvedRequestPolicy},
    quic_listener::{evaluate_local_auth_policy, evaluate_scoped_rate_limit_policy},
    resilience::{
        quota::{QuotaDecision, QuotaDenyReason, QuotaIdentityContext, evaluate_admission_quota},
        runtime::RuntimeResilience,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QuotaRejectedDecision {
    pub(crate) policy_name: String,
    pub(crate) reason: QuotaDenyReason,
    pub(crate) status: StatusCode,
    pub(crate) body: &'static [u8],
    pub(crate) retry_after_seconds: Option<u32>,
}

impl QuotaRejectedDecision {
    fn from_quota_decision(decision: QuotaDecision) -> Option<Self> {
        match decision {
            QuotaDecision::Denied(denial) | QuotaDecision::ShadowDenied(denial) => Some(Self {
                policy_name: denial.policy_name,
                reason: denial.reason,
                status: StatusCode::TOO_MANY_REQUESTS,
                body: quota_response_body(denial.reason),
                retry_after_seconds: denial.retry_after_seconds.map(|value| value.max(1)),
            }),
            QuotaDecision::FailedClosed(failure) => Some(Self {
                policy_name: failure.policy_name.unwrap_or_else(|| "unknown".to_string()),
                reason: failure.reason,
                status: StatusCode::SERVICE_UNAVAILABLE,
                body: quota_response_body(failure.reason),
                retry_after_seconds: None,
            }),
            QuotaDecision::NotApplied
            | QuotaDecision::Allowed(_)
            | QuotaDecision::FailedOpen(_) => None,
        }
    }

    pub(crate) fn as_response(&self) -> BoundedRejectionResponse {
        BoundedRejectionResponse {
            status: self.status,
            body: self.body,
            www_authenticate: None,
            retry_after_seconds: self.retry_after_seconds,
        }
    }
}

fn quota_response_body(reason: QuotaDenyReason) -> &'static [u8] {
    match reason {
        QuotaDenyReason::BurstQuotaExhausted => b"burst quota exhausted\n",
        QuotaDenyReason::SustainedQuotaExhausted => b"sustained quota exhausted\n",
        QuotaDenyReason::SelectorIdentityMissing => b"quota selector identity missing\n",
        QuotaDenyReason::SelectorIdentityInvalid => b"quota selector identity invalid\n",
        QuotaDenyReason::BackendTimeout => b"quota backend timed out\n",
        QuotaDenyReason::BackendUnavailable => b"quota backend unavailable\n",
        QuotaDenyReason::BackendError => b"quota backend error\n",
    }
}

pub(crate) async fn evaluate_post_auth_quota_policy(
    resilience: &RuntimeResilience,
    quota_context: &QuotaIdentityContext<'_>,
) -> Option<QuotaRejectedDecision> {
    let backend = resilience.quota_backend.as_ref()?;
    match evaluate_admission_quota(resilience.quota.as_ref(), backend.as_ref(), quota_context).await
    {
        QuotaDecision::NotApplied | QuotaDecision::Allowed(_) | QuotaDecision::FailedOpen(_) => {
            None
        }
        QuotaDecision::ShadowDenied(denial) => {
            log::debug!(
                "quota shadow deny observed: policy={} reason={}",
                denial.policy_name,
                denial.reason.slug()
            );
            None
        }
        denied => QuotaRejectedDecision::from_quota_decision(denied),
    }
}

/// Evaluates admission for a resolved request using the active resilience state.
pub(super) fn evaluate_admission(
    resilience: &RuntimeResilience,
    policy: &ResolvedRequestPolicy,
    route: &str,
    request: &RequestExecutionInput<'_>,
) -> RequestDecision {
    let auth = evaluate_local_auth_policy(&policy.local_auth_policy, request.headers);
    if auth != RequestDecision::AdmitReady {
        return auth;
    }

    let brownout = evaluate_brownout_admission(
        &resilience.brownout,
        resilience.adaptive_admission.inflight_percent(),
        route,
        resilience.shed_retry_after_seconds,
    );
    if brownout != RequestDecision::AdmitReady {
        return brownout;
    }

    evaluate_scoped_rate_limit_policy(
        &resilience.scoped_rate_limits,
        route,
        request.method,
        request.path,
        request.authority,
        request.peer_address,
        request.headers,
    )
}
