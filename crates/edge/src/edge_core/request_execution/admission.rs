use http::StatusCode;
use impulse_contracts::{BoundedRejectionResponse, PluginRejection, RequestDecision};
use impulse_policy::evaluate_brownout_admission;

use crate::resilience::{
    quota::{QuotaDecision, QuotaDenyReason},
    runtime::RuntimeResilience,
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
    pub(crate) fn from_quota_decision(decision: QuotaDecision) -> Option<Self> {
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

    pub(crate) fn as_plugin_rejection(&self) -> PluginRejection {
        if self.status == StatusCode::TOO_MANY_REQUESTS {
            PluginRejection::quota_denied(self.retry_after_seconds, self.body)
        } else {
            PluginRejection::quota_unavailable(self.body)
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

/// Evaluates admission for a resolved request using the active resilience state.
pub(super) fn evaluate_admission(resilience: &RuntimeResilience, route: &str) -> RequestDecision {
    let brownout = evaluate_core_overload_admission(resilience, route);
    if brownout != RequestDecision::AdmitReady {
        return brownout;
    }

    RequestDecision::AdmitReady
}

pub(super) fn evaluate_core_overload_admission(
    resilience: &RuntimeResilience,
    route: &str,
) -> RequestDecision {
    evaluate_brownout_admission(
        &resilience.brownout,
        resilience.adaptive_admission.inflight_percent(),
        route,
        resilience.shed_retry_after_seconds,
    )
}
