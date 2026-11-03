use super::*;

impl QuotaDenyReason {
    pub fn slug(self) -> &'static str {
        match self {
            Self::BurstQuotaExhausted => "burst_quota_exhausted",
            Self::SustainedQuotaExhausted => "sustained_quota_exhausted",
            Self::SelectorIdentityMissing => "selector_identity_missing",
            Self::SelectorIdentityInvalid => "selector_identity_invalid",
            Self::BackendTimeout => "backend_timeout",
            Self::BackendUnavailable => "backend_unavailable",
            Self::BackendError => "backend_error",
        }
    }

    pub fn from_slug(value: &str) -> Option<Self> {
        match value {
            "burst_quota_exhausted" => Some(Self::BurstQuotaExhausted),
            "sustained_quota_exhausted" => Some(Self::SustainedQuotaExhausted),
            "selector_identity_missing" => Some(Self::SelectorIdentityMissing),
            "selector_identity_invalid" => Some(Self::SelectorIdentityInvalid),
            "backend_timeout" => Some(Self::BackendTimeout),
            "backend_unavailable" => Some(Self::BackendUnavailable),
            "backend_error" => Some(Self::BackendError),
            _ => None,
        }
    }
}

pub(super) fn local_fallback_backend_mode(
    primary_backend_kind: &str,
    reason: QuotaDenyReason,
) -> String {
    format!(
        "{}{}{}",
        primary_backend_kind,
        LOCAL_FALLBACK_BACKEND_SEPARATOR,
        reason.slug()
    )
}

impl QuotaCounterBackendError {
    pub fn deny_reason(&self) -> QuotaDenyReason {
        match self.kind {
            QuotaCounterBackendErrorKind::Timeout => QuotaDenyReason::BackendTimeout,
            QuotaCounterBackendErrorKind::Unavailable => QuotaDenyReason::BackendUnavailable,
            QuotaCounterBackendErrorKind::Error => QuotaDenyReason::BackendError,
        }
    }
}

pub(super) fn should_attempt_local_fallback(error: &QuotaCounterBackendError) -> bool {
    matches!(
        error.kind,
        QuotaCounterBackendErrorKind::Timeout | QuotaCounterBackendErrorKind::Unavailable
    )
}

pub(super) fn combine_primary_and_fallback_error(
    primary: QuotaCounterBackendError,
    fallback: QuotaCounterBackendError,
) -> QuotaCounterBackendError {
    QuotaCounterBackendError {
        policy_name: fallback.policy_name.or(primary.policy_name),
        composite_key: fallback.composite_key.or(primary.composite_key),
        kind: fallback.kind,
        detail: Some(match (primary.detail, fallback.detail) {
            (Some(primary_detail), Some(fallback_detail)) => format!(
                "primary quota backend failed: {primary_detail}; local fallback failed: {fallback_detail}"
            ),
            (Some(primary_detail), None) => {
                format!("primary quota backend failed: {primary_detail}; local fallback failed")
            }
            (None, Some(fallback_detail)) => {
                format!("local fallback failed after primary backend outage: {fallback_detail}")
            }
            (None, None) => "primary quota backend and local fallback both failed".to_string(),
        }),
    }
}

impl QuotaDecision {
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Denied(_) | Self::FailedClosed(_))
    }

    pub fn deny_reason(&self) -> Option<QuotaDenyReason> {
        match self {
            Self::ShadowDenied(denial) | Self::Denied(denial) => Some(denial.reason),
            Self::FailedOpen(failure) | Self::FailedClosed(failure) => Some(failure.reason),
            Self::NotApplied | Self::Allowed(_) => None,
        }
    }
}

pub(super) fn quota_rejection_decision(
    enforcement: QuotaEnforcementMode,
    denial: QuotaDenial,
) -> QuotaDecision {
    match enforcement {
        QuotaEnforcementMode::Shadow => QuotaDecision::ShadowDenied(denial),
        QuotaEnforcementMode::Enforce => QuotaDecision::Denied(denial),
    }
}

pub(super) fn quota_retry_after_seconds(
    reason: QuotaDenyReason,
    counter: &QuotaCounterResult,
) -> Option<u32> {
    let reset_after = match reason {
        QuotaDenyReason::BurstQuotaExhausted => {
            counter.burst.as_ref().and_then(|window| window.reset_after)
        }
        QuotaDenyReason::SustainedQuotaExhausted => counter
            .sustained
            .as_ref()
            .and_then(|window| window.reset_after),
        QuotaDenyReason::SelectorIdentityMissing
        | QuotaDenyReason::SelectorIdentityInvalid
        | QuotaDenyReason::BackendTimeout
        | QuotaDenyReason::BackendUnavailable
        | QuotaDenyReason::BackendError => None,
    }?;

    let rounded = reset_after
        .as_secs()
        .saturating_add(u64::from(reset_after.subsec_nanos() > 0));
    Some(rounded.max(1).min(u64::from(u32::MAX)) as u32)
}
