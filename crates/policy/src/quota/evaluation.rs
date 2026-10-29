use super::*;

pub async fn evaluate_admission_quota(
    runtime: &QuotaRuntime,
    backend: &dyn DistributedQuotaCounterBackend,
    context: &QuotaIdentityContext<'_>,
) -> QuotaDecision {
    if !runtime.enabled {
        return QuotaDecision::NotApplied;
    }

    let Some(route) = context.route else {
        return QuotaDecision::NotApplied;
    };

    let mut outcome = QuotaDecision::NotApplied;
    let mut shadow_denial: Option<QuotaDecision> = None;

    for policy in runtime
        .policies
        .iter()
        .filter(|policy| policy.applies_to_route(route))
    {
        match evaluate_quota_policy(runtime, backend, context, policy).await {
            decision @ (QuotaDecision::Denied(_) | QuotaDecision::FailedClosed(_)) => {
                return decision;
            }
            decision @ QuotaDecision::ShadowDenied(_) => {
                shadow_denial.get_or_insert(decision);
            }
            decision @ (QuotaDecision::Allowed(_) | QuotaDecision::FailedOpen(_)) => {
                if !matches!(outcome, QuotaDecision::Allowed(_)) {
                    outcome = decision;
                }
            }
            QuotaDecision::NotApplied => {}
        }
    }

    shadow_denial.unwrap_or(outcome)
}

async fn evaluate_quota_policy(
    runtime: &QuotaRuntime,
    backend: &dyn DistributedQuotaCounterBackend,
    context: &QuotaIdentityContext<'_>,
    policy: &QuotaPolicyRuntime,
) -> QuotaDecision {
    let composite_key = match policy.composite_key(context) {
        Ok(key) => key,
        Err(rejection) => {
            let decision = quota_rejection_decision(
                runtime.enforcement,
                QuotaDenial {
                    policy_name: rejection.policy_name,
                    reason: rejection.reason,
                    retry_after_seconds: None,
                    counter: None,
                },
            );
            observe_quota_policy_outcome(
                runtime,
                Some(policy),
                context,
                &decision,
                false,
                None,
                None,
            );
            return decision;
        }
    };

    let backend_mode = runtime.backend.backend_kind();
    let (decision, backend_observed, backend_mode, backend_error_detail) = match backend
        .evaluate(policy.counter_request(composite_key))
        .await
    {
        Ok(outcome) => match outcome.decision {
            QuotaCounterEvaluationDecision::Allowed => (
                QuotaDecision::Allowed(QuotaAllowance {
                    policy_name: outcome.matched_policy,
                    counter: Some(outcome.counter),
                }),
                true,
                outcome.backend_metadata.backend_kind,
                None,
            ),
            QuotaCounterEvaluationDecision::Denied(reason) => (
                quota_rejection_decision(
                    runtime.enforcement,
                    QuotaDenial {
                        policy_name: outcome.matched_policy,
                        reason,
                        retry_after_seconds: quota_retry_after_seconds(reason, &outcome.counter),
                        counter: Some(outcome.counter),
                    },
                ),
                true,
                outcome.backend_metadata.backend_kind,
                None,
            ),
        },
        Err(error) => {
            let deny_reason = error.deny_reason();
            let error_detail = error.detail.clone();
            let decision = match runtime.backend_failure_policy {
                QuotaBackendFailurePolicy::FailOpen => {
                    QuotaDecision::FailedOpen(QuotaBackendFailure {
                        policy_name: error.policy_name.or_else(|| Some(policy.name.clone())),
                        reason: deny_reason,
                    })
                }
                QuotaBackendFailurePolicy::FailClosed => {
                    QuotaDecision::FailedClosed(QuotaBackendFailure {
                        policy_name: error.policy_name.or_else(|| Some(policy.name.clone())),
                        reason: deny_reason,
                    })
                }
            };
            (decision, true, backend_mode.to_string(), error_detail)
        }
    };

    observe_quota_policy_outcome(
        runtime,
        Some(policy),
        context,
        &decision,
        backend_observed,
        Some(backend_mode.as_str()),
        backend_error_detail,
    );
    decision
}
