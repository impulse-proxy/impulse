use impulse_contracts::{AlternateBackendFailureReason, RetryPolicyDenialReason, RouteId};
use impulse_errors::{
    PoolError, ProxyError, RetryPolicyDecision, RetryPolicyFacts, classify_retryability,
    evaluate_retry_policy,
};

use crate::resilience::retry_budget::RetryBudget;

const MAX_UPSTREAM_RETRY_ATTEMPTS: u8 = 1;

/// Coordinates retry policy without owning upstream connection attempts.
#[derive(Clone, Copy)]
pub(crate) struct RetryCoordinator {
    method_idempotent: bool,
    body_replayable: bool,
}

impl RetryCoordinator {
    pub(crate) const fn new(method_idempotent: bool, body_replayable: bool) -> Self {
        Self {
            method_idempotent,
            body_replayable,
        }
    }

    pub(crate) fn retry_after_error(
        self,
        primary_error: &ProxyError,
        retry_count: u8,
        route_id: RouteId,
        retry_budget: &RetryBudget,
        alternate_backend_available: bool,
        alternate_backend_failure: Option<AlternateBackendFailureReason>,
    ) -> RetryPolicyDecision {
        let facts = |budget_available| RetryPolicyFacts {
            retryability: classify_retryability(primary_error),
            method_idempotent: self.method_idempotent,
            request_body_replayable: self.body_replayable,
            attempt_count: retry_count,
            max_attempts: MAX_UPSTREAM_RETRY_ATTEMPTS,
            budget_available,
            alternate_backend_available,
            alternate_backend_failure,
        };
        let decision = evaluate_retry_policy(facts(true));
        if !matches!(decision, RetryPolicyDecision::Retry { .. }) {
            return decision;
        }
        if matches!(primary_error, ProxyError::Pool(PoolError::CircuitOpen(_)))
            || retry_budget.allow_retry(route_id).is_ok()
        {
            decision
        } else {
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::BudgetDenied),
            }
        }
    }
}
