use impulse_contracts::AlternateBackendFailureReason;
use impulse_errors::{
    HedgePolicyDecision, HedgePolicyFacts, HedgePrimaryState, PoolError, ProxyError,
    RetryPolicyDecision, RetryPolicyDenialReason, RetryPolicyFacts, classify_retryability,
    evaluate_hedge_policy, evaluate_retry_policy,
};

use crate::resilience::retry_budget::RetryBudget;

const MAX_UPSTREAM_RETRY_ATTEMPTS: u8 = 1;

/// Coordinates retry and hedge policy without owning upstream connection attempts.
#[derive(Clone, Copy)]
pub(crate) struct RetryCoordinator {
    method_idempotent: bool,
    body_replayable: bool,
    hedge_method_allowed: bool,
    hedge_configured: bool,
    hedge_tunnel_request: bool,
}

impl RetryCoordinator {
    pub(crate) const fn new(
        method_idempotent: bool,
        body_replayable: bool,
        hedge_method_allowed: bool,
        hedge_configured: bool,
        hedge_tunnel_request: bool,
    ) -> Self {
        Self {
            method_idempotent,
            body_replayable,
            hedge_method_allowed,
            hedge_configured,
            hedge_tunnel_request,
        }
    }

    pub(crate) fn hedge_before_delay(
        self,
        alternate_backend_available: bool,
        alternate_backend_failure: Option<AlternateBackendFailureReason>,
    ) -> HedgePolicyDecision {
        evaluate_hedge_policy(HedgePolicyFacts {
            hedging_configured: self.hedge_configured,
            method_allowed: self.hedge_method_allowed,
            request_body_replayable: self.body_replayable,
            tunnel_request: self.hedge_tunnel_request,
            alternate_backend_available,
            alternate_backend_failure,
            budget_available: false,
            primary_state: HedgePrimaryState::InFlightBeforeDelay,
        })
    }

    pub(crate) fn hedge_after_delay(self, budget_available: bool) -> HedgePolicyDecision {
        evaluate_hedge_policy(HedgePolicyFacts {
            hedging_configured: self.hedge_configured,
            method_allowed: self.hedge_method_allowed,
            request_body_replayable: self.body_replayable,
            tunnel_request: self.hedge_tunnel_request,
            alternate_backend_available: true,
            alternate_backend_failure: None,
            budget_available,
            primary_state: HedgePrimaryState::InFlightAfterDelay,
        })
    }

    pub(crate) fn retry_after_error(
        self,
        primary_error: &ProxyError,
        retry_count: u8,
        route_name: &str,
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
            || retry_budget.allow_retry(route_name).is_ok()
        {
            decision
        } else {
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::BudgetDenied),
            }
        }
    }
}
