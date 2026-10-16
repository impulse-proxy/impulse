use std::sync::{Arc, RwLock};

use impulse_errors::{
    HedgePolicyDecision, HedgePolicyFacts, HedgePrimaryState, PoolError, ProxyError,
    RetryPolicyDecision, RetryPolicyFacts, classify_retryability, evaluate_hedge_policy,
    evaluate_retry_policy,
};
use impulse_lb::{alternate_backend::AlternateBackendFailureReason, upstream_pool::UpstreamPool};
use log::error;

use super::{
    super::QUICListener,
    lb_key::ResolvedLbKey,
    resolve::{BackendSelection, TargetResolutionRequest},
};
use crate::resilience::{
    circuit_breaker::{CircuitBreakerPermit, CircuitBreakers},
    retry_budget::RetryBudget,
};

/// Selects an eligible backend and builds retry/hedge policy inputs without
/// coupling those decisions to an upstream wire protocol.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ForwardingSelectionService;

impl ForwardingSelectionService {
    pub(crate) fn select_backend(
        request: &TargetResolutionRequest<'_>,
        upstream_pool: &Arc<RwLock<UpstreamPool>>,
        begin_request: bool,
    ) -> Result<BackendSelection, ProxyError> {
        let mut pool = upstream_pool
            .write()
            .map_err(|_| ProxyError::Transport("upstream pool lock poisoned".into()))?;
        if pool.is_empty() {
            return Err(ProxyError::Transport("no servers in upstream".into()));
        }

        let ResolvedLbKey {
            value: lb_key,
            source: _lb_key_source,
        } = QUICListener::resolve_lb_key_for_runtime_request(
            pool.lb_strategy(),
            pool.lb_key_spec(),
            request,
        );
        let backend_lb = pool.lb_strategy().canonical_name().to_string();
        let backend_index = if begin_request {
            pool.pick(lb_key.as_str())
        } else {
            pool.pick_without_begin(lb_key.as_str())
        }
        .ok_or_else(|| Self::no_healthy_servers_error(&pool))?;
        let backend_addr = pool
            .backend_address(backend_index)
            .map(str::to_string)
            .ok_or_else(|| ProxyError::Transport("invalid server address".into()))?;

        Ok(BackendSelection {
            backend_addr,
            backend_index,
            backend_lb,
        })
    }

    pub(super) fn allow_backend_request<'a>(
        circuit_breakers: &'a CircuitBreakers,
        backend: &str,
    ) -> Result<CircuitBreakerPermit<'a>, ProxyError> {
        circuit_breakers
            .allow_request(backend)
            .ok_or_else(|| ProxyError::Pool(PoolError::CircuitOpen(backend.to_string())))
    }

    pub(super) fn retry_budget_available(
        primary_err: &ProxyError,
        route_name: &str,
        retry_budget: &RetryBudget,
    ) -> bool {
        matches!(primary_err, ProxyError::Pool(PoolError::CircuitOpen(_)))
            || retry_budget.allow_retry(route_name).is_ok()
    }

    fn no_healthy_servers_error(pool: &UpstreamPool) -> ProxyError {
        let summary = pool.membership_summary();
        error!(
            "no healthy backends available: {}/{} backends healthy",
            summary.healthy_backends, summary.total_backends
        );
        ProxyError::Transport("no healthy servers".into())
    }
}

/// Retry and hedge facts derived before dispatch begins.
#[derive(Clone, Copy)]
pub(super) struct RetryHedgePolicyInputs {
    method_idempotent: bool,
    bodyless_mode: bool,
    hedge_method_allowed: bool,
    hedge_configured: bool,
    hedge_tunnel_request: bool,
}

impl RetryHedgePolicyInputs {
    pub(super) const fn new(
        method_idempotent: bool,
        bodyless_mode: bool,
        hedge_method_allowed: bool,
        hedge_configured: bool,
        hedge_tunnel_request: bool,
    ) -> Self {
        Self {
            method_idempotent,
            bodyless_mode,
            hedge_method_allowed,
            hedge_configured,
            hedge_tunnel_request,
        }
    }

    pub(super) fn hedge_before_delay(
        self,
        alternate_backend_available: bool,
        alternate_backend_failure: Option<AlternateBackendFailureReason>,
    ) -> HedgePolicyDecision {
        evaluate_hedge_policy(HedgePolicyFacts {
            hedging_configured: self.hedge_configured,
            method_allowed: self.hedge_method_allowed,
            request_body_replayable: self.bodyless_mode,
            tunnel_request: self.hedge_tunnel_request,
            alternate_backend_available,
            alternate_backend_failure,
            budget_available: false,
            primary_state: HedgePrimaryState::InFlightBeforeDelay,
        })
    }

    pub(super) fn hedge_after_delay(self, budget_available: bool) -> HedgePolicyDecision {
        evaluate_hedge_policy(HedgePolicyFacts {
            hedging_configured: self.hedge_configured,
            method_allowed: self.hedge_method_allowed,
            request_body_replayable: self.bodyless_mode,
            tunnel_request: self.hedge_tunnel_request,
            alternate_backend_available: true,
            alternate_backend_failure: None,
            budget_available,
            primary_state: HedgePrimaryState::InFlightAfterDelay,
        })
    }

    pub(super) fn retry_after_error(
        self,
        primary_err: &ProxyError,
        retry_count: u8,
        max_attempts: u8,
        budget_available: bool,
        alternate_backend_available: bool,
        alternate_backend_failure: Option<AlternateBackendFailureReason>,
    ) -> RetryPolicyDecision {
        evaluate_retry_policy(RetryPolicyFacts {
            retryability: classify_retryability(primary_err),
            method_idempotent: self.method_idempotent,
            request_body_replayable: self.bodyless_mode,
            attempt_count: retry_count,
            max_attempts,
            budget_available,
            alternate_backend_available,
            alternate_backend_failure,
        })
    }
}
