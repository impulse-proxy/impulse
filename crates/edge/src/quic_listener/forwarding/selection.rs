use std::sync::{Arc, RwLock};

use impulse_config::runtime::RuntimeBackendTlsPolicy;
use impulse_errors::{
    HedgePolicyDecision, HedgePolicyFacts, HedgePrimaryState, PoolError, ProxyError,
    RetryPolicyDecision, RetryPolicyFacts, classify_retryability, evaluate_hedge_policy,
    evaluate_retry_policy,
};
use impulse_lb::{
    alternate_backend::{
        AlternateBackendDecision, AlternateBackendFailureReason, choose_alternate_backend,
    },
    pingora_backend::GenerationSelector,
    upstream_pool::UpstreamPool,
};

use super::{
    super::QUICListener,
    resolve::{BackendSelection, TargetResolutionRequest},
};
use crate::{
    Metrics,
    resilience::{
        circuit_breaker::{CircuitBreakerPermit, CircuitBreakers},
        retry_budget::RetryBudget,
    },
};

/// Selects an eligible backend and builds retry/hedge policy inputs without
/// coupling those decisions to an upstream wire protocol.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ForwardingSelectionService;

pub(crate) const MAX_UPSTREAM_RETRY_ATTEMPTS: u8 = 1;

pub(crate) struct BackendCandidate {
    pub(crate) address: String,
    pub(crate) index: usize,
}

impl ForwardingSelectionService {
    pub(crate) fn select_backend(
        request: &TargetResolutionRequest<'_>,
        upstream_pool: &Arc<RwLock<UpstreamPool>>,
        selector: &GenerationSelector<RuntimeBackendTlsPolicy>,
        generation: u64,
        begin_request: bool,
        metrics: &Metrics,
    ) -> Result<BackendSelection, ProxyError> {
        let (lb_key, backend_lb) = {
            let pool = upstream_pool.read().map_err(|_| {
                metrics
                    .runtime_observations()
                    .inc_pingora_lb_selector_failure();
                ProxyError::Transport("upstream pool lock poisoned".into())
            })?;
            let lb_key = QUICListener::resolve_lb_key_for_runtime_request(
                pool.lb_strategy(),
                pool.lb_key_spec(),
                request,
            )
            .value;
            (lb_key, pool.lb_strategy().canonical_name().to_string())
        };
        let Some(selected) = Self::select_backend_excluding(
            selector,
            upstream_pool,
            generation,
            &lb_key,
            &[],
            begin_request,
            metrics,
        )?
        else {
            return Err(ProxyError::Transport("no healthy servers".into()));
        };
        Ok(BackendSelection {
            backend_addr: selected.address,
            backend_index: selected.index,
            backend_lb,
            lb_key,
        })
    }

    pub(crate) fn select_backend_excluding(
        selector: &GenerationSelector<RuntimeBackendTlsPolicy>,
        pool: &Arc<RwLock<UpstreamPool>>,
        generation: u64,
        key: &str,
        excluded_backend_indices: &[usize],
        begin_request: bool,
        metrics: &Metrics,
    ) -> Result<Option<BackendCandidate>, ProxyError> {
        if selector.generation() != generation {
            metrics
                .runtime_observations()
                .inc_pingora_lb_selector_failure();
            return Err(ProxyError::Transport(format!(
                "selector generation {} does not match runtime generation {generation}",
                selector.generation()
            )));
        }
        if selector.uses_custom_dynamic_selector() {
            return Self::select_custom_dynamic_backend(
                pool,
                key,
                excluded_backend_indices,
                begin_request,
            );
        }
        let pool = pool.read().map_err(|_| {
            metrics
                .runtime_observations()
                .inc_pingora_lb_selector_failure();
            ProxyError::Transport("upstream pool lock poisoned".into())
        })?;
        let Some(selected) = selector.select_excluding(key, excluded_backend_indices) else {
            metrics
                .runtime_observations()
                .inc_pingora_lb_selector_failure();
            return Ok(None);
        };
        if selected.generation() != generation {
            metrics
                .runtime_observations()
                .inc_pingora_lb_selector_failure();
            return Err(ProxyError::Transport(format!(
                "Pingora selector generation {} does not match runtime generation {generation}",
                selected.generation()
            )));
        }
        let index = selected.index();
        let Some(address) = pool.backend_address(index).map(str::to_string) else {
            metrics
                .runtime_observations()
                .inc_pingora_lb_selector_failure();
            return Err(ProxyError::Transport(
                "Pingora selector returned an invalid backend index".into(),
            ));
        };
        if begin_request && !pool.begin_request_if_healthy(index) {
            metrics
                .runtime_observations()
                .inc_pingora_lb_selector_failure();
            return Ok(None);
        }
        metrics.runtime_observations().inc_pingora_lb_selection();
        Ok(Some(BackendCandidate { address, index }))
    }

    fn select_custom_dynamic_backend(
        pool: &Arc<RwLock<UpstreamPool>>,
        key: &str,
        excluded_backend_indices: &[usize],
        begin_request: bool,
    ) -> Result<Option<BackendCandidate>, ProxyError> {
        let mut pool = pool
            .write()
            .map_err(|_| ProxyError::Transport("upstream pool lock poisoned".into()))?;
        let selected = if excluded_backend_indices.is_empty() {
            if begin_request {
                pool.pick(key)
            } else {
                pool.pick_without_begin(key)
            }
        } else {
            match choose_alternate_backend(&pool, excluded_backend_indices, Some(key)) {
                AlternateBackendDecision::Select(choice) => {
                    if begin_request && !pool.begin_request_if_healthy(choice.index) {
                        None
                    } else {
                        Some(choice.index)
                    }
                }
                AlternateBackendDecision::DoNotSelect { .. } => None,
            }
        };
        let Some(index) = selected else {
            return Ok(None);
        };
        let Some(address) = pool.backend_address(index).map(str::to_string) else {
            return Err(ProxyError::Transport(
                "custom selector returned an invalid backend index".into(),
            ));
        };
        Ok(Some(BackendCandidate { address, index }))
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
}

/// Retry and hedge facts derived before dispatch begins.
#[derive(Clone, Copy)]
pub(crate) struct RetryCoordinator {
    method_idempotent: bool,
    bodyless_mode: bool,
    hedge_method_allowed: bool,
    hedge_configured: bool,
    hedge_tunnel_request: bool,
}

impl RetryCoordinator {
    pub(crate) const fn new(
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

    pub(crate) fn retry_after_error(
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
