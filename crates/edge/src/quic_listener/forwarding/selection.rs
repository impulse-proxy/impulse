use std::sync::{Arc, RwLock};

use impulse_config::runtime::RuntimeBackendTlsPolicy;
use impulse_errors::{PoolError, ProxyError};
use impulse_lb::{
    BackendSelectionInput,
    alternate_backend::{AlternateBackendDecision, choose_alternate_backend},
    pingora_backend::GenerationSelector,
    upstream_pool::UpstreamPool,
};

use super::{
    super::QUICListener,
    resolve::{BackendSelection, TargetResolutionRequest},
};
use crate::{
    Metrics,
    resilience::circuit_breaker::{CircuitBreakerPermit, CircuitBreakers},
};

/// Selects an eligible backend without coupling the choice to an upstream wire protocol.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ForwardingSelectionService;

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
            BackendSelectionInput::new(generation, &lb_key, &[], begin_request),
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
        input: BackendSelectionInput<'_>,
        metrics: &Metrics,
    ) -> Result<Option<BackendCandidate>, ProxyError> {
        if selector.generation() != input.generation() {
            metrics
                .runtime_observations()
                .inc_pingora_lb_selector_failure();
            return Err(ProxyError::Transport(format!(
                "selector generation {} does not match runtime generation {}",
                selector.generation(),
                input.generation()
            )));
        }
        if selector.uses_custom_dynamic_selector() {
            return Self::select_custom_dynamic_backend(pool, input);
        }
        let pool = pool.read().map_err(|_| {
            metrics
                .runtime_observations()
                .inc_pingora_lb_selector_failure();
            ProxyError::Transport("upstream pool lock poisoned".into())
        })?;
        let Some(selected) =
            selector.select_excluding(input.request_key(), input.excluded_backend_indices())
        else {
            metrics
                .runtime_observations()
                .inc_pingora_lb_selector_failure();
            return Ok(None);
        };
        if selected.generation() != input.generation() {
            metrics
                .runtime_observations()
                .inc_pingora_lb_selector_failure();
            return Err(ProxyError::Transport(format!(
                "Pingora selector generation {} does not match runtime generation {generation}",
                selected.generation(),
                generation = input.generation()
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
        if input.begin_request() && !pool.begin_request_if_healthy(index) {
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
        input: BackendSelectionInput<'_>,
    ) -> Result<Option<BackendCandidate>, ProxyError> {
        let mut pool = pool
            .write()
            .map_err(|_| ProxyError::Transport("upstream pool lock poisoned".into()))?;
        let selected = if input.excluded_backend_indices().is_empty() {
            if input.begin_request() {
                pool.pick(input.request_key())
            } else {
                pool.pick_without_begin(input.request_key())
            }
        } else {
            match choose_alternate_backend(
                &pool,
                input.excluded_backend_indices(),
                Some(input.request_key()),
            ) {
                AlternateBackendDecision::Select(choice) => {
                    if input.begin_request() && !pool.begin_request_if_healthy(choice.index) {
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
}
