use std::sync::{Arc, RwLock};

use impulse_config::{backend_endpoint::BackendEndpoint, runtime::RuntimeBackendTlsPolicy};
use impulse_contracts::BackendId;
use impulse_errors::{PoolError, ProxyError, RequestFailure};
use impulse_lb::{
    BackendSelectionInput,
    alternate_backend::{AlternateBackendDecision, choose_alternate_backend_with_exclusion},
    pingora_backend::GenerationSelector,
    upstream_pool::UpstreamPool,
};

use super::{
    super::Http3Service,
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
    pub(crate) id: BackendId,
    pub(crate) address: String,
    pub(crate) index: usize,
    pub(crate) transport_identity: BackendEndpoint,
}

fn transport_identity_for_backend(
    id: BackendId,
    address: &str,
    identities: &[BackendEndpoint],
) -> Option<BackendEndpoint> {
    identities.get(id.get() as usize).cloned().or_else(|| {
        #[cfg(test)]
        {
            return BackendEndpoint::parse(address).ok();
        }
        #[cfg(not(test))]
        {
            let _ = address;
            None
        }
    })
}

impl ForwardingSelectionService {
    pub(crate) fn select_backend(
        request: &TargetResolutionRequest<'_>,
        upstream_pool: &Arc<RwLock<UpstreamPool>>,
        selector: &GenerationSelector<RuntimeBackendTlsPolicy>,
        backend_transport_identities: &[BackendEndpoint],
        generation: u64,
        begin_request: bool,
        worker_slot: usize,
        metrics: &Metrics,
    ) -> Result<BackendSelection, ProxyError> {
        let (lb_key, backend_lb) = {
            let pool = upstream_pool.read().map_err(|_| {
                metrics
                    .runtime_observations()
                    .inc_pingora_lb_selector_failure();
                ProxyError::RequestTransport(RequestFailure::UpstreamPoolLockPoisoned)
            })?;
            let lb_key = Http3Service::resolve_lb_key_for_runtime_request(
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
            backend_transport_identities,
            BackendSelectionInput::new(generation, &lb_key, &[], begin_request),
            worker_slot,
            metrics,
        )?
        else {
            return Err(ProxyError::RequestTransport(
                RequestFailure::NoHealthyServers,
            ));
        };
        Ok(BackendSelection {
            backend_id: selected.id,
            backend_addr: selected.address,
            backend_index: selected.index,
            transport_identity: selected.transport_identity,
            backend_lb,
            lb_key,
        })
    }

    pub(crate) fn select_backend_excluding(
        selector: &GenerationSelector<RuntimeBackendTlsPolicy>,
        pool: &Arc<RwLock<UpstreamPool>>,
        backend_transport_identities: &[BackendEndpoint],
        input: BackendSelectionInput<'_>,
        worker_slot: usize,
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
            return Self::select_custom_dynamic_backend(
                selector,
                pool,
                backend_transport_identities,
                input,
            );
        }
        let pool = pool.read().map_err(|_| {
            metrics
                .runtime_observations()
                .inc_pingora_lb_selector_failure();
            ProxyError::RequestTransport(RequestFailure::UpstreamPoolLockPoisoned)
        })?;
        let Some(selected) = selector.select_excluding_for_worker(
            input.request_key(),
            input.excluded_backend_ids(),
            worker_slot,
        ) else {
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
        let id = selected.runtime_id();
        let Some(address) = pool.backend_address(index).map(str::to_string) else {
            metrics
                .runtime_observations()
                .inc_pingora_lb_selector_failure();
            return Err(ProxyError::RequestTransport(
                RequestFailure::InvalidBackendIndex,
            ));
        };
        let Some(transport_identity) =
            transport_identity_for_backend(id, &address, backend_transport_identities)
        else {
            return Err(ProxyError::RequestTransport(
                RequestFailure::UnknownBackendTransportIdentity,
            ));
        };
        if input.begin_request() && !pool.begin_request_if_healthy(index) {
            metrics
                .runtime_observations()
                .inc_pingora_lb_selector_failure();
            return Ok(None);
        }
        metrics.runtime_observations().inc_pingora_lb_selection();
        Ok(Some(BackendCandidate {
            id,
            address,
            index,
            transport_identity,
        }))
    }

    fn select_custom_dynamic_backend(
        selector: &GenerationSelector<RuntimeBackendTlsPolicy>,
        pool: &Arc<RwLock<UpstreamPool>>,
        backend_transport_identities: &[BackendEndpoint],
        input: BackendSelectionInput<'_>,
    ) -> Result<Option<BackendCandidate>, ProxyError> {
        let mut pool = pool
            .write()
            .map_err(|_| ProxyError::RequestTransport(RequestFailure::UpstreamPoolLockPoisoned))?;
        let selected = if input.excluded_backend_ids().is_empty() {
            if input.begin_request() {
                pool.pick(input.request_key())
            } else {
                pool.pick_without_begin(input.request_key())
            }
        } else {
            match choose_alternate_backend_with_exclusion(
                &pool,
                |index| {
                    selector
                        .custom_backend_runtime_id(index)
                        .is_some_and(|id| input.excluded_backend_ids().contains(&id))
                },
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
        let Some(id) = selector.custom_backend_runtime_id(index) else {
            return Err(ProxyError::RequestTransport(
                RequestFailure::InvalidBackendIndex,
            ));
        };
        let Some(address) = pool.backend_address(index).map(str::to_string) else {
            return Err(ProxyError::RequestTransport(
                RequestFailure::InvalidBackendIndex,
            ));
        };
        let Some(transport_identity) =
            transport_identity_for_backend(id, &address, backend_transport_identities)
        else {
            return Err(ProxyError::RequestTransport(
                RequestFailure::UnknownBackendTransportIdentity,
            ));
        };
        Ok(Some(BackendCandidate {
            id,
            address,
            index,
            transport_identity,
        }))
    }

    pub(super) fn allow_backend_request<'a>(
        circuit_breakers: &'a CircuitBreakers,
        backend_id: BackendId,
        backend_addr: &str,
    ) -> Result<CircuitBreakerPermit<'a>, ProxyError> {
        circuit_breakers
            .allow_request(backend_id)
            .ok_or_else(|| ProxyError::Pool(PoolError::CircuitOpen(backend_addr.to_string())))
    }
}
