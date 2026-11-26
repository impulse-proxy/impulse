use impulse_config::{backend_endpoint::BackendEndpoint, runtime::RuntimeBackendTlsPolicy};
use impulse_contracts::BackendId;
use impulse_errors::{PoolError, ProxyError, RequestFailure};
use impulse_lb::{BackendSelectionInput, pingora_backend::GenerationSelector};

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

/// Per-selection scope shared by every backend pick for one request.
#[derive(Clone, Copy)]
pub(crate) struct SelectionScope {
    pub(crate) generation: u64,
    pub(crate) begin_request: bool,
    pub(crate) worker_slot: usize,
}

impl ForwardingSelectionService {
    pub(crate) fn select_backend(
        request: &TargetResolutionRequest<'_>,
        selector: &GenerationSelector<RuntimeBackendTlsPolicy>,
        backend_transport_identities: &[BackendEndpoint],
        scope: SelectionScope,
        metrics: &Metrics,
    ) -> Result<BackendSelection, ProxyError> {
        let lb_key = Http3Service::resolve_lb_key_for_runtime_request(
            selector.lb_strategy(),
            selector.lb_key_spec(),
            request,
        )
        .value;
        let backend_lb = selector.lb_strategy().canonical_name().to_string();
        let Some(selected) = Self::select_backend_excluding(
            selector,
            backend_transport_identities,
            BackendSelectionInput::new(scope.generation, &lb_key, &[], scope.begin_request)
                .with_worker_slot(scope.worker_slot),
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
        backend_transport_identities: &[BackendEndpoint],
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
        let Some(selected) = selector.select_excluding_for_worker(
            input.request_key(),
            input.excluded_backend_ids(),
            input.worker_slot(),
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
        let address = selected.configured_address().to_string();
        let Some(transport_identity) =
            transport_identity_for_backend(id, &address, backend_transport_identities)
        else {
            return Err(ProxyError::RequestTransport(
                RequestFailure::UnknownBackendTransportIdentity,
            ));
        };
        if input.begin_request() {
            selected.begin_request();
        }
        metrics.runtime_observations().inc_pingora_lb_selection();
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
