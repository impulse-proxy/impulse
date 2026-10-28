use std::sync::Arc;

use crate::runtime::generation::{RuntimeGenerationState, RuntimeSharedServices};

/// Shared runtime services plus the currently published generation-owned state.
///
/// Callers should treat this as the stable hand-off point between runtime
/// assembly and worker execution. The split between `shared_services` and
/// `generation_state` mirrors the runtime ownership model without exposing the
/// internal reload planner here.
pub struct SharedRuntimeState {
    pub(crate) shared_services: Arc<RuntimeSharedServices>,
    pub(crate) generation_state: Arc<RuntimeGenerationState>,
}

impl SharedRuntimeState {
    pub(crate) fn from_parts(
        shared_services: RuntimeSharedServices,
        generation_state: RuntimeGenerationState,
    ) -> Self {
        let shared_services = Arc::new(shared_services);
        let generation_state = Arc::new(generation_state);

        Self {
            shared_services,
            generation_state,
        }
    }

    pub fn shared_services(&self) -> &RuntimeSharedServices {
        self.shared_services.as_ref()
    }

    pub fn generation_state(&self) -> &RuntimeGenerationState {
        self.generation_state.as_ref()
    }

    pub fn bind_metrics_worker_slot(&self, slot: usize) {
        self.shared_services
            .metrics
            .runtime_observations()
            .bind_worker_slot(slot);
    }

    pub fn inc_ingress_queue_drop(&self) {
        self.shared_services
            .metrics
            .ingress_observations()
            .inc_ingress_queue_drop();
    }

    pub fn inc_ingress_queue_drop_bytes(&self, bytes: usize) {
        self.shared_services
            .metrics
            .ingress_observations()
            .inc_ingress_queue_drop_bytes(bytes);
    }

    pub fn set_ingress_queue_bytes(&self, bytes: usize) {
        self.shared_services
            .metrics
            .ingress_observations()
            .set_ingress_queue_bytes(bytes);
    }

    pub fn snapshot_backend_health(&self) -> (usize, usize) {
        let summary = self
            .shared_services
            .backend_lifecycle
            .snapshot_inventory(
                self.generation_state
                    .pingora_load_balancing
                    .upstream_pools(),
            )
            .summary();
        (summary.healthy_backends, summary.total_backends)
    }
}
