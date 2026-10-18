use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use impulse_lb::{HealthTransition, upstream_pool::UpstreamPool};

use super::health::apply_backend_health_observation;
use crate::runtime::backend::{
    event,
    resolution::{RuntimeBackendAddressKind, RuntimeBackendResolution},
    state::{
        BackendHealthState, BackendIdentity, BackendLifecycleInventorySnapshot,
        BackendLifecycleSnapshot, BackendMembershipState, BackendPoolPlacementSnapshot,
        BackendResolutionState, CanonicalBackendLifecycleSnapshot,
    },
    store::RuntimeBackendResolutionStore,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBackendLifecycleState {
    pub identity: BackendIdentity,
    pub resolution: BackendResolutionState,
    pub health: BackendHealthState,
    pub membership: BackendMembershipState,
}

impl RuntimeBackendLifecycleState {
    pub fn new(
        identity: BackendIdentity,
        resolution: BackendResolutionState,
        health: BackendHealthState,
        membership: BackendMembershipState,
    ) -> Self {
        Self {
            identity,
            resolution,
            health,
            membership,
        }
    }

    pub fn from_resolution_seed(resolution: &RuntimeBackendResolution) -> Self {
        Self {
            identity: BackendIdentity::from(resolution),
            resolution: BackendResolutionState::from(resolution),
            health: BackendHealthState::Unknown,
            membership: BackendMembershipState::Active,
        }
    }

    pub fn snapshot(&self) -> BackendLifecycleSnapshot {
        BackendLifecycleSnapshot {
            identity: self.identity.clone(),
            resolution: self.resolution.clone(),
            health: self.health.clone(),
            membership: self.membership,
        }
    }
}

impl From<&RuntimeBackendResolution> for RuntimeBackendLifecycleState {
    fn from(value: &RuntimeBackendResolution) -> Self {
        Self::from_resolution_seed(value)
    }
}

impl From<&RuntimeBackendLifecycleState> for BackendLifecycleSnapshot {
    fn from(value: &RuntimeBackendLifecycleState) -> Self {
        value.snapshot()
    }
}

#[derive(Debug, Clone)]
pub struct BackendLifecycleCoordinator {
    resolution_store: Arc<RuntimeBackendResolutionStore>,
}

impl BackendLifecycleCoordinator {
    pub fn new(resolution_store: Arc<RuntimeBackendResolutionStore>) -> Self {
        Self { resolution_store }
    }

    pub fn backend(&self, backend_addr: &str) -> Option<RuntimeBackendLifecycleState> {
        self.resolution_store.backend(backend_addr)
    }

    pub fn snapshot_backend(&self, backend_addr: &str) -> Option<BackendLifecycleSnapshot> {
        self.backend(backend_addr).map(|backend| backend.snapshot())
    }

    pub fn snapshot_all(&self) -> HashMap<String, BackendLifecycleSnapshot> {
        self.resolution_store.snapshot()
    }

    pub fn snapshot_inventory(
        &self,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
    ) -> BackendLifecycleInventorySnapshot {
        let mut snapshots = self
            .snapshot_all()
            .into_values()
            .map(|snapshot| {
                (
                    snapshot.identity.backend_addr.clone(),
                    CanonicalBackendLifecycleSnapshot {
                        identity: snapshot.identity,
                        resolution: snapshot.resolution,
                        health: snapshot.health,
                        membership: snapshot.membership,
                        placements: Vec::new(),
                    },
                )
            })
            .collect::<HashMap<_, _>>();

        for (upstream_name, pool) in upstream_pools {
            let Ok(guard) = pool.read() else {
                continue;
            };
            let membership_summary = guard.membership_summary();
            for backend_index in guard.backend_indices() {
                let Some(backend_addr) = guard.backend_address(backend_index) else {
                    continue;
                };
                let Some(backend) = guard.backend_runtime_state(backend_index) else {
                    continue;
                };
                let entry = snapshots
                    .entry(backend_addr.to_string())
                    .or_insert_with(|| CanonicalBackendLifecycleSnapshot {
                        identity: BackendIdentity::new(backend_addr.to_string()),
                        resolution: BackendResolutionState {
                            authority_host: backend_addr.to_string(),
                            authority_port: 0,
                            address_kind: RuntimeBackendAddressKind::IpLiteral,
                            resolved_addrs: Vec::new(),
                            last_refresh_success_at: None,
                            refresh_generation: 0,
                        },
                        health: BackendHealthState::Unknown,
                        membership: BackendMembershipState::Removed,
                        placements: Vec::new(),
                    });
                entry.placements.push(BackendPoolPlacementSnapshot {
                    upstream_name: upstream_name.clone(),
                    backend_index,
                    healthy: backend.healthy,
                    active_requests: backend.active_requests,
                    ewma_latency_ms: backend.ewma_latency_ms,
                    membership_epoch: membership_summary.membership_epoch,
                });
            }
        }

        let mut backends = snapshots.into_values().collect::<Vec<_>>();
        for backend in &mut backends {
            if backend.placements.is_empty() {
                backend.membership = BackendMembershipState::Removed;
                continue;
            }

            backend.membership = BackendMembershipState::Active;
            backend.health = if backend.placements.iter().all(|placement| placement.healthy) {
                BackendHealthState::Healthy
            } else {
                BackendHealthState::Unhealthy { reason: None }
            };
            backend.placements.sort_by(|left, right| {
                left.upstream_name
                    .cmp(&right.upstream_name)
                    .then(left.backend_index.cmp(&right.backend_index))
            });
        }
        backends
            .sort_by(|left, right| left.identity.backend_addr.cmp(&right.identity.backend_addr));

        BackendLifecycleInventorySnapshot { backends }
    }

    pub(crate) fn apply_health_observation(
        &self,
        upstream_pool: Option<&Arc<RwLock<UpstreamPool>>>,
        backend_index: Option<usize>,
        observation: &event::BackendHealthObservation,
    ) -> Option<HealthTransition> {
        apply_backend_health_observation(upstream_pool, backend_index, observation)
    }
}

#[cfg(test)]
mod tests {
    mod snapshot_inventory {
        use std::{collections::HashMap, sync::Arc};

        use impulse_lb::HealthTransition;

        use super::super::{
            super::test_support::{test_active_health_upstream_pool, test_upstream_pool},
            BackendLifecycleCoordinator, RuntimeBackendLifecycleState,
        };
        use crate::runtime::backend::{
            event::BackendHealthObservationOutcome,
            lifecycle::evaluate_active_health_check,
            resolution::RuntimeBackendResolution,
            state::{BackendHealthState, BackendIdentity, BackendMembershipState},
            store::RuntimeBackendResolutionStore,
        };

        #[test]
        fn lifecycle_state_seeds_from_resolution_with_unknown_health() {
            let resolution = RuntimeBackendResolution::hostname(
                "https://backend.internal:8443".to_string(),
                "backend.internal".to_string(),
                8443,
            );

            let state = RuntimeBackendLifecycleState::from(&resolution);

            assert_eq!(state.identity.backend_addr, "https://backend.internal:8443");
            assert_eq!(state.membership, BackendMembershipState::Active);
            assert_eq!(state.health, BackendHealthState::Unknown);
            assert!(state.resolution.is_hostname());
        }

        #[test]
        fn lifecycle_coordinator_exposes_backend_snapshots() {
            let store = Arc::new(RuntimeBackendResolutionStore::new([
                RuntimeBackendResolution::hostname(
                    "https://backend.internal:8443".to_string(),
                    "backend.internal".to_string(),
                    8443,
                ),
            ]));
            let coordinator = BackendLifecycleCoordinator::new(Arc::clone(&store));

            let snapshot = coordinator
                .snapshot_backend("https://backend.internal:8443")
                .expect("backend snapshot");
            assert_eq!(
                snapshot.identity.backend_addr,
                "https://backend.internal:8443"
            );

            let all = coordinator.snapshot_all();
            assert_eq!(all.len(), 1);
            assert!(all.contains_key("https://backend.internal:8443"));
        }

        #[test]
        fn lifecycle_coordinator_merges_resolution_and_pool_health_into_inventory() {
            let store = Arc::new(RuntimeBackendResolutionStore::new([
                RuntimeBackendResolution::hostname(
                    "127.0.0.1:8080".to_string(),
                    "backend.internal".to_string(),
                    8080,
                ),
            ]));
            let coordinator = BackendLifecycleCoordinator::new(store);
            let mut pools = HashMap::new();
            pools.insert("api".to_string(), test_upstream_pool());

            let inventory = coordinator.snapshot_inventory(&pools);
            let backend = inventory
                .backends
                .iter()
                .find(|backend| backend.identity.backend_addr == "127.0.0.1:8080")
                .expect("backend inventory");

            assert_eq!(inventory.summary().healthy_backends, 1);
            assert_eq!(inventory.summary().total_backends, 1);
            assert_eq!(backend.placements.len(), 1);
            assert!(matches!(backend.health, BackendHealthState::Healthy));
            assert_eq!(backend.placements[0].upstream_name, "api");
        }

        #[test]
        fn inventory_marks_missing_pool_members_as_removed_without_losing_live_placements() {
            let store = Arc::new(RuntimeBackendResolutionStore::new([
                RuntimeBackendResolution::hostname(
                    "127.0.0.1:8080".to_string(),
                    "backend-a.internal".to_string(),
                    8080,
                ),
                RuntimeBackendResolution::hostname(
                    "127.0.0.1:9090".to_string(),
                    "backend-b.internal".to_string(),
                    9090,
                ),
            ]));
            let coordinator = BackendLifecycleCoordinator::new(store);
            let mut pools = HashMap::new();
            pools.insert("api".to_string(), test_upstream_pool());

            let inventory = coordinator.snapshot_inventory(&pools);
            let active = inventory
                .backends
                .iter()
                .find(|backend| backend.identity.backend_addr == "127.0.0.1:8080")
                .expect("active backend");
            let removed = inventory
                .backends
                .iter()
                .find(|backend| backend.identity.backend_addr == "127.0.0.1:9090")
                .expect("removed backend");

            assert_eq!(active.membership, BackendMembershipState::Active);
            assert_eq!(active.placements.len(), 1);
            assert_eq!(removed.membership, BackendMembershipState::Removed);
            assert!(removed.placements.is_empty());
            assert_eq!(inventory.summary().total_backends, 1);
        }

        #[test]
        fn inventory_exposes_canonical_health_membership_and_resolution_views() {
            let placed_backend = "127.0.0.1:8080";
            let removed_backend = "127.0.0.1:9090";
            let store = Arc::new(RuntimeBackendResolutionStore::new([
                RuntimeBackendResolution::hostname(
                    placed_backend.to_string(),
                    "backend-a.internal".to_string(),
                    8080,
                ),
                RuntimeBackendResolution::hostname(
                    removed_backend.to_string(),
                    "backend-b.internal".to_string(),
                    9090,
                ),
            ]));
            let coordinator = BackendLifecycleCoordinator::new(Arc::clone(&store));
            let pool = test_active_health_upstream_pool();
            let failure = evaluate_active_health_check(
                BackendIdentity::new(placed_backend),
                BackendHealthObservationOutcome::Failure,
                Some(impulse_lb::health::HealthFailureReason::Transport),
                100,
                0,
            );
            let transition =
                coordinator.apply_health_observation(Some(&pool), Some(0), &failure.observation);
            assert!(matches!(
                transition,
                Some(HealthTransition::BecameUnhealthy)
            ));

            let mut pools = HashMap::new();
            pools.insert("api".to_string(), pool);
            let inventory = coordinator.snapshot_inventory(&pools);

            let active = inventory
                .backends
                .iter()
                .find(|backend| backend.identity.backend_addr == placed_backend)
                .expect("active backend");
            assert_eq!(active.identity.backend_addr, placed_backend);
            assert_eq!(active.membership, BackendMembershipState::Active);
            assert!(matches!(
                active.health,
                BackendHealthState::Unhealthy { reason: None }
            ));
            assert!(active.resolution.resolved_addrs.is_empty());
            assert_eq!(active.resolution.refresh_generation, 0);
            assert_eq!(active.resolution.last_refresh_success_at, None);
            assert_eq!(active.placements.len(), 1);
            assert!(!active.placements[0].healthy);

            let removed = inventory
                .backends
                .iter()
                .find(|backend| backend.identity.backend_addr == removed_backend)
                .expect("removed backend");
            assert_eq!(removed.identity.backend_addr, removed_backend);
            assert_eq!(removed.membership, BackendMembershipState::Removed);
            assert!(matches!(removed.health, BackendHealthState::Unknown));
            assert!(removed.placements.is_empty());

            assert_eq!(inventory.summary().total_backends, 1);
            assert_eq!(inventory.summary().healthy_backends, 0);
        }
    }
}
