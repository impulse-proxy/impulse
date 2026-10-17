use std::{net::SocketAddr, time::SystemTime};

use impulse_transport::{SharedDnsResolver, UpstreamTransportPool};
use log::{debug, info, warn};

use super::coordinator::RuntimeBackendLifecycleState;
use crate::{
    Metrics,
    runtime::backend::{
        event::{BackendLifecycleMutation, BackendRefreshOutcome},
        store::RuntimeBackendResolutionStore,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClientRotationOutcome {
    Rotated,
    NotRotated,
    Failed { error: String },
}

impl ClientRotationOutcome {
    #[cfg(test)]
    pub(crate) fn rotated(&self) -> bool {
        matches!(self, Self::Rotated)
    }

    pub(crate) fn failure(&self) -> Option<&str> {
        match self {
            Self::Failed { error } => Some(error.as_str()),
            Self::Rotated | Self::NotRotated => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BackendDnsRefreshApplication {
    Updated {
        backend_addr: String,
        authority_host: String,
        previous_addrs: Vec<SocketAddr>,
        current_addrs: Vec<SocketAddr>,
        generation: u64,
        refreshed_at: SystemTime,
        client_rotation: ClientRotationOutcome,
    },
    Unchanged {
        backend_addr: String,
        authority_host: String,
        current_addrs: Vec<SocketAddr>,
        generation: u64,
        refreshed_at: SystemTime,
    },
    EmptyAnswerRetained {
        backend_addr: String,
        authority_host: String,
        retained_addrs: Vec<SocketAddr>,
    },
    LookupFailed {
        backend_addr: String,
        authority_host: String,
        retained_addrs: Vec<SocketAddr>,
        error: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendRefreshClassification {
    Refreshed,
    Unchanged,
    Rejected,
    FailedActivePreserved,
}

impl BackendRefreshClassification {
    pub fn traffic_continues_on_existing(self) -> bool {
        !matches!(self, Self::Refreshed)
    }

    pub fn is_failure(self) -> bool {
        matches!(self, Self::Rejected | Self::FailedActivePreserved)
    }

    pub fn slug(self) -> &'static str {
        match self {
            Self::Refreshed => "refreshed",
            Self::Unchanged => "unchanged",
            Self::Rejected => "rejected_empty_answer",
            Self::FailedActivePreserved => "failed_active_preserved",
        }
    }
}

impl BackendDnsRefreshApplication {
    pub(crate) fn backend_addr(&self) -> &str {
        match self {
            Self::Updated { backend_addr, .. }
            | Self::Unchanged { backend_addr, .. }
            | Self::EmptyAnswerRetained { backend_addr, .. }
            | Self::LookupFailed { backend_addr, .. } => backend_addr,
        }
    }

    pub(crate) fn authority_host(&self) -> &str {
        match self {
            Self::Updated { authority_host, .. }
            | Self::Unchanged { authority_host, .. }
            | Self::EmptyAnswerRetained { authority_host, .. }
            | Self::LookupFailed { authority_host, .. } => authority_host,
        }
    }

    pub(crate) fn classification(&self) -> BackendRefreshClassification {
        match self {
            Self::Updated { .. } => BackendRefreshClassification::Refreshed,
            Self::Unchanged { .. } => BackendRefreshClassification::Unchanged,
            Self::EmptyAnswerRetained { .. } => BackendRefreshClassification::Rejected,
            Self::LookupFailed { .. } => BackendRefreshClassification::FailedActivePreserved,
        }
    }

    #[cfg(test)]
    pub(crate) fn traffic_continues_on_existing(&self) -> bool {
        self.classification().traffic_continues_on_existing()
    }
}

pub(crate) fn apply_backend_dns_refresh(
    backend: &RuntimeBackendLifecycleState,
    resolved_addrs: Result<Vec<SocketAddr>, String>,
    resolution_store: &RuntimeBackendResolutionStore,
    backend_dns_resolver: &SharedDnsResolver,
    transport_pool: &UpstreamTransportPool,
) -> BackendDnsRefreshApplication {
    match resolved_addrs {
        Err(error) => BackendDnsRefreshApplication::LookupFailed {
            backend_addr: backend.identity.backend_addr.clone(),
            authority_host: backend.resolution.authority_host.clone(),
            retained_addrs: backend.resolution.resolved_addrs.clone(),
            error,
        },
        Ok(resolved) if resolved.is_empty() => BackendDnsRefreshApplication::EmptyAnswerRetained {
            backend_addr: backend.identity.backend_addr.clone(),
            authority_host: backend.resolution.authority_host.clone(),
            retained_addrs: backend.resolution.resolved_addrs.clone(),
        },
        Ok(resolved) => {
            let refreshed_at = SystemTime::now();
            let Some(mutation) = resolution_store.apply_resolution_refresh(
                &backend.identity.backend_addr,
                resolved.clone(),
                refreshed_at,
            ) else {
                return BackendDnsRefreshApplication::LookupFailed {
                    backend_addr: backend.identity.backend_addr.clone(),
                    authority_host: backend.resolution.authority_host.clone(),
                    retained_addrs: backend.resolution.resolved_addrs.clone(),
                    error: "hostname backend disappeared from resolution store".to_string(),
                };
            };

            backend_dns_resolver.set_host_addrs(
                &backend.resolution.authority_host,
                resolved
                    .into_iter()
                    .map(|addr| SocketAddr::new(addr.ip(), 0)),
            );

            let BackendLifecycleMutation::ResolutionUpdated { result, .. } = mutation else {
                return BackendDnsRefreshApplication::LookupFailed {
                    backend_addr: backend.identity.backend_addr.clone(),
                    authority_host: backend.resolution.authority_host.clone(),
                    retained_addrs: backend.resolution.resolved_addrs.clone(),
                    error: "unexpected backend lifecycle mutation during dns refresh".to_string(),
                };
            };

            let client_rotation = if matches!(result.outcome, BackendRefreshOutcome::Updated { .. })
            {
                match transport_pool.rotate_backend_client(&result.identity.backend_addr) {
                    Ok(rotation) if rotation.rotated() => ClientRotationOutcome::Rotated,
                    Ok(_) => ClientRotationOutcome::NotRotated,
                    Err(error) => ClientRotationOutcome::Failed { error },
                }
            } else {
                ClientRotationOutcome::NotRotated
            };

            match result.outcome {
                BackendRefreshOutcome::Updated {
                    previous_addrs,
                    current_addrs,
                    refreshed_at,
                    refresh_generation,
                } => BackendDnsRefreshApplication::Updated {
                    backend_addr: result.identity.backend_addr,
                    authority_host: backend.resolution.authority_host.clone(),
                    previous_addrs,
                    current_addrs,
                    generation: refresh_generation,
                    refreshed_at: refreshed_at.unwrap_or_else(SystemTime::now),
                    client_rotation,
                },
                BackendRefreshOutcome::Unchanged {
                    current_addrs,
                    refreshed_at,
                    refresh_generation,
                } => BackendDnsRefreshApplication::Unchanged {
                    backend_addr: result.identity.backend_addr,
                    authority_host: backend.resolution.authority_host.clone(),
                    current_addrs,
                    generation: refresh_generation,
                    refreshed_at: refreshed_at.unwrap_or_else(SystemTime::now),
                },
                BackendRefreshOutcome::EmptyAnswerRetained { retained_addrs } => {
                    BackendDnsRefreshApplication::EmptyAnswerRetained {
                        backend_addr: result.identity.backend_addr,
                        authority_host: backend.resolution.authority_host.clone(),
                        retained_addrs,
                    }
                }
                BackendRefreshOutcome::LookupFailed {
                    retained_addrs,
                    error,
                } => BackendDnsRefreshApplication::LookupFailed {
                    backend_addr: result.identity.backend_addr,
                    authority_host: backend.resolution.authority_host.clone(),
                    retained_addrs,
                    error,
                },
            }
        }
    }
}

pub(crate) fn observe_backend_dns_refresh(
    metrics: &Metrics,
    outcome: &BackendDnsRefreshApplication,
) {
    let classification = outcome.classification();
    if classification.is_failure() {
        debug!(
            "backend refresh classification for '{}' (backend '{}'): {} traffic_continues_on_existing={}",
            outcome.authority_host(),
            outcome.backend_addr(),
            classification.slug(),
            classification.traffic_continues_on_existing()
        );
    }

    match outcome {
        BackendDnsRefreshApplication::Updated {
            backend_addr,
            current_addrs,
            refreshed_at,
            client_rotation,
            ..
        } => {
            metrics.record_backend_dns_refresh_success(
                backend_addr,
                *refreshed_at,
                current_addrs.len(),
                true,
            );
            match client_rotation {
                ClientRotationOutcome::Rotated => {
                    metrics.inc_backend_client_rotation(backend_addr);
                }
                ClientRotationOutcome::Failed { .. } => {
                    metrics.inc_backend_client_rotation_failure();
                }
                ClientRotationOutcome::NotRotated => {}
            }
        }
        BackendDnsRefreshApplication::Unchanged {
            backend_addr,
            current_addrs,
            refreshed_at,
            ..
        } => {
            metrics.record_backend_dns_refresh_success(
                backend_addr,
                *refreshed_at,
                current_addrs.len(),
                false,
            );
        }
        BackendDnsRefreshApplication::EmptyAnswerRetained { .. }
        | BackendDnsRefreshApplication::LookupFailed { .. } => {
            metrics.inc_backend_dns_refresh_failure();
        }
    }
}

pub(crate) fn log_backend_dns_refresh(outcome: &BackendDnsRefreshApplication) {
    match outcome {
        BackendDnsRefreshApplication::Updated {
            backend_addr,
            authority_host,
            previous_addrs,
            current_addrs,
            generation,
            client_rotation,
            ..
        } => {
            if previous_addrs.is_empty() {
                info!(
                    "backend DNS refresh populated '{}' (backend '{}') with {:?} generation={}",
                    authority_host, backend_addr, current_addrs, generation
                );
            } else {
                info!(
                    "backend DNS refresh updated '{}' (backend '{}'): {:?} -> {:?} generation={} stale_pooled_connections=possible_until_idle_timeout",
                    authority_host, backend_addr, previous_addrs, current_addrs, generation
                );
            }
            if let Some(error) = client_rotation.failure() {
                warn!(
                    "backend client rotation failed for '{}' (backend '{}') after DNS refresh: {}; stale pooled connections persist until idle timeout",
                    authority_host, backend_addr, error
                );
            }
        }
        BackendDnsRefreshApplication::Unchanged {
            backend_addr,
            authority_host,
            current_addrs,
            generation,
            ..
        } => {
            debug!(
                "backend DNS refresh unchanged for '{}' (backend '{}') addrs={:?} generation={}",
                authority_host, backend_addr, current_addrs, generation
            );
        }
        BackendDnsRefreshApplication::EmptyAnswerRetained {
            backend_addr,
            authority_host,
            retained_addrs,
        } => {
            warn!(
                "backend DNS refresh returned no addresses for '{}' (backend '{}') [{}]; retaining {:?}; traffic continues on existing resolution (no manual action required unless persistent)",
                authority_host,
                backend_addr,
                BackendRefreshClassification::Rejected.slug(),
                retained_addrs
            );
        }
        BackendDnsRefreshApplication::LookupFailed {
            backend_addr,
            authority_host,
            retained_addrs,
            error,
        } => {
            warn!(
                "backend DNS refresh failed for '{}' (backend '{}') [{}]: {}; retaining {:?}; traffic continues on existing resolution (fix DNS/upstream if persistent)",
                authority_host,
                backend_addr,
                BackendRefreshClassification::FailedActivePreserved.slug(),
                error,
                retained_addrs
            );
        }
    }
}

#[cfg(test)]
mod tests {
    mod refresh_application {
        use std::{net::SocketAddr, sync::Arc, time::SystemTime};

        use impulse_transport::SharedDnsResolver;

        use super::super::{
            super::test_support::test_transport_pool, BackendDnsRefreshApplication,
            BackendRefreshClassification, ClientRotationOutcome, observe_backend_dns_refresh,
        };
        use crate::{
            Metrics,
            runtime::backend::{
                lifecycle::BackendLifecycleCoordinator, resolution::RuntimeBackendResolution,
                store::RuntimeBackendResolutionStore,
            },
        };

        fn updated_client_rotation(app: &BackendDnsRefreshApplication) -> &ClientRotationOutcome {
            match app {
                BackendDnsRefreshApplication::Updated {
                    client_rotation, ..
                } => client_rotation,
                other => panic!("expected Updated, got {other:?}"),
            }
        }

        #[test]
        fn refresh_classification_maps_every_variant_and_preserves_traffic_on_failure() {
            let updated = BackendDnsRefreshApplication::Updated {
                backend_addr: "http://backend:8080".to_string(),
                authority_host: "backend".to_string(),
                previous_addrs: vec![],
                current_addrs: vec!["10.0.0.1:8080".parse().expect("addr")],
                generation: 1,
                refreshed_at: SystemTime::UNIX_EPOCH,
                client_rotation: ClientRotationOutcome::Rotated,
            };
            assert_eq!(
                updated.classification(),
                BackendRefreshClassification::Refreshed
            );
            assert!(!updated.traffic_continues_on_existing());

            let unchanged = BackendDnsRefreshApplication::Unchanged {
                backend_addr: "http://backend:8080".to_string(),
                authority_host: "backend".to_string(),
                current_addrs: vec!["10.0.0.1:8080".parse().expect("addr")],
                generation: 1,
                refreshed_at: SystemTime::UNIX_EPOCH,
            };
            assert_eq!(
                unchanged.classification(),
                BackendRefreshClassification::Unchanged
            );
            assert!(unchanged.traffic_continues_on_existing());

            let empty = BackendDnsRefreshApplication::EmptyAnswerRetained {
                backend_addr: "http://backend:8080".to_string(),
                authority_host: "backend".to_string(),
                retained_addrs: vec!["10.0.0.1:8080".parse().expect("addr")],
            };
            assert_eq!(
                empty.classification(),
                BackendRefreshClassification::Rejected
            );
            assert!(empty.traffic_continues_on_existing());
            assert!(empty.classification().is_failure());

            let failed = BackendDnsRefreshApplication::LookupFailed {
                backend_addr: "http://backend:8080".to_string(),
                authority_host: "backend".to_string(),
                retained_addrs: vec!["10.0.0.1:8080".parse().expect("addr")],
                error: "nxdomain".to_string(),
            };
            assert_eq!(
                failed.classification(),
                BackendRefreshClassification::FailedActivePreserved
            );
            assert!(failed.traffic_continues_on_existing());
            assert!(failed.classification().is_failure());
            assert_eq!(failed.backend_addr(), "http://backend:8080");
            assert_eq!(failed.authority_host(), "backend");
        }

        #[test]
        fn rotation_failure_is_metered_and_does_not_hide_refresh_success() {
            let metrics = Metrics::default();
            let updated = BackendDnsRefreshApplication::Updated {
                backend_addr: "http://backend.internal:8080".to_string(),
                authority_host: "backend.internal".to_string(),
                previous_addrs: vec!["10.0.0.1:8080".parse().expect("addr")],
                current_addrs: vec!["10.0.0.2:8080".parse().expect("addr")],
                generation: 2,
                refreshed_at: SystemTime::UNIX_EPOCH,
                client_rotation: ClientRotationOutcome::Failed {
                    error: "pool busy".to_string(),
                },
            };

            observe_backend_dns_refresh(&metrics, &updated);

            assert_eq!(
                metrics
                    .backend_client_rotation_failures
                    .load(std::sync::atomic::Ordering::Relaxed),
                1,
                "rotation failure must be metered, not silently dropped"
            );
            assert_eq!(
                metrics
                    .backend_client_rotations
                    .load(std::sync::atomic::Ordering::Relaxed),
                0
            );
            assert_eq!(
                updated_client_rotation(&updated).failure(),
                Some("pool busy")
            );
        }

        #[test]
        fn hostname_refresh_updates_resolved_addrs_and_generation() {
            let backend_addr = "http://localhost:8080";
            let store = Arc::new(RuntimeBackendResolutionStore::new([
                RuntimeBackendResolution::hostname(
                    backend_addr.to_string(),
                    "localhost".to_string(),
                    8080,
                ),
            ]));
            let coordinator = BackendLifecycleCoordinator::new(Arc::clone(&store));
            let resolver = SharedDnsResolver::new();
            let transport_pool = test_transport_pool(backend_addr);
            let backend = coordinator.backend(backend_addr).expect("backend");
            let new_addrs = vec!["10.0.0.10:8080".parse::<SocketAddr>().expect("addr")];

            let outcome = coordinator.apply_refresh(
                &backend,
                Ok(new_addrs.clone()),
                &resolver,
                &transport_pool,
            );

            let BackendDnsRefreshApplication::Updated {
                current_addrs,
                generation,
                client_rotation,
                ..
            } = &outcome
            else {
                panic!("expected Updated outcome, got: {outcome:?}");
            };
            assert_eq!(current_addrs, &new_addrs);
            assert_eq!(*generation, 1);
            assert!(client_rotation.rotated());

            let snapshot = coordinator
                .snapshot_backend(backend_addr)
                .expect("snapshot");
            assert_eq!(snapshot.resolution.resolved_addrs, new_addrs);
            assert_eq!(snapshot.resolution.refresh_generation, 1);
            assert_eq!(
                resolver.cached_addrs("localhost"),
                Some(vec!["10.0.0.10:0".parse::<SocketAddr>().expect("addr")])
            );
        }

        #[test]
        fn unchanged_refresh_does_not_rotate_clients_unnecessarily() {
            let backend_addr = "http://localhost:8080";
            let initial_addrs = vec!["10.0.0.10:8080".parse::<SocketAddr>().expect("addr")];
            let store = Arc::new(RuntimeBackendResolutionStore::new([
                RuntimeBackendResolution::hostname(
                    backend_addr.to_string(),
                    "localhost".to_string(),
                    8080,
                ),
            ]));
            store
                .apply_resolution_refresh(
                    backend_addr,
                    initial_addrs.clone(),
                    SystemTime::UNIX_EPOCH,
                )
                .expect("seed refresh");
            let coordinator = BackendLifecycleCoordinator::new(Arc::clone(&store));
            let resolver = SharedDnsResolver::new();
            let transport_pool = test_transport_pool(backend_addr);
            let backend = coordinator.backend(backend_addr).expect("backend");

            let outcome = coordinator.apply_refresh(
                &backend,
                Ok(initial_addrs.clone()),
                &resolver,
                &transport_pool,
            );

            assert!(matches!(
                outcome,
                BackendDnsRefreshApplication::Unchanged {
                    current_addrs,
                    generation: 2,
                    ..
                } if current_addrs == initial_addrs
            ));
        }

        #[test]
        fn successive_refreshes_increment_generation_across_outcomes() {
            let backend_addr = "http://localhost:8080";
            let initial_addrs = vec!["10.0.0.10:8080".parse::<SocketAddr>().expect("addr")];
            let updated_addrs = vec!["10.0.0.11:8080".parse::<SocketAddr>().expect("addr")];
            let store = Arc::new(RuntimeBackendResolutionStore::new([
                RuntimeBackendResolution::hostname(
                    backend_addr.to_string(),
                    "localhost".to_string(),
                    8080,
                ),
            ]));
            store
                .apply_resolution_refresh(backend_addr, initial_addrs, SystemTime::UNIX_EPOCH)
                .expect("seed refresh");
            let coordinator = BackendLifecycleCoordinator::new(Arc::clone(&store));
            let resolver = SharedDnsResolver::new();
            let transport_pool = test_transport_pool(backend_addr);
            let backend = coordinator.backend(backend_addr).expect("backend");

            let refreshed = coordinator.apply_refresh(
                &backend,
                Ok(updated_addrs.clone()),
                &resolver,
                &transport_pool,
            );
            assert!(matches!(
                refreshed,
                BackendDnsRefreshApplication::Updated {
                    generation: 2,
                    current_addrs,
                    ..
                } if current_addrs == updated_addrs
            ));

            let backend = coordinator.backend(backend_addr).expect("backend");
            let unchanged = coordinator.apply_refresh(
                &backend,
                Ok(updated_addrs.clone()),
                &resolver,
                &transport_pool,
            );
            assert!(matches!(
                unchanged,
                BackendDnsRefreshApplication::Unchanged {
                    generation: 3,
                    current_addrs,
                    ..
                } if current_addrs == updated_addrs
            ));

            let snapshot = coordinator
                .snapshot_backend(backend_addr)
                .expect("snapshot");
            assert_eq!(snapshot.resolution.resolved_addrs, updated_addrs);
            assert_eq!(snapshot.resolution.refresh_generation, 3);
        }

        #[test]
        fn empty_dns_answer_retains_prior_addresses() {
            let backend_addr = "http://localhost:8080";
            let retained_addrs = vec!["10.0.0.10:8080".parse::<SocketAddr>().expect("addr")];
            let store = Arc::new(RuntimeBackendResolutionStore::new([
                RuntimeBackendResolution::hostname(
                    backend_addr.to_string(),
                    "localhost".to_string(),
                    8080,
                ),
            ]));
            store
                .apply_resolution_refresh(
                    backend_addr,
                    retained_addrs.clone(),
                    SystemTime::UNIX_EPOCH,
                )
                .expect("seed refresh");
            let coordinator = BackendLifecycleCoordinator::new(store);
            let resolver = SharedDnsResolver::new();
            let transport_pool = test_transport_pool(backend_addr);
            let backend = coordinator.backend(backend_addr).expect("backend");

            let outcome =
                coordinator.apply_refresh(&backend, Ok(Vec::new()), &resolver, &transport_pool);

            assert!(matches!(
                outcome,
                BackendDnsRefreshApplication::EmptyAnswerRetained {
                    retained_addrs: actual,
                    ..
                } if actual == retained_addrs
            ));
        }

        #[test]
        fn failed_refresh_preserves_existing_resolution_and_generation() {
            let backend_addr = "http://localhost:8080";
            let retained_addrs = vec!["10.0.0.10:8080".parse::<SocketAddr>().expect("addr")];
            let store = Arc::new(RuntimeBackendResolutionStore::new([
                RuntimeBackendResolution::hostname(
                    backend_addr.to_string(),
                    "localhost".to_string(),
                    8080,
                ),
            ]));
            store
                .apply_resolution_refresh(
                    backend_addr,
                    retained_addrs.clone(),
                    SystemTime::UNIX_EPOCH,
                )
                .expect("seed refresh");
            let coordinator = BackendLifecycleCoordinator::new(Arc::clone(&store));
            let resolver = SharedDnsResolver::new();
            let transport_pool = test_transport_pool(backend_addr);
            let backend = coordinator.backend(backend_addr).expect("backend");

            let outcome = coordinator.apply_refresh(
                &backend,
                Err("nxdomain".to_string()),
                &resolver,
                &transport_pool,
            );

            assert!(matches!(
                outcome,
                BackendDnsRefreshApplication::LookupFailed {
                    retained_addrs: ref actual,
                    ..
                } if *actual == retained_addrs
            ));
            let snapshot = coordinator
                .snapshot_backend(backend_addr)
                .expect("snapshot after failed refresh");
            assert_eq!(snapshot.resolution.resolved_addrs, retained_addrs);
            assert_eq!(snapshot.resolution.refresh_generation, 1);
            assert_eq!(
                outcome.classification(),
                BackendRefreshClassification::FailedActivePreserved
            );
        }
    }
}
