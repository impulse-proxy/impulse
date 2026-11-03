use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use impulse_contracts::HealthFailureReason;
use impulse_lb::{health::HealthTransition, upstream_pool::UpstreamPool};

use crate::runtime::backend::{
    event::{
        BackendHealthObservation, BackendHealthObservationOutcome, BackendHealthObservationSource,
        BackendRequestFeedback, BackendRequestFeedbackOutcome,
    },
    state::BackendIdentity,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActiveHealthCheckEvaluation {
    pub observation: BackendHealthObservation,
    pub next_consecutive_failures: u32,
    pub next_delay: Duration,
}

pub(crate) fn apply_backend_request_accounting(
    upstream_pool: Option<&Arc<RwLock<UpstreamPool>>>,
    backend_index: Option<usize>,
    elapsed: Duration,
    status: Option<u16>,
) {
    if let (Some(pool), Some(index)) = (upstream_pool, backend_index)
        && let Ok(mut guard) = pool.write()
    {
        guard.finish_request(index, elapsed, status);
    }
}

pub(crate) fn apply_backend_request_feedback(
    upstream_pool: Option<&Arc<RwLock<UpstreamPool>>>,
    backend_index: Option<usize>,
    feedback: &BackendRequestFeedback,
) -> Option<HealthTransition> {
    let (Some(pool), Some(index)) = (upstream_pool, backend_index) else {
        return None;
    };
    let mut pool = pool.write().ok()?;
    match feedback.outcome {
        BackendRequestFeedbackOutcome::Success => pool.mark_backend_request_success(index),
        BackendRequestFeedbackOutcome::Neutral => None,
        BackendRequestFeedbackOutcome::Failure { reason } => {
            pool.observe_backend_request_failure(index, feedback.elapsed, reason)
        }
    }
}

pub(crate) fn evaluate_active_health_check(
    identity: BackendIdentity,
    outcome: BackendHealthObservationOutcome,
    reason: Option<HealthFailureReason>,
    base_interval_ms: u64,
    consecutive_failures: u32,
) -> ActiveHealthCheckEvaluation {
    let next_consecutive_failures = match outcome {
        BackendHealthObservationOutcome::Failure => consecutive_failures.saturating_add(1),
        BackendHealthObservationOutcome::Success | BackendHealthObservationOutcome::Neutral => 0,
    };
    let backoff_multiplier = 1u64 << next_consecutive_failures.min(2);
    let delay_ms = base_interval_ms.saturating_mul(backoff_multiplier);

    ActiveHealthCheckEvaluation {
        observation: BackendHealthObservation::active_check(identity, outcome, reason),
        next_consecutive_failures,
        next_delay: Duration::from_millis(delay_ms),
    }
}

pub(crate) fn apply_backend_health_observation(
    upstream_pool: Option<&Arc<RwLock<UpstreamPool>>>,
    backend_index: Option<usize>,
    observation: &BackendHealthObservation,
) -> Option<HealthTransition> {
    let (Some(pool), Some(index)) = (upstream_pool, backend_index) else {
        return None;
    };
    let mut pool = pool.write().ok()?;
    match (observation.source, observation.outcome) {
        (BackendHealthObservationSource::ActiveCheck, BackendHealthObservationOutcome::Success) => {
            pool.mark_backend_healthy(index)
        }
        (BackendHealthObservationSource::ActiveCheck, BackendHealthObservationOutcome::Failure) => {
            pool.mark_backend_failure_from_active_check(index)
        }
        (BackendHealthObservationSource::ActiveCheck, BackendHealthObservationOutcome::Neutral) => {
            None
        }
        (_, BackendHealthObservationOutcome::Success) => pool.mark_backend_request_success(index),
        (_, BackendHealthObservationOutcome::Neutral) => None,
        (_, BackendHealthObservationOutcome::Failure) => observation
            .reason
            .and_then(|reason| pool.mark_backend_request_failure(index, reason)),
    }
}

#[cfg(test)]
mod tests {
    mod health_observation_application {
        use std::{collections::HashMap, sync::Arc, time::Duration};

        use impulse_lb::health::HealthTransition;

        use super::super::{
            super::test_support::{test_active_health_upstream_pool, test_upstream_pool},
            apply_backend_health_observation, evaluate_active_health_check,
        };
        use crate::runtime::backend::{
            event::{
                BackendHealthObservation, BackendHealthObservationOutcome,
                BackendHealthObservationSource,
            },
            lifecycle::BackendLifecycleCoordinator,
            resolution::RuntimeBackendResolution,
            state::{BackendHealthState, BackendIdentity},
            store::RuntimeBackendResolutionStore,
        };

        #[test]
        fn active_health_check_evaluation_tracks_backoff_and_transition() {
            let pool = test_active_health_upstream_pool();

            let failure = evaluate_active_health_check(
                BackendIdentity::new("127.0.0.1:8080"),
                BackendHealthObservationOutcome::Failure,
                Some(impulse_lb::health::HealthFailureReason::Transport),
                100,
                0,
            );
            assert_eq!(failure.next_consecutive_failures, 1);
            assert_eq!(failure.next_delay, Duration::from_millis(200));
            let transition =
                apply_backend_health_observation(Some(&pool), Some(0), &failure.observation);
            assert!(matches!(
                transition,
                Some(HealthTransition::BecameUnhealthy)
            ));

            let success = evaluate_active_health_check(
                BackendIdentity::new("127.0.0.1:8080"),
                BackendHealthObservationOutcome::Success,
                None,
                100,
                failure.next_consecutive_failures,
            );
            assert_eq!(success.next_consecutive_failures, 0);
            assert_eq!(success.next_delay, Duration::from_millis(100));
            let transition =
                apply_backend_health_observation(Some(&pool), Some(0), &success.observation);
            assert!(matches!(transition, Some(HealthTransition::BecameHealthy)));
        }

        #[test]
        fn success_observation_keeps_healthy_backend_aligned_with_pool_state() {
            let pool = test_active_health_upstream_pool();
            let observation = BackendHealthObservation::active_check(
                BackendIdentity::new("127.0.0.1:8080"),
                BackendHealthObservationOutcome::Success,
                None,
            );

            let transition = apply_backend_health_observation(Some(&pool), Some(0), &observation);
            assert!(
                transition.is_none(),
                "healthy backend should not re-transition"
            );

            let guard = pool.read().expect("read");
            let state = guard.backend_runtime_state(0).expect("backend state");
            assert!(state.healthy, "pool runtime state must remain healthy");
        }

        #[test]
        fn coordinator_health_observation_marks_backend_unhealthy_and_recovers() {
            let pool = test_active_health_upstream_pool();
            let store = Arc::new(RuntimeBackendResolutionStore::new([
                RuntimeBackendResolution::hostname(
                    "127.0.0.1:8080".to_string(),
                    "backend.internal".to_string(),
                    8080,
                ),
            ]));
            let coordinator = BackendLifecycleCoordinator::new(store);

            let failure = evaluate_active_health_check(
                BackendIdentity::new("127.0.0.1:8080"),
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
            pools.insert("api".to_string(), Arc::clone(&pool));
            let summary = coordinator.snapshot_inventory(&pools).summary();
            assert_eq!(summary.healthy_backends, 0);
            assert_eq!(summary.total_backends, 1);

            let success = evaluate_active_health_check(
                BackendIdentity::new("127.0.0.1:8080"),
                BackendHealthObservationOutcome::Success,
                None,
                100,
                failure.next_consecutive_failures,
            );
            let transition =
                coordinator.apply_health_observation(Some(&pool), Some(0), &success.observation);
            assert!(matches!(transition, Some(HealthTransition::BecameHealthy)));

            let summary = coordinator.snapshot_inventory(&pools).summary();
            assert_eq!(summary.healthy_backends, 1);

            let backend = coordinator
                .snapshot_inventory(&pools)
                .backends
                .into_iter()
                .find(|backend| backend.identity.backend_addr == "127.0.0.1:8080")
                .expect("backend inventory");
            assert!(matches!(backend.health, BackendHealthState::Healthy));
            assert!(backend.placements[0].healthy);
        }

        #[test]
        fn passive_failure_observation_requires_reason_and_threshold_before_unhealthy() {
            let pool = test_upstream_pool();
            let no_reason = BackendHealthObservation {
                identity: BackendIdentity::new("127.0.0.1:8080"),
                source: BackendHealthObservationSource::PassiveRequest,
                outcome: BackendHealthObservationOutcome::Failure,
                reason: None,
            };

            let transition = apply_backend_health_observation(Some(&pool), Some(0), &no_reason);
            assert!(
                transition.is_none(),
                "missing reason must not mutate health"
            );
            assert!(
                pool.read().expect("read").is_backend_healthy(0),
                "pool should remain healthy without a mapped reason"
            );

            let failure = BackendHealthObservation {
                identity: BackendIdentity::new("127.0.0.1:8080"),
                source: BackendHealthObservationSource::PassiveRequest,
                outcome: BackendHealthObservationOutcome::Failure,
                reason: Some(impulse_lb::health::HealthFailureReason::Timeout),
            };

            assert!(apply_backend_health_observation(Some(&pool), Some(0), &failure).is_none());
            assert!(apply_backend_health_observation(Some(&pool), Some(0), &failure).is_none());
            let transition = apply_backend_health_observation(Some(&pool), Some(0), &failure);
            assert!(matches!(
                transition,
                Some(HealthTransition::BecameUnhealthy)
            ));

            let guard = pool.read().expect("read");
            let state = guard.backend_runtime_state(0).expect("backend state");
            assert!(
                !state.healthy,
                "pool runtime state must reflect passive failure threshold crossing"
            );
        }

        #[test]
        fn passive_failure_observation_keeps_inventory_aligned_with_pool_state() {
            let pool = test_upstream_pool();
            let store = Arc::new(RuntimeBackendResolutionStore::new([
                RuntimeBackendResolution::hostname(
                    "127.0.0.1:8080".to_string(),
                    "backend.internal".to_string(),
                    8080,
                ),
            ]));
            let coordinator = BackendLifecycleCoordinator::new(store);
            let mut pools = HashMap::new();
            pools.insert("api".to_string(), Arc::clone(&pool));

            let failure = BackendHealthObservation {
                identity: BackendIdentity::new("127.0.0.1:8080"),
                source: BackendHealthObservationSource::PassiveRequest,
                outcome: BackendHealthObservationOutcome::Failure,
                reason: Some(impulse_lb::health::HealthFailureReason::Transport),
            };
            assert!(
                coordinator
                    .apply_health_observation(Some(&pool), Some(0), &failure)
                    .is_none()
            );
            assert!(
                coordinator
                    .apply_health_observation(Some(&pool), Some(0), &failure)
                    .is_none()
            );
            let transition = coordinator.apply_health_observation(Some(&pool), Some(0), &failure);
            assert!(matches!(
                transition,
                Some(HealthTransition::BecameUnhealthy)
            ));

            let inventory = coordinator.snapshot_inventory(&pools);
            let backend = inventory
                .backends
                .iter()
                .find(|backend| backend.identity.backend_addr == "127.0.0.1:8080")
                .expect("backend inventory after failure");
            assert!(matches!(
                backend.health,
                BackendHealthState::Unhealthy { reason: None }
            ));
            assert!(
                !backend.placements[0].healthy,
                "placement health must match lifecycle unhealthy state"
            );
        }

        #[test]
        fn passive_success_does_not_override_health_without_transition() {
            let pool = test_upstream_pool();
            let failure = BackendHealthObservation {
                identity: BackendIdentity::new("127.0.0.1:8080"),
                source: BackendHealthObservationSource::PassiveRequest,
                outcome: BackendHealthObservationOutcome::Failure,
                reason: Some(impulse_lb::health::HealthFailureReason::Transport),
            };
            assert!(apply_backend_health_observation(Some(&pool), Some(0), &failure).is_none());
            assert!(apply_backend_health_observation(Some(&pool), Some(0), &failure).is_none());
            assert!(matches!(
                apply_backend_health_observation(Some(&pool), Some(0), &failure),
                Some(HealthTransition::BecameUnhealthy)
            ));

            let success = BackendHealthObservation {
                identity: BackendIdentity::new("127.0.0.1:8080"),
                source: BackendHealthObservationSource::PassiveRequest,
                outcome: BackendHealthObservationOutcome::Success,
                reason: None,
            };
            let transition = apply_backend_health_observation(Some(&pool), Some(0), &success);
            assert!(
                transition.is_none(),
                "passive success should not invent a recovery transition on its own"
            );
            assert!(
                !pool.read().expect("read").is_backend_healthy(0),
                "pool should remain unhealthy until the proper recovery path runs"
            );
        }
    }

    mod request_feedback_application {
        use std::{collections::HashMap, sync::Arc, time::Duration};

        use impulse_lb::health::HealthTransition;

        use super::super::{
            super::test_support::{test_active_health_upstream_pool, test_upstream_pool},
            apply_backend_request_accounting, apply_backend_request_feedback,
            evaluate_active_health_check,
        };
        use crate::runtime::backend::{
            event::{BackendHealthObservationOutcome, BackendRequestFeedback},
            lifecycle::BackendLifecycleCoordinator,
            resolution::RuntimeBackendResolution,
            state::{BackendHealthState, BackendIdentity},
            store::RuntimeBackendResolutionStore,
        };

        #[test]
        fn request_feedback_applier_marks_backend_unhealthy_after_failure_threshold() {
            let pool = test_upstream_pool();
            let feedback = BackendRequestFeedback::failure(
                BackendIdentity::new("127.0.0.1:8080"),
                Duration::from_millis(10),
                Some(503),
                Some(impulse_lb::health::HealthFailureReason::HttpStatus5xx),
            );
            assert!(apply_backend_request_feedback(Some(&pool), Some(0), &feedback).is_none());
            assert!(apply_backend_request_feedback(Some(&pool), Some(0), &feedback).is_none());
            let unhealthy = apply_backend_request_feedback(Some(&pool), Some(0), &feedback);
            assert!(matches!(unhealthy, Some(HealthTransition::BecameUnhealthy)));
        }

        #[test]
        fn request_feedback_success_keeps_backend_healthy_without_transition() {
            let pool = test_upstream_pool();
            let feedback = BackendRequestFeedback::from_status(
                BackendIdentity::new("127.0.0.1:8080"),
                Duration::from_millis(10),
                http::StatusCode::OK,
            );

            let transition = apply_backend_request_feedback(Some(&pool), Some(0), &feedback);
            assert!(
                transition.is_none(),
                "healthy request completion should not invent a transition"
            );
            assert!(
                pool.read().expect("read").is_backend_healthy(0),
                "success feedback must preserve healthy state"
            );
        }

        #[test]
        fn request_feedback_client_error_is_neutral_for_health() {
            let pool = test_upstream_pool();
            let feedback = BackendRequestFeedback::from_status(
                BackendIdentity::new("127.0.0.1:8080"),
                Duration::from_millis(10),
                http::StatusCode::NOT_FOUND,
            );

            let transition = apply_backend_request_feedback(Some(&pool), Some(0), &feedback);
            assert!(
                transition.is_none(),
                "client errors should not mutate backend health"
            );
            assert!(
                pool.read().expect("read").is_backend_healthy(0),
                "neutral feedback must leave pool health unchanged"
            );
        }

        #[test]
        fn request_feedback_timeout_and_transport_failures_share_health_effect_contract() {
            let timeout_pool = test_upstream_pool();
            let timeout_feedback = BackendRequestFeedback::failure(
                BackendIdentity::new("127.0.0.1:8080"),
                Duration::from_millis(100),
                None,
                Some(impulse_lb::health::HealthFailureReason::Timeout),
            );
            assert!(
                apply_backend_request_feedback(Some(&timeout_pool), Some(0), &timeout_feedback)
                    .is_none()
            );
            assert!(
                apply_backend_request_feedback(Some(&timeout_pool), Some(0), &timeout_feedback)
                    .is_none()
            );
            let timeout_transition =
                apply_backend_request_feedback(Some(&timeout_pool), Some(0), &timeout_feedback);
            assert!(matches!(
                timeout_transition,
                Some(HealthTransition::BecameUnhealthy)
            ));

            let transport_pool = test_upstream_pool();
            let transport_feedback = BackendRequestFeedback::failure(
                BackendIdentity::new("127.0.0.1:8080"),
                Duration::from_millis(100),
                None,
                Some(impulse_lb::health::HealthFailureReason::Transport),
            );
            assert!(
                apply_backend_request_feedback(Some(&transport_pool), Some(0), &transport_feedback)
                    .is_none()
            );
            assert!(
                apply_backend_request_feedback(Some(&transport_pool), Some(0), &transport_feedback)
                    .is_none()
            );
            let transport_transition =
                apply_backend_request_feedback(Some(&transport_pool), Some(0), &transport_feedback);
            assert!(matches!(
                transport_transition,
                Some(HealthTransition::BecameUnhealthy)
            ));
        }

        #[test]
        fn request_feedback_without_reason_does_not_change_health() {
            let pool = test_upstream_pool();
            let feedback = BackendRequestFeedback::failure(
                BackendIdentity::new("127.0.0.1:8080"),
                Duration::from_millis(25),
                Some(503),
                None,
            );

            let transition = apply_backend_request_feedback(Some(&pool), Some(0), &feedback);
            assert!(
                transition.is_none(),
                "failure feedback without a mapped health reason must not mutate health"
            );
            assert!(
                pool.read().expect("read").is_backend_healthy(0),
                "reasonless failure feedback should stay a no-op for health"
            );
            let runtime = pool
                .read()
                .expect("read")
                .backend_runtime_state(0)
                .expect("backend state");
            assert!(
                runtime
                    .ewma_latency_ms
                    .is_some_and(|latency| latency >= 1_000.0)
            );
        }

        #[test]
        fn request_accounting_applier_finishes_inflight_request() {
            let pool = test_upstream_pool();
            {
                let guard = pool.read().expect("read");
                assert!(guard.begin_request_if_healthy(0));
            }

            apply_backend_request_accounting(
                Some(&pool),
                Some(0),
                Duration::from_millis(15),
                Some(200),
            );

            let guard = pool.read().expect("read");
            let state = guard.backend_runtime_state(0).expect("backend state");
            assert_eq!(state.active_requests, 0);
            assert!(state.ewma_latency_ms.is_some());
        }

        #[test]
        fn request_feedback_failure_penalizes_latency_even_with_active_health_checks() {
            let pool = test_active_health_upstream_pool();
            let feedback = BackendRequestFeedback::failure(
                BackendIdentity::new("127.0.0.1:8080"),
                Duration::from_millis(10),
                Some(503),
                Some(impulse_lb::health::HealthFailureReason::HttpStatus5xx),
            );

            let transition = apply_backend_request_feedback(Some(&pool), Some(0), &feedback);

            assert!(transition.is_none());
            let runtime = pool
                .read()
                .expect("read")
                .backend_runtime_state(0)
                .expect("backend state");
            assert!(runtime.healthy);
            assert!(
                runtime
                    .ewma_latency_ms
                    .is_some_and(|latency| latency >= 1_000.0)
            );
        }

        #[test]
        fn request_feedback_coordinator_inventory_tracks_timeout_failures() {
            let pool = test_upstream_pool();
            let store = Arc::new(RuntimeBackendResolutionStore::new([
                RuntimeBackendResolution::hostname(
                    "127.0.0.1:8080".to_string(),
                    "backend.internal".to_string(),
                    8080,
                ),
            ]));
            let coordinator = BackendLifecycleCoordinator::new(store);
            let mut pools = HashMap::new();
            pools.insert("api".to_string(), Arc::clone(&pool));

            let feedback = BackendRequestFeedback::failure(
                BackendIdentity::new("127.0.0.1:8080"),
                Duration::from_millis(10),
                None,
                Some(impulse_lb::health::HealthFailureReason::Timeout),
            );
            assert!(apply_backend_request_feedback(Some(&pool), Some(0), &feedback).is_none());
            assert!(apply_backend_request_feedback(Some(&pool), Some(0), &feedback).is_none());
            let transition = apply_backend_request_feedback(Some(&pool), Some(0), &feedback);
            assert!(matches!(
                transition,
                Some(HealthTransition::BecameUnhealthy)
            ));

            let inventory = coordinator.snapshot_inventory(&pools);
            let backend = inventory
                .backends
                .iter()
                .find(|backend| backend.identity.backend_addr == "127.0.0.1:8080")
                .expect("backend inventory");
            assert!(matches!(
                backend.health,
                BackendHealthState::Unhealthy { reason: None }
            ));
            assert!(
                !backend.placements[0].healthy,
                "coordinator inventory must reflect the pool mutation contract instead of caller-local branching"
            );
        }

        #[test]
        fn coordinator_request_feedback_updates_inventory_consistently() {
            let pool = test_upstream_pool();
            let store = Arc::new(RuntimeBackendResolutionStore::new([
                RuntimeBackendResolution::hostname(
                    "127.0.0.1:8080".to_string(),
                    "backend.internal".to_string(),
                    8080,
                ),
            ]));
            let coordinator = BackendLifecycleCoordinator::new(store);
            let mut pools = HashMap::new();
            pools.insert("api".to_string(), Arc::clone(&pool));

            let transition = apply_backend_request_feedback(
                Some(&pool),
                Some(0),
                &BackendRequestFeedback::failure(
                    BackendIdentity::new("127.0.0.1:8080"),
                    Duration::from_millis(10),
                    Some(503),
                    Some(impulse_lb::health::HealthFailureReason::HttpStatus5xx),
                ),
            );
            assert!(transition.is_none());

            let transition = apply_backend_request_feedback(
                Some(&pool),
                Some(0),
                &BackendRequestFeedback::failure(
                    BackendIdentity::new("127.0.0.1:8080"),
                    Duration::from_millis(10),
                    Some(503),
                    Some(impulse_lb::health::HealthFailureReason::HttpStatus5xx),
                ),
            );
            assert!(transition.is_none());

            let transition = apply_backend_request_feedback(
                Some(&pool),
                Some(0),
                &BackendRequestFeedback::failure(
                    BackendIdentity::new("127.0.0.1:8080"),
                    Duration::from_millis(10),
                    Some(503),
                    Some(impulse_lb::health::HealthFailureReason::HttpStatus5xx),
                ),
            );
            assert!(matches!(
                transition,
                Some(HealthTransition::BecameUnhealthy)
            ));

            let inventory = coordinator.snapshot_inventory(&pools);
            let backend = inventory
                .backends
                .iter()
                .find(|backend| backend.identity.backend_addr == "127.0.0.1:8080")
                .expect("backend inventory");
            assert!(matches!(
                backend.health,
                BackendHealthState::Unhealthy { .. }
            ));
            assert!(!backend.placements[0].healthy);
            assert_eq!(inventory.summary().healthy_backends, 0);
        }

        #[test]
        fn request_feedback_does_not_duplicate_active_health_check_ownership() {
            let pool = test_active_health_upstream_pool();
            let store = Arc::new(RuntimeBackendResolutionStore::new([
                RuntimeBackendResolution::hostname(
                    "127.0.0.1:8080".to_string(),
                    "backend.internal".to_string(),
                    8080,
                ),
            ]));
            let coordinator = BackendLifecycleCoordinator::new(store);
            let mut pools = HashMap::new();
            pools.insert("api".to_string(), Arc::clone(&pool));

            let transition = apply_backend_request_feedback(
                Some(&pool),
                Some(0),
                &BackendRequestFeedback::failure(
                    BackendIdentity::new("127.0.0.1:8080"),
                    Duration::from_millis(10),
                    Some(503),
                    Some(impulse_lb::health::HealthFailureReason::HttpStatus5xx),
                ),
            );
            assert!(transition.is_none());
            assert_eq!(
                coordinator
                    .snapshot_inventory(&pools)
                    .summary()
                    .healthy_backends,
                1
            );

            let failure = evaluate_active_health_check(
                BackendIdentity::new("127.0.0.1:8080"),
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
            assert_eq!(
                coordinator
                    .snapshot_inventory(&pools)
                    .summary()
                    .healthy_backends,
                0
            );
        }
    }
}
