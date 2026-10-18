use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use impulse_config::{
    BackendEndpoint,
    runtime::{RuntimeBackendHealthCheck, RuntimeBackendTlsPolicy},
};
use impulse_lb::{
    health::HealthFailureReason,
    pingora_backend::{
        HealthCheckService, PingoraBackend, PingoraBackendIdentity, PingoraHealthCheck,
        PingoraHttpHealthCheck, SharedPingoraLoadBalancingRuntimeState,
    },
    upstream_pool::UpstreamPool,
};
use impulse_transport::UpstreamTransportPool;
use pingora_core::{Error, ErrorType, Result as PingoraResult};
use pingora_http::RequestHeader;

use super::{QUICListener, runtime_handle, spawn_supervised_async_task};
use crate::{
    Metrics,
    runtime::{
        backend::{
            event::BackendHealthObservationOutcome,
            lifecycle::{
                ActiveHealthCheckEvaluation, BackendLifecycleCoordinator,
                evaluate_active_health_check,
            },
            state::BackendIdentity,
        },
        connection::outcome::record_classified_backend_failure_metrics,
        tasks::RuntimeTaskRegistry,
    },
};

struct PingoraHealthTarget {
    upstream_pool: Arc<RwLock<UpstreamPool>>,
    backend_index: usize,
    policy: RuntimeBackendHealthCheck,
}

struct PingoraProbeSchedule {
    next_due_at: Instant,
    consecutive_failures: u32,
}

struct ImpulsePingoraHealthCheck {
    generation: u64,
    targets: HashMap<String, PingoraHealthTarget>,
    schedules: Mutex<HashMap<String, PingoraProbeSchedule>>,
    transport_pool: Arc<UpstreamTransportPool>,
    backend_lifecycle: Arc<BackendLifecycleCoordinator>,
    metrics: Arc<Metrics>,
}

impl ImpulsePingoraHealthCheck {
    fn new(
        generation: u64,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
        policies: &HashMap<String, RuntimeBackendHealthCheck>,
        transport_pool: Arc<UpstreamTransportPool>,
        backend_lifecycle: Arc<BackendLifecycleCoordinator>,
        metrics: Arc<Metrics>,
    ) -> Self {
        let mut targets = HashMap::new();
        let mut schedules = HashMap::new();
        for upstream_pool in upstream_pools.values() {
            let Ok(pool) = upstream_pool.read() else {
                continue;
            };
            for backend_index in pool.backend_indices() {
                let Some(backend) = pool.backend_address(backend_index) else {
                    continue;
                };
                let Some(policy) = policies.get(backend) else {
                    continue;
                };
                let backend = backend.to_string();
                let interval_ms = u64::try_from(policy.interval.as_millis())
                    .unwrap_or(u64::MAX)
                    .max(1);
                let initial_jitter_ms = if interval_ms > 1 {
                    crate::stable_hash64(backend.as_bytes()) % interval_ms
                } else {
                    0
                };
                targets
                    .entry(backend.clone())
                    .or_insert_with(|| PingoraHealthTarget {
                        upstream_pool: Arc::clone(upstream_pool),
                        backend_index,
                        policy: policy.clone(),
                    });
                schedules.entry(backend).or_insert(PingoraProbeSchedule {
                    next_due_at: Instant::now() + Duration::from_millis(initial_jitter_ms),
                    consecutive_failures: 0,
                });
            }
        }
        Self {
            generation,
            targets,
            schedules: Mutex::new(schedules),
            transport_pool,
            backend_lifecycle,
            metrics,
        }
    }

    fn current_health(target: &PingoraHealthTarget) -> bool {
        target
            .upstream_pool
            .read()
            .ok()
            .and_then(|pool| pool.backend_runtime_state(target.backend_index))
            .is_some_and(|state| state.healthy)
    }

    fn health_result(backend: &str, healthy: bool) -> PingoraResult<()> {
        if healthy {
            Ok(())
        } else {
            Error::e_explain(
                ErrorType::Custom("impulse backend health"),
                format!("backend '{backend}' remains unhealthy under Impulse health policy"),
            )
        }
    }

    async fn probe(
        &self,
        backend: &str,
        target: &PingoraBackend,
        policy: &RuntimeBackendHealthCheck,
    ) -> PingoraResult<()> {
        let endpoint = BackendEndpoint::parse(backend).map_err(|error| {
            Error::explain(
                ErrorType::Custom("impulse health configuration"),
                format!("invalid health-check backend '{backend}': {error}"),
            )
        })?;
        let mut peer = self
            .transport_pool
            .pingora_peer(backend, self.generation)
            .map_err(|error| {
                Error::explain(ErrorType::Custom("impulse health peer"), error.to_string())
            })?;
        peer.options.connection_timeout = Some(policy.timeout);
        peer.options.read_timeout = Some(policy.timeout);

        let mut check = PingoraHttpHealthCheck::new(endpoint.authority_host(), peer.is_tls());
        check.peer_template = peer;
        let mut request = RequestHeader::build("GET", policy.path.as_bytes(), None)?;
        request.append_header("Host", endpoint.authority_host())?;
        check.req = request;
        check.validator = Some(Box::new(|response| {
            if response.status.is_success() {
                Ok(())
            } else {
                Error::e_explain(
                    ErrorType::CustomCode("health check status", response.status.as_u16()),
                    "upstream returned a non-success health-check status",
                )
            }
        }));
        check.check(target).await
    }

    fn record_observation(
        &self,
        backend: &str,
        target: &PingoraHealthTarget,
        result: &PingoraResult<()>,
        consecutive_failures: u32,
    ) -> ActiveHealthCheckEvaluation {
        let base_interval_ms = u64::try_from(target.policy.interval.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let evaluation = match result {
            Ok(()) => evaluate_active_health_check(
                BackendIdentity::new(backend.to_string()),
                BackendHealthObservationOutcome::Success,
                None,
                base_interval_ms,
                consecutive_failures,
            ),
            Err(error) => {
                let proxy_error = impulse_transport::classify_pingora_h1_error(error);
                let reason = impulse_errors::classify_upstream_proxy_error(&proxy_error)
                    .and_then(|classified| {
                        record_classified_backend_failure_metrics(
                            "health_check",
                            "unknown",
                            backend,
                            self.metrics.as_ref(),
                            &classified,
                        )
                    })
                    .or_else(|| {
                        self.metrics
                            .inc_health_failure(HealthFailureReason::Transport);
                        Some(HealthFailureReason::Transport)
                    });
                evaluate_active_health_check(
                    BackendIdentity::new(backend.to_string()),
                    BackendHealthObservationOutcome::Failure,
                    reason,
                    base_interval_ms,
                    consecutive_failures,
                )
            }
        };

        let transition = self.backend_lifecycle.apply_health_observation(
            Some(&target.upstream_pool),
            Some(target.backend_index),
            &evaluation.observation,
        );
        match evaluation.observation.outcome {
            BackendHealthObservationOutcome::Success => self.metrics.inc_health_check_success(),
            BackendHealthObservationOutcome::Failure => self.metrics.inc_health_check_failure(),
            BackendHealthObservationOutcome::Neutral => {}
        }
        let _ = crate::runtime::connection::outcome::log_backend_health_transition_result(
            backend, transition,
        );
        evaluation
    }
}

#[async_trait]
impl PingoraHealthCheck for ImpulsePingoraHealthCheck {
    async fn check(&self, backend: &PingoraBackend) -> PingoraResult<()> {
        let identity = backend
            .ext
            .get::<PingoraBackendIdentity<RuntimeBackendTlsPolicy>>()
            .ok_or_else(|| {
                Error::explain(
                    ErrorType::Custom("impulse health identity"),
                    "Pingora backend has no Impulse health identity",
                )
            })?;
        let configured_address = identity.configured_address();
        let Some(target) = self.targets.get(configured_address) else {
            return Ok(());
        };

        let consecutive_failures = {
            let mut schedules = self
                .schedules
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let schedule = schedules
                .get_mut(configured_address)
                .expect("configured health target has a probe schedule");
            if Instant::now() < schedule.next_due_at {
                return Self::health_result(configured_address, Self::current_health(target));
            }
            schedule.consecutive_failures
        };

        let result = self
            .probe(configured_address, backend, &target.policy)
            .await;
        let evaluation =
            self.record_observation(configured_address, target, &result, consecutive_failures);
        let mut schedules = self
            .schedules
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let schedule = schedules
            .get_mut(configured_address)
            .expect("configured health target has a probe schedule");
        schedule.consecutive_failures = evaluation.next_consecutive_failures;
        schedule.next_due_at = Instant::now() + evaluation.next_delay;
        // Publish the post-policy state so Pingora does not bypass Impulse thresholds or cooldowns.
        Self::health_result(configured_address, Self::current_health(target))
    }

    fn backend_summary(&self, backend: &PingoraBackend) -> String {
        backend
            .ext
            .get::<PingoraBackendIdentity<RuntimeBackendTlsPolicy>>()
            .map_or_else(
                || format!("backend={}", backend.addr),
                |identity| format!("backend={}", identity.configured_address()),
            )
    }

    fn health_threshold(&self, _success: bool) -> usize {
        1
    }
}

impl QUICListener {
    pub(super) fn spawn_pingora_health_service(
        generation: u64,
        upstream_pools: HashMap<String, Arc<RwLock<UpstreamPool>>>,
        transport_pool: Arc<UpstreamTransportPool>,
        backend_health_checks: Arc<HashMap<String, RuntimeBackendHealthCheck>>,
        pingora_load_balancing: SharedPingoraLoadBalancingRuntimeState<RuntimeBackendTlsPolicy>,
        backend_lifecycle: Arc<BackendLifecycleCoordinator>,
        metrics: Arc<Metrics>,
        generation_tasks: Arc<RuntimeTaskRegistry>,
    ) {
        let Some(frequency) = backend_health_checks
            .values()
            .map(|health| health.interval)
            .min()
        else {
            return;
        };
        let Some(registry) = pingora_load_balancing.health_registry() else {
            log::error!("Pingora health service disabled: no shared health registry");
            return;
        };
        registry.set_health_check(Box::new(ImpulsePingoraHealthCheck::new(
            generation,
            &upstream_pools,
            backend_health_checks.as_ref(),
            transport_pool,
            backend_lifecycle,
            metrics.clone(),
        )));

        let Some(handle) = runtime_handle() else {
            log::error!("Pingora health service disabled: no Tokio runtime available");
            return;
        };
        let mut service = HealthCheckService::new(registry);
        service.health_check_frequency = Some(frequency);
        service.parallel_health_check = true;
        let (shutdown_tx, shutdown_watch) = tokio::sync::watch::channel(false);
        let registration = spawn_supervised_async_task(
            &handle,
            "pingora-health-service",
            Some(metrics),
            async move {
                service.run(shutdown_watch, None).await;
                drop(shutdown_tx);
            },
        );
        generation_tasks.register(registration);
    }
}
