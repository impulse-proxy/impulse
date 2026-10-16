use impulse_errors::classify_upstream_proxy_error;

use super::*;
use crate::runtime::{
    backend::{
        event::BackendHealthObservationOutcome,
        lifecycle::{
            ActiveHealthCheckEvaluation, BackendLifecycleCoordinator, evaluate_active_health_check,
        },
        state::BackendIdentity,
    },
    connection::outcome::record_classified_backend_failure_metrics,
};

impl QUICListener {
    pub(super) fn spawn_health_checks(
        upstream_pools: HashMap<String, Arc<RwLock<UpstreamPool>>>,
        transport_pool: Arc<UpstreamTransportPool>,
        backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
        backend_health_checks: Arc<
            HashMap<String, impulse_config::runtime::RuntimeBackendHealthCheck>,
        >,
        backend_lifecycle: Arc<BackendLifecycleCoordinator>,
        metrics: Arc<Metrics>,
        task_registry: Arc<RuntimeTaskRegistry>,
    ) {
        struct HealthCheckJob {
            upstream_pool: Arc<RwLock<UpstreamPool>>,
            index: usize,
            // Stable configured backend identity. DNS refresh changes connect targets
            // underneath this identity without changing health ownership.
            backend_identity: String,
            health_uri: String,
            base_interval_ms: u64,
            timeout: Duration,
            consecutive_failures: u32,
            next_due_at: Instant,
        }

        let mut grouped_jobs: HashMap<u64, Vec<HealthCheckJob>> = HashMap::new();
        #[allow(clippy::for_kv_map)]
        for (_upstream_name, upstream_pool) in upstream_pools.iter() {
            let pool = match upstream_pool.read() {
                Ok(pool) => pool,
                Err(_) => continue,
            };
            for index in pool.backend_indices() {
                let Some(address) = pool.backend_address(index).map(str::to_string) else {
                    continue;
                };
                let Some(health) = backend_health_checks.get(&address) else {
                    continue;
                };
                let endpoint = match backend_endpoints.get(&address) {
                    Some(endpoint) => endpoint,
                    None => {
                        error!(
                            "disabling health checks for backend '{}' due to missing canonical endpoint",
                            address
                        );
                        continue;
                    }
                };
                let base_interval_ms: u64 = health
                    .interval
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX)
                    .max(1);
                let initial_jitter_ms = if base_interval_ms > 1 {
                    crate::stable_hash64(address.as_bytes()) % base_interval_ms
                } else {
                    0
                };
                let next_due_at = Instant::now() + Duration::from_millis(initial_jitter_ms);
                let job = HealthCheckJob {
                    upstream_pool: Arc::clone(upstream_pool),
                    index,
                    backend_identity: address,
                    health_uri: endpoint.uri_for_path(&health.path),
                    base_interval_ms,
                    timeout: health.timeout,
                    consecutive_failures: 0,
                    next_due_at,
                };
                grouped_jobs.entry(base_interval_ms).or_default().push(job);
            }
        }

        if grouped_jobs.is_empty() {
            return;
        }

        let handle = match runtime_handle() {
            Some(handle) => handle,
            None => {
                error!("Health checks disabled: no Tokio runtime available");
                return;
            }
        };

        for (base_interval_ms, mut jobs) in grouped_jobs {
            let transport_pool = Arc::clone(&transport_pool);
            let backend_lifecycle = Arc::clone(&backend_lifecycle);
            let task_metrics = Arc::clone(&metrics);
            let handle = handle.clone();
            let supervise_metrics = Arc::clone(&task_metrics);
            let registration = spawn_supervised_async_task(
                &handle,
                "health-check-group",
                Some(supervise_metrics),
                async move {
                    let scheduler_tick_ms = (base_interval_ms / 4).clamp(20, base_interval_ms);
                    let mut ticker =
                        tokio::time::interval(Duration::from_millis(scheduler_tick_ms.max(1)));
                    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                    loop {
                        ticker.tick().await;
                        let now = Instant::now();
                        let mut pending = tokio::task::JoinSet::new();
                        let mut pending_job_indices = HashMap::new();
                        for (job_index, job) in jobs.iter_mut().enumerate() {
                            if now < job.next_due_at {
                                continue;
                            }

                            let health_uri = match job.health_uri.parse() {
                                Ok(uri) => uri,
                                Err(_) => continue,
                            };

                            let backend_identity = job.backend_identity.clone();
                            let timeout = job.timeout;
                            let transport_pool = Arc::clone(&transport_pool);
                            let task = pending.spawn(async move {
                                transport_pool
                                    .send_health_check(&backend_identity, health_uri, timeout)
                                    .await
                            });
                            pending_job_indices.insert(task.id(), job_index);
                        }

                        while let Some(joined) = pending.join_next_with_id().await {
                            let (task_id, result) = match joined {
                                Ok(completed) => completed,
                                Err(join_error) => {
                                    let task_id = join_error.id();
                                    let Some(job_index) = pending_job_indices.remove(&task_id)
                                    else {
                                        error!(
                                            "health check task failed without a scheduler job mapping: {}",
                                            join_error
                                        );
                                        continue;
                                    };
                                    let job = &mut jobs[job_index];
                                    let evaluation = Self::evaluate_interrupted_health_check(
                                        &job.backend_identity,
                                        job.base_interval_ms,
                                        job.consecutive_failures,
                                    );
                                    job.consecutive_failures = evaluation.next_consecutive_failures;
                                    job.next_due_at = Instant::now() + evaluation.next_delay;
                                    task_metrics.inc_health_check_failure();
                                    error!(
                                        "health check task failed backend='{}' cancelled={} panicked={} retry_delay_ms={}: {}",
                                        job.backend_identity,
                                        join_error.is_cancelled(),
                                        join_error.is_panic(),
                                        evaluation.next_delay.as_millis(),
                                        join_error
                                    );
                                    continue;
                                }
                            };
                            let Some(job_index) = pending_job_indices.remove(&task_id) else {
                                error!("completed health check task missing scheduler job mapping");
                                continue;
                            };
                            let job = &mut jobs[job_index];

                            let evaluation = match result {
                                Ok(response) => {
                                    let outcome =
                                        match classify_active_health_check_response(response) {
                                            HealthClassification::Success => {
                                                BackendHealthObservationOutcome::Success
                                            }
                                            HealthClassification::Failure => {
                                                BackendHealthObservationOutcome::Failure
                                            }
                                            HealthClassification::Neutral => {
                                                BackendHealthObservationOutcome::Neutral
                                            }
                                        };
                                    evaluate_active_health_check(
                                        BackendIdentity::new(job.backend_identity.clone()),
                                        outcome,
                                        None,
                                        job.base_interval_ms,
                                        job.consecutive_failures,
                                    )
                                }
                                Err(proxy_err) => {
                                    let failure_reason = if matches!(proxy_err, ProxyError::Timeout)
                                    {
                                        HealthFailureReason::Timeout
                                    } else {
                                        HealthFailureReason::Transport
                                    };
                                    Self::evaluate_failed_health_check(
                                        &job.backend_identity,
                                        task_metrics.as_ref(),
                                        job.base_interval_ms,
                                        job.consecutive_failures,
                                        proxy_err,
                                        failure_reason,
                                    )
                                }
                            };

                            let transition = backend_lifecycle.apply_health_observation(
                                Some(&job.upstream_pool),
                                Some(job.index),
                                &evaluation.observation,
                            );

                            match evaluation.observation.outcome {
                                BackendHealthObservationOutcome::Success => {
                                    task_metrics.inc_health_check_success();
                                }
                                BackendHealthObservationOutcome::Failure => {
                                    task_metrics.inc_health_check_failure();
                                }
                                BackendHealthObservationOutcome::Neutral => {}
                            }

                            job.consecutive_failures = evaluation.next_consecutive_failures;
                            job.next_due_at = Instant::now() + evaluation.next_delay;

                            let _ = crate::runtime::connection::outcome::log_backend_health_transition_result(
                                &job.backend_identity,
                                transition,
                            );
                        }
                    }
                },
            );
            task_registry.register(registration);
        }
    }
}

pub(super) fn classify_active_health_check_response(status: StatusCode) -> HealthClassification {
    outcome_from_status(status)
}

impl QUICListener {
    fn evaluate_failed_health_check(
        backend_identity: &str,
        metrics: &Metrics,
        base_interval_ms: u64,
        consecutive_failures: u32,
        proxy_error: ProxyError,
        fallback_reason: HealthFailureReason,
    ) -> ActiveHealthCheckEvaluation {
        let reason = if let Some(classified) = classify_upstream_proxy_error(&proxy_error) {
            Self::log_classified_upstream_failure(
                "health_check",
                None,
                None,
                backend_identity,
                &classified,
            );
            record_classified_backend_failure_metrics(
                "health_check",
                "unknown",
                backend_identity,
                metrics,
                &classified,
            )
        } else {
            metrics.inc_health_failure(fallback_reason);
            Some(fallback_reason)
        };

        evaluate_active_health_check(
            BackendIdentity::new(backend_identity.to_string()),
            BackendHealthObservationOutcome::Failure,
            reason,
            base_interval_ms,
            consecutive_failures,
        )
    }

    fn evaluate_interrupted_health_check(
        backend_identity: &str,
        base_interval_ms: u64,
        consecutive_failures: u32,
    ) -> ActiveHealthCheckEvaluation {
        // A JoinError is an internal execution failure, not evidence that the
        // backend itself is unhealthy. Reuse the canonical failure schedule for
        // bounded backoff, but do not apply this observation to backend state.
        evaluate_active_health_check(
            BackendIdentity::new(backend_identity.to_string()),
            BackendHealthObservationOutcome::Failure,
            None,
            base_interval_ms,
            consecutive_failures,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use impulse_errors::{PoolError, ProxyError};
    use impulse_lb::health::HealthFailureReason;

    use super::*;

    #[test]
    fn timeout_health_check_failures_remain_mapped_to_timeout_reason() {
        let metrics = Metrics::default();

        let evaluation = QUICListener::evaluate_failed_health_check(
            "http://backend-a",
            &metrics,
            1_000,
            0,
            ProxyError::Timeout,
            HealthFailureReason::Timeout,
        );

        assert_eq!(
            evaluation.observation.outcome,
            BackendHealthObservationOutcome::Failure
        );
        assert_eq!(
            evaluation.observation.reason,
            Some(HealthFailureReason::Timeout),
            "timeout health checks must keep the canonical timeout failure mapping after lint cleanup"
        );
        assert_eq!(evaluation.next_consecutive_failures, 1);
        assert_eq!(metrics.health_failure_timeout.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.health_failure_transport.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn unclassified_health_check_failures_fall_back_to_supplied_reason() {
        let metrics = Metrics::default();

        let evaluation = QUICListener::evaluate_failed_health_check(
            "http://backend-a",
            &metrics,
            1_000,
            2,
            ProxyError::Pool(PoolError::UnknownBackend("backend-a".to_string())),
            HealthFailureReason::Transport,
        );

        assert_eq!(
            evaluation.observation.outcome,
            BackendHealthObservationOutcome::Failure
        );
        assert_eq!(
            evaluation.observation.reason,
            Some(HealthFailureReason::Transport),
            "health checks must still emit the fallback transport reason when proxy classification is unavailable"
        );
        assert_eq!(evaluation.next_consecutive_failures, 3);
        assert_eq!(metrics.health_failure_transport.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.health_failure_timeout.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn interrupted_health_check_advances_failure_backoff_without_backend_reason() {
        let first = QUICListener::evaluate_interrupted_health_check("http://backend-a", 1_000, 0);
        assert_eq!(first.next_consecutive_failures, 1);
        assert_eq!(first.next_delay, Duration::from_millis(2_000));
        assert_eq!(
            first.observation.outcome,
            BackendHealthObservationOutcome::Failure
        );
        assert_eq!(first.observation.reason, None);

        let repeated = QUICListener::evaluate_interrupted_health_check(
            "http://backend-a",
            1_000,
            first.next_consecutive_failures,
        );
        assert_eq!(repeated.next_consecutive_failures, 2);
        assert_eq!(repeated.next_delay, Duration::from_millis(4_000));
    }
}
