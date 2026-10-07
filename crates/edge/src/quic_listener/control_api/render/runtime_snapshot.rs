use bytes::Bytes;
use http_body_util::Full;
use serde::Serialize;

use super::{
    super::audit::ControlApiAdminAuditTarget,
    redaction::sanitize_path,
    secrets_jwks::{build_auth_and_jwks_payloads, build_secrets_payload, build_tls_upstreams},
    *,
};
use crate::runtime::policy::RuntimeLifecyclePhase;

impl QUICListener {
    pub(in crate::quic_listener::control_api) fn json_response<T>(
        status: StatusCode,
        value: T,
    ) -> Response<Full<Bytes>>
    where
        T: Serialize,
    {
        let body = match serde_json::to_vec(&value) {
            Ok(body) => body,
            Err(_) => br#"{"error":"response"}"#.to_vec(),
        };
        match Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body)))
        {
            Ok(resp) => resp,
            Err(_) => Response::new(Full::new(Bytes::from_static(b"{\"error\":\"response\"}"))),
        }
    }

    pub(in crate::quic_listener::control_api) fn render_control_api_health(
        state: &ControlApiState,
    ) -> Response<Full<Bytes>> {
        let runtime_state = state.current_service_state();
        let watchdog = runtime_state.watchdog();
        let payload = ControlApiHealthPayload {
            status: "ok",
            uptime_ms: state.started_at.elapsed().as_millis() as u64,
            watchdog: ControlApiHealthWatchdogPayload {
                enabled: watchdog.enabled(),
                degraded: watchdog.is_degraded(),
                restart_requested: watchdog.restart_requested(),
            },
        };
        Self::json_response(StatusCode::OK, payload)
    }

    pub(in crate::quic_listener::control_api) fn render_control_api_ready(
        state: &ControlApiState,
    ) -> Response<Full<Bytes>> {
        let runtime_state = state.current_service_state();
        let backend_summary = runtime_state.snapshot_backend_health();
        let restart_requested = runtime_state.watchdog().restart_requested();
        let shutdown_requested = runtime_state.runtime_bundle_handle().is_some_and(|handle| {
            matches!(
                handle.lifecycle().phase(),
                RuntimeLifecyclePhase::ShuttingDown | RuntimeLifecyclePhase::Terminated
            )
        });
        let payload = ControlApiReadyPayload {
            ready: !restart_requested
                && !shutdown_requested
                && (backend_summary.total_backends == 0 || backend_summary.healthy_backends > 0),
            healthy_backends: backend_summary.healthy_backends,
            total_backends: backend_summary.total_backends,
            restart_requested,
        };
        Self::json_response(
            if payload.ready {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            },
            payload,
        )
    }

    pub(in crate::quic_listener::control_api) fn render_control_api_runtime_snapshot(
        state: &ControlApiState,
    ) -> Response<Full<Bytes>> {
        let payload = ControlApiRuntimePayload::from_state(state);
        Self::json_response(StatusCode::OK, payload)
    }

    pub(in crate::quic_listener::control_api) fn render_control_api_runtime_history(
        state: &ControlApiState,
    ) -> Response<Full<Bytes>> {
        let runtime_state = state.current_service_state();
        let Some(runtime_bundle_handle) = runtime_state.runtime_bundle_handle().cloned() else {
            return Self::control_api_not_found_response();
        };
        let backend_inventory = runtime_state.snapshot_backend_inventory();
        let backend_summary = backend_inventory.summary();
        let quota_backend_status = runtime_state.resilience().quota.backend_status_snapshot(
            runtime_state
                .resilience()
                .quota_backend_initialization_error
                .as_ref(),
        );

        Self::json_response(
            StatusCode::OK,
            ControlApiRuntimeHistoryPayload {
                active_generation: runtime_bundle_handle.current_generation(),
                observability: ControlApiObservabilityPayload::from_runtime_state(
                    &runtime_state,
                    &backend_inventory,
                    &backend_summary,
                    &quota_backend_status,
                ),
                retained_generations: runtime_bundle_handle
                    .generation_history()
                    .into_iter()
                    .map(ControlApiRetainedGenerationPayload::from_record)
                    .collect(),
                entries: runtime_bundle_handle.generation_change_history(),
            },
        )
    }

    pub(in crate::quic_listener::control_api) fn render_control_api_runtime_history_generation(
        state: &ControlApiState,
        generation: u64,
    ) -> Response<Full<Bytes>> {
        let runtime_state = state.current_service_state();
        let Some(runtime_bundle_handle) = runtime_state.runtime_bundle_handle().cloned() else {
            return Self::control_api_not_found_response();
        };
        let backend_inventory = runtime_state.snapshot_backend_inventory();
        let backend_summary = backend_inventory.summary();
        let quota_backend_status = runtime_state.resilience().quota.backend_status_snapshot(
            runtime_state
                .resilience()
                .quota_backend_initialization_error
                .as_ref(),
        );

        let entries = runtime_bundle_handle
            .generation_change_history()
            .into_iter()
            .filter(|entry| entry.generation == generation)
            .collect::<Vec<_>>();
        let Some(record) = runtime_bundle_handle.generation_record(generation) else {
            return Self::json_response(
                StatusCode::NOT_FOUND,
                json!({
                    "error": format!("generation {generation} not found in runtime history"),
                }),
            );
        };

        Self::json_response(
            StatusCode::OK,
            ControlApiRuntimeHistoryGenerationPayload {
                generation,
                observability: ControlApiObservabilityPayload::from_runtime_state(
                    &runtime_state,
                    &backend_inventory,
                    &backend_summary,
                    &quota_backend_status,
                ),
                retained_generation: ControlApiRetainedGenerationPayload::from_record(record),
                entries,
            },
        )
    }
}

impl ControlApiRetainedGenerationPayload {
    fn from_record(record: RuntimeGenerationRecord) -> Self {
        Self {
            generation: record.generation(),
            status: record.status().as_str(),
            rollback_candidate: record.status().is_rollback_candidate(),
            has_bundle: record.has_bundle(),
            note: record.note().map(ToOwned::to_owned),
        }
    }
}

impl ControlApiRuntimePayload {
    fn from_state(service_ctx: &ControlApiState) -> Self {
        let state = service_ctx.current_service_state();
        let runtime = &state.runtime;
        let watchdog = state.watchdog();
        let resilience = state.resilience();
        let metrics = state.metrics();
        let listener_tls_store = state.listener_tls_store();
        let listener_tls_states = listener_tls_store.snapshot_states();
        let backend_inventory = state.snapshot_backend_inventory();
        let backend_summary = backend_inventory.summary();
        let quota_backend_status = resilience
            .quota
            .backend_status_snapshot(resilience.quota_backend_initialization_error.as_ref());
        let (auth_providers, jwks) = build_auth_and_jwks_payloads(runtime.runtime_config());

        Self {
            uptime_ms: service_ctx.started_at.elapsed().as_millis() as u64,
            workers: ControlApiWorkerPayload {
                expected: runtime.expected_workers(),
            },
            watchdog: ControlApiRuntimeWatchdogPayload {
                enabled: watchdog.enabled(),
                degraded: watchdog.is_degraded(),
                restart_requested: watchdog.restart_requested(),
                restart_reason: watchdog.restart_reason(),
                restart_requested_at_ms: watchdog.restart_requested_at_ms(),
            },
            adaptive_admission: ControlApiAdaptiveAdmissionPayload {
                enabled: resilience.adaptive_admission.enabled(),
                current_limit: resilience.adaptive_admission.current_limit(),
                inflight_percent: resilience.adaptive_admission.inflight_percent(),
            },
            quota: ControlApiQuotaPayload::from_snapshot(
                resilience.quota.as_ref(),
                quota_backend_status.clone(),
            ),
            observability: ControlApiObservabilityPayload::from_runtime_state(
                &state,
                &backend_inventory,
                &backend_summary,
                &quota_backend_status,
            ),
            auth: ControlApiAuthPayload {
                providers: auth_providers,
                jwt_validation_failures: metrics
                    .snapshot_jwt_validation_failures()
                    .into_iter()
                    .map(|(reason, count)| ControlApiReasonCountPayload { reason, count })
                    .collect(),
                jwt_algorithm_rejections: metrics
                    .snapshot_jwt_algorithm_rejections()
                    .into_iter()
                    .map(|(reason, count)| ControlApiReasonCountPayload { reason, count })
                    .collect(),
                unknown_kid_events: metrics
                    .snapshot_jwks_unknown_kid_events()
                    .into_iter()
                    .map(|(jwks_source_id, count)| ControlApiUnknownKidEventPayload {
                        jwks_source_id,
                        count,
                    })
                    .collect(),
            },
            jwks,
            backends: ControlApiBackendInventoryPayload::from_inventory(
                backend_inventory,
                backend_summary.healthy_backends,
                backend_summary.total_backends,
            ),
            metrics: ControlApiMetricsPayload {
                requests_total: metrics.requests_total.load(Ordering::Relaxed),
                requests_success: metrics.requests_success.load(Ordering::Relaxed),
                requests_failure: metrics.requests_failure.load(Ordering::Relaxed),
                active_connections: metrics.active_connections.load(Ordering::Relaxed),
                backend_timeouts: metrics.backend_timeouts.load(Ordering::Relaxed),
                backend_errors: metrics.backend_errors.load(Ordering::Relaxed),
            },
            tls: ControlApiTlsPayload {
                listeners: listener_tls_states
                    .into_iter()
                    .map(|(listener, inventory)| {
                        (
                            listener.clone(),
                            ControlApiTlsListenerPayload {
                                default_cert: sanitize_path(
                                    &inventory.inventory.default_identity.identity.cert_path,
                                ),
                                default_key: sanitize_path(
                                    &inventory.inventory.default_identity.identity.key_path,
                                ),
                                default_cert_not_after_unix_seconds: inventory
                                    .inventory
                                    .default_identity
                                    .metadata
                                    .not_after_unix_seconds,
                                sni_names: inventory
                                    .inventory
                                    .sni_identities
                                    .keys()
                                    .cloned()
                                    .collect(),
                                client_auth_enabled: inventory
                                    .inventory
                                    .listener_tls
                                    .client_auth
                                    .enabled,
                                require_client_cert: inventory
                                    .inventory
                                    .listener_tls
                                    .client_auth
                                    .require_client_cert,
                                generation: inventory.generation,
                                last_loaded_at_unix_ms: inventory.loaded_at_unix_ms,
                                last_reload_status: inventory.last_reload_status,
                            },
                        )
                    })
                    .collect(),
                upstreams: build_tls_upstreams(runtime.runtime_config()),
            },
            secrets: build_secrets_payload(runtime.runtime_config()),
            extension_model: ControlApiExtensionModelPayload {
                status: "non_goal",
                details: "No plugin/middleware ABI is exposed in-process today; extension support remains a deliberate non-goal until a safe isolation model is designed.",
            },
            runtime: state
                .generation
                .map(|active| ControlApiRuntimeGenerationPayload {
                    generation: active.generation(),
                    config_path: active.startup().config_path.clone(),
                }),
        }
    }
}

impl ControlApiQuotaPayload {
    fn from_snapshot(
        runtime: &crate::resilience::quota::QuotaRuntime,
        backend_status: QuotaBackendStatusSnapshot,
    ) -> Self {
        Self {
            enabled: runtime.enabled,
            enforcement: runtime.enforcement.slug(),
            backend_failure_policy: runtime.backend_failure_policy.slug(),
            active_backend: backend_status.backend_mode.clone(),
            backend_status: ControlApiQuotaBackendStatusPayload::from_snapshot(backend_status),
            policies: runtime
                .policy_snapshots()
                .into_iter()
                .map(ControlApiQuotaPolicyPayload::from_snapshot)
                .collect(),
        }
    }
}

impl ControlApiObservabilityPayload {
    fn from_runtime_state(
        state: &super::context::ControlApiServiceState,
        backend_inventory: &BackendLifecycleInventorySnapshot,
        backend_summary: &crate::runtime::backend::state::BackendLifecycleInventorySummary,
        quota_backend_status: &QuotaBackendStatusSnapshot,
    ) -> Self {
        Self {
            contract_version: OBSERVABILITY_CONTRACT_VERSION,
            audit_schema_version: ADMIN_AUDIT_SCHEMA_VERSION,
            audit_sink: ControlApiAuditSinkPayload {
                enabled: state.security.audit.enabled,
                target: match state.security.audit.sink {
                    ControlApiAdminAuditTarget::Log => "log",
                    ControlApiAdminAuditTarget::File(_) => "file",
                },
                degraded: state.security.audit.delivery_degraded(),
                reason: state.security.audit.delivery_reason(),
            },
            current_generation: state
                .generation
                .as_ref()
                .map(|generation| generation.generation()),
            dashboard_packages: vec![
                ControlApiObservabilityDashboardPayload {
                    dashboard_id: "edge_traffic",
                    definition_path: "deploy/observability/grafana/edge-traffic.json",
                    focus: "edge traffic, status mix, and latency",
                },
                ControlApiObservabilityDashboardPayload {
                    dashboard_id: "admission_overload",
                    definition_path: "deploy/observability/grafana/admission-overload.json",
                    focus: "admission, overload, quota, and auth outcomes",
                },
                ControlApiObservabilityDashboardPayload {
                    dashboard_id: "backend_health",
                    definition_path: "deploy/observability/grafana/backend-health.json",
                    focus: "backend health, dns refresh, and client rotations",
                },
                ControlApiObservabilityDashboardPayload {
                    dashboard_id: "retries_hedges",
                    definition_path: "deploy/observability/grafana/retries-hedges.json",
                    focus: "retry amplification and hedge effectiveness",
                },
                ControlApiObservabilityDashboardPayload {
                    dashboard_id: "tls_certificates",
                    definition_path: "deploy/observability/grafana/tls-certificates.json",
                    focus: "tls handshake failures and certificate expiry",
                },
                ControlApiObservabilityDashboardPayload {
                    dashboard_id: "control_plane",
                    definition_path: "deploy/observability/grafana/control-plane.json",
                    focus: "runtime activity, watchdog state, and control-plane health",
                },
            ],
            backend_health_summary: ControlApiBackendHealthSummaryPayload::from_inventory(
                backend_inventory,
                *backend_summary,
            ),
            quota_backend_health_summary: ControlApiQuotaBackendHealthSummaryPayload::from_snapshot(
                state.resilience().quota.enabled,
                quota_backend_status,
            ),
            recent_admin_actions: state
                .runtime_bundle_handle()
                .map(|handle| {
                    handle
                        .generation_change_events()
                        .into_iter()
                        .take(RECENT_ADMIN_ACTION_LIMIT)
                        .map(ControlApiRecentAdminActionPayload::from_event)
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}

impl ControlApiQuotaBackendStatusPayload {
    fn from_snapshot(snapshot: QuotaBackendStatusSnapshot) -> Self {
        Self {
            availability: snapshot.availability,
            degraded: snapshot.degraded,
            health_reason: snapshot.health_reason,
            last_observed_at_unix_ms: snapshot.last_observed_at_unix_ms,
            recent_errors: snapshot
                .recent_errors
                .into_iter()
                .map(ControlApiQuotaBackendErrorPayload::from_snapshot)
                .collect(),
        }
    }
}

impl ControlApiBackendHealthSummaryPayload {
    fn from_inventory(
        inventory: &BackendLifecycleInventorySnapshot,
        summary: crate::runtime::backend::state::BackendLifecycleInventorySummary,
    ) -> Self {
        let mut unhealthy = 0;
        let mut unknown = 0;
        let mut active_membership = 0;
        let mut suppressed_membership = 0;
        let mut removed_membership = 0;

        for backend in &inventory.backends {
            match backend.health {
                BackendHealthState::Healthy => {}
                BackendHealthState::Unhealthy { .. } => unhealthy += 1,
                BackendHealthState::Unknown => unknown += 1,
            }

            match backend.membership {
                BackendMembershipState::Active => active_membership += 1,
                BackendMembershipState::Suppressed => suppressed_membership += 1,
                BackendMembershipState::Removed => removed_membership += 1,
            }
        }

        let availability = if summary.total_backends == 0 {
            "empty"
        } else if unhealthy == 0 && unknown == 0 {
            "healthy"
        } else {
            "degraded"
        };

        Self {
            availability,
            placed_total: summary.total_backends,
            healthy: summary.healthy_backends,
            unhealthy,
            unknown,
            active_membership,
            suppressed_membership,
            removed_membership,
        }
    }
}

impl ControlApiQuotaBackendHealthSummaryPayload {
    fn from_snapshot(enabled: bool, snapshot: &QuotaBackendStatusSnapshot) -> Self {
        Self {
            enabled,
            active_backend: snapshot.backend_mode.clone(),
            availability: snapshot.availability.clone(),
            degraded: snapshot.degraded,
            health_reason: snapshot.health_reason.clone(),
            last_observed_at_unix_ms: snapshot.last_observed_at_unix_ms,
            recent_error_count: snapshot.recent_errors.len(),
        }
    }
}

impl ControlApiRecentAdminActionPayload {
    fn from_event(event: GenerationChangeEvent) -> Self {
        Self {
            kind: event.kind,
            operation: event.entry.operation,
            generation: event.entry.generation,
            status: event.entry.status,
            config_version: event.entry.config_version,
            requested_by: event.entry.requested_by,
            trigger_source: event.entry.trigger_source,
            requested_at_ms: event.entry.requested_at_ms,
            completed_at_ms: event.entry.completed_at_ms,
            event_emitted_at_ms: event.emitted_at_ms,
            summary: event.entry.summary,
        }
    }
}

impl ControlApiQuotaBackendErrorPayload {
    fn from_snapshot(snapshot: QuotaBackendErrorSnapshot) -> Self {
        Self {
            observed_at_unix_ms: snapshot.observed_at_unix_ms,
            policy_name: snapshot.policy_name,
            reason: snapshot.reason,
            detail: snapshot.detail,
        }
    }
}

impl ControlApiQuotaPolicyPayload {
    fn from_snapshot(snapshot: QuotaPolicyIntrospectionSnapshot) -> Self {
        Self {
            name: snapshot.name,
            route_allowlist: snapshot.route_allowlist,
            selector: ControlApiQuotaSelectorPayload::from_snapshot(snapshot.selector),
            burst: snapshot
                .burst
                .map(ControlApiQuotaWindowPayload::from_snapshot),
            sustained: snapshot
                .sustained
                .map(ControlApiQuotaWindowPayload::from_snapshot),
        }
    }
}

impl ControlApiQuotaSelectorPayload {
    fn from_snapshot(snapshot: QuotaSelectorIntrospectionSnapshot) -> Self {
        Self {
            route: snapshot.route,
            tenant: snapshot.tenant,
            token: snapshot.token,
            client: snapshot.client,
        }
    }
}

impl ControlApiQuotaWindowPayload {
    fn from_snapshot(snapshot: QuotaWindowIntrospectionSnapshot) -> Self {
        Self {
            requests: snapshot.requests,
            window_secs: snapshot.window_secs,
        }
    }
}
