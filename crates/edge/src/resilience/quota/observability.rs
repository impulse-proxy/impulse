use super::*;

impl QuotaBackendAvailability {
    fn slug(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Unknown => "unknown",
            Self::Available => "available",
            Self::Degraded => "degraded",
        }
    }
}

impl QuotaRuntime {
    pub fn register_metrics(metrics: &Arc<Metrics>) {
        if let Ok(mut sink) = quota_metrics_sink().write() {
            *sink = Arc::downgrade(metrics);
        }
    }

    pub fn policy_snapshots(&self) -> Vec<QuotaPolicyIntrospectionSnapshot> {
        self.policies
            .iter()
            .map(|policy| {
                let mut route_allowlist =
                    policy.route_allowlist.iter().cloned().collect::<Vec<_>>();
                route_allowlist.sort();
                QuotaPolicyIntrospectionSnapshot {
                    name: policy.name.clone(),
                    route_allowlist,
                    selector: QuotaSelectorIntrospectionSnapshot {
                        route: policy.selector.route,
                        tenant: policy
                            .selector
                            .tenant
                            .as_ref()
                            .map(QuotaSelectorKeySpec::descriptor),
                        token: policy
                            .selector
                            .token
                            .as_ref()
                            .map(QuotaSelectorKeySpec::descriptor),
                        client: policy
                            .selector
                            .client
                            .as_ref()
                            .map(QuotaSelectorKeySpec::descriptor),
                    },
                    burst: policy
                        .burst
                        .as_ref()
                        .map(QuotaWindowPolicy::introspection_snapshot),
                    sustained: policy
                        .sustained
                        .as_ref()
                        .map(QuotaWindowPolicy::introspection_snapshot),
                }
            })
            .collect()
    }

    pub fn backend_status_snapshot(
        &self,
        initialization_error: Option<&QuotaCounterBackendError>,
    ) -> QuotaBackendStatusSnapshot {
        let backend_mode = self.backend.backend_kind().to_string();
        if !self.enabled {
            return QuotaBackendStatusSnapshot {
                backend_mode,
                availability: QuotaBackendAvailability::Disabled.slug().to_string(),
                degraded: false,
                health_reason: None,
                last_observed_at_unix_ms: None,
                recent_errors: Vec::new(),
            };
        }

        if let Some(error) = initialization_error {
            return QuotaBackendStatusSnapshot {
                backend_mode: backend_mode.clone(),
                availability: QuotaBackendAvailability::Degraded.slug().to_string(),
                degraded: true,
                health_reason: Some(
                    quota_backend_health_reason_from_deny_reason(error.deny_reason())
                        .slug()
                        .to_string(),
                ),
                last_observed_at_unix_ms: None,
                recent_errors: vec![QuotaBackendErrorSnapshot {
                    observed_at_unix_ms: None,
                    policy_name: error.policy_name.clone(),
                    reason: error.deny_reason().slug().to_string(),
                    detail: error.detail.clone(),
                }],
            };
        }

        let state = current_quota_introspection_state();
        if state.backend_mode.as_deref() == Some(backend_mode.as_str()) {
            let availability = state
                .availability
                .unwrap_or_else(|| default_quota_backend_availability(&self.backend));
            return QuotaBackendStatusSnapshot {
                backend_mode,
                availability: availability.slug().to_string(),
                degraded: matches!(availability, QuotaBackendAvailability::Degraded),
                health_reason: state.health_reason.map(|reason| reason.slug().to_string()),
                last_observed_at_unix_ms: state.last_observed_at_unix_ms,
                recent_errors: state.recent_errors,
            };
        }

        let availability = default_quota_backend_availability(&self.backend);
        QuotaBackendStatusSnapshot {
            backend_mode,
            availability: availability.slug().to_string(),
            degraded: matches!(availability, QuotaBackendAvailability::Degraded),
            health_reason: None,
            last_observed_at_unix_ms: None,
            recent_errors: Vec::new(),
        }
    }
}

fn quota_metrics_sink() -> &'static RwLock<Weak<Metrics>> {
    QUOTA_METRICS_SINK.get_or_init(|| RwLock::new(Weak::new()))
}

fn quota_introspection_state() -> &'static RwLock<QuotaIntrospectionState> {
    QUOTA_INTROSPECTION_STATE.get_or_init(|| RwLock::new(QuotaIntrospectionState::default()))
}

fn current_quota_metrics() -> Option<Arc<Metrics>> {
    quota_metrics_sink()
        .read()
        .ok()
        .and_then(|metrics| metrics.upgrade())
}

fn current_quota_introspection_state() -> QuotaIntrospectionState {
    quota_introspection_state()
        .read()
        .map(|state| state.clone())
        .unwrap_or_default()
}

fn record_quota_backend_observation(
    backend_mode: &str,
    decision: &QuotaDecision,
    detail: Option<String>,
    observed_at_unix_ms: u64,
) {
    let degraded_reason = degraded_backend_health_reason(backend_mode);
    let availability = if degraded_reason.is_some() {
        QuotaBackendAvailability::Degraded
    } else {
        match decision {
            QuotaDecision::Allowed(_)
            | QuotaDecision::Denied(_)
            | QuotaDecision::ShadowDenied(_) => QuotaBackendAvailability::Available,
            QuotaDecision::FailedOpen(_) | QuotaDecision::FailedClosed(_) => {
                QuotaBackendAvailability::Degraded
            }
            QuotaDecision::NotApplied => return,
        }
    };
    let health_reason = quota_backend_health_reason(decision, backend_mode);

    if let Ok(mut state) = quota_introspection_state().write() {
        state.backend_mode = Some(backend_mode.to_string());
        state.availability = Some(availability);
        state.health_reason = health_reason;
        state.last_observed_at_unix_ms = Some(observed_at_unix_ms);

        if let Some(snapshot) =
            quota_backend_error_snapshot(decision, backend_mode, detail, observed_at_unix_ms)
        {
            state.recent_errors.insert(0, snapshot);
            if state.recent_errors.len() > QUOTA_RECENT_BACKEND_ERRORS_LIMIT {
                state
                    .recent_errors
                    .truncate(QUOTA_RECENT_BACKEND_ERRORS_LIMIT);
            }
        }
    }
}

fn quota_backend_error_snapshot(
    decision: &QuotaDecision,
    backend_mode: &str,
    detail: Option<String>,
    observed_at_unix_ms: u64,
) -> Option<QuotaBackendErrorSnapshot> {
    if let Some(reason) = degraded_backend_deny_reason(backend_mode) {
        return Some(QuotaBackendErrorSnapshot {
            observed_at_unix_ms: Some(observed_at_unix_ms),
            policy_name: quota_decision_policy_name(decision).map(ToOwned::to_owned),
            reason: reason.slug().to_string(),
            detail,
        });
    }

    match decision {
        QuotaDecision::FailedOpen(failure) | QuotaDecision::FailedClosed(failure) => {
            Some(QuotaBackendErrorSnapshot {
                observed_at_unix_ms: Some(observed_at_unix_ms),
                policy_name: failure.policy_name.clone(),
                reason: failure.reason.slug().to_string(),
                detail,
            })
        }
        QuotaDecision::NotApplied
        | QuotaDecision::Allowed(_)
        | QuotaDecision::Denied(_)
        | QuotaDecision::ShadowDenied(_) => None,
    }
}

fn default_quota_backend_availability(backend: &QuotaCounterBackend) -> QuotaBackendAvailability {
    match backend {
        QuotaCounterBackend::InMemory { .. } => QuotaBackendAvailability::Available,
        QuotaCounterBackend::Redis { .. } => QuotaBackendAvailability::Unknown,
    }
}

pub(super) fn observe_quota_policy_outcome(
    runtime: &QuotaRuntime,
    policy: Option<&QuotaPolicyRuntime>,
    context: &QuotaIdentityContext<'_>,
    decision: &QuotaDecision,
    backend_observed: bool,
    backend_mode: Option<&str>,
    backend_error_detail: Option<String>,
) {
    let policy_name = policy
        .map(|value| value.name.as_str())
        .or(match decision {
            QuotaDecision::Allowed(allowance) => Some(allowance.policy_name.as_str()),
            QuotaDecision::Denied(denial) | QuotaDecision::ShadowDenied(denial) => {
                Some(denial.policy_name.as_str())
            }
            QuotaDecision::FailedOpen(failure) | QuotaDecision::FailedClosed(failure) => {
                failure.policy_name.as_deref()
            }
            QuotaDecision::NotApplied => None,
        })
        .unwrap_or("unmatched");
    let selector_dimensions =
        policy
            .map(|value| value.selector.dimensions())
            .unwrap_or(QuotaSelectorDimensions {
                route: false,
                tenant: false,
                token: false,
                client: false,
            });
    let selector_dimensions = selector_dimensions.slug();
    let backend_mode = backend_mode.unwrap_or(runtime.backend.backend_kind());
    let decision_kind = quota_policy_decision_kind(decision);
    let reason = quota_policy_reason(decision);
    let degraded_health_reason = degraded_backend_health_reason(backend_mode);

    if backend_observed {
        record_quota_backend_observation(
            backend_mode,
            decision,
            backend_error_detail,
            unix_now_ms(),
        );
    }

    if let Some(metrics) = current_quota_metrics() {
        metrics.policy_observations().record_quota_policy_outcome(
            policy_name,
            decision_kind,
            reason,
            &selector_dimensions,
            backend_mode,
        );
        if backend_observed
            && let Some(health_reason) = quota_backend_health_reason(decision, backend_mode)
        {
            metrics
                .policy_observations()
                .record_quota_backend_health(backend_mode, health_reason);
        }
    }

    let route = context.route.unwrap_or("unrouted");
    let reason_slug = reason.slug();
    let degraded_reason = degraded_health_reason.map(QuotaBackendHealthReason::slug);
    let log_line = format!(
        "quota policy outcome: upstream={} policy={} selector_dimensions={} backend_mode={} decision={} reason={} enforcement={} degraded_reason={}",
        route,
        policy_name,
        selector_dimensions,
        backend_mode,
        decision_kind.slug(),
        reason_slug,
        quota_enforcement_slug(runtime.enforcement),
        degraded_reason.unwrap_or("none"),
    );
    if degraded_reason.is_some() {
        warn!("{log_line}");
    } else {
        match decision_kind {
            QuotaPolicyDecision::Denied | QuotaPolicyDecision::FailedClosed => warn!("{log_line}"),
            QuotaPolicyDecision::FailedOpen | QuotaPolicyDecision::ShadowDenied => {
                warn!("{log_line}")
            }
            QuotaPolicyDecision::Allowed | QuotaPolicyDecision::NotApplied => debug!("{log_line}"),
        }
    }
}

fn quota_policy_decision_kind(decision: &QuotaDecision) -> QuotaPolicyDecision {
    match decision {
        QuotaDecision::NotApplied => QuotaPolicyDecision::NotApplied,
        QuotaDecision::Allowed(_) => QuotaPolicyDecision::Allowed,
        QuotaDecision::ShadowDenied(_) => QuotaPolicyDecision::ShadowDenied,
        QuotaDecision::Denied(_) => QuotaPolicyDecision::Denied,
        QuotaDecision::FailedOpen(_) => QuotaPolicyDecision::FailedOpen,
        QuotaDecision::FailedClosed(_) => QuotaPolicyDecision::FailedClosed,
    }
}

fn quota_policy_reason(decision: &QuotaDecision) -> QuotaPolicyReason {
    match decision {
        QuotaDecision::NotApplied => QuotaPolicyReason::NotApplied,
        QuotaDecision::Allowed(_) => QuotaPolicyReason::Allowed,
        QuotaDecision::ShadowDenied(denial) | QuotaDecision::Denied(denial) => {
            quota_policy_reason_from_deny_reason(denial.reason)
        }
        QuotaDecision::FailedOpen(failure) | QuotaDecision::FailedClosed(failure) => {
            quota_policy_reason_from_deny_reason(failure.reason)
        }
    }
}

fn quota_policy_reason_from_deny_reason(reason: QuotaDenyReason) -> QuotaPolicyReason {
    match reason {
        QuotaDenyReason::BurstQuotaExhausted => QuotaPolicyReason::BurstQuotaExhausted,
        QuotaDenyReason::SustainedQuotaExhausted => QuotaPolicyReason::SustainedQuotaExhausted,
        QuotaDenyReason::SelectorIdentityMissing => QuotaPolicyReason::SelectorIdentityMissing,
        QuotaDenyReason::SelectorIdentityInvalid => QuotaPolicyReason::SelectorIdentityInvalid,
        QuotaDenyReason::BackendTimeout => QuotaPolicyReason::BackendTimeout,
        QuotaDenyReason::BackendUnavailable => QuotaPolicyReason::BackendUnavailable,
        QuotaDenyReason::BackendError => QuotaPolicyReason::BackendError,
    }
}

fn quota_backend_health_reason(
    decision: &QuotaDecision,
    backend_mode: &str,
) -> Option<QuotaBackendHealthReason> {
    if let Some(reason) = degraded_backend_health_reason(backend_mode) {
        return Some(reason);
    }

    match decision {
        QuotaDecision::Allowed(_) | QuotaDecision::Denied(_) | QuotaDecision::ShadowDenied(_) => {
            Some(QuotaBackendHealthReason::Available)
        }
        QuotaDecision::FailedOpen(failure) | QuotaDecision::FailedClosed(failure) => {
            Some(match failure.reason {
                QuotaDenyReason::BackendTimeout => QuotaBackendHealthReason::Timeout,
                QuotaDenyReason::BackendUnavailable => QuotaBackendHealthReason::Unavailable,
                QuotaDenyReason::BackendError => QuotaBackendHealthReason::Error,
                QuotaDenyReason::BurstQuotaExhausted
                | QuotaDenyReason::SustainedQuotaExhausted
                | QuotaDenyReason::SelectorIdentityMissing
                | QuotaDenyReason::SelectorIdentityInvalid => return None,
            })
        }
        QuotaDecision::NotApplied => None,
    }
}

pub(super) fn quota_backend_health_reason_from_deny_reason(
    reason: QuotaDenyReason,
) -> QuotaBackendHealthReason {
    match reason {
        QuotaDenyReason::BackendTimeout => QuotaBackendHealthReason::Timeout,
        QuotaDenyReason::BackendUnavailable => QuotaBackendHealthReason::Unavailable,
        QuotaDenyReason::BackendError => QuotaBackendHealthReason::Error,
        QuotaDenyReason::BurstQuotaExhausted
        | QuotaDenyReason::SustainedQuotaExhausted
        | QuotaDenyReason::SelectorIdentityMissing
        | QuotaDenyReason::SelectorIdentityInvalid => QuotaBackendHealthReason::Error,
    }
}

fn quota_enforcement_slug(enforcement: QuotaEnforcementMode) -> &'static str {
    enforcement.slug()
}

fn degraded_backend_health_reason(backend_mode: &str) -> Option<QuotaBackendHealthReason> {
    degraded_backend_deny_reason(backend_mode).map(quota_backend_health_reason_from_deny_reason)
}

fn degraded_backend_deny_reason(backend_mode: &str) -> Option<QuotaDenyReason> {
    let suffix = backend_mode
        .rsplit_once(LOCAL_FALLBACK_BACKEND_SEPARATOR)
        .map(|(_, suffix)| suffix)?;
    QuotaDenyReason::from_slug(suffix)
}

fn quota_decision_policy_name(decision: &QuotaDecision) -> Option<&str> {
    match decision {
        QuotaDecision::Allowed(allowance) => Some(allowance.policy_name.as_str()),
        QuotaDecision::ShadowDenied(denial) | QuotaDecision::Denied(denial) => {
            Some(denial.policy_name.as_str())
        }
        QuotaDecision::FailedOpen(failure) | QuotaDecision::FailedClosed(failure) => {
            failure.policy_name.as_deref()
        }
        QuotaDecision::NotApplied => None,
    }
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}
