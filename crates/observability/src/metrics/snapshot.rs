use super::*;

impl RequestResultMetricsSnapshot {
    fn from_store(store: &RequestResultMetricsStore) -> Self {
        let mut upstream_request_counts = store
            .upstream_request_counts
            .iter()
            .map(|(key, value)| (key.clone(), *value))
            .collect::<Vec<_>>();
        upstream_request_counts.sort_by(|(left, _), (right, _)| {
            left.upstream
                .cmp(&right.upstream)
                .then_with(|| left.status_class.cmp(right.status_class))
                .then_with(|| left.outcome.cmp(right.outcome))
        });

        let mut backend_request_counts = store
            .backend_request_counts
            .iter()
            .map(|(key, value)| (key.clone(), *value))
            .collect::<Vec<_>>();
        backend_request_counts.sort_by(|(left, _), (right, _)| {
            left.upstream
                .cmp(&right.upstream)
                .then_with(|| left.backend.cmp(&right.backend))
                .then_with(|| left.status_class.cmp(right.status_class))
                .then_with(|| left.outcome.cmp(right.outcome))
        });

        let mut upstream_request_latency = store
            .upstream_request_latency
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        upstream_request_latency.sort_by(|(left, _), (right, _)| {
            left.upstream
                .cmp(&right.upstream)
                .then_with(|| left.outcome.cmp(right.outcome))
        });

        Self {
            upstream_request_counts,
            backend_request_counts,
            upstream_request_latency,
        }
    }
}

impl QuotaMetricsSnapshot {
    fn from_metrics(metrics: &Metrics) -> Self {
        let quota_policy_outcomes = metrics
            .quota_policy_outcomes
            .read()
            .map(|guard| {
                let mut rows = guard
                    .iter()
                    .map(|(key, value)| (key.clone(), *value))
                    .collect::<Vec<_>>();
                rows.sort_by(|(left, _), (right, _)| {
                    left.policy
                        .cmp(&right.policy)
                        .then(left.decision.cmp(&right.decision))
                        .then(left.reason.cmp(&right.reason))
                        .then(left.selector_dimensions.cmp(&right.selector_dimensions))
                        .then(left.backend_mode.cmp(&right.backend_mode))
                });
                rows
            })
            .unwrap_or_default();

        let quota_backend_health = metrics
            .quota_backend_health
            .read()
            .map(|guard| {
                let mut rows = guard
                    .iter()
                    .map(|(key, value)| (key.clone(), *value))
                    .collect::<Vec<_>>();
                rows.sort_by(|(left, _), (right, _)| {
                    left.backend_mode
                        .cmp(&right.backend_mode)
                        .then(left.reason.cmp(&right.reason))
                });
                rows
            })
            .unwrap_or_default();

        Self {
            quota_policy_outcomes,
            quota_backend_health,
        }
    }
}

impl JwtJwksMetricsSnapshot {
    fn from_metrics(metrics: &Metrics) -> Self {
        let jwt_validation_failures = metrics
            .jwt_validation_failures
            .read()
            .map(|guard| {
                let mut entries = guard
                    .iter()
                    .map(|(reason, value)| (reason.clone(), *value))
                    .collect::<Vec<_>>();
                entries.sort_by(|(left, _), (right, _)| left.cmp(right));
                entries
            })
            .unwrap_or_default();

        let jwt_algorithm_rejections = metrics
            .jwt_algorithm_rejections
            .read()
            .map(|guard| {
                let mut entries = guard
                    .iter()
                    .map(|(algorithm, value)| (algorithm.clone(), *value))
                    .collect::<Vec<_>>();
                entries.sort_by(|(left, _), (right, _)| left.cmp(right));
                entries
            })
            .unwrap_or_default();

        let jwks_unknown_kid_events = metrics
            .jwks_unknown_kid_events
            .read()
            .map(|guard| {
                let mut entries = guard
                    .iter()
                    .map(|(jwks_source_id, value)| (jwks_source_id.clone(), *value))
                    .collect::<Vec<_>>();
                entries.sort_by(|(left, _), (right, _)| left.cmp(right));
                entries
            })
            .unwrap_or_default();

        let jwks_source_state = metrics
            .jwks_source_state
            .read()
            .map(|guard| {
                let mut entries = guard.values().cloned().collect::<Vec<_>>();
                entries.sort_by(|left, right| left.jwks_source_id.cmp(&right.jwks_source_id));
                entries
            })
            .unwrap_or_default();

        Self {
            jwt_validation_failures,
            jwt_algorithm_rejections,
            jwks_unknown_kid_events,
            jwks_source_state,
        }
    }
}

impl BackendMetricsSnapshot {
    fn from_metrics(metrics: &Metrics) -> Self {
        let backend_dns_state = metrics
            .backend_dns_state
            .read()
            .map(|guard| {
                let mut entries = guard
                    .iter()
                    .map(|(backend, state)| (backend.clone(), state.clone()))
                    .collect::<Vec<_>>();
                entries.sort_by(|(left, _), (right, _)| left.cmp(right));
                entries
            })
            .unwrap_or_default();

        let backend_rotation_state = metrics
            .backend_rotation_state
            .read()
            .map(|guard| {
                let mut entries = guard
                    .iter()
                    .map(|(backend, state)| (backend.clone(), state.clone()))
                    .collect::<Vec<_>>();
                entries.sort_by(|(left, _), (right, _)| left.cmp(right));
                entries
            })
            .unwrap_or_default();

        let backend_connect_attempts = metrics
            .backend_connect_attempts
            .read()
            .map(|guard| {
                let mut entries = guard
                    .iter()
                    .map(|(key, value)| (key.clone(), *value))
                    .collect::<Vec<_>>();
                entries.sort_by(|(left, _), (right, _)| {
                    left.backend
                        .cmp(&right.backend)
                        .then_with(|| left.hostname.cmp(&right.hostname))
                        .then_with(|| left.resolved_addr.cmp(&right.resolved_addr))
                });
                entries
            })
            .unwrap_or_default();

        Self {
            backend_dns_state,
            backend_rotation_state,
            backend_connect_attempts,
        }
    }
}

impl SecretMetricsSnapshot {
    fn from_metrics(metrics: &Metrics) -> Self {
        let secret_reload_totals = metrics
            .secret_reload_totals
            .read()
            .map(|guard| {
                let mut entries = guard
                    .iter()
                    .map(|(key, value)| (key.clone(), *value))
                    .collect::<Vec<_>>();
                entries.sort_by(|(left, _), (right, _)| {
                    left.scope
                        .cmp(&right.scope)
                        .then_with(|| left.result.cmp(&right.result))
                        .then_with(|| left.reason.cmp(&right.reason))
                });
                entries
            })
            .unwrap_or_default();

        let secret_resolve_totals = metrics
            .secret_resolve_totals
            .read()
            .map(|guard| {
                let mut entries = guard
                    .iter()
                    .map(|(key, value)| (key.clone(), *value))
                    .collect::<Vec<_>>();
                entries.sort_by(|(left, _), (right, _)| {
                    left.provider
                        .cmp(&right.provider)
                        .then_with(|| left.result.cmp(&right.result))
                        .then_with(|| left.reason.cmp(&right.reason))
                });
                entries
            })
            .unwrap_or_default();

        let secret_last_success_unixtime = metrics
            .secret_last_success_unixtime
            .read()
            .map(|guard| {
                let mut entries = guard
                    .iter()
                    .map(|(key, value)| (key.clone(), *value))
                    .collect::<Vec<_>>();
                entries.sort_by(|(left, _), (right, _)| left.scope.cmp(&right.scope));
                entries
            })
            .unwrap_or_default();

        let upstream_client_cert_expiry = metrics
            .upstream_client_cert_expiry
            .read()
            .map(|guard| {
                let mut entries = guard
                    .iter()
                    .map(|(key, value)| (key.clone(), *value))
                    .collect::<Vec<_>>();
                entries.sort_by(|(left, _), (right, _)| left.upstream.cmp(&right.upstream));
                entries
            })
            .unwrap_or_default();

        let control_plane_cert_reload_totals = metrics
            .control_plane_cert_reload_totals
            .read()
            .map(|guard| {
                let mut entries = guard
                    .iter()
                    .map(|(key, value)| (key.clone(), *value))
                    .collect::<Vec<_>>();
                entries.sort_by(|(left, _), (right, _)| {
                    left.result
                        .cmp(&right.result)
                        .then_with(|| left.reason.cmp(&right.reason))
                });
                entries
            })
            .unwrap_or_default();

        Self {
            secret_reload_totals,
            secret_resolve_totals,
            secret_last_success_unixtime,
            upstream_client_cert_expiry,
            control_plane_cert_reload_totals,
        }
    }
}

impl Metrics {
    pub(crate) fn snapshot_quota_metrics(&self) -> QuotaMetricsSnapshot {
        let version = self.quota_metrics_version.load(Ordering::Relaxed);
        if let Ok(cache) = self.quota_metrics_cache.read()
            && cache.version == version
        {
            return cache.snapshot.clone();
        }

        let snapshot = QuotaMetricsSnapshot::from_metrics(self);

        if let Ok(mut cache) = self.quota_metrics_cache.write() {
            cache.version = version;
            cache.snapshot = snapshot.clone();
            cache.rendered.clear();
        }

        snapshot
    }

    pub(crate) fn snapshot_jwt_jwks_metrics(&self) -> JwtJwksMetricsSnapshot {
        let version = self.jwt_jwks_metrics_version.load(Ordering::Relaxed);
        if let Ok(cache) = self.jwt_jwks_metrics_cache.read()
            && cache.version == version
        {
            return cache.snapshot.clone();
        }

        let snapshot = JwtJwksMetricsSnapshot::from_metrics(self);

        if let Ok(mut cache) = self.jwt_jwks_metrics_cache.write() {
            cache.version = version;
            cache.snapshot = snapshot.clone();
            cache.rendered.clear();
        }

        snapshot
    }

    pub(crate) fn snapshot_backend_metrics(&self) -> BackendMetricsSnapshot {
        let version = self.backend_metrics_version.load(Ordering::Relaxed);
        if let Ok(cache) = self.backend_metrics_cache.read()
            && cache.version == version
        {
            return cache.snapshot.clone();
        }

        let snapshot = BackendMetricsSnapshot::from_metrics(self);

        if let Ok(mut cache) = self.backend_metrics_cache.write() {
            cache.version = version;
            cache.snapshot = snapshot.clone();
            cache.rendered.clear();
        }

        snapshot
    }

    pub(crate) fn snapshot_secret_metrics(&self) -> SecretMetricsSnapshot {
        let version = self.secret_metrics_version.load(Ordering::Relaxed);
        if let Ok(cache) = self.secret_metrics_cache.read()
            && cache.version == version
        {
            return cache.snapshot.clone();
        }

        let snapshot = SecretMetricsSnapshot::from_metrics(self);

        if let Ok(mut cache) = self.secret_metrics_cache.write() {
            cache.version = version;
            cache.snapshot = snapshot.clone();
        }

        snapshot
    }

    pub fn snapshot_jwt_validation_failures(&self) -> Vec<(String, u64)> {
        self.snapshot_jwt_jwks_metrics().jwt_validation_failures
    }

    pub fn snapshot_jwt_algorithm_rejections(&self) -> Vec<(String, u64)> {
        self.snapshot_jwt_jwks_metrics().jwt_algorithm_rejections
    }

    pub fn snapshot_jwks_unknown_kid_events(&self) -> Vec<(String, u64)> {
        self.snapshot_jwt_jwks_metrics().jwks_unknown_kid_events
    }

    #[cfg(test)]
    pub(crate) fn snapshot_jwks_source_state(&self) -> Vec<JwksSourceState> {
        self.snapshot_jwt_jwks_metrics().jwks_source_state
    }

    pub(crate) fn snapshot_request_result_metrics(&self) -> RequestResultMetricsSnapshot {
        let version = self.request_result_metrics_version.load(Ordering::Relaxed);
        if let Ok(cache) = self.request_result_metrics_cache.read()
            && cache.version == version
        {
            return cache.snapshot.clone();
        }

        let snapshot = self
            .request_result_metrics
            .read()
            .map(|guard| RequestResultMetricsSnapshot::from_store(&guard))
            .unwrap_or_default();

        if let Ok(mut cache) = self.request_result_metrics_cache.write() {
            cache.version = version;
            cache.snapshot = snapshot.clone();
        }

        snapshot
    }

    #[cfg(test)]
    pub fn snapshot_upstream_request_counts(&self) -> Vec<(UpstreamRequestCountKey, u64)> {
        self.snapshot_request_result_metrics()
            .upstream_request_counts
    }

    #[cfg(test)]
    pub fn snapshot_backend_request_counts(&self) -> Vec<(BackendRequestCountKey, u64)> {
        self.snapshot_request_result_metrics()
            .backend_request_counts
    }

    #[cfg(test)]
    pub fn snapshot_upstream_request_latency(
        &self,
    ) -> Vec<(UpstreamRequestLatencyKey, RequestLatencyStats)> {
        self.snapshot_request_result_metrics()
            .upstream_request_latency
    }

    pub(crate) fn snapshot_downstream_tls_handshake_failures(
        &self,
    ) -> Vec<(DownstreamTlsHandshakeFailureKey, u64)> {
        self.downstream_tls_handshake_failures
            .read()
            .map(|guard| {
                let mut entries = guard
                    .iter()
                    .map(|(key, value)| (key.clone(), *value))
                    .collect::<Vec<_>>();
                entries.sort_by(|(left, _), (right, _)| {
                    left.listener
                        .cmp(&right.listener)
                        .then_with(|| left.reason.cmp(&right.reason))
                });
                entries
            })
            .unwrap_or_default()
    }

    pub(crate) fn snapshot_downstream_tls_cert_selections(
        &self,
    ) -> Vec<(DownstreamTlsCertSelectionKey, u64)> {
        self.downstream_tls_cert_selections
            .read()
            .map(|guard| {
                let mut entries = guard
                    .iter()
                    .map(|(key, value)| (key.clone(), *value))
                    .collect::<Vec<_>>();
                entries.sort_by(|(left, _), (right, _)| {
                    left.listener
                        .cmp(&right.listener)
                        .then_with(|| left.selection.cmp(&right.selection))
                });
                entries
            })
            .unwrap_or_default()
    }

    pub(crate) fn snapshot_downstream_tls_alpn(&self) -> Vec<(DownstreamTlsAlpnKey, u64)> {
        self.downstream_tls_alpn_negotiated
            .read()
            .map(|guard| {
                let mut entries = guard
                    .iter()
                    .map(|(key, value)| (key.clone(), *value))
                    .collect::<Vec<_>>();
                entries.sort_by(|(left, _), (right, _)| {
                    left.listener
                        .cmp(&right.listener)
                        .then_with(|| left.protocol.cmp(&right.protocol))
                });
                entries
            })
            .unwrap_or_default()
    }

    pub(crate) fn snapshot_upstream_tls_failures(&self) -> Vec<(UpstreamTlsFailureKey, u64)> {
        self.upstream_tls_failures
            .read()
            .map(|guard| {
                let mut entries = guard
                    .iter()
                    .map(|(key, value)| (key.clone(), *value))
                    .collect::<Vec<_>>();
                entries.sort_by(|(left, _), (right, _)| {
                    left.upstream
                        .cmp(&right.upstream)
                        .then_with(|| left.backend.cmp(&right.backend))
                        .then_with(|| left.phase.cmp(&right.phase))
                        .then_with(|| left.reason.cmp(&right.reason))
                });
                entries
            })
            .unwrap_or_default()
    }

    pub(crate) fn snapshot_downstream_tls_cert_expiry(
        &self,
    ) -> Vec<(DownstreamTlsCertExpiryKey, i64)> {
        self.downstream_tls_cert_expiry
            .read()
            .map(|guard| {
                let mut entries = guard
                    .iter()
                    .map(|(key, value)| (key.clone(), *value))
                    .collect::<Vec<_>>();
                entries.sort_by(|(left, _), (right, _)| {
                    left.listener
                        .cmp(&right.listener)
                        .then_with(|| left.server_name.cmp(&right.server_name))
                });
                entries
            })
            .unwrap_or_default()
    }
}
