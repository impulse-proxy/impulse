use std::collections::HashSet;

use super::*;
use crate::runtime::{bundle::RuntimeBundle, policy::TransitionRejection};

pub(super) fn classify_compatibility(
    rejections: &[TransitionRejection],
) -> ReloadCompatibilityClassification {
    if rejections.is_empty() {
        ReloadCompatibilityClassification::LiveReloadable
    } else if rejections.iter().any(TransitionRejection::requires_restart) {
        ReloadCompatibilityClassification::RestartRequired
    } else {
        ReloadCompatibilityClassification::Rejected
    }
}

pub(super) fn snapshot_from_bundle(bundle: &RuntimeBundle) -> ProposedGenerationSnapshot {
    let state = bundle.shared_state.generation_state();
    let mut listener_labels = state
        .listener_runtime_configs
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    listener_labels.sort_unstable();

    ProposedGenerationSnapshot {
        generation: bundle.generation,
        config_path: bundle.startup.config_path.clone(),
        log_level: bundle.startup.log_config.level.clone(),
        listener_labels,
        upstream_count: state.upstream_policies.len(),
        backend_count: state.backend_endpoints.len(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum ReloadDiffDomain {
    Listeners,
    RoutesUpstreams,
    BackendPolicies,
    AuthAdmissionResilience,
    ObservabilityControlPlane,
}

impl ReloadDiffDomain {
    fn as_str(self) -> &'static str {
        match self {
            Self::Listeners => "listeners",
            Self::RoutesUpstreams => "routes_upstreams",
            Self::BackendPolicies => "backend_policies",
            Self::AuthAdmissionResilience => "auth_admission_resilience",
            Self::ObservabilityControlPlane => "observability_control_plane",
        }
    }
}

pub(super) fn build_reload_diff(
    current: &RuntimeBundle,
    next: &RuntimeBundle,
    rejected_domains: HashSet<ReloadDiffDomain>,
) -> ReloadDiff {
    let specs = [
        (
            ReloadDiffDomain::Listeners,
            summarize_listeners(current),
            summarize_listeners(next),
        ),
        (
            ReloadDiffDomain::RoutesUpstreams,
            summarize_routes_upstreams(current),
            summarize_routes_upstreams(next),
        ),
        (
            ReloadDiffDomain::BackendPolicies,
            summarize_backend_policies(current),
            summarize_backend_policies(next),
        ),
        (
            ReloadDiffDomain::AuthAdmissionResilience,
            summarize_auth_admission_resilience(current),
            summarize_auth_admission_resilience(next),
        ),
        (
            ReloadDiffDomain::ObservabilityControlPlane,
            summarize_observability_control_plane(current),
            summarize_observability_control_plane(next),
        ),
    ];

    let secret_fingerprints_before = summarize_backend_tls_fingerprints(current);
    let secret_fingerprints_after = summarize_backend_tls_fingerprints(next);
    let secret_material_changed_globally = secret_fingerprints_before != secret_fingerprints_after;

    let entries = specs
        .into_iter()
        .map(|(domain, current_summary, next_summary)| {
            let change = text_change_kind(&current_summary, &next_summary);
            let disposition = if matches!(change, ReloadChangeKind::Unchanged) {
                ReloadDiffDisposition::NoOp
            } else if rejected_domains.contains(&domain) {
                ReloadDiffDisposition::RejectedStartupOwned
            } else {
                ReloadDiffDisposition::Reloadable
            };

            let secret_material_changed = matches!(domain, ReloadDiffDomain::BackendPolicies)
                && secret_material_changed_globally;

            ReloadDiffEntry {
                domain: domain.as_str().to_string(),
                change,
                disposition,
                summary: format!(
                    "{}: [{}] -> [{}]",
                    domain.as_str(),
                    current_summary,
                    next_summary
                ),
                secret_material_changed,
            }
        })
        .collect();

    ReloadDiff { entries }
}

fn summarize_backend_tls_fingerprints(bundle: &RuntimeBundle) -> String {
    let mut upstreams = bundle
        .runtime_config
        .upstreams
        .iter()
        .map(|(name, upstream)| {
            let policy = upstream.backend_tls_policy();
            format!(
                "{}:ca_fp={:?}:ca_dir_fp={:?}:client_cert_fp={:?}:client_key_fp={:?}",
                name,
                policy.ca_file_fingerprint_sha256,
                policy.ca_dir_fingerprint_sha256,
                policy
                    .client_certificate
                    .as_ref()
                    .map(|metadata| metadata.fingerprint_sha256.as_str()),
                policy
                    .client_key
                    .as_ref()
                    .map(|metadata| metadata.fingerprint_sha256.as_str()),
            )
        })
        .collect::<Vec<_>>();
    upstreams.sort_unstable();
    upstreams.join(" | ")
}

fn summarize_listeners(bundle: &RuntimeBundle) -> String {
    let mut listeners = bundle
        .runtime_config
        .listeners
        .iter()
        .map(|listener| {
            format!(
                "{}:{:?}:{}:{}:{}:client_auth(enabled={},required={})",
                listener.index,
                listener.source,
                listener.listen.protocol,
                listener.listen.address,
                listener.listen.port,
                listener.tls.client_auth.enabled,
                listener.tls.client_auth.require_client_cert,
            )
        })
        .collect::<Vec<_>>();
    listeners.sort_unstable();
    listeners.join(" | ")
}

fn summarize_routes_upstreams(bundle: &RuntimeBundle) -> String {
    let mut upstreams = bundle
        .runtime_config
        .upstreams
        .iter()
        .map(|(name, upstream)| {
            format!(
                "{}:{}:{:?}:{:?}:{:?}:{}:{:?}:cache(bytes={},entries={})",
                name,
                upstream.load_balancing.strategy.canonical_name(),
                upstream.route.host,
                upstream.route.path_prefix,
                upstream.route.method,
                upstream.policy.protocol.0.allow_connect,
                upstream.load_balancing.key_spec,
                upstream.policy.response_cache.max_bytes,
                upstream.policy.response_cache.max_entries,
            )
        })
        .collect::<Vec<_>>();
    upstreams.sort_unstable();
    upstreams.join(" | ")
}

fn summarize_backend_policies(bundle: &RuntimeBundle) -> String {
    let mut upstreams = bundle
        .runtime_config
        .upstreams
        .iter()
        .map(|(name, upstream)| {
            let backend_ids = upstream
                .backends
                .iter()
                .map(|backend| {
                    format!(
                        "{}:{:?}:{:?}:hc={}",
                        backend.backend.id,
                        backend.endpoint.transport_kind,
                        backend.endpoint.address_kind,
                        backend.health_check.is_some()
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "{}:tls(v={},sni={},ca_file={:?},ca_fp={:?},ca_dir={:?},ca_dir_fp={:?},client_cert_fp={:?},client_key_fp={:?}):dns(enabled={},refresh={}s):{}",
                name,
                upstream.backend_tls_policy().verify_certificates,
                upstream.backend_tls_policy().strict_sni,
                upstream.backend_tls_policy().ca_file,
                upstream.backend_tls_policy().ca_file_fingerprint_sha256,
                upstream.backend_tls_policy().ca_dir,
                upstream.backend_tls_policy().ca_dir_fingerprint_sha256,
                upstream
                    .backend_tls_policy()
                    .client_certificate
                    .as_ref()
                    .map(|metadata| metadata.fingerprint_sha256.as_str()),
                upstream
                    .backend_tls_policy()
                    .client_key
                    .as_ref()
                    .map(|metadata| metadata.fingerprint_sha256.as_str()),
                bundle
                    .runtime_config
                    .performance
                    .backend_dns_refresh_enabled,
                bundle
                    .runtime_config
                    .performance
                    .backend_dns_refresh_interval_ms
                    / 1000,
                backend_ids
            )
        })
        .collect::<Vec<_>>();
    upstreams.sort_unstable();
    upstreams.join(" | ")
}

fn summarize_auth_admission_resilience(bundle: &RuntimeBundle) -> String {
    let mut auth = bundle
        .runtime_config
        .upstreams
        .iter()
        .map(|(name, upstream)| {
            let jwt_mode = upstream
                .policy
                .upstream_auth
                .jwt
                .as_ref()
                .map(runtime_jwt_summary_mode)
                .unwrap_or("none");
            let jwt_algorithms = upstream
                .policy
                .upstream_auth
                .jwt
                .as_ref()
                .map(|jwt| {
                    jwt.allowed_algorithms
                        .iter()
                        .map(|algorithm| match algorithm {
                            impulse_config::config::JwtAlgorithm::Hs256 => "HS256",
                            impulse_config::config::JwtAlgorithm::Rs256 => "RS256",
                            impulse_config::config::JwtAlgorithm::Es256 => "ES256",
                        })
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();
            let jwks_configured = upstream
                .policy
                .upstream_auth
                .jwt
                .as_ref()
                .is_some_and(|jwt| jwt.jwks_url.is_some());
            format!(
                "{}:api_key={}:jwt={}:jwt_mode={}:jwt_algs={}:jwks_configured={}:external={}:scopes={}:roles={}",
                name,
                upstream.policy.upstream_auth.api_key.is_some(),
                upstream.policy.upstream_auth.jwt.is_some(),
                jwt_mode,
                jwt_algorithms,
                jwks_configured,
                upstream.policy.upstream_auth.external_auth.is_some(),
                upstream.policy.upstream_auth.required_scopes.join(","),
                upstream.policy.upstream_auth.required_roles.join(","),
            )
        })
        .collect::<Vec<_>>();
    auth.sort_unstable();

    let admission = &bundle.runtime_config.policies.admission;
    let rate_limits = &bundle.runtime_config.policies.rate_limits;
    let resilience = format!(
        "adaptive={}..{:?};route_queue={}..{};circuit={}#{};hedging={}@{:?};retry={}@{};brownout={}%;watchdog={};scoped_rate_limits={}",
        admission.adaptive_admission.min_limit,
        admission.adaptive_admission.max_limit,
        admission.route_queue.default_cap,
        admission.route_queue.global_cap,
        admission.circuit_breaker.enabled,
        admission.circuit_breaker.failure_threshold,
        admission.hedging.enabled,
        admission.hedging.delay,
        admission.retry_budget.enabled,
        admission.retry_budget.ratio_percent,
        admission.brownout.trigger_inflight_percent,
        admission.watchdog.enabled,
        rate_limits.scoped_limits.len(),
    );

    format!("auth=[{}]; policies=[{}]", auth.join(" | "), resilience)
}

fn runtime_jwt_summary_mode(jwt: &impulse_config::runtime::RuntimeJwtAuth) -> &'static str {
    let has_hs256 = !jwt.secret.is_empty();
    let has_static_asymmetric = !jwt.static_keys.is_empty();
    let has_jwks = jwt.jwks_url.is_some();
    match (has_hs256, has_static_asymmetric, has_jwks) {
        (true, false, false) => "hs256_only",
        (false, true, false) => "static_asymmetric",
        (false, false, true) => "remote_jwks",
        (false, true, true) => "hybrid_asymmetric",
        (true, true, false) | (true, false, true) | (true, true, true) => "hybrid",
        (false, false, false) => "unconfigured",
    }
}

fn summarize_observability_control_plane(bundle: &RuntimeBundle) -> String {
    let startup = bundle.startup();
    let observability = &bundle.runtime_config.observability;
    let performance = &bundle.runtime_config.performance;
    format!(
        "log(level={},format={:?},file_enabled={},file_path={});control_api(enabled={},bind={}:{},path={});metrics(enabled={},bind={}:{},path={});tracing(enabled={},service={},otlp={:?},ratio={});control_plane_threads={}",
        startup.log_config.level,
        startup.log_config.format,
        startup.log_config.file.enabled,
        startup.log_config.file.path,
        observability.control_api.enabled,
        observability.control_api.address,
        observability.control_api.port,
        observability.control_api.runtime_path,
        observability.metrics.enabled,
        observability.metrics.address,
        observability.metrics.port,
        observability.metrics.path,
        observability.tracing.enabled,
        observability.tracing.service_name,
        observability.tracing.otlp_endpoint,
        observability.tracing.sample_ratio,
        performance.control_plane_threads,
    )
}

fn text_change_kind(current: &str, next: &str) -> ReloadChangeKind {
    if current == next {
        ReloadChangeKind::Unchanged
    } else if current.is_empty() && !next.is_empty() {
        ReloadChangeKind::Added
    } else if !current.is_empty() && next.is_empty() {
        ReloadChangeKind::Removed
    } else {
        ReloadChangeKind::Modified
    }
}

pub(super) fn rejected_startup_owned_domains(
    rejected_changes: &[RejectedChange],
) -> HashSet<ReloadDiffDomain> {
    rejected_changes
        .iter()
        .filter(|rejection| rejection.kind == RejectedChangeKind::RestartRequired)
        .filter_map(|rejection| rejection.field_path.as_deref())
        .filter_map(|field_path| {
            if field_path.starts_with("log.")
                || field_path.starts_with("observability.tracing.")
                || field_path == "performance.control_plane_threads"
            {
                Some(ReloadDiffDomain::ObservabilityControlPlane)
            } else if field_path.starts_with("upstreams[].cache.") {
                Some(ReloadDiffDomain::RoutesUpstreams)
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reload_diff_reports_noop_when_no_effective_changes_exist() {
        assert!(ReloadDiff::default().is_noop());

        let diff = ReloadDiff {
            entries: vec![ReloadDiffEntry {
                domain: "observability.metrics".to_string(),
                change: ReloadChangeKind::Unchanged,
                disposition: ReloadDiffDisposition::NoOp,
                summary: "no effective change".to_string(),
                secret_material_changed: false,
            }],
        };
        assert!(diff.is_noop());
    }

    #[test]
    fn compatibility_classification_distinguishes_reloadable_restart_required_and_rejected() {
        assert_eq!(
            classify_compatibility(&[]),
            ReloadCompatibilityClassification::LiveReloadable
        );

        let restart_required = [TransitionRejection::restart_required(
            "performance.worker_threads",
            "1",
            "8",
        )];
        assert_eq!(
            classify_compatibility(&restart_required),
            ReloadCompatibilityClassification::RestartRequired
        );

        let rejected = [TransitionRejection::resource_preflight_failed(
            "metrics listener",
            "127.0.0.1:9090",
            "bind conflict on 127.0.0.1:9090",
        )];
        assert_eq!(
            classify_compatibility(&rejected),
            ReloadCompatibilityClassification::Rejected
        );
    }
}
