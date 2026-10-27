//! Edge adapters for the shared operational observability contracts.

#[cfg(test)]
use impulse_contracts::{
    AdmissionOutcomeKind, BackendFailureReason, BackendHealthObservationOutcome,
    BackendHealthObservationSource, HedgePolicyDenialReason, RejectionReason,
    RetryPolicyDenialReason, TimeoutReason, UpstreamRetryReason,
};
pub use impulse_observability::{
    AdmissionDecisionReason, AdmissionOverloadCause, BackendHealthReason, HedgeDecisionReason,
    MetricReasonLabels, OperationalEventContext, QuotaBackendHealthReason, QuotaPolicyDecision,
    QuotaPolicyReason, RequestOutcomeReason, RetryDecisionReason, backend_health_reason,
};

#[cfg(test)]
fn admission_decision_reason(outcome: AdmissionOutcomeKind) -> AdmissionDecisionReason {
    outcome.into()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        fs,
        path::{Path, PathBuf},
    };

    use serde_json::Value as JsonValue;
    use serde_yaml::Value as YamlValue;

    use super::*;

    fn assert_unique_slug_family(slugs: &[&str], family: &str) {
        let mut values = slugs.to_vec();
        let before = values.len();
        values.sort_unstable();
        values.dedup();
        assert_eq!(
            before,
            values.len(),
            "canonical slug family `{family}` must not contain duplicate values"
        );
    }

    fn assert_reason_surface_alignment(reason: &'static str) {
        let metric_labels = MetricReasonLabels {
            outcome: None,
            reason: Some(reason),
            failure_class: None,
        };
        let control_plane_reason = reason;
        let log_ctx = OperationalEventContext::new()
            .with_reason(reason)
            .to_string();

        assert_eq!(
            metric_labels.reason,
            Some(control_plane_reason),
            "metric reason label should keep the canonical token"
        );
        assert_eq!(
            log_ctx,
            format!("reason={reason}"),
            "structured logs should render the canonical reason token verbatim"
        );
    }

    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("workspace root")
    }

    fn collect_json_exprs(value: &JsonValue, exprs: &mut Vec<String>) {
        match value {
            JsonValue::Array(values) => {
                for value in values {
                    collect_json_exprs(value, exprs);
                }
            }
            JsonValue::Object(values) => {
                for (key, value) in values {
                    if key == "expr"
                        && let Some(expr) = value.as_str()
                    {
                        exprs.push(expr.to_string());
                    }
                    collect_json_exprs(value, exprs);
                }
            }
            JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) | JsonValue::String(_) => {}
        }
    }

    fn collect_yaml_exprs(value: &YamlValue, exprs: &mut Vec<String>) {
        match value {
            YamlValue::Sequence(values) => {
                for value in values {
                    collect_yaml_exprs(value, exprs);
                }
            }
            YamlValue::Mapping(values) => {
                for (key, value) in values {
                    if key.as_str() == Some("expr")
                        && let Some(expr) = value.as_str()
                    {
                        exprs.push(expr.to_string());
                    }
                    collect_yaml_exprs(value, exprs);
                }
            }
            YamlValue::Null | YamlValue::Bool(_) | YamlValue::Number(_) | YamlValue::String(_) => {}
            YamlValue::Tagged(tagged) => collect_yaml_exprs(&tagged.value, exprs),
        }
    }

    fn packaged_observability_exprs() -> Vec<(PathBuf, String)> {
        let root = workspace_root().join("deploy/observability");
        let mut exprs = Vec::new();

        let mut dashboards = fs::read_dir(root.join("grafana"))
            .expect("grafana dashboards directory")
            .map(|entry| entry.expect("dashboard dir entry").path())
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
            .collect::<Vec<_>>();
        dashboards.sort();

        for dashboard in dashboards {
            let source = fs::read_to_string(&dashboard).expect("read dashboard");
            let value: JsonValue = serde_json::from_str(&source).expect("parse dashboard json");
            let mut dashboard_exprs = Vec::new();
            collect_json_exprs(&value, &mut dashboard_exprs);
            exprs.extend(
                dashboard_exprs
                    .into_iter()
                    .map(|expr| (dashboard.clone(), expr)),
            );
        }

        for relative in ["prometheus/recording-rules.yaml", "prometheus/alerts.yaml"] {
            let path = root.join(relative);
            let source = fs::read_to_string(&path).expect("read Prometheus rule file");
            let value: YamlValue = serde_yaml::from_str(&source).expect("parse Prometheus yaml");
            let mut rule_exprs = Vec::new();
            collect_yaml_exprs(&value, &mut rule_exprs);
            exprs.extend(rule_exprs.into_iter().map(|expr| (path.clone(), expr)));
        }

        exprs
    }

    fn extract_label_matcher_values(expr: &str, label: &str) -> BTreeSet<String> {
        let mut tokens = BTreeSet::new();

        for operator in ["=\"", "!=\"", "=~\"", "!~\""] {
            let needle = format!("{label}{operator}");
            let mut search_start = 0;

            while let Some(offset) = expr[search_start..].find(&needle) {
                let value_start = search_start + offset + needle.len();
                let Some(value_end) = expr[value_start..].find('"') else {
                    break;
                };
                let raw = &expr[value_start..value_start + value_end];
                if operator.contains('~') {
                    for token in raw.split('|') {
                        let token = token.trim();
                        if !token.is_empty() {
                            tokens.insert(token.to_string());
                        }
                    }
                } else if !raw.trim().is_empty() {
                    tokens.insert(raw.trim().to_string());
                }
                search_start = value_start + value_end + 1;
            }
        }

        tokens
    }

    fn canonical_packaged_reason_tokens() -> BTreeSet<&'static str> {
        [
            RequestOutcomeReason::Completed.slug(),
            RequestOutcomeReason::Cancelled.slug(),
            RequestOutcomeReason::TimedOut.slug(),
            RequestOutcomeReason::AuthDenied.slug(),
            RequestOutcomeReason::RateLimited.slug(),
            RequestOutcomeReason::Overloaded.slug(),
            RequestOutcomeReason::ValidationRejected.slug(),
            RequestOutcomeReason::BackendTransportFailed.slug(),
            RequestOutcomeReason::BackendProtocolFailed.slug(),
            RequestOutcomeReason::BackendTlsFailed.slug(),
            RequestOutcomeReason::BackendBridgeFailed.slug(),
            BackendHealthReason::ActiveProbeSuccess.slug(),
            BackendHealthReason::ActiveProbeFailure.slug(),
            BackendHealthReason::PassiveSuccess.slug(),
            BackendHealthReason::PassiveFailure.slug(),
            BackendHealthReason::DnsRefreshFailed.slug(),
            BackendHealthReason::EmptyResolutionRetained.slug(),
            BackendHealthReason::PoolPoisoned.slug(),
            RetryDecisionReason::UpstreamTimeout.slug(),
            RetryDecisionReason::UpstreamTransportFailure.slug(),
            RetryDecisionReason::UpstreamProtocolFailure.slug(),
            RetryDecisionReason::RetryBudgetDenied.slug(),
            RetryDecisionReason::RetryPolicyDisabled.slug(),
            RetryDecisionReason::IdempotencyDenied.slug(),
            HedgeDecisionReason::DelayElapsed.slug(),
            HedgeDecisionReason::HedgingDisabled.slug(),
            HedgeDecisionReason::PrimaryCompleted.slug(),
            HedgeDecisionReason::RequestBodyNotReplayable.slug(),
            HedgeDecisionReason::TunnelRequest.slug(),
            HedgeDecisionReason::MethodNotAllowed.slug(),
            HedgeDecisionReason::AlternateBackendUnavailable.slug(),
            HedgeDecisionReason::HedgeBudgetDenied.slug(),
            AdmissionDecisionReason::AuthDenied.slug(),
            AdmissionDecisionReason::AuthUnavailable.slug(),
            AdmissionDecisionReason::RateLimited.slug(),
            AdmissionDecisionReason::Overloaded.slug(),
            AdmissionDecisionReason::ValidationRejected.slug(),
            AdmissionDecisionReason::PolicyRejected.slug(),
            AdmissionOverloadCause::Brownout.slug(),
            AdmissionOverloadCause::AdaptiveAdmission.slug(),
            AdmissionOverloadCause::RouteCap.slug(),
            AdmissionOverloadCause::RouteGlobalCap.slug(),
            AdmissionOverloadCause::GlobalInflight.slug(),
            AdmissionOverloadCause::UpstreamInflight.slug(),
            AdmissionOverloadCause::BackendInflight.slug(),
            AdmissionOverloadCause::CircuitOpen.slug(),
            AdmissionOverloadCause::RequestBufferCap.slug(),
            AdmissionOverloadCause::ResponsePrebufferCap.slug(),
            AdmissionOverloadCause::ConnectionCap.slug(),
            QuotaPolicyDecision::Allowed.slug(),
            QuotaPolicyDecision::Denied.slug(),
            QuotaPolicyDecision::ShadowDenied.slug(),
            QuotaPolicyDecision::FailedOpen.slug(),
            QuotaPolicyDecision::FailedClosed.slug(),
            QuotaPolicyDecision::NotApplied.slug(),
            QuotaPolicyReason::Allowed.slug(),
            QuotaPolicyReason::NotApplied.slug(),
            QuotaPolicyReason::BurstQuotaExhausted.slug(),
            QuotaPolicyReason::SustainedQuotaExhausted.slug(),
            QuotaPolicyReason::SelectorIdentityMissing.slug(),
            QuotaPolicyReason::SelectorIdentityInvalid.slug(),
            QuotaPolicyReason::BackendTimeout.slug(),
            QuotaPolicyReason::BackendUnavailable.slug(),
            QuotaPolicyReason::BackendError.slug(),
            QuotaBackendHealthReason::Available.slug(),
            QuotaBackendHealthReason::Timeout.slug(),
            QuotaBackendHealthReason::Unavailable.slug(),
            QuotaBackendHealthReason::Error.slug(),
        ]
        .into_iter()
        .collect()
    }

    mod canonical_observability_slug_stability {
        use super::*;

        #[test]
        fn canonical_reason_families_use_unique_slug_values() {
            assert_unique_slug_family(
                &[
                    RequestOutcomeReason::Completed.slug(),
                    RequestOutcomeReason::Cancelled.slug(),
                    RequestOutcomeReason::TimedOut.slug(),
                    RequestOutcomeReason::AuthDenied.slug(),
                    RequestOutcomeReason::RateLimited.slug(),
                    RequestOutcomeReason::Overloaded.slug(),
                    RequestOutcomeReason::ValidationRejected.slug(),
                    RequestOutcomeReason::BackendTransportFailed.slug(),
                    RequestOutcomeReason::BackendProtocolFailed.slug(),
                    RequestOutcomeReason::BackendTlsFailed.slug(),
                    RequestOutcomeReason::BackendBridgeFailed.slug(),
                ],
                "RequestOutcomeReason",
            );
            assert_unique_slug_family(
                &[
                    BackendHealthReason::ActiveProbeSuccess.slug(),
                    BackendHealthReason::ActiveProbeFailure.slug(),
                    BackendHealthReason::PassiveSuccess.slug(),
                    BackendHealthReason::PassiveFailure.slug(),
                    BackendHealthReason::DnsRefreshFailed.slug(),
                    BackendHealthReason::EmptyResolutionRetained.slug(),
                    BackendHealthReason::PoolPoisoned.slug(),
                ],
                "BackendHealthReason",
            );
            assert_unique_slug_family(
                &[
                    RetryDecisionReason::UpstreamTimeout.slug(),
                    RetryDecisionReason::UpstreamTransportFailure.slug(),
                    RetryDecisionReason::UpstreamProtocolFailure.slug(),
                    RetryDecisionReason::RetryBudgetDenied.slug(),
                    RetryDecisionReason::RetryPolicyDisabled.slug(),
                    RetryDecisionReason::IdempotencyDenied.slug(),
                ],
                "RetryDecisionReason",
            );
            assert_unique_slug_family(
                &[
                    HedgeDecisionReason::DelayElapsed.slug(),
                    HedgeDecisionReason::HedgingDisabled.slug(),
                    HedgeDecisionReason::PrimaryCompleted.slug(),
                    HedgeDecisionReason::RequestBodyNotReplayable.slug(),
                    HedgeDecisionReason::TunnelRequest.slug(),
                    HedgeDecisionReason::MethodNotAllowed.slug(),
                    HedgeDecisionReason::AlternateBackendUnavailable.slug(),
                    HedgeDecisionReason::HedgeBudgetDenied.slug(),
                ],
                "HedgeDecisionReason",
            );
            assert_unique_slug_family(
                &[
                    AdmissionDecisionReason::AuthDenied.slug(),
                    AdmissionDecisionReason::AuthUnavailable.slug(),
                    AdmissionDecisionReason::RateLimited.slug(),
                    AdmissionDecisionReason::Overloaded.slug(),
                    AdmissionDecisionReason::ValidationRejected.slug(),
                    AdmissionDecisionReason::PolicyRejected.slug(),
                ],
                "AdmissionDecisionReason",
            );
            assert_unique_slug_family(
                &[
                    AdmissionOverloadCause::Brownout.slug(),
                    AdmissionOverloadCause::AdaptiveAdmission.slug(),
                    AdmissionOverloadCause::RouteCap.slug(),
                    AdmissionOverloadCause::RouteGlobalCap.slug(),
                    AdmissionOverloadCause::GlobalInflight.slug(),
                    AdmissionOverloadCause::UpstreamInflight.slug(),
                    AdmissionOverloadCause::BackendInflight.slug(),
                    AdmissionOverloadCause::CircuitOpen.slug(),
                    AdmissionOverloadCause::RequestBufferCap.slug(),
                    AdmissionOverloadCause::ResponsePrebufferCap.slug(),
                    AdmissionOverloadCause::ConnectionCap.slug(),
                ],
                "AdmissionOverloadCause",
            );
            assert_unique_slug_family(
                &[
                    QuotaPolicyDecision::Allowed.slug(),
                    QuotaPolicyDecision::Denied.slug(),
                    QuotaPolicyDecision::ShadowDenied.slug(),
                    QuotaPolicyDecision::FailedOpen.slug(),
                    QuotaPolicyDecision::FailedClosed.slug(),
                    QuotaPolicyDecision::NotApplied.slug(),
                ],
                "QuotaPolicyDecision",
            );
            assert_unique_slug_family(
                &[
                    QuotaPolicyReason::Allowed.slug(),
                    QuotaPolicyReason::NotApplied.slug(),
                    QuotaPolicyReason::BurstQuotaExhausted.slug(),
                    QuotaPolicyReason::SustainedQuotaExhausted.slug(),
                    QuotaPolicyReason::SelectorIdentityMissing.slug(),
                    QuotaPolicyReason::SelectorIdentityInvalid.slug(),
                    QuotaPolicyReason::BackendTimeout.slug(),
                    QuotaPolicyReason::BackendUnavailable.slug(),
                    QuotaPolicyReason::BackendError.slug(),
                ],
                "QuotaPolicyReason",
            );
            assert_unique_slug_family(
                &[
                    QuotaBackendHealthReason::Available.slug(),
                    QuotaBackendHealthReason::Timeout.slug(),
                    QuotaBackendHealthReason::Unavailable.slug(),
                    QuotaBackendHealthReason::Error.slug(),
                ],
                "QuotaBackendHealthReason",
            );
        }

        #[test]
        fn overload_metric_reason_labels_follow_canonical_cause_vocabulary() {
            // obs Phase 2 (step 5): the metrics `reason=` label must come from the
            // canonical vocabulary. Every OverloadShedReason maps to a canonical cause
            // whose slug is the emitted label.
            use crate::metrics::OverloadShedReason;
            let cases = [
                (
                    OverloadShedReason::Brownout,
                    AdmissionOverloadCause::Brownout,
                ),
                (
                    OverloadShedReason::AdaptiveAdmission,
                    AdmissionOverloadCause::AdaptiveAdmission,
                ),
                (
                    OverloadShedReason::RouteCap,
                    AdmissionOverloadCause::RouteCap,
                ),
                (
                    OverloadShedReason::RouteGlobalCap,
                    AdmissionOverloadCause::RouteGlobalCap,
                ),
                (
                    OverloadShedReason::GlobalInflight,
                    AdmissionOverloadCause::GlobalInflight,
                ),
                (
                    OverloadShedReason::UpstreamInflight,
                    AdmissionOverloadCause::UpstreamInflight,
                ),
                (
                    OverloadShedReason::BackendInflight,
                    AdmissionOverloadCause::BackendInflight,
                ),
                (
                    OverloadShedReason::CircuitOpen,
                    AdmissionOverloadCause::CircuitOpen,
                ),
                (
                    OverloadShedReason::RequestBufferCap,
                    AdmissionOverloadCause::RequestBufferCap,
                ),
                (
                    OverloadShedReason::ResponsePrebufferCap,
                    AdmissionOverloadCause::ResponsePrebufferCap,
                ),
                (
                    OverloadShedReason::ConnectionCap,
                    AdmissionOverloadCause::ConnectionCap,
                ),
            ];
            for (reason, cause) in cases {
                assert_eq!(reason.canonical(), cause);
                assert_eq!(reason.reason_label(), cause.slug());
            }
        }

        #[test]
        fn overload_cause_slugs_match_legacy_metric_labels() {
            // These must stay byte-identical to `OverloadShedReason` labels so a later
            // migration of the overload emitter does not change the `reason=` series.
            assert_eq!(
                AdmissionOverloadCause::GlobalInflight.slug(),
                "global_inflight"
            );
            assert_eq!(
                AdmissionOverloadCause::ResponsePrebufferCap.slug(),
                "response_prebuffer_cap"
            );
        }

        #[test]
        fn request_outcome_coarse_labels_preserve_legacy_metric_buckets() {
            assert_eq!(
                RequestOutcomeReason::Completed.coarse_outcome_label(),
                "success"
            );
            assert_eq!(
                RequestOutcomeReason::TimedOut.coarse_outcome_label(),
                "timeout"
            );
            assert_eq!(
                RequestOutcomeReason::Overloaded.coarse_outcome_label(),
                "overload_shed"
            );
            assert_eq!(
                RequestOutcomeReason::AuthDenied.coarse_outcome_label(),
                "failure"
            );
        }

        #[test]
        fn representative_canonical_slugs_remain_stable() {
            assert_eq!(AdmissionDecisionReason::AuthDenied.slug(), "auth_denied");
            assert_eq!(
                RetryDecisionReason::UpstreamTransportFailure.slug(),
                "upstream_transport_failure"
            );
            assert_eq!(
                HedgeDecisionReason::AlternateBackendUnavailable.slug(),
                "alternate_backend_unavailable"
            );
            assert_eq!(
                BackendHealthReason::DnsRefreshFailed.slug(),
                "dns_refresh_failed"
            );
            assert_eq!(RequestOutcomeReason::TimedOut.slug(), "timed_out");
        }
    }

    mod cross_surface_reason_alignment {
        use super::*;

        #[test]
        fn operational_event_context_renders_canonical_fields_in_stable_order() {
            let ctx = OperationalEventContext::new()
                .with_request_id(42)
                .with_upstream("api")
                .with_backend("10.0.0.1:8080")
                .with_reason("timed_out");
            assert_eq!(
                ctx.to_string(),
                "request_id=42 upstream=api backend=10.0.0.1:8080 reason=timed_out"
            );
        }

        #[test]
        fn empty_event_context_renders_nothing() {
            assert_eq!(OperationalEventContext::new().to_string(), "");
        }

        #[test]
        fn local_rejection_maps_to_canonical_request_outcome() {
            assert_eq!(
                RequestOutcomeReason::from(RejectionReason::AuthDenied),
                RequestOutcomeReason::AuthDenied
            );
            assert_eq!(
                RequestOutcomeReason::from(RejectionReason::AuthUnavailable),
                RequestOutcomeReason::AuthDenied
            );
            assert_eq!(
                RequestOutcomeReason::from(RejectionReason::RequestBodyTooLarge),
                RequestOutcomeReason::ValidationRejected
            );
            assert_eq!(
                RequestOutcomeReason::from(RejectionReason::QuotaDenied),
                RequestOutcomeReason::RateLimited
            );
            assert_eq!(
                RequestOutcomeReason::from(RejectionReason::ResponsePrebufferCap),
                RequestOutcomeReason::Overloaded
            );
        }

        #[test]
        fn local_backend_failure_maps_to_canonical_transport_class() {
            assert_eq!(
                RequestOutcomeReason::from(BackendFailureReason::UpstreamTimeout),
                RequestOutcomeReason::TimedOut
            );
            assert_eq!(
                RequestOutcomeReason::from(BackendFailureReason::UpstreamTls),
                RequestOutcomeReason::BackendTlsFailed
            );
            assert_eq!(
                RequestOutcomeReason::from(BackendFailureReason::UpstreamProtocol),
                RequestOutcomeReason::BackendProtocolFailed
            );
            assert_eq!(
                RequestOutcomeReason::from(BackendFailureReason::UpstreamBridge),
                RequestOutcomeReason::BackendBridgeFailed
            );
            assert_eq!(
                RequestOutcomeReason::from(BackendFailureReason::DispatchSpawnFailed),
                RequestOutcomeReason::BackendTransportFailed
            );
        }

        #[test]
        fn backend_health_observation_maps_to_canonical_health_reason() {
            use BackendHealthObservationOutcome as O;
            use BackendHealthObservationSource as S;
            assert_eq!(
                backend_health_reason(S::ActiveCheck, O::Success),
                Some(BackendHealthReason::ActiveProbeSuccess)
            );
            assert_eq!(
                backend_health_reason(S::ActiveCheck, O::Failure),
                Some(BackendHealthReason::ActiveProbeFailure)
            );
            assert_eq!(
                backend_health_reason(S::PassiveRequest, O::Failure),
                Some(BackendHealthReason::PassiveFailure)
            );
            // Neutral observations carry no health reason.
            assert_eq!(backend_health_reason(S::ActiveCheck, O::Neutral), None);
        }

        #[test]
        fn admission_outcome_maps_to_canonical_decision_reason() {
            assert_eq!(
                admission_decision_reason(AdmissionOutcomeKind::AuthDenied),
                AdmissionDecisionReason::AuthDenied
            );
            assert_eq!(
                admission_decision_reason(AdmissionOutcomeKind::RateLimited),
                AdmissionDecisionReason::RateLimited
            );
            assert_eq!(
                admission_decision_reason(AdmissionOutcomeKind::QuotaDenied),
                AdmissionDecisionReason::RateLimited
            );
            assert_eq!(
                admission_decision_reason(AdmissionOutcomeKind::OverloadShed),
                AdmissionDecisionReason::Overloaded
            );
            assert_eq!(
                admission_decision_reason(AdmissionOutcomeKind::Failed),
                AdmissionDecisionReason::PolicyRejected
            );
        }

        #[test]
        fn admission_log_reason_literals_match_canonical_slugs() {
            // obs Phase 7: the `reason=` values emitted by the forwarding/bootstrap
            // admission logs are the canonical AdmissionDecisionReason slugs. This
            // guards those hand-written literals against enum drift.
            assert_eq!(AdmissionDecisionReason::AuthDenied.slug(), "auth_denied");
            assert_eq!(
                AdmissionDecisionReason::AuthUnavailable.slug(),
                "auth_unavailable"
            );
            assert_eq!(AdmissionDecisionReason::RateLimited.slug(), "rate_limited");
            assert_eq!(AdmissionDecisionReason::Overloaded.slug(), "overloaded");
        }

        #[test]
        fn quota_log_reason_literals_match_canonical_slugs() {
            assert_eq!(QuotaPolicyDecision::Allowed.slug(), "allowed");
            assert_eq!(QuotaPolicyDecision::ShadowDenied.slug(), "shadow_denied");
            assert_eq!(
                QuotaPolicyReason::BurstQuotaExhausted.slug(),
                "burst_quota_exhausted"
            );
            assert_eq!(
                QuotaPolicyReason::BackendUnavailable.slug(),
                "backend_unavailable"
            );
            assert_eq!(QuotaBackendHealthReason::Available.slug(), "available");
            assert_eq!(QuotaBackendHealthReason::Timeout.slug(), "timeout");
        }

        #[test]
        fn representative_reason_tokens_stay_aligned_across_metrics_logs_and_control_plane() {
            use crate::metrics::OverloadShedReason;

            assert_reason_surface_alignment(RequestOutcomeReason::TimedOut.slug());
            assert_reason_surface_alignment(
                RequestOutcomeReason::from(BackendFailureReason::UpstreamTransport).slug(),
            );
            assert_reason_surface_alignment(
                RequestOutcomeReason::from(BackendFailureReason::UpstreamTls).slug(),
            );
            assert_reason_surface_alignment(
                admission_decision_reason(AdmissionOutcomeKind::AuthDenied).slug(),
            );
            assert_reason_surface_alignment(
                admission_decision_reason(AdmissionOutcomeKind::RateLimited).slug(),
            );
            assert_reason_surface_alignment(
                admission_decision_reason(AdmissionOutcomeKind::QuotaDenied).slug(),
            );
            assert_reason_surface_alignment(
                admission_decision_reason(AdmissionOutcomeKind::OverloadShed).slug(),
            );
            assert_reason_surface_alignment(QuotaPolicyDecision::Denied.slug());
            assert_reason_surface_alignment(QuotaPolicyReason::BackendError.slug());
            assert_reason_surface_alignment(QuotaBackendHealthReason::Unavailable.slug());

            assert_eq!(
                OverloadShedReason::GlobalInflight.reason_label(),
                AdmissionOverloadCause::GlobalInflight.slug()
            );
        }

        #[test]
        fn packaged_dashboards_and_alerts_only_reference_canonical_reason_vocabularies() {
            let canonical = canonical_packaged_reason_tokens();
            let mut unknown = Vec::new();

            for (path, expr) in packaged_observability_exprs() {
                for label in ["reason", "decision"] {
                    for token in extract_label_matcher_values(&expr, label) {
                        if !canonical.contains(token.as_str()) {
                            unknown.push(format!(
                                "{} references unknown {label} slug `{token}` in `{expr}`",
                                path.display()
                            ));
                        }
                    }
                }
            }

            assert!(
                unknown.is_empty(),
                "packaged observability artifacts drifted from the canonical reason vocabulary:\n{}",
                unknown.join("\n")
            );
        }

        #[test]
        fn retry_and_hedge_denials_map_to_canonical_reasons() {
            assert_eq!(
                RetryDecisionReason::from(UpstreamRetryReason::Timeout),
                RetryDecisionReason::UpstreamTimeout
            );
            assert_eq!(
                RetryDecisionReason::from(RetryPolicyDenialReason::BudgetDenied),
                RetryDecisionReason::RetryBudgetDenied
            );
            assert_eq!(
                RetryDecisionReason::from(RetryPolicyDenialReason::MethodNotIdempotent),
                RetryDecisionReason::IdempotencyDenied
            );
            assert_eq!(
                RetryDecisionReason::from(RetryPolicyDenialReason::RequestBodyNotReplayable),
                RetryDecisionReason::IdempotencyDenied
            );
            assert_eq!(
                RetryDecisionReason::from(RetryPolicyDenialReason::AttemptLimitReached),
                RetryDecisionReason::RetryPolicyDisabled
            );
            assert_eq!(
                RetryDecisionReason::from(RetryPolicyDenialReason::AlternateBackendUnavailable(
                    impulse_lb::alternate_backend::AlternateBackendFailureReason::NoHealthyBackends
                )),
                RetryDecisionReason::RetryPolicyDisabled
            );
            assert_eq!(
                HedgeDecisionReason::from(HedgePolicyDenialReason::TunnelRequest),
                HedgeDecisionReason::TunnelRequest
            );
            assert_eq!(
                HedgeDecisionReason::from(HedgePolicyDenialReason::PrimaryRequestCompleted),
                HedgeDecisionReason::PrimaryCompleted
            );
            assert_eq!(
                HedgeDecisionReason::from(HedgePolicyDenialReason::AlternateBackendUnavailable(
                    impulse_lb::alternate_backend::AlternateBackendFailureReason::NoHealthyBackends
                )),
                HedgeDecisionReason::AlternateBackendUnavailable
            );
            assert_eq!(
                HedgeDecisionReason::from(HedgePolicyDenialReason::BudgetDenied),
                HedgeDecisionReason::HedgeBudgetDenied
            );
        }

        #[test]
        fn retry_and_hedge_reason_slugs_preserve_trigger_vs_denial_contract() {
            assert_eq!(
                RetryDecisionReason::UpstreamTimeout.slug(),
                "upstream_timeout"
            );
            assert!(RetryDecisionReason::UpstreamTimeout.is_retry());
            assert_eq!(
                RetryDecisionReason::RetryBudgetDenied.slug(),
                "retry_budget_denied"
            );
            assert!(!RetryDecisionReason::RetryBudgetDenied.is_retry());
            assert_eq!(HedgeDecisionReason::DelayElapsed.slug(), "delay_elapsed");
            assert!(HedgeDecisionReason::DelayElapsed.is_triggered());
            assert_eq!(
                HedgeDecisionReason::HedgeBudgetDenied.slug(),
                "hedge_budget_denied"
            );
            assert!(!HedgeDecisionReason::HedgeBudgetDenied.is_triggered());
        }

        #[test]
        fn retry_and_outcome_mappings_stay_aligned_but_distinct_by_failure_class() {
            use impulse_contracts::{
                RetryPolicyDenialReason, UpstreamRetryReason, UpstreamTerminalErrorKind,
            };

            assert_eq!(
                RetryDecisionReason::from(UpstreamRetryReason::Transport),
                RetryDecisionReason::UpstreamTransportFailure
            );
            assert_eq!(
                RequestOutcomeReason::from(BackendFailureReason::UpstreamTransport),
                RequestOutcomeReason::BackendTransportFailed
            );

            assert_eq!(
                RetryDecisionReason::from(RetryPolicyDenialReason::TerminalError(
                    UpstreamTerminalErrorKind::Protocol
                )),
                RetryDecisionReason::RetryPolicyDisabled
            );
            assert_eq!(
                RequestOutcomeReason::from(BackendFailureReason::UpstreamProtocol),
                RequestOutcomeReason::BackendProtocolFailed
            );

            assert_eq!(
                RetryDecisionReason::from(RetryPolicyDenialReason::TerminalError(
                    UpstreamTerminalErrorKind::Bridge
                )),
                RetryDecisionReason::RetryPolicyDisabled
            );
            assert_eq!(
                RequestOutcomeReason::from(BackendFailureReason::UpstreamBridge),
                RequestOutcomeReason::BackendBridgeFailed
            );
        }
    }
}
