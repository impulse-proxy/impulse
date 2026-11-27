use std::{collections::HashMap, time::Duration};

use super::{
    RuntimeQuotaPolicySet, config_invalid, normalize_optional_string,
    resilience::{normalize_circuit_breaker_policy, normalize_retry_budget_policy},
    watchdog::normalize_watchdog_policy,
};
use crate::{
    config::Resilience,
    policy_helpers::early_data_methods_are_safe,
    runtime::{RuntimeConfigError, RuntimeProtocolPolicy},
    validator::is_valid_http_token,
};

fn require_nonzero_usize(name: &str, value: usize) -> Result<(), RuntimeConfigError> {
    if value == 0 {
        return Err(config_invalid(format!("{name} must be greater than 0")));
    }
    Ok(())
}

fn normalize_string_vec(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn normalize_nonempty_string_vec(
    field_name: &str,
    values: &[String],
) -> Result<Vec<String>, RuntimeConfigError> {
    let normalized = normalize_string_vec(values);
    if normalized.len() != values.len() {
        return Err(config_invalid(format!(
            "{field_name} must not contain empty values"
        )));
    }
    Ok(normalized)
}

fn is_valid_connect_authority(authority: &str) -> bool {
    let Some((host, port)) = authority.rsplit_once(':') else {
        return false;
    };
    !host.trim().is_empty() && port.parse::<u16>().ok().is_some_and(|parsed| parsed > 0)
}

fn is_valid_request_key_spec(key_spec: &str) -> bool {
    let key_spec = key_spec.trim().to_ascii_lowercase();
    matches!(
        key_spec.as_str(),
        "path"
            | "authority"
            | "method"
            | "cid"
            | "sticky-cid"
            | "peer_ip"
            | "client_ip"
            | "bearer_token"
    ) || key_spec.split_once(':').is_some_and(|(source, key_name)| {
        !key_name.trim().is_empty() && matches!(source.trim(), "header" | "cookie" | "query")
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeScopedRateLimitPolicy {
    pub name: String,
    pub scope: crate::config::ScopedRateLimitScope,
    pub requests_per_sec: u32,
    pub burst: u32,
    pub key: Option<String>,
    pub route_allowlist: Vec<String>,
    pub idle_ttl: Duration,
}

impl RuntimeScopedRateLimitPolicy {
    pub(crate) fn normalize(
        rule: &crate::config::ScopedRateLimit,
    ) -> Result<Self, RuntimeConfigError> {
        let rule_name = rule.name.trim();
        if rule_name.is_empty() {
            return Err(config_invalid(
                "resilience.scoped_rate_limits[].name must be non-empty",
            ));
        }
        if rule.requests_per_sec == 0 {
            return Err(config_invalid(format!(
                "resilience.scoped_rate_limits['{}'].requests_per_sec must be greater than 0",
                rule_name
            )));
        }
        if rule.burst == 0 {
            return Err(config_invalid(format!(
                "resilience.scoped_rate_limits['{}'].burst must be greater than 0",
                rule_name
            )));
        }
        if rule.idle_ttl_secs == 0 {
            return Err(config_invalid(format!(
                "resilience.scoped_rate_limits['{}'].idle_ttl_secs must be greater than 0",
                rule_name
            )));
        }
        let route_allowlist = normalize_string_vec(&rule.route_allowlist);
        if route_allowlist.len() != rule.route_allowlist.len() {
            return Err(config_invalid(format!(
                "resilience.scoped_rate_limits['{}'].route_allowlist must not contain empty values",
                rule_name
            )));
        }

        let key = normalize_optional_string(rule.key.as_deref());
        match rule.scope {
            crate::config::ScopedRateLimitScope::Route => {
                if key.is_some() {
                    return Err(config_invalid(format!(
                        "resilience.scoped_rate_limits['{}'].key is invalid for scope=route",
                        rule_name
                    )));
                }
            }
            crate::config::ScopedRateLimitScope::Tenant => {
                let Some(key_spec) = key.as_deref() else {
                    return Err(config_invalid(format!(
                        "resilience.scoped_rate_limits['{}'].key is required for scope=tenant",
                        rule_name
                    )));
                };
                if !is_valid_request_key_spec(key_spec) {
                    return Err(config_invalid(format!(
                        "resilience.scoped_rate_limits['{}'].key must be a supported request key spec",
                        rule_name
                    )));
                }
            }
            crate::config::ScopedRateLimitScope::Client
            | crate::config::ScopedRateLimitScope::Token => {
                if let Some(key_spec) = key.as_deref()
                    && !is_valid_request_key_spec(key_spec)
                {
                    return Err(config_invalid(format!(
                        "resilience.scoped_rate_limits['{}'].key must be a supported request key spec",
                        rule_name
                    )));
                }
            }
        }

        Ok(Self {
            name: rule.name.clone(),
            scope: rule.scope,
            requests_per_sec: rule.requests_per_sec,
            burst: rule.burst,
            key,
            route_allowlist,
            idle_ttl: Duration::from_secs(rule.idle_ttl_secs),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeAdaptiveAdmissionPolicy {
    pub enabled: bool,
    pub min_limit: usize,
    pub max_limit: usize,
    pub decrease_step: usize,
    pub increase_step: usize,
    pub high_latency: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeRouteQueuePolicy {
    pub default_cap: usize,
    pub global_cap: usize,
    pub shed_retry_after_seconds: u32,
    pub caps: HashMap<String, usize>,
}

impl RuntimeRouteQueuePolicy {
    pub fn clamped(&self, default_cap_limit: usize, global_cap_limit: usize) -> Self {
        let mut clamped = self.clone();
        clamped.default_cap = clamped.default_cap.min(default_cap_limit).max(1);
        clamped.global_cap = clamped.global_cap.min(global_cap_limit).max(1);
        for cap in clamped.caps.values_mut() {
            *cap = (*cap).min(default_cap_limit).max(1);
        }
        clamped
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBrownoutPolicy {
    pub enabled: bool,
    pub trigger_inflight_percent: u8,
    pub recover_inflight_percent: u8,
    pub core_routes: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeRateLimitPolicy {
    pub scoped_limits: Vec<RuntimeScopedRateLimitPolicy>,
    pub quota: RuntimeQuotaPolicySet,
}

impl RuntimeRateLimitPolicy {
    pub(crate) fn normalize(resilience: &Resilience) -> Result<Self, RuntimeConfigError> {
        let mut seen_names = std::collections::HashSet::new();
        let mut scoped_limits = Vec::with_capacity(resilience.scoped_rate_limits.len());
        for rule in &resilience.scoped_rate_limits {
            let normalized = RuntimeScopedRateLimitPolicy::normalize(rule)?;
            if !seen_names.insert(normalized.name.clone()) {
                return Err(config_invalid(format!(
                    "resilience.scoped_rate_limits contains duplicate rule name '{}'",
                    normalized.name
                )));
            }
            scoped_limits.push(normalized);
        }

        Ok(Self {
            scoped_limits,
            quota: RuntimeQuotaPolicySet::normalize(resilience)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeAdmissionPolicy {
    pub adaptive_admission: RuntimeAdaptiveAdmissionPolicy,
    pub route_queue: RuntimeRouteQueuePolicy,
    pub circuit_breaker: super::RuntimeCircuitBreakerPolicy,
    pub retry_budget: super::RuntimeRetryBudgetPolicy,
    pub brownout: RuntimeBrownoutPolicy,
    pub watchdog: super::RuntimeWatchdogPolicy,
    pub protocol: RuntimeProtocolPolicy,
}

impl RuntimeAdmissionPolicy {
    pub(crate) fn normalize(
        resilience: &Resilience,
        global_inflight_limit: usize,
    ) -> Result<Self, RuntimeConfigError> {
        if resilience.adaptive_admission.min_limit == 0 {
            return Err(config_invalid(
                "resilience.adaptive_admission.min_limit must be greater than 0",
            ));
        }
        if let Some(max_limit) = resilience.adaptive_admission.max_limit {
            if max_limit == 0 {
                return Err(config_invalid(
                    "resilience.adaptive_admission.max_limit must be greater than 0",
                ));
            }
            if max_limit < resilience.adaptive_admission.min_limit {
                return Err(config_invalid(format!(
                    "resilience.adaptive_admission.max_limit ({}) must be >= min_limit ({})",
                    max_limit, resilience.adaptive_admission.min_limit
                )));
            }
            if max_limit > global_inflight_limit {
                return Err(config_invalid(format!(
                    "resilience.adaptive_admission.max_limit ({}) must be <= performance.global_inflight_limit ({})",
                    max_limit, global_inflight_limit
                )));
            }
        }
        require_nonzero_usize(
            "resilience.adaptive_admission.decrease_step",
            resilience.adaptive_admission.decrease_step,
        )?;
        require_nonzero_usize(
            "resilience.adaptive_admission.increase_step",
            resilience.adaptive_admission.increase_step,
        )?;

        require_nonzero_usize(
            "resilience.route_queue.default_cap",
            resilience.route_queue.default_cap,
        )?;
        require_nonzero_usize(
            "resilience.route_queue.global_cap",
            resilience.route_queue.global_cap,
        )?;
        if resilience.route_queue.shed_retry_after_seconds == 0 {
            return Err(config_invalid(
                "resilience.route_queue.shed_retry_after_seconds must be greater than 0",
            ));
        }
        if resilience.route_queue.caps.values().any(|cap| *cap == 0) {
            return Err(config_invalid(
                "resilience.route_queue.caps values must be greater than 0",
            ));
        }

        let early_data_safe_methods = normalize_nonempty_string_vec(
            "resilience.protocol.early_data_safe_methods",
            &resilience.protocol.early_data_safe_methods,
        )?;
        if early_data_safe_methods
            .iter()
            .any(|method| !is_valid_http_token(method))
        {
            return Err(config_invalid(
                "resilience.protocol.early_data_safe_methods must contain valid HTTP method tokens",
            ));
        }
        let allowed_methods = normalize_nonempty_string_vec(
            "resilience.protocol.allowed_methods",
            &resilience.protocol.allowed_methods,
        )?;
        if allowed_methods
            .iter()
            .any(|method| !is_valid_http_token(method))
        {
            return Err(config_invalid(
                "resilience.protocol.allowed_methods must contain valid HTTP method tokens",
            ));
        }
        let denied_path_prefixes = normalize_nonempty_string_vec(
            "resilience.protocol.denied_path_prefixes",
            &resilience.protocol.denied_path_prefixes,
        )?;
        if denied_path_prefixes
            .iter()
            .any(|prefix| !prefix.starts_with('/'))
        {
            return Err(config_invalid(
                "resilience.protocol.denied_path_prefixes must contain '/'-prefixed paths",
            ));
        }
        require_nonzero_usize(
            "resilience.protocol.max_headers_count",
            resilience.protocol.max_headers_count,
        )?;
        require_nonzero_usize(
            "resilience.protocol.max_headers_bytes",
            resilience.protocol.max_headers_bytes,
        )?;
        if !resilience.protocol.allow_connect
            && (!resilience.protocol.connect_allowed_ports.is_empty()
                || !resilience.protocol.connect_allowed_authorities.is_empty())
        {
            return Err(config_invalid(
                "resilience.protocol.connect_allowed_ports/connect_allowed_authorities require allow_connect=true",
            ));
        }
        if resilience.protocol.connect_allowed_ports.contains(&0) {
            return Err(config_invalid(
                "resilience.protocol.connect_allowed_ports must contain ports in range 1-65535",
            ));
        }
        if resilience
            .protocol
            .connect_allowed_authorities
            .iter()
            .any(|authority| !is_valid_connect_authority(authority))
        {
            return Err(config_invalid(
                "resilience.protocol.connect_allowed_authorities must contain authority-form host:port targets",
            ));
        }
        if resilience.protocol.allow_0rtt && early_data_safe_methods.is_empty() {
            return Err(config_invalid(
                "resilience.protocol.early_data_safe_methods must be non-empty when allow_0rtt=true",
            ));
        }
        if resilience.protocol.allow_0rtt && !early_data_methods_are_safe(&early_data_safe_methods)
        {
            return Err(config_invalid(
                "resilience.protocol.early_data_safe_methods may contain only GET or HEAD when allow_0rtt=true",
            ));
        }

        if resilience.brownout.trigger_inflight_percent > 100
            || resilience.brownout.recover_inflight_percent > 100
        {
            return Err(config_invalid(
                "resilience.brownout inflight percentages must be <= 100",
            ));
        }
        if resilience.brownout.recover_inflight_percent
            >= resilience.brownout.trigger_inflight_percent
        {
            return Err(config_invalid(
                "resilience.brownout.recover_inflight_percent must be < trigger_inflight_percent",
            ));
        }

        let mut protocol = resilience.protocol.clone();
        protocol.early_data_safe_methods = early_data_safe_methods;
        protocol.allowed_methods = allowed_methods;
        protocol.denied_path_prefixes = denied_path_prefixes;
        Ok(Self {
            adaptive_admission: RuntimeAdaptiveAdmissionPolicy {
                enabled: resilience.adaptive_admission.enabled,
                min_limit: resilience.adaptive_admission.min_limit,
                max_limit: resilience
                    .adaptive_admission
                    .max_limit
                    .unwrap_or(global_inflight_limit)
                    .max(resilience.adaptive_admission.min_limit),
                decrease_step: resilience.adaptive_admission.decrease_step,
                increase_step: resilience.adaptive_admission.increase_step,
                high_latency: Duration::from_millis(resilience.adaptive_admission.high_latency_ms),
            },
            route_queue: RuntimeRouteQueuePolicy {
                default_cap: resilience.route_queue.default_cap,
                global_cap: resilience.route_queue.global_cap,
                shed_retry_after_seconds: resilience.route_queue.shed_retry_after_seconds.max(1),
                caps: resilience.route_queue.caps.clone(),
            },
            circuit_breaker: normalize_circuit_breaker_policy(resilience)?,
            retry_budget: normalize_retry_budget_policy(resilience)?,
            brownout: RuntimeBrownoutPolicy {
                enabled: resilience.brownout.enabled,
                trigger_inflight_percent: resilience.brownout.trigger_inflight_percent,
                recover_inflight_percent: resilience.brownout.recover_inflight_percent,
                core_routes: normalize_string_vec(&resilience.brownout.core_routes),
            },
            watchdog: normalize_watchdog_policy(resilience)?,
            protocol: RuntimeProtocolPolicy(protocol),
        })
    }

    pub fn with_runtime_overrides(
        &self,
        default_route_cap_limit: usize,
        global_route_cap_limit: usize,
        adaptive_high_latency_limit: Duration,
    ) -> Self {
        let mut updated = self.clone();
        updated.route_queue = updated
            .route_queue
            .clamped(default_route_cap_limit, global_route_cap_limit);
        if updated.adaptive_admission.high_latency > adaptive_high_latency_limit {
            updated.adaptive_admission.high_latency = adaptive_high_latency_limit;
        }
        updated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Resilience, ScopedRateLimit, ScopedRateLimitScope};

    fn assert_config_invalid(err: RuntimeConfigError, expected: impl AsRef<str>) {
        let expected = expected.as_ref();
        assert_eq!(err.category(), "config_invalid");
        assert_eq!(err.to_string(), format!("config_invalid: {expected}"));
    }

    fn valid_scoped_rule(scope: ScopedRateLimitScope) -> ScopedRateLimit {
        ScopedRateLimit {
            name: "tenant-budget".to_string(),
            scope,
            requests_per_sec: 25,
            burst: 50,
            key: None,
            route_allowlist: vec!["payments".to_string()],
            idle_ttl_secs: 60,
        }
    }

    fn valid_resilience() -> Resilience {
        Resilience::default()
    }

    #[test]
    fn scoped_rate_limit_normalization_shapes_route_client_tenant_and_token_scopes() {
        let route = RuntimeScopedRateLimitPolicy::normalize(&ScopedRateLimit {
            name: "route-limit".to_string(),
            scope: ScopedRateLimitScope::Route,
            ..valid_scoped_rule(ScopedRateLimitScope::Route)
        })
        .expect("route rule");
        assert_eq!(route.scope, ScopedRateLimitScope::Route);
        assert_eq!(route.key, None);

        let client = RuntimeScopedRateLimitPolicy::normalize(&ScopedRateLimit {
            name: "client-limit".to_string(),
            scope: ScopedRateLimitScope::Client,
            key: Some("  header:x-client-id  ".to_string()),
            ..valid_scoped_rule(ScopedRateLimitScope::Client)
        })
        .expect("client rule");
        assert_eq!(client.key.as_deref(), Some("header:x-client-id"));

        let tenant = RuntimeScopedRateLimitPolicy::normalize(&ScopedRateLimit {
            name: "tenant-limit".to_string(),
            scope: ScopedRateLimitScope::Tenant,
            key: Some(" query:tenant ".to_string()),
            ..valid_scoped_rule(ScopedRateLimitScope::Tenant)
        })
        .expect("tenant rule");
        assert_eq!(tenant.key.as_deref(), Some("query:tenant"));

        let token = RuntimeScopedRateLimitPolicy::normalize(&ScopedRateLimit {
            name: "token-limit".to_string(),
            scope: ScopedRateLimitScope::Token,
            key: Some(" bearer_token ".to_string()),
            ..valid_scoped_rule(ScopedRateLimitScope::Token)
        })
        .expect("token rule");
        assert_eq!(token.key.as_deref(), Some("bearer_token"));
        assert_eq!(token.idle_ttl, Duration::from_secs(60));
    }

    #[test]
    fn rate_limit_normalization_rejects_duplicate_rule_names() {
        let mut resilience = valid_resilience();
        resilience.scoped_rate_limits = vec![
            ScopedRateLimit {
                name: "client-limit".to_string(),
                scope: ScopedRateLimitScope::Client,
                key: Some("header:x-client-id".to_string()),
                ..valid_scoped_rule(ScopedRateLimitScope::Client)
            },
            ScopedRateLimit {
                name: "client-limit".to_string(),
                scope: ScopedRateLimitScope::Token,
                key: Some("bearer_token".to_string()),
                ..valid_scoped_rule(ScopedRateLimitScope::Token)
            },
        ];

        let err = RuntimeRateLimitPolicy::normalize(&resilience).expect_err("duplicate names");

        assert_config_invalid(
            err,
            "resilience.scoped_rate_limits contains duplicate rule name 'client-limit'",
        );
    }

    #[test]
    fn admission_policy_normalization_shapes_brownout_and_route_queue() {
        let mut resilience = valid_resilience();
        resilience.adaptive_admission.min_limit = 10;
        resilience.adaptive_admission.max_limit = Some(25);
        resilience.adaptive_admission.high_latency_ms = 1_500;
        resilience.route_queue.default_cap = 9;
        resilience.route_queue.global_cap = 40;
        resilience.route_queue.shed_retry_after_seconds = 12;
        resilience
            .route_queue
            .caps
            .insert("payments".to_string(), 3);
        resilience.brownout.enabled = true;
        resilience.brownout.trigger_inflight_percent = 85;
        resilience.brownout.recover_inflight_percent = 55;
        resilience.brownout.core_routes = vec![" /ledger ".to_string(), " /payments ".to_string()];

        let policy = RuntimeAdmissionPolicy::normalize(&resilience, 100).expect("admission");

        assert!(policy.brownout.enabled);
        assert_eq!(policy.brownout.trigger_inflight_percent, 85);
        assert_eq!(policy.brownout.recover_inflight_percent, 55);
        assert_eq!(
            policy.brownout.core_routes,
            vec!["/ledger".to_string(), "/payments".to_string()]
        );
        assert_eq!(policy.route_queue.default_cap, 9);
        assert_eq!(policy.route_queue.global_cap, 40);
        assert_eq!(policy.route_queue.shed_retry_after_seconds, 12);
        assert_eq!(policy.route_queue.caps.get("payments"), Some(&3));
        assert_eq!(policy.adaptive_admission.min_limit, 10);
        assert_eq!(policy.adaptive_admission.max_limit, 25);
        assert_eq!(
            policy.adaptive_admission.high_latency,
            Duration::from_millis(1_500)
        );
    }

    #[test]
    fn scoped_rate_limit_normalization_rejects_invalid_empty_values_and_scope_mismatches() {
        let route_with_key = ScopedRateLimit {
            key: Some("header:x-route-id".to_string()),
            ..valid_scoped_rule(ScopedRateLimitScope::Route)
        };
        let err = RuntimeScopedRateLimitPolicy::normalize(&route_with_key)
            .expect_err("route scope with key must fail");
        assert_config_invalid(
            err,
            "resilience.scoped_rate_limits['tenant-budget'].key is invalid for scope=route",
        );

        let tenant_without_key = valid_scoped_rule(ScopedRateLimitScope::Tenant);
        let err = RuntimeScopedRateLimitPolicy::normalize(&tenant_without_key)
            .expect_err("tenant scope without key must fail");
        assert_config_invalid(
            err,
            "resilience.scoped_rate_limits['tenant-budget'].key is required for scope=tenant",
        );

        let invalid_key = ScopedRateLimit {
            scope: ScopedRateLimitScope::Client,
            key: Some("header:   ".to_string()),
            ..valid_scoped_rule(ScopedRateLimitScope::Client)
        };
        let err = RuntimeScopedRateLimitPolicy::normalize(&invalid_key)
            .expect_err("invalid key spec must fail");
        assert_config_invalid(
            err,
            "resilience.scoped_rate_limits['tenant-budget'].key must be a supported request key spec",
        );

        let empty_route_allowlist = ScopedRateLimit {
            route_allowlist: vec!["payments".to_string(), "   ".to_string()],
            ..valid_scoped_rule(ScopedRateLimitScope::Token)
        };
        let err = RuntimeScopedRateLimitPolicy::normalize(&empty_route_allowlist)
            .expect_err("empty route allowlist entry must fail");
        assert_config_invalid(
            err,
            "resilience.scoped_rate_limits['tenant-budget'].route_allowlist must not contain empty values",
        );
    }

    #[test]
    fn admission_policy_normalization_rejects_unsupported_protocol_and_brownout_combinations() {
        let mut resilience = valid_resilience();
        resilience.protocol.allow_connect = false;
        resilience.protocol.connect_allowed_ports = vec![443];

        let err = RuntimeAdmissionPolicy::normalize(&resilience, 100)
            .expect_err("connect restrictions without allow_connect must fail");
        assert_config_invalid(
            err,
            "resilience.protocol.connect_allowed_ports/connect_allowed_authorities require allow_connect=true",
        );

        let mut resilience = valid_resilience();
        resilience.protocol.allowed_methods = vec!["GET".to_string(), "BAD METHOD".to_string()];
        let err = RuntimeAdmissionPolicy::normalize(&resilience, 100)
            .expect_err("invalid http token must fail");
        assert_config_invalid(
            err,
            "resilience.protocol.allowed_methods must contain valid HTTP method tokens",
        );

        let mut resilience = valid_resilience();
        resilience.protocol.denied_path_prefixes = vec!["payments".to_string()];
        let err = RuntimeAdmissionPolicy::normalize(&resilience, 100)
            .expect_err("non slash-prefixed path must fail");
        assert_config_invalid(
            err,
            "resilience.protocol.denied_path_prefixes must contain '/'-prefixed paths",
        );

        let mut resilience = valid_resilience();
        resilience.protocol.allow_0rtt = true;
        resilience.protocol.early_data_safe_methods = Vec::new();
        let err =
            RuntimeAdmissionPolicy::normalize(&resilience, 100).expect_err("0-rtt guard must fail");
        assert_config_invalid(
            err,
            "resilience.protocol.early_data_safe_methods must be non-empty when allow_0rtt=true",
        );

        let mut resilience = valid_resilience();
        resilience.protocol.allow_0rtt = true;
        resilience.protocol.early_data_safe_methods = vec!["POST".to_string()];
        let err = RuntimeAdmissionPolicy::normalize(&resilience, 100)
            .expect_err("state-changing 0-rtt method must fail");
        assert_config_invalid(
            err,
            "resilience.protocol.early_data_safe_methods may contain only GET or HEAD when allow_0rtt=true",
        );

        let mut resilience = valid_resilience();
        resilience.brownout.trigger_inflight_percent = 70;
        resilience.brownout.recover_inflight_percent = 70;
        let err = RuntimeAdmissionPolicy::normalize(&resilience, 100)
            .expect_err("brownout recover threshold must fail");
        assert_config_invalid(
            err,
            "resilience.brownout.recover_inflight_percent must be < trigger_inflight_percent",
        );
    }
}
