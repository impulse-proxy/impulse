use super::*;

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct Resilience {
    pub adaptive_admission: AdaptiveAdmission,
    pub route_queue: RouteQueue,
    pub scoped_rate_limits: Vec<ScopedRateLimit>,
    pub quota: QuotaPolicyConfig,
    pub protocol: ProtocolPolicy,
    pub circuit_breaker: CircuitBreaker,
    pub hedging: Hedging,
    pub retry_budget: RetryBudget,
    pub brownout: Brownout,
    pub watchdog: Watchdog,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct AdaptiveAdmission {
    pub enabled: bool,
    pub min_limit: usize,
    pub max_limit: Option<usize>,
    pub decrease_step: usize,
    pub increase_step: usize,
    pub high_latency_ms: u64,
}

impl Resilience {
    pub fn validate(&self) -> Result<(), String> {
        if self.brownout.recover_inflight_percent >= self.brownout.trigger_inflight_percent {
            return Err(format!(
                "resilience.brownout: recover_inflight_percent ({}) must be \
                 less than trigger_inflight_percent ({})",
                self.brownout.recover_inflight_percent, self.brownout.trigger_inflight_percent,
            ));
        }
        if self.adaptive_admission.min_limit == 0 {
            return Err("resilience.adaptive_admission: min_limit must be > 0".into());
        }
        if let Some(max_limit) = self.adaptive_admission.max_limit {
            if max_limit == 0 {
                return Err(
                    "resilience.adaptive_admission: max_limit must be > 0 when provided".into(),
                );
            }
            if max_limit < self.adaptive_admission.min_limit {
                return Err(format!(
                    "resilience.adaptive_admission: max_limit ({}) must be >= min_limit ({})",
                    max_limit, self.adaptive_admission.min_limit
                ));
            }
        }
        if self.retry_budget.ratio_percent > 100 {
            return Err(format!(
                "resilience.retry_budget: ratio_percent ({}) must be 0-100",
                self.retry_budget.ratio_percent
            ));
        }
        for rule in &self.scoped_rate_limits {
            let rule_name = rule.name.trim();
            if rule_name.is_empty() {
                return Err("resilience.scoped_rate_limits[].name must be non-empty".into());
            }
            if rule.requests_per_sec == 0 {
                return Err(format!(
                    "resilience.scoped_rate_limits['{}'].requests_per_sec must be > 0",
                    rule_name
                ));
            }
            if rule.burst == 0 {
                return Err(format!(
                    "resilience.scoped_rate_limits['{}'].burst must be > 0",
                    rule_name
                ));
            }
            if rule.idle_ttl_secs == 0 {
                return Err(format!(
                    "resilience.scoped_rate_limits['{}'].idle_ttl_secs must be > 0",
                    rule_name
                ));
            }
            if rule
                .route_allowlist
                .iter()
                .any(|route| route.trim().is_empty())
            {
                return Err(format!(
                    "resilience.scoped_rate_limits['{}'].route_allowlist must not contain empty values",
                    rule_name
                ));
            }
            match rule.scope {
                ScopedRateLimitScope::Route => {
                    if rule
                        .key
                        .as_ref()
                        .is_some_and(|value| !value.trim().is_empty())
                    {
                        return Err(format!(
                            "resilience.scoped_rate_limits['{}'].key is invalid for scope=route",
                            rule_name
                        ));
                    }
                }
                ScopedRateLimitScope::Tenant => {
                    let Some(key_spec) = rule.key.as_deref() else {
                        return Err(format!(
                            "resilience.scoped_rate_limits['{}'].key is required for scope=tenant",
                            rule_name
                        ));
                    };
                    if !is_supported_request_key_spec(key_spec) {
                        return Err(format!(
                            "resilience.scoped_rate_limits['{}'].key must be a supported request key spec",
                            rule_name
                        ));
                    }
                }
                ScopedRateLimitScope::Client | ScopedRateLimitScope::Token => {
                    if let Some(key_spec) = rule.key.as_deref()
                        && !is_supported_request_key_spec(key_spec)
                    {
                        return Err(format!(
                            "resilience.scoped_rate_limits['{}'].key must be a supported request key spec",
                            rule_name
                        ));
                    }
                }
            }
        }
        self.quota.validate()?;
        if self.hedging.enabled && self.hedging.delay_ms == 0 {
            return Err("resilience.hedging: delay_ms must be > 0 when hedging is enabled".into());
        }
        Ok(())
    }
}

fn is_supported_request_key_spec(spec: &str) -> bool {
    matches!(
        spec.trim().to_ascii_lowercase().as_str(),
        "path"
            | "authority"
            | "method"
            | "cid"
            | "sticky-cid"
            | "peer_ip"
            | "client_ip"
            | "bearer_token"
    ) || spec.split_once(':').is_some_and(|(source, key_name)| {
        !key_name.trim().is_empty()
            && matches!(
                source.trim().to_ascii_lowercase().as_str(),
                "header" | "cookie" | "query"
            )
    })
}

impl Default for AdaptiveAdmission {
    fn default() -> Self {
        Self {
            enabled: true,
            min_limit: 64,
            max_limit: None,
            decrease_step: 16,
            increase_step: 16,
            high_latency_ms: 500,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct RouteQueue {
    pub default_cap: usize,
    pub global_cap: usize,
    pub shed_retry_after_seconds: u32,
    pub caps: HashMap<String, usize>,
}

impl Default for RouteQueue {
    fn default() -> Self {
        Self {
            default_cap: 512,
            global_cap: 2048,
            shed_retry_after_seconds: 1,
            caps: HashMap::new(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScopedRateLimitScope {
    Route,
    Client,
    Tenant,
    Token,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ScopedRateLimit {
    pub name: String,
    pub scope: ScopedRateLimitScope,
    pub requests_per_sec: u32,
    pub burst: u32,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub route_allowlist: Vec<String>,
    #[serde(default = "ScopedRateLimit::default_idle_ttl_secs")]
    pub idle_ttl_secs: u64,
}

impl ScopedRateLimit {
    pub(crate) fn default_idle_ttl_secs() -> u64 {
        300
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum QuotaEnforcementMode {
    Shadow,
    #[default]
    Enforce,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QuotaBackendFailurePolicy {
    FailOpen,
    #[default]
    FailClosed,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct QuotaPolicyConfig {
    pub enabled: bool,
    pub enforcement: QuotaEnforcementMode,
    pub backend_failure_policy: QuotaBackendFailurePolicy,
    pub backend: QuotaCounterBackend,
    pub local_fallback: Option<QuotaLocalFallbackConfig>,
    pub policies: Vec<DistributedQuotaPolicy>,
}

impl QuotaPolicyConfig {
    fn validate(&self) -> Result<(), String> {
        for policy in &self.policies {
            policy.validate()?;
        }

        match &self.backend {
            QuotaCounterBackend::InMemory { key_prefix } => {
                if key_prefix.trim().is_empty() {
                    return Err(
                        "resilience.quota.backend.key_prefix must be non-empty for kind=in_memory"
                            .into(),
                    );
                }
                if self.local_fallback.is_some() {
                    return Err(
                        "resilience.quota.local_fallback is only supported when backend.kind=redis"
                            .into(),
                    );
                }
            }
            QuotaCounterBackend::Redis {
                url,
                key_prefix,
                connect_timeout_ms,
                command_timeout_ms,
                max_inflight,
            } => {
                if url.trim().is_empty() {
                    return Err(
                        "resilience.quota.backend.url must be non-empty for kind=redis".into(),
                    );
                }
                if key_prefix.trim().is_empty() {
                    return Err(
                        "resilience.quota.backend.key_prefix must be non-empty for kind=redis"
                            .into(),
                    );
                }
                if *connect_timeout_ms == 0 {
                    return Err(
                        "resilience.quota.backend.connect_timeout_ms must be > 0 for kind=redis"
                            .into(),
                    );
                }
                if *command_timeout_ms == 0 {
                    return Err(
                        "resilience.quota.backend.command_timeout_ms must be > 0 for kind=redis"
                            .into(),
                    );
                }
                if *max_inflight == 0 {
                    return Err(
                        "resilience.quota.backend.max_inflight must be > 0 for kind=redis".into(),
                    );
                }
            }
        }

        if let Some(local_fallback) = &self.local_fallback {
            local_fallback.validate()?;
        }

        if self.enabled && self.policies.is_empty() {
            return Err("resilience.quota.policies must not be empty when quota is enabled".into());
        }

        Ok(())
    }

    fn default_key_prefix() -> String {
        "impulse:quota".to_string()
    }

    fn default_connect_timeout_ms() -> u64 {
        250
    }

    fn default_command_timeout_ms() -> u64 {
        100
    }

    fn default_max_inflight() -> usize {
        1024
    }

    fn default_local_fallback_key_prefix() -> String {
        "impulse:quota:fallback".to_string()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct QuotaLocalFallbackConfig {
    #[serde(default = "QuotaPolicyConfig::default_local_fallback_key_prefix")]
    pub key_prefix: String,
    pub max_entries: usize,
}

impl QuotaLocalFallbackConfig {
    fn validate(&self) -> Result<(), String> {
        if self.key_prefix.trim().is_empty() {
            return Err("resilience.quota.local_fallback.key_prefix must be non-empty".to_string());
        }
        if self.max_entries == 0 {
            return Err("resilience.quota.local_fallback.max_entries must be > 0".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum QuotaCounterBackend {
    InMemory {
        #[serde(default = "QuotaPolicyConfig::default_key_prefix")]
        key_prefix: String,
    },
    Redis {
        url: String,
        #[serde(default = "QuotaPolicyConfig::default_key_prefix")]
        key_prefix: String,
        #[serde(default = "QuotaPolicyConfig::default_connect_timeout_ms")]
        connect_timeout_ms: u64,
        #[serde(default = "QuotaPolicyConfig::default_command_timeout_ms")]
        command_timeout_ms: u64,
        #[serde(default = "QuotaPolicyConfig::default_max_inflight")]
        max_inflight: usize,
    },
}

impl Default for QuotaCounterBackend {
    fn default() -> Self {
        Self::InMemory {
            key_prefix: QuotaPolicyConfig::default_key_prefix(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DistributedQuotaPolicy {
    pub name: String,
    #[serde(default)]
    pub route_allowlist: Vec<String>,
    #[serde(default)]
    pub selector: DistributedQuotaSelector,
    #[serde(default)]
    pub burst: Option<DistributedQuotaWindow>,
    #[serde(default)]
    pub sustained: Option<DistributedQuotaWindow>,
}

impl DistributedQuotaPolicy {
    fn validate(&self) -> Result<(), String> {
        let policy_name = self.name.trim();
        if policy_name.is_empty() {
            return Err("resilience.quota.policies[].name must be non-empty".into());
        }
        if self
            .route_allowlist
            .iter()
            .any(|route| route.trim().is_empty())
        {
            return Err(format!(
                "resilience.quota.policies['{}'].route_allowlist must not contain empty values",
                policy_name
            ));
        }
        if !self.selector.has_dimension() {
            return Err(format!(
                "resilience.quota.policies['{}'].selector must include at least one dimension",
                policy_name
            ));
        }
        self.selector.validate(policy_name)?;

        if self.burst.is_none() && self.sustained.is_none() {
            return Err(format!(
                "resilience.quota.policies['{}'] must define at least one of burst or sustained",
                policy_name
            ));
        }

        if let Some(window) = &self.burst {
            window.validate(&format!(
                "resilience.quota.policies['{}'].burst",
                policy_name
            ))?;
        }
        if let Some(window) = &self.sustained {
            window.validate(&format!(
                "resilience.quota.policies['{}'].sustained",
                policy_name
            ))?;
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct DistributedQuotaSelector {
    pub route: bool,
    pub tenant: Option<DistributedQuotaSelectorSource>,
    pub token: Option<DistributedQuotaSelectorSource>,
    pub client: Option<DistributedQuotaSelectorSource>,
}

impl DistributedQuotaSelector {
    fn has_dimension(&self) -> bool {
        self.route || self.tenant.is_some() || self.token.is_some() || self.client.is_some()
    }

    fn validate(&self, policy_name: &str) -> Result<(), String> {
        if let Some(source) = &self.tenant {
            source.validate(&format!(
                "resilience.quota.policies['{}'].selector.tenant",
                policy_name
            ))?;
        }
        if let Some(source) = &self.token {
            source.validate(&format!(
                "resilience.quota.policies['{}'].selector.token",
                policy_name
            ))?;
        }
        if let Some(source) = &self.client {
            source.validate(&format!(
                "resilience.quota.policies['{}'].selector.client",
                policy_name
            ))?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DistributedQuotaSelectorSource {
    pub key: String,
}

impl DistributedQuotaSelectorSource {
    fn validate(&self, field_path: &str) -> Result<(), String> {
        if self.key.trim().is_empty() {
            return Err(format!("{field_path}.key must be non-empty"));
        }
        if !is_supported_request_key_spec(&self.key) {
            return Err(format!(
                "{field_path}.key must be a supported request key spec"
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DistributedQuotaWindow {
    pub requests: u64,
    pub window_secs: u64,
}

impl DistributedQuotaWindow {
    fn validate(&self, field_path: &str) -> Result<(), String> {
        if self.requests == 0 {
            return Err(format!("{field_path}.requests must be > 0"));
        }
        if self.window_secs == 0 {
            return Err(format!("{field_path}.window_secs must be > 0"));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct ProtocolPolicy {
    pub allow_0rtt: bool,
    pub allow_connect: bool,
    pub early_data_safe_methods: Vec<String>,
    pub max_headers_count: usize,
    pub max_headers_bytes: usize,
    pub enforce_authority_host_match: bool,
    pub allowed_methods: Vec<String>,
    pub denied_path_prefixes: Vec<String>,
    pub connect_allowed_ports: Vec<u16>,
    pub connect_allowed_authorities: Vec<String>,
}

impl Default for ProtocolPolicy {
    fn default() -> Self {
        Self {
            allow_0rtt: false,
            allow_connect: false,
            early_data_safe_methods: vec!["GET".to_string(), "HEAD".to_string()],
            max_headers_count: 128,
            max_headers_bytes: 16 * 1024,
            enforce_authority_host_match: true,
            allowed_methods: Vec::new(),
            denied_path_prefixes: Vec::new(),
            connect_allowed_ports: Vec::new(),
            connect_allowed_authorities: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct CircuitBreaker {
    pub enabled: bool,
    pub failure_threshold: u32,
    pub open_ms: u64,
    pub half_open_max_probes: u32,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self {
            enabled: true,
            failure_threshold: 3,
            open_ms: 30_000,
            half_open_max_probes: 1,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct Hedging {
    pub enabled: bool,
    pub delay_ms: u64,
    pub safe_methods: Vec<String>,
    pub route_allowlist: Vec<String>,
}

impl Default for Hedging {
    fn default() -> Self {
        Self {
            enabled: false,
            delay_ms: 100,
            safe_methods: vec!["GET".to_string(), "HEAD".to_string()],
            route_allowlist: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct RetryBudget {
    pub enabled: bool,
    pub ratio_percent: u8,
    pub per_route_ratio_percent: HashMap<String, u8>,
}

impl Default for RetryBudget {
    fn default() -> Self {
        Self {
            enabled: true,
            ratio_percent: 10,
            per_route_ratio_percent: HashMap::new(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct Brownout {
    pub enabled: bool,
    pub trigger_inflight_percent: u8,
    pub recover_inflight_percent: u8,
    pub core_routes: Vec<String>,
}

impl Default for Brownout {
    fn default() -> Self {
        Self {
            enabled: true,
            trigger_inflight_percent: 90,
            recover_inflight_percent: 60,
            core_routes: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct Watchdog {
    pub enabled: bool,
    pub check_interval_ms: u64,
    pub poll_stall_timeout_ms: u64,
    pub timeout_error_rate_percent: u8,
    pub min_requests_per_window: u64,
    pub overload_inflight_percent: u8,
    pub unhealthy_consecutive_windows: u32,
    pub drain_grace_ms: u64,
    pub restart_cooldown_ms: u64,
    pub restart_command: Vec<String>,
    pub restart_hook: Option<String>,
}

impl Default for Watchdog {
    fn default() -> Self {
        Self {
            enabled: false,
            check_interval_ms: 1_000,
            poll_stall_timeout_ms: 5_000,
            timeout_error_rate_percent: 60,
            min_requests_per_window: 20,
            overload_inflight_percent: 95,
            unhealthy_consecutive_windows: 3,
            drain_grace_ms: 8_000,
            restart_cooldown_ms: 120_000,
            restart_command: Vec::new(),
            restart_hook: None,
        }
    }
}
