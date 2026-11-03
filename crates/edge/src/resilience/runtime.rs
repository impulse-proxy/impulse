use std::{collections::HashSet, sync::Arc, time::Duration};

use impulse_config::{
    config::{
        QuotaBackendFailurePolicy as ConfigQuotaBackendFailurePolicy,
        QuotaCounterBackend as ConfigQuotaCounterBackend,
        QuotaEnforcementMode as ConfigQuotaEnforcementMode, QuotaPolicyConfig,
        Resilience as ResilienceConfig,
    },
    runtime::{
        RuntimeAdmissionPolicy, RuntimeQuotaBackendFailurePolicy, RuntimeQuotaCounterBackend,
        RuntimeQuotaEnforcementMode, RuntimeQuotaPolicySet, RuntimeRateLimitPolicy,
        RuntimeRequestKeySpec,
    },
};

use crate::resilience::{
    adaptive_admission::AdaptiveAdmission,
    brownout::BrownoutController,
    circuit_breaker::CircuitBreakers,
    connect::{connect_authority_port, normalize_connect_authority},
    quota::{
        QuotaBackendFailurePolicy, QuotaCounterBackend, QuotaCounterBackendError,
        QuotaEnforcementMode, QuotaLocalFallbackPolicy, QuotaPolicyRuntime, QuotaRuntime,
        QuotaSelectorKeySpec, QuotaSelectorMatcher, QuotaWindowPolicy,
        SharedDistributedQuotaCounterBackend,
    },
    retry_budget::RetryBudget,
    route_queue::RouteQueueLimiter,
    scoped_rate_limit::ScopedRateLimiters,
};

fn quota_selector_key(spec: &RuntimeRequestKeySpec) -> QuotaSelectorKeySpec {
    match spec {
        RuntimeRequestKeySpec::Path => QuotaSelectorKeySpec::Path,
        RuntimeRequestKeySpec::Authority => QuotaSelectorKeySpec::Authority,
        RuntimeRequestKeySpec::Method => QuotaSelectorKeySpec::Method,
        RuntimeRequestKeySpec::Cid => QuotaSelectorKeySpec::Cid,
        RuntimeRequestKeySpec::StickyCid => QuotaSelectorKeySpec::StickyCid,
        RuntimeRequestKeySpec::PeerIp => QuotaSelectorKeySpec::PeerIp,
        RuntimeRequestKeySpec::ClientIp => QuotaSelectorKeySpec::ClientIp,
        RuntimeRequestKeySpec::BearerToken => QuotaSelectorKeySpec::BearerToken,
        RuntimeRequestKeySpec::Header(name) => QuotaSelectorKeySpec::Header(name.clone()),
        RuntimeRequestKeySpec::Cookie(name) => QuotaSelectorKeySpec::Cookie(name.clone()),
        RuntimeRequestKeySpec::Query(name) => QuotaSelectorKeySpec::Query(name.clone()),
    }
}

fn quota_runtime_from_policy_set(config: &RuntimeQuotaPolicySet) -> QuotaRuntime {
    QuotaRuntime {
        enabled: config.enabled,
        enforcement: match config.enforcement {
            RuntimeQuotaEnforcementMode::Shadow => QuotaEnforcementMode::Shadow,
            RuntimeQuotaEnforcementMode::Enforce => QuotaEnforcementMode::Enforce,
        },
        backend_failure_policy: match config.backend_failure_policy {
            RuntimeQuotaBackendFailurePolicy::FailOpen => QuotaBackendFailurePolicy::FailOpen,
            RuntimeQuotaBackendFailurePolicy::FailClosed => QuotaBackendFailurePolicy::FailClosed,
        },
        backend: match &config.backend {
            RuntimeQuotaCounterBackend::InMemory { key_prefix } => QuotaCounterBackend::InMemory {
                key_prefix: key_prefix.clone(),
            },
            RuntimeQuotaCounterBackend::Redis {
                url,
                key_prefix,
                connect_timeout,
                command_timeout,
                max_inflight,
            } => QuotaCounterBackend::Redis {
                url: url.clone(),
                key_prefix: key_prefix.clone(),
                connect_timeout: *connect_timeout,
                command_timeout: *command_timeout,
                max_inflight: *max_inflight,
            },
        },
        local_fallback: config
            .local_fallback
            .as_ref()
            .map(|fallback| QuotaLocalFallbackPolicy {
                key_prefix: fallback.key_prefix.clone(),
                max_entries: fallback.max_entries,
            }),
        policies: config
            .policies
            .iter()
            .map(|policy| QuotaPolicyRuntime {
                name: policy.name.clone(),
                route_allowlist: policy.route_allowlist.iter().cloned().collect(),
                selector: QuotaSelectorMatcher {
                    route: policy.selector.route,
                    tenant: policy.selector.tenant.as_ref().map(quota_selector_key),
                    token: policy.selector.token.as_ref().map(quota_selector_key),
                    client: policy.selector.client.as_ref().map(quota_selector_key),
                },
                burst: policy.burst.as_ref().map(|window| QuotaWindowPolicy {
                    requests: window.requests,
                    window: window.window,
                }),
                sustained: policy.sustained.as_ref().map(|window| QuotaWindowPolicy {
                    requests: window.requests,
                    window: window.window,
                }),
            })
            .collect(),
    }
}

fn quota_runtime_from_config(config: &QuotaPolicyConfig) -> QuotaRuntime {
    QuotaRuntime {
        enabled: config.enabled,
        enforcement: match config.enforcement {
            ConfigQuotaEnforcementMode::Shadow => QuotaEnforcementMode::Shadow,
            ConfigQuotaEnforcementMode::Enforce => QuotaEnforcementMode::Enforce,
        },
        backend_failure_policy: match config.backend_failure_policy {
            ConfigQuotaBackendFailurePolicy::FailOpen => QuotaBackendFailurePolicy::FailOpen,
            ConfigQuotaBackendFailurePolicy::FailClosed => QuotaBackendFailurePolicy::FailClosed,
        },
        backend: match &config.backend {
            ConfigQuotaCounterBackend::InMemory { key_prefix } => QuotaCounterBackend::InMemory {
                key_prefix: key_prefix.trim().to_string(),
            },
            ConfigQuotaCounterBackend::Redis {
                url,
                key_prefix,
                connect_timeout_ms,
                command_timeout_ms,
                max_inflight,
            } => QuotaCounterBackend::Redis {
                url: url.trim().to_string(),
                key_prefix: key_prefix.trim().to_string(),
                connect_timeout: Duration::from_millis(*connect_timeout_ms),
                command_timeout: Duration::from_millis(*command_timeout_ms),
                max_inflight: *max_inflight,
            },
        },
        local_fallback: config
            .local_fallback
            .as_ref()
            .map(|fallback| QuotaLocalFallbackPolicy {
                key_prefix: fallback.key_prefix.trim().to_string(),
                max_entries: fallback.max_entries.max(1),
            }),
        policies: config
            .policies
            .iter()
            .map(|policy| QuotaPolicyRuntime {
                name: policy.name.trim().to_string(),
                route_allowlist: policy
                    .route_allowlist
                    .iter()
                    .map(|route| route.trim())
                    .filter(|route| !route.is_empty())
                    .map(ToOwned::to_owned)
                    .collect(),
                selector: QuotaSelectorMatcher {
                    route: policy.selector.route,
                    tenant: policy
                        .selector
                        .tenant
                        .as_ref()
                        .map(|source| QuotaSelectorKeySpec::from_raw_key(&source.key)),
                    token: policy
                        .selector
                        .token
                        .as_ref()
                        .map(|source| QuotaSelectorKeySpec::from_raw_key(&source.key)),
                    client: policy
                        .selector
                        .client
                        .as_ref()
                        .map(|source| QuotaSelectorKeySpec::from_raw_key(&source.key)),
                },
                burst: policy.burst.as_ref().map(|window| QuotaWindowPolicy {
                    requests: window.requests.max(1),
                    window: Duration::from_secs(window.window_secs.max(1)),
                }),
                sustained: policy.sustained.as_ref().map(|window| QuotaWindowPolicy {
                    requests: window.requests.max(1),
                    window: Duration::from_secs(window.window_secs.max(1)),
                }),
            })
            .collect(),
    }
}

pub struct RuntimeResilience {
    pub adaptive_admission: Arc<AdaptiveAdmission>,
    pub route_queue: Arc<RouteQueueLimiter>,
    pub scoped_rate_limits: Arc<ScopedRateLimiters>,
    pub quota: Arc<QuotaRuntime>,
    pub quota_backend: Option<SharedDistributedQuotaCounterBackend>,
    pub quota_backend_initialization_error: Option<QuotaCounterBackendError>,
    pub circuit_breakers: Arc<CircuitBreakers>,
    pub retry_budget: Arc<RetryBudget>,
    pub brownout: Arc<BrownoutController>,
    pub shed_retry_after_seconds: u32,
    pub allow_0rtt: bool,
    pub max_headers_count: usize,
    pub max_headers_bytes: usize,
    pub enforce_authority_host_match: bool,
    pub allow_connect: bool,
    pub hedging_enabled: bool,
    pub hedging_delay: Duration,
    hedge_safe_methods: HashSet<String>,
    early_data_safe_methods: HashSet<String>,
    allowed_methods: HashSet<String>,
    denied_path_prefixes: Vec<String>,
    connect_allowed_ports: HashSet<u16>,
    connect_allowed_authorities: HashSet<String>,
    route_allowlist: HashSet<String>,
}

impl RuntimeResilience {
    pub fn from_config(config: &ResilienceConfig, global_limit: usize) -> Self {
        let adaptive = &config.adaptive_admission;
        let admission = Arc::new(AdaptiveAdmission::new(
            adaptive.enabled,
            adaptive.min_limit,
            adaptive
                .max_limit
                .unwrap_or(global_limit)
                .max(adaptive.min_limit),
            adaptive.increase_step,
            adaptive.decrease_step,
            adaptive.high_latency_ms,
        ));
        let route_queue = Arc::new(RouteQueueLimiter::new(
            config.route_queue.default_cap,
            config.route_queue.global_cap,
            config.route_queue.caps.clone(),
        ));
        let scoped_rate_limits = Arc::new(ScopedRateLimiters::new(&config.scoped_rate_limits));
        let quota = Arc::new(quota_runtime_from_config(&config.quota));
        let mut quota_backend_initialization_error = None;
        let quota_backend = if quota.enabled {
            let (backend, initialization_error) = quota.enforcement_backend();
            quota_backend_initialization_error = initialization_error;
            Some(backend)
        } else {
            None
        };
        let cb = &config.circuit_breaker;
        let circuit_breakers = Arc::new(CircuitBreakers::new(
            cb.enabled,
            cb.failure_threshold,
            Duration::from_millis(cb.open_ms.max(1)),
            cb.half_open_max_probes,
        ));
        let retry_budget = Arc::new(RetryBudget::new(
            config.retry_budget.enabled,
            config.retry_budget.ratio_percent,
            config.retry_budget.per_route_ratio_percent.clone(),
        ));
        let brownout = Arc::new(BrownoutController::new(
            config.brownout.enabled,
            config.brownout.trigger_inflight_percent,
            config.brownout.recover_inflight_percent,
            config.brownout.core_routes.clone(),
        ));
        let hedge_safe_methods = config
            .hedging
            .safe_methods
            .iter()
            .map(|method| method.to_ascii_uppercase())
            .collect::<HashSet<_>>();
        let early_data_safe_methods = config
            .protocol
            .early_data_safe_methods
            .iter()
            .map(|method| method.to_ascii_uppercase())
            .collect::<HashSet<_>>();
        let allowed_methods = config
            .protocol
            .allowed_methods
            .iter()
            .map(|method| method.to_ascii_uppercase())
            .collect::<HashSet<_>>();
        let route_allowlist = config
            .hedging
            .route_allowlist
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        let connect_allowed_ports = config
            .protocol
            .connect_allowed_ports
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        let connect_allowed_authorities = config
            .protocol
            .connect_allowed_authorities
            .iter()
            .filter_map(|authority| normalize_connect_authority(authority))
            .collect::<HashSet<_>>();

        Self {
            adaptive_admission: admission,
            route_queue,
            scoped_rate_limits,
            quota,
            quota_backend,
            quota_backend_initialization_error,
            circuit_breakers,
            retry_budget,
            brownout,
            shed_retry_after_seconds: config.route_queue.shed_retry_after_seconds.max(1),
            allow_0rtt: config.protocol.allow_0rtt,
            max_headers_count: config.protocol.max_headers_count.max(1),
            max_headers_bytes: config.protocol.max_headers_bytes.max(1),
            enforce_authority_host_match: config.protocol.enforce_authority_host_match,
            allow_connect: config.protocol.allow_connect,
            hedging_enabled: config.hedging.enabled,
            hedging_delay: Duration::from_millis(config.hedging.delay_ms),
            hedge_safe_methods,
            early_data_safe_methods,
            allowed_methods,
            denied_path_prefixes: config.protocol.denied_path_prefixes.clone(),
            connect_allowed_ports,
            connect_allowed_authorities,
            route_allowlist,
        }
    }

    pub fn from_policies(
        admission_policy: &RuntimeAdmissionPolicy,
        rate_limit_policy: &RuntimeRateLimitPolicy,
    ) -> Self {
        let adaptive = &admission_policy.adaptive_admission;
        let admission = Arc::new(AdaptiveAdmission::new(
            adaptive.enabled,
            adaptive.min_limit,
            adaptive.max_limit.max(adaptive.min_limit),
            adaptive.increase_step,
            adaptive.decrease_step,
            adaptive
                .high_latency
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
        ));
        let route_queue = Arc::new(RouteQueueLimiter::new(
            admission_policy.route_queue.default_cap,
            admission_policy.route_queue.global_cap,
            admission_policy.route_queue.caps.clone(),
        ));
        let scoped_rate_limits = Arc::new(ScopedRateLimiters::new(
            &rate_limit_policy
                .scoped_limits
                .iter()
                .map(|rule| impulse_config::config::ScopedRateLimit {
                    name: rule.name.clone(),
                    scope: rule.scope,
                    requests_per_sec: rule.requests_per_sec,
                    burst: rule.burst,
                    key: rule.key.clone(),
                    route_allowlist: rule.route_allowlist.clone(),
                    idle_ttl_secs: rule.idle_ttl.as_secs(),
                })
                .collect::<Vec<_>>(),
        ));
        let quota = Arc::new(quota_runtime_from_policy_set(&rate_limit_policy.quota));
        let mut quota_backend_initialization_error = None;
        let quota_backend = if quota.enabled {
            let (backend, initialization_error) = quota.enforcement_backend();
            quota_backend_initialization_error = initialization_error;
            Some(backend)
        } else {
            None
        };
        let circuit_breakers = Arc::new(CircuitBreakers::new(
            admission_policy.circuit_breaker.enabled,
            admission_policy.circuit_breaker.failure_threshold,
            admission_policy.circuit_breaker.open,
            admission_policy.circuit_breaker.half_open_max_probes,
        ));
        let retry_budget = Arc::new(RetryBudget::new(
            admission_policy.retry_budget.enabled,
            admission_policy.retry_budget.ratio_percent,
            admission_policy
                .retry_budget
                .per_route_ratio_percent
                .clone(),
        ));
        let brownout = Arc::new(BrownoutController::new(
            admission_policy.brownout.enabled,
            admission_policy.brownout.trigger_inflight_percent,
            admission_policy.brownout.recover_inflight_percent,
            admission_policy.brownout.core_routes.clone(),
        ));
        let hedge_safe_methods = admission_policy
            .hedging
            .safe_methods
            .iter()
            .map(|method| method.to_ascii_uppercase())
            .collect::<HashSet<_>>();
        let early_data_safe_methods = admission_policy
            .protocol
            .0
            .early_data_safe_methods
            .iter()
            .map(|method| method.to_ascii_uppercase())
            .collect::<HashSet<_>>();
        let allowed_methods = admission_policy
            .protocol
            .0
            .allowed_methods
            .iter()
            .map(|method| method.to_ascii_uppercase())
            .collect::<HashSet<_>>();
        let route_allowlist = admission_policy
            .hedging
            .route_allowlist
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        let connect_allowed_ports = admission_policy
            .protocol
            .0
            .connect_allowed_ports
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        let connect_allowed_authorities = admission_policy
            .protocol
            .0
            .connect_allowed_authorities
            .iter()
            .filter_map(|authority| normalize_connect_authority(authority))
            .collect::<HashSet<_>>();

        Self {
            adaptive_admission: admission,
            route_queue,
            scoped_rate_limits,
            quota,
            quota_backend,
            quota_backend_initialization_error,
            circuit_breakers,
            retry_budget,
            brownout,
            shed_retry_after_seconds: admission_policy.route_queue.shed_retry_after_seconds,
            allow_0rtt: admission_policy.protocol.0.allow_0rtt,
            max_headers_count: admission_policy.protocol.0.max_headers_count.max(1),
            max_headers_bytes: admission_policy.protocol.0.max_headers_bytes.max(1),
            enforce_authority_host_match: admission_policy.protocol.0.enforce_authority_host_match,
            allow_connect: admission_policy.protocol.0.allow_connect,
            hedging_enabled: admission_policy.hedging.enabled,
            hedging_delay: admission_policy.hedging.delay,
            hedge_safe_methods,
            early_data_safe_methods,
            allowed_methods,
            denied_path_prefixes: admission_policy.protocol.0.denied_path_prefixes.clone(),
            connect_allowed_ports,
            connect_allowed_authorities,
            route_allowlist,
        }
    }

    pub fn hedging_route_enabled_for(&self, route: &str) -> bool {
        if !self.hedging_enabled || self.brownout.is_active() {
            return false;
        }
        self.route_allowlist.is_empty() || self.route_allowlist.contains(route)
    }

    pub fn hedging_method_allowed(&self, method: &str) -> bool {
        self.hedge_safe_methods
            .contains(&method.to_ascii_uppercase())
    }

    pub fn hedging_allowed_for(&self, method: &str, route: &str, bodyless: bool) -> bool {
        self.hedging_route_enabled_for(route) && bodyless && self.hedging_method_allowed(method)
    }

    pub fn early_data_allowed_for(&self, method: &str) -> bool {
        self.allow_0rtt
            && self
                .early_data_safe_methods
                .contains(&method.to_ascii_uppercase())
    }

    pub fn method_allowed(&self, method: &str) -> bool {
        self.allowed_methods.is_empty()
            || self.allowed_methods.contains(&method.to_ascii_uppercase())
    }

    pub fn path_denied(&self, path: &str) -> bool {
        self.denied_path_prefixes
            .iter()
            .any(|prefix| path.starts_with(prefix))
    }

    pub fn connect_allowed(&self, authority: &str) -> bool {
        if !self.allow_connect {
            return false;
        }
        let Some(normalized_authority) = normalize_connect_authority(authority) else {
            return false;
        };
        let Some(port) = connect_authority_port(&normalized_authority) else {
            return false;
        };
        if !self.connect_allowed_ports.is_empty() && !self.connect_allowed_ports.contains(&port) {
            return false;
        }
        if self.connect_allowed_authorities.is_empty() {
            return true;
        }
        self.connect_allowed_authorities
            .contains(&normalized_authority)
    }
}
