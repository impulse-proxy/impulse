use std::{
    collections::HashSet,
    future::Future,
    pin::Pin,
    sync::{Arc, OnceLock, RwLock, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use impulse_config::{
    config::{
        DistributedQuotaPolicy as RawDistributedQuotaPolicy,
        DistributedQuotaSelector as RawDistributedQuotaSelector,
        DistributedQuotaWindow as RawDistributedQuotaWindow,
        QuotaBackendFailurePolicy as RawQuotaBackendFailurePolicy,
        QuotaCounterBackend as RawQuotaCounterBackend,
        QuotaEnforcementMode as RawQuotaEnforcementMode, QuotaPolicyConfig as RawQuotaPolicyConfig,
        Resilience as ResilienceConfig,
    },
    runtime::{
        RuntimeQuotaBackendFailurePolicy as ConfigRuntimeQuotaBackendFailurePolicy,
        RuntimeQuotaCounterBackend as ConfigRuntimeQuotaCounterBackend,
        RuntimeQuotaEnforcementMode as ConfigRuntimeQuotaEnforcementMode,
        RuntimeQuotaLocalFallback as ConfigRuntimeQuotaLocalFallback,
        RuntimeQuotaPolicy as ConfigRuntimeQuotaPolicy,
        RuntimeQuotaPolicySet as ConfigRuntimeQuotaPolicySet,
        RuntimeQuotaSelectorMatcher as ConfigRuntimeQuotaSelectorMatcher,
        RuntimeQuotaWindow as ConfigRuntimeQuotaWindow, RuntimeRequestKeySpec,
    },
};
use impulse_observability::{
    Metrics, QuotaBackendHealthReason, QuotaPolicyDecision, QuotaPolicyReason,
};
use log::{debug, warn};

mod backend;
mod errors;
mod evaluation;
mod identity;
mod memory;
mod observability;
mod policy;
mod redis;

pub use memory::{IN_MEMORY_QUOTA_PROTOCOL_VERSION, InMemoryDistributedQuotaCounterStore};
pub use redis::{REDIS_QUOTA_PROTOCOL_VERSION, RedisDistributedQuotaCounterStore};

pub use self::evaluation::evaluate_admission_quota;
#[cfg(test)]
use self::identity::{canonical_quota_identity_value, compose_quota_key};
use self::{
    errors::{
        combine_primary_and_fallback_error, local_fallback_backend_mode, quota_rejection_decision,
        quota_retry_after_seconds, should_attempt_local_fallback,
    },
    observability::observe_quota_policy_outcome,
};
pub use crate::{
    ScopedRateLimitHeaderLookup as QuotaHeaderLookup,
    ScopedRateLimitIdentity as QuotaIdentityContext,
    ScopedRateLimitKeyExtraction as RequestKeyExtraction,
    extract_scoped_rate_limit_key as extract_runtime_request_key,
};

const LOCAL_FALLBACK_PROTOCOL_VERSION: &str = "degraded-local-fallback/v1";
const LOCAL_FALLBACK_BACKEND_SEPARATOR: &str = "_local_fallback_";
/// Upper bound for request-derived quota identity values handled by this
/// module. Keep this local to quota extraction so later hardening can enforce a
/// single canonical limit without introducing broader runtime config surface.
const MAX_REQUEST_DERIVED_QUOTA_IDENTITY_BYTES: usize = 256;
const MAX_REQUEST_DERIVED_QUOTA_IDENTITY_COMPONENTS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaEnforcementMode {
    Shadow,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaBackendFailurePolicy {
    FailOpen,
    FailClosed,
}

impl QuotaEnforcementMode {
    pub fn slug(self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
            Self::Enforce => "enforce",
        }
    }
}

impl QuotaBackendFailurePolicy {
    pub fn slug(self) -> &'static str {
        match self {
            Self::FailOpen => "fail_open",
            Self::FailClosed => "fail_closed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaSelectorKeySpec {
    Path,
    Authority,
    Method,
    Cid,
    StickyCid,
    PeerIp,
    ClientIp,
    BearerToken,
    Header(String),
    Cookie(String),
    Query(String),
    LegacyFallback(Box<QuotaSelectorKeySpec>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaIdentityDimension {
    Route,
    Tenant,
    Token,
    Client,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaIdentityLabels {
    pub route: Option<String>,
    pub tenant: Option<String>,
    pub token: Option<String>,
    pub client: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaCompositeKey {
    pub policy_name: String,
    pub key: String,
    pub labels: QuotaIdentityLabels,
    pub dimensions: QuotaSelectorDimensions,
}

pub type QuotaCounterEvalFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<QuotaCounterEvaluationOutcome, QuotaCounterBackendError>>
            + Send
            + 'a,
    >,
>;

/// Distributed quota backends must evaluate all configured windows in one atomic operation.
/// Implementations should not split this into independent reads and writes, which would admit
/// request races between burst and sustained counters under concurrent load.
pub trait DistributedQuotaCounterBackend: Send + Sync {
    fn evaluate<'a>(&'a self, request: QuotaCounterEvaluationRequest)
    -> QuotaCounterEvalFuture<'a>;
}

pub type SharedDistributedQuotaCounterBackend = Arc<dyn DistributedQuotaCounterBackend>;

static QUOTA_METRICS_SINK: OnceLock<RwLock<Weak<Metrics>>> = OnceLock::new();
static QUOTA_INTROSPECTION_STATE: OnceLock<RwLock<QuotaIntrospectionState>> = OnceLock::new();

const QUOTA_RECENT_BACKEND_ERRORS_LIMIT: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaSelectorIntrospectionSnapshot {
    pub route: bool,
    pub tenant: Option<String>,
    pub token: Option<String>,
    pub client: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaWindowIntrospectionSnapshot {
    pub requests: u64,
    pub window_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaPolicyIntrospectionSnapshot {
    pub name: String,
    pub route_allowlist: Vec<String>,
    pub selector: QuotaSelectorIntrospectionSnapshot,
    pub burst: Option<QuotaWindowIntrospectionSnapshot>,
    pub sustained: Option<QuotaWindowIntrospectionSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaBackendErrorSnapshot {
    pub observed_at_unix_ms: Option<u64>,
    pub policy_name: Option<String>,
    pub reason: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaBackendStatusSnapshot {
    pub backend_mode: String,
    pub availability: String,
    pub degraded: bool,
    pub health_reason: Option<String>,
    pub last_observed_at_unix_ms: Option<u64>,
    pub recent_errors: Vec<QuotaBackendErrorSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuotaBackendAvailability {
    Disabled,
    Unknown,
    Available,
    Degraded,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct QuotaIntrospectionState {
    backend_mode: Option<String>,
    availability: Option<QuotaBackendAvailability>,
    health_reason: Option<QuotaBackendHealthReason>,
    last_observed_at_unix_ms: Option<u64>,
    recent_errors: Vec<QuotaBackendErrorSnapshot>,
}

#[derive(Debug, Clone)]
pub struct UnavailableDistributedQuotaCounterStore {
    error: QuotaCounterBackendError,
}

#[derive(Clone)]
pub struct DegradedQuotaCounterBackend {
    primary: SharedDistributedQuotaCounterBackend,
    primary_backend_kind: String,
    local_fallback: Arc<InMemoryDistributedQuotaCounterStore>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaIdentityRejection {
    pub policy_name: String,
    pub dimension: QuotaIdentityDimension,
    pub reason: QuotaDenyReason,
}

impl From<&RuntimeRequestKeySpec> for QuotaSelectorKeySpec {
    fn from(value: &RuntimeRequestKeySpec) -> Self {
        match value {
            RuntimeRequestKeySpec::Path => Self::Path,
            RuntimeRequestKeySpec::Authority => Self::Authority,
            RuntimeRequestKeySpec::Method => Self::Method,
            RuntimeRequestKeySpec::Cid => Self::Cid,
            RuntimeRequestKeySpec::StickyCid => Self::StickyCid,
            RuntimeRequestKeySpec::PeerIp => Self::PeerIp,
            RuntimeRequestKeySpec::ClientIp => Self::ClientIp,
            RuntimeRequestKeySpec::BearerToken => Self::BearerToken,
            RuntimeRequestKeySpec::Header(name) => Self::Header(name.clone()),
            RuntimeRequestKeySpec::Cookie(name) => Self::Cookie(name.clone()),
            RuntimeRequestKeySpec::Query(name) => Self::Query(name.clone()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaSelectorMatcher {
    pub route: bool,
    pub tenant: Option<QuotaSelectorKeySpec>,
    pub token: Option<QuotaSelectorKeySpec>,
    pub client: Option<QuotaSelectorKeySpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaSelectorDimensions {
    pub route: bool,
    pub tenant: bool,
    pub token: bool,
    pub client: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaWindowPolicy {
    pub requests: u64,
    pub window: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaPolicyRuntime {
    pub name: String,
    pub route_allowlist: HashSet<String>,
    pub selector: QuotaSelectorMatcher,
    pub burst: Option<QuotaWindowPolicy>,
    pub sustained: Option<QuotaWindowPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaLocalFallbackPolicy {
    pub key_prefix: String,
    pub max_entries: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaCounterBackend {
    InMemory {
        key_prefix: String,
    },
    Redis {
        url: String,
        key_prefix: String,
        connect_timeout: Duration,
        command_timeout: Duration,
        max_inflight: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaRuntime {
    pub enabled: bool,
    pub enforcement: QuotaEnforcementMode,
    pub backend_failure_policy: QuotaBackendFailurePolicy,
    pub backend: QuotaCounterBackend,
    pub local_fallback: Option<QuotaLocalFallbackPolicy>,
    pub policies: Vec<QuotaPolicyRuntime>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaDenyReason {
    BurstQuotaExhausted,
    SustainedQuotaExhausted,
    SelectorIdentityMissing,
    SelectorIdentityInvalid,
    BackendTimeout,
    BackendUnavailable,
    BackendError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaWindowUsage {
    pub limit: u64,
    pub consumed: u64,
    pub remaining: u64,
    pub window: Duration,
    pub reset_after: Option<Duration>,
    pub bucket_started_at_unix_ms: Option<u64>,
    pub reset_at_unix_ms: Option<u64>,
    pub storage_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaCounterResult {
    pub burst: Option<QuotaWindowUsage>,
    pub sustained: Option<QuotaWindowUsage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaCounterEvaluationRequest {
    pub policy_name: String,
    pub composite_key: QuotaCompositeKey,
    pub cost: u64,
    pub burst: Option<QuotaWindowPolicy>,
    pub sustained: Option<QuotaWindowPolicy>,
}

impl QuotaCounterEvaluationRequest {
    pub fn with_cost(mut self, cost: u64) -> Self {
        self.cost = cost.max(1);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaCounterEvaluationDecision {
    Allowed,
    Denied(QuotaDenyReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaCounterBackendMetadata {
    pub backend_kind: String,
    pub protocol_version: String,
    pub evaluated_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaCounterEvaluationOutcome {
    pub matched_policy: String,
    pub composite_key: QuotaCompositeKey,
    pub decision: QuotaCounterEvaluationDecision,
    pub counter: QuotaCounterResult,
    pub backend_metadata: QuotaCounterBackendMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaCounterBackendErrorKind {
    Timeout,
    Unavailable,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaCounterBackendError {
    pub policy_name: Option<String>,
    pub composite_key: Option<String>,
    pub kind: QuotaCounterBackendErrorKind,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaAllowance {
    pub policy_name: String,
    pub counter: Option<QuotaCounterResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaDenial {
    pub policy_name: String,
    pub reason: QuotaDenyReason,
    pub retry_after_seconds: Option<u32>,
    pub counter: Option<QuotaCounterResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaBackendFailure {
    pub policy_name: Option<String>,
    pub reason: QuotaDenyReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaDecision {
    NotApplied,
    Allowed(QuotaAllowance),
    ShadowDenied(QuotaDenial),
    Denied(QuotaDenial),
    FailedOpen(QuotaBackendFailure),
    FailedClosed(QuotaBackendFailure),
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, net::SocketAddr};

    use impulse_config::{
        config::{
            DistributedQuotaPolicy, DistributedQuotaSelector, DistributedQuotaSelectorSource,
            DistributedQuotaWindow, QuotaBackendFailurePolicy as RawQuotaBackendFailurePolicy,
            QuotaCounterBackend as RawQuotaCounterBackend,
            QuotaEnforcementMode as RawQuotaEnforcementMode,
            QuotaPolicyConfig as RawQuotaPolicyConfig, Resilience,
        },
        runtime::{
            RuntimeQuotaBackendFailurePolicy, RuntimeQuotaCounterBackend,
            RuntimeQuotaEnforcementMode, RuntimeQuotaPolicy, RuntimeQuotaPolicySet,
            RuntimeQuotaSelectorMatcher, RuntimeQuotaWindow, RuntimeRequestKeySpec,
        },
    };

    use super::*;

    fn identity_context_with_headers(
        route: Option<&'static str>,
        method: &'static str,
        path: &'static str,
        authority: Option<&'static str>,
        cid_key: Option<&'static str>,
        client_addr: Option<SocketAddr>,
        headers: HashMap<String, String>,
    ) -> QuotaIdentityContext<'static> {
        let leaked = Box::leak(Box::new(headers));
        let lookup = Box::leak(Box::new(move |name: &str| {
            leaked.get(&name.to_ascii_lowercase()).cloned()
        }));
        QuotaIdentityContext::new(
            route,
            method,
            path,
            authority,
            cid_key,
            client_addr,
            Some(lookup),
        )
    }

    fn leak_string(value: String) -> &'static str {
        Box::leak(value.into_boxed_str())
    }

    fn quota_policy_with_selectors(
        tenant: Option<QuotaSelectorKeySpec>,
        token: Option<QuotaSelectorKeySpec>,
        client: Option<QuotaSelectorKeySpec>,
    ) -> QuotaPolicyRuntime {
        QuotaPolicyRuntime {
            name: "tenant-quota".to_string(),
            route_allowlist: HashSet::new(),
            selector: QuotaSelectorMatcher {
                route: true,
                tenant,
                token,
                client,
            },
            burst: Some(QuotaWindowPolicy {
                requests: 10,
                window: Duration::from_secs(1),
            }),
            sustained: None,
        }
    }

    fn assert_selector_identity_invalid(
        policy: &QuotaPolicyRuntime,
        context: &QuotaIdentityContext<'_>,
        dimension: QuotaIdentityDimension,
    ) {
        let err = policy
            .composite_key(context)
            .expect_err("selector identity should be rejected");
        assert_eq!(err.dimension, dimension);
        assert_eq!(err.reason, QuotaDenyReason::SelectorIdentityInvalid);
    }

    #[test]
    fn quota_deny_reason_slugs_are_stable() {
        assert_eq!(
            QuotaDenyReason::BurstQuotaExhausted.slug(),
            "burst_quota_exhausted"
        );
        assert_eq!(
            QuotaDenyReason::SustainedQuotaExhausted.slug(),
            "sustained_quota_exhausted"
        );
        assert_eq!(
            QuotaDenyReason::SelectorIdentityMissing.slug(),
            "selector_identity_missing"
        );
        assert_eq!(
            QuotaDenyReason::SelectorIdentityInvalid.slug(),
            "selector_identity_invalid"
        );
        assert_eq!(QuotaDenyReason::BackendTimeout.slug(), "backend_timeout");
        assert_eq!(
            QuotaDenyReason::BackendUnavailable.slug(),
            "backend_unavailable"
        );
        assert_eq!(QuotaDenyReason::BackendError.slug(), "backend_error");
    }

    #[test]
    fn runtime_quota_converts_from_runtime_policy_set() {
        let runtime = QuotaRuntime::from_runtime_policy_set(&RuntimeQuotaPolicySet {
            enabled: true,
            enforcement: RuntimeQuotaEnforcementMode::Shadow,
            backend_failure_policy: RuntimeQuotaBackendFailurePolicy::FailOpen,
            backend: RuntimeQuotaCounterBackend::Redis {
                url: "redis://127.0.0.1:6379/0".to_string(),
                key_prefix: "impulse:quota".to_string(),
                connect_timeout: Duration::from_millis(250),
                command_timeout: Duration::from_millis(100),
                max_inflight: 64,
            },
            local_fallback: None,
            policies: vec![RuntimeQuotaPolicy {
                name: "tenant-quota".to_string(),
                route_allowlist: vec!["api".to_string()],
                selector: RuntimeQuotaSelectorMatcher {
                    route: true,
                    tenant: Some(RuntimeRequestKeySpec::Header("x-tenant-id".to_string())),
                    token: None,
                    client: Some(RuntimeRequestKeySpec::ClientIp),
                },
                burst: Some(RuntimeQuotaWindow {
                    requests: 100,
                    window: Duration::from_secs(1),
                }),
                sustained: Some(RuntimeQuotaWindow {
                    requests: 1000,
                    window: Duration::from_secs(60),
                }),
            }],
        });

        assert!(runtime.enabled);
        assert_eq!(runtime.enforcement, QuotaEnforcementMode::Shadow);
        assert_eq!(
            runtime.backend_failure_policy,
            QuotaBackendFailurePolicy::FailOpen
        );
        assert_eq!(runtime.policies.len(), 1);
        assert_eq!(runtime.policies[0].name, "tenant-quota");
        assert!(runtime.policies[0].route_allowlist.contains("api"));
        assert_eq!(
            runtime.policies[0].selector.tenant,
            Some(QuotaSelectorKeySpec::Header("x-tenant-id".to_string()))
        );
        assert_eq!(
            runtime.policies[0].selector.client,
            Some(QuotaSelectorKeySpec::ClientIp)
        );
    }

    #[test]
    fn runtime_quota_converts_from_raw_resilience_config() {
        let resilience = Resilience {
            quota: RawQuotaPolicyConfig {
                enabled: true,
                enforcement: RawQuotaEnforcementMode::Enforce,
                backend_failure_policy: RawQuotaBackendFailurePolicy::FailClosed,
                backend: RawQuotaCounterBackend::InMemory {
                    key_prefix: "impulse:quota".to_string(),
                },
                local_fallback: None,
                policies: vec![DistributedQuotaPolicy {
                    name: "client-quota".to_string(),
                    route_allowlist: vec![" public ".to_string()],
                    selector: DistributedQuotaSelector {
                        route: false,
                        tenant: None,
                        token: None,
                        client: Some(DistributedQuotaSelectorSource {
                            key: "client_ip".to_string(),
                        }),
                    },
                    burst: Some(DistributedQuotaWindow {
                        requests: 25,
                        window_secs: 1,
                    }),
                    sustained: None,
                }],
            },
            ..Resilience::default()
        };

        let runtime = QuotaRuntime::from_resilience_config(&resilience);

        assert!(runtime.enabled);
        assert_eq!(runtime.enforcement, QuotaEnforcementMode::Enforce);
        assert_eq!(
            runtime.backend_failure_policy,
            QuotaBackendFailurePolicy::FailClosed
        );
        assert_eq!(runtime.policies[0].name, "client-quota");
        assert!(runtime.policies[0].route_allowlist.contains("public"));
        assert_eq!(
            runtime.policies[0].selector.client,
            Some(QuotaSelectorKeySpec::ClientIp)
        );
        assert_eq!(
            runtime.policies[0]
                .burst
                .as_ref()
                .map(|window| window.requests),
            Some(25)
        );
        assert!(
            runtime
                .in_memory_store()
                .expect("in-memory quota backend should build")
                .is_some()
        );
        assert!(
            runtime
                .redis_store()
                .expect("in-memory quota backend should not fail redis lookup")
                .is_none()
        );
        let _backend = runtime
            .distributed_store()
            .expect("quota runtime should build generic backend");
    }

    fn sample_counter_request(
        policy_name: &str,
        composite_key: &str,
    ) -> QuotaCounterEvaluationRequest {
        QuotaCounterEvaluationRequest {
            policy_name: policy_name.to_string(),
            composite_key: QuotaCompositeKey {
                policy_name: policy_name.to_string(),
                key: composite_key.to_string(),
                labels: QuotaIdentityLabels {
                    route: Some("api".to_string()),
                    tenant: Some("acme".to_string()),
                    token: None,
                    client: None,
                },
                dimensions: QuotaSelectorDimensions {
                    route: true,
                    tenant: true,
                    token: false,
                    client: false,
                },
            },
            burst: Some(QuotaWindowPolicy {
                requests: 2,
                window: Duration::from_secs(1),
            }),
            sustained: Some(QuotaWindowPolicy {
                requests: 5,
                window: Duration::from_secs(60),
            }),
            cost: 1,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn degraded_quota_backend_uses_local_fallback_for_outage_failures() {
        let primary = Arc::new(UnavailableDistributedQuotaCounterStore::new(
            QuotaCounterBackendError {
                policy_name: None,
                composite_key: None,
                kind: QuotaCounterBackendErrorKind::Timeout,
                detail: Some("redis timed out".to_string()),
            },
        )) as SharedDistributedQuotaCounterBackend;
        let fallback = Arc::new(InMemoryDistributedQuotaCounterStore::bounded(
            "impulse:quota:fallback",
            16,
        ));
        let backend = DegradedQuotaCounterBackend::new(primary, "redis", fallback);

        let outcome = backend
            .evaluate(sample_counter_request(
                "tenant-quota",
                "policy=12:tenant-quota|route=3:api|tenant=4:acme|",
            ))
            .await
            .expect("timeout failures should degrade into local fallback evaluation");

        assert_eq!(outcome.decision, QuotaCounterEvaluationDecision::Allowed);
        assert_eq!(
            outcome.backend_metadata.backend_kind,
            "redis_local_fallback_backend_timeout"
        );
        assert_eq!(
            outcome.backend_metadata.protocol_version,
            format!(
                "{}+{}",
                LOCAL_FALLBACK_PROTOCOL_VERSION,
                memory::IN_MEMORY_QUOTA_PROTOCOL_VERSION
            )
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn degraded_quota_backend_does_not_fallback_for_non_outage_errors() {
        let primary = Arc::new(UnavailableDistributedQuotaCounterStore::new(
            QuotaCounterBackendError {
                policy_name: None,
                composite_key: None,
                kind: QuotaCounterBackendErrorKind::Error,
                detail: Some("redis script protocol mismatch".to_string()),
            },
        )) as SharedDistributedQuotaCounterBackend;
        let fallback = Arc::new(InMemoryDistributedQuotaCounterStore::bounded(
            "impulse:quota:fallback",
            16,
        ));
        let backend = DegradedQuotaCounterBackend::new(primary, "redis", fallback);

        let err = backend
            .evaluate(sample_counter_request(
                "tenant-quota",
                "policy=12:tenant-quota|route=3:api|tenant=4:acme|",
            ))
            .await
            .expect_err("non-outage backend errors must not fall back locally");

        assert_eq!(err.kind, QuotaCounterBackendErrorKind::Error);
        assert_eq!(
            err.detail.as_deref(),
            Some("redis script protocol mismatch")
        );
    }

    fn runtime_policy_set_with(
        enforcement: RuntimeQuotaEnforcementMode,
        policies: Vec<RuntimeQuotaPolicy>,
    ) -> QuotaRuntime {
        QuotaRuntime::from_runtime_policy_set(&RuntimeQuotaPolicySet {
            enabled: true,
            enforcement,
            backend_failure_policy: RuntimeQuotaBackendFailurePolicy::FailClosed,
            backend: RuntimeQuotaCounterBackend::InMemory {
                key_prefix: "impulse:quota:test".to_string(),
            },
            local_fallback: None,
            policies,
        })
    }

    fn route_only_policy(name: &str, requests: u64) -> RuntimeQuotaPolicy {
        RuntimeQuotaPolicy {
            name: name.to_string(),
            route_allowlist: vec!["api".to_string()],
            selector: RuntimeQuotaSelectorMatcher {
                route: true,
                tenant: None,
                token: None,
                client: None,
            },
            burst: Some(RuntimeQuotaWindow {
                requests,
                window: Duration::from_secs(1),
            }),
            sustained: None,
        }
    }

    fn tenant_policy(name: &str, requests: u64) -> RuntimeQuotaPolicy {
        RuntimeQuotaPolicy {
            name: name.to_string(),
            route_allowlist: vec!["api".to_string()],
            selector: RuntimeQuotaSelectorMatcher {
                route: true,
                tenant: Some(RuntimeRequestKeySpec::Header("x-tenant-id".to_string())),
                token: None,
                client: None,
            },
            burst: Some(RuntimeQuotaWindow {
                requests,
                window: Duration::from_secs(1),
            }),
            sustained: None,
        }
    }

    /// A narrow policy layered on the same route as a broad one must still be
    /// enforced. Evaluating only the first route match let the broad policy
    /// mask the narrow one entirely, so a caller could exceed the narrow
    /// contract — or skip it by omitting its selector header — while the
    /// config validated and appeared in the control API.
    #[tokio::test(flavor = "current_thread")]
    async fn every_route_matching_policy_is_evaluated_not_just_the_first() {
        // Broad policy first, narrow tenant policy second: the ordering that
        // previously left the tenant contract dead.
        let runtime = runtime_policy_set_with(
            RuntimeQuotaEnforcementMode::Enforce,
            vec![route_only_policy("broad", 100), tenant_policy("narrow", 2)],
        );
        let backend = InMemoryDistributedQuotaCounterStore::new("impulse:quota:test");

        let context = identity_context_with_headers(
            Some("api"),
            "GET",
            "/v1/items",
            Some("api.example.com"),
            None,
            Some("203.0.113.10:443".parse().expect("client addr")),
            HashMap::from([("x-tenant-id".to_string(), "acme".to_string())]),
        );

        // The narrow policy allows 2; the broad one allows 100.
        for attempt in 1..=2 {
            assert!(
                matches!(
                    evaluate_admission_quota(&runtime, &backend, &context).await,
                    QuotaDecision::Allowed(_)
                ),
                "request {attempt} is within both contracts",
            );
        }

        let decision = evaluate_admission_quota(&runtime, &backend, &context).await;
        let QuotaDecision::Denied(denial) = decision else {
            panic!("third request must be denied by the narrow policy, got {decision:?}");
        };
        assert_eq!(denial.policy_name, "narrow");
        assert_eq!(denial.reason, QuotaDenyReason::BurstQuotaExhausted);
    }

    /// A request missing a policy's selector identity must be denied rather
    /// than admitted by an earlier, broader policy that does not need it.
    #[tokio::test(flavor = "current_thread")]
    async fn missing_selector_identity_denies_even_when_a_broader_policy_allows() {
        let runtime = runtime_policy_set_with(
            RuntimeQuotaEnforcementMode::Enforce,
            vec![route_only_policy("broad", 100), tenant_policy("narrow", 10)],
        );
        let backend = InMemoryDistributedQuotaCounterStore::new("impulse:quota:test");

        // No x-tenant-id header at all.
        let context = identity_context_with_headers(
            Some("api"),
            "GET",
            "/v1/items",
            Some("api.example.com"),
            None,
            Some("203.0.113.10:443".parse().expect("client addr")),
            HashMap::new(),
        );

        let decision = evaluate_admission_quota(&runtime, &backend, &context).await;
        let QuotaDecision::Denied(denial) = decision else {
            panic!("missing tenant identity must not be admitted, got {decision:?}");
        };
        assert_eq!(denial.policy_name, "narrow");
        assert_eq!(denial.reason, QuotaDenyReason::SelectorIdentityMissing);
    }

    /// Shadow mode must not stop at the first would-deny: every matching policy
    /// still needs to record an outcome, otherwise sizing one policy hides the
    /// blast radius of the others.
    #[tokio::test(flavor = "current_thread")]
    async fn shadow_mode_evaluates_all_policies_and_admits() {
        let runtime = runtime_policy_set_with(
            RuntimeQuotaEnforcementMode::Shadow,
            vec![tenant_policy("narrow", 1), route_only_policy("broad", 100)],
        );
        let backend = InMemoryDistributedQuotaCounterStore::new("impulse:quota:test");

        let context = identity_context_with_headers(
            Some("api"),
            "GET",
            "/v1/items",
            Some("api.example.com"),
            None,
            Some("203.0.113.10:443".parse().expect("client addr")),
            HashMap::from([("x-tenant-id".to_string(), "acme".to_string())]),
        );

        assert!(matches!(
            evaluate_admission_quota(&runtime, &backend, &context).await,
            QuotaDecision::Allowed(_)
        ));

        // Second request exhausts the narrow policy, but shadow mode reports a
        // would-deny rather than a denial.
        let decision = evaluate_admission_quota(&runtime, &backend, &context).await;
        let QuotaDecision::ShadowDenied(denial) = decision else {
            panic!("shadow mode must report a would-deny, got {decision:?}");
        };
        assert_eq!(denial.policy_name, "narrow");
    }

    #[test]
    fn quota_decision_reports_terminal_denials() {
        let denied = QuotaDecision::Denied(QuotaDenial {
            policy_name: "tenant-quota".to_string(),
            reason: QuotaDenyReason::BurstQuotaExhausted,
            retry_after_seconds: Some(1),
            counter: None,
        });
        assert!(denied.is_denied());
        assert_eq!(
            denied.deny_reason(),
            Some(QuotaDenyReason::BurstQuotaExhausted)
        );

        let failed_closed = QuotaDecision::FailedClosed(QuotaBackendFailure {
            policy_name: None,
            reason: QuotaDenyReason::BackendUnavailable,
        });
        assert!(failed_closed.is_denied());
        assert_eq!(
            failed_closed.deny_reason(),
            Some(QuotaDenyReason::BackendUnavailable)
        );

        let allowed = QuotaDecision::Allowed(QuotaAllowance {
            policy_name: "tenant-quota".to_string(),
            counter: None,
        });
        assert!(!allowed.is_denied());
        assert_eq!(allowed.deny_reason(), None);
    }

    #[test]
    fn quota_identity_extraction_builds_stable_composite_keys() {
        let policy = QuotaPolicyRuntime {
            name: "tenant-quota".to_string(),
            route_allowlist: HashSet::from(["api".to_string()]),
            selector: QuotaSelectorMatcher {
                route: true,
                tenant: Some(QuotaSelectorKeySpec::Header("x-tenant-id".to_string())),
                token: Some(QuotaSelectorKeySpec::BearerToken),
                client: Some(QuotaSelectorKeySpec::ClientIp),
            },
            burst: Some(QuotaWindowPolicy {
                requests: 100,
                window: Duration::from_secs(1),
            }),
            sustained: Some(QuotaWindowPolicy {
                requests: 1000,
                window: Duration::from_secs(60),
            }),
        };
        let context = identity_context_with_headers(
            Some("api"),
            "POST",
            "/v1/payments?tenant=acme",
            Some("api.example.com"),
            None,
            Some("203.0.113.10:443".parse().expect("client addr")),
            HashMap::from([
                (
                    "authorization".to_string(),
                    "Bearer secret-token".to_string(),
                ),
                ("x-tenant-id".to_string(), "acme".to_string()),
            ]),
        );

        let composite = policy
            .composite_key(&context)
            .expect("quota identities should resolve");

        let hashed_tenant = composite
            .labels
            .tenant
            .as_ref()
            .expect("hashed tenant label");
        let hashed_token = composite.labels.token.as_ref().expect("hashed token label");
        let hashed_client = composite
            .labels
            .client
            .as_ref()
            .expect("hashed client label");

        assert_eq!(composite.policy_name, "tenant-quota");
        assert_eq!(composite.labels.route.as_deref(), Some("api"));
        assert!(
            hashed_tenant.starts_with("sha256:"),
            "tenant-derived identities must be hashed before reuse"
        );
        assert!(
            hashed_token.starts_with("sha256:"),
            "token-derived identities must be hashed before reuse"
        );
        assert!(
            hashed_client.starts_with("sha256:"),
            "client-derived identities must be hashed before reuse"
        );
        assert_eq!(
            composite.key,
            format!(
                "policy=12:tenant-quota|route=3:api|tenant={}:{}|token={}:{}|client={}:{}|",
                hashed_tenant.len(),
                hashed_tenant,
                hashed_token.len(),
                hashed_token,
                hashed_client.len(),
                hashed_client,
            )
        );
    }

    #[test]
    fn compose_quota_key_canonicalizes_non_route_labels_before_storage() {
        let labels = QuotaIdentityLabels {
            route: Some("api".to_string()),
            tenant: Some("acme".to_string()),
            token: Some("secret-token".to_string()),
            client: Some("203.0.113.10".to_string()),
        };

        let canonical = labels.canonicalize_for_storage();
        assert_eq!(canonical.route.as_deref(), Some("api"));
        assert!(
            canonical
                .tenant
                .as_deref()
                .is_some_and(|value| value.starts_with("sha256:"))
        );
        assert!(
            canonical
                .token
                .as_deref()
                .is_some_and(|value| value.starts_with("sha256:"))
        );
        assert!(
            canonical
                .client
                .as_deref()
                .is_some_and(|value| value.starts_with("sha256:"))
        );

        let key = compose_quota_key("tenant-quota", &labels);
        assert!(key.contains("route=3:api|"));
        assert!(!key.contains("tenant=4:acme|"));
        assert!(!key.contains("token=12:secret-token|"));
        assert!(!key.contains("client=12:203.0.113.10|"));
        assert!(key.contains(canonical.tenant.as_deref().expect("hashed tenant")));
        assert!(key.contains(canonical.token.as_deref().expect("hashed token")));
        assert!(key.contains(canonical.client.as_deref().expect("hashed client")));
    }

    #[test]
    fn route_identity_remains_readable_during_storage_canonicalization() {
        let labels = QuotaIdentityLabels {
            route: Some("payments".to_string()),
            tenant: Some("acme".to_string()),
            token: None,
            client: None,
        };

        let canonical = labels.canonicalize_for_storage();
        assert_eq!(canonical.route.as_deref(), Some("payments"));
        assert_eq!(
            canonical.tenant.as_deref(),
            Some(canonical_quota_identity_value(QuotaIdentityDimension::Tenant, "acme",).as_str())
        );

        let key = compose_quota_key("tenant-quota", &labels);
        assert!(key.contains("route=8:payments|"));
        assert!(!key.contains("tenant=4:acme|"));
    }

    #[test]
    fn quota_identity_extraction_rejects_missing_and_invalid_selector_values() {
        let policy = QuotaPolicyRuntime {
            name: "tenant-quota".to_string(),
            route_allowlist: HashSet::new(),
            selector: QuotaSelectorMatcher {
                route: true,
                tenant: Some(QuotaSelectorKeySpec::Header("x-tenant-id".to_string())),
                token: Some(QuotaSelectorKeySpec::BearerToken),
                client: None,
            },
            burst: Some(QuotaWindowPolicy {
                requests: 10,
                window: Duration::from_secs(1),
            }),
            sustained: None,
        };

        let missing_tenant = identity_context_with_headers(
            Some("api"),
            "GET",
            "/v1",
            Some("api.example.com"),
            None,
            None,
            HashMap::from([("authorization".to_string(), "Bearer token-1".to_string())]),
        );
        let err = policy
            .composite_key(&missing_tenant)
            .expect_err("missing tenant header must reject");
        assert_eq!(err.dimension, QuotaIdentityDimension::Tenant);
        assert_eq!(err.reason, QuotaDenyReason::SelectorIdentityMissing);

        let invalid_token = identity_context_with_headers(
            Some("api"),
            "GET",
            "/v1",
            Some("api.example.com"),
            None,
            None,
            HashMap::from([
                ("authorization".to_string(), "Basic abc123".to_string()),
                ("x-tenant-id".to_string(), "acme".to_string()),
            ]),
        );
        let err = policy
            .composite_key(&invalid_token)
            .expect_err("invalid bearer token must reject");
        assert_eq!(err.dimension, QuotaIdentityDimension::Token);
        assert_eq!(err.reason, QuotaDenyReason::SelectorIdentityInvalid);
    }

    #[test]
    fn oversized_bearer_token_is_rejected() {
        let policy =
            quota_policy_with_selectors(None, Some(QuotaSelectorKeySpec::BearerToken), None);
        let oversized_token = "t".repeat(MAX_REQUEST_DERIVED_QUOTA_IDENTITY_BYTES + 1);
        let context = identity_context_with_headers(
            Some("api"),
            "GET",
            "/v1",
            Some("api.example.com"),
            None,
            None,
            HashMap::from([(
                "authorization".to_string(),
                format!("Bearer {oversized_token}"),
            )]),
        );

        assert_eq!(
            extract_runtime_request_key(&RuntimeRequestKeySpec::BearerToken, &context),
            RequestKeyExtraction::Invalid
        );
        assert_selector_identity_invalid(&policy, &context, QuotaIdentityDimension::Token);
    }

    #[test]
    fn oversized_header_cookie_query_and_cid_values_are_rejected() {
        let oversized = "a".repeat(MAX_REQUEST_DERIVED_QUOTA_IDENTITY_BYTES + 1);

        let header_policy = quota_policy_with_selectors(
            Some(QuotaSelectorKeySpec::Header("x-tenant-id".to_string())),
            None,
            None,
        );
        let header_context = identity_context_with_headers(
            Some("api"),
            "GET",
            "/v1",
            Some("api.example.com"),
            None,
            None,
            HashMap::from([("x-tenant-id".to_string(), oversized.clone())]),
        );
        assert_eq!(
            extract_runtime_request_key(
                &RuntimeRequestKeySpec::Header("x-tenant-id".to_string()),
                &header_context,
            ),
            RequestKeyExtraction::Invalid
        );
        assert_selector_identity_invalid(
            &header_policy,
            &header_context,
            QuotaIdentityDimension::Tenant,
        );

        let cookie_policy = quota_policy_with_selectors(
            Some(QuotaSelectorKeySpec::Cookie("session".to_string())),
            None,
            None,
        );
        let cookie_context = identity_context_with_headers(
            Some("api"),
            "GET",
            "/v1",
            Some("api.example.com"),
            None,
            None,
            HashMap::from([(
                "cookie".to_string(),
                format!("session={oversized}; theme=dark"),
            )]),
        );
        assert_eq!(
            extract_runtime_request_key(
                &RuntimeRequestKeySpec::Cookie("session".to_string()),
                &cookie_context,
            ),
            RequestKeyExtraction::Invalid
        );
        assert_selector_identity_invalid(
            &cookie_policy,
            &cookie_context,
            QuotaIdentityDimension::Tenant,
        );

        let query_policy = quota_policy_with_selectors(
            Some(QuotaSelectorKeySpec::Query("tenant".to_string())),
            None,
            None,
        );
        let query_context = identity_context_with_headers(
            Some("api"),
            "GET",
            leak_string(format!("/v1?tenant={oversized}")),
            Some("api.example.com"),
            None,
            None,
            HashMap::new(),
        );
        assert_eq!(
            extract_runtime_request_key(
                &RuntimeRequestKeySpec::Query("tenant".to_string()),
                &query_context,
            ),
            RequestKeyExtraction::Invalid
        );
        assert_selector_identity_invalid(
            &query_policy,
            &query_context,
            QuotaIdentityDimension::Tenant,
        );

        let cid_policy = quota_policy_with_selectors(Some(QuotaSelectorKeySpec::Cid), None, None);
        let cid_context = identity_context_with_headers(
            Some("api"),
            "GET",
            "/v1",
            Some("api.example.com"),
            Some(leak_string(oversized)),
            None,
            HashMap::new(),
        );
        assert_eq!(
            extract_runtime_request_key(&RuntimeRequestKeySpec::Cid, &cid_context),
            RequestKeyExtraction::Invalid
        );
        assert_selector_identity_invalid(&cid_policy, &cid_context, QuotaIdentityDimension::Tenant);
    }

    #[test]
    fn legacy_fallback_does_not_mask_invalid_selector_values() {
        let policy = QuotaPolicyRuntime {
            name: "tenant-quota".to_string(),
            route_allowlist: HashSet::new(),
            selector: QuotaSelectorMatcher {
                route: true,
                tenant: Some(
                    QuotaSelectorKeySpec::Header("x-tenant-id".to_string())
                        .with_legacy_default_fallback(),
                ),
                token: None,
                client: None,
            },
            burst: Some(QuotaWindowPolicy {
                requests: 10,
                window: Duration::from_secs(1),
            }),
            sustained: None,
        };

        let oversized_header = "a".repeat(MAX_REQUEST_DERIVED_QUOTA_IDENTITY_BYTES + 1);
        let context = identity_context_with_headers(
            Some("api"),
            "GET",
            "/v1",
            Some("api.example.com"),
            None,
            None,
            HashMap::from([("x-tenant-id".to_string(), oversized_header)]),
        );

        let err = policy
            .composite_key(&context)
            .expect_err("oversized selector values must stay invalid");
        assert_eq!(err.dimension, QuotaIdentityDimension::Tenant);
        assert_eq!(err.reason, QuotaDenyReason::SelectorIdentityInvalid);
    }

    #[test]
    fn distinct_oversized_selector_values_do_not_collide_via_truncation() {
        let policy = quota_policy_with_selectors(
            Some(QuotaSelectorKeySpec::Header("x-tenant-id".to_string())),
            None,
            None,
        );
        let prefix = "x".repeat(MAX_REQUEST_DERIVED_QUOTA_IDENTITY_BYTES);
        let first = format!("{prefix}a");
        let second = format!("{prefix}b");

        let first_context = identity_context_with_headers(
            Some("api"),
            "GET",
            "/v1",
            Some("api.example.com"),
            None,
            None,
            HashMap::from([("x-tenant-id".to_string(), first)]),
        );
        let second_context = identity_context_with_headers(
            Some("api"),
            "GET",
            "/v1",
            Some("api.example.com"),
            None,
            None,
            HashMap::from([("x-tenant-id".to_string(), second)]),
        );

        assert_eq!(
            extract_runtime_request_key(
                &RuntimeRequestKeySpec::Header("x-tenant-id".to_string()),
                &first_context,
            ),
            RequestKeyExtraction::Invalid
        );
        assert_eq!(
            extract_runtime_request_key(
                &RuntimeRequestKeySpec::Header("x-tenant-id".to_string()),
                &second_context,
            ),
            RequestKeyExtraction::Invalid
        );
        assert_selector_identity_invalid(&policy, &first_context, QuotaIdentityDimension::Tenant);
        assert_selector_identity_invalid(&policy, &second_context, QuotaIdentityDimension::Tenant);
    }

    #[test]
    fn quota_policy_route_allowlist_scopes_composite_selector_matching() {
        let policy = QuotaPolicyRuntime {
            name: "tenant-quota".to_string(),
            route_allowlist: HashSet::from(["payments".to_string()]),
            selector: QuotaSelectorMatcher {
                route: true,
                tenant: Some(QuotaSelectorKeySpec::Header("x-tenant-id".to_string())),
                token: None,
                client: Some(QuotaSelectorKeySpec::ClientIp),
            },
            burst: Some(QuotaWindowPolicy {
                requests: 100,
                window: Duration::from_secs(1),
            }),
            sustained: None,
        };

        assert!(policy.applies_to_route("payments"));
        assert!(!policy.applies_to_route("api"));

        let context = identity_context_with_headers(
            Some("payments"),
            "POST",
            "/v1/payments",
            Some("api.example.com"),
            None,
            Some("203.0.113.10:443".parse().expect("client addr")),
            HashMap::from([("x-tenant-id".to_string(), "acme".to_string())]),
        );
        let composite = policy
            .composite_key(&context)
            .expect("matching route should still build composite keys");

        assert_eq!(composite.labels.route.as_deref(), Some("payments"));
        assert!(
            composite
                .labels
                .tenant
                .as_deref()
                .is_some_and(|value| value.starts_with("sha256:"))
        );
        assert!(
            composite
                .labels
                .client
                .as_deref()
                .is_some_and(|value| value.starts_with("sha256:"))
        );
    }

    #[test]
    fn runtime_request_key_extraction_covers_canonical_identity_sources() {
        let context = identity_context_with_headers(
            Some("api"),
            "post",
            "/v1/payments?tenant=acme",
            Some("api.example.com"),
            Some("cid-123"),
            Some("203.0.113.10:443".parse().expect("client addr")),
            HashMap::from([
                ("authorization".to_string(), "Bearer token-1".to_string()),
                ("cookie".to_string(), "session=s123; theme=dark".to_string()),
                ("x-client-id".to_string(), "client-a".to_string()),
            ]),
        );

        assert_eq!(
            extract_runtime_request_key(&RuntimeRequestKeySpec::Path, &context),
            RequestKeyExtraction::Found("/v1/payments".to_string())
        );
        assert_eq!(
            extract_runtime_request_key(&RuntimeRequestKeySpec::Authority, &context),
            RequestKeyExtraction::Found("api.example.com".to_string())
        );
        assert_eq!(
            extract_runtime_request_key(&RuntimeRequestKeySpec::Method, &context),
            RequestKeyExtraction::Found("POST".to_string())
        );
        assert_eq!(
            extract_runtime_request_key(&RuntimeRequestKeySpec::Cid, &context),
            RequestKeyExtraction::Found("cid-123".to_string())
        );
        assert_eq!(
            extract_runtime_request_key(&RuntimeRequestKeySpec::ClientIp, &context),
            RequestKeyExtraction::Found("203.0.113.10".to_string())
        );
        assert_eq!(
            extract_runtime_request_key(&RuntimeRequestKeySpec::BearerToken, &context),
            RequestKeyExtraction::Found("token-1".to_string())
        );
        assert_eq!(
            extract_runtime_request_key(
                &RuntimeRequestKeySpec::Cookie("session".to_string()),
                &context
            ),
            RequestKeyExtraction::Found("s123".to_string())
        );
        assert_eq!(
            extract_runtime_request_key(
                &RuntimeRequestKeySpec::Query("tenant".to_string()),
                &context
            ),
            RequestKeyExtraction::Found("acme".to_string())
        );
        assert_eq!(
            extract_runtime_request_key(
                &RuntimeRequestKeySpec::Header("x-client-id".to_string()),
                &context
            ),
            RequestKeyExtraction::Found("client-a".to_string())
        );
    }

    #[test]
    fn quota_counter_request_clones_policy_windows_and_defaults_cost() {
        let policy = QuotaPolicyRuntime {
            name: "tenant-quota".to_string(),
            route_allowlist: HashSet::from(["api".to_string()]),
            selector: QuotaSelectorMatcher {
                route: true,
                tenant: Some(QuotaSelectorKeySpec::Header("x-tenant-id".to_string())),
                token: None,
                client: None,
            },
            burst: Some(QuotaWindowPolicy {
                requests: 50,
                window: Duration::from_secs(1),
            }),
            sustained: Some(QuotaWindowPolicy {
                requests: 500,
                window: Duration::from_secs(60),
            }),
        };
        let composite_key = QuotaCompositeKey {
            policy_name: "tenant-quota".to_string(),
            key: "policy=12:tenant-quota|route=3:api|tenant=4:acme|".to_string(),
            labels: QuotaIdentityLabels {
                route: Some("api".to_string()),
                tenant: Some("acme".to_string()),
                token: None,
                client: None,
            },
            dimensions: policy.selector.dimensions(),
        };

        let request = policy.counter_request(composite_key.clone()).with_cost(3);

        assert_eq!(request.policy_name, "tenant-quota");
        assert_eq!(request.composite_key, composite_key);
        assert_eq!(request.cost, 3);
        assert_eq!(request.burst, policy.burst);
        assert_eq!(request.sustained, policy.sustained);
    }

    #[test]
    fn quota_counter_backend_errors_map_to_canonical_deny_reasons() {
        let timeout = QuotaCounterBackendError {
            policy_name: Some("tenant-quota".to_string()),
            composite_key: Some("k1".to_string()),
            kind: QuotaCounterBackendErrorKind::Timeout,
            detail: None,
        };
        assert_eq!(timeout.deny_reason(), QuotaDenyReason::BackendTimeout);

        let unavailable = QuotaCounterBackendError {
            policy_name: Some("tenant-quota".to_string()),
            composite_key: Some("k1".to_string()),
            kind: QuotaCounterBackendErrorKind::Unavailable,
            detail: Some("redis unavailable".to_string()),
        };
        assert_eq!(
            unavailable.deny_reason(),
            QuotaDenyReason::BackendUnavailable
        );

        let error = QuotaCounterBackendError {
            policy_name: Some("tenant-quota".to_string()),
            composite_key: Some("k1".to_string()),
            kind: QuotaCounterBackendErrorKind::Error,
            detail: Some("script error".to_string()),
        };
        assert_eq!(error.deny_reason(), QuotaDenyReason::BackendError);
    }

    #[test]
    fn quota_counter_outcome_captures_multi_window_consumption_and_denial() {
        let composite_key = QuotaCompositeKey {
            policy_name: "tenant-quota".to_string(),
            key: "policy=12:tenant-quota|route=3:api|tenant=4:acme|".to_string(),
            labels: QuotaIdentityLabels {
                route: Some("api".to_string()),
                tenant: Some("acme".to_string()),
                token: None,
                client: None,
            },
            dimensions: QuotaSelectorDimensions {
                route: true,
                tenant: true,
                token: false,
                client: false,
            },
        };

        let outcome = QuotaCounterEvaluationOutcome {
            matched_policy: "tenant-quota".to_string(),
            composite_key,
            decision: QuotaCounterEvaluationDecision::Denied(QuotaDenyReason::BurstQuotaExhausted),
            counter: QuotaCounterResult {
                burst: Some(QuotaWindowUsage {
                    limit: 50,
                    consumed: 50,
                    remaining: 0,
                    window: Duration::from_secs(1),
                    reset_after: Some(Duration::from_millis(750)),
                    bucket_started_at_unix_ms: Some(1_700_000_000_000),
                    reset_at_unix_ms: Some(1_700_000_001_000),
                    storage_key: Some(
                        "impulse:quota:qv1:12:tenant-quota:burst:1000:1700000000000:abc"
                            .to_string(),
                    ),
                }),
                sustained: Some(QuotaWindowUsage {
                    limit: 500,
                    consumed: 320,
                    remaining: 180,
                    window: Duration::from_secs(60),
                    reset_after: Some(Duration::from_secs(12)),
                    bucket_started_at_unix_ms: Some(1_699_999_980_000),
                    reset_at_unix_ms: Some(1_700_000_040_000),
                    storage_key: Some(
                        "impulse:quota:qv1:12:tenant-quota:sustained:60000:1699999980000:def"
                            .to_string(),
                    ),
                }),
            },
            backend_metadata: QuotaCounterBackendMetadata {
                backend_kind: "redis".to_string(),
                protocol_version: REDIS_QUOTA_PROTOCOL_VERSION.to_string(),
                evaluated_at_unix_ms: Some(1_700_000_000_250),
            },
        };

        assert_eq!(outcome.matched_policy, "tenant-quota");
        assert_eq!(
            outcome.decision,
            QuotaCounterEvaluationDecision::Denied(QuotaDenyReason::BurstQuotaExhausted)
        );
        assert_eq!(
            outcome.counter.burst.as_ref().map(|window| window.consumed),
            Some(50)
        );
        assert_eq!(
            outcome
                .counter
                .sustained
                .as_ref()
                .map(|window| window.remaining),
            Some(180)
        );
    }
}
