use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseCompressionAction {
    Gzip,
    Bypass(ResponseCompressionBypassReason),
}

impl ResponseCompressionAction {
    pub(super) const ALL: [Self; 11] = [
        Self::Gzip,
        Self::Bypass(ResponseCompressionBypassReason::Disabled),
        Self::Bypass(ResponseCompressionBypassReason::Bodyless),
        Self::Bypass(ResponseCompressionBypassReason::Status),
        Self::Bypass(ResponseCompressionBypassReason::ExistingEncoding),
        Self::Bypass(ResponseCompressionBypassReason::NoTransform),
        Self::Bypass(ResponseCompressionBypassReason::Range),
        Self::Bypass(ResponseCompressionBypassReason::ContentType),
        Self::Bypass(ResponseCompressionBypassReason::UnknownLength),
        Self::Bypass(ResponseCompressionBypassReason::BelowMinimumSize),
        Self::Bypass(ResponseCompressionBypassReason::NotAccepted),
    ];
    pub(super) const COUNT: usize = Self::ALL.len();

    pub(super) const fn index(self) -> usize {
        match self {
            Self::Gzip => 0,
            Self::Bypass(ResponseCompressionBypassReason::Disabled) => 1,
            Self::Bypass(ResponseCompressionBypassReason::Bodyless) => 2,
            Self::Bypass(ResponseCompressionBypassReason::Status) => 3,
            Self::Bypass(ResponseCompressionBypassReason::ExistingEncoding) => 4,
            Self::Bypass(ResponseCompressionBypassReason::NoTransform) => 5,
            Self::Bypass(ResponseCompressionBypassReason::Range) => 6,
            Self::Bypass(ResponseCompressionBypassReason::ContentType) => 7,
            Self::Bypass(ResponseCompressionBypassReason::UnknownLength) => 8,
            Self::Bypass(ResponseCompressionBypassReason::BelowMinimumSize) => 9,
            Self::Bypass(ResponseCompressionBypassReason::NotAccepted) => 10,
        }
    }

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Bypass(ResponseCompressionBypassReason::Disabled) => "disabled",
            Self::Bypass(ResponseCompressionBypassReason::Bodyless) => "bodyless",
            Self::Bypass(ResponseCompressionBypassReason::Status) => "status",
            Self::Bypass(ResponseCompressionBypassReason::ExistingEncoding) => "existing_encoding",
            Self::Bypass(ResponseCompressionBypassReason::NoTransform) => "no_transform",
            Self::Bypass(ResponseCompressionBypassReason::Range) => "range",
            Self::Bypass(ResponseCompressionBypassReason::ContentType) => "content_type",
            Self::Bypass(ResponseCompressionBypassReason::UnknownLength) => "unknown_length",
            Self::Bypass(ResponseCompressionBypassReason::BelowMinimumSize) => "below_minimum_size",
            Self::Bypass(ResponseCompressionBypassReason::NotAccepted) => "not_accepted",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseCompressionBypassReason {
    Disabled,
    Bodyless,
    Status,
    ExistingEncoding,
    NoTransform,
    Range,
    ContentType,
    UnknownLength,
    BelowMinimumSize,
    NotAccepted,
}

#[derive(Default, Clone)]
pub(crate) struct BackendDnsState {
    pub(crate) last_success_unix_seconds: u64,
    pub(crate) resolved_address_count: u64,
}

#[derive(Default, Clone)]
pub(crate) struct BackendRotationState {
    pub(crate) rotations: u64,
}

#[derive(Default, Clone)]
pub(crate) struct JwksSourceState {
    pub(crate) jwks_source_id: String,
    pub(crate) refresh_success_total: u64,
    pub(crate) refresh_failure_total: u64,
    pub(crate) active_key_count: u64,
    pub(crate) state: &'static str,
    pub(crate) last_refresh_attempt_unix_seconds: Option<u64>,
    pub(crate) last_refresh_success_unix_seconds: Option<u64>,
    pub(crate) last_failure_reason: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct BackendConnectAttemptKey {
    pub(crate) backend: String,
    pub(crate) hostname: String,
    pub(crate) resolved_addr: String,
}

/// Upper bound on the number of distinct `impulse_backend_connect_attempt_total`
/// series. Once this many distinct keys exist, further keys collapse into a
/// stable overflow series so label cardinality does not grow with DNS churn.
pub(crate) const BACKEND_CONNECT_ATTEMPT_LABEL_CAP: usize = 512;

/// Stable sentinel used for the `hostname`/`resolved_addr` labels once the
/// cardinality cap is reached.
pub(crate) const METRIC_LABEL_OVER_CAP: &str = "__over_cap__";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpstreamRequestCountKey {
    pub upstream: String,
    pub status_class: &'static str,
    pub outcome: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BackendRequestCountKey {
    pub upstream: String,
    pub backend: String,
    pub status_class: &'static str,
    pub outcome: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpstreamRequestLatencyKey {
    pub upstream: String,
    pub outcome: &'static str,
}

#[derive(Default)]
pub(super) struct RequestResultMetricsStore {
    pub(super) upstream_request_counts: HashMap<UpstreamRequestCountKey, u64>,
    pub(super) backend_request_counts: HashMap<BackendRequestCountKey, u64>,
    pub(super) upstream_request_latency: HashMap<UpstreamRequestLatencyKey, RequestLatencyStats>,
}

#[derive(Default, Clone)]
pub(crate) struct RequestResultMetricsSnapshot {
    pub(crate) upstream_request_counts: Vec<(UpstreamRequestCountKey, u64)>,
    pub(crate) backend_request_counts: Vec<(BackendRequestCountKey, u64)>,
    pub(crate) upstream_request_latency: Vec<(UpstreamRequestLatencyKey, RequestLatencyStats)>,
}

#[derive(Default, Clone)]
pub(super) struct RequestResultMetricsSnapshotCache {
    pub(super) version: u64,
    pub(super) snapshot: RequestResultMetricsSnapshot,
}

#[derive(Default, Clone)]
pub(crate) struct QuotaMetricsSnapshot {
    pub(crate) quota_policy_outcomes: Vec<(QuotaPolicyOutcomeKey, u64)>,
    pub(crate) quota_backend_health: Vec<(QuotaBackendHealthKey, u64)>,
}

#[derive(Default, Clone)]
pub(super) struct QuotaMetricsSnapshotCache {
    pub(super) version: u64,
    pub(super) snapshot: QuotaMetricsSnapshot,
    pub(super) rendered: String,
}

#[derive(Default, Clone)]
pub(crate) struct JwtJwksMetricsSnapshot {
    pub(crate) jwt_validation_failures: Vec<(String, u64)>,
    pub(crate) jwt_algorithm_rejections: Vec<(String, u64)>,
    pub(crate) jwks_unknown_kid_events: Vec<(String, u64)>,
    pub(crate) jwks_source_state: Vec<JwksSourceState>,
}

#[derive(Default, Clone)]
pub(super) struct JwtJwksMetricsSnapshotCache {
    pub(super) version: u64,
    pub(super) snapshot: JwtJwksMetricsSnapshot,
    pub(super) rendered: String,
}

#[derive(Default, Clone)]
pub(crate) struct BackendMetricsSnapshot {
    pub(crate) backend_dns_state: Vec<(String, BackendDnsState)>,
    pub(crate) backend_rotation_state: Vec<(String, BackendRotationState)>,
    pub(crate) backend_connect_attempts: Vec<(BackendConnectAttemptKey, u64)>,
}

#[derive(Default, Clone)]
pub(super) struct BackendMetricsSnapshotCache {
    pub(super) version: u64,
    pub(super) snapshot: BackendMetricsSnapshot,
    pub(super) rendered: String,
}

#[derive(Default, Clone)]
pub(crate) struct SecretMetricsSnapshot {
    pub(crate) secret_reload_totals: Vec<(SecretReloadKey, u64)>,
    pub(crate) secret_resolve_totals: Vec<(SecretResolveKey, u64)>,
    pub(crate) secret_last_success_unixtime: Vec<(SecretLastSuccessKey, u64)>,
    pub(crate) upstream_client_cert_expiry: Vec<(UpstreamClientCertExpiryKey, i64)>,
    pub(crate) control_plane_cert_reload_totals: Vec<(ControlPlaneCertReloadKey, u64)>,
}

#[derive(Default, Clone)]
pub(super) struct SecretMetricsSnapshotCache {
    pub(super) version: u64,
    pub(super) snapshot: SecretMetricsSnapshot,
}

#[derive(Default, Clone)]
pub(super) struct RouteWorkerMetricsRenderCache {
    pub(super) version: u64,
    pub(super) rendered: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct QuotaPolicyOutcomeKey {
    pub(crate) policy: String,
    pub(crate) decision: String,
    pub(crate) reason: String,
    pub(crate) selector_dimensions: String,
    pub(crate) backend_mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct QuotaBackendHealthKey {
    pub(crate) backend_mode: String,
    pub(crate) reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct DownstreamTlsHandshakeFailureKey {
    pub(crate) listener: String,
    pub(crate) reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct DownstreamTlsCertSelectionKey {
    pub(crate) listener: String,
    pub(crate) selection: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct DownstreamTlsAlpnKey {
    pub(crate) listener: String,
    pub(crate) protocol: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct UpstreamTlsFailureKey {
    pub(crate) upstream: String,
    pub(crate) backend: String,
    pub(crate) phase: String,
    pub(crate) reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct SecretReloadKey {
    pub(crate) scope: String,
    pub(crate) result: String,
    pub(crate) reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct SecretResolveKey {
    pub(crate) provider: String,
    pub(crate) result: String,
    pub(crate) reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct SecretLastSuccessKey {
    pub(crate) scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct UpstreamClientCertExpiryKey {
    pub(crate) upstream: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ControlPlaneCertReloadKey {
    pub(crate) result: String,
    pub(crate) reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct DownstreamTlsCertExpiryKey {
    pub(crate) listener: String,
    pub(crate) server_name: String,
}

pub(super) const LATENCY_BUCKETS_MS: [u64; 14] = [
    1, 5, 10, 25, 50, 100, 250, 500, 1_000, 2_000, 5_000, 10_000, 30_000, 60_000,
];
pub(super) const ROUTE_LATENCY_SAMPLE_EVERY_ENV: &str = "IMPULSE_ROUTE_LATENCY_SAMPLE_EVERY";

#[derive(Default, Clone)]
pub(super) struct RouteStats {
    pub(super) requests_total: u64,
    pub(super) success: u64,
    pub(super) failure: u64,
    pub(super) rate_limited: u64,
    pub(super) timeout: u64,
    pub(super) backend_error: u64,
    pub(super) overload_shed: u64,
    pub(super) latency_buckets: [u64; LATENCY_BUCKETS_MS.len() + 1],
}

#[derive(Default, Clone)]
pub(super) struct WorkerStats {
    pub(super) requests_total: u64,
    pub(super) requests_success: u64,
    pub(super) requests_failure: u64,
    pub(super) ingress_packets_total: u64,
    pub(super) ingress_queue_drops: u64,
    pub(super) ingress_queue_drop_bytes: u64,
}

#[derive(Default, Clone)]
pub struct RequestLatencyStats {
    pub latency_buckets: [u64; LATENCY_BUCKETS_MS.len() + 1],
    pub latency_ms_sum: u64,
    pub count: u64,
}

pub(super) struct RouteStatsAtomic {
    pub(super) requests_total: AtomicU64,
    pub(super) success: AtomicU64,
    pub(super) failure: AtomicU64,
    pub(super) rate_limited: AtomicU64,
    pub(super) timeout: AtomicU64,
    pub(super) backend_error: AtomicU64,
    pub(super) overload_shed: AtomicU64,
    pub(super) latency_buckets: [AtomicU64; LATENCY_BUCKETS_MS.len() + 1],
}

impl RouteStatsAtomic {
    pub(super) fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            success: AtomicU64::new(0),
            failure: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            timeout: AtomicU64::new(0),
            backend_error: AtomicU64::new(0),
            overload_shed: AtomicU64::new(0),
            latency_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    pub(super) fn snapshot(&self) -> RouteStats {
        let mut latency_buckets = [0u64; LATENCY_BUCKETS_MS.len() + 1];
        for (idx, bucket) in self.latency_buckets.iter().enumerate() {
            latency_buckets[idx] = bucket.load(Ordering::Relaxed);
        }

        RouteStats {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            success: self.success.load(Ordering::Relaxed),
            failure: self.failure.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            timeout: self.timeout.load(Ordering::Relaxed),
            backend_error: self.backend_error.load(Ordering::Relaxed),
            overload_shed: self.overload_shed.load(Ordering::Relaxed),
            latency_buckets,
        }
    }
}

pub(super) struct WorkerStatsAtomic {
    pub(super) requests_total: AtomicU64,
    pub(super) requests_success: AtomicU64,
    pub(super) requests_failure: AtomicU64,
    pub(super) ingress_packets_total: AtomicU64,
    pub(super) ingress_queue_drops: AtomicU64,
    pub(super) ingress_queue_drop_bytes: AtomicU64,
}

impl WorkerStatsAtomic {
    pub(super) fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            requests_success: AtomicU64::new(0),
            requests_failure: AtomicU64::new(0),
            ingress_packets_total: AtomicU64::new(0),
            ingress_queue_drops: AtomicU64::new(0),
            ingress_queue_drop_bytes: AtomicU64::new(0),
        }
    }

    pub(super) fn snapshot(&self) -> WorkerStats {
        WorkerStats {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            requests_success: self.requests_success.load(Ordering::Relaxed),
            requests_failure: self.requests_failure.load(Ordering::Relaxed),
            ingress_packets_total: self.ingress_packets_total.load(Ordering::Relaxed),
            ingress_queue_drops: self.ingress_queue_drops.load(Ordering::Relaxed),
            ingress_queue_drop_bytes: self.ingress_queue_drop_bytes.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum RouteOutcome {
    Success,
    Failure,
    RateLimited,
    Timeout,
    BackendError,
    OverloadShed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverloadShedReason {
    Brownout,
    AdaptiveAdmission,
    RouteCap,
    RouteGlobalCap,
    GlobalInflight,
    UpstreamInflight,
    BackendInflight,
    CircuitOpen,
    RequestBufferCap,
    ResponsePrebufferCap,
    ConnectionCap,
}

impl OverloadShedReason {
    pub fn canonical(self) -> crate::AdmissionOverloadCause {
        use crate::AdmissionOverloadCause as C;
        match self {
            Self::Brownout => C::Brownout,
            Self::AdaptiveAdmission => C::AdaptiveAdmission,
            Self::RouteCap => C::RouteCap,
            Self::RouteGlobalCap => C::RouteGlobalCap,
            Self::GlobalInflight => C::GlobalInflight,
            Self::UpstreamInflight => C::UpstreamInflight,
            Self::BackendInflight => C::BackendInflight,
            Self::CircuitOpen => C::CircuitOpen,
            Self::RequestBufferCap => C::RequestBufferCap,
            Self::ResponsePrebufferCap => C::ResponsePrebufferCap,
            Self::ConnectionCap => C::ConnectionCap,
        }
    }

    pub fn reason_label(self) -> &'static str {
        self.canonical().slug()
    }
}
