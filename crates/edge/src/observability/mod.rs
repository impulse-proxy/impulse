//! Canonical observability vocabulary.
//!
//! This module is the **single, handler-free schema** for the operational reason
//! vocabularies. It defines each canonical enum *once*, with one `slug()` per
//! concept that is the stable string used across all three observability
//! surfaces — metric label value, structured-log `reason=` value, and
//! control-API serialized value. The `From` mappings below tie every local
//! reason enum (QUIC data path, bootstrap, retry/hedge, admission, backend
//! health) to this canonical vocabulary, so one operational concept is described
//! one way everywhere.
//!
//! This is the source of truth for dashboard and alert consumers: a reader can
//! understand the reason vocabularies and canonical field names from this one
//! module without reading any emitter, and the mapping tests guarantee emitters
//! cannot drift from it.
//!
//! # Operational observability schema reference (obs plan, Phase 9)
//!
//! This is the stable source of truth for dashboard/alert consumers. For each
//! canonical reason family: the enum value, its `slug()` (which is the metric
//! label value, the structured-log `reason=` value, and the control-API string —
//! one string per concept across all three surfaces).
//!
//! ## Request outcome — [`RequestOutcomeReason`]
//!
//! | enum value | slug (metric / log / control-API) | coarse `outcome` label |
//! |---|---|---|
//! | `Completed` | `completed` | `success` |
//! | `Cancelled` | `cancelled` | `failure` |
//! | `TimedOut` | `timed_out` | `timeout` |
//! | `AuthDenied` | `auth_denied` | `failure` |
//! | `RateLimited` | `rate_limited` | `rate_limited` |
//! | `Overloaded` | `overloaded` | `overload_shed` |
//! | `ValidationRejected` | `validation_rejected` | `failure` |
//! | `BackendTransportFailed` | `backend_transport_failed` | `failure` |
//! | `BackendProtocolFailed` | `backend_protocol_failed` | `failure` |
//! | `BackendTlsFailed` | `backend_tls_failed` | `failure` |
//! | `BackendBridgeFailed` | `backend_bridge_failed` | `failure` |
//!
//! ## Backend health — [`BackendHealthReason`]
//!
//! | enum value | slug | failure? |
//! |---|---|---|
//! | `ActiveProbeSuccess` | `active_probe_success` | no |
//! | `ActiveProbeFailure` | `active_probe_failure` | yes |
//! | `PassiveSuccess` | `passive_success` | no |
//! | `PassiveFailure` | `passive_failure` | yes |
//! | `DnsRefreshFailed` | `dns_refresh_failed` | yes |
//! | `EmptyResolutionRetained` | `empty_resolution_retained` | no |
//! | `PoolPoisoned` | `pool_poisoned` | yes |
//!
//! Health-failure *class* (distinct axis, control-API `health_reason` +
//! `impulse_health_failures_total{reason}`): `5xx`, `timeout`, `transport`,
//! `tls`, `circuit_open`. Refresh *classification* (distinct axis): `refreshed`,
//! `unchanged`, `rejected_empty_answer`, `failed_active_preserved`.
//!
//! ## Retry — [`RetryDecisionReason`]
//!
//! | enum value | slug | retry? |
//! |---|---|---|
//! | `UpstreamTimeout` | `upstream_timeout` | yes |
//! | `UpstreamTransportFailure` | `upstream_transport_failure` | yes |
//! | `UpstreamProtocolFailure` | `upstream_protocol_failure` | yes |
//! | `RetryBudgetDenied` | `retry_budget_denied` | no |
//! | `RetryPolicyDisabled` | `retry_policy_disabled` | no |
//! | `IdempotencyDenied` | `idempotency_denied` | no |
//!
//! ## Hedge — [`HedgeDecisionReason`]
//!
//! | enum value | slug | triggered? |
//! |---|---|---|
//! | `DelayElapsed` | `delay_elapsed` | yes |
//! | `HedgingDisabled` | `hedging_disabled` | no |
//! | `PrimaryCompleted` | `primary_completed` | no |
//! | `RequestBodyNotReplayable` | `request_body_not_replayable` | no |
//! | `TunnelRequest` | `tunnel_request` | no |
//! | `MethodNotAllowed` | `method_not_allowed` | no |
//! | `AlternateBackendUnavailable` | `alternate_backend_unavailable` | no |
//! | `HedgeBudgetDenied` | `hedge_budget_denied` | no |
//!
//! ## Admission / auth — [`AdmissionDecisionReason`]
//!
//! | enum value | slug |
//! |---|---|
//! | `AuthDenied` | `auth_denied` |
//! | `AuthUnavailable` | `auth_unavailable` |
//! | `RateLimited` | `rate_limited` |
//! | `Overloaded` | `overloaded` (cause axis: [`AdmissionOverloadCause`]) |
//! | `ValidationRejected` | `validation_rejected` |
//! | `PolicyRejected` | `policy_rejected` |
//!
//! ## Quota policy — [`QuotaPolicyDecision`] / [`QuotaPolicyReason`]
//!
//! | decision enum value | slug |
//! |---|---|
//! | `Allowed` | `allowed` |
//! | `Denied` | `denied` |
//! | `ShadowDenied` | `shadow_denied` |
//! | `FailedOpen` | `failed_open` |
//! | `FailedClosed` | `failed_closed` |
//! | `NotApplied` | `not_applied` |
//!
//! | reason enum value | slug |
//! |---|---|
//! | `Allowed` | `allowed` |
//! | `NotApplied` | `not_applied` |
//! | `BurstQuotaExhausted` | `burst_quota_exhausted` |
//! | `SustainedQuotaExhausted` | `sustained_quota_exhausted` |
//! | `SelectorIdentityMissing` | `selector_identity_missing` |
//! | `SelectorIdentityInvalid` | `selector_identity_invalid` |
//! | `BackendTimeout` | `backend_timeout` |
//! | `BackendUnavailable` | `backend_unavailable` |
//! | `BackendError` | `backend_error` |
//!
//! ## Quota backend health — [`QuotaBackendHealthReason`]
//!
//! | enum value | slug |
//! |---|---|
//! | `Available` | `available` |
//! | `Timeout` | `timeout` |
//! | `Unavailable` | `unavailable` |
//! | `Error` | `error` |
//!
//! Overload cause ([`AdmissionOverloadCause`], the `impulse_overload_shed_by_reason_total{reason}`
//! label): `brownout`, `adaptive_admission`, `route_cap`, `route_global_cap`,
//! `global_inflight`, `upstream_inflight`, `backend_inflight`, `circuit_open`,
//! `request_buffer_cap`, `response_prebuffer_cap`, `connection_cap`.
//!
//! ## Required dimensions per event class
//!
//! Emitted via [`OperationalEventContext`] (canonical field names). `request_id`
//! is omitted (not `unassigned`) when no id exists yet.
//!
//! - **request / forwarding**: `request_id`, `upstream`, `backend`, `reason`,
//!   `failure_class`, status
//! - **backend lifecycle**: `backend`, `health_reason` (or refresh classification)
//! - **retry / hedge**: `request_id`, `upstream`, `backend`, `decision`, `reason`
//! - **admission / auth**: `request_id` (when known), `upstream`, `reason`
//!
//! ## Deprecated names / migration notes
//!
//! Superseded by the canonical field names above; dashboards keying on the old
//! strings must migrate:
//! - log field `route=` and `route_upstream=` → **`upstream=`**.
//! - literal `request_id=unassigned` → field **omitted** when no id exists.
//! - `Bootstrap request route=…` / `Bootstrap upstream error …` prose → the
//!   canonical `admission denied: …` / `upstream failure: …` schemas.
//! - `Backend <addr> became healthy/unhealthy` → `backend health transition:
//!   backend=<addr> health_reason=…`.
//! - Metric series names (`impulse_*`) are unchanged; only label *values* are now
//!   canonical enum slugs.

use std::fmt;

/// Why a request reached its terminal state — the one canonical request-outcome
/// vocabulary. Unifies the QUIC data-path terminal enums
/// (`RejectionReason`/`BackendFailureReason`/`TimeoutReason`) and the bootstrap
/// `Bootstrap*` slugs, which Phase 0 found were two disjoint vocabularies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestOutcomeReason {
    /// Response completed successfully (status-derived success).
    Completed,
    /// Client cancelled (reset / connection closed / operator abort).
    Cancelled,
    /// A deadline expired before completion.
    TimedOut,
    /// Rejected by authentication/authorization.
    AuthDenied,
    /// Rejected by rate limiting.
    RateLimited,
    /// Shed due to overload / admission control.
    Overloaded,
    /// Rejected by request validation or policy.
    ValidationRejected,
    /// Backend transport-level failure (connect/send/reset).
    BackendTransportFailed,
    /// Backend protocol-level failure (malformed/illegal upstream response).
    BackendProtocolFailed,
    /// Backend TLS failure.
    BackendTlsFailed,
    /// Backend bridge/translation failure.
    BackendBridgeFailed,
}

/// Why a backend's health/observation reached its state — the one canonical
/// backend-health vocabulary. Unifies `HealthFailureReason`,
/// `BackendHealthObservationOutcome`, and the DNS-refresh classifications, which
/// Phase 0 found were reported at three different granularities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendHealthReason {
    /// An active probe succeeded.
    ActiveProbeSuccess,
    /// An active probe failed.
    ActiveProbeFailure,
    /// Passive (live-traffic) observation succeeded.
    PassiveSuccess,
    /// Passive observation failed.
    PassiveFailure,
    /// A DNS refresh failed; the prior resolution is retained.
    DnsRefreshFailed,
    /// A DNS refresh returned no addresses; the prior resolution is retained.
    EmptyResolutionRetained,
    /// A backend pool lock was poisoned (observed as a health-affecting event).
    PoolPoisoned,
}

/// Why a retry was attempted or denied — the one canonical retry vocabulary.
/// Reconciles `RetryAttemptTelemetryReason` and `RetryPolicyDenialReason`, which
/// Phase 0 found emitted lossy/merged metric labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetryDecisionReason {
    /// Retriable: the prior attempt timed out.
    UpstreamTimeout,
    /// Retriable: the prior attempt hit a transport failure.
    UpstreamTransportFailure,
    /// Retriable: the prior attempt hit a protocol failure.
    UpstreamProtocolFailure,
    /// Denied: the retry budget is exhausted.
    RetryBudgetDenied,
    /// Denied: retries are disabled by policy.
    RetryPolicyDisabled,
    /// Denied: the request is not idempotent / body not replayable.
    IdempotencyDenied,
}

/// Why a hedge was triggered or denied — the one canonical hedge vocabulary.
/// Phase 0 found `HedgePolicyDenialReason` (7 variants) entirely unobserved; this
/// gives every hedge decision a canonical name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HedgeDecisionReason {
    /// A hedge fired because the primary passed the hedge delay.
    DelayElapsed,
    /// Denied: hedging is disabled by policy.
    HedgingDisabled,
    /// Denied: the primary request already completed.
    PrimaryCompleted,
    /// Denied: the request body is not replayable.
    RequestBodyNotReplayable,
    /// Denied: the request is a tunnel (CONNECT/websocket).
    TunnelRequest,
    /// Denied: the method is not allowed to hedge.
    MethodNotAllowed,
    /// Denied: no alternate backend is available.
    AlternateBackendUnavailable,
    /// Denied: the hedge budget is exhausted.
    HedgeBudgetDenied,
}

/// Why admission/auth rejected a request — the one canonical admission vocabulary.
/// Reconciles `AdmissionOutcomeClass`, `OverloadDecisionReason`, and the external
/// auth outcomes. Phase 0 found overload was split across two enums
/// (`OverloadDecisionReason` 6-variant vs `OverloadShedReason` 11-variant); the
/// fine-grained overload cause is carried separately by
/// [`AdmissionOverloadCause`] so this stays low-cardinality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdmissionDecisionReason {
    /// Authentication/authorization denied the request.
    AuthDenied,
    /// The auth service was unavailable (fail-closed).
    AuthUnavailable,
    /// Rate limiting rejected the request.
    RateLimited,
    /// Overload/admission control shed the request.
    Overloaded,
    /// Request validation rejected the request.
    ValidationRejected,
    /// A non-auth policy rejected the request.
    PolicyRejected,
}

/// The fine-grained cause of an [`AdmissionDecisionReason::Overloaded`] decision,
/// carried alongside it. This is the union of the two legacy overload enums so
/// the shed cause is not lost when the coarse decision is recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdmissionOverloadCause {
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

/// The coarse result of a quota-policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuotaPolicyDecision {
    Allowed,
    Denied,
    ShadowDenied,
    FailedOpen,
    FailedClosed,
    NotApplied,
}

/// The reason attached to a quota-policy evaluation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuotaPolicyReason {
    Allowed,
    NotApplied,
    BurstQuotaExhausted,
    SustainedQuotaExhausted,
    SelectorIdentityMissing,
    SelectorIdentityInvalid,
    BackendTimeout,
    BackendUnavailable,
    BackendError,
}

/// The health/error classification of a quota backend interaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuotaBackendHealthReason {
    Available,
    Timeout,
    Unavailable,
    Error,
}

// ---------------------------------------------------------------------------
// Stable string mapping layer (enum -> metric label / log value / control API)
// ---------------------------------------------------------------------------
//
// Each canonical enum exposes exactly one `slug()`: a single stable string that
// serves all three surfaces (metric label, log value, control-API string), so
// one concept has exactly one name.

impl RequestOutcomeReason {
    /// The canonical stable slug for metrics labels, log values, and control-API
    /// strings.
    pub fn slug(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
            Self::AuthDenied => "auth_denied",
            Self::RateLimited => "rate_limited",
            Self::Overloaded => "overloaded",
            Self::ValidationRejected => "validation_rejected",
            Self::BackendTransportFailed => "backend_transport_failed",
            Self::BackendProtocolFailed => "backend_protocol_failed",
            Self::BackendTlsFailed => "backend_tls_failed",
            Self::BackendBridgeFailed => "backend_bridge_failed",
        }
    }

    /// Whether this outcome is a success terminal.
    pub fn is_success(self) -> bool {
        matches!(self, Self::Completed)
    }

    /// The coarse `outcome` metric-label bucket, matching the existing
    /// `route_outcome_label` values so migrating an emitter does not change the
    /// low-cardinality `outcome` series. Note the *canonical* per-reason detail
    /// lives in [`Self::slug`]; this is the legacy coarse bucket.
    pub fn coarse_outcome_label(self) -> &'static str {
        match self {
            Self::Completed => "success",
            Self::TimedOut => "timeout",
            Self::Overloaded => "overload_shed",
            Self::RateLimited => "rate_limited",
            // Phase 0 finding #2: auth-denied and validation currently collapse to
            // `failure`; the canonical `slug()` distinguishes them, a later phase
            // decides whether to widen the coarse label.
            Self::AuthDenied
            | Self::ValidationRejected
            | Self::Cancelled
            | Self::BackendTransportFailed
            | Self::BackendProtocolFailed
            | Self::BackendTlsFailed
            | Self::BackendBridgeFailed => "failure",
        }
    }
}

impl BackendHealthReason {
    pub fn slug(self) -> &'static str {
        match self {
            Self::ActiveProbeSuccess => "active_probe_success",
            Self::ActiveProbeFailure => "active_probe_failure",
            Self::PassiveSuccess => "passive_success",
            Self::PassiveFailure => "passive_failure",
            Self::DnsRefreshFailed => "dns_refresh_failed",
            Self::EmptyResolutionRetained => "empty_resolution_retained",
            Self::PoolPoisoned => "pool_poisoned",
        }
    }

    /// Whether this reason represents a health-affecting failure.
    pub fn is_failure(self) -> bool {
        matches!(
            self,
            Self::ActiveProbeFailure
                | Self::PassiveFailure
                | Self::DnsRefreshFailed
                | Self::PoolPoisoned
        )
    }
}

impl RetryDecisionReason {
    pub fn slug(self) -> &'static str {
        match self {
            Self::UpstreamTimeout => "upstream_timeout",
            Self::UpstreamTransportFailure => "upstream_transport_failure",
            Self::UpstreamProtocolFailure => "upstream_protocol_failure",
            Self::RetryBudgetDenied => "retry_budget_denied",
            Self::RetryPolicyDisabled => "retry_policy_disabled",
            Self::IdempotencyDenied => "idempotency_denied",
        }
    }

    /// Whether this reason authorized a retry (vs. denied one).
    pub fn is_retry(self) -> bool {
        matches!(
            self,
            Self::UpstreamTimeout | Self::UpstreamTransportFailure | Self::UpstreamProtocolFailure
        )
    }
}

impl HedgeDecisionReason {
    pub fn slug(self) -> &'static str {
        match self {
            Self::DelayElapsed => "delay_elapsed",
            Self::HedgingDisabled => "hedging_disabled",
            Self::PrimaryCompleted => "primary_completed",
            Self::RequestBodyNotReplayable => "request_body_not_replayable",
            Self::TunnelRequest => "tunnel_request",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::AlternateBackendUnavailable => "alternate_backend_unavailable",
            Self::HedgeBudgetDenied => "hedge_budget_denied",
        }
    }

    /// Whether this reason triggered a hedge (vs. denied one).
    pub fn is_triggered(self) -> bool {
        matches!(self, Self::DelayElapsed)
    }
}

impl AdmissionDecisionReason {
    pub fn slug(self) -> &'static str {
        match self {
            Self::AuthDenied => "auth_denied",
            Self::AuthUnavailable => "auth_unavailable",
            Self::RateLimited => "rate_limited",
            Self::Overloaded => "overloaded",
            Self::ValidationRejected => "validation_rejected",
            Self::PolicyRejected => "policy_rejected",
        }
    }
}

impl AdmissionOverloadCause {
    /// The canonical slug, matching the existing `OverloadShedReason` metric-label
    /// values (Phase 0 §1.6) so migrating the overload emitter is a no-op on the
    /// `reason=` label.
    pub fn slug(self) -> &'static str {
        match self {
            Self::Brownout => "brownout",
            Self::AdaptiveAdmission => "adaptive_admission",
            Self::RouteCap => "route_cap",
            Self::RouteGlobalCap => "route_global_cap",
            Self::GlobalInflight => "global_inflight",
            Self::UpstreamInflight => "upstream_inflight",
            Self::BackendInflight => "backend_inflight",
            Self::CircuitOpen => "circuit_open",
            Self::RequestBufferCap => "request_buffer_cap",
            Self::ResponsePrebufferCap => "response_prebuffer_cap",
            Self::ConnectionCap => "connection_cap",
        }
    }
}

impl QuotaPolicyDecision {
    pub fn slug(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::ShadowDenied => "shadow_denied",
            Self::FailedOpen => "failed_open",
            Self::FailedClosed => "failed_closed",
            Self::NotApplied => "not_applied",
        }
    }
}

impl QuotaPolicyReason {
    pub fn slug(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::NotApplied => "not_applied",
            Self::BurstQuotaExhausted => "burst_quota_exhausted",
            Self::SustainedQuotaExhausted => "sustained_quota_exhausted",
            Self::SelectorIdentityMissing => "selector_identity_missing",
            Self::SelectorIdentityInvalid => "selector_identity_invalid",
            Self::BackendTimeout => "backend_timeout",
            Self::BackendUnavailable => "backend_unavailable",
            Self::BackendError => "backend_error",
        }
    }
}

impl QuotaBackendHealthReason {
    pub fn slug(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Timeout => "timeout",
            Self::Unavailable => "unavailable",
            Self::Error => "error",
        }
    }
}

// ---------------------------------------------------------------------------
// Shared event-context carrier + metric label model
// ---------------------------------------------------------------------------

/// The one canonical set of dimensions for an operational event, used to give
/// structured logs of the same event class the same fields (Phase 0 findings
/// #9/#10: `route`/`upstream`/`route_upstream` and `request_id=unassigned` were
/// inconsistent across the forwarding and bootstrap planes).
///
/// The canonical field name for the upstream-name concept is **`upstream`**.
#[derive(Debug, Clone, Copy, Default)]
pub struct OperationalEventContext<'a> {
    pub request_id: Option<impulse_contracts::RequestId>,
    pub route: Option<&'a str>,
    pub upstream: Option<&'a str>,
    pub backend: Option<&'a str>,
    pub decision_reason: Option<&'a str>,
    pub failure_class: Option<&'a str>,
}

impl<'a> OperationalEventContext<'a> {
    /// Start an empty context; fill fields with the builder methods.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_request_id(mut self, request_id: impulse_contracts::RequestId) -> Self {
        self.request_id = Some(request_id);
        self
    }

    pub fn with_upstream(mut self, upstream: &'a str) -> Self {
        self.upstream = Some(upstream);
        self
    }

    pub fn with_backend(mut self, backend: &'a str) -> Self {
        self.backend = Some(backend);
        self
    }

    pub fn with_reason(mut self, reason: &'a str) -> Self {
        self.decision_reason = Some(reason);
        self
    }
}

impl fmt::Display for OperationalEventContext<'_> {
    /// Render the canonical `key=value` field set, in a stable order, skipping
    /// unset fields. This is the single log-field format for an operational event.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut field = |f: &mut fmt::Formatter<'_>, key: &str, value: &str| -> fmt::Result {
            if !first {
                f.write_str(" ")?;
            }
            first = false;
            write!(f, "{key}={value}")
        };
        if let Some(request_id) = self.request_id {
            field(f, "request_id", &request_id.to_string())?;
        }
        if let Some(route) = self.route {
            field(f, "route", route)?;
        }
        if let Some(upstream) = self.upstream {
            field(f, "upstream", upstream)?;
        }
        if let Some(backend) = self.backend {
            field(f, "backend", backend)?;
        }
        if let Some(reason) = self.decision_reason {
            field(f, "reason", reason)?;
        }
        if let Some(failure_class) = self.failure_class {
            field(f, "failure_class", failure_class)?;
        }
        Ok(())
    }
}

/// The one canonical metric reason-label model. Emitters that record a reasoned
/// outcome populate this rather than assembling ad hoc label sets, so the label
/// keys (`outcome`, `reason`, `failure_class`) are the same everywhere.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetricReasonLabels<'a> {
    pub outcome: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub failure_class: Option<&'a str>,
}

// ---------------------------------------------------------------------------
// Canonical mappings from local reason vocabularies (obs Phase 5)
// ---------------------------------------------------------------------------
//
// Phase 5 classifies every local reason enum against the canonical vocabulary so
// one operational concept is described one way. Each local enum is either:
//   - an ALIAS of a canonical concept → `From<Local> for Canonical`, or
//   - a RICHER SUBTYPE → mapped to the coarse canonical reason (the extra detail
//     stays available as the local enum for debug/telemetry).
// The QUIC-datapath terminal enums (edge-local) and the retry/hedge enums
// (impulse_errors) are mapped here; `OverloadShedReason::canonical()` lives with
// that enum. These impls are the single source that keeps the surfaces aligned.

use impulse_errors::{HedgePolicyDenialReason, RetryPolicyDenialReason, UpstreamRetryReason};

use crate::runtime::connection::stream::{BackendFailureReason, RejectionReason, TimeoutReason};

/// Request rejection → canonical request outcome. Alias mapping.
impl From<RejectionReason> for RequestOutcomeReason {
    fn from(reason: RejectionReason) -> Self {
        match reason {
            RejectionReason::AuthDenied => Self::AuthDenied,
            // AuthUnavailable is a richer subtype of "auth-related rejection";
            // it maps to the canonical AuthDenied outcome (the request was not
            // admitted), with the finer cause preserved by the local enum.
            RejectionReason::AuthUnavailable => Self::AuthDenied,
            RejectionReason::ValidationFailed
            | RejectionReason::RequestBodyNotAllowed
            | RejectionReason::RequestBodyTooLarge => Self::ValidationRejected,
            RejectionReason::RateLimited | RejectionReason::QuotaDenied => Self::RateLimited,
            RejectionReason::Overloaded | RejectionReason::ResponsePrebufferCap => Self::Overloaded,
        }
    }
}

/// Backend failure → canonical request outcome. Richer subtype: the transport
/// class is mapped to the matching canonical backend-failure outcome.
impl From<BackendFailureReason> for RequestOutcomeReason {
    fn from(reason: BackendFailureReason) -> Self {
        match reason {
            BackendFailureReason::UpstreamTimeout => Self::TimedOut,
            BackendFailureReason::UpstreamTls => Self::BackendTlsFailed,
            BackendFailureReason::UpstreamProtocol => Self::BackendProtocolFailed,
            BackendFailureReason::UpstreamBridge => Self::BackendBridgeFailed,
            BackendFailureReason::UpstreamTransport
            | BackendFailureReason::DispatchSpawnFailed
            | BackendFailureReason::UpstreamResultChannelDropped
            | BackendFailureReason::ResponseWriteFailed
            | BackendFailureReason::ResponseStreamAborted => Self::BackendTransportFailed,
        }
    }
}

/// Timeout phase → canonical request outcome. All phases are the one canonical
/// `TimedOut` outcome; the phase remains the richer local detail.
impl From<TimeoutReason> for RequestOutcomeReason {
    fn from(_reason: TimeoutReason) -> Self {
        Self::TimedOut
    }
}

/// Retry attempt cause → canonical retry decision reason. Alias mapping.
impl From<UpstreamRetryReason> for RetryDecisionReason {
    fn from(reason: UpstreamRetryReason) -> Self {
        match reason {
            UpstreamRetryReason::Timeout => Self::UpstreamTimeout,
            UpstreamRetryReason::Transport => Self::UpstreamTransportFailure,
            UpstreamRetryReason::Pool => Self::UpstreamTransportFailure,
        }
    }
}

/// Retry denial → canonical retry decision reason. Richer subtype: the several
/// idempotency/terminal causes collapse to the coarse canonical denials.
impl From<RetryPolicyDenialReason> for RetryDecisionReason {
    fn from(reason: RetryPolicyDenialReason) -> Self {
        match reason {
            RetryPolicyDenialReason::BudgetDenied => Self::RetryBudgetDenied,
            RetryPolicyDenialReason::MethodNotIdempotent
            | RetryPolicyDenialReason::RequestBodyNotReplayable => Self::IdempotencyDenied,
            RetryPolicyDenialReason::TerminalError(_)
            | RetryPolicyDenialReason::AttemptLimitReached
            | RetryPolicyDenialReason::AlternateBackendUnavailable(_) => Self::RetryPolicyDisabled,
        }
    }
}

/// Backend health observation (source + outcome) → canonical backend health
/// reason (obs Phase 8). This is the health axis: active vs passive probe,
/// success vs failure. `Neutral` observations are not a health *reason* (they
/// neither confirm nor fault the backend), so they return `None`.
pub fn backend_health_reason(
    source: crate::runtime::backend::event::BackendHealthObservationSource,
    outcome: crate::runtime::backend::event::BackendHealthObservationOutcome,
) -> Option<BackendHealthReason> {
    use crate::runtime::backend::event::{
        BackendHealthObservationOutcome as O, BackendHealthObservationSource as S,
    };
    match (source, outcome) {
        (S::ActiveCheck, O::Success) => Some(BackendHealthReason::ActiveProbeSuccess),
        (S::ActiveCheck, O::Failure) => Some(BackendHealthReason::ActiveProbeFailure),
        (S::PassiveRequest, O::Success) => Some(BackendHealthReason::PassiveSuccess),
        (S::PassiveRequest, O::Failure) => Some(BackendHealthReason::PassiveFailure),
        (_, O::Neutral) => None,
    }
}

/// Admission outcome class → canonical admission decision reason (obs Phase 7).
/// The single vocabulary both forwarding and bootstrap resolve admission denials
/// through. `Failed { timed_out }` is a richer subtype: a timeout maps to the
/// generic policy rejection here (the timeout axis is carried elsewhere).
impl From<crate::runtime::connection::outcome::AdmissionOutcomeClass> for AdmissionDecisionReason {
    fn from(outcome: crate::runtime::connection::outcome::AdmissionOutcomeClass) -> Self {
        use crate::runtime::connection::outcome::AdmissionOutcomeClass as A;
        match outcome {
            A::AuthDenied => Self::AuthDenied,
            A::RateLimited | A::QuotaDenied => Self::RateLimited,
            A::OverloadShed { .. } => Self::Overloaded,
            A::Failed { .. } => Self::PolicyRejected,
        }
    }
}

/// Hedge denial → canonical hedge decision reason. Alias / richer subtype.
impl From<HedgePolicyDenialReason> for HedgeDecisionReason {
    fn from(reason: HedgePolicyDenialReason) -> Self {
        match reason {
            HedgePolicyDenialReason::HedgingDisabled => Self::HedgingDisabled,
            HedgePolicyDenialReason::PrimaryRequestCompleted => Self::PrimaryCompleted,
            HedgePolicyDenialReason::RequestBodyNotReplayable => Self::RequestBodyNotReplayable,
            HedgePolicyDenialReason::TunnelRequest => Self::TunnelRequest,
            HedgePolicyDenialReason::MethodNotAllowed => Self::MethodNotAllowed,
            HedgePolicyDenialReason::AlternateBackendUnavailable(_) => {
                Self::AlternateBackendUnavailable
            }
            HedgePolicyDenialReason::BudgetDenied => Self::HedgeBudgetDenied,
        }
    }
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
            use crate::runtime::connection::stream::RejectionReason;
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
            use crate::runtime::connection::stream::BackendFailureReason;
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
            use crate::runtime::backend::event::{
                BackendHealthObservationOutcome as O, BackendHealthObservationSource as S,
            };
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
            use crate::{
                metrics::OverloadShedReason, runtime::connection::outcome::AdmissionOutcomeClass,
            };
            assert_eq!(
                AdmissionDecisionReason::from(AdmissionOutcomeClass::AuthDenied),
                AdmissionDecisionReason::AuthDenied
            );
            assert_eq!(
                AdmissionDecisionReason::from(AdmissionOutcomeClass::RateLimited),
                AdmissionDecisionReason::RateLimited
            );
            assert_eq!(
                AdmissionDecisionReason::from(AdmissionOutcomeClass::QuotaDenied),
                AdmissionDecisionReason::RateLimited
            );
            assert_eq!(
                AdmissionDecisionReason::from(AdmissionOutcomeClass::OverloadShed {
                    reason: Some(OverloadShedReason::GlobalInflight)
                }),
                AdmissionDecisionReason::Overloaded
            );
            assert_eq!(
                AdmissionDecisionReason::from(AdmissionOutcomeClass::Failed { timed_out: true }),
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
            use crate::{
                metrics::OverloadShedReason,
                runtime::connection::{
                    outcome::AdmissionOutcomeClass, stream::BackendFailureReason,
                },
            };

            assert_reason_surface_alignment(RequestOutcomeReason::TimedOut.slug());
            assert_reason_surface_alignment(
                RequestOutcomeReason::from(BackendFailureReason::UpstreamTransport).slug(),
            );
            assert_reason_surface_alignment(
                RequestOutcomeReason::from(BackendFailureReason::UpstreamTls).slug(),
            );
            assert_reason_surface_alignment(
                AdmissionDecisionReason::from(AdmissionOutcomeClass::AuthDenied).slug(),
            );
            assert_reason_surface_alignment(
                AdmissionDecisionReason::from(AdmissionOutcomeClass::RateLimited).slug(),
            );
            assert_reason_surface_alignment(
                AdmissionDecisionReason::from(AdmissionOutcomeClass::QuotaDenied).slug(),
            );
            assert_reason_surface_alignment(
                AdmissionDecisionReason::from(AdmissionOutcomeClass::OverloadShed {
                    reason: Some(OverloadShedReason::GlobalInflight),
                })
                .slug(),
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
            use impulse_errors::{
                HedgePolicyDenialReason, RetryPolicyDenialReason, UpstreamRetryReason,
            };
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
            use impulse_errors::{
                RetryPolicyDenialReason, UpstreamRetryReason, UpstreamTerminalErrorKind,
            };

            use crate::runtime::connection::stream::BackendFailureReason;

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
