#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RequestOutcomeReason {
    Completed,
    Cancelled,
    TimedOut,
    AuthDenied,
    RateLimited,
    Overloaded,
    ValidationRejected,
    BackendTransportFailed,
    BackendProtocolFailed,
    BackendTlsFailed,
    BackendBridgeFailed,
}

impl RequestOutcomeReason {
    #[must_use]
    pub const fn slug(self) -> &'static str {
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

    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Completed)
    }

    #[must_use]
    pub const fn coarse_outcome_label(self) -> &'static str {
        match self {
            Self::Completed => "success",
            Self::TimedOut => "timeout",
            Self::Overloaded => "overload_shed",
            Self::RateLimited => "rate_limited",
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BackendHealthReason {
    ActiveProbeSuccess,
    ActiveProbeFailure,
    PassiveSuccess,
    PassiveFailure,
    DnsRefreshFailed,
    EmptyResolutionRetained,
    PoolPoisoned,
}

impl BackendHealthReason {
    #[must_use]
    pub const fn slug(self) -> &'static str {
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

    #[must_use]
    pub const fn is_failure(self) -> bool {
        matches!(
            self,
            Self::ActiveProbeFailure
                | Self::PassiveFailure
                | Self::DnsRefreshFailed
                | Self::PoolPoisoned
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RetryDecisionReason {
    UpstreamTimeout,
    UpstreamTransportFailure,
    UpstreamProtocolFailure,
    RetryBudgetDenied,
    RetryPolicyDisabled,
    IdempotencyDenied,
}

impl RetryDecisionReason {
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::UpstreamTimeout => "upstream_timeout",
            Self::UpstreamTransportFailure => "upstream_transport_failure",
            Self::UpstreamProtocolFailure => "upstream_protocol_failure",
            Self::RetryBudgetDenied => "retry_budget_denied",
            Self::RetryPolicyDisabled => "retry_policy_disabled",
            Self::IdempotencyDenied => "idempotency_denied",
        }
    }

    #[must_use]
    pub const fn is_retry(self) -> bool {
        matches!(
            self,
            Self::UpstreamTimeout | Self::UpstreamTransportFailure | Self::UpstreamProtocolFailure
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HedgeDecisionReason {
    DelayElapsed,
    HedgingDisabled,
    PrimaryCompleted,
    RequestBodyNotReplayable,
    TunnelRequest,
    MethodNotAllowed,
    AlternateBackendUnavailable,
    HedgeBudgetDenied,
}

impl HedgeDecisionReason {
    #[must_use]
    pub const fn slug(self) -> &'static str {
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

    #[must_use]
    pub const fn is_triggered(self) -> bool {
        matches!(self, Self::DelayElapsed)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AdmissionDecisionReason {
    AuthDenied,
    AuthUnavailable,
    RateLimited,
    Overloaded,
    ValidationRejected,
    PolicyRejected,
}

impl AdmissionDecisionReason {
    #[must_use]
    pub const fn slug(self) -> &'static str {
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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

impl AdmissionOverloadCause {
    #[must_use]
    pub const fn slug(self) -> &'static str {
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum QuotaPolicyDecision {
    Allowed,
    Denied,
    ShadowDenied,
    FailedOpen,
    FailedClosed,
    NotApplied,
}

impl QuotaPolicyDecision {
    #[must_use]
    pub const fn slug(self) -> &'static str {
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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

impl QuotaPolicyReason {
    #[must_use]
    pub const fn slug(self) -> &'static str {
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum QuotaBackendHealthReason {
    Available,
    Timeout,
    Unavailable,
    Error,
}

impl QuotaBackendHealthReason {
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Timeout => "timeout",
            Self::Unavailable => "unavailable",
            Self::Error => "error",
        }
    }
}
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeRejectionReason {
    InvalidConfig,
    StartupOwnedChange,
    BindConflict,
    ResourcePrepareFailed,
    IncompatibleReload,
    UnknownGeneration,
    RollbackNotAllowed,
}

impl RuntimeRejectionReason {
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::InvalidConfig => "invalid_config",
            Self::StartupOwnedChange => "startup_owned_change",
            Self::BindConflict => "bind_conflict",
            Self::ResourcePrepareFailed => "resource_prepare_failed",
            Self::IncompatibleReload => "incompatible_reload",
            Self::UnknownGeneration => "unknown_generation",
            Self::RollbackNotAllowed => "rollback_not_allowed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeOperationOutcomeReason {
    Applied,
    InvalidConfig,
    StartupOwnedChange,
    BindConflict,
    ResourcePrepareFailed,
    IncompatibleReload,
    UnknownGeneration,
    RollbackNotAllowed,
}

impl RuntimeOperationOutcomeReason {
    pub const COUNT: usize = 8;
    pub const ALL: [Self; Self::COUNT] = [
        Self::Applied,
        Self::InvalidConfig,
        Self::StartupOwnedChange,
        Self::BindConflict,
        Self::ResourcePrepareFailed,
        Self::IncompatibleReload,
        Self::UnknownGeneration,
        Self::RollbackNotAllowed,
    ];

    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Applied => 0,
            Self::InvalidConfig => 1,
            Self::StartupOwnedChange => 2,
            Self::BindConflict => 3,
            Self::ResourcePrepareFailed => 4,
            Self::IncompatibleReload => 5,
            Self::UnknownGeneration => 6,
            Self::RollbackNotAllowed => 7,
        }
    }

    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::InvalidConfig => "invalid_config",
            Self::StartupOwnedChange => "startup_owned_change",
            Self::BindConflict => "bind_conflict",
            Self::ResourcePrepareFailed => "resource_prepare_failed",
            Self::IncompatibleReload => "incompatible_reload",
            Self::UnknownGeneration => "unknown_generation",
            Self::RollbackNotAllowed => "rollback_not_allowed",
        }
    }

    #[must_use]
    pub const fn result_label(self) -> &'static str {
        match self {
            Self::Applied => "success",
            Self::InvalidConfig
            | Self::StartupOwnedChange
            | Self::BindConflict
            | Self::ResourcePrepareFailed
            | Self::IncompatibleReload
            | Self::UnknownGeneration
            | Self::RollbackNotAllowed => "failure",
        }
    }

    #[must_use]
    pub const fn from_rejection_reason(reason: RuntimeRejectionReason) -> Self {
        match reason {
            RuntimeRejectionReason::InvalidConfig => Self::InvalidConfig,
            RuntimeRejectionReason::StartupOwnedChange => Self::StartupOwnedChange,
            RuntimeRejectionReason::BindConflict => Self::BindConflict,
            RuntimeRejectionReason::ResourcePrepareFailed => Self::ResourcePrepareFailed,
            RuntimeRejectionReason::IncompatibleReload => Self::IncompatibleReload,
            RuntimeRejectionReason::UnknownGeneration => Self::UnknownGeneration,
            RuntimeRejectionReason::RollbackNotAllowed => Self::RollbackNotAllowed,
        }
    }
}
