#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthFailureReason {
    HttpStatus5xx,
    Timeout,
    Transport,
    Tls,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlternateBackendFailureReason {
    NoHealthyBackends,
    OnlyExcludedBackendsHealthy,
    PoolUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamRetryReason {
    Timeout,
    Transport,
    Pool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamTerminalErrorKind {
    Tls,
    Protocol,
    Bridge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryPolicyDenialReason {
    TerminalError(UpstreamTerminalErrorKind),
    MethodNotIdempotent,
    RequestBodyNotReplayable,
    AttemptLimitReached,
    BudgetDenied,
    AlternateBackendUnavailable(AlternateBackendFailureReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryAttemptTelemetryReason {
    Timeout,
    Transport,
    Pool,
}

impl From<UpstreamRetryReason> for RetryAttemptTelemetryReason {
    fn from(value: UpstreamRetryReason) -> Self {
        match value {
            UpstreamRetryReason::Timeout => Self::Timeout,
            UpstreamRetryReason::Transport => Self::Transport,
            UpstreamRetryReason::Pool => Self::Pool,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HedgePolicyDenialReason {
    HedgingDisabled,
    PrimaryRequestCompleted,
    RequestBodyNotReplayable,
    TunnelRequest,
    MethodNotAllowed,
    AlternateBackendUnavailable(AlternateBackendFailureReason),
    BudgetDenied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HedgeTriggerTelemetryReason {
    DelayElapsed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HedgeOutcomeTelemetryReason {
    PrimaryWonAfterTrigger,
    HedgeWon,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationReason {
    ClientReset,
    ConnectionClosed,
    OperatorAbort,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeoutReason {
    RequestBodyIdle,
    RequestBodyTotal,
    ExternalAuth,
    TotalRequest,
    AwaitingUpstream,
    ResponseBodyIdle,
    ResponseBodyTotal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectionReason {
    AuthDenied,
    AuthUnavailable,
    ValidationFailed,
    RateLimited,
    QuotaDenied,
    Overloaded,
    RequestBodyNotAllowed,
    RequestBodyTooLarge,
    ResponsePrebufferCap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendFailureReason {
    DispatchSpawnFailed,
    UpstreamResultChannelDropped,
    UpstreamTimeout,
    UpstreamTransport,
    UpstreamProtocol,
    UpstreamTls,
    UpstreamBridge,
    ResponseWriteFailed,
    ResponseStreamAborted,
}
