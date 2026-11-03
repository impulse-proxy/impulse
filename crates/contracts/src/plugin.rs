#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PluginKind {
    ConnectionRateLimit,
    ApiKeyAuth,
    JwtAuth,
    ExternalAuth,
    ScopedRateLimit,
    Quota,
    ResponseCache,
    ResponseCompression,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PluginPhase {
    ConnectionAdmission,
    RequestGate,
    AsyncRequestGate,
    CacheLookup,
    CacheFill,
    ResponsePolicy,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PluginScope {
    Runtime,
    Listener,
    Upstream,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PluginExecutionOutcome {
    Continue,
    Reject,
    Bypass,
    Fail,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PluginRejectionReason {
    ApiKeyMissing,
    ApiKeyInvalid,
    JwtMissing,
    JwtInvalid,
    JwtClaimsRejected,
    JwksUnavailable,
    ExternalAuthDenied,
    ExternalAuthUnavailable,
    RateLimited,
    QuotaDenied,
    QuotaUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PluginStateOwnership {
    Startup,
    Generation,
    SharedService,
    Request,
}
