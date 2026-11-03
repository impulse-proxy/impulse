use std::time::Duration;

#[derive(Clone, Eq, PartialEq)]
pub struct PluginConstructionInputs {
    pub connection_rate_limit: ConnectionRateLimitInput,
    pub scoped_rate_limits: Box<[ScopedRateLimitInput]>,
    pub quota: Option<QuotaInput>,
    pub upstreams: Box<[UpstreamPluginInputs]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionRateLimitInput {
    pub requests_per_second: u32,
    pub burst: u32,
}

#[derive(Clone, Eq, PartialEq)]
pub struct UpstreamPluginInputs {
    pub upstream_name: String,
    pub api_key_auth: Option<ApiKeyAuthInput>,
    pub jwt_auth: Option<JwtAuthInput>,
    pub external_auth: Option<ExternalAuthInput>,
    pub response_cache: Option<ResponseCacheInput>,
    pub response_compression: Option<ResponseCompressionInput>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ApiKeyAuthInput {
    pub header_name: String,
    pub accepted_keys: Box<[String]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JwtAlgorithmInput {
    Hs256,
    Rs256,
    Es256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JwtVerificationKeyInput {
    Pem {
        kid: Option<String>,
        algorithm: Option<JwtAlgorithmInput>,
        public_key_pem: String,
    },
    Jwk {
        kid: Option<String>,
        algorithm: Option<JwtAlgorithmInput>,
        jwk: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JwksStartupBehaviorInput {
    RequireReady,
    AllowDegraded,
}

#[derive(Clone, Eq, PartialEq)]
pub struct JwtAuthInput {
    pub secret: String,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub issuers: Box<[String]>,
    pub audiences: Box<[String]>,
    pub allowed_algorithms: Box<[JwtAlgorithmInput]>,
    pub require_kid: bool,
    pub static_keys: Box<[JwtVerificationKeyInput]>,
    pub jwks_url: Option<String>,
    pub jwks_refresh_interval: Duration,
    pub jwks_request_timeout: Duration,
    pub jwks_cache_ttl: Duration,
    pub jwks_stale_if_error: Duration,
    pub jwks_startup_behavior: JwksStartupBehaviorInput,
    pub clock_skew: Duration,
    pub required_scopes: Box<[String]>,
    pub required_roles: Box<[String]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalAuthFailureModeInput {
    FailOpen,
    FailClosed,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ExternalAuthRequestHeaderInput {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Eq, PartialEq)]
pub enum ExternalAuthInput {
    Http {
        endpoint: String,
        request_headers: Box<[ExternalAuthRequestHeaderInput]>,
        response_header_allowlist: Box<[String]>,
        timeout: Duration,
        failure_mode: ExternalAuthFailureModeInput,
    },
    Oidc {
        discovery_url: Option<String>,
        issuer_url: Option<String>,
        client_id: String,
        client_secret: Option<String>,
        audience: Option<String>,
        scopes: Box<[String]>,
        request_headers: Box<[ExternalAuthRequestHeaderInput]>,
        response_header_allowlist: Box<[String]>,
        timeout: Duration,
        failure_mode: ExternalAuthFailureModeInput,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopedRateLimitScopeInput {
    Route,
    Tenant,
    Client,
    Token,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopedRateLimitInput {
    pub name: String,
    pub scope: ScopedRateLimitScopeInput,
    pub requests_per_second: u32,
    pub burst: u32,
    pub key: Option<String>,
    pub route_allowlist: Box<[String]>,
    pub idle_ttl: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestKeyInput {
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaEnforcementInput {
    Shadow,
    Enforce,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaBackendFailureInput {
    FailOpen,
    FailClosed,
}

#[derive(Clone, Eq, PartialEq)]
pub enum QuotaCounterBackendInput {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotaLocalFallbackInput {
    pub key_prefix: String,
    pub max_entries: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotaSelectorInput {
    pub route: bool,
    pub tenant: Option<RequestKeyInput>,
    pub token: Option<RequestKeyInput>,
    pub client: Option<RequestKeyInput>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotaWindowInput {
    pub requests: u64,
    pub window: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotaPolicyInput {
    pub name: String,
    pub route_allowlist: Box<[String]>,
    pub selector: QuotaSelectorInput,
    pub burst: Option<QuotaWindowInput>,
    pub sustained: Option<QuotaWindowInput>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct QuotaInput {
    pub enforcement: QuotaEnforcementInput,
    pub backend_failure_policy: QuotaBackendFailureInput,
    pub backend: QuotaCounterBackendInput,
    pub local_fallback: Option<QuotaLocalFallbackInput>,
    pub policies: Box<[QuotaPolicyInput]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseCacheInput {
    pub max_bytes: usize,
    pub max_entries: usize,
    pub max_object_bytes: usize,
    pub max_ttl_seconds: u64,
    pub authenticated_route: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseCompressionInput {
    pub minimum_size_bytes: usize,
}
