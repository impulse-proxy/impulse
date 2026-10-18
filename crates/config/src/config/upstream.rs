use std::fmt;

use super::*;

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    #[serde(default)]
    pub load_balancing: LoadBalancing,
    #[serde(default)]
    pub auth: RouteAuth,
    #[serde(default)]
    pub host_policy: UpstreamHostPolicy,
    #[serde(default)]
    pub forwarded_headers: ForwardedHeaderPolicy,
    #[serde(default)]
    pub compression: ResponseCompression,
    #[serde(default)]
    pub tls: Option<UpstreamTls>,
    pub route: RouteMatch,
    pub backends: Vec<Backend>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct ResponseCompression {
    pub enabled: bool,
    pub minimum_size_bytes: usize,
}

impl Default for ResponseCompression {
    fn default() -> Self {
        Self {
            enabled: false,
            minimum_size_bytes: 1_024,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct RouteAuth {
    pub api_key: Option<ApiKeyAuth>,
    pub jwt: Option<JwtAuth>,
    pub external_auth: Option<ExternalAuth>,
    pub required_scopes: Vec<String>,
    pub required_roles: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExternalAuthFailureMode {
    FailOpen,
    #[default]
    FailClosed,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExternalAuth {
    Http {
        endpoint: String,
        // Deliberately omitted from every serialized config view, not only logs:
        // injected header values may contain credentials. Deserialization still
        // accepts this field from operator-supplied configuration.
        #[serde(default, skip_serializing)]
        request_headers: Vec<ExternalAuthRequestHeader>,
        #[serde(default)]
        response_header_allowlist: Vec<String>,
        #[serde(default = "ExternalAuth::default_timeout_ms")]
        timeout_ms: u64,
        #[serde(default = "ExternalAuthFailureMode::default")]
        failure_mode: ExternalAuthFailureMode,
    },
    Oidc {
        #[serde(default)]
        discovery_url: Option<String>,
        #[serde(default)]
        issuer_url: Option<String>,
        client_id: String,
        // Deliberately omitted from every serialized config view, not only logs.
        // Deserialization remains supported for operator-supplied configuration.
        #[serde(default, skip_serializing)]
        client_secret: Option<String>,
        #[serde(default)]
        client_secret_ref: Option<SecretRef>,
        #[serde(default)]
        audience: Option<String>,
        #[serde(default)]
        scopes: Vec<String>,
        // See the HTTP variant: header values are treated as credentials and
        // therefore never emitted by generic config serialization.
        #[serde(default, skip_serializing)]
        request_headers: Vec<ExternalAuthRequestHeader>,
        #[serde(default)]
        response_header_allowlist: Vec<String>,
        #[serde(default = "ExternalAuth::default_timeout_ms")]
        timeout_ms: u64,
        #[serde(default = "ExternalAuthFailureMode::default")]
        failure_mode: ExternalAuthFailureMode,
    },
}

impl ExternalAuth {
    pub(crate) fn default_timeout_ms() -> u64 {
        1_000
    }
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ExternalAuthRequestHeader {
    pub name: String,
    pub value: String,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct ApiKeyAuth {
    pub header_name: String,
    // This affects every serialization consumer, not only Debug/log output.
    // Keys are accepted while deserializing but never exported in config views.
    #[serde(skip_serializing)]
    pub keys: Vec<String>,
}

impl Default for ApiKeyAuth {
    fn default() -> Self {
        Self {
            header_name: "x-api-key".to_string(),
            keys: Vec::new(),
        }
    }
}

impl fmt::Debug for ExternalAuthRequestHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Keep this pattern exhaustive: adding a field must trigger a compile
        // error until its redaction behavior is reviewed.
        let Self { name, value: _ } = self;
        f.debug_struct("ExternalAuthRequestHeader")
            .field("name", name)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for ApiKeyAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Keep this pattern exhaustive: adding a field must trigger a compile
        // error until its redaction behavior is reviewed.
        let Self {
            header_name,
            keys: _,
        } = self;
        f.debug_struct("ApiKeyAuth")
            .field("header_name", header_name)
            .field("keys", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct JwtAuth {
    // Deliberately omitted from every serialized config view, not only logs.
    // Deserialization remains supported for operator-supplied configuration.
    #[serde(skip_serializing)]
    pub secret: String,
    pub secret_ref: Option<SecretRef>,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub issuers: Option<Vec<String>>,
    pub audiences: Option<Vec<String>>,
    #[serde(default = "JwtAuth::default_allowed_algorithms")]
    pub allowed_algorithms: Vec<JwtAlgorithm>,
    pub require_kid: bool,
    pub static_keys: Vec<JwtVerificationKey>,
    pub jwks_url: Option<String>,
    #[serde(default = "JwtAuth::default_jwks_refresh_interval_secs")]
    pub jwks_refresh_interval_secs: u64,
    #[serde(default = "JwtAuth::default_jwks_request_timeout_ms")]
    pub jwks_request_timeout_ms: u64,
    #[serde(default = "JwtAuth::default_jwks_cache_ttl_secs")]
    pub jwks_cache_ttl_secs: u64,
    #[serde(default = "JwtAuth::default_jwks_stale_if_error_secs")]
    pub jwks_stale_if_error_secs: u64,
    #[serde(default = "JwksStartupBehavior::default")]
    pub jwks_startup_behavior: JwksStartupBehavior,
    pub clock_skew_secs: u64,
}

impl fmt::Debug for ExternalAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Keep every variant pattern exhaustive (no `..`): adding an auth field
        // must fail compilation until its Debug/redaction behavior is reviewed.
        match self {
            Self::Http {
                endpoint,
                request_headers,
                response_header_allowlist,
                timeout_ms,
                failure_mode,
            } => f
                .debug_struct("ExternalAuth::Http")
                .field("endpoint", endpoint)
                .field("request_headers", request_headers)
                .field("response_header_allowlist", response_header_allowlist)
                .field("timeout_ms", timeout_ms)
                .field("failure_mode", failure_mode)
                .finish(),
            Self::Oidc {
                discovery_url,
                issuer_url,
                client_id,
                client_secret,
                client_secret_ref,
                audience,
                scopes,
                request_headers,
                response_header_allowlist,
                timeout_ms,
                failure_mode,
            } => f
                .debug_struct("ExternalAuth::Oidc")
                .field("discovery_url", discovery_url)
                .field("issuer_url", issuer_url)
                .field("client_id", client_id)
                .field(
                    "client_secret",
                    &client_secret.as_ref().map(|_| "<redacted>"),
                )
                .field(
                    "client_secret_ref",
                    &client_secret_ref.as_ref().map(|_| "<configured>"),
                )
                .field("audience", audience)
                .field("scopes", scopes)
                .field("request_headers", request_headers)
                .field("response_header_allowlist", response_header_allowlist)
                .field("timeout_ms", timeout_ms)
                .field("failure_mode", failure_mode)
                .finish(),
        }
    }
}

impl fmt::Debug for JwtAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Keep this pattern exhaustive: adding a field must trigger a compile
        // error until its Debug/redaction behavior is reviewed.
        let Self {
            secret: _,
            secret_ref,
            issuer,
            audience,
            issuers,
            audiences,
            allowed_algorithms,
            require_kid,
            static_keys,
            jwks_url,
            jwks_refresh_interval_secs,
            jwks_request_timeout_ms,
            jwks_cache_ttl_secs,
            jwks_stale_if_error_secs,
            jwks_startup_behavior,
            clock_skew_secs,
        } = self;
        f.debug_struct("JwtAuth")
            .field("secret", &"<redacted>")
            .field("secret_ref", &secret_ref.as_ref().map(|_| "<configured>"))
            .field("issuer", issuer)
            .field("audience", audience)
            .field("issuers", issuers)
            .field("audiences", audiences)
            .field("allowed_algorithms", allowed_algorithms)
            .field("require_kid", require_kid)
            .field("static_keys", static_keys)
            .field("jwks_url", jwks_url)
            .field("jwks_refresh_interval_secs", jwks_refresh_interval_secs)
            .field("jwks_request_timeout_ms", jwks_request_timeout_ms)
            .field("jwks_cache_ttl_secs", jwks_cache_ttl_secs)
            .field("jwks_stale_if_error_secs", jwks_stale_if_error_secs)
            .field("jwks_startup_behavior", jwks_startup_behavior)
            .field("clock_skew_secs", clock_skew_secs)
            .finish()
    }
}

impl Default for JwtAuth {
    fn default() -> Self {
        Self {
            secret: String::new(),
            secret_ref: None,
            issuer: None,
            audience: None,
            issuers: None,
            audiences: None,
            allowed_algorithms: Self::default_allowed_algorithms(),
            require_kid: false,
            static_keys: Vec::new(),
            jwks_url: None,
            jwks_refresh_interval_secs: Self::default_jwks_refresh_interval_secs(),
            jwks_request_timeout_ms: Self::default_jwks_request_timeout_ms(),
            jwks_cache_ttl_secs: Self::default_jwks_cache_ttl_secs(),
            jwks_stale_if_error_secs: Self::default_jwks_stale_if_error_secs(),
            jwks_startup_behavior: JwksStartupBehavior::default(),
            clock_skew_secs: 30,
        }
    }
}

impl JwtAuth {
    fn default_allowed_algorithms() -> Vec<JwtAlgorithm> {
        vec![JwtAlgorithm::Hs256]
    }

    const fn default_jwks_refresh_interval_secs() -> u64 {
        300
    }

    const fn default_jwks_request_timeout_ms() -> u64 {
        2_000
    }

    const fn default_jwks_cache_ttl_secs() -> u64 {
        900
    }

    const fn default_jwks_stale_if_error_secs() -> u64 {
        3_600
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JwtAlgorithm {
    #[serde(rename = "HS256", alias = "hs256")]
    Hs256,
    #[serde(rename = "RS256", alias = "rs256")]
    Rs256,
    #[serde(rename = "ES256", alias = "es256")]
    Es256,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JwksStartupBehavior {
    #[default]
    RequireReady,
    AllowDegraded,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum JwtVerificationKey {
    Pem {
        #[serde(default)]
        kid: Option<String>,
        #[serde(default)]
        alg: Option<JwtAlgorithm>,
        public_key_pem: String,
    },
    Jwk {
        #[serde(default)]
        kid: Option<String>,
        #[serde(default)]
        alg: Option<JwtAlgorithm>,
        jwk: String,
    },
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamHostPolicyMode {
    #[default]
    #[serde(alias = "pass-through")]
    PassThrough,
    Rewrite,
    #[serde(
        alias = "static_upstream",
        alias = "static-upstream",
        alias = "upstream-host"
    )]
    Upstream,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ForwardedHeaderPolicyMode {
    #[default]
    #[serde(alias = "overwrite")]
    Overwrite,
    Append,
    Preserve,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq, Eq)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct ForwardedHeaderPolicy {
    pub mode: ForwardedHeaderPolicyMode,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq, Eq)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct UpstreamHostPolicy {
    pub mode: UpstreamHostPolicyMode,
    pub host: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Backend {
    pub id: String,
    pub address: String,
    #[serde(default = "Backend::default_weight")]
    pub weight: u32,
    #[serde(default)]
    pub health_check: Option<HealthCheck>,
}

impl Backend {
    pub(crate) fn default_weight() -> u32 {
        100
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct RouteMatch {
    pub host: Option<String>,
    pub path_prefix: Option<String>,
    pub method: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct HealthCheck {
    pub path: String,
    pub interval: u64,
    pub timeout_ms: u64,
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub cooldown_ms: u64,
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self {
            path: "/health".to_string(),
            interval: 5_000,
            timeout_ms: 1_000,
            failure_threshold: 3,
            success_threshold: 2,
            cooldown_ms: 5_000,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct LoadBalancing {
    #[serde(rename = "type")]
    pub lb_type: String,
    pub key: Option<String>,
}

impl Default for LoadBalancing {
    fn default() -> Self {
        Self {
            lb_type: "round-robin".to_string(),
            key: None,
        }
    }
}
