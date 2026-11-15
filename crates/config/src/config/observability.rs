use super::*;

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct Observability {
    pub metrics: MetricsEndpoint,
    pub control_api: ControlApi,
    pub tracing: Tracing,
    pub routing: RoutingTransparency,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct MetricsEndpoint {
    pub enabled: bool,
    pub required: bool,
    pub address: String,
    /// Permit binding the unauthenticated plaintext metrics endpoint beyond loopback.
    pub allow_non_loopback: bool,
    pub port: u16,
    pub path: String,
    /// Measure per-plugin execution durations for detailed timing metrics.
    pub detailed_plugin_timing: bool,
    pub max_connections: usize,
    pub connection_timeout_ms: u64,
}

impl Default for MetricsEndpoint {
    fn default() -> Self {
        Self {
            enabled: false,
            required: false,
            address: "127.0.0.1".to_string(),
            allow_non_loopback: false,
            port: 9901,
            path: "/metrics".to_string(),
            detailed_plugin_timing: false,
            max_connections: 512,
            connection_timeout_ms: 30_000,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ControlApiClientAuthMode {
    #[default]
    Disabled,
    Optional,
    Required,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum ControlApiRole {
    #[default]
    Viewer,
    Operator,
    Admin,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ControlApiAuditFormat {
    #[default]
    Json,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ControlApiAuditSink {
    #[default]
    Log,
    File,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, Eq, PartialEq)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct ControlApiTls {
    pub client_auth: ControlApiTlsClientAuth,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, Eq, PartialEq)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct ControlApiTlsClientAuth {
    pub mode: ControlApiClientAuthMode,
    pub ca_file: Option<String>,
    pub ca_dir: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Default, Eq, PartialEq)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct ControlApiAuth {
    pub bearer_tokens: Vec<ControlApiBearerToken>,
    pub identity_source: Option<ControlApiIdentitySource>,
}

impl std::fmt::Debug for ControlApiAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlApiAuth")
            .field(
                "bearer_tokens",
                &format_args!("{} configured", self.bearer_tokens.len()),
            )
            .field("identity_source", &self.identity_source)
            .finish()
    }
}

#[derive(Deserialize, Serialize, Clone, Eq, PartialEq)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct ControlApiBearerToken {
    #[serde(skip_serializing)]
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_ref: Option<SecretRef>,
    pub role: ControlApiRole,
    pub actor_id: Option<String>,
}

impl Default for ControlApiBearerToken {
    fn default() -> Self {
        Self {
            token: String::new(),
            token_ref: None,
            role: ControlApiRole::Viewer,
            actor_id: None,
        }
    }
}

impl std::fmt::Debug for ControlApiBearerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlApiBearerToken")
            .field("token", &"<redacted>")
            .field(
                "token_ref",
                &self.token_ref.as_ref().map(|_| "<configured>"),
            )
            .field("role", &self.role)
            .field("actor_id", &self.actor_id)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, Eq, PartialEq)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct ControlApiIdentitySource {
    pub kind: String,
    pub role_attribute: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Eq, PartialEq)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct ControlApiAuthorization {
    pub protect_health: bool,
    pub protect_ready: bool,
    pub runtime_read_role: ControlApiRole,
    pub runtime_mutate_role: ControlApiRole,
    pub restart_role: ControlApiRole,
}

impl Default for ControlApiAuthorization {
    fn default() -> Self {
        Self {
            protect_health: false,
            protect_ready: false,
            runtime_read_role: ControlApiRole::Viewer,
            runtime_mutate_role: ControlApiRole::Operator,
            restart_role: ControlApiRole::Admin,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, Eq, PartialEq)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct ControlApiIpAllowlist {
    pub cidrs: Vec<String>,
    #[serde(default)]
    pub trusted_proxy_cidrs: Vec<String>,
    pub trust_proxy_headers: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Eq, PartialEq)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct ControlApiAudit {
    pub enabled: bool,
    pub format: ControlApiAuditFormat,
    pub sink: ControlApiAuditSink,
    pub file_path: Option<String>,
}

impl Default for ControlApiAudit {
    fn default() -> Self {
        Self {
            enabled: false,
            format: ControlApiAuditFormat::Json,
            sink: ControlApiAuditSink::Log,
            file_path: None,
        }
    }
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct ControlApi {
    pub enabled: bool,
    pub required: bool,
    pub address: String,
    pub port: u16,
    pub health_path: String,
    pub ready_path: String,
    pub runtime_path: String,
    pub restart_path: String,
    pub reload_path: String,
    pub reload_certs_path: String,
    #[serde(skip_serializing)]
    pub auth_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_token_ref: Option<SecretRef>,
    pub tls: ControlApiTls,
    pub auth: ControlApiAuth,
    pub authorization: ControlApiAuthorization,
    pub ip_allowlist: ControlApiIpAllowlist,
    pub audit: ControlApiAudit,
    pub max_connections: usize,
    pub connection_timeout_ms: u64,
}

impl Default for ControlApi {
    fn default() -> Self {
        Self {
            enabled: false,
            required: false,
            address: "127.0.0.1".to_string(),
            port: 9902,
            health_path: "/health".to_string(),
            ready_path: "/ready".to_string(),
            runtime_path: "/admin/runtime".to_string(),
            restart_path: "/admin/runtime/restart".to_string(),
            reload_path: "/admin/runtime/reload".to_string(),
            reload_certs_path: "/admin/runtime/reload-certs".to_string(),
            auth_token: None,
            auth_token_ref: None,
            tls: ControlApiTls::default(),
            auth: ControlApiAuth::default(),
            authorization: ControlApiAuthorization::default(),
            ip_allowlist: ControlApiIpAllowlist::default(),
            audit: ControlApiAudit::default(),
            max_connections: 256,
            connection_timeout_ms: 30_000,
        }
    }
}

impl std::fmt::Debug for ControlApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlApi")
            .field("enabled", &self.enabled)
            .field("required", &self.required)
            .field("address", &self.address)
            .field("port", &self.port)
            .field("health_path", &self.health_path)
            .field("ready_path", &self.ready_path)
            .field("runtime_path", &self.runtime_path)
            .field("restart_path", &self.restart_path)
            .field("reload_path", &self.reload_path)
            .field("reload_certs_path", &self.reload_certs_path)
            .field(
                "auth_token",
                &self.auth_token.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "auth_token_ref",
                &self.auth_token_ref.as_ref().map(|_| "<configured>"),
            )
            .field("tls", &self.tls)
            .field("auth", &self.auth)
            .field("authorization", &self.authorization)
            .field("ip_allowlist", &self.ip_allowlist)
            .field("audit", &self.audit)
            .field("max_connections", &self.max_connections)
            .field("connection_timeout_ms", &self.connection_timeout_ms)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct Tracing {
    pub enabled: bool,
    pub service_name: String,
    pub otlp_endpoint: Option<String>,
    pub sample_ratio: f64,
}

impl Default for Tracing {
    fn default() -> Self {
        Self {
            enabled: false,
            service_name: "impulse".to_string(),
            otlp_endpoint: None,
            sample_ratio: 1.0,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct RoutingTransparency {
    pub enabled: bool,
    pub include_reason: bool,
    pub expose_header: bool,
    pub header_name: String,
}

impl Default for RoutingTransparency {
    fn default() -> Self {
        Self {
            enabled: false,
            include_reason: true,
            expose_header: false,
            header_name: "x-impulse-route-decision".to_string(),
        }
    }
}
