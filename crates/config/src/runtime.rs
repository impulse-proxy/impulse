//! Canonical runtime-ready configuration for the rest of the system.
//!
//! `RuntimeConfig` and the types re-exported from this module are the validated,
//! normalized outputs that downstream crates should consume. Interpreter-only
//! shaping details stay internal to the runtime lowering modules.

use std::{collections::HashMap, fmt, net::IpAddr};

use crate::config::{
    Backend, ClientAuth, Config, ForwardedHeaderPolicy, Listen, Observability, Performance,
    ProtocolPolicy, Resilience, Secrets, Security, TlsCertificate, Upstream, UpstreamHostPolicy,
    UpstreamHostPolicyMode, UpstreamTls,
};

mod listeners;
mod policies;
mod secrets;
mod upstreams;

pub use self::{
    policies::{
        RuntimeAdmissionPolicy, RuntimeAlternateBackendPolicy, RuntimeApiKeyAuth,
        RuntimeAuthPolicy, RuntimeBackendAddressKind, RuntimeBackendConnectionPolicy,
        RuntimeBackendDnsPolicy, RuntimeBackendEndpoint, RuntimeBackendHealthCheck,
        RuntimeBackendTlsPolicy, RuntimeBackendTransportKind, RuntimeBrownoutPolicy,
        RuntimeCircuitBreakerPolicy, RuntimeConnectionLimits, RuntimeExternalAuth,
        RuntimeExternalAuthFailureMode, RuntimeExternalAuthRequestHeader, RuntimeHedgingPolicy,
        RuntimeJwtAuth, RuntimeJwtVerificationKey, RuntimeListenerPolicySet,
        RuntimeLoadBalancingPolicy, RuntimeLoadBalancingStrategy, RuntimePolicySet,
        RuntimeQuotaBackendFailurePolicy, RuntimeQuotaCounterBackend, RuntimeQuotaEnforcementMode,
        RuntimeQuotaLocalFallback, RuntimeQuotaPolicy, RuntimeQuotaPolicySet,
        RuntimeQuotaSelectorDimension, RuntimeQuotaSelectorMatcher, RuntimeQuotaWindow,
        RuntimeRateLimitPolicy, RuntimeRequestKeySpec, RuntimeResponseCachePolicy,
        RuntimeResponseCompressionPolicy, RuntimeRetryBudgetPolicy, RuntimeRouteHostPattern,
        RuntimeRouteMatchPolicy, RuntimeRouteQueuePolicy, RuntimeScopedRateLimitPolicy,
        RuntimeTimeoutPolicy, RuntimeTransportPolicy, RuntimeWatchdogPolicy,
    },
    secrets::{
        FilesystemSecretProvider, LiteralSecretProvider, RuntimeResolvedSecret,
        RuntimeResolvedSecretMetadata, RuntimeSecretProvider, RuntimeSecretResolutionError,
        RuntimeSecretResolutionErrorKind, RuntimeSecretResolver, RuntimeSecretSourceKind,
        resolve_config_secrets, resolve_file_secret_path,
    },
};

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub version: u32,
    pub listeners: Vec<RuntimeListener>,
    pub upstreams: HashMap<String, RuntimeUpstream>,
    pub secrets: Secrets,
    pub policies: RuntimePolicySet,
    pub performance: Performance,
    pub observability: Observability,
    pub resilience: Resilience,
    pub security: Security,
}

impl RuntimeConfig {
    pub fn from_config(config: &Config) -> Result<Self, RuntimeConfigError> {
        let resolved_config = resolve_config_secrets(config)?;
        let policies = RuntimePolicySet::from_config(&resolved_config)?;
        Ok(Self {
            version: resolved_config.version,
            listeners: listeners::runtime_listeners(&resolved_config)?,
            upstreams: upstreams::normalize_upstreams(&resolved_config, &policies)?,
            secrets: resolved_config.secrets.clone(),
            policies,
            performance: resolved_config.performance.clone(),
            observability: resolved_config.observability.clone(),
            resilience: resolved_config.resilience.clone(),
            security: resolved_config.security.clone(),
        })
    }

    pub fn listener_runtime_configs(&self) -> Vec<ListenerRuntimeConfig> {
        self.listeners
            .iter()
            .cloned()
            .map(|listen| ListenerRuntimeConfig {
                policies: RuntimeListenerPolicySet {
                    timeouts: self.policies.timeouts.clone(),
                    transport: self.policies.transport.clone(),
                    tls: listen.tls.clone(),
                },
                listen,
                performance: self.performance.clone(),
                observability: self.observability.clone(),
            })
            .collect()
    }

    pub fn primary_listener_runtime_config(&self) -> Option<ListenerRuntimeConfig> {
        self.listener_runtime_configs().into_iter().next()
    }

    #[cfg(test)]
    pub(crate) fn upstreams_as_config(&self) -> HashMap<String, Upstream> {
        self.upstreams
            .iter()
            .map(|(name, upstream)| (name.clone(), upstream.as_config_upstream()))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeConfigError {
    ConfigInvalid(String),
    TlsMaterialInvalid(String),
    SecretResolutionFailed(String),
    BackendAddressInvalid {
        upstream: String,
        backend: String,
        address: String,
        reason: String,
    },
    DuplicateRouteAmbiguity {
        upstream: String,
        existing_upstream: String,
        host: Option<String>,
        path_prefix: Option<String>,
        method: Option<String>,
    },
    ListenerBindConflict {
        current: String,
        existing: String,
        address: String,
        port: u16,
    },
    UnsupportedPolicyCombination(String),
}

impl RuntimeConfigError {
    pub fn category(&self) -> &'static str {
        match self {
            Self::ConfigInvalid(_) => "config_invalid",
            Self::TlsMaterialInvalid(_) => "tls_material_invalid",
            Self::SecretResolutionFailed(_) => "secret_resolution_failed",
            Self::BackendAddressInvalid { .. } => "backend_address_invalid",
            Self::DuplicateRouteAmbiguity { .. } => "duplicate_route_ambiguity",
            Self::ListenerBindConflict { .. } => "listener_bind_conflict",
            Self::UnsupportedPolicyCombination(_) => "unsupported_policy_combination",
        }
    }
}

impl fmt::Display for RuntimeConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigInvalid(message)
            | Self::TlsMaterialInvalid(message)
            | Self::SecretResolutionFailed(message)
            | Self::UnsupportedPolicyCombination(message) => {
                write!(f, "{}: {}", self.category(), message)
            }
            Self::BackendAddressInvalid {
                upstream,
                backend,
                address,
                reason,
            } => write!(
                f,
                "{}: upstream '{}' backend '{}' address '{}' is invalid: {}",
                self.category(),
                upstream,
                backend,
                address,
                reason
            ),
            Self::DuplicateRouteAmbiguity {
                upstream,
                existing_upstream,
                host,
                path_prefix,
                method,
            } => write!(
                f,
                "{}: upstream '{}' conflicts with upstream '{}' for host={:?} path_prefix={:?} method={:?}",
                self.category(),
                upstream,
                existing_upstream,
                host,
                path_prefix,
                method
            ),
            Self::ListenerBindConflict {
                current,
                existing,
                address,
                port,
            } => write!(
                f,
                "{}: {} duplicates {} on {}:{}",
                self.category(),
                current,
                existing,
                address,
                port
            ),
        }
    }
}

impl std::error::Error for RuntimeConfigError {}

#[derive(Debug, Clone)]
pub struct RuntimeListener {
    pub index: usize,
    pub source: RuntimeListenerSource,
    pub listen: Listen,
    pub tls: RuntimeListenerTls,
}

#[derive(Debug, Clone)]
pub struct ListenerRuntimeConfig {
    pub listen: RuntimeListener,
    pub policies: RuntimeListenerPolicySet,
    pub performance: Performance,
    pub observability: Observability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeListenerSource {
    LegacyListen,
    ExplicitListeners,
}

#[derive(Debug, Clone)]
pub struct RuntimeListenerTls {
    pub default_identity: RuntimeTlsIdentity,
    pub sni_identities: HashMap<String, RuntimeTlsIdentity>,
    pub client_auth: ClientAuth,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTlsIdentity {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone)]
pub struct RuntimeUpstream {
    pub name: String,
    pub load_balancing: RuntimeLoadBalancingPolicy,
    pub route: RuntimeRouteMatchPolicy,
    pub policy: RuntimeUpstreamPolicy,
    pub effective_tls: UpstreamTls,
    pub backends: Vec<RuntimeBackend>,
    pub(crate) backend_tls_policy: RuntimeBackendTlsPolicy,
}

impl RuntimeUpstream {
    pub fn backend_tls_policy(&self) -> &RuntimeBackendTlsPolicy {
        &self.backend_tls_policy
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeBackend {
    pub backend: Backend,
    pub endpoint: RuntimeBackendEndpoint,
    pub health_check: Option<RuntimeBackendHealthCheck>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeHostPolicy(pub UpstreamHostPolicy);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeForwardedHeaderPolicy(pub ForwardedHeaderPolicy);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeProtocolPolicy(pub ProtocolPolicy);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeUpstreamPolicy {
    /// Upstream-owned auth policy selected after route lookup resolves an upstream.
    pub upstream_auth: RuntimeAuthPolicy,
    pub host: RuntimeHostPolicy,
    pub forwarded_headers: RuntimeForwardedHeaderPolicy,
    pub response_cache: RuntimeResponseCachePolicy,
    pub response_compression: RuntimeResponseCompressionPolicy,
    pub protocol: RuntimeProtocolPolicy,
}

// NOTE: Public-API `RuntimeConfig::from_config` contract tests live in the
// regression suite at `crates/config/tests/regression/`. The tests kept here are
// the ones that reach crate-internal items — the private `listeners` module's
// `runtime_listeners` and the `#[cfg(test)] pub(crate)` `upstreams_as_config`
// helper — which are not reachable from an external integration-test crate.
#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{listeners::runtime_listeners, *};
    use crate::config::{
        Config, ForwardedHeaderPolicyMode, Listen, LoadBalancing, RouteMatch, Tls, TlsCertificate,
        Upstream, UpstreamHostPolicyMode,
    };

    fn sample_config() -> Config {
        let mut config = Config {
            version: 1,
            listen: Listen {
                protocol: "http3".to_string(),
                port: 443,
                address: "0.0.0.0".to_string(),
                tls: Tls {
                    cert: "/tmp/tls/default.pem".to_string(),
                    key: "/tmp/tls/default.key".to_string(),
                    certificates: Vec::new(),
                    client_auth: ClientAuth::default(),
                },
            },
            listeners: Vec::new(),
            upstream: HashMap::new(),
            load_balancing: None,
            upstream_tls: UpstreamTls::default(),
            secrets: Default::default(),
            log: crate::config::Log::default(),
            performance: Performance::default(),
            observability: Observability::default(),
            resilience: Resilience::default(),
            security: Security::default(),
        };

        config.upstream.insert(
            "api".to_string(),
            Upstream {
                load_balancing: LoadBalancing {
                    lb_type: "round-robin".to_string(),
                    key: None,
                },
                auth: Default::default(),
                host_policy: UpstreamHostPolicy {
                    mode: UpstreamHostPolicyMode::Rewrite,
                    host: Some("api.internal".to_string()),
                },
                forwarded_headers: ForwardedHeaderPolicy {
                    mode: ForwardedHeaderPolicyMode::Append,
                },
                compression: Default::default(),
                cache: Default::default(),
                tls: None,
                route: RouteMatch {
                    host: Some("api.example.com".to_string()),
                    path_prefix: Some("/".to_string()),
                    method: None,
                },
                backends: vec![Backend {
                    id: "api-1".to_string(),
                    address: "https://api.internal:8443".to_string(),
                    weight: 100,
                    health_check: None,
                }],
            },
        );

        config
    }

    #[test]
    fn runtime_upstream_carries_canonical_lb_auth_and_tls_shapes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca = rcgen::generate_simple_self_signed(vec!["upstream-ca".to_string()])
            .expect("build upstream ca");
        let ca_path = dir.path().join("upstream-ca.pem");
        std::fs::write(&ca_path, ca.serialize_pem().expect("serialize upstream ca"))
            .expect("write upstream ca");

        let mut config = sample_config();
        let upstream = config.upstream.get_mut("api").expect("api upstream");
        upstream.load_balancing = LoadBalancing {
            lb_type: "sticky-cid".to_string(),
            key: Some("header:x-user-id".to_string()),
        };
        upstream.auth.api_key = Some(crate::config::ApiKeyAuth {
            header_name: "x-api-key".to_string(),
            keys: vec!["secret-1".to_string()],
        });
        upstream.tls = Some(UpstreamTls {
            verify_certificates: false,
            strict_sni: false,
            ca_file: Some(ca_path.to_string_lossy().to_string()),
            ca_dir: None,
            client_certificate: None,
            client_certificate_ref: None,
            client_key: None,
            client_key_ref: None,
        });
        config.resilience.scoped_rate_limits = vec![crate::config::ScopedRateLimit {
            name: "client-default".to_string(),
            scope: crate::config::ScopedRateLimitScope::Client,
            requests_per_sec: 10,
            burst: 20,
            key: Some("peer_ip".to_string()),
            route_allowlist: vec!["api".to_string()],
            idle_ttl_secs: 30,
        }];

        let runtime = RuntimeConfig::from_config(&config).expect("runtime config");
        let api = runtime.upstreams.get("api").expect("api runtime upstream");

        assert_eq!(
            api.load_balancing.strategy,
            RuntimeLoadBalancingStrategy::StickyCid
        );
        assert_eq!(api.load_balancing.key.as_deref(), Some("header:x-user-id"));
        assert_eq!(
            api.policy
                .upstream_auth
                .api_key
                .as_ref()
                .map(|auth| auth.header_name.as_str()),
            Some("x-api-key")
        );
        assert_eq!(
            api.backend_tls_policy().ca_file.as_deref(),
            Some(ca_path.to_string_lossy().as_ref())
        );
        assert_eq!(
            runtime.policies.transport.backend_connections.max_inflight,
            runtime
                .policies
                .transport
                .connection_limits
                .backend_pool_max_inflight
        );
        assert_eq!(runtime.policies.rate_limits.scoped_limits.len(), 1);
        assert_eq!(
            runtime.policies.rate_limits.scoped_limits[0].idle_ttl,
            Duration::from_secs(30)
        );
    }

    #[test]
    fn runtime_upstreams_as_config_canonicalizes_route_and_lb_shapes() {
        let mut config = sample_config();
        let upstream = config.upstream.get_mut("api").expect("api upstream");
        upstream.load_balancing = LoadBalancing {
            lb_type: "cid_sticky".to_string(),
            key: Some("header:x-user-id".to_string()),
        };
        upstream.route = RouteMatch {
            host: Some("API.EXAMPLE.COM:443.".to_string()),
            path_prefix: Some("/v1".to_string()),
            method: Some("get".to_string()),
        };

        let runtime = RuntimeConfig::from_config(&config).expect("runtime config");
        let runtime_upstream = runtime.upstreams.get("api").expect("api runtime upstream");
        let exported = runtime
            .upstreams_as_config()
            .remove("api")
            .expect("api exported upstream");

        assert_eq!(
            runtime_upstream.load_balancing.strategy,
            RuntimeLoadBalancingStrategy::StickyCid
        );
        assert_eq!(
            runtime_upstream.load_balancing.key_spec,
            Some(RuntimeRequestKeySpec::Header("x-user-id".to_string()))
        );
        assert!(
            !runtime_upstream
                .load_balancing
                .alternate_backend
                .readonly_lb_pick
        );
        assert!(
            runtime_upstream
                .load_balancing
                .alternate_backend
                .healthy_fallback
        );
        assert_eq!(
            runtime_upstream.route.host.as_deref(),
            Some("api.example.com:443")
        );
        assert_eq!(runtime_upstream.route.method.as_deref(), Some("GET"));
        assert_eq!(runtime_upstream.route.path_prefix.as_deref(), Some("/v1"));
        assert_eq!(exported.load_balancing.lb_type, "sticky-cid");
        assert_eq!(exported.route.host.as_deref(), Some("api.example.com:443"));
        assert_eq!(exported.route.method.as_deref(), Some("GET"));
        assert_eq!(exported.route.path_prefix.as_deref(), Some("/v1"));
    }

    #[test]
    fn runtime_config_rejects_whitespace_only_route_host_without_path_prefix() {
        let mut config = sample_config();
        let upstream = config.upstream.get_mut("api").expect("api upstream");
        upstream.route = RouteMatch {
            host: Some("   ".to_string()),
            path_prefix: None,
            method: None,
        };

        assert!(RuntimeConfig::from_config(&config).is_err());
    }

    #[test]
    fn runtime_config_rejects_malformed_route_host() {
        let mut config = sample_config();
        let upstream = config.upstream.get_mut("api").expect("api upstream");
        upstream.route = RouteMatch {
            host: Some("[missing-end".to_string()),
            path_prefix: None,
            method: None,
        };

        assert!(RuntimeConfig::from_config(&config).is_err());
    }

    #[test]
    fn runtime_listeners_uses_legacy_listen_when_explicit_list_is_empty() {
        let config = sample_config();
        let listeners = runtime_listeners(&config).expect("legacy listeners");

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].source, RuntimeListenerSource::LegacyListen);
        assert_eq!(listeners[0].listen.port, 443);
    }

    #[test]
    fn runtime_listeners_prefer_explicit_listeners() {
        let mut config = sample_config();
        config.listeners = vec![
            Listen {
                protocol: "http3".to_string(),
                port: 8443,
                address: "127.0.0.1".to_string(),
                tls: Tls {
                    cert: "/tmp/tls/explicit-1.pem".to_string(),
                    key: "/tmp/tls/explicit-1.key".to_string(),
                    certificates: Vec::new(),
                    client_auth: ClientAuth::default(),
                },
            },
            Listen {
                protocol: "http3".to_string(),
                port: 9443,
                address: "127.0.0.2".to_string(),
                tls: Tls {
                    cert: "/tmp/tls/explicit-2.pem".to_string(),
                    key: "/tmp/tls/explicit-2.key".to_string(),
                    certificates: Vec::new(),
                    client_auth: ClientAuth::default(),
                },
            },
        ];

        let listeners = runtime_listeners(&config).expect("explicit listeners");

        assert_eq!(listeners.len(), 2);
        assert_eq!(
            listeners[0].source,
            RuntimeListenerSource::ExplicitListeners
        );
        assert_eq!(
            listeners[1].source,
            RuntimeListenerSource::ExplicitListeners
        );
        assert_eq!(listeners[0].listen.port, 8443);
        assert_eq!(listeners[1].listen.port, 9443);
    }

    #[test]
    fn runtime_listener_tls_uses_legacy_pair_as_default_identity() {
        let mut config = sample_config();
        config.listen.tls.cert = "/tmp/tls/cert.pem".to_string();
        config.listen.tls.key = "/tmp/tls/key.pem".to_string();
        config.listen.tls.certificates = vec![TlsCertificate {
            server_name: "api.example.com".to_string(),
            cert: "/tmp/tls/api.pem".to_string(),
            key: "/tmp/tls/api.key".to_string(),
        }];

        let listeners = runtime_listeners(&config).expect("runtime listeners");
        let tls = &listeners[0].tls;

        assert_eq!(
            tls.default_identity,
            RuntimeTlsIdentity {
                cert_path: "/tmp/tls/cert.pem".to_string(),
                key_path: "/tmp/tls/key.pem".to_string(),
            }
        );
        assert!(tls.sni_identities.contains_key("api.example.com"));
    }

    #[test]
    fn runtime_listener_tls_uses_first_sni_identity_as_default_when_legacy_pair_is_absent() {
        let mut config = sample_config();
        config.listen.tls.cert.clear();
        config.listen.tls.key.clear();
        config.listen.tls.certificates = vec![
            TlsCertificate {
                server_name: "api.example.com".to_string(),
                cert: "/tmp/tls/api.pem".to_string(),
                key: "/tmp/tls/api.key".to_string(),
            },
            TlsCertificate {
                server_name: "WWW.EXAMPLE.COM".to_string(),
                cert: "/tmp/tls/www.pem".to_string(),
                key: "/tmp/tls/www.key".to_string(),
            },
        ];

        let listeners = runtime_listeners(&config).expect("runtime listeners");
        let tls = &listeners[0].tls;

        assert_eq!(
            tls.default_identity,
            RuntimeTlsIdentity {
                cert_path: "/tmp/tls/api.pem".to_string(),
                key_path: "/tmp/tls/api.key".to_string(),
            }
        );
        assert_eq!(
            tls.sni_identities.get("api.example.com"),
            Some(&RuntimeTlsIdentity {
                cert_path: "/tmp/tls/api.pem".to_string(),
                key_path: "/tmp/tls/api.key".to_string(),
            })
        );
        assert_eq!(
            tls.sni_identities.get("www.example.com"),
            Some(&RuntimeTlsIdentity {
                cert_path: "/tmp/tls/www.pem".to_string(),
                key_path: "/tmp/tls/www.key".to_string(),
            })
        );
    }

    #[test]
    fn runtime_listeners_reject_duplicate_effective_bindings() {
        let mut config = sample_config();
        config.listeners = vec![
            Listen {
                protocol: "http3".to_string(),
                port: 8443,
                address: "127.0.0.1".to_string(),
                tls: Tls {
                    cert: "/tmp/tls/dup-1.pem".to_string(),
                    key: "/tmp/tls/dup-1.key".to_string(),
                    certificates: Vec::new(),
                    client_auth: ClientAuth::default(),
                },
            },
            Listen {
                protocol: "http3".to_string(),
                port: 8443,
                address: "127.0.0.1".to_string(),
                tls: Tls {
                    cert: "/tmp/tls/dup-2.pem".to_string(),
                    key: "/tmp/tls/dup-2.key".to_string(),
                    certificates: Vec::new(),
                    client_auth: ClientAuth::default(),
                },
            },
        ];

        let err = runtime_listeners(&config).expect_err("duplicate listeners must fail");
        assert_eq!(err.category(), "listener_bind_conflict");
        assert!(err.to_string().contains("duplicates"));
    }

    #[test]
    fn runtime_listeners_reject_duplicate_bindings_after_address_normalization() {
        let mut config = sample_config();
        config.listeners = vec![
            Listen {
                protocol: "http3".to_string(),
                port: 8443,
                address: "LOCALHOST".to_string(),
                tls: Tls {
                    cert: "/tmp/tls/dup-1.pem".to_string(),
                    key: "/tmp/tls/dup-1.key".to_string(),
                    certificates: Vec::new(),
                    client_auth: ClientAuth::default(),
                },
            },
            Listen {
                protocol: "http3".to_string(),
                port: 8443,
                address: " localhost ".to_string(),
                tls: Tls {
                    cert: "/tmp/tls/dup-2.pem".to_string(),
                    key: "/tmp/tls/dup-2.key".to_string(),
                    certificates: Vec::new(),
                    client_auth: ClientAuth::default(),
                },
            },
        ];

        let err = runtime_listeners(&config).expect_err("normalized duplicates must fail");
        assert_eq!(err.category(), "listener_bind_conflict");
        assert_eq!(
            err.to_string(),
            "listener_bind_conflict:  localhost :8443 (listener #1) duplicates LOCALHOST:8443 (listener #0) on  localhost :8443"
        );
    }

    #[test]
    fn runtime_listener_tls_rejects_partial_legacy_pair() {
        let mut config = sample_config();
        config.listen.tls.cert = "/tmp/tls/cert.pem".to_string();
        config.listen.tls.key.clear();

        let err = runtime_listeners(&config).expect_err("partial legacy pair must fail");
        assert_eq!(err.category(), "tls_material_invalid");
        assert!(
            err.to_string()
                .contains("listen.tls.cert and listen.tls.key must both be set")
        );
    }

    #[test]
    fn runtime_listener_tls_rejects_duplicate_sni_names() {
        let mut config = sample_config();
        config.listen.tls.certificates = vec![
            TlsCertificate {
                server_name: "api.example.com".to_string(),
                cert: "/tmp/tls/api.pem".to_string(),
                key: "/tmp/tls/api.key".to_string(),
            },
            TlsCertificate {
                server_name: "API.EXAMPLE.COM".to_string(),
                cert: "/tmp/tls/api-2.pem".to_string(),
                key: "/tmp/tls/api-2.key".to_string(),
            },
        ];

        let err = runtime_listeners(&config).expect_err("duplicate sni names must fail");
        assert_eq!(err.category(), "tls_material_invalid");
        assert!(err.to_string().contains("duplicate server_name"));
    }
}
