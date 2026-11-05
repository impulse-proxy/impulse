use impulse_bridge::{
    ForwardedHeaderMode, ForwardingPolicyInput, HostPolicyInput, HostPolicyMode, UpstreamScheme,
    UpstreamTargetInput,
    request::{RequestBuildPolicies, RequestBuildTarget},
};
use impulse_config::{
    backend_endpoint::{BackendEndpoint, BackendScheme},
    config::{
        ForwardedHeaderPolicy, ForwardedHeaderPolicyMode, JwksStartupBehavior, JwtAlgorithm,
        ScopedRateLimitScope, UpstreamHostPolicy, UpstreamHostPolicyMode,
    },
    runtime::{
        RuntimeAuthPolicy, RuntimeBackend, RuntimeBackendTransportKind, RuntimeConfig,
        RuntimeExternalAuth, RuntimeExternalAuthFailureMode, RuntimeExternalAuthRequestHeader,
        RuntimeJwtAuth, RuntimeJwtVerificationKey, RuntimeLoadBalancingStrategy,
        RuntimeQuotaBackendFailurePolicy, RuntimeQuotaCounterBackend, RuntimeQuotaEnforcementMode,
        RuntimeQuotaPolicySet, RuntimeRequestKeySpec, RuntimeUpstream, RuntimeWatchdogPolicy,
    },
};
use impulse_lb::{
    BackendHealthInput, BackendInput, BackendWeight, LoadBalancingStrategy, RequestKeyInput,
    upstream_pool::UpstreamPool,
};
use impulse_operations::watchdog::WatchdogRuntimeConfig;
use impulse_plugins::{
    ApiKeyAuthInput as PluginApiKeyAuthInput, ConnectionRateLimitInput,
    ExternalAuthFailureModeInput, ExternalAuthInput, ExternalAuthRequestHeaderInput,
    JwksStartupBehaviorInput, JwtAlgorithmInput, JwtAuthInput, JwtVerificationKeyInput,
    PluginConstructionInputs, QuotaBackendFailureInput, QuotaCounterBackendInput,
    QuotaEnforcementInput, QuotaInput, QuotaLocalFallbackInput, QuotaPolicyInput,
    QuotaSelectorInput, QuotaWindowInput, RequestKeyInput as PluginRequestKeyInput,
    ResponseCacheInput, ResponseCompressionInput, ScopedRateLimitInput, ScopedRateLimitScopeInput,
    UpstreamPluginInputs,
};
use impulse_policy::{JwtAllowedAlgorithms, JwtPolicyInput};
use impulse_transport::{
    UpstreamConnectionLimitsInput, UpstreamEndpointInput, UpstreamProtocol, UpstreamTimeoutInput,
    UpstreamTlsInput, UpstreamTransportInput,
};

pub(crate) fn jwt_allowed_algorithms(jwt: &RuntimeJwtAuth) -> JwtAllowedAlgorithms {
    JwtAllowedAlgorithms {
        hs256: jwt.allowed_algorithms.contains(&JwtAlgorithm::Hs256),
        rs256: jwt.allowed_algorithms.contains(&JwtAlgorithm::Rs256),
        es256: jwt.allowed_algorithms.contains(&JwtAlgorithm::Es256),
    }
}

pub(crate) fn jwt_policy_input(jwt: &RuntimeJwtAuth) -> JwtPolicyInput<'_> {
    JwtPolicyInput {
        allowed_algorithms: jwt_allowed_algorithms(jwt),
        issuer: jwt.issuer.as_deref(),
        issuers: &jwt.issuers,
        audience: jwt.audience.as_deref(),
        audiences: &jwt.audiences,
        clock_skew_seconds: jwt.clock_skew.as_secs(),
    }
}

fn plugin_jwt_algorithm(algorithm: JwtAlgorithm) -> JwtAlgorithmInput {
    match algorithm {
        JwtAlgorithm::Hs256 => JwtAlgorithmInput::Hs256,
        JwtAlgorithm::Rs256 => JwtAlgorithmInput::Rs256,
        JwtAlgorithm::Es256 => JwtAlgorithmInput::Es256,
    }
}

fn plugin_jwt_verification_key(key: &RuntimeJwtVerificationKey) -> JwtVerificationKeyInput {
    match key {
        RuntimeJwtVerificationKey::Pem {
            kid,
            alg,
            public_key_pem,
        } => JwtVerificationKeyInput::Pem {
            kid: kid.clone(),
            algorithm: alg.map(plugin_jwt_algorithm),
            public_key_pem: public_key_pem.clone(),
        },
        RuntimeJwtVerificationKey::Jwk { kid, alg, jwk } => JwtVerificationKeyInput::Jwk {
            kid: kid.clone(),
            algorithm: alg.map(plugin_jwt_algorithm),
            jwk: jwk.clone(),
        },
    }
}

fn plugin_jwt_input(jwt: &RuntimeJwtAuth, auth: &RuntimeAuthPolicy) -> JwtAuthInput {
    JwtAuthInput {
        secret: jwt.secret.clone(),
        issuer: jwt.issuer.clone(),
        audience: jwt.audience.clone(),
        issuers: jwt.issuers.clone().into_boxed_slice(),
        audiences: jwt.audiences.clone().into_boxed_slice(),
        allowed_algorithms: jwt
            .allowed_algorithms
            .iter()
            .copied()
            .map(plugin_jwt_algorithm)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        require_kid: jwt.require_kid,
        static_keys: jwt
            .static_keys
            .iter()
            .map(plugin_jwt_verification_key)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        jwks_url: jwt.jwks_url.clone(),
        jwks_refresh_interval: jwt.jwks_refresh_interval,
        jwks_request_timeout: jwt.jwks_request_timeout,
        jwks_cache_ttl: jwt.jwks_cache_ttl,
        jwks_stale_if_error: jwt.jwks_stale_if_error,
        jwks_startup_behavior: match &jwt.jwks_startup_behavior {
            JwksStartupBehavior::RequireReady => JwksStartupBehaviorInput::RequireReady,
            JwksStartupBehavior::AllowDegraded => JwksStartupBehaviorInput::AllowDegraded,
        },
        clock_skew: jwt.clock_skew,
        required_scopes: auth.required_scopes.clone().into_boxed_slice(),
        required_roles: auth.required_roles.clone().into_boxed_slice(),
    }
}

fn plugin_external_auth_headers(
    headers: &[RuntimeExternalAuthRequestHeader],
) -> Box<[ExternalAuthRequestHeaderInput]> {
    headers
        .iter()
        .map(|header| ExternalAuthRequestHeaderInput {
            name: header.name.clone(),
            value: header.value.clone(),
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

fn plugin_external_auth_failure_mode(
    mode: RuntimeExternalAuthFailureMode,
) -> ExternalAuthFailureModeInput {
    match mode {
        RuntimeExternalAuthFailureMode::FailOpen => ExternalAuthFailureModeInput::FailOpen,
        RuntimeExternalAuthFailureMode::FailClosed => ExternalAuthFailureModeInput::FailClosed,
    }
}

fn plugin_external_auth_input(policy: &RuntimeExternalAuth) -> ExternalAuthInput {
    match policy {
        RuntimeExternalAuth::Http {
            endpoint,
            request_headers,
            response_header_allowlist,
            timeout,
            failure_mode,
        } => ExternalAuthInput::Http {
            endpoint: endpoint.clone(),
            request_headers: plugin_external_auth_headers(request_headers),
            response_header_allowlist: response_header_allowlist.clone().into_boxed_slice(),
            timeout: *timeout,
            failure_mode: plugin_external_auth_failure_mode(*failure_mode),
        },
        RuntimeExternalAuth::Oidc {
            discovery_url,
            issuer_url,
            client_id,
            client_secret,
            audience,
            scopes,
            request_headers,
            response_header_allowlist,
            timeout,
            failure_mode,
        } => ExternalAuthInput::Oidc {
            discovery_url: discovery_url.clone(),
            issuer_url: issuer_url.clone(),
            client_id: client_id.clone(),
            client_secret: client_secret.clone(),
            audience: audience.clone(),
            scopes: scopes.clone().into_boxed_slice(),
            request_headers: plugin_external_auth_headers(request_headers),
            response_header_allowlist: response_header_allowlist.clone().into_boxed_slice(),
            timeout: *timeout,
            failure_mode: plugin_external_auth_failure_mode(*failure_mode),
        },
    }
}

fn plugin_request_key(input: &RuntimeRequestKeySpec) -> PluginRequestKeyInput {
    match input {
        RuntimeRequestKeySpec::Path => PluginRequestKeyInput::Path,
        RuntimeRequestKeySpec::Authority => PluginRequestKeyInput::Authority,
        RuntimeRequestKeySpec::Method => PluginRequestKeyInput::Method,
        RuntimeRequestKeySpec::Cid => PluginRequestKeyInput::Cid,
        RuntimeRequestKeySpec::StickyCid => PluginRequestKeyInput::StickyCid,
        RuntimeRequestKeySpec::PeerIp => PluginRequestKeyInput::PeerIp,
        RuntimeRequestKeySpec::ClientIp => PluginRequestKeyInput::ClientIp,
        RuntimeRequestKeySpec::BearerToken => PluginRequestKeyInput::BearerToken,
        RuntimeRequestKeySpec::Header(name) => PluginRequestKeyInput::Header(name.clone()),
        RuntimeRequestKeySpec::Cookie(name) => PluginRequestKeyInput::Cookie(name.clone()),
        RuntimeRequestKeySpec::Query(name) => PluginRequestKeyInput::Query(name.clone()),
    }
}

fn plugin_quota_input(policy: &RuntimeQuotaPolicySet) -> Option<QuotaInput> {
    policy.enabled.then(|| QuotaInput {
        enforcement: match policy.enforcement {
            RuntimeQuotaEnforcementMode::Shadow => QuotaEnforcementInput::Shadow,
            RuntimeQuotaEnforcementMode::Enforce => QuotaEnforcementInput::Enforce,
        },
        backend_failure_policy: match policy.backend_failure_policy {
            RuntimeQuotaBackendFailurePolicy::FailOpen => QuotaBackendFailureInput::FailOpen,
            RuntimeQuotaBackendFailurePolicy::FailClosed => QuotaBackendFailureInput::FailClosed,
        },
        backend: match &policy.backend {
            RuntimeQuotaCounterBackend::InMemory { key_prefix } => {
                QuotaCounterBackendInput::InMemory {
                    key_prefix: key_prefix.clone(),
                }
            }
            RuntimeQuotaCounterBackend::Redis {
                url,
                key_prefix,
                connect_timeout,
                command_timeout,
                max_inflight,
            } => QuotaCounterBackendInput::Redis {
                url: url.clone(),
                key_prefix: key_prefix.clone(),
                connect_timeout: *connect_timeout,
                command_timeout: *command_timeout,
                max_inflight: *max_inflight,
            },
        },
        local_fallback: policy
            .local_fallback
            .as_ref()
            .map(|fallback| QuotaLocalFallbackInput {
                key_prefix: fallback.key_prefix.clone(),
                max_entries: fallback.max_entries,
            }),
        policies: policy
            .policies
            .iter()
            .map(|policy| QuotaPolicyInput {
                name: policy.name.clone(),
                route_allowlist: policy.route_allowlist.clone().into_boxed_slice(),
                selector: QuotaSelectorInput {
                    route: policy.selector.route,
                    tenant: policy.selector.tenant.as_ref().map(plugin_request_key),
                    token: policy.selector.token.as_ref().map(plugin_request_key),
                    client: policy.selector.client.as_ref().map(plugin_request_key),
                },
                burst: policy.burst.as_ref().map(|window| QuotaWindowInput {
                    requests: window.requests,
                    window: window.window,
                }),
                sustained: policy.sustained.as_ref().map(|window| QuotaWindowInput {
                    requests: window.requests,
                    window: window.window,
                }),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    })
}

pub(crate) fn plugin_construction_inputs(config: &RuntimeConfig) -> PluginConstructionInputs {
    let mut upstreams = config
        .upstreams
        .iter()
        .map(|(upstream_name, upstream)| {
            let auth = &upstream.policy.upstream_auth;
            UpstreamPluginInputs {
                upstream_name: upstream_name.clone(),
                api_key_auth: auth.api_key.as_ref().map(|policy| PluginApiKeyAuthInput {
                    header_name: policy.header_name.clone(),
                    accepted_keys: policy.keys.clone().into_boxed_slice(),
                }),
                jwt_auth: auth.jwt.as_ref().map(|jwt| plugin_jwt_input(jwt, auth)),
                external_auth: auth.external_auth.as_ref().map(plugin_external_auth_input),
                response_cache: upstream.policy.response_cache.enabled.then(|| {
                    ResponseCacheInput {
                        max_bytes: upstream.policy.response_cache.max_bytes,
                        max_entries: upstream.policy.response_cache.max_entries,
                        max_object_bytes: upstream.policy.response_cache.max_object_bytes,
                        max_ttl_seconds: upstream.policy.response_cache.max_ttl_secs,
                        authenticated_route: auth.api_key.is_some()
                            || auth.jwt.is_some()
                            || auth.external_auth.is_some()
                            || !auth.required_scopes.is_empty()
                            || !auth.required_roles.is_empty(),
                    }
                }),
                response_compression: upstream.policy.response_compression.enabled.then_some(
                    ResponseCompressionInput {
                        minimum_size_bytes: upstream.policy.response_compression.minimum_size_bytes,
                    },
                ),
            }
        })
        .collect::<Vec<_>>();
    upstreams.sort_unstable_by(|left, right| left.upstream_name.cmp(&right.upstream_name));

    PluginConstructionInputs {
        connection_rate_limit: ConnectionRateLimitInput {
            requests_per_second: config.policies.transport.new_connections_per_sec,
            burst: config.policies.transport.new_connections_burst,
        },
        scoped_rate_limits: config
            .policies
            .rate_limits
            .scoped_limits
            .iter()
            .map(|policy| ScopedRateLimitInput {
                name: policy.name.clone(),
                scope: match policy.scope {
                    ScopedRateLimitScope::Route => ScopedRateLimitScopeInput::Route,
                    ScopedRateLimitScope::Tenant => ScopedRateLimitScopeInput::Tenant,
                    ScopedRateLimitScope::Client => ScopedRateLimitScopeInput::Client,
                    ScopedRateLimitScope::Token => ScopedRateLimitScopeInput::Token,
                },
                requests_per_second: policy.requests_per_sec,
                burst: policy.burst,
                key: policy.key.clone(),
                route_allowlist: policy.route_allowlist.clone().into_boxed_slice(),
                idle_ttl: policy.idle_ttl,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        quota: plugin_quota_input(&config.policies.rate_limits.quota),
        upstreams: upstreams.into_boxed_slice(),
    }
}

pub(crate) fn watchdog_runtime_config(policy: &RuntimeWatchdogPolicy) -> WatchdogRuntimeConfig {
    WatchdogRuntimeConfig {
        enabled: policy.enabled,
        check_interval_ms: policy
            .check_interval
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX),
        poll_stall_timeout_ms: policy
            .poll_stall_timeout
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX),
        timeout_error_rate_percent: policy.timeout_error_rate_percent,
        min_requests_per_window: policy.min_requests_per_window,
        overload_inflight_percent: policy.overload_inflight_percent,
        unhealthy_consecutive_windows: policy.unhealthy_consecutive_windows,
        drain_grace_ms: policy
            .drain_grace
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX),
        restart_cooldown_ms: policy
            .restart_cooldown
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX),
        restart_command: policy.restart_command.clone(),
        restart_hook: None,
    }
}

pub(crate) fn bridge_request_target<'a>(
    endpoint: &'a BackendEndpoint,
    host_policy: &'a UpstreamHostPolicy,
    forwarded_header_policy: &ForwardedHeaderPolicy,
) -> RequestBuildTarget<'a> {
    RequestBuildTarget {
        endpoint: UpstreamTargetInput {
            scheme: match endpoint.scheme() {
                BackendScheme::Http => UpstreamScheme::Http,
                BackendScheme::Https => UpstreamScheme::Https,
            },
            authority: endpoint.authority(),
        },
        policies: RequestBuildPolicies {
            host_policy: HostPolicyInput {
                mode: match host_policy.mode {
                    UpstreamHostPolicyMode::PassThrough => HostPolicyMode::PassThrough,
                    UpstreamHostPolicyMode::Rewrite => HostPolicyMode::Rewrite,
                    UpstreamHostPolicyMode::Upstream => HostPolicyMode::Upstream,
                },
                rewrite_host: host_policy.host.as_deref(),
            },
            forwarded_header_policy: ForwardingPolicyInput {
                mode: match forwarded_header_policy.mode {
                    ForwardedHeaderPolicyMode::Preserve => ForwardedHeaderMode::Preserve,
                    ForwardedHeaderPolicyMode::Append => ForwardedHeaderMode::Append,
                    ForwardedHeaderPolicyMode::Overwrite => ForwardedHeaderMode::Overwrite,
                },
            },
        },
    }
}

pub(crate) fn load_balancing_strategy_input(
    strategy: RuntimeLoadBalancingStrategy,
) -> Result<LoadBalancingStrategy, String> {
    match strategy {
        RuntimeLoadBalancingStrategy::RoundRobin => Ok(LoadBalancingStrategy::RoundRobin),
        RuntimeLoadBalancingStrategy::ConsistentHash => Ok(LoadBalancingStrategy::ConsistentHash),
        RuntimeLoadBalancingStrategy::Random => Ok(LoadBalancingStrategy::Random),
        RuntimeLoadBalancingStrategy::LeastConnections => {
            Ok(LoadBalancingStrategy::LeastConnections)
        }
        RuntimeLoadBalancingStrategy::LatencyAware => Ok(LoadBalancingStrategy::LatencyAware),
        RuntimeLoadBalancingStrategy::StickyCid => Ok(LoadBalancingStrategy::StickyCid),
        RuntimeLoadBalancingStrategy::Other => {
            Err("unsupported load balancing strategy".to_string())
        }
    }
}

fn request_key_input(input: &RuntimeRequestKeySpec) -> RequestKeyInput {
    match input {
        RuntimeRequestKeySpec::Path => RequestKeyInput::Path,
        RuntimeRequestKeySpec::Authority => RequestKeyInput::Authority,
        RuntimeRequestKeySpec::Method => RequestKeyInput::Method,
        RuntimeRequestKeySpec::Cid => RequestKeyInput::Cid,
        RuntimeRequestKeySpec::StickyCid => RequestKeyInput::StickyCid,
        RuntimeRequestKeySpec::PeerIp => RequestKeyInput::PeerIp,
        RuntimeRequestKeySpec::ClientIp => RequestKeyInput::ClientIp,
        RuntimeRequestKeySpec::BearerToken => RequestKeyInput::BearerToken,
        RuntimeRequestKeySpec::Header(name) => RequestKeyInput::Header(name.clone()),
        RuntimeRequestKeySpec::Cookie(name) => RequestKeyInput::Cookie(name.clone()),
        RuntimeRequestKeySpec::Query(name) => RequestKeyInput::Query(name.clone()),
    }
}

fn backend_input(index: usize, backend: &RuntimeBackend) -> BackendInput {
    BackendInput::new(
        backend.backend.id.clone(),
        backend.backend.address.clone(),
        index,
        BackendWeight::new(backend.backend.weight),
        backend.health_check.as_ref().map(|health| {
            BackendHealthInput::new(
                health.failure_threshold,
                health.success_threshold,
                health.cooldown,
                true,
            )
        }),
    )
}

pub(crate) fn load_balancing_backend_inputs(upstream: &RuntimeUpstream) -> Vec<BackendInput> {
    upstream
        .backends
        .iter()
        .enumerate()
        .map(|(index, backend)| backend_input(index, backend))
        .collect()
}

pub(crate) fn upstream_pool_from_runtime(
    upstream: &RuntimeUpstream,
) -> Result<UpstreamPool, String> {
    Ok(UpstreamPool::new(
        load_balancing_backend_inputs(upstream),
        load_balancing_strategy_input(upstream.load_balancing.strategy)?,
        upstream
            .load_balancing
            .key_spec
            .as_ref()
            .map(request_key_input),
    ))
}

fn upstream_tls_input(upstream: &RuntimeUpstream) -> UpstreamTlsInput {
    let tls = upstream.backend_tls_policy();
    UpstreamTlsInput {
        verify_certificates: tls.verify_certificates,
        verify_hostname: tls.strict_sni,
        ca_file_fingerprint_sha256: tls.ca_file_fingerprint_sha256.clone(),
        ca_dir_fingerprint_sha256: tls.ca_dir_fingerprint_sha256.clone(),
        ca_pem_blobs: tls.ca_pem_blobs().to_vec(),
        client_certificate_pem: tls.client_certificate_pem().map(|pem| pem.to_vec()),
        client_key_pem: tls.client_key_pem().map(|pem| pem.to_vec()),
        client_certificate_fingerprint_sha256: tls
            .client_certificate
            .as_ref()
            .map(|metadata| metadata.fingerprint_sha256.clone()),
        client_key_fingerprint_sha256: tls
            .client_key
            .as_ref()
            .map(|metadata| metadata.fingerprint_sha256.clone()),
    }
}

pub(crate) fn upstream_transport_inputs(config: &RuntimeConfig) -> Vec<UpstreamTransportInput> {
    let connection = &config.policies.transport.backend_connections;
    let timeouts = UpstreamTimeoutInput {
        connect: connection.connect_timeout,
        execution: connection.execution_timeout,
        pool_idle: connection.pool_idle_timeout,
    };
    let connection_limits = UpstreamConnectionLimitsInput {
        max_inflight: connection.max_inflight,
        max_idle: connection.max_idle_per_backend,
    };

    config
        .upstreams
        .values()
        .flat_map(|upstream| {
            let tls = upstream_tls_input(upstream);
            upstream.backends.iter().map(move |backend| {
                let uses_tls = backend.endpoint.canonical.scheme() == BackendScheme::Https;
                UpstreamTransportInput {
                    endpoint: UpstreamEndpointInput {
                        configured_address: backend.backend.address.clone(),
                        authority_host: backend.endpoint.authority_host.clone(),
                        authority_port: backend.endpoint.authority_port,
                        protocol: match backend.endpoint.transport_kind {
                            RuntimeBackendTransportKind::Http1 => UpstreamProtocol::Http1,
                            RuntimeBackendTransportKind::H2 => UpstreamProtocol::Http2,
                        },
                        tls: uses_tls,
                    },
                    tls: uses_tls.then(|| tls.clone()),
                    timeouts,
                    proxy: None,
                    connection_limits,
                }
            })
        })
        .collect()
}
