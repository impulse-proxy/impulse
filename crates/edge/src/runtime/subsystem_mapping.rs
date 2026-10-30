use impulse_bridge::{
    ForwardedHeaderMode, ForwardingPolicyInput, HostPolicyInput, HostPolicyMode, UpstreamScheme,
    UpstreamTargetInput,
    request::{RequestBuildPolicies, RequestBuildTarget},
};
use impulse_config::{
    backend_endpoint::{BackendEndpoint, BackendScheme},
    config::{
        ForwardedHeaderPolicy, ForwardedHeaderPolicyMode, JwtAlgorithm, UpstreamHostPolicy,
        UpstreamHostPolicyMode,
    },
    runtime::{
        RuntimeAuthPolicy, RuntimeBackend, RuntimeBackendTransportKind, RuntimeConfig,
        RuntimeJwtAuth, RuntimeLoadBalancingStrategy, RuntimeRequestKeySpec,
        RuntimeResponseCachePolicy, RuntimeResponseCompressionPolicy, RuntimeUpstream,
    },
};
use impulse_lb::{
    BackendHealthInput, BackendInput, BackendWeight, LoadBalancingStrategy, RequestKeyInput,
    upstream_pool::UpstreamPool,
};
use impulse_policy::{
    ApiKeyPolicyInput, JwtAllowedAlgorithms, JwtPolicyInput, ResponseCacheAuthInput,
    ResponseCachePolicyInput, ResponseCompressionPolicyInput,
};
use impulse_transport::{
    UpstreamConnectionLimitsInput, UpstreamEndpointInput, UpstreamProtocol, UpstreamTimeoutInput,
    UpstreamTlsInput, UpstreamTransportInput,
};

pub(crate) fn api_key_policy_input(policy: &RuntimeAuthPolicy) -> Option<ApiKeyPolicyInput<'_>> {
    policy
        .api_key
        .as_ref()
        .map(|api_key| ApiKeyPolicyInput::new(&api_key.header_name, &api_key.keys))
}

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

pub(crate) const fn response_cache_policy_input(
    policy: &RuntimeResponseCachePolicy,
) -> ResponseCachePolicyInput {
    ResponseCachePolicyInput {
        enabled: policy.enabled,
    }
}

pub(crate) fn response_cache_auth_input(policy: &RuntimeAuthPolicy) -> ResponseCacheAuthInput {
    ResponseCacheAuthInput {
        api_key: policy.api_key.is_some(),
        jwt: policy.jwt.is_some(),
        external_auth: policy.external_auth.is_some(),
        required_scopes: !policy.required_scopes.is_empty(),
        required_roles: !policy.required_roles.is_empty(),
    }
}

pub(crate) const fn response_compression_policy_input(
    policy: &RuntimeResponseCompressionPolicy,
) -> ResponseCompressionPolicyInput {
    ResponseCompressionPolicyInput {
        enabled: policy.enabled,
        minimum_size_bytes: policy.minimum_size_bytes,
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
