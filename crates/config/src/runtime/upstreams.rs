use super::*;
use crate::validator::is_valid_https_or_loopback_http_url;

type RouteMatcherKey = RuntimeRouteMatchPolicy;

impl RuntimeUpstream {
    pub(super) fn from_config(
        config: &Config,
        name: &str,
        upstream: &Upstream,
        base_policies: &RuntimePolicySet,
        secret_resolver: &RuntimeSecretResolver,
    ) -> Result<Self, RuntimeConfigError> {
        let effective_tls = upstream
            .tls
            .clone()
            .unwrap_or_else(|| config.upstream_tls.clone());
        let load_balancing = RuntimeLoadBalancingPolicy::normalize(&upstream.load_balancing)?;
        let route = RuntimeRouteMatchPolicy::normalize(name, &upstream.route)?;
        let policy = RuntimeUpstreamPolicy {
            upstream_auth: RuntimeAuthPolicy::normalize(&upstream.auth, name)?,
            host: RuntimeHostPolicy(upstream.host_policy.clone()),
            forwarded_headers: RuntimeForwardedHeaderPolicy(upstream.forwarded_headers.clone()),
            response_compression: RuntimeResponseCompressionPolicy::normalize(
                name,
                &upstream.compression,
            )?,
            protocol: base_policies.admission.protocol.clone(),
        };
        let backends = upstream
            .backends
            .iter()
            .map(|backend| RuntimeBackend::normalize(name, backend))
            .collect::<Result<Vec<_>, _>>()?;

        // HTTP-only upstreams never establish a TLS connection, so TLS-backed
        // fields (CA bundle, client cert/key) are not resolved for them. This
        // avoids failing runtime lowering on stale or placeholder TLS config
        // that is simply irrelevant for a plaintext backend.
        let uses_https_backends = backends
            .iter()
            .any(|backend| backend.endpoint.transport_kind == RuntimeBackendTransportKind::H2);
        let backend_tls_policy = if uses_https_backends {
            RuntimeBackendTlsPolicy::from_effective_tls(
                &effective_tls,
                &format!("upstream '{name}' tls"),
                secret_resolver,
            )?
        } else {
            RuntimeBackendTlsPolicy::empty()
        };

        let runtime_upstream = Self {
            name: name.to_string(),
            load_balancing: load_balancing.clone(),
            route: route.clone(),
            policy,
            effective_tls: effective_tls.clone(),
            backend_tls_policy,
            backends,
        };

        Ok(runtime_upstream)
    }

    #[cfg(test)]
    pub(crate) fn as_config_upstream(&self) -> Upstream {
        Upstream {
            load_balancing: self.load_balancing.as_config(),
            auth: self.policy.upstream_auth.as_config(),
            host_policy: self.policy.host.0.clone(),
            forwarded_headers: self.policy.forwarded_headers.0.clone(),
            compression: self.policy.response_compression.as_config(),
            cache: Default::default(),
            tls: Some(self.effective_tls.clone()),
            route: self.route.as_config(),
            backends: self
                .backends
                .iter()
                .map(|backend| {
                    let mut config_backend = backend.backend.clone();
                    config_backend.health_check = backend
                        .health_check
                        .as_ref()
                        .map(RuntimeBackendHealthCheck::as_config);
                    config_backend
                })
                .collect(),
        }
    }
}

pub(super) fn normalize_upstreams(
    config: &Config,
    base_policies: &RuntimePolicySet,
) -> Result<HashMap<String, RuntimeUpstream>, RuntimeConfigError> {
    if config.upstream.is_empty() {
        return Err(RuntimeConfigError::ConfigInvalid(
            "no upstreams configured".to_string(),
        ));
    }

    validate_protocol_policy(&config.resilience.protocol)?;
    let secret_resolver = RuntimeSecretResolver::from_secrets_config(&config.secrets);

    let mut seen_route_matchers: HashMap<RouteMatcherKey, String> = HashMap::new();
    let mut seen_backend_origins: HashMap<String, (String, String)> = HashMap::new();
    let mut normalized = HashMap::new();

    let mut ordered_upstreams: Vec<(&String, &Upstream)> = config.upstream.iter().collect();
    ordered_upstreams.sort_by_key(|(upstream_name, _)| *upstream_name);

    for (upstream_name, upstream) in ordered_upstreams {
        validate_upstream_policy(config, upstream_name, upstream)?;

        let route_key = RuntimeRouteMatchPolicy::normalize(upstream_name, &upstream.route)?;
        if let Some(existing) = seen_route_matchers.insert(route_key.clone(), upstream_name.clone())
        {
            return Err(RuntimeConfigError::DuplicateRouteAmbiguity {
                upstream: upstream_name.clone(),
                existing_upstream: existing,
                host: route_key.host.clone(),
                path_prefix: route_key.path_prefix.clone(),
                method: route_key.method.clone(),
            });
        }

        let runtime_upstream = RuntimeUpstream::from_config(
            config,
            upstream_name.as_str(),
            upstream,
            base_policies,
            &secret_resolver,
        )?;
        let mut upstream_uses_https_backends = false;

        for backend in &runtime_upstream.backends {
            if matches!(
                backend.endpoint.transport_kind,
                RuntimeBackendTransportKind::H2
            ) {
                upstream_uses_https_backends = true;
            }

            if let Some((existing_upstream, existing_backend)) = seen_backend_origins.insert(
                backend.endpoint.origin.clone(),
                (upstream_name.clone(), backend.backend.id.clone()),
            ) {
                return Err(RuntimeConfigError::BackendAddressInvalid {
                    upstream: upstream_name.clone(),
                    backend: backend.backend.id.clone(),
                    address: backend.endpoint.origin.clone(),
                    reason: format!(
                        "conflicts with upstream '{}' backend '{}'",
                        existing_upstream, existing_backend
                    ),
                });
            }
        }

        if upstream_uses_https_backends {
            validate_runtime_upstream_tls(upstream_name, &runtime_upstream.effective_tls, true)?;
        } else {
            validate_runtime_upstream_tls(upstream_name, &runtime_upstream.effective_tls, false)?;
        }

        normalized.insert(upstream_name.clone(), runtime_upstream);
    }

    Ok(normalized)
}

impl RuntimeBackend {
    pub(super) fn normalize(
        upstream_name: &str,
        backend: &Backend,
    ) -> Result<Self, RuntimeConfigError> {
        if backend.id.trim().is_empty() {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "upstream '{upstream_name}' contains an empty backend id"
            )));
        }
        if backend.address.trim().is_empty() {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "backend '{}' in upstream '{}' has an empty address",
                backend.id, upstream_name
            )));
        }

        Ok(Self {
            backend: backend.clone(),
            endpoint: RuntimeBackendEndpoint::normalize(
                upstream_name,
                backend.id.as_str(),
                backend.address.as_str(),
            )?,
            health_check: backend
                .health_check
                .as_ref()
                .map(|health_check| {
                    RuntimeBackendHealthCheck::normalize(
                        upstream_name,
                        backend.id.as_str(),
                        health_check,
                    )
                })
                .transpose()?,
        })
    }
}

fn validate_protocol_policy(policy: &ProtocolPolicy) -> Result<(), RuntimeConfigError> {
    if policy.max_headers_count == 0 {
        return Err(RuntimeConfigError::ConfigInvalid(
            "resilience.protocol.max_headers_count must be greater than 0".to_string(),
        ));
    }
    if policy.max_headers_bytes == 0 {
        return Err(RuntimeConfigError::ConfigInvalid(
            "resilience.protocol.max_headers_bytes must be greater than 0".to_string(),
        ));
    }
    if policy
        .allowed_methods
        .iter()
        .any(|method| method.trim().is_empty())
    {
        return Err(RuntimeConfigError::ConfigInvalid(
            "resilience.protocol.allowed_methods must not contain empty values".to_string(),
        ));
    }
    if policy
        .denied_path_prefixes
        .iter()
        .any(|prefix| prefix.is_empty() || !prefix.starts_with('/'))
    {
        return Err(RuntimeConfigError::ConfigInvalid(
            "resilience.protocol.denied_path_prefixes must contain '/'-prefixed paths".to_string(),
        ));
    }
    if !policy.allow_connect
        && (!policy.connect_allowed_ports.is_empty()
            || !policy.connect_allowed_authorities.is_empty())
    {
        return Err(RuntimeConfigError::UnsupportedPolicyCombination(
            "resilience.protocol.connect_allowed_ports/connect_allowed_authorities require allow_connect=true"
                .to_string(),
        ));
    }
    if policy.connect_allowed_ports.contains(&0) {
        return Err(RuntimeConfigError::ConfigInvalid(
            "resilience.protocol.connect_allowed_ports must contain ports in range 1-65535"
                .to_string(),
        ));
    }
    if policy
        .connect_allowed_authorities
        .iter()
        .any(|authority| !is_valid_connect_authority(authority))
    {
        return Err(RuntimeConfigError::ConfigInvalid(
            "resilience.protocol.connect_allowed_authorities must contain authority-form host:port targets"
                .to_string(),
        ));
    }
    if policy.allow_0rtt && policy.early_data_safe_methods.is_empty() {
        return Err(RuntimeConfigError::UnsupportedPolicyCombination(
            "resilience.protocol.early_data_safe_methods must be non-empty when allow_0rtt=true"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_runtime_external_auth_headers(
    upstream_name: &str,
    field_prefix: &str,
    request_headers: &[crate::config::ExternalAuthRequestHeader],
    response_header_allowlist: &[String],
) -> Result<(), RuntimeConfigError> {
    let mut seen_request_headers = std::collections::HashSet::new();
    for header in request_headers {
        let header_name = header.name.trim();
        if header_name.is_empty() {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "upstream '{upstream_name}' {field_prefix}.request_headers[].name must be non-empty"
            )));
        }
        if http::header::HeaderName::from_bytes(header_name.as_bytes()).is_err() {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "upstream '{upstream_name}' {field_prefix}.request_headers[].name must be a valid HTTP header name"
            )));
        }
        if http::HeaderValue::from_str(header.value.as_str()).is_err() {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "upstream '{upstream_name}' {field_prefix}.request_headers[].value must be a valid HTTP header value"
            )));
        }
        if !seen_request_headers.insert(header_name.to_ascii_lowercase()) {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "upstream '{upstream_name}' {field_prefix}.request_headers contains duplicate header names"
            )));
        }
    }

    let mut seen_allowed_headers = std::collections::HashSet::new();
    for header_name in response_header_allowlist {
        let header_name = header_name.trim();
        if header_name.is_empty() {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "upstream '{upstream_name}' {field_prefix}.response_header_allowlist[] must be non-empty"
            )));
        }
        if http::header::HeaderName::from_bytes(header_name.as_bytes()).is_err() {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "upstream '{upstream_name}' {field_prefix}.response_header_allowlist[] must be a valid HTTP header name"
            )));
        }
        if !seen_allowed_headers.insert(header_name.to_ascii_lowercase()) {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "upstream '{upstream_name}' {field_prefix}.response_header_allowlist contains duplicate header names"
            )));
        }
    }

    Ok(())
}

fn validate_upstream_policy(
    config: &Config,
    upstream_name: &str,
    upstream: &Upstream,
) -> Result<(), RuntimeConfigError> {
    match upstream.host_policy.mode {
        UpstreamHostPolicyMode::PassThrough | UpstreamHostPolicyMode::Upstream => {
            if upstream.host_policy.host.is_some() {
                return Err(RuntimeConfigError::UnsupportedPolicyCombination(format!(
                    "upstream '{upstream_name}' sets host_policy.host but mode is not rewrite"
                )));
            }
        }
        UpstreamHostPolicyMode::Rewrite => match upstream.host_policy.host.as_deref() {
            Some(host) if valid_static_host_header(host) => {}
            _ => {
                return Err(RuntimeConfigError::UnsupportedPolicyCombination(format!(
                    "upstream '{upstream_name}' requires a valid non-empty host_policy.host when mode=rewrite"
                )));
            }
        },
    }

    if let Some(path) = upstream.route.path_prefix.as_deref()
        && (path.is_empty() || !path.starts_with('/'))
    {
        return Err(RuntimeConfigError::ConfigInvalid(format!(
            "upstream '{upstream_name}' has an invalid route.path_prefix '{}'",
            path
        )));
    }

    if normalized_route_method(upstream.route.method.as_deref()).as_deref() == Some("CONNECT")
        && !config.resilience.protocol.allow_connect
    {
        return Err(RuntimeConfigError::UnsupportedPolicyCombination(format!(
            "upstream '{upstream_name}' routes CONNECT but resilience.protocol.allow_connect=false"
        )));
    }

    if let Some(api_key) = upstream.auth.api_key.as_ref() {
        if api_key.header_name.trim().is_empty() {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "upstream '{upstream_name}' auth.api_key.header_name must be non-empty"
            )));
        }
        if http::header::HeaderName::from_bytes(api_key.header_name.trim().as_bytes()).is_err() {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "upstream '{upstream_name}' auth.api_key.header_name must be a valid HTTP header name"
            )));
        }
        if api_key.keys.is_empty() || api_key.keys.iter().any(|value| value.trim().is_empty()) {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "upstream '{upstream_name}' auth.api_key.keys must contain at least one non-empty key"
            )));
        }
        let mut seen_api_keys = std::collections::HashSet::new();
        for key in &api_key.keys {
            if !seen_api_keys.insert(key.trim().to_string()) {
                return Err(RuntimeConfigError::ConfigInvalid(format!(
                    "upstream '{upstream_name}' auth.api_key.keys contains duplicate values"
                )));
            }
        }
    }

    if let Some(external_auth) = upstream.auth.external_auth.as_ref() {
        if upstream.auth.api_key.is_some() || upstream.auth.jwt.is_some() {
            return Err(RuntimeConfigError::UnsupportedPolicyCombination(format!(
                "upstream '{upstream_name}' auth.external_auth cannot be combined with auth.api_key or auth.jwt in v1"
            )));
        }
        if !upstream.auth.required_scopes.is_empty() || !upstream.auth.required_roles.is_empty() {
            return Err(RuntimeConfigError::UnsupportedPolicyCombination(format!(
                "upstream '{upstream_name}' auth.external_auth cannot be combined with auth.required_scopes or auth.required_roles in v1"
            )));
        }

        match external_auth {
            crate::config::ExternalAuth::Http {
                endpoint,
                request_headers,
                response_header_allowlist,
                timeout_ms,
                ..
            } => {
                let valid_endpoint = is_valid_https_or_loopback_http_url(endpoint);
                if !valid_endpoint {
                    return Err(RuntimeConfigError::ConfigInvalid(format!(
                        "upstream '{upstream_name}' auth.external_auth.http.endpoint must be an absolute https URL or loopback http URL"
                    )));
                }
                validate_runtime_external_auth_headers(
                    upstream_name,
                    "auth.external_auth.http",
                    request_headers,
                    response_header_allowlist,
                )?;
                if *timeout_ms == 0 {
                    return Err(RuntimeConfigError::ConfigInvalid(format!(
                        "upstream '{upstream_name}' auth.external_auth.http.timeout_ms must be greater than 0"
                    )));
                }
            }
            crate::config::ExternalAuth::Oidc {
                discovery_url,
                issuer_url,
                client_id,
                client_secret,
                audience,
                scopes,
                request_headers,
                response_header_allowlist,
                timeout_ms,
                ..
            } => {
                let has_discovery_url = discovery_url
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty());
                let has_issuer_url = issuer_url
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty());
                if !has_discovery_url && !has_issuer_url {
                    return Err(RuntimeConfigError::ConfigInvalid(format!(
                        "upstream '{upstream_name}' auth.external_auth.oidc requires discovery_url or issuer_url"
                    )));
                }
                if let Some(discovery_url) = discovery_url.as_deref() {
                    let valid_discovery_url = is_valid_https_or_loopback_http_url(discovery_url);
                    if !discovery_url.trim().is_empty() && !valid_discovery_url {
                        return Err(RuntimeConfigError::ConfigInvalid(format!(
                            "upstream '{upstream_name}' auth.external_auth.oidc.discovery_url must be an absolute https URL or loopback http URL"
                        )));
                    }
                }
                if let Some(issuer_url) = issuer_url.as_deref() {
                    let valid_issuer_url = is_valid_https_or_loopback_http_url(issuer_url);
                    if !issuer_url.trim().is_empty() && !valid_issuer_url {
                        return Err(RuntimeConfigError::ConfigInvalid(format!(
                            "upstream '{upstream_name}' auth.external_auth.oidc.issuer_url must be an absolute https URL or loopback http URL"
                        )));
                    }
                }
                if client_id.trim().is_empty() {
                    return Err(RuntimeConfigError::ConfigInvalid(format!(
                        "upstream '{upstream_name}' auth.external_auth.oidc.client_id must be non-empty"
                    )));
                }
                if client_secret
                    .as_deref()
                    .is_some_and(|value| value.trim().is_empty())
                {
                    return Err(RuntimeConfigError::ConfigInvalid(format!(
                        "upstream '{upstream_name}' auth.external_auth.oidc.client_secret must be non-empty when provided"
                    )));
                }
                if audience
                    .as_deref()
                    .is_some_and(|value| value.trim().is_empty())
                {
                    return Err(RuntimeConfigError::ConfigInvalid(format!(
                        "upstream '{upstream_name}' auth.external_auth.oidc.audience must be non-empty when provided"
                    )));
                }
                if scopes.iter().any(|scope| scope.trim().is_empty()) {
                    return Err(RuntimeConfigError::ConfigInvalid(format!(
                        "upstream '{upstream_name}' auth.external_auth.oidc.scopes must not contain empty values"
                    )));
                }
                validate_runtime_external_auth_headers(
                    upstream_name,
                    "auth.external_auth.oidc",
                    request_headers,
                    response_header_allowlist,
                )?;
                if *timeout_ms == 0 {
                    return Err(RuntimeConfigError::ConfigInvalid(format!(
                        "upstream '{upstream_name}' auth.external_auth.oidc.timeout_ms must be greater than 0"
                    )));
                }
            }
        }
    }

    if let Some(jwt) = upstream.auth.jwt.as_ref() {
        let has_hs256 = jwt
            .allowed_algorithms
            .iter()
            .any(|alg| matches!(alg, crate::config::JwtAlgorithm::Hs256));
        let has_asymmetric_alg = jwt.allowed_algorithms.iter().any(|alg| {
            matches!(
                alg,
                crate::config::JwtAlgorithm::Rs256 | crate::config::JwtAlgorithm::Es256
            )
        });

        if jwt.allowed_algorithms.is_empty() {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "upstream '{upstream_name}' auth.jwt.allowed_algorithms must contain at least one algorithm"
            )));
        }
        if has_hs256 && jwt.secret.trim().is_empty() {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "upstream '{upstream_name}' auth.jwt.secret must be non-empty"
            )));
        }
        if !jwt.secret.trim().is_empty() && !has_hs256 {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "upstream '{upstream_name}' auth.jwt.secret requires auth.jwt.allowed_algorithms to include HS256"
            )));
        }
        if jwt
            .issuer
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "upstream '{upstream_name}' auth.jwt.issuer must be non-empty when provided"
            )));
        }
        if jwt
            .audience
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "upstream '{upstream_name}' auth.jwt.audience must be non-empty when provided"
            )));
        }
        if jwt.issuer.is_some() && jwt.issuers.is_some() {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "upstream '{upstream_name}' auth.jwt.issuer and auth.jwt.issuers cannot both be set"
            )));
        }
        if jwt.audience.is_some() && jwt.audiences.is_some() {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "upstream '{upstream_name}' auth.jwt.audience and auth.jwt.audiences cannot both be set"
            )));
        }
        if let Some(issuers) = jwt.issuers.as_ref()
            && (issuers.is_empty() || issuers.iter().any(|value| value.trim().is_empty()))
        {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "upstream '{upstream_name}' auth.jwt.issuers must be non-empty and must not contain empty values"
            )));
        }
        if let Some(audiences) = jwt.audiences.as_ref()
            && (audiences.is_empty() || audiences.iter().any(|value| value.trim().is_empty()))
        {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "upstream '{upstream_name}' auth.jwt.audiences must be non-empty and must not contain empty values"
            )));
        }
        if jwt
            .jwks_url
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "upstream '{upstream_name}' auth.jwt.jwks_url must be non-empty when provided"
            )));
        }
        if let Some(jwks_url) = jwt.jwks_url.as_deref() {
            let valid_jwks_url = crate::validator::is_valid_https_url(jwks_url);
            if !jwks_url.trim().is_empty() && !valid_jwks_url {
                return Err(RuntimeConfigError::ConfigInvalid(format!(
                    "upstream '{upstream_name}' auth.jwt.jwks_url must be an absolute https URL"
                )));
            }
        }
        if jwt.jwks_url.is_some() && !has_asymmetric_alg {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "upstream '{upstream_name}' auth.jwt.jwks_url requires auth.jwt.allowed_algorithms to include RS256 or ES256"
            )));
        }
        if !jwt.static_keys.is_empty() && !has_asymmetric_alg {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "upstream '{upstream_name}' auth.jwt.static_keys require auth.jwt.allowed_algorithms to include RS256 or ES256"
            )));
        }
        if jwt.jwks_url.is_some() {
            if jwt.jwks_refresh_interval_secs == 0 {
                return Err(RuntimeConfigError::ConfigInvalid(format!(
                    "upstream '{upstream_name}' auth.jwt.jwks_refresh_interval_secs must be greater than 0"
                )));
            }
            if jwt.jwks_request_timeout_ms == 0 {
                return Err(RuntimeConfigError::ConfigInvalid(format!(
                    "upstream '{upstream_name}' auth.jwt.jwks_request_timeout_ms must be greater than 0"
                )));
            }
            if jwt.jwks_cache_ttl_secs == 0 {
                return Err(RuntimeConfigError::ConfigInvalid(format!(
                    "upstream '{upstream_name}' auth.jwt.jwks_cache_ttl_secs must be greater than 0"
                )));
            }
        }
        for (index, key) in jwt.static_keys.iter().enumerate() {
            match key {
                crate::config::JwtVerificationKey::Pem {
                    kid,
                    public_key_pem,
                    ..
                } => {
                    if kid.as_deref().is_some_and(|value| value.trim().is_empty()) {
                        return Err(RuntimeConfigError::ConfigInvalid(format!(
                            "upstream '{upstream_name}' auth.jwt.static_keys[{index}].kid must be non-empty when provided"
                        )));
                    }
                    if public_key_pem.trim().is_empty() {
                        return Err(RuntimeConfigError::ConfigInvalid(format!(
                            "upstream '{upstream_name}' auth.jwt.static_keys[{index}].public_key_pem must be non-empty"
                        )));
                    }
                }
                crate::config::JwtVerificationKey::Jwk { kid, jwk, .. } => {
                    if kid.as_deref().is_some_and(|value| value.trim().is_empty()) {
                        return Err(RuntimeConfigError::ConfigInvalid(format!(
                            "upstream '{upstream_name}' auth.jwt.static_keys[{index}].kid must be non-empty when provided"
                        )));
                    }
                    if jwk.trim().is_empty() {
                        return Err(RuntimeConfigError::ConfigInvalid(format!(
                            "upstream '{upstream_name}' auth.jwt.static_keys[{index}].jwk must be non-empty"
                        )));
                    }
                }
            }
        }
        if jwt.secret.trim().is_empty() && jwt.static_keys.is_empty() && jwt.jwks_url.is_none() {
            return Err(RuntimeConfigError::ConfigInvalid(format!(
                "upstream '{upstream_name}' auth.jwt must configure at least one key source"
            )));
        }
    }
    if upstream
        .auth
        .required_scopes
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return Err(RuntimeConfigError::ConfigInvalid(format!(
            "upstream '{upstream_name}' auth.required_scopes must not contain empty values"
        )));
    }
    if upstream
        .auth
        .required_roles
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return Err(RuntimeConfigError::ConfigInvalid(format!(
            "upstream '{upstream_name}' auth.required_roles must not contain empty values"
        )));
    }
    if (!upstream.auth.required_scopes.is_empty() || !upstream.auth.required_roles.is_empty())
        && upstream.auth.jwt.is_none()
    {
        return Err(RuntimeConfigError::ConfigInvalid(format!(
            "upstream '{upstream_name}' auth.required_scopes/auth.required_roles require auth.jwt"
        )));
    }

    Ok(())
}

fn validate_runtime_upstream_tls(
    upstream_name: &str,
    tls: &UpstreamTls,
    uses_https_backends: bool,
) -> Result<(), RuntimeConfigError> {
    let has_client_certificate = tls
        .client_certificate
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        || tls.client_certificate_ref.is_some();
    let has_client_key = tls
        .client_key
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        || tls.client_key_ref.is_some();

    if has_client_certificate != has_client_key {
        return Err(RuntimeConfigError::UnsupportedPolicyCombination(format!(
            "upstream '{upstream_name}' tls.client_certificate and tls.client_key must be configured as a complete mTLS pair"
        )));
    }
    if (has_client_certificate || has_client_key) && !uses_https_backends {
        return Err(RuntimeConfigError::UnsupportedPolicyCombination(format!(
            "upstream '{upstream_name}' tls.client_certificate/tls.client_key require at least one HTTPS backend"
        )));
    }
    if !uses_https_backends {
        return Ok(());
    }
    if tls
        .ca_file
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(RuntimeConfigError::TlsMaterialInvalid(format!(
            "upstream '{upstream_name}' has an empty effective upstream_tls.ca_file"
        )));
    }
    if tls
        .ca_dir
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(RuntimeConfigError::TlsMaterialInvalid(format!(
            "upstream '{upstream_name}' has an empty effective upstream_tls.ca_dir"
        )));
    }
    Ok(())
}

fn normalized_route_method(method: Option<&str>) -> Option<String> {
    method
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_uppercase())
}

fn valid_static_host_header(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed == value
        && !trimmed.chars().any(|ch| ch.is_ascii_whitespace())
        && !trimmed.contains('/')
        && !trimmed.contains('?')
        && !trimmed.contains('#')
        && http::HeaderValue::from_str(trimmed).is_ok()
}

pub(super) fn normalize_sni_server_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.contains(':')
        || trimmed.contains('*')
        || trimmed.chars().any(char::is_whitespace)
    {
        return None;
    }
    let without_trailing_dot = trimmed.trim_end_matches('.');
    if without_trailing_dot.is_empty() {
        return None;
    }
    let ascii = idna::domain_to_ascii(without_trailing_dot).ok()?;
    if ascii.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(ascii.to_ascii_lowercase())
}

fn is_valid_connect_authority(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
        return false;
    }

    if let Some(rest) = trimmed.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return false;
        };
        let suffix = &rest[end + 1..];
        if !suffix.starts_with(':') || suffix.len() <= 1 {
            return false;
        }
        return suffix[1..].parse::<u16>().ok().is_some_and(|port| port > 0);
    }

    let Some((host, port)) = trimmed.rsplit_once(':') else {
        return false;
    };
    if host.is_empty() || host.contains(':') {
        return false;
    }
    port.parse::<u16>().ok().is_some_and(|value| value > 0)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::normalize_upstreams;
    use crate::{
        config::{
            ApiKeyAuth, Backend, Config, ExternalAuth, ExternalAuthFailureMode,
            ExternalAuthRequestHeader, ForwardedHeaderPolicy, Listen, LoadBalancing, Resilience,
            RouteAuth, RouteMatch, Tls, Upstream, UpstreamHostPolicy,
        },
        runtime::{RuntimeConfigError, RuntimePolicySet},
    };

    fn upstream(host: Option<&str>, path_prefix: &str, method: Option<&str>) -> Upstream {
        Upstream {
            load_balancing: LoadBalancing {
                lb_type: "round-robin".to_string(),
                key: None,
            },
            auth: RouteAuth::default(),
            host_policy: UpstreamHostPolicy::default(),
            forwarded_headers: ForwardedHeaderPolicy::default(),
            compression: Default::default(),
            cache: Default::default(),
            tls: None,
            route: RouteMatch {
                host: host.map(str::to_string),
                path_prefix: Some(path_prefix.to_string()),
                method: method.map(str::to_string),
            },
            backends: vec![Backend {
                id: "b1".to_string(),
                address: "http://127.0.0.1:7001".to_string(),
                weight: 1,
                health_check: None,
            }],
        }
    }

    fn config_with_upstreams(upstreams: HashMap<String, Upstream>) -> Config {
        Config {
            version: 1,
            listen: Listen {
                protocol: "http1".to_string(),
                tls: Tls {
                    cert: "/tmp/test-cert.pem".to_string(),
                    key: "/tmp/test-key.pem".to_string(),
                    ..Tls::default()
                },
                ..Listen::default()
            },
            listeners: Vec::new(),
            upstream: upstreams,
            load_balancing: None,
            upstream_tls: Default::default(),
            secrets: Default::default(),
            log: Default::default(),
            performance: Default::default(),
            observability: Default::default(),
            resilience: Resilience::default(),
            security: Default::default(),
        }
    }

    #[test]
    fn duplicate_route_ambiguity_is_reported_deterministically() {
        let mut first_order = HashMap::new();
        first_order.insert(
            "zeta".to_string(),
            upstream(Some("api.example.com"), "/v1", None),
        );
        first_order.insert(
            "alpha".to_string(),
            upstream(Some("api.example.com"), "/v1", None),
        );

        let mut second_order = HashMap::new();
        second_order.insert(
            "alpha".to_string(),
            upstream(Some("api.example.com"), "/v1", None),
        );
        second_order.insert(
            "zeta".to_string(),
            upstream(Some("api.example.com"), "/v1", None),
        );

        let first_config = config_with_upstreams(first_order);
        let second_config = config_with_upstreams(second_order);
        let first_policies = RuntimePolicySet::from_config(&first_config).expect("policies");
        let second_policies = RuntimePolicySet::from_config(&second_config).expect("policies");

        let first_err = normalize_upstreams(&first_config, &first_policies).expect_err("duplicate");
        let second_err =
            normalize_upstreams(&second_config, &second_policies).expect_err("duplicate");

        assert_eq!(first_err, second_err);
        assert_eq!(
            first_err,
            RuntimeConfigError::DuplicateRouteAmbiguity {
                upstream: "zeta".to_string(),
                existing_upstream: "alpha".to_string(),
                host: Some("api.example.com".to_string()),
                path_prefix: Some("/v1".to_string()),
                method: None,
            }
        );
    }

    #[test]
    fn connect_route_requires_allow_connect_during_normalization() {
        let config = config_with_upstreams(HashMap::from([(
            "tunnel".to_string(),
            upstream(None, "/", Some("CONNECT")),
        )]));
        let policies = RuntimePolicySet::from_config(&config).expect("policies");

        let err = normalize_upstreams(&config, &policies).expect_err("connect must be rejected");
        assert_eq!(
            err,
            RuntimeConfigError::UnsupportedPolicyCombination(
                "upstream 'tunnel' routes CONNECT but resilience.protocol.allow_connect=false"
                    .to_string()
            )
        );
    }

    #[test]
    fn connect_route_normalizes_when_protocol_policy_allows_it() {
        let mut config = config_with_upstreams(HashMap::from([(
            "tunnel".to_string(),
            upstream(None, "/", Some("connect")),
        )]));
        config.resilience.protocol.allow_connect = true;
        let policies = RuntimePolicySet::from_config(&config).expect("policies");

        let normalized = normalize_upstreams(&config, &policies).expect("normalized upstreams");
        assert_eq!(
            normalized
                .get("tunnel")
                .expect("tunnel upstream")
                .route
                .method
                .as_deref(),
            Some("CONNECT")
        );
    }

    #[test]
    fn external_auth_misconfiguration_is_rejected_during_normalization() {
        let mut invalid_header = upstream(None, "/", None);
        invalid_header.auth.external_auth = Some(ExternalAuth::Http {
            endpoint: "https://auth.example.com/check".to_string(),
            request_headers: vec![ExternalAuthRequestHeader {
                name: "bad header".to_string(),
                value: "value".to_string(),
            }],
            response_header_allowlist: vec!["x-auth-user".to_string()],
            timeout_ms: 1000,
            failure_mode: ExternalAuthFailureMode::FailClosed,
        });
        let config = config_with_upstreams(HashMap::from([("api".to_string(), invalid_header)]));
        let policies = RuntimePolicySet::from_config(&config).expect("policies");

        let err = normalize_upstreams(&config, &policies).expect_err("invalid external auth");
        assert_eq!(
            err,
            RuntimeConfigError::ConfigInvalid(
                "upstream 'api' auth.external_auth.http.request_headers[].name must be a valid HTTP header name"
                    .to_string()
            )
        );

        let mut duplicate_allowlist = upstream(None, "/", None);
        duplicate_allowlist.auth.external_auth = Some(ExternalAuth::Http {
            endpoint: "https://auth.example.com/check".to_string(),
            request_headers: Vec::new(),
            response_header_allowlist: vec!["x-auth-user".to_string(), "X-Auth-User".to_string()],
            timeout_ms: 1000,
            failure_mode: ExternalAuthFailureMode::FailClosed,
        });
        let config =
            config_with_upstreams(HashMap::from([("api".to_string(), duplicate_allowlist)]));
        let policies = RuntimePolicySet::from_config(&config).expect("policies");

        let err = normalize_upstreams(&config, &policies).expect_err("duplicate allowlist");
        assert_eq!(
            err,
            RuntimeConfigError::ConfigInvalid(
                "upstream 'api' auth.external_auth.http.response_header_allowlist contains duplicate header names"
                    .to_string()
            )
        );

        let mut invalid_oidc = upstream(None, "/", None);
        invalid_oidc.auth.external_auth = Some(ExternalAuth::Oidc {
            discovery_url: Some("http://issuer.example.com/oidc".to_string()),
            issuer_url: None,
            client_id: "edge-gateway".to_string(),
            client_secret: Some("secret-1".to_string()),
            client_secret_ref: None,
            audience: None,
            scopes: vec!["openid".to_string()],
            request_headers: Vec::new(),
            response_header_allowlist: Vec::new(),
            timeout_ms: 1_000,
            failure_mode: ExternalAuthFailureMode::FailClosed,
        });
        let config = config_with_upstreams(HashMap::from([("api".to_string(), invalid_oidc)]));
        let policies = RuntimePolicySet::from_config(&config).expect("policies");

        let err = normalize_upstreams(&config, &policies).expect_err("invalid oidc url");
        assert_eq!(
            err,
            RuntimeConfigError::ConfigInvalid(
                "upstream 'api' auth.external_auth.oidc.discovery_url must be an absolute https URL or loopback http URL"
                    .to_string()
            )
        );

        let mut invalid_jwks = upstream(None, "/", None);
        invalid_jwks.auth.jwt = Some(crate::config::JwtAuth {
            secret: String::new(),
            allowed_algorithms: vec![crate::config::JwtAlgorithm::Rs256],
            jwks_url: Some("http://issuer.example.com/.well-known/jwks.json".to_string()),
            ..crate::config::JwtAuth::default()
        });
        let config = config_with_upstreams(HashMap::from([("api".to_string(), invalid_jwks)]));
        let policies = RuntimePolicySet::from_config(&config).expect("policies");

        let err = normalize_upstreams(&config, &policies).expect_err("invalid jwks url");
        assert_eq!(
            err,
            RuntimeConfigError::ConfigInvalid(
                "upstream 'api' auth.jwt.jwks_url must be an absolute https URL".to_string()
            )
        );
    }

    #[test]
    fn external_auth_precedence_is_explicit_at_normalization_time() {
        let mut external_plus_api_key = upstream(None, "/", None);
        external_plus_api_key.auth = RouteAuth {
            api_key: Some(ApiKeyAuth {
                header_name: "x-api-key".to_string(),
                keys: vec!["secret".to_string()],
            }),
            jwt: None,
            external_auth: Some(ExternalAuth::Http {
                endpoint: "https://auth.example.com/check".to_string(),
                request_headers: Vec::new(),
                response_header_allowlist: Vec::new(),
                timeout_ms: 1000,
                failure_mode: ExternalAuthFailureMode::FailClosed,
            }),
            required_scopes: Vec::new(),
            required_roles: Vec::new(),
        };
        let config =
            config_with_upstreams(HashMap::from([("api".to_string(), external_plus_api_key)]));
        let policies = RuntimePolicySet::from_config(&config).expect("policies");

        let err = normalize_upstreams(&config, &policies).expect_err("external auth precedence");
        assert_eq!(
            err,
            RuntimeConfigError::UnsupportedPolicyCombination(
                "upstream 'api' auth.external_auth cannot be combined with auth.api_key or auth.jwt in v1"
                    .to_string()
            )
        );

        let mut external_plus_scopes = upstream(None, "/", None);
        external_plus_scopes.auth.external_auth = Some(ExternalAuth::Http {
            endpoint: "https://auth.example.com/check".to_string(),
            request_headers: Vec::new(),
            response_header_allowlist: Vec::new(),
            timeout_ms: 1000,
            failure_mode: ExternalAuthFailureMode::FailClosed,
        });
        external_plus_scopes.auth.required_scopes = vec!["read".to_string()];
        let config =
            config_with_upstreams(HashMap::from([("api".to_string(), external_plus_scopes)]));
        let policies = RuntimePolicySet::from_config(&config).expect("policies");

        let err = normalize_upstreams(&config, &policies).expect_err("external auth scope mix");
        assert_eq!(
            err,
            RuntimeConfigError::UnsupportedPolicyCombination(
                "upstream 'api' auth.external_auth cannot be combined with auth.required_scopes or auth.required_roles in v1"
                    .to_string()
            )
        );
    }
}
