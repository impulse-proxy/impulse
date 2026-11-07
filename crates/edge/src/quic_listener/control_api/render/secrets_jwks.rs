use std::collections::HashMap;

use impulse_config::config::SecretProvider;
#[cfg(feature = "jwt-auth")]
use impulse_config::runtime::RuntimeJwtAuth;

use super::{redaction::option_is_present, *};

#[cfg(feature = "jwt-auth")]
pub(super) fn build_auth_and_jwks_payloads(
    runtime_config: &impulse_config::runtime::RuntimeConfig,
) -> (Vec<ControlApiAuthProviderPayload>, ControlApiJwksPayload) {
    let jwks_sources = crate::runtime::jwks::snapshot_sources(runtime_config);
    let jwks_by_source_id = jwks_sources
        .iter()
        .map(|snapshot| (snapshot.source_id.as_str(), snapshot))
        .collect::<HashMap<_, _>>();

    let mut auth_providers = runtime_config
        .upstreams
        .iter()
        .map(|(name, upstream)| ControlApiAuthProviderPayload {
            upstream: name.clone(),
            jwt: upstream
                .policy
                .upstream_auth
                .jwt
                .as_ref()
                .map(|jwt| jwt_provider_payload(jwt, &jwks_by_source_id)),
        })
        .collect::<Vec<_>>();
    auth_providers.sort_by(|left, right| left.upstream.cmp(&right.upstream));

    let jwks = ControlApiJwksPayload {
        sources: jwks_sources
            .into_iter()
            .map(|snapshot| ControlApiJwksSourcePayload {
                jwks_source_id: snapshot.source_id,
                allowed_algorithms: snapshot.allowed_algorithms,
                startup_behavior: snapshot.startup_behavior,
                cache_state: snapshot.state,
                active_key_count: snapshot.active_key_count,
                age_seconds: snapshot.age_seconds,
                last_refresh_attempt_unix_seconds: snapshot.last_refresh_attempt_unix_seconds,
                last_refresh_success_unix_seconds: snapshot.last_refresh_success_unix_seconds,
                last_failure_reason: snapshot.last_failure_reason,
                last_error: snapshot.last_error,
            })
            .collect(),
    };

    (auth_providers, jwks)
}

#[cfg(not(feature = "jwt-auth"))]
pub(super) fn build_auth_and_jwks_payloads(
    _runtime_config: &impulse_config::runtime::RuntimeConfig,
) -> (Vec<ControlApiAuthProviderPayload>, ControlApiJwksPayload) {
    (
        Vec::new(),
        ControlApiJwksPayload {
            sources: Vec::new(),
        },
    )
}

pub(super) fn build_tls_upstreams(
    runtime_config: &impulse_config::runtime::RuntimeConfig,
) -> HashMap<String, ControlApiTlsUpstreamPayload> {
    runtime_config
        .upstreams
        .iter()
        .map(|(name, upstream)| {
            let tls_policy = upstream.backend_tls_policy();
            (
                name.clone(),
                ControlApiTlsUpstreamPayload {
                    verify_certificates: tls_policy.verify_certificates,
                    strict_sni: tls_policy.strict_sni,
                    custom_ca_file_configured: option_is_present(tls_policy.ca_file.as_deref()),
                    custom_ca_dir_configured: option_is_present(tls_policy.ca_dir.as_deref()),
                    client_certificate: tls_policy.client_certificate.as_ref().map(|metadata| {
                        ControlApiSecretMaterialPayload {
                            scope: format!("upstream.{name}.tls.client_certificate"),
                            source_kind: metadata.source_kind.as_str(),
                            last_loaded_at_unix_ms: metadata.loaded_at_unix_ms,
                            last_reload_status: "loaded".to_string(),
                            expiry_not_after_unix_seconds: tls_policy
                                .client_certificate_not_after_unix_seconds,
                        }
                    }),
                    client_key: tls_policy.client_key.as_ref().map(|metadata| {
                        ControlApiSecretMaterialPayload {
                            scope: format!("upstream.{name}.tls.client_key"),
                            source_kind: metadata.source_kind.as_str(),
                            last_loaded_at_unix_ms: metadata.loaded_at_unix_ms,
                            last_reload_status: "loaded".to_string(),
                            expiry_not_after_unix_seconds: None,
                        }
                    }),
                },
            )
        })
        .collect()
}

pub(super) fn build_secrets_payload(
    runtime_config: &impulse_config::runtime::RuntimeConfig,
) -> ControlApiSecretsPayload {
    ControlApiSecretsPayload {
        providers: runtime_config
            .secrets
            .providers
            .iter()
            .map(|(provider, config)| ControlApiSecretProviderPayload {
                provider: provider.clone(),
                kind: match config {
                    SecretProvider::File { .. } => "file",
                },
                base_dir_configured: match config {
                    SecretProvider::File { base_dir } => option_is_present(base_dir.as_deref()),
                },
                default_provider: runtime_config.secrets.default_provider.as_deref()
                    == Some(provider.as_str()),
            })
            .collect(),
        material: runtime_config
            .upstreams
            .iter()
            .flat_map(|(name, upstream)| {
                let tls_policy = upstream.backend_tls_policy();
                let mut material = Vec::new();
                if let Some(metadata) = tls_policy.client_certificate.as_ref() {
                    material.push(ControlApiSecretMaterialPayload {
                        scope: format!("upstream.{name}.tls.client_certificate"),
                        source_kind: metadata.source_kind.as_str(),
                        last_loaded_at_unix_ms: metadata.loaded_at_unix_ms,
                        last_reload_status: "loaded".to_string(),
                        expiry_not_after_unix_seconds: tls_policy
                            .client_certificate_not_after_unix_seconds,
                    });
                }
                if let Some(metadata) = tls_policy.client_key.as_ref() {
                    material.push(ControlApiSecretMaterialPayload {
                        scope: format!("upstream.{name}.tls.client_key"),
                        source_kind: metadata.source_kind.as_str(),
                        last_loaded_at_unix_ms: metadata.loaded_at_unix_ms,
                        last_reload_status: "loaded".to_string(),
                        expiry_not_after_unix_seconds: None,
                    });
                }
                material
            })
            .collect(),
    }
}

#[cfg(feature = "jwt-auth")]
pub(super) fn jwt_provider_payload(
    jwt: &RuntimeJwtAuth,
    jwks_by_source_id: &HashMap<&str, &impulse_policy::jwks::JwtJwksRuntimeSnapshot>,
) -> ControlApiJwtProviderPayload {
    let issuers = jwt
        .issuer
        .iter()
        .cloned()
        .chain(jwt.issuers.iter().cloned())
        .collect::<Vec<_>>();
    let audiences = jwt
        .audience
        .iter()
        .cloned()
        .chain(jwt.audiences.iter().cloned())
        .collect::<Vec<_>>();
    let jwks_snapshot = jwt
        .jwks_url
        .as_deref()
        .and_then(|_| crate::runtime::jwks::source_identity(jwt))
        .and_then(|source_id| jwks_by_source_id.get(source_id.as_str()).copied());
    let jwks_cache_state = jwks_snapshot.map(|snapshot| snapshot.state);
    let serving_from_stale_cache = jwks_cache_state.map(|state| {
        matches!(
            state,
            "stale" | "refresh_failed_retained" | "quarantined_retained"
        )
    });
    let usable_key_count = jwks_snapshot.map(|snapshot| snapshot.active_key_count);
    let jwks_active = jwks_snapshot.is_some_and(|snapshot| {
        snapshot.active_key_count > 0
            && !matches!(snapshot.state, "never_fetched" | "empty_unusable")
    });

    ControlApiJwtProviderPayload {
        provider_mode: jwt_provider_mode(jwt),
        allowed_algorithms: jwt
            .allowed_algorithms
            .iter()
            .map(|algorithm| jwt_algorithm_name(*algorithm).to_string())
            .collect(),
        require_kid: jwt.require_kid,
        issuers,
        audiences,
        static_key_count: jwt.static_keys.len(),
        jwks_configured: jwt.jwks_url.is_some(),
        jwks_active,
        jwks_cache_state,
        serving_from_stale_cache,
        usable_key_count,
        last_refresh_success_unix_seconds: jwks_snapshot
            .and_then(|snapshot| snapshot.last_refresh_success_unix_seconds),
        last_refresh_attempt_unix_seconds: jwks_snapshot
            .and_then(|snapshot| snapshot.last_refresh_attempt_unix_seconds),
        last_failure_reason: jwks_snapshot
            .and_then(|snapshot| snapshot.last_failure_reason.clone()),
    }
}

#[cfg(feature = "jwt-auth")]
fn jwt_provider_mode(jwt: &RuntimeJwtAuth) -> &'static str {
    let has_hs256 = !jwt.secret.is_empty();
    let has_static_asymmetric = !jwt.static_keys.is_empty();
    let has_jwks = jwt.jwks_url.is_some();
    match (has_hs256, has_static_asymmetric, has_jwks) {
        (true, false, false) => "hs256_only",
        (false, true, false) => "static_asymmetric",
        (false, false, true) => "remote_jwks",
        (false, true, true) => "hybrid_asymmetric",
        (true, true, false) | (true, false, true) | (true, true, true) => "hybrid",
        (false, false, false) => "unconfigured",
    }
}

#[cfg(feature = "jwt-auth")]
fn jwt_algorithm_name(algorithm: impulse_config::config::JwtAlgorithm) -> &'static str {
    match algorithm {
        impulse_config::config::JwtAlgorithm::Hs256 => "HS256",
        impulse_config::config::JwtAlgorithm::Rs256 => "RS256",
        impulse_config::config::JwtAlgorithm::Es256 => "ES256",
    }
}
