pub(crate) use impulse_policy::{JwtValidationFailure, JwtValidationFailureReason};

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedJoseHeader {
    pub(crate) algorithm: JwtAlgorithm,
    pub(crate) kid: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ValidatedJwt {
    pub(crate) algorithm: JwtAlgorithm,
    pub(crate) claims: Value,
}

#[cfg(test)]
pub(crate) fn validated_hs256_jwt_claims(
    token: &str,
    jwt: &RuntimeJwtAuth,
    now: SystemTime,
) -> Option<Value> {
    let validated = validate_jwt_token(token, jwt, now).ok()?;
    matches!(validated.algorithm, JwtAlgorithm::Hs256).then_some(validated.claims)
}

pub(crate) fn validate_jwt_token(
    token: &str,
    jwt: &RuntimeJwtAuth,
    now: SystemTime,
) -> Result<ValidatedJwt, JwtValidationFailure> {
    let parsed = impulse_policy::parse_jwt(
        token,
        crate::runtime::subsystem_mapping::jwt_allowed_algorithms(jwt),
    )?;
    let algorithm = config_algorithm(parsed.algorithm());
    let key = match JwtKeyResolver::new(jwt, algorithm, parsed.kid()).resolve() {
        JwtKeyResolution::Found(resolved) | JwtKeyResolution::StaleButUsable(resolved) => {
            resolved.key
        }
        JwtKeyResolution::KeyNotFound { .. } => {
            return Err(JwtValidationFailure::new(
                JwtValidationFailureReason::MissingVerificationKey,
            ));
        }
        JwtKeyResolution::SourceUnavailable { .. } => {
            return Err(JwtValidationFailure::new(
                JwtValidationFailureReason::KeySourceUnavailable,
            ));
        }
        JwtKeyResolution::ConfigurationInvalid { reason, .. } => {
            return Err(JwtValidationFailure::new(reason));
        }
    };
    let validated = impulse_policy::validate_parsed_jwt(
        parsed,
        key,
        crate::runtime::subsystem_mapping::jwt_policy_input(jwt),
        now,
    )?;
    Ok(ValidatedJwt {
        algorithm: config_algorithm(validated.algorithm),
        claims: validated.claims,
    })
}

pub(crate) fn parse_jose_header(
    header_bytes: &[u8],
) -> Result<ParsedJoseHeader, JwtValidationFailure> {
    let header = impulse_policy::parse_jose_header(header_bytes)?;
    Ok(ParsedJoseHeader {
        algorithm: config_algorithm(header.algorithm),
        kid: header.kid,
    })
}

pub(super) fn jwt_algorithm_name(algorithm: JwtAlgorithm) -> &'static str {
    match algorithm {
        JwtAlgorithm::Hs256 => "HS256",
        JwtAlgorithm::Rs256 => "RS256",
        JwtAlgorithm::Es256 => "ES256",
    }
}

pub(crate) fn jwt_claims_satisfy_rbac(policy: &RuntimeUpstreamPolicy, claims: &Value) -> bool {
    impulse_policy::jwt_claims_satisfy_requirements(
        claims,
        impulse_policy::JwtClaimsRequirements {
            required_scopes: &policy.upstream_auth.required_scopes,
            required_roles: &policy.upstream_auth.required_roles,
        },
    )
}

pub(super) fn log_jwt_validation_rejection(
    jwt: &RuntimeJwtAuth,
    token: &str,
    failure: &JwtValidationFailure,
) {
    let header = token_header(token);
    let algorithm = header
        .as_ref()
        .map(|header| header.algorithm.name())
        .unwrap_or("unknown");
    let kid = header
        .as_ref()
        .and_then(|header| header.kid.as_deref())
        .unwrap_or("none");
    if let Some(source) = JwtJwksSourceConfig::from_jwt(jwt) {
        let snapshot =
            JwtJwksSharedCache::shared().snapshot(&source.source_identity, Instant::now());
        let state = snapshot
            .as_ref()
            .map(|entry| jwt_jwks_cache_state_name(entry.state))
            .unwrap_or("missing");
        let cache_reason = snapshot
            .as_ref()
            .and_then(|entry| entry.last_failure_reason)
            .map(|reason| reason.as_str())
            .unwrap_or("none");
        let stale_expired = snapshot
            .as_ref()
            .is_some_and(jwt_jwks_cache_stale_window_expired);
        log::debug!(
            "JWT validation rejected request: reason={} alg={} kid={} jwks_source_id={} jwks_endpoint={} jwks_state={} jwks_failure_reason={} stale_window_expired={}",
            failure.reason.as_str(),
            algorithm,
            kid,
            source.source_identity,
            source.public_endpoint(),
            state,
            cache_reason,
            stale_expired
        );
        return;
    }
    log::debug!(
        "JWT validation rejected request: reason={} alg={} kid={}",
        failure.reason.as_str(),
        algorithm,
        kid
    );
}

pub(super) fn observe_jwt_validation_failure(
    jwt: &RuntimeJwtAuth,
    token: &str,
    failure: &JwtValidationFailure,
) {
    let Some(metrics) = current_jwt_jwks_metrics() else {
        return;
    };
    metrics
        .runtime_observations()
        .record_jwt_validation_failure(failure.reason.as_str());
    let header = token_header(token);
    if matches!(
        failure.reason,
        JwtValidationFailureReason::AlgorithmNotAllowed
            | JwtValidationFailureReason::UnsupportedAlgorithm
            | JwtValidationFailureReason::MissingAlgorithm
    ) {
        let algorithm = header
            .as_ref()
            .map(|header| header.algorithm.name())
            .unwrap_or("unknown");
        metrics
            .runtime_observations()
            .record_jwt_algorithm_rejection(algorithm);
    }
    if failure.reason == JwtValidationFailureReason::MissingVerificationKey
        && let Some(source) = JwtJwksSourceConfig::from_jwt(jwt)
        && header
            .as_ref()
            .and_then(|header| header.kid.as_deref())
            .is_some()
    {
        metrics
            .runtime_observations()
            .record_jwks_unknown_kid(&source.source_identity);
    }
}

fn token_header(token: &str) -> Option<impulse_policy::ParsedJoseHeader> {
    let parsed = impulse_policy::parse_jwt(token, all_algorithms()).ok()?;
    Some(impulse_policy::ParsedJoseHeader {
        algorithm: parsed.algorithm(),
        kid: parsed.kid().map(str::to_owned),
    })
}

fn all_algorithms() -> impulse_policy::JwtAllowedAlgorithms {
    impulse_policy::JwtAllowedAlgorithms {
        hs256: true,
        rs256: true,
        es256: true,
    }
}

fn config_algorithm(algorithm: impulse_policy::JwtAlgorithm) -> JwtAlgorithm {
    match algorithm {
        impulse_policy::JwtAlgorithm::Hs256 => JwtAlgorithm::Hs256,
        impulse_policy::JwtAlgorithm::Rs256 => JwtAlgorithm::Rs256,
        impulse_policy::JwtAlgorithm::Es256 => JwtAlgorithm::Es256,
    }
}
