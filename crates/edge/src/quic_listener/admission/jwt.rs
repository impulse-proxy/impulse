use super::*;

#[cfg(test)]
pub(crate) fn validated_hs256_jwt_claims(
    token: &str,
    jwt: &RuntimeJwtAuth,
    now: SystemTime,
) -> Option<Value> {
    let validated = validate_jwt_token(token, jwt, now).ok()?;
    matches!(validated.algorithm, JwtAlgorithm::Hs256).then_some(validated.claims)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JwtValidationFailureReason {
    MalformedToken,
    MalformedHeader,
    MalformedClaims,
    MissingAlgorithm,
    AlgorithmNotAllowed,
    UnsupportedAlgorithm,
    MissingKid,
    MissingVerificationKey,
    AmbiguousVerificationKey,
    KeySourceUnavailable,
    PemKeyParseFailed,
    JwkKeyParseFailed,
    InvalidKeyType,
    UnsupportedCurve,
    KeyTooWeak,
    SignatureInvalid,
    MissingExpiration,
    TokenExpired,
    TokenNotYetValid,
    TokenIssuedInFuture,
    IssuerMismatch,
    AudienceMismatch,
}

impl JwtValidationFailureReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::MalformedToken => "malformed_token",
            Self::MalformedHeader => "malformed_header",
            Self::MalformedClaims => "malformed_claims",
            Self::MissingAlgorithm => "missing_algorithm",
            Self::AlgorithmNotAllowed => "algorithm_not_allowed",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
            Self::MissingKid => "missing_kid",
            Self::MissingVerificationKey => "missing_verification_key",
            Self::AmbiguousVerificationKey => "ambiguous_verification_key",
            Self::KeySourceUnavailable => "key_source_unavailable",
            Self::PemKeyParseFailed => "pem_key_parse_failed",
            Self::JwkKeyParseFailed => "jwk_key_parse_failed",
            Self::InvalidKeyType => "invalid_key_type",
            Self::UnsupportedCurve => "unsupported_curve",
            Self::KeyTooWeak => "key_too_weak",
            Self::SignatureInvalid => "signature_invalid",
            Self::MissingExpiration => "missing_expiration",
            Self::TokenExpired => "token_expired",
            Self::TokenNotYetValid => "token_not_yet_valid",
            Self::TokenIssuedInFuture => "token_issued_in_future",
            Self::IssuerMismatch => "issuer_mismatch",
            Self::AudienceMismatch => "audience_mismatch",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JwtValidationFailure {
    pub(crate) reason: JwtValidationFailureReason,
}

impl JwtValidationFailure {
    pub(super) fn new(reason: JwtValidationFailureReason) -> Self {
        Self { reason }
    }
}

pub(super) fn log_jwt_validation_rejection(
    jwt: &RuntimeJwtAuth,
    token: &str,
    failure: &JwtValidationFailure,
) {
    let header = parse_compact_jwt(token)
        .ok()
        .and_then(|parsed| parse_jose_header(&parsed.header_bytes).ok());
    let algorithm = header
        .as_ref()
        .map(|header| jwt_algorithm_name(header.algorithm))
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
    let header = parse_compact_jwt(token)
        .ok()
        .and_then(|parsed| parse_jose_header(&parsed.header_bytes).ok());
    if matches!(
        failure.reason,
        JwtValidationFailureReason::AlgorithmNotAllowed
            | JwtValidationFailureReason::UnsupportedAlgorithm
            | JwtValidationFailureReason::MissingAlgorithm
    ) {
        let algorithm = header
            .as_ref()
            .map(|header| jwt_algorithm_name(header.algorithm))
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

#[derive(Debug, Clone)]
struct ParsedJwt<'a> {
    header_b64: &'a str,
    payload_b64: &'a str,
    header_bytes: Vec<u8>,
    payload_bytes: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedJoseHeader {
    pub(crate) algorithm: JwtAlgorithm,
    pub(crate) kid: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ValidatedJwt {
    /// Retained for per-algorithm validation metrics and key-type confusion
    /// checks; only read from tests until those land.
    #[allow(dead_code)]
    pub(crate) algorithm: JwtAlgorithm,
    pub(crate) claims: Value,
}

pub(crate) fn validate_jwt_token(
    token: &str,
    jwt: &RuntimeJwtAuth,
    now: SystemTime,
) -> Result<ValidatedJwt, JwtValidationFailure> {
    let parsed = parse_compact_jwt(token)?;
    let header = parse_jose_header(&parsed.header_bytes)?;
    let algorithm = validate_jwt_algorithm_policy(jwt, header.algorithm)?;
    let key = match JwtKeyResolver::new(jwt, algorithm, header.kid.as_deref()).resolve() {
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
    verify_jwt_signature(&parsed, algorithm, key)?;
    let claims = parse_jwt_claims(&parsed.payload_bytes)?;
    validate_jwt_registered_claims(jwt, &claims, now)?;

    Ok(ValidatedJwt { algorithm, claims })
}

pub(super) fn jwt_algorithm_name(algorithm: JwtAlgorithm) -> &'static str {
    match algorithm {
        JwtAlgorithm::Hs256 => "HS256",
        JwtAlgorithm::Rs256 => "RS256",
        JwtAlgorithm::Es256 => "ES256",
    }
}

fn parse_compact_jwt(token: &str) -> Result<ParsedJwt<'_>, JwtValidationFailure> {
    let mut parts = token.split('.');
    let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(JwtValidationFailure::new(
            JwtValidationFailureReason::MalformedToken,
        ));
    };
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| JwtValidationFailure::new(JwtValidationFailureReason::MalformedHeader))?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| JwtValidationFailure::new(JwtValidationFailureReason::MalformedClaims))?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| JwtValidationFailure::new(JwtValidationFailureReason::MalformedToken))?;

    Ok(ParsedJwt {
        header_b64,
        payload_b64,
        header_bytes,
        payload_bytes,
        signature,
    })
}

pub(crate) fn parse_jose_header(
    header_bytes: &[u8],
) -> Result<ParsedJoseHeader, JwtValidationFailure> {
    let header = serde_json::from_slice::<Value>(header_bytes)
        .map_err(|_| JwtValidationFailure::new(JwtValidationFailureReason::MalformedHeader))?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| JwtValidationFailure::new(JwtValidationFailureReason::MissingAlgorithm))?;
    let algorithm = match alg {
        "HS256" => JwtAlgorithm::Hs256,
        "RS256" => JwtAlgorithm::Rs256,
        "ES256" => JwtAlgorithm::Es256,
        _ => {
            return Err(JwtValidationFailure::new(
                JwtValidationFailureReason::UnsupportedAlgorithm,
            ));
        }
    };

    Ok(ParsedJoseHeader {
        algorithm,
        kid: header
            .get("kid")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

fn validate_jwt_algorithm_policy(
    jwt: &RuntimeJwtAuth,
    algorithm: JwtAlgorithm,
) -> Result<JwtAlgorithm, JwtValidationFailure> {
    if !jwt.allowed_algorithms.contains(&algorithm) {
        return Err(JwtValidationFailure::new(
            JwtValidationFailureReason::AlgorithmNotAllowed,
        ));
    }
    match algorithm {
        JwtAlgorithm::Hs256 | JwtAlgorithm::Rs256 | JwtAlgorithm::Es256 => Ok(algorithm),
    }
}

fn verify_jwt_signature(
    parsed: &ParsedJwt<'_>,
    algorithm: JwtAlgorithm,
    key: JwtVerificationKey<'_>,
) -> Result<(), JwtValidationFailure> {
    match (algorithm, key) {
        (JwtAlgorithm::Hs256, JwtVerificationKey::Hs256Secret(secret)) => {
            let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
                return Err(JwtValidationFailure::new(
                    JwtValidationFailureReason::MissingVerificationKey,
                ));
            };
            mac.update(format!("{}.{}", parsed.header_b64, parsed.payload_b64).as_bytes());
            let expected = mac.finalize().into_bytes();
            if expected.len() != parsed.signature.len()
                || !bool::from(expected.as_slice().ct_eq(parsed.signature.as_slice()))
            {
                return Err(JwtValidationFailure::new(
                    JwtValidationFailureReason::SignatureInvalid,
                ));
            }
            Ok(())
        }
        (JwtAlgorithm::Rs256, JwtVerificationKey::RsaPublicKey(public_key)) => {
            let mut verifier =
                Verifier::new(MessageDigest::sha256(), &public_key).map_err(|_| {
                    JwtValidationFailure::new(JwtValidationFailureReason::SignatureInvalid)
                })?;
            verifier.set_rsa_padding(Padding::PKCS1).map_err(|_| {
                JwtValidationFailure::new(JwtValidationFailureReason::SignatureInvalid)
            })?;
            verifier
                .update(format!("{}.{}", parsed.header_b64, parsed.payload_b64).as_bytes())
                .map_err(|_| {
                    JwtValidationFailure::new(JwtValidationFailureReason::SignatureInvalid)
                })?;
            if !verifier.verify(&parsed.signature).map_err(|_| {
                JwtValidationFailure::new(JwtValidationFailureReason::SignatureInvalid)
            })? {
                return Err(JwtValidationFailure::new(
                    JwtValidationFailureReason::SignatureInvalid,
                ));
            }
            Ok(())
        }
        (JwtAlgorithm::Es256, JwtVerificationKey::EcP256PublicKey(public_key)) => {
            let der_signature = jose_es256_signature_to_der(&parsed.signature)?;
            let digest = Sha256::digest(format!("{}.{}", parsed.header_b64, parsed.payload_b64));
            let ecdsa_sig = EcdsaSig::from_der(&der_signature).map_err(|_| {
                JwtValidationFailure::new(JwtValidationFailureReason::SignatureInvalid)
            })?;
            if !ecdsa_sig.verify(&digest, &public_key).map_err(|_| {
                JwtValidationFailure::new(JwtValidationFailureReason::SignatureInvalid)
            })? {
                return Err(JwtValidationFailure::new(
                    JwtValidationFailureReason::SignatureInvalid,
                ));
            }
            Ok(())
        }
        (JwtAlgorithm::Hs256, JwtVerificationKey::RsaPublicKey(_))
        | (JwtAlgorithm::Hs256, JwtVerificationKey::EcP256PublicKey(_)) => Err(
            JwtValidationFailure::new(JwtValidationFailureReason::InvalidKeyType),
        ),
        (JwtAlgorithm::Rs256 | JwtAlgorithm::Es256, _) => Err(JwtValidationFailure::new(
            JwtValidationFailureReason::InvalidKeyType,
        )),
    }
}

fn parse_jwt_claims(payload_bytes: &[u8]) -> Result<Value, JwtValidationFailure> {
    serde_json::from_slice::<Value>(payload_bytes)
        .map_err(|_| JwtValidationFailure::new(JwtValidationFailureReason::MalformedClaims))
}

fn validate_jwt_registered_claims(
    jwt: &RuntimeJwtAuth,
    claims: &Value,
    now: SystemTime,
) -> Result<(), JwtValidationFailure> {
    let Ok(now_secs) = now.duration_since(UNIX_EPOCH).map(|value| value.as_secs()) else {
        return Err(JwtValidationFailure::new(
            JwtValidationFailureReason::MalformedClaims,
        ));
    };
    let clock_skew_secs = jwt.clock_skew.as_secs();
    let exp = claims
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or_else(|| JwtValidationFailure::new(JwtValidationFailureReason::MissingExpiration))?;
    if now_secs > exp.saturating_add(clock_skew_secs) {
        return Err(JwtValidationFailure::new(
            JwtValidationFailureReason::TokenExpired,
        ));
    }
    if claims
        .get("nbf")
        .and_then(Value::as_u64)
        .is_some_and(|nbf| now_secs.saturating_add(clock_skew_secs) < nbf)
    {
        return Err(JwtValidationFailure::new(
            JwtValidationFailureReason::TokenNotYetValid,
        ));
    }
    if claims
        .get("iat")
        .and_then(Value::as_u64)
        .is_some_and(|iat| now_secs.saturating_add(clock_skew_secs) < iat)
    {
        return Err(JwtValidationFailure::new(
            JwtValidationFailureReason::TokenIssuedInFuture,
        ));
    }
    if !jwt_issuer_matches(jwt, claims) {
        return Err(JwtValidationFailure::new(
            JwtValidationFailureReason::IssuerMismatch,
        ));
    }
    if !jwt_audience_matches(jwt, claims) {
        return Err(JwtValidationFailure::new(
            JwtValidationFailureReason::AudienceMismatch,
        ));
    }

    Ok(())
}

fn jwt_issuer_matches(jwt: &RuntimeJwtAuth, claims: &Value) -> bool {
    let expected = jwt_expected_issuers(jwt);
    if expected.is_empty() {
        return true;
    }
    let actual = claims.get("iss").and_then(Value::as_str);
    expected.into_iter().any(|issuer| actual == Some(issuer))
}

fn jwt_audience_matches(jwt: &RuntimeJwtAuth, claims: &Value) -> bool {
    let expected = jwt_expected_audiences(jwt);
    if expected.is_empty() {
        return true;
    }

    let Some(claim_aud) = claims.get("aud") else {
        return false;
    };
    match claim_aud {
        Value::String(value) => expected.contains(&value.as_str()),
        Value::Array(values) => values.iter().any(|value| {
            value
                .as_str()
                .is_some_and(|value| expected.contains(&value))
        }),
        _ => false,
    }
}

fn jwt_expected_issuers(jwt: &RuntimeJwtAuth) -> Vec<&str> {
    if let Some(issuer) = jwt.issuer.as_deref() {
        vec![issuer]
    } else {
        jwt.issuers.iter().map(String::as_str).collect()
    }
}

fn jwt_expected_audiences(jwt: &RuntimeJwtAuth) -> Vec<&str> {
    if let Some(audience) = jwt.audience.as_deref() {
        vec![audience]
    } else {
        jwt.audiences.iter().map(String::as_str).collect()
    }
}

pub(crate) fn jwt_claims_satisfy_rbac(policy: &RuntimeUpstreamPolicy, claims: &Value) -> bool {
    let scopes = jwt_string_claim_values(claims, &["scope", "scp"]);
    let roles = jwt_string_claim_values(claims, &["roles", "role"]);
    policy
        .upstream_auth
        .required_scopes
        .iter()
        .all(|required| scopes.contains(required))
        && policy
            .upstream_auth
            .required_roles
            .iter()
            .all(|required| roles.contains(required))
}

fn jwt_string_claim_values(claims: &Value, claim_names: &[&str]) -> HashSet<String> {
    let mut values = HashSet::new();
    for claim_name in claim_names {
        let Some(value) = claims.get(*claim_name) else {
            continue;
        };
        match value {
            Value::String(value) => {
                for item in value.split_whitespace() {
                    if !item.is_empty() {
                        values.insert(item.to_string());
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    if let Some(item) = item.as_str()
                        && !item.is_empty()
                    {
                        values.insert(item.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    values
}
