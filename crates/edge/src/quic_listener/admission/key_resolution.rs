use impulse_policy::JwtVerificationKey;

use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum JwtVerificationKeySource {
    StaticSecret,
    StaticAsymmetricKeys,
    RemoteJwks { source_identity: String },
}
#[derive(Debug, Clone)]
pub(super) struct ResolvedJwtVerificationKey<'a> {
    pub(super) source: JwtVerificationKeySource,
    pub(super) key: JwtVerificationKey<'a>,
}

#[derive(Debug, Clone)]
pub(super) enum JwtKeyResolution<'a> {
    Found(ResolvedJwtVerificationKey<'a>),
    StaleButUsable(ResolvedJwtVerificationKey<'a>),
    KeyNotFound {
        source: JwtVerificationKeySource,
    },
    SourceUnavailable {
        source: JwtVerificationKeySource,
    },
    ConfigurationInvalid {
        source: JwtVerificationKeySource,
        reason: JwtValidationFailureReason,
    },
}
pub(super) struct JwtKeyResolver<'a> {
    jwt: &'a RuntimeJwtAuth,
    algorithm: JwtAlgorithm,
    kid: Option<&'a str>,
    jwks_cache: &'static JwtJwksSharedCache,
}

impl<'a> JwtKeyResolver<'a> {
    pub(super) fn new(
        jwt: &'a RuntimeJwtAuth,
        algorithm: JwtAlgorithm,
        kid: Option<&'a str>,
    ) -> Self {
        Self {
            jwt,
            algorithm,
            kid,
            jwks_cache: JwtJwksSharedCache::shared(),
        }
    }

    pub(super) fn resolve(&self) -> JwtKeyResolution<'a> {
        if self.jwt.require_kid && self.kid.is_none() {
            return JwtKeyResolution::ConfigurationInvalid {
                source: match self.algorithm {
                    JwtAlgorithm::Hs256 => JwtVerificationKeySource::StaticSecret,
                    JwtAlgorithm::Rs256 | JwtAlgorithm::Es256 => {
                        if self.jwt.jwks_url.is_some() {
                            JwtVerificationKeySource::RemoteJwks {
                                source_identity: JwtJwksSourceConfig::from_jwt(self.jwt)
                                    .map(|source| source.source_identity)
                                    .unwrap_or_default(),
                            }
                        } else {
                            JwtVerificationKeySource::StaticAsymmetricKeys
                        }
                    }
                },
                reason: JwtValidationFailureReason::MissingKid,
            };
        }

        match self.algorithm {
            JwtAlgorithm::Hs256 => self.resolve_static_secret_source(),
            JwtAlgorithm::Rs256 | JwtAlgorithm::Es256 => self.resolve_asymmetric_sources(),
        }
    }

    fn resolve_static_secret_source(&self) -> JwtKeyResolution<'a> {
        if self.jwt.secret.is_empty() {
            return JwtKeyResolution::KeyNotFound {
                source: JwtVerificationKeySource::StaticSecret,
            };
        }
        JwtKeyResolution::Found(ResolvedJwtVerificationKey {
            source: JwtVerificationKeySource::StaticSecret,
            key: JwtVerificationKey::Hs256Secret(self.jwt.secret.as_str()),
        })
    }

    fn resolve_asymmetric_sources(&self) -> JwtKeyResolution<'a> {
        let mut found = Vec::new();
        let mut stale = Vec::new();
        let mut source_unavailable = None;
        let mut key_not_found = None;

        if !self.jwt.static_keys.is_empty() {
            match self.resolve_static_asymmetric_source() {
                JwtKeyResolution::Found(resolved) => found.push(resolved),
                JwtKeyResolution::StaleButUsable(resolved) => stale.push(resolved),
                JwtKeyResolution::KeyNotFound { source } => key_not_found = Some(source),
                JwtKeyResolution::SourceUnavailable { source } => source_unavailable = Some(source),
                JwtKeyResolution::ConfigurationInvalid { source, reason } => {
                    return JwtKeyResolution::ConfigurationInvalid { source, reason };
                }
            }
        }

        if let Some(source) = JwtJwksSourceConfig::from_jwt(self.jwt) {
            match self.resolve_remote_jwks_source(&source) {
                JwtKeyResolution::Found(resolved) => found.push(resolved),
                JwtKeyResolution::StaleButUsable(resolved) => stale.push(resolved),
                JwtKeyResolution::KeyNotFound { source } => key_not_found = Some(source),
                JwtKeyResolution::SourceUnavailable { source } => source_unavailable = Some(source),
                JwtKeyResolution::ConfigurationInvalid { source, reason } => {
                    return JwtKeyResolution::ConfigurationInvalid { source, reason };
                }
            }
        }

        if found.len() + stale.len() > 1 {
            return JwtKeyResolution::ConfigurationInvalid {
                source: if found
                    .first()
                    .map(|resolved| {
                        matches!(resolved.source, JwtVerificationKeySource::RemoteJwks { .. })
                    })
                    .unwrap_or(false)
                {
                    found[0].source.clone()
                } else if let Some(resolved) = stale.first() {
                    resolved.source.clone()
                } else {
                    JwtVerificationKeySource::StaticAsymmetricKeys
                },
                reason: JwtValidationFailureReason::AmbiguousVerificationKey,
            };
        }

        if let Some(resolved) = found.into_iter().next() {
            return JwtKeyResolution::Found(resolved);
        }
        if let Some(resolved) = stale.into_iter().next() {
            return JwtKeyResolution::StaleButUsable(resolved);
        }
        if let Some(source) = source_unavailable {
            return JwtKeyResolution::SourceUnavailable { source };
        }
        if let Some(source) = key_not_found {
            return JwtKeyResolution::KeyNotFound { source };
        }

        JwtKeyResolution::KeyNotFound {
            source: if let Some(source) = JwtJwksSourceConfig::from_jwt(self.jwt) {
                JwtVerificationKeySource::RemoteJwks {
                    source_identity: source.source_identity,
                }
            } else {
                JwtVerificationKeySource::StaticAsymmetricKeys
            },
        }
    }

    fn resolve_static_asymmetric_source(&self) -> JwtKeyResolution<'a> {
        resolve_matching_asymmetric_key(
            &self.jwt.static_keys,
            self.algorithm,
            self.kid,
            JwtVerificationKeySource::StaticAsymmetricKeys,
            JwtJwksCacheState::Fresh,
        )
    }

    fn resolve_remote_jwks_source(
        &self,
        source_config: &JwtJwksSourceConfig,
    ) -> JwtKeyResolution<'a> {
        self.jwks_cache.register_source(source_config.clone());
        let source = JwtVerificationKeySource::RemoteJwks {
            source_identity: source_config.source_identity.clone(),
        };
        let Some(entry) = self
            .jwks_cache
            .snapshot(&source_config.source_identity, Instant::now())
        else {
            return JwtKeyResolution::SourceUnavailable { source };
        };

        match entry.state {
            JwtJwksCacheState::NeverFetched => JwtKeyResolution::SourceUnavailable { source },
            JwtJwksCacheState::EmptyUnusable => {
                if matches!(
                    entry.last_failure_reason,
                    Some(
                        JwtJwksFetchFailureReason::MalformedDocument
                            | JwtJwksFetchFailureReason::AmbiguousDuplicateKid
                    )
                ) {
                    JwtKeyResolution::ConfigurationInvalid {
                        source,
                        reason: JwtValidationFailureReason::JwkKeyParseFailed,
                    }
                } else {
                    JwtKeyResolution::SourceUnavailable { source }
                }
            }
            JwtJwksCacheState::Fresh
            | JwtJwksCacheState::Stale
            | JwtJwksCacheState::RefreshFailedRetained
            | JwtJwksCacheState::QuarantinedRetained => {
                let resolution = resolve_matching_asymmetric_key(
                    &entry.active_keys,
                    self.algorithm,
                    self.kid,
                    source.clone(),
                    entry.state,
                );
                if matches!(resolution, JwtKeyResolution::StaleButUsable(_)) {
                    log::debug!(
                        "Serving JWT verification from stale JWKS cache source_id={} endpoint={} state={} kid={} alg={}",
                        source_config.source_identity,
                        source_config.public_endpoint(),
                        jwt_jwks_cache_state_name(entry.state),
                        self.kid.unwrap_or("none"),
                        jwt_algorithm_name(self.algorithm)
                    );
                }
                if matches!(resolution, JwtKeyResolution::KeyNotFound { .. }) && self.kid.is_some()
                {
                    log::debug!(
                        "Unknown JWKS kid encountered source_id={} endpoint={} kid={} alg={} action=trigger_refresh_hint",
                        source_config.source_identity,
                        source_config.public_endpoint(),
                        self.kid.unwrap_or("none"),
                        jwt_algorithm_name(self.algorithm)
                    );
                    maybe_spawn_jwks_on_demand_refresh(&entry.source);
                }
                resolution
            }
        }
    }
}

fn resolve_matching_asymmetric_key<'a>(
    keys: &[RuntimeJwtVerificationKey],
    algorithm: JwtAlgorithm,
    requested_kid: Option<&str>,
    source: JwtVerificationKeySource,
    cache_state: JwtJwksCacheState,
) -> JwtKeyResolution<'a> {
    let mut candidates = Vec::new();
    for key in keys {
        let metadata = match static_key_metadata(key) {
            Ok(metadata) => metadata,
            Err(failure) => {
                return JwtKeyResolution::ConfigurationInvalid {
                    source,
                    reason: failure.reason,
                };
            }
        };
        let effective_kid = metadata
            .kid
            .as_deref()
            .or_else(|| static_key_config_kid(key));
        // A token without a `kid` filters on algorithm alone, and is only
        // accepted when exactly one compatible key survives; the ambiguity
        // check below rejects the rest rather than guessing which key the
        // issuer intended.
        if let Some(requested_kid) = requested_kid
            && effective_kid != Some(requested_kid)
        {
            continue;
        }
        if let Some(key_alg) = metadata.alg.or_else(|| static_key_config_alg(key))
            && key_alg != algorithm
        {
            continue;
        }
        candidates.push(key);
    }

    if candidates.is_empty() {
        return JwtKeyResolution::KeyNotFound { source };
    }
    if candidates.len() > 1 {
        return JwtKeyResolution::ConfigurationInvalid {
            source,
            reason: JwtValidationFailureReason::AmbiguousVerificationKey,
        };
    }

    // Both callers filter these states before selecting a key, so this is
    // defensive: degrade to a rejection rather than panicking on the request
    // path if that ever stops holding.
    match cache_state {
        JwtJwksCacheState::NeverFetched | JwtJwksCacheState::EmptyUnusable => {
            return JwtKeyResolution::SourceUnavailable { source };
        }
        JwtJwksCacheState::Fresh
        | JwtJwksCacheState::Stale
        | JwtJwksCacheState::RefreshFailedRetained
        | JwtJwksCacheState::QuarantinedRetained => {}
    }

    let resolved_key = match parse_static_verification_key(candidates[0], algorithm) {
        Ok(key) => key,
        Err(failure) => {
            return JwtKeyResolution::ConfigurationInvalid {
                source,
                reason: failure.reason,
            };
        }
    };
    let resolved = ResolvedJwtVerificationKey {
        source,
        key: resolved_key,
    };
    match cache_state {
        JwtJwksCacheState::Stale
        | JwtJwksCacheState::RefreshFailedRetained
        | JwtJwksCacheState::QuarantinedRetained => JwtKeyResolution::StaleButUsable(resolved),
        _ => JwtKeyResolution::Found(resolved),
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct StaticKeyMetadata {
    pub(super) kid: Option<String>,
    pub(super) alg: Option<JwtAlgorithm>,
}

pub(super) fn static_key_metadata(
    key: &RuntimeJwtVerificationKey,
) -> Result<StaticKeyMetadata, JwtValidationFailure> {
    match key {
        RuntimeJwtVerificationKey::Pem { kid, alg, .. } => Ok(StaticKeyMetadata {
            kid: kid.clone(),
            alg: *alg,
        }),
        RuntimeJwtVerificationKey::Jwk { kid, alg, jwk } => {
            let parsed = parse_jwk_value(jwk)?;
            let jwk_kid = parsed
                .get("kid")
                .and_then(Value::as_str)
                .map(str::to_string);
            let jwk_alg = parsed
                .get("alg")
                .and_then(Value::as_str)
                .map(parse_jwt_alg_str)
                .transpose()?;
            if let (Some(config_kid), Some(jwk_kid)) = (kid.as_deref(), jwk_kid.as_deref())
                && config_kid != jwk_kid
            {
                return Err(JwtValidationFailure::new(
                    JwtValidationFailureReason::JwkKeyParseFailed,
                ));
            }
            if let (Some(config_alg), Some(jwk_alg)) = (*alg, jwk_alg)
                && config_alg != jwk_alg
            {
                return Err(JwtValidationFailure::new(
                    JwtValidationFailureReason::JwkKeyParseFailed,
                ));
            }
            Ok(StaticKeyMetadata {
                kid: kid.clone().or(jwk_kid),
                alg: alg.or(jwk_alg),
            })
        }
    }
}

fn static_key_config_kid(key: &RuntimeJwtVerificationKey) -> Option<&str> {
    match key {
        RuntimeJwtVerificationKey::Pem { kid, .. } | RuntimeJwtVerificationKey::Jwk { kid, .. } => {
            kid.as_deref()
        }
    }
}

fn static_key_config_alg(key: &RuntimeJwtVerificationKey) -> Option<JwtAlgorithm> {
    match key {
        RuntimeJwtVerificationKey::Pem { alg, .. } | RuntimeJwtVerificationKey::Jwk { alg, .. } => {
            *alg
        }
    }
}

pub(super) fn parse_static_verification_key(
    key: &RuntimeJwtVerificationKey,
    algorithm: JwtAlgorithm,
) -> Result<JwtVerificationKey<'static>, JwtValidationFailure> {
    match key {
        RuntimeJwtVerificationKey::Pem { public_key_pem, .. } => {
            parse_pem_verification_key(public_key_pem, algorithm)
        }
        RuntimeJwtVerificationKey::Jwk { jwk, .. } => parse_jwk_verification_key(jwk, algorithm),
    }
}

pub(super) fn parse_pem_verification_key(
    public_key_pem: &str,
    algorithm: JwtAlgorithm,
) -> Result<JwtVerificationKey<'static>, JwtValidationFailure> {
    match algorithm {
        JwtAlgorithm::Rs256 => {
            if let Ok(public_key) = PKey::public_key_from_pem(public_key_pem.as_bytes()) {
                if !matches!(public_key.id(), PKeyId::RSA | PKeyId::RSAPSS) {
                    return Err(JwtValidationFailure::new(
                        JwtValidationFailureReason::InvalidKeyType,
                    ));
                }
                ensure_rsa_key_strength(&public_key)?;
                return Ok(JwtVerificationKey::RsaPublicKey(public_key));
            }
            let rsa = Rsa::public_key_from_pem(public_key_pem.as_bytes())
                .or_else(|_| Rsa::public_key_from_pem_pkcs1(public_key_pem.as_bytes()))
                .map_err(|_| {
                    JwtValidationFailure::new(JwtValidationFailureReason::PemKeyParseFailed)
                })?;
            let key = PKey::from_rsa(rsa).map_err(|_| {
                JwtValidationFailure::new(JwtValidationFailureReason::PemKeyParseFailed)
            })?;
            ensure_rsa_key_strength(&key)?;
            Ok(JwtVerificationKey::RsaPublicKey(key))
        }
        JwtAlgorithm::Es256 => {
            if let Ok(public_key) = PKey::public_key_from_pem(public_key_pem.as_bytes()) {
                if public_key.id() != PKeyId::EC {
                    return Err(JwtValidationFailure::new(
                        JwtValidationFailureReason::InvalidKeyType,
                    ));
                }
                let ec_key = public_key.ec_key().map_err(|_| {
                    JwtValidationFailure::new(JwtValidationFailureReason::PemKeyParseFailed)
                })?;
                ensure_p256_public_key(&ec_key)?;
                return Ok(JwtVerificationKey::EcP256PublicKey(ec_key));
            }
            let ec_key = EcKey::public_key_from_pem(public_key_pem.as_bytes()).map_err(|_| {
                JwtValidationFailure::new(JwtValidationFailureReason::PemKeyParseFailed)
            })?;
            ensure_p256_public_key(&ec_key)?;
            Ok(JwtVerificationKey::EcP256PublicKey(ec_key))
        }
        JwtAlgorithm::Hs256 => Err(JwtValidationFailure::new(
            JwtValidationFailureReason::InvalidKeyType,
        )),
    }
}

pub(super) fn parse_jwk_verification_key(
    jwk: &str,
    algorithm: JwtAlgorithm,
) -> Result<JwtVerificationKey<'static>, JwtValidationFailure> {
    let jwk = parse_jwk_value(jwk)?;
    match algorithm {
        JwtAlgorithm::Rs256 => {
            let kty = jwk.get("kty").and_then(Value::as_str);
            if kty != Some("RSA") {
                return Err(JwtValidationFailure::new(
                    JwtValidationFailureReason::InvalidKeyType,
                ));
            }
            let n = jwk
                .get("n")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    JwtValidationFailure::new(JwtValidationFailureReason::JwkKeyParseFailed)
                })
                .and_then(decode_jwk_bignum)?;
            let e = jwk
                .get("e")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    JwtValidationFailure::new(JwtValidationFailureReason::JwkKeyParseFailed)
                })
                .and_then(decode_jwk_bignum)?;
            let rsa = Rsa::from_public_components(n, e).map_err(|_| {
                JwtValidationFailure::new(JwtValidationFailureReason::JwkKeyParseFailed)
            })?;
            let key = PKey::from_rsa(rsa).map_err(|_| {
                JwtValidationFailure::new(JwtValidationFailureReason::JwkKeyParseFailed)
            })?;
            ensure_rsa_key_strength(&key)?;
            Ok(JwtVerificationKey::RsaPublicKey(key))
        }
        JwtAlgorithm::Es256 => {
            let kty = jwk.get("kty").and_then(Value::as_str);
            if kty != Some("EC") {
                return Err(JwtValidationFailure::new(
                    JwtValidationFailureReason::InvalidKeyType,
                ));
            }
            let crv = jwk.get("crv").and_then(Value::as_str);
            if crv != Some("P-256") {
                return Err(JwtValidationFailure::new(
                    JwtValidationFailureReason::UnsupportedCurve,
                ));
            }
            let x = jwk
                .get("x")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    JwtValidationFailure::new(JwtValidationFailureReason::JwkKeyParseFailed)
                })
                .and_then(decode_jwk_bignum)?;
            let y = jwk
                .get("y")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    JwtValidationFailure::new(JwtValidationFailureReason::JwkKeyParseFailed)
                })
                .and_then(decode_jwk_bignum)?;
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|_| {
                JwtValidationFailure::new(JwtValidationFailureReason::UnsupportedCurve)
            })?;
            let ec_key =
                EcKey::from_public_key_affine_coordinates(&group, &x, &y).map_err(|_| {
                    JwtValidationFailure::new(JwtValidationFailureReason::JwkKeyParseFailed)
                })?;
            ensure_p256_public_key(&ec_key)?;
            Ok(JwtVerificationKey::EcP256PublicKey(ec_key))
        }
        JwtAlgorithm::Hs256 => Err(JwtValidationFailure::new(
            JwtValidationFailureReason::InvalidKeyType,
        )),
    }
}

fn parse_jwk_value(jwk: &str) -> Result<Value, JwtValidationFailure> {
    serde_json::from_str::<Value>(jwk)
        .map_err(|_| JwtValidationFailure::new(JwtValidationFailureReason::JwkKeyParseFailed))
}

pub(super) fn parse_jwt_alg_str(alg: &str) -> Result<JwtAlgorithm, JwtValidationFailure> {
    match alg {
        "HS256" => Ok(JwtAlgorithm::Hs256),
        "RS256" => Ok(JwtAlgorithm::Rs256),
        "ES256" => Ok(JwtAlgorithm::Es256),
        _ => Err(JwtValidationFailure::new(
            JwtValidationFailureReason::JwkKeyParseFailed,
        )),
    }
}

fn decode_jwk_bignum(encoded: &str) -> Result<BigNum, JwtValidationFailure> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| JwtValidationFailure::new(JwtValidationFailureReason::JwkKeyParseFailed))?;
    BigNum::from_slice(&bytes)
        .map_err(|_| JwtValidationFailure::new(JwtValidationFailureReason::JwkKeyParseFailed))
}

/// Smallest RSA modulus accepted for RS256 verification. Anything shorter is
/// forgeable in practice, so reject it rather than trusting operator config or
/// a remote JWKS document to only publish sound keys.
const MIN_RSA_KEY_BITS: u32 = 2048;

fn ensure_rsa_key_strength(key: &PKey<Public>) -> Result<(), JwtValidationFailure> {
    let bits = key
        .rsa()
        .map_err(|_| JwtValidationFailure::new(JwtValidationFailureReason::InvalidKeyType))?
        .size()
        .saturating_mul(8);
    if bits < MIN_RSA_KEY_BITS {
        return Err(JwtValidationFailure::new(
            JwtValidationFailureReason::KeyTooWeak,
        ));
    }
    Ok(())
}
fn ensure_p256_public_key(ec_key: &EcKey<Public>) -> Result<(), JwtValidationFailure> {
    ec_key
        .check_key()
        .map_err(|_| JwtValidationFailure::new(JwtValidationFailureReason::InvalidKeyType))?;
    let curve = ec_key.group().curve_name();
    if curve != Some(Nid::X9_62_PRIME256V1) {
        return Err(JwtValidationFailure::new(
            JwtValidationFailureReason::UnsupportedCurve,
        ));
    }
    Ok(())
}
