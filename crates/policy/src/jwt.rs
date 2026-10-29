use std::{
    collections::HashSet,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use boring::{
    ec::EcKey,
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    pkey::{PKey, Public},
    rsa::Padding,
    sign::Verifier,
};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JwtAlgorithm {
    Hs256,
    Rs256,
    Es256,
}

impl JwtAlgorithm {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Hs256 => "HS256",
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JwtAllowedAlgorithms {
    pub hs256: bool,
    pub rs256: bool,
    pub es256: bool,
}

impl JwtAllowedAlgorithms {
    const fn contains(self, algorithm: JwtAlgorithm) -> bool {
        match algorithm {
            JwtAlgorithm::Hs256 => self.hs256,
            JwtAlgorithm::Rs256 => self.rs256,
            JwtAlgorithm::Es256 => self.es256,
        }
    }
}

#[derive(Clone, Copy)]
pub struct JwtPolicyInput<'a> {
    pub allowed_algorithms: JwtAllowedAlgorithms,
    pub issuer: Option<&'a str>,
    pub issuers: &'a [String],
    pub audience: Option<&'a str>,
    pub audiences: &'a [String],
    pub clock_skew_seconds: u64,
}

#[derive(Clone, Copy)]
pub struct JwtClaimsRequirements<'a> {
    pub required_scopes: &'a [String],
    pub required_roles: &'a [String],
}

#[derive(Debug, Clone)]
pub enum JwtVerificationKey<'a> {
    Hs256Secret(&'a str),
    RsaPublicKey(PKey<Public>),
    EcP256PublicKey(EcKey<Public>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtValidationFailureReason {
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
    #[must_use]
    pub const fn as_str(self) -> &'static str {
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
pub struct JwtValidationFailure {
    pub reason: JwtValidationFailureReason,
}

impl JwtValidationFailure {
    #[must_use]
    pub const fn new(reason: JwtValidationFailureReason) -> Self {
        Self { reason }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedJoseHeader {
    pub algorithm: JwtAlgorithm,
    pub kid: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedJwt<'a> {
    header_b64: &'a str,
    payload_b64: &'a str,
    payload_bytes: Vec<u8>,
    signature: Vec<u8>,
    header: ParsedJoseHeader,
}

impl ParsedJwt<'_> {
    #[must_use]
    pub const fn algorithm(&self) -> JwtAlgorithm {
        self.header.algorithm
    }

    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.header.kid.as_deref()
    }
}

#[derive(Debug, Clone)]
pub struct ValidatedJwt {
    pub algorithm: JwtAlgorithm,
    pub claims: Value,
}

pub fn parse_jwt(
    token: &str,
    allowed_algorithms: JwtAllowedAlgorithms,
) -> Result<ParsedJwt<'_>, JwtValidationFailure> {
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
    let header = parse_jose_header(&header_bytes)?;
    if !allowed_algorithms.contains(header.algorithm) {
        return Err(JwtValidationFailure::new(
            JwtValidationFailureReason::AlgorithmNotAllowed,
        ));
    }

    Ok(ParsedJwt {
        header_b64,
        payload_b64,
        payload_bytes,
        signature,
        header,
    })
}

pub fn parse_jose_header(header_bytes: &[u8]) -> Result<ParsedJoseHeader, JwtValidationFailure> {
    let header = serde_json::from_slice::<Value>(header_bytes)
        .map_err(|_| JwtValidationFailure::new(JwtValidationFailureReason::MalformedHeader))?;
    let algorithm = match header.get("alg").and_then(Value::as_str) {
        Some("HS256") => JwtAlgorithm::Hs256,
        Some("RS256") => JwtAlgorithm::Rs256,
        Some("ES256") => JwtAlgorithm::Es256,
        Some(_) => {
            return Err(JwtValidationFailure::new(
                JwtValidationFailureReason::UnsupportedAlgorithm,
            ));
        }
        None => {
            return Err(JwtValidationFailure::new(
                JwtValidationFailureReason::MissingAlgorithm,
            ));
        }
    };
    Ok(ParsedJoseHeader {
        algorithm,
        kid: header.get("kid").and_then(Value::as_str).map(str::to_owned),
    })
}

pub fn validate_parsed_jwt(
    parsed: ParsedJwt<'_>,
    key: JwtVerificationKey<'_>,
    policy: JwtPolicyInput<'_>,
    now: SystemTime,
) -> Result<ValidatedJwt, JwtValidationFailure> {
    if !policy.allowed_algorithms.contains(parsed.header.algorithm) {
        return Err(JwtValidationFailure::new(
            JwtValidationFailureReason::AlgorithmNotAllowed,
        ));
    }
    verify_signature(&parsed, key)?;
    let claims = serde_json::from_slice::<Value>(&parsed.payload_bytes)
        .map_err(|_| JwtValidationFailure::new(JwtValidationFailureReason::MalformedClaims))?;
    validate_registered_claims(policy, &claims, now)?;
    Ok(ValidatedJwt {
        algorithm: parsed.header.algorithm,
        claims,
    })
}

fn verify_signature(
    parsed: &ParsedJwt<'_>,
    key: JwtVerificationKey<'_>,
) -> Result<(), JwtValidationFailure> {
    let signing_input = format!("{}.{}", parsed.header_b64, parsed.payload_b64);
    match (parsed.header.algorithm, key) {
        (JwtAlgorithm::Hs256, JwtVerificationKey::Hs256Secret(secret)) => {
            let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
                return Err(JwtValidationFailure::new(
                    JwtValidationFailureReason::MissingVerificationKey,
                ));
            };
            mac.update(signing_input.as_bytes());
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
            verifier.update(signing_input.as_bytes()).map_err(|_| {
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
            let digest = Sha256::digest(signing_input.as_bytes());
            let signature = EcdsaSig::from_der(&der_signature).map_err(|_| {
                JwtValidationFailure::new(JwtValidationFailureReason::SignatureInvalid)
            })?;
            if !signature.verify(&digest, &public_key).map_err(|_| {
                JwtValidationFailure::new(JwtValidationFailureReason::SignatureInvalid)
            })? {
                return Err(JwtValidationFailure::new(
                    JwtValidationFailureReason::SignatureInvalid,
                ));
            }
            Ok(())
        }
        _ => Err(JwtValidationFailure::new(
            JwtValidationFailureReason::InvalidKeyType,
        )),
    }
}

fn validate_registered_claims(
    policy: JwtPolicyInput<'_>,
    claims: &Value,
    now: SystemTime,
) -> Result<(), JwtValidationFailure> {
    let now_secs = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| JwtValidationFailure::new(JwtValidationFailureReason::MalformedClaims))?
        .as_secs();
    let exp = claims
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or_else(|| JwtValidationFailure::new(JwtValidationFailureReason::MissingExpiration))?;
    if now_secs > exp.saturating_add(policy.clock_skew_seconds) {
        return Err(JwtValidationFailure::new(
            JwtValidationFailureReason::TokenExpired,
        ));
    }
    if claims
        .get("nbf")
        .and_then(Value::as_u64)
        .is_some_and(|nbf| now_secs.saturating_add(policy.clock_skew_seconds) < nbf)
    {
        return Err(JwtValidationFailure::new(
            JwtValidationFailureReason::TokenNotYetValid,
        ));
    }
    if claims
        .get("iat")
        .and_then(Value::as_u64)
        .is_some_and(|iat| now_secs.saturating_add(policy.clock_skew_seconds) < iat)
    {
        return Err(JwtValidationFailure::new(
            JwtValidationFailureReason::TokenIssuedInFuture,
        ));
    }
    if !issuer_matches(policy, claims) {
        return Err(JwtValidationFailure::new(
            JwtValidationFailureReason::IssuerMismatch,
        ));
    }
    if !audience_matches(policy, claims) {
        return Err(JwtValidationFailure::new(
            JwtValidationFailureReason::AudienceMismatch,
        ));
    }
    Ok(())
}

fn issuer_matches(policy: JwtPolicyInput<'_>, claims: &Value) -> bool {
    let actual = claims.get("iss").and_then(Value::as_str);
    if let Some(issuer) = policy.issuer {
        return actual == Some(issuer);
    }
    policy.issuers.is_empty()
        || policy
            .issuers
            .iter()
            .any(|issuer| actual == Some(issuer.as_str()))
}

fn audience_matches(policy: JwtPolicyInput<'_>, claims: &Value) -> bool {
    if policy.audience.is_none() && policy.audiences.is_empty() {
        return true;
    }
    let expected = |audience: &str| {
        policy.audience == Some(audience)
            || policy
                .audiences
                .iter()
                .any(|expected| expected.as_str() == audience)
    };
    match claims.get("aud") {
        Some(Value::String(value)) => expected(value),
        Some(Value::Array(values)) => values.iter().filter_map(Value::as_str).any(expected),
        _ => false,
    }
}

#[must_use]
pub fn jwt_claims_satisfy_requirements(
    claims: &Value,
    requirements: JwtClaimsRequirements<'_>,
) -> bool {
    let scopes = string_claim_values(claims, &["scope", "scp"]);
    let roles = string_claim_values(claims, &["roles", "role"]);
    requirements
        .required_scopes
        .iter()
        .all(|required| scopes.contains(required))
        && requirements
            .required_roles
            .iter()
            .all(|required| roles.contains(required))
}

fn string_claim_values(claims: &Value, claim_names: &[&str]) -> HashSet<String> {
    let mut values = HashSet::new();
    for claim_name in claim_names {
        let Some(value) = claims.get(*claim_name) else {
            continue;
        };
        match value {
            Value::String(value) => values.extend(value.split_whitespace().map(str::to_owned)),
            Value::Array(items) => values.extend(
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned),
            ),
            _ => {}
        }
    }
    values
}

fn jose_es256_signature_to_der(signature: &[u8]) -> Result<Vec<u8>, JwtValidationFailure> {
    if signature.len() != 64 {
        return Err(JwtValidationFailure::new(
            JwtValidationFailureReason::SignatureInvalid,
        ));
    }
    let r = boring::bn::BigNum::from_slice(&signature[..32])
        .map_err(|_| JwtValidationFailure::new(JwtValidationFailureReason::SignatureInvalid))?;
    let s = boring::bn::BigNum::from_slice(&signature[32..])
        .map_err(|_| JwtValidationFailure::new(JwtValidationFailureReason::SignatureInvalid))?;
    EcdsaSig::from_private_components(r, s)
        .and_then(|signature| signature.to_der())
        .map_err(|_| JwtValidationFailure::new(JwtValidationFailureReason::SignatureInvalid))
}
