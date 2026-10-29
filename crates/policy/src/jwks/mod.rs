//! Generation-aware JWKS cache and refresh runtime.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::Infallible,
    sync::{
        Arc, Mutex, OnceLock, RwLock, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use boring::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{PKey, Public},
    rsa::Rsa,
};
use bytes::Bytes;
use http::StatusCode;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{
    Request, Response,
    body::{Body, Incoming},
};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use impulse_config::{
    config::{JwksStartupBehavior, JwtAlgorithm},
    runtime::{RuntimeJwtAuth, RuntimeJwtVerificationKey},
};
use impulse_observability::Metrics;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{JwtValidationFailure, JwtValidationFailureReason, JwtVerificationKey};

mod cache;
mod refresh;

use cache::{JWT_JWKS_FETCH_SCRIPT, JWT_JWKS_HTTP_CLIENT, MAX_JWKS_BODY_BYTES};
pub use cache::{
    JwtJwksActiveKey, JwtJwksCacheEntry, JwtJwksCacheSnapshot, JwtJwksCacheState,
    JwtJwksRuntimeSnapshot, JwtJwksSharedCache, JwtJwksSourceConfig, clear_jwks_cache_for_test,
    current_jwt_jwks_metrics, jwks_source_identity_for_test, jwt_jwks_cache_stale_window_expired,
    jwt_jwks_cache_state_name, jwt_jwks_cache_state_usable, jwt_jwks_metrics_sink,
    jwt_jwks_public_endpoint, jwt_jwks_source_identity, mark_jwks_source_invalid_for_test,
    mark_jwks_source_unavailable_for_test, merge_jwks_source_configs, prime_jwks_cache_for_test,
    runtime_jwks_source_identity, snapshot_jwks_sources,
};
pub use refresh::{
    JwtJwksFetchFailure, JwtJwksFetchFailureReason, collect_jwks_body_bounded,
    fetch_and_normalize_jwks, maybe_spawn_jwks_on_demand_refresh, normalize_jwks_document_for_test,
    refresh_jwks_source_inflight, refresh_jwks_source_once, script_jwks_fetches_for_test,
};
use refresh::{JwtJwksHttpClient, jwt_verification_keys_equivalent};

fn runtime_handle() -> Option<tokio::runtime::Handle> {
    tokio::runtime::Handle::try_current().ok()
}

fn parse_jwt_alg_str(value: &str) -> Result<JwtAlgorithm, JwtValidationFailure> {
    match value {
        "HS256" => Ok(JwtAlgorithm::Hs256),
        "RS256" => Ok(JwtAlgorithm::Rs256),
        "ES256" => Ok(JwtAlgorithm::Es256),
        _ => Err(JwtValidationFailure::new(
            JwtValidationFailureReason::UnsupportedAlgorithm,
        )),
    }
}

fn jwt_algorithm_name(algorithm: JwtAlgorithm) -> &'static str {
    match algorithm {
        JwtAlgorithm::Hs256 => "HS256",
        JwtAlgorithm::Rs256 => "RS256",
        JwtAlgorithm::Es256 => "ES256",
    }
}

fn static_key_metadata(
    key: &RuntimeJwtVerificationKey,
) -> Result<StaticKeyMetadata, JwtValidationFailure> {
    match key {
        RuntimeJwtVerificationKey::Pem { kid, alg, .. } => Ok(StaticKeyMetadata {
            kid: kid.clone(),
            alg: *alg,
        }),
        RuntimeJwtVerificationKey::Jwk { kid, alg, jwk } => {
            let parsed: Value = serde_json::from_str(jwk).map_err(|_| {
                JwtValidationFailure::new(JwtValidationFailureReason::JwkKeyParseFailed)
            })?;
            Ok(StaticKeyMetadata {
                kid: kid
                    .clone()
                    .or_else(|| parsed.get("kid").and_then(Value::as_str).map(str::to_owned)),
                alg: alg.or_else(|| {
                    parsed
                        .get("alg")
                        .and_then(Value::as_str)
                        .and_then(|value| parse_jwt_alg_str(value).ok())
                }),
            })
        }
    }
}

#[derive(Default)]
struct StaticKeyMetadata {
    kid: Option<String>,
    alg: Option<JwtAlgorithm>,
}

fn parse_static_verification_key(
    key: &RuntimeJwtVerificationKey,
    algorithm: JwtAlgorithm,
) -> Result<JwtVerificationKey<'static>, JwtValidationFailure> {
    let RuntimeJwtVerificationKey::Jwk { jwk, .. } = key else {
        return Err(JwtValidationFailure::new(
            JwtValidationFailureReason::InvalidKeyType,
        ));
    };
    let jwk: Value = serde_json::from_str(jwk)
        .map_err(|_| JwtValidationFailure::new(JwtValidationFailureReason::JwkKeyParseFailed))?;
    match algorithm {
        JwtAlgorithm::Rs256 => {
            if jwk.get("kty").and_then(Value::as_str) != Some("RSA") {
                return Err(JwtValidationFailure::new(
                    JwtValidationFailureReason::InvalidKeyType,
                ));
            }
            let n = decode_jwk_bignum(jwk.get("n").and_then(Value::as_str))?;
            let e = decode_jwk_bignum(jwk.get("e").and_then(Value::as_str))?;
            let rsa = Rsa::from_public_components(n, e).map_err(|_| {
                JwtValidationFailure::new(JwtValidationFailureReason::JwkKeyParseFailed)
            })?;
            let key = PKey::from_rsa(rsa).map_err(|_| {
                JwtValidationFailure::new(JwtValidationFailureReason::JwkKeyParseFailed)
            })?;
            if key
                .rsa()
                .map_err(|_| JwtValidationFailure::new(JwtValidationFailureReason::InvalidKeyType))?
                .size()
                .saturating_mul(8)
                < 2048
            {
                return Err(JwtValidationFailure::new(
                    JwtValidationFailureReason::KeyTooWeak,
                ));
            }
            Ok(JwtVerificationKey::RsaPublicKey(key))
        }
        JwtAlgorithm::Es256 => {
            if jwk.get("kty").and_then(Value::as_str) != Some("EC") {
                return Err(JwtValidationFailure::new(
                    JwtValidationFailureReason::InvalidKeyType,
                ));
            }
            if jwk.get("crv").and_then(Value::as_str) != Some("P-256") {
                return Err(JwtValidationFailure::new(
                    JwtValidationFailureReason::UnsupportedCurve,
                ));
            }
            let x = decode_jwk_bignum(jwk.get("x").and_then(Value::as_str))?;
            let y = decode_jwk_bignum(jwk.get("y").and_then(Value::as_str))?;
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|_| {
                JwtValidationFailure::new(JwtValidationFailureReason::UnsupportedCurve)
            })?;
            let key = EcKey::from_public_key_affine_coordinates(&group, &x, &y).map_err(|_| {
                JwtValidationFailure::new(JwtValidationFailureReason::JwkKeyParseFailed)
            })?;
            key.check_key().map_err(|_| {
                JwtValidationFailure::new(JwtValidationFailureReason::InvalidKeyType)
            })?;
            Ok(JwtVerificationKey::EcP256PublicKey(key))
        }
        JwtAlgorithm::Hs256 => Err(JwtValidationFailure::new(
            JwtValidationFailureReason::InvalidKeyType,
        )),
    }
}

fn decode_jwk_bignum(value: Option<&str>) -> Result<BigNum, JwtValidationFailure> {
    let value = value
        .ok_or_else(|| JwtValidationFailure::new(JwtValidationFailureReason::JwkKeyParseFailed))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| JwtValidationFailure::new(JwtValidationFailureReason::JwkKeyParseFailed))?;
    BigNum::from_slice(&bytes)
        .map_err(|_| JwtValidationFailure::new(JwtValidationFailureReason::JwkKeyParseFailed))
}
