mod auth;
mod dispatch;
mod lb_key;
mod orchestration;
mod orchestration_service;
mod outcome;
mod prepare;
mod resolve;
mod response;
mod selection;
mod stream_progress;

use impulse_config::runtime::RuntimeBackendTlsPolicy;
use impulse_lb::pingora_backend::PingoraLoadBalancingRuntimeState;

pub(in crate::quic_listener) use self::outcome::{
    backend_failure_reason_for_proxy_error, rejection_reason_for_status, terminalize_stream,
};
use self::prepare::RequestFinalizationConfig;
#[cfg(test)]
pub(in crate::quic_listener) use self::resolve::{
    TargetResolutionRequest as TestTargetResolutionRequest, selectors_for_test as test_selectors,
};
pub(crate) use self::{
    auth::execute_external_auth_request,
    resolve::TargetResolutionRequest,
    selection::{BackendCandidate, ForwardingSelectionService},
};
use super::*;
use crate::runtime::cache::BoundedPingoraMemoryCache;

// Shared forwarding dependencies passed through extracted submodules.
pub(in crate::quic_listener) struct ForwardingSharedCtx<'a> {
    pub(in crate::quic_listener) metrics: Arc<Metrics>,
    pub(in crate::quic_listener) resilience: &'a RuntimeResilience,
    pub(in crate::quic_listener) routing_index: &'a RouteIndex,
    pub(in crate::quic_listener) upstream_pools: &'a HashMap<String, Arc<RwLock<UpstreamPool>>>,
    pub(in crate::quic_listener) upstream_policies: &'a HashMap<String, RuntimeUpstreamPolicy>,
    pub(in crate::quic_listener) pingora_load_balancing:
        &'a PingoraLoadBalancingRuntimeState<RuntimeBackendTlsPolicy>,
    pub(in crate::quic_listener) generation: u64,
}

pub(in crate::quic_listener) struct ForwardingExecutionCtx<'a> {
    pub(in crate::quic_listener) upstream_executor: UpstreamRequestExecutor,
    pub(in crate::quic_listener) backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
    pub(in crate::quic_listener) upstream_inflight: &'a HashMap<String, Arc<Semaphore>>,
    pub(in crate::quic_listener) global_inflight: Arc<Semaphore>,
    pub(in crate::quic_listener) inflight_acquire_wait: Duration,
    pub(in crate::quic_listener) response_cache: Option<&'static BoundedPingoraMemoryCache>,
    pub(in crate::quic_listener) response_cache_namespace: u64,
}

pub(in crate::quic_listener) struct StreamProgressConfig {
    pub(in crate::quic_listener) backend_body_idle_timeout: Duration,
    pub(in crate::quic_listener) backend_body_total_timeout: Duration,
    pub(in crate::quic_listener) max_response_body_bytes: usize,
    pub(in crate::quic_listener) unknown_length_response_prebuffer_bytes: usize,
    pub(in crate::quic_listener) client_body_idle_timeout: Duration,
    pub(in crate::quic_listener) listen_port: u16,
}

pub(in crate::quic_listener) struct H3RequestHandlingConfig {
    request_finalization: RequestFinalizationConfig,
    pub(in crate::quic_listener) max_request_body_bytes: usize,
    pub(in crate::quic_listener) request_buffer_global_cap_bytes: usize,
    pub(in crate::quic_listener) tracing_enabled: bool,
    pub(in crate::quic_listener) max_streams_per_connection: usize,
}

impl H3RequestHandlingConfig {
    pub(in crate::quic_listener) fn new(
        routing_transparency_enabled: bool,
        routing_transparency_include_reason: bool,
        backend_total_request_timeout: Duration,
        max_request_body_bytes: usize,
        request_buffer_global_cap_bytes: usize,
        tracing_enabled: bool,
        max_streams_per_connection: usize,
    ) -> Self {
        Self {
            request_finalization: RequestFinalizationConfig {
                routing_transparency_enabled,
                routing_transparency_include_reason,
                backend_total_request_timeout,
            },
            max_request_body_bytes,
            request_buffer_global_cap_bytes,
            tracing_enabled,
            max_streams_per_connection,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use boring::{
        bn::{BigNum, BigNumContext},
        ec::{EcGroup, EcKey},
        ecdsa::EcdsaSig,
        hash::MessageDigest,
        nid::Nid,
        pkey::{PKey, Private},
        rsa::{Padding, Rsa},
        sign::Signer,
    };
    use hmac::{Hmac, Mac};
    use impulse_config::{
        config::{JwtAlgorithm, ScopedRateLimit, ScopedRateLimitScope},
        runtime::{
            RuntimeApiKeyAuth, RuntimeAuthPolicy, RuntimeJwtAuth, RuntimeJwtVerificationKey,
            RuntimeUpstreamPolicy,
        },
    };
    use serde_json::Value;
    use sha2::Sha256;

    use super::{auth::append_auth_request_headers, *};
    use crate::runtime::connection::{
        auth::PendingHeaderMutation, request::PendingForward, stream::BackendFailureReason,
    };

    fn sample_pending_forward(headers: Vec<quiche::h3::Header>) -> PendingForward {
        PendingForward {
            path: Arc::<str>::from("/"),
            authority: Some(Arc::<str>::from("example.com")),
            route_path_len: 1,
            route_host_specific: false,
            backend_addr: Arc::<str>::from("http://127.0.0.1:8080"),
            client_addr: "127.0.0.1:443".parse().expect("client addr"),
            request_id: 7,
            ..PendingForward::sample_for_test(headers)
        }
    }

    fn test_hs256_jwt(secret: &str, claims: serde_json::Value, alg: &str) -> String {
        let header = serde_json::json!({ "alg": alg, "typ": "JWT" });
        let signing_input = test_signing_input(&header, &claims);
        let signature = {
            let mut payload = Vec::new();
            let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("mac");
            mac.update(signing_input.as_bytes());
            payload.extend_from_slice(&mac.finalize().into_bytes());
            payload
        };
        test_signed_jwt(header, claims, signature)
    }

    fn test_rs256_jwt(key: &PKey<Private>, kid: Option<&str>, claims: serde_json::Value) -> String {
        let header = serde_json::json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": kid,
        });
        let signing_input = test_signing_input(&header, &claims);
        let mut signer = Signer::new(MessageDigest::sha256(), key).expect("rsa signer");
        signer.set_rsa_padding(Padding::PKCS1).expect("rsa padding");
        signer
            .update(signing_input.as_bytes())
            .expect("rsa signing input");
        test_signed_jwt(header, claims, signer.sign_to_vec().expect("rsa signature"))
    }

    fn test_es256_jwt(
        key: &EcKey<Private>,
        kid: Option<&str>,
        claims: serde_json::Value,
    ) -> String {
        let header = serde_json::json!({
            "alg": "ES256",
            "typ": "JWT",
            "kid": kid,
        });
        let signing_input = test_signing_input(&header, &claims);
        let pkey = PKey::from_ec_key(key.clone()).expect("ec pkey");
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey).expect("ec signer");
        signer
            .update(signing_input.as_bytes())
            .expect("ec signing input");
        let der_signature = signer.sign_to_vec().expect("ec signature");
        let jose_signature = der_ecdsa_signature_to_jose(&der_signature);
        test_signed_jwt(header, claims, jose_signature)
    }

    fn test_signing_input(header: &serde_json::Value, claims: &serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).expect("serialize header"));
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("serialize claims"));
        format!("{header}.{payload}")
    }

    fn test_signed_jwt(
        header: serde_json::Value,
        claims: serde_json::Value,
        signature: impl AsRef<[u8]>,
    ) -> String {
        let signing_input = test_signing_input(&header, &claims);
        let signature = URL_SAFE_NO_PAD.encode(signature.as_ref());
        format!("{signing_input}.{signature}")
    }

    fn der_ecdsa_signature_to_jose(der_signature: &[u8]) -> Vec<u8> {
        let sig = EcdsaSig::from_der(der_signature).expect("ecdsa der");
        let mut jose = sig.r().to_vec_padded(32).expect("ecdsa r");
        jose.extend_from_slice(&sig.s().to_vec_padded(32).expect("ecdsa s"));
        jose
    }

    fn ec_public_jwk(key: &EcKey<Private>, kid: Option<&str>) -> String {
        let mut ctx = BigNumContext::new().expect("bn ctx");
        let mut x = BigNum::new().expect("x");
        let mut y = BigNum::new().expect("y");
        let coordinate_len = key.group().degree().div_ceil(8) as usize;
        key.public_key()
            .affine_coordinates_gfp(key.group(), &mut x, &mut y, &mut ctx)
            .expect("affine coordinates");
        serde_json::json!({
            "kty": "EC",
            "alg": "ES256",
            "kid": kid,
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(x.to_vec_padded(coordinate_len).expect("x bytes")),
            "y": URL_SAFE_NO_PAD.encode(y.to_vec_padded(coordinate_len).expect("y bytes")),
        })
        .to_string()
    }

    fn rsa_public_jwk(
        key: &PKey<Private>,
        kid: Option<&str>,
        alg: Option<&str>,
        use_value: Option<&str>,
        key_ops: Option<Vec<&str>>,
    ) -> String {
        let rsa = key.rsa().expect("rsa private key");
        serde_json::json!({
            "kty": "RSA",
            "kid": kid,
            "alg": alg,
            "use": use_value,
            "key_ops": key_ops,
            "n": URL_SAFE_NO_PAD.encode(rsa.n().to_vec()),
            "e": URL_SAFE_NO_PAD.encode(rsa.e().to_vec()),
        })
        .to_string()
    }

    #[test]
    fn internal_pool_errors_are_classified_as_control_plane_only() {
        assert!(QUICListener::is_internal_pool_control_error(
            &PoolError::InflightLimiterClosed
        ));
        assert!(QUICListener::is_internal_pool_control_error(
            &PoolError::UnknownBackend("missing".to_string())
        ));
    }

    #[test]
    fn backend_overload_is_not_classified_as_internal_pool_error() {
        assert!(!QUICListener::is_internal_pool_control_error(
            &PoolError::BackendOverloaded("busy".to_string())
        ));
    }

    #[test]
    fn circuit_open_is_not_classified_as_internal_pool_error() {
        assert!(!QUICListener::is_internal_pool_control_error(
            &PoolError::CircuitOpen("open".to_string())
        ));
    }

    #[test]
    fn send_connect_error_with_tls_details_maps_to_tls_health_failure() {
        assert_eq!(
            impulse_errors::classify_upstream_error_detail(
                "client error (Connect): tls handshake failed: invalid certificate",
                true,
            ),
            impulse_errors::UpstreamErrorClassification::tls(
                impulse_errors::UpstreamTlsReason::Handshake,
            )
        );
    }

    #[test]
    fn send_connect_error_without_tls_details_maps_to_transport_health_failure() {
        assert_eq!(
            impulse_errors::classify_upstream_error_detail(
                "client error (Connect): connection refused",
                true,
            ),
            impulse_errors::UpstreamErrorClassification::transport()
        );
    }

    #[test]
    fn send_error_with_timeout_detail_maps_to_timeout_health_failure() {
        assert_eq!(
            impulse_errors::classify_upstream_error_detail("request timed out", false),
            impulse_errors::UpstreamErrorClassification::timeout()
        );
    }

    #[test]
    fn backend_failure_reason_for_proxy_error_preserves_transport_protocol_and_bridge_buckets() {
        assert_eq!(
            backend_failure_reason_for_proxy_error(&ProxyError::Transport(
                "connection reset".to_string()
            )),
            BackendFailureReason::UpstreamTransport
        );
        assert_eq!(
            backend_failure_reason_for_proxy_error(&ProxyError::Pool(PoolError::UnknownBackend(
                "missing".to_string()
            ))),
            BackendFailureReason::UpstreamTransport
        );
        assert_eq!(
            backend_failure_reason_for_proxy_error(&ProxyError::Protocol(
                "bad response frame".to_string()
            )),
            BackendFailureReason::UpstreamProtocol
        );
        assert_eq!(
            backend_failure_reason_for_proxy_error(&ProxyError::Bridge(
                impulse_errors::BridgeError::InvalidHeader
            )),
            BackendFailureReason::UpstreamBridge
        );
    }

    #[test]
    fn api_key_authorization_requires_exact_configured_match() {
        let policy = RuntimeUpstreamPolicy {
            upstream_auth: RuntimeAuthPolicy {
                api_key: Some(RuntimeApiKeyAuth {
                    header_name: "x-api-key".to_string(),
                    keys: vec!["secret-key".to_string()],
                }),
                jwt: None,
                external_auth: None,
                required_scopes: Vec::new(),
                required_roles: Vec::new(),
            },
            host: Default::default(),
            forwarded_headers: Default::default(),
            response_cache: Default::default(),
            response_compression: Default::default(),
            protocol: Default::default(),
        };
        let headers = [("x-api-key".to_string(), "secret-key".to_string())]
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();
        let lookup = |name: &str| headers.get(&name.to_ascii_lowercase()).cloned();
        let wrong_lookup = |_: &str| Some("wrong-key".to_string());

        assert!(super::super::admission::api_key_is_authorized(
            &policy,
            Some(&lookup)
        ));
        assert!(!super::super::admission::api_key_is_authorized(
            &policy,
            Some(&wrong_lookup)
        ));
        assert!(!super::super::admission::api_key_is_authorized(
            &policy, None
        ));
    }

    #[test]
    fn hs256_jwt_validation_enforces_signature_and_claims() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let token = test_hs256_jwt(
            "jwt-secret",
            serde_json::json!({
                "sub": "user-1",
                "iss": "issuer-1",
                "aud": "aud-1",
                "exp": 4_000_000_000u64,
                "nbf": 1_699_999_900u64,
            }),
            "HS256",
        );
        let policy = RuntimeUpstreamPolicy {
            upstream_auth: RuntimeAuthPolicy {
                api_key: None,
                jwt: Some(RuntimeJwtAuth {
                    secret: "jwt-secret".to_string(),
                    issuer: Some("issuer-1".to_string()),
                    audience: Some("aud-1".to_string()),
                    clock_skew: Duration::from_secs(30),
                    ..RuntimeJwtAuth::default()
                }),
                external_auth: None,
                required_scopes: Vec::new(),
                required_roles: Vec::new(),
            },
            host: Default::default(),
            forwarded_headers: Default::default(),
            response_cache: Default::default(),
            response_compression: Default::default(),
            protocol: Default::default(),
        };
        let headers = [("authorization".to_string(), format!("Bearer {token}"))]
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();
        let lookup = |name: &str| headers.get(&name.to_ascii_lowercase()).cloned();

        assert!(super::super::admission::jwt_is_authorized(
            &policy,
            Some(&lookup)
        ));
        assert!(
            super::super::admission::validated_hs256_jwt_claims(
                token.as_str(),
                policy.upstream_auth.jwt.as_ref().expect("jwt policy"),
                now
            )
            .is_some()
        );

        let wrong_secret = RuntimeJwtAuth {
            secret: "wrong".to_string(),
            issuer: Some("issuer-1".to_string()),
            audience: Some("aud-1".to_string()),
            clock_skew: Duration::from_secs(30),
            ..RuntimeJwtAuth::default()
        };
        assert!(
            super::super::admission::validated_hs256_jwt_claims(token.as_str(), &wrong_secret, now)
                .is_none()
        );

        let expired = test_hs256_jwt(
            "jwt-secret",
            serde_json::json!({ "exp": 1_699_999_900u64 }),
            "HS256",
        );
        assert!(
            super::super::admission::validated_hs256_jwt_claims(
                expired.as_str(),
                &RuntimeJwtAuth {
                    secret: "jwt-secret".to_string(),
                    issuer: None,
                    audience: None,
                    clock_skew: Duration::ZERO,
                    ..RuntimeJwtAuth::default()
                },
                now
            )
            .is_none()
        );

        let validated = super::super::admission::validate_jwt_token(
            token.as_str(),
            policy.upstream_auth.jwt.as_ref().expect("jwt policy"),
            now,
        )
        .expect("validated jwt");
        assert_eq!(
            validated.algorithm,
            impulse_config::config::JwtAlgorithm::Hs256
        );
        assert_eq!(
            validated.claims.get("sub").and_then(Value::as_str),
            Some("user-1")
        );
    }

    #[test]
    fn jwt_validation_rejects_algorithms_by_policy_with_stable_reasons() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let token = test_hs256_jwt(
            "jwt-secret",
            serde_json::json!({
                "iss": "issuer-1",
                "aud": "aud-1",
                "exp": 4_000_000_000u64,
            }),
            "HS256",
        );

        let failure = super::super::admission::validate_jwt_token(
            token.as_str(),
            &RuntimeJwtAuth {
                secret: "jwt-secret".to_string(),
                issuer: Some("issuer-1".to_string()),
                audience: Some("aud-1".to_string()),
                allowed_algorithms: vec![impulse_config::config::JwtAlgorithm::Rs256],
                clock_skew: Duration::from_secs(30),
                ..RuntimeJwtAuth::default()
            },
            now,
        )
        .expect_err("algorithm must be rejected");

        assert_eq!(failure.reason.as_str(), "algorithm_not_allowed");
    }

    #[test]
    fn jwt_validation_rejects_missing_required_kid_with_stable_reason() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let token = test_hs256_jwt(
            "jwt-secret",
            serde_json::json!({
                "iss": "issuer-1",
                "aud": "aud-1",
                "exp": 4_000_000_000u64,
            }),
            "HS256",
        );

        let failure = super::super::admission::validate_jwt_token(
            token.as_str(),
            &RuntimeJwtAuth {
                secret: "jwt-secret".to_string(),
                issuer: Some("issuer-1".to_string()),
                audience: Some("aud-1".to_string()),
                require_kid: true,
                clock_skew: Duration::from_secs(30),
                ..RuntimeJwtAuth::default()
            },
            now,
        )
        .expect_err("kid must be required");

        assert_eq!(failure.reason.as_str(), "missing_kid");
    }

    #[test]
    fn rs256_jwt_validation_accepts_static_pem_keys() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let rsa = Rsa::generate(2048).expect("rsa key");
        let pkey = PKey::from_rsa(rsa).expect("rsa pkey");
        let token = test_rs256_jwt(
            &pkey,
            Some("rsa-key-1"),
            serde_json::json!({
                "iss": "issuer-1",
                "aud": "aud-1",
                "exp": 4_000_000_000u64,
            }),
        );
        let policy = RuntimeJwtAuth {
            issuer: Some("issuer-1".to_string()),
            audience: Some("aud-1".to_string()),
            allowed_algorithms: vec![JwtAlgorithm::Rs256],
            require_kid: true,
            static_keys: vec![RuntimeJwtVerificationKey::Pem {
                kid: Some("rsa-key-1".to_string()),
                alg: Some(JwtAlgorithm::Rs256),
                public_key_pem: String::from_utf8(
                    pkey.public_key_to_pem().expect("rsa public pem"),
                )
                .expect("utf8"),
            }],
            clock_skew: Duration::from_secs(30),
            ..RuntimeJwtAuth::default()
        };

        let validated = super::super::admission::validate_jwt_token(token.as_str(), &policy, now)
            .expect("rs256 jwt");
        assert_eq!(validated.algorithm, JwtAlgorithm::Rs256);
    }

    #[test]
    fn rs256_jwt_validation_allows_missing_kid_when_exactly_one_key_matches() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let rsa = Rsa::generate(2048).expect("rsa key");
        let pkey = PKey::from_rsa(rsa).expect("rsa pkey");
        let token = test_rs256_jwt(
            &pkey,
            None,
            serde_json::json!({
                "iss": "issuer-1",
                "aud": "aud-1",
                "exp": 4_000_000_000u64,
            }),
        );
        let policy = RuntimeJwtAuth {
            issuer: Some("issuer-1".to_string()),
            audience: Some("aud-1".to_string()),
            allowed_algorithms: vec![JwtAlgorithm::Rs256],
            require_kid: false,
            static_keys: vec![RuntimeJwtVerificationKey::Pem {
                kid: Some("rsa-key-1".to_string()),
                alg: Some(JwtAlgorithm::Rs256),
                public_key_pem: String::from_utf8(
                    pkey.public_key_to_pem().expect("rsa public pem"),
                )
                .expect("utf8"),
            }],
            clock_skew: Duration::from_secs(30),
            ..RuntimeJwtAuth::default()
        };

        let validated = super::super::admission::validate_jwt_token(token.as_str(), &policy, now)
            .expect("rs256 jwt without kid");
        assert_eq!(validated.algorithm, JwtAlgorithm::Rs256);
    }

    #[test]
    fn rs256_jwt_validation_rejects_missing_kid_when_multiple_keys_match() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let first = Rsa::generate(2048).expect("first rsa key");
        let first_key = PKey::from_rsa(first).expect("first rsa pkey");
        let second = Rsa::generate(2048).expect("second rsa key");
        let second_key = PKey::from_rsa(second).expect("second rsa pkey");
        let token = test_rs256_jwt(
            &first_key,
            None,
            serde_json::json!({
                "iss": "issuer-1",
                "aud": "aud-1",
                "exp": 4_000_000_000u64,
            }),
        );

        let failure = super::super::admission::validate_jwt_token(
            token.as_str(),
            &RuntimeJwtAuth {
                issuer: Some("issuer-1".to_string()),
                audience: Some("aud-1".to_string()),
                allowed_algorithms: vec![JwtAlgorithm::Rs256],
                static_keys: vec![
                    RuntimeJwtVerificationKey::Pem {
                        kid: Some("rsa-key-1".to_string()),
                        alg: Some(JwtAlgorithm::Rs256),
                        public_key_pem: String::from_utf8(
                            first_key.public_key_to_pem().expect("first rsa public pem"),
                        )
                        .expect("utf8"),
                    },
                    RuntimeJwtVerificationKey::Pem {
                        kid: Some("rsa-key-2".to_string()),
                        alg: Some(JwtAlgorithm::Rs256),
                        public_key_pem: String::from_utf8(
                            second_key
                                .public_key_to_pem()
                                .expect("second rsa public pem"),
                        )
                        .expect("utf8"),
                    },
                ],
                clock_skew: Duration::from_secs(30),
                ..RuntimeJwtAuth::default()
            },
            now,
        )
        .expect_err("missing kid with multiple matching keys must be ambiguous");

        assert_eq!(failure.reason.as_str(), "ambiguous_verification_key");
    }

    #[test]
    fn es256_jwt_validation_accepts_static_jwk_keys() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("p256");
        let ec_key = EcKey::generate(&group).expect("ec key");
        let token = test_es256_jwt(
            &ec_key,
            Some("ec-key-1"),
            serde_json::json!({
                "iss": "issuer-1",
                "aud": "aud-1",
                "exp": 4_000_000_000u64,
            }),
        );
        let policy = RuntimeJwtAuth {
            issuer: Some("issuer-1".to_string()),
            audience: Some("aud-1".to_string()),
            allowed_algorithms: vec![JwtAlgorithm::Es256],
            require_kid: true,
            static_keys: vec![RuntimeJwtVerificationKey::Jwk {
                kid: Some("ec-key-1".to_string()),
                alg: Some(JwtAlgorithm::Es256),
                jwk: ec_public_jwk(&ec_key, Some("ec-key-1")),
            }],
            clock_skew: Duration::from_secs(30),
            ..RuntimeJwtAuth::default()
        };

        let validated = super::super::admission::validate_jwt_token(token.as_str(), &policy, now)
            .expect("es256 jwt");
        assert_eq!(validated.algorithm, JwtAlgorithm::Es256);
    }

    #[test]
    fn jwt_validation_rejects_invalid_key_type_for_declared_algorithm() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let rsa = Rsa::generate(2048).expect("rsa key");
        let pkey = PKey::from_rsa(rsa).expect("rsa pkey");
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("p256");
        let ec_key = EcKey::generate(&group).expect("ec key");
        let ec_public_pem = String::from_utf8(
            PKey::from_ec_key(ec_key)
                .expect("ec pkey")
                .public_key_to_pem()
                .expect("ec public pem"),
        )
        .expect("utf8");
        let token = test_rs256_jwt(
            &pkey,
            Some("wrong-type"),
            serde_json::json!({
                "iss": "issuer-1",
                "aud": "aud-1",
                "exp": 4_000_000_000u64,
            }),
        );

        let failure = super::super::admission::validate_jwt_token(
            token.as_str(),
            &RuntimeJwtAuth {
                issuer: Some("issuer-1".to_string()),
                audience: Some("aud-1".to_string()),
                allowed_algorithms: vec![JwtAlgorithm::Rs256],
                require_kid: true,
                static_keys: vec![RuntimeJwtVerificationKey::Pem {
                    kid: Some("wrong-type".to_string()),
                    alg: Some(JwtAlgorithm::Rs256),
                    public_key_pem: ec_public_pem,
                }],
                clock_skew: Duration::from_secs(30),
                ..RuntimeJwtAuth::default()
            },
            now,
        )
        .expect_err("invalid key type");

        assert_eq!(failure.reason.as_str(), "invalid_key_type");
    }

    #[test]
    fn jwt_validation_rejects_valid_signature_for_wrong_issuer() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let rsa = Rsa::generate(2048).expect("rsa key");
        let pkey = PKey::from_rsa(rsa).expect("rsa pkey");
        let token = test_rs256_jwt(
            &pkey,
            Some("rsa-key-1"),
            serde_json::json!({
                "iss": "issuer-2",
                "aud": "aud-1",
                "exp": 4_000_000_000u64,
            }),
        );

        let failure = super::super::admission::validate_jwt_token(
            token.as_str(),
            &RuntimeJwtAuth {
                issuers: vec!["issuer-1".to_string(), "issuer-3".to_string()],
                audience: Some("aud-1".to_string()),
                allowed_algorithms: vec![JwtAlgorithm::Rs256],
                require_kid: true,
                static_keys: vec![RuntimeJwtVerificationKey::Pem {
                    kid: Some("rsa-key-1".to_string()),
                    alg: Some(JwtAlgorithm::Rs256),
                    public_key_pem: String::from_utf8(
                        pkey.public_key_to_pem().expect("rsa public pem"),
                    )
                    .expect("utf8"),
                }],
                clock_skew: Duration::from_secs(30),
                ..RuntimeJwtAuth::default()
            },
            now,
        )
        .expect_err("wrong issuer must be rejected after signature verification");

        assert_eq!(failure.reason.as_str(), "issuer_mismatch");
    }

    #[test]
    fn jwt_validation_accepts_tokens_against_multiple_issuer_and_audience_values() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let token = test_hs256_jwt(
            "jwt-secret",
            serde_json::json!({
                "iss": "issuer-2",
                "aud": ["aud-3", "aud-2"],
                "exp": 4_000_000_000u64,
            }),
            "HS256",
        );

        let validated = super::super::admission::validate_jwt_token(
            token.as_str(),
            &RuntimeJwtAuth {
                secret: "jwt-secret".to_string(),
                issuers: vec!["issuer-1".to_string(), "issuer-2".to_string()],
                audiences: vec!["aud-1".to_string(), "aud-2".to_string()],
                allowed_algorithms: vec![JwtAlgorithm::Hs256],
                clock_skew: Duration::from_secs(30),
                ..RuntimeJwtAuth::default()
            },
            now,
        )
        .expect("jwt should match one configured issuer and one configured audience");

        assert_eq!(validated.algorithm, JwtAlgorithm::Hs256);
    }

    #[test]
    fn jwt_validation_rejects_rsa_keys_below_the_minimum_modulus_size() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let rsa = Rsa::generate(1024).expect("weak rsa key");
        let key = PKey::from_rsa(rsa).expect("weak rsa pkey");
        let token = test_rs256_jwt(
            &key,
            Some("weak-rsa"),
            serde_json::json!({
                "iss": "issuer-1",
                "aud": "aud-1",
                "exp": 4_000_000_000u64,
            }),
        );
        let public_key_pem =
            String::from_utf8(key.public_key_to_pem().expect("weak rsa pem")).expect("utf8 pem");

        let failure = super::super::admission::validate_jwt_token(
            token.as_str(),
            &RuntimeJwtAuth {
                issuer: Some("issuer-1".to_string()),
                audience: Some("aud-1".to_string()),
                allowed_algorithms: vec![JwtAlgorithm::Rs256],
                static_keys: vec![RuntimeJwtVerificationKey::Pem {
                    kid: Some("weak-rsa".to_string()),
                    alg: Some(JwtAlgorithm::Rs256),
                    public_key_pem,
                }],
                clock_skew: Duration::from_secs(30),
                ..RuntimeJwtAuth::default()
            },
            now,
        )
        .expect_err("weak rsa key must be rejected");

        assert_eq!(failure.reason.as_str(), "key_too_weak");
    }

    #[test]
    fn jwt_validation_rejects_static_keys_that_collide_on_the_requested_kid() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("p256");
        let first = EcKey::generate(&group).expect("first p256 key");
        let second = EcKey::generate(&group).expect("second p256 key");
        let token = test_es256_jwt(
            &first,
            Some("shared-kid"),
            serde_json::json!({
                "iss": "issuer-1",
                "aud": "aud-1",
                "exp": 4_000_000_000u64,
            }),
        );

        // Both keys resolve to the same effective kid because it is declared
        // inside the JWK body, which config validation cannot deduplicate.
        let failure = super::super::admission::validate_jwt_token(
            token.as_str(),
            &RuntimeJwtAuth {
                issuer: Some("issuer-1".to_string()),
                audience: Some("aud-1".to_string()),
                allowed_algorithms: vec![JwtAlgorithm::Es256],
                static_keys: vec![
                    RuntimeJwtVerificationKey::Jwk {
                        kid: None,
                        alg: Some(JwtAlgorithm::Es256),
                        jwk: ec_public_jwk(&first, Some("shared-kid")),
                    },
                    RuntimeJwtVerificationKey::Jwk {
                        kid: None,
                        alg: Some(JwtAlgorithm::Es256),
                        jwk: ec_public_jwk(&second, Some("shared-kid")),
                    },
                ],
                clock_skew: Duration::from_secs(30),
                ..RuntimeJwtAuth::default()
            },
            now,
        )
        .expect_err("colliding kid must be rejected");

        assert_eq!(failure.reason.as_str(), "ambiguous_verification_key");
    }

    #[test]
    fn jwt_validation_rejects_unsupported_ec_curve() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let token = test_signed_jwt(
            serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": "ec-384" }),
            serde_json::json!({
                "iss": "issuer-1",
                "aud": "aud-1",
                "exp": 4_000_000_000u64,
            }),
            vec![0u8; 64],
        );
        let group = EcGroup::from_curve_name(Nid::SECP384R1).expect("p384");
        let ec_key = EcKey::generate(&group).expect("p384 key");

        let failure = super::super::admission::validate_jwt_token(
            token.as_str(),
            &RuntimeJwtAuth {
                issuer: Some("issuer-1".to_string()),
                audience: Some("aud-1".to_string()),
                allowed_algorithms: vec![JwtAlgorithm::Es256],
                require_kid: true,
                static_keys: vec![RuntimeJwtVerificationKey::Jwk {
                    kid: Some("ec-384".to_string()),
                    alg: Some(JwtAlgorithm::Es256),
                    jwk: ec_public_jwk(&ec_key, Some("ec-384")).replace("\"P-256\"", "\"P-384\""),
                }],
                clock_skew: Duration::from_secs(30),
                ..RuntimeJwtAuth::default()
            },
            now,
        )
        .expect_err("unsupported curve");

        assert_eq!(failure.reason.as_str(), "unsupported_curve");
    }

    #[test]
    fn rs256_jwt_validation_accepts_remote_jwks_cached_keys() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let jwks_url = "https://issuer.example/.well-known/jwks.json";
        super::super::admission::clear_jwks_cache_for_test(jwks_url);

        let rsa = Rsa::generate(2048).expect("rsa key");
        let pkey = PKey::from_rsa(rsa).expect("rsa pkey");
        let token = test_rs256_jwt(
            &pkey,
            Some("jwks-rsa-1"),
            serde_json::json!({
                "iss": "issuer-1",
                "aud": "aud-1",
                "exp": 4_000_000_000u64,
            }),
        );
        super::super::admission::prime_jwks_cache_for_test(
            jwks_url,
            false,
            vec![RuntimeJwtVerificationKey::Pem {
                kid: Some("jwks-rsa-1".to_string()),
                alg: Some(JwtAlgorithm::Rs256),
                public_key_pem: String::from_utf8(
                    pkey.public_key_to_pem().expect("rsa public pem"),
                )
                .expect("utf8"),
            }],
        );

        let policy = RuntimeJwtAuth {
            issuer: Some("issuer-1".to_string()),
            audience: Some("aud-1".to_string()),
            allowed_algorithms: vec![JwtAlgorithm::Rs256],
            require_kid: true,
            jwks_url: Some(jwks_url.to_string()),
            clock_skew: Duration::from_secs(30),
            ..RuntimeJwtAuth::default()
        };

        let validated = super::super::admission::validate_jwt_token(token.as_str(), &policy, now)
            .expect("rs256 jwt from cached jwks");
        assert_eq!(validated.algorithm, JwtAlgorithm::Rs256);

        super::super::admission::clear_jwks_cache_for_test(jwks_url);
    }

    #[test]
    fn es256_jwt_validation_accepts_stale_remote_jwks_keys() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let jwks_url = "https://issuer.example/stale-jwks.json";
        super::super::admission::clear_jwks_cache_for_test(jwks_url);

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("p256");
        let ec_key = EcKey::generate(&group).expect("ec key");
        let token = test_es256_jwt(
            &ec_key,
            Some("jwks-ec-1"),
            serde_json::json!({
                "iss": "issuer-1",
                "aud": "aud-1",
                "exp": 4_000_000_000u64,
            }),
        );
        super::super::admission::prime_jwks_cache_for_test(
            jwks_url,
            true,
            vec![RuntimeJwtVerificationKey::Jwk {
                kid: Some("jwks-ec-1".to_string()),
                alg: Some(JwtAlgorithm::Es256),
                jwk: ec_public_jwk(&ec_key, Some("jwks-ec-1")),
            }],
        );

        let policy = RuntimeJwtAuth {
            issuer: Some("issuer-1".to_string()),
            audience: Some("aud-1".to_string()),
            allowed_algorithms: vec![JwtAlgorithm::Es256],
            require_kid: true,
            jwks_url: Some(jwks_url.to_string()),
            clock_skew: Duration::from_secs(30),
            ..RuntimeJwtAuth::default()
        };

        let validated = super::super::admission::validate_jwt_token(token.as_str(), &policy, now)
            .expect("es256 jwt from stale jwks cache");
        assert_eq!(validated.algorithm, JwtAlgorithm::Es256);

        super::super::admission::clear_jwks_cache_for_test(jwks_url);
    }

    #[test]
    fn jwt_validation_rejects_unavailable_remote_jwks_source() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let jwks_url = "https://issuer.example/unavailable-jwks.json";
        super::super::admission::clear_jwks_cache_for_test(jwks_url);

        let rsa = Rsa::generate(2048).expect("rsa key");
        let pkey = PKey::from_rsa(rsa).expect("rsa pkey");
        let token = test_rs256_jwt(
            &pkey,
            Some("jwks-rsa-2"),
            serde_json::json!({
                "iss": "issuer-1",
                "aud": "aud-1",
                "exp": 4_000_000_000u64,
            }),
        );
        super::super::admission::mark_jwks_source_unavailable_for_test(jwks_url);

        let failure = super::super::admission::validate_jwt_token(
            token.as_str(),
            &RuntimeJwtAuth {
                issuer: Some("issuer-1".to_string()),
                audience: Some("aud-1".to_string()),
                allowed_algorithms: vec![JwtAlgorithm::Rs256],
                require_kid: true,
                jwks_url: Some(jwks_url.to_string()),
                clock_skew: Duration::from_secs(30),
                ..RuntimeJwtAuth::default()
            },
            now,
        )
        .expect_err("unavailable jwks source must be surfaced");

        assert_eq!(failure.reason.as_str(), "key_source_unavailable");

        super::super::admission::clear_jwks_cache_for_test(jwks_url);
    }

    #[test]
    fn jwt_validation_rejects_invalid_remote_jwks_source() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let jwks_url = "https://issuer.example/invalid-jwks.json";
        super::super::admission::clear_jwks_cache_for_test(jwks_url);

        let rsa = Rsa::generate(2048).expect("rsa key");
        let pkey = PKey::from_rsa(rsa).expect("rsa pkey");
        let token = test_rs256_jwt(
            &pkey,
            Some("jwks-rsa-3"),
            serde_json::json!({
                "iss": "issuer-1",
                "aud": "aud-1",
                "exp": 4_000_000_000u64,
            }),
        );
        super::super::admission::mark_jwks_source_invalid_for_test(jwks_url);

        let failure = super::super::admission::validate_jwt_token(
            token.as_str(),
            &RuntimeJwtAuth {
                issuer: Some("issuer-1".to_string()),
                audience: Some("aud-1".to_string()),
                allowed_algorithms: vec![JwtAlgorithm::Rs256],
                require_kid: true,
                jwks_url: Some(jwks_url.to_string()),
                clock_skew: Duration::from_secs(30),
                ..RuntimeJwtAuth::default()
            },
            now,
        )
        .expect_err("invalid jwks source must be surfaced");

        assert_eq!(failure.reason.as_str(), "jwk_key_parse_failed");

        super::super::admission::clear_jwks_cache_for_test(jwks_url);
    }

    #[test]
    fn jwks_normalization_filters_keys_by_policy() {
        let rsa = Rsa::generate(2048).expect("rsa key");
        let rsa_key = PKey::from_rsa(rsa).expect("rsa pkey");
        let ec_group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("p256");
        let ec_key = EcKey::generate(&ec_group).expect("ec key");
        let ignored_rsa = Rsa::generate(2048).expect("ignored rsa");
        let ignored_rsa_key = PKey::from_rsa(ignored_rsa).expect("ignored rsa pkey");

        let jwks = serde_json::json!({
            "keys": [
                serde_json::from_str::<Value>(&rsa_public_jwk(
                    &rsa_key,
                    Some("rsa-allowed"),
                    None,
                    Some("sig"),
                    Some(vec!["verify"]),
                )).expect("rsa jwk"),
                serde_json::from_str::<Value>(&ec_public_jwk(&ec_key, Some("ec-not-allowed")))
                    .expect("ec jwk"),
                serde_json::from_str::<Value>(&rsa_public_jwk(
                    &ignored_rsa_key,
                    Some("rsa-enc"),
                    Some("RS256"),
                    Some("enc"),
                    Some(vec!["verify"]),
                )).expect("enc jwk"),
                serde_json::json!({
                    "kty": "RSA",
                    "kid": "malformed-rsa",
                    "alg": "RS256",
                    "use": "sig",
                    "key_ops": ["verify"],
                    "e": "AQAB"
                })
            ]
        });

        let keys = super::super::admission::normalize_jwks_document_for_test(
            "https://issuer.example/jwks.json",
            &jwks,
            &[JwtAlgorithm::Rs256],
        )
        .expect("normalized jwks");

        assert_eq!(keys.len(), 1);
        match &keys[0] {
            RuntimeJwtVerificationKey::Jwk { kid, alg, .. } => {
                assert_eq!(kid.as_deref(), Some("rsa-allowed"));
                assert_eq!(*alg, Some(JwtAlgorithm::Rs256));
            }
            other => panic!("expected normalized jwk key, got {other:?}"),
        }
    }

    #[test]
    fn jwks_normalization_rejects_duplicate_kid_entries() {
        let first = Rsa::generate(2048).expect("first rsa");
        let second = Rsa::generate(2048).expect("second rsa");
        let first_key = PKey::from_rsa(first).expect("first pkey");
        let second_key = PKey::from_rsa(second).expect("second pkey");
        let jwks = serde_json::json!({
            "keys": [
                serde_json::from_str::<Value>(&rsa_public_jwk(
                    &first_key,
                    Some("shared-kid"),
                    Some("RS256"),
                    Some("sig"),
                    Some(vec!["verify"]),
                )).expect("first jwk"),
                serde_json::from_str::<Value>(&rsa_public_jwk(
                    &second_key,
                    Some("shared-kid"),
                    Some("RS256"),
                    Some("sig"),
                    Some(vec!["verify"]),
                )).expect("second jwk")
            ]
        });

        let failure = super::super::admission::normalize_jwks_document_for_test(
            "https://issuer.example/jwks.json",
            &jwks,
            &[JwtAlgorithm::Rs256],
        )
        .expect_err("duplicate kid must be rejected");

        assert_eq!(
            failure.reason,
            super::super::admission::JwtJwksFetchFailureReason::AmbiguousDuplicateKid
        );
    }

    #[test]
    fn jwt_rbac_requires_configured_scopes_and_roles() {
        let policy = RuntimeUpstreamPolicy {
            upstream_auth: RuntimeAuthPolicy {
                api_key: None,
                jwt: None,
                external_auth: None,
                required_scopes: vec!["read:fast".to_string()],
                required_roles: vec!["admin".to_string()],
            },
            host: Default::default(),
            forwarded_headers: Default::default(),
            response_cache: Default::default(),
            response_compression: Default::default(),
            protocol: Default::default(),
        };
        let allowed_claims = serde_json::json!({
            "scope": "read:fast write:slow",
            "roles": ["admin", "operator"]
        });
        let denied_claims = serde_json::json!({
            "scope": "write:slow",
            "roles": ["operator"]
        });

        assert!(super::super::admission::jwt_claims_satisfy_rbac(
            &policy,
            &allowed_claims
        ));
        assert!(!super::super::admission::jwt_claims_satisfy_rbac(
            &policy,
            &denied_claims
        ));
    }

    fn lb_key_request_parts<'a>(
        method: &'a str,
        path: &'a str,
        authority: Option<&'a str>,
        cid_key: Option<&'a str>,
        client_addr: Option<SocketAddr>,
        header_lookup: Option<&'a LbHeaderLookup<'a>>,
    ) -> super::lb_key::LbKeyRequestParts<'a> {
        super::lb_key::LbKeyRequestParts::new(
            method,
            path,
            authority,
            cid_key,
            client_addr,
            header_lookup,
        )
    }

    #[test]
    fn resolve_lb_key_supports_peer_ip_and_bearer_token() {
        let headers = [("authorization".to_string(), "Bearer token-1".to_string())]
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();
        let lookup = |name: &str| headers.get(&name.to_ascii_lowercase()).cloned();
        let client_addr = "203.0.113.9:443".parse().expect("client addr");

        assert_eq!(
            QUICListener::resolve_lb_key(
                "",
                Some("peer_ip"),
                lb_key_request_parts(
                    "GET",
                    "/",
                    Some("api.example.com"),
                    None,
                    Some(client_addr),
                    Some(&lookup),
                ),
            )
            .value,
            "203.0.113.9"
        );
        assert_eq!(
            QUICListener::resolve_lb_key(
                "",
                Some("bearer_token"),
                lb_key_request_parts(
                    "GET",
                    "/",
                    Some("api.example.com"),
                    None,
                    Some(client_addr),
                    Some(&lookup),
                ),
            )
            .value,
            "token-1"
        );
    }

    #[test]
    fn canonical_lb_key_resolver_extracts_common_sources() {
        let headers = [
            ("authorization".to_string(), "Bearer token-3".to_string()),
            ("cookie".to_string(), "session=s123; theme=dark".to_string()),
            ("x-user-id".to_string(), "alice".to_string()),
        ]
        .into_iter()
        .collect::<std::collections::HashMap<_, _>>();
        let lookup = |name: &str| headers.get(&name.to_ascii_lowercase()).cloned();
        let client_addr = "203.0.113.9:443".parse().expect("client addr");

        let assert_key = |spec: &str, expected: &str| {
            let resolved = QUICListener::resolve_lb_key(
                "",
                Some(spec),
                lb_key_request_parts(
                    "POST",
                    "/api/items?tenant=acme",
                    Some("api.example.com"),
                    Some("cid-123"),
                    Some(client_addr),
                    Some(&lookup),
                ),
            );
            assert_eq!(resolved.value, expected);
            assert!(matches!(
                resolved.source,
                super::lb_key::LbKeySource::ConfiguredSpec
            ));
        };

        assert_key("header:x-user-id", "alice");
        assert_key("cookie:session", "s123");
        assert_key("query:tenant", "acme");
        assert_key("bearer_token", "token-3");
        assert_key("cid", "cid-123");
        assert_key("peer_ip", "203.0.113.9");
        assert_key("path", "/api/items");
        assert_key("authority", "api.example.com");
        assert_key("method", "POST");
    }

    #[test]
    fn canonical_lb_key_resolver_unifies_default_and_sticky_cid_fallbacks() {
        let sticky = QUICListener::resolve_lb_key(
            "sticky-cid",
            Some("header:x-user-id"),
            lb_key_request_parts(
                "GET",
                "/resource",
                Some("api.example.com"),
                Some("cid-123"),
                None,
                None,
            ),
        );
        assert_eq!(sticky.value, "cid-123");
        assert!(matches!(
            sticky.source,
            super::lb_key::LbKeySource::StickyCidFallback
        ));

        let authority_default = QUICListener::resolve_lb_key(
            "",
            Some("header:x-user-id"),
            lb_key_request_parts(
                "GET",
                "/resource",
                Some("api.example.com"),
                None,
                None,
                None,
            ),
        );
        assert_eq!(authority_default.value, "api.example.com");
        assert!(matches!(
            authority_default.source,
            super::lb_key::LbKeySource::DefaultFallback
        ));

        let path_default = QUICListener::resolve_lb_key(
            "",
            Some("header:x-user-id"),
            lb_key_request_parts("GET", "/resource", None, None, None, None),
        );
        assert_eq!(path_default.value, "/resource");

        let method_default = QUICListener::resolve_lb_key(
            "",
            Some("header:x-user-id"),
            lb_key_request_parts("GET", "", None, None, None, None),
        );
        assert_eq!(method_default.value, "GET");
        assert!(matches!(
            method_default.source,
            super::lb_key::LbKeySource::DefaultFallback
        ));
    }

    #[test]
    fn canonical_lb_key_route_request_adapter_matches_direct_resolver() {
        let headers = [
            ("authorization".to_string(), "Bearer token-4".to_string()),
            ("x-user-id".to_string(), "bob".to_string()),
        ]
        .into_iter()
        .collect::<std::collections::HashMap<_, _>>();
        let lookup = |name: &str| headers.get(&name.to_ascii_lowercase()).cloned();
        let route_request = TestTargetResolutionRequest::new(
            "GET",
            "/api/items?tenant=acme",
            Some("api.example.com"),
            Some("cid-456"),
            Some(&lookup),
        );

        let direct_header = QUICListener::resolve_lb_key(
            "",
            Some("header:x-user-id"),
            lb_key_request_parts(
                "GET",
                "/api/items?tenant=acme",
                Some("api.example.com"),
                Some("cid-456"),
                None,
                Some(&lookup),
            ),
        );
        let routed_header = QUICListener::resolve_lb_key_for_runtime_request(
            impulse_lb::LoadBalancingStrategy::RoundRobin,
            Some(&impulse_lb::RequestKeyInput::Header(
                "x-user-id".to_string(),
            )),
            &route_request,
        );
        assert_eq!(direct_header.value, routed_header.value);
        assert!(matches!(
            routed_header.source,
            super::lb_key::LbKeySource::ConfiguredSpec
        ));

        let direct_sticky = QUICListener::resolve_lb_key(
            "sticky-cid",
            Some("header:x-missing"),
            lb_key_request_parts(
                "GET",
                "/api/items?tenant=acme",
                Some("api.example.com"),
                Some("cid-456"),
                None,
                Some(&lookup),
            ),
        );
        let routed_sticky = QUICListener::resolve_lb_key_for_runtime_request(
            impulse_lb::LoadBalancingStrategy::StickyCid,
            Some(&impulse_lb::RequestKeyInput::Header(
                "x-missing".to_string(),
            )),
            &route_request,
        );
        assert_eq!(direct_sticky.value, routed_sticky.value);
        assert!(matches!(
            routed_sticky.source,
            super::lb_key::LbKeySource::StickyCidFallback
        ));
    }

    #[test]
    fn resolve_scoped_rate_limit_key_defaults_match_scope() {
        let client_rule = crate::resilience::scoped_rate_limit::ScopedRateLimitRule::from_config(
            &ScopedRateLimit {
                name: "client".to_string(),
                scope: ScopedRateLimitScope::Client,
                requests_per_sec: 10,
                burst: 10,
                key: None,
                route_allowlist: Vec::new(),
                idle_ttl_secs: 300,
            },
        );
        let token_rule = crate::resilience::scoped_rate_limit::ScopedRateLimitRule::from_config(
            &ScopedRateLimit {
                name: "token".to_string(),
                scope: ScopedRateLimitScope::Token,
                requests_per_sec: 10,
                burst: 10,
                key: None,
                route_allowlist: Vec::new(),
                idle_ttl_secs: 300,
            },
        );
        let headers = [("authorization".to_string(), "Bearer token-2".to_string())]
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();
        let lookup = |name: &str| headers.get(&name.to_ascii_lowercase()).cloned();
        let client_addr = "198.51.100.10:443".parse().expect("client addr");

        assert_eq!(
            QUICListener::resolve_scoped_rate_limit_key(
                &client_rule,
                "api",
                "GET",
                "/resource",
                Some("api.example.com"),
                client_addr,
                Some(&lookup),
            )
            .as_deref(),
            Some("198.51.100.10")
        );
        assert_eq!(
            QUICListener::resolve_scoped_rate_limit_key(
                &token_rule,
                "api",
                "GET",
                "/resource",
                Some("api.example.com"),
                client_addr,
                Some(&lookup),
            )
            .as_deref(),
            Some("token-2")
        );
    }

    #[test]
    fn resolve_scoped_rate_limit_key_falls_back_to_default_request_key() {
        let tenant_rule = crate::resilience::scoped_rate_limit::ScopedRateLimitRule::from_config(
            &ScopedRateLimit {
                name: "tenant".to_string(),
                scope: ScopedRateLimitScope::Tenant,
                requests_per_sec: 10,
                burst: 10,
                key: Some("header:x-tenant-id".to_string()),
                route_allowlist: Vec::new(),
                idle_ttl_secs: 300,
            },
        );
        let headers = std::collections::HashMap::<String, String>::new();
        let lookup = |name: &str| headers.get(&name.to_ascii_lowercase()).cloned();
        let client_addr = "198.51.100.10:443".parse().expect("client addr");

        assert_eq!(
            QUICListener::resolve_scoped_rate_limit_key(
                &tenant_rule,
                "api",
                "GET",
                "/resource",
                Some("api.example.com"),
                client_addr,
                Some(&lookup),
            )
            .as_deref(),
            Some("api.example.com")
        );
    }

    #[test]
    fn resolve_lb_key_uses_sticky_cid_before_default_fallback() {
        let resolved = QUICListener::resolve_lb_key(
            "sticky-cid",
            Some("header:x-user-id"),
            lb_key_request_parts(
                "GET",
                "/resource",
                Some("api.example.com"),
                Some("cid-123"),
                None,
                None,
            ),
        );

        assert_eq!(resolved.value, "cid-123");
        assert!(matches!(
            resolved.source,
            super::lb_key::LbKeySource::StickyCidFallback
        ));
    }

    #[test]
    fn pending_forward_request_headers_apply_auth_mutations() {
        let pending_forward = PendingForward {
            auth_header_mutations: vec![
                PendingHeaderMutation::Upsert {
                    name: b"x-user-id".to_vec(),
                    value: b"fresh".to_vec(),
                },
                PendingHeaderMutation::Remove {
                    name: b"x-remove-me".to_vec(),
                },
            ],
            ..sample_pending_forward(vec![
                quiche::h3::Header::new(b":method", b"GET"),
                quiche::h3::Header::new(b"x-user-id", b"stale"),
                quiche::h3::Header::new(b"x-remove-me", b"1"),
            ])
        };

        let headers = pending_forward.owned_request_headers();
        assert!(headers.iter().any(|header| header.name() == b":method"));
        assert!(
            headers
                .iter()
                .any(|header| header.name() == b"x-user-id" && header.value() == b"fresh")
        );
        assert!(
            !headers
                .iter()
                .any(|header| header.name() == b"x-user-id" && header.value() == b"stale")
        );
        assert!(!headers.iter().any(|header| header.name() == b"x-remove-me"));
    }

    #[test]
    fn append_auth_request_headers_strips_hop_by_hop_and_framing_headers() {
        let pending_forward = sample_pending_forward(vec![
            quiche::h3::Header::new(b":method", b"GET"),
            quiche::h3::Header::new(b"host", b"client.example.com"),
            quiche::h3::Header::new(b"content-length", b"42"),
            quiche::h3::Header::new(b"connection", b"keep-alive"),
            quiche::h3::Header::new(b"cookie", b"session=1"),
            quiche::h3::Header::new(b"authorization", b"Bearer token"),
        ]);
        let mut builder = Request::builder()
            .method(http::Method::GET)
            .uri("https://auth.internal/check");

        append_auth_request_headers(&mut builder, &pending_forward, &[]);

        let headers = builder.headers_ref().expect("headers");
        assert!(!headers.contains_key(http::header::HOST));
        assert!(!headers.contains_key(http::header::CONTENT_LENGTH));
        assert!(!headers.contains_key(http::header::CONNECTION));
        assert_eq!(
            headers
                .get(http::header::COOKIE)
                .and_then(|value| value.to_str().ok()),
            Some("session=1")
        );
        assert_eq!(
            headers
                .get(http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer token")
        );
    }
}
