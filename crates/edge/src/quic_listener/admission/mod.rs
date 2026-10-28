#[cfg(test)]
use std::{collections::VecDeque, sync::Mutex};
use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    future::Future,
    net::SocketAddr,
    sync::{Arc, OnceLock, RwLock, Weak},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _engine, engine::general_purpose::URL_SAFE_NO_PAD};
use boring::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id as PKeyId, PKey, Public},
    rsa::{Padding, Rsa},
    sign::Verifier,
};
use bytes::Bytes;
use hmac::{Hmac, Mac};
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
    runtime::{RuntimeConfig, RuntimeJwtAuth, RuntimeJwtVerificationKey, RuntimeUpstreamPolicy},
};
use impulse_lb::upstream_pool::UpstreamPool;
use quiche::h3::NameValue;
use serde_json::Value;
#[cfg(test)]
use serial_test::serial;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::{
    runtime::RuntimeFlavor,
    sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError},
    task::block_in_place,
};

use super::{LbHeaderLookup, QUICListener, runtime_handle, spawn_supervised_async_task};
use crate::{
    RouteOutcome,
    metrics::OverloadShedReason,
    resilience::{
        adaptive_admission::AdaptivePermit,
        brownout::BrownoutController,
        quota::{QuotaDecision, QuotaDenyReason, QuotaIdentityContext, evaluate_admission_quota},
        route_queue::{RouteQueuePermit, RouteQueueRejection},
        runtime::RuntimeResilience,
        scoped_rate_limit::ScopedRateLimiters,
    },
    runtime::{
        connection::{auth::apply_auth_request_mutations, request::PendingForward},
        tasks::RuntimeTaskRegistry,
    },
};

mod jwks_cache;
mod jwks_refresh;
mod jwt;
mod key_resolution;
mod startup;

pub(crate) use impulse_contracts::{
    AuthChallengeKind, BoundedRejectionResponse as AdmissionRejectionResponse, OverloadDecision,
    OverloadDecisionReason, RateLimitedDecision, RequestDecision as AdmissionPolicyDecision,
    UnauthorizedDecision,
};

#[cfg(test)]
pub(super) use self::jwks_cache::{
    clear_jwks_cache_for_test, jwks_source_identity_for_test, mark_jwks_source_invalid_for_test,
    mark_jwks_source_unavailable_for_test, prime_jwks_cache_for_test,
};
#[cfg(test)]
pub(super) use self::jwks_refresh::{
    normalize_jwks_document_for_test, script_jwks_fetches_for_test,
};
#[cfg(test)]
pub(super) use self::jwt::validated_hs256_jwt_claims;
#[allow(unused_imports)]
pub(super) use self::jwt::{
    JwtValidationFailure, JwtValidationFailureReason, ValidatedJwt, jwt_claims_satisfy_rbac,
    validate_jwt_token,
};
use self::{jwks_cache::*, jwks_refresh::*, jwt::*, key_resolution::*};
pub(super) use self::{
    jwks_cache::{
        JwtJwksRuntimeSnapshot, runtime_jwks_source_identity, snapshot_runtime_jwks_sources,
    },
    jwks_refresh::{JwtJwksFetchFailure, JwtJwksFetchFailureReason},
};

pub(crate) const fn overload_metrics_reason(reason: OverloadDecisionReason) -> OverloadShedReason {
    match reason {
        OverloadDecisionReason::Brownout => OverloadShedReason::Brownout,
        OverloadDecisionReason::AdaptiveAdmission => OverloadShedReason::AdaptiveAdmission,
        OverloadDecisionReason::RouteCap => OverloadShedReason::RouteCap,
        OverloadDecisionReason::RouteGlobalCap => OverloadShedReason::RouteGlobalCap,
        OverloadDecisionReason::GlobalInflight => OverloadShedReason::GlobalInflight,
        OverloadDecisionReason::UpstreamInflight => OverloadShedReason::UpstreamInflight,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QuotaRejectedDecision {
    pub(super) policy_name: String,
    pub(super) reason: QuotaDenyReason,
    pub(super) status: StatusCode,
    pub(super) body: &'static [u8],
    pub(super) retry_after_seconds: Option<u32>,
}

#[derive(Debug, Clone)]
pub(super) struct PostAuthAdmissionFailure {
    pub(super) status: StatusCode,
    pub(super) body: &'static [u8],
    pub(super) overload_reason: Option<OverloadDecisionReason>,
    pub(super) route_outcome: Option<RouteOutcome>,
    pub(super) observe_adaptive_overload: bool,
}

pub(super) struct PostAuthAdmissionReady {
    pub(super) backend_index: usize,
    pub(super) upstream_pool: Arc<RwLock<UpstreamPool>>,
    pub(super) global_permit: OwnedSemaphorePermit,
    pub(super) upstream_permit: OwnedSemaphorePermit,
    pub(super) adaptive_permit: AdaptivePermit,
    pub(super) route_queue_permit: RouteQueuePermit,
    pub(super) waited_for_global_permit: bool,
    pub(super) waited_for_upstream_permit: bool,
}

#[derive(Debug, Clone)]
pub(super) enum PostAuthAdmissionRejection {
    Quota(QuotaRejectedDecision),
    Overloaded(OverloadDecision),
    Failed(PostAuthAdmissionFailure),
}

pub(super) enum PostAuthAdmissionExecution {
    Ready(PostAuthAdmissionReady),
    Rejected(PostAuthAdmissionRejection),
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_forwarding_pre_admission_policy(
    policy: &RuntimeUpstreamPolicy,
    header_lookup: Option<&LbHeaderLookup<'_>>,
    brownout: &BrownoutController,
    inflight_percent: u8,
    route: &str,
    method: &str,
    path: &str,
    authority: Option<&str>,
    client_addr: SocketAddr,
    retry_after_seconds: u32,
    scoped_rate_limits: &ScopedRateLimiters,
) -> AdmissionPolicyDecision {
    let auth = evaluate_local_auth_policy(policy, header_lookup);
    if auth != AdmissionPolicyDecision::AdmitReady {
        return auth;
    }

    let brownout = evaluate_brownout_policy(brownout, inflight_percent, route, retry_after_seconds);
    if brownout != AdmissionPolicyDecision::AdmitReady {
        return brownout;
    }

    evaluate_scoped_rate_limit_policy(
        scoped_rate_limits,
        route,
        method,
        path,
        authority,
        client_addr,
        header_lookup,
    )
}

pub(super) fn evaluate_local_auth_policy(
    policy: &RuntimeUpstreamPolicy,
    header_lookup: Option<&LbHeaderLookup<'_>>,
) -> AdmissionPolicyDecision {
    if !api_key_is_authorized(policy, header_lookup) {
        return AdmissionPolicyDecision::Unauthorized(UnauthorizedDecision {
            challenge: AuthChallengeKind::ApiKey,
            status: StatusCode::UNAUTHORIZED,
            body: b"unauthorized\n",
        });
    }

    if !jwt_is_authorized(policy, header_lookup) {
        return AdmissionPolicyDecision::Unauthorized(UnauthorizedDecision {
            challenge: AuthChallengeKind::Bearer,
            status: StatusCode::UNAUTHORIZED,
            body: b"unauthorized\n",
        });
    }

    AdmissionPolicyDecision::AdmitReady
}

pub(super) fn evaluate_scoped_rate_limit_policy(
    scoped_rate_limits: &ScopedRateLimiters,
    route: &str,
    method: &str,
    path: &str,
    authority: Option<&str>,
    client_addr: SocketAddr,
    header_lookup: Option<&LbHeaderLookup<'_>>,
) -> AdmissionPolicyDecision {
    if runtime_handle().is_none() {
        return AdmissionPolicyDecision::AdmitReady;
    }
    let quota_context = QuotaIdentityContext::new(
        Some(route),
        method,
        path,
        authority,
        None,
        Some(client_addr),
        header_lookup,
    );

    match block_on_admission_future(async {
        evaluate_admission_quota(
            scoped_rate_limits.quota_runtime(),
            scoped_rate_limits,
            &quota_context,
        )
        .await
    })
    .unwrap_or(QuotaDecision::NotApplied)
    {
        QuotaDecision::Denied(denial) => {
            AdmissionPolicyDecision::RateLimited(RateLimitedDecision {
                rule_name: denial.policy_name,
                route: route.to_string(),
                status: StatusCode::TOO_MANY_REQUESTS,
                body: b"request rate limited\n",
                retry_after_seconds: denial.retry_after_seconds.unwrap_or(1).max(1),
            })
        }
        QuotaDecision::NotApplied
        | QuotaDecision::Allowed(_)
        | QuotaDecision::ShadowDenied(_)
        | QuotaDecision::FailedOpen(_)
        | QuotaDecision::FailedClosed(_) => AdmissionPolicyDecision::AdmitReady,
    }
}

pub(super) fn evaluate_brownout_policy(
    brownout: &BrownoutController,
    inflight_percent: u8,
    route: &str,
    retry_after_seconds: u32,
) -> AdmissionPolicyDecision {
    brownout.observe_admission_pressure(inflight_percent);
    if brownout.route_allowed(route) {
        return AdmissionPolicyDecision::AdmitReady;
    }

    overload_decision(OverloadDecisionReason::Brownout, retry_after_seconds)
}

fn overload_decision(
    reason: OverloadDecisionReason,
    retry_after_seconds: u32,
) -> AdmissionPolicyDecision {
    AdmissionPolicyDecision::Overloaded(OverloadDecision {
        reason,
        status: StatusCode::SERVICE_UNAVAILABLE,
        body: reason.response_body(),
        retry_after_seconds: retry_after_seconds.max(1),
    })
}

fn overload_decision_for_route_queue_rejection(
    rejection: RouteQueueRejection,
    retry_after_seconds: u32,
) -> AdmissionPolicyDecision {
    let reason = match rejection {
        RouteQueueRejection::GlobalCap => OverloadDecisionReason::RouteGlobalCap,
        RouteQueueRejection::RouteCap => OverloadDecisionReason::RouteCap,
    };
    overload_decision(reason, retry_after_seconds)
}

pub(crate) fn admission_rejection_response(
    decision: &AdmissionPolicyDecision,
) -> Option<AdmissionRejectionResponse> {
    decision.rejection_response()
}

impl QuotaRejectedDecision {
    fn from_quota_decision(decision: QuotaDecision) -> Option<Self> {
        match decision {
            QuotaDecision::Denied(denial) | QuotaDecision::ShadowDenied(denial) => Some(Self {
                policy_name: denial.policy_name,
                reason: denial.reason,
                status: StatusCode::TOO_MANY_REQUESTS,
                body: quota_response_body(denial.reason),
                retry_after_seconds: denial.retry_after_seconds.map(|value| value.max(1)),
            }),
            QuotaDecision::FailedClosed(failure) => Some(Self {
                policy_name: failure.policy_name.unwrap_or_else(|| "unknown".to_string()),
                reason: failure.reason,
                status: StatusCode::SERVICE_UNAVAILABLE,
                body: quota_response_body(failure.reason),
                retry_after_seconds: None,
            }),
            QuotaDecision::NotApplied
            | QuotaDecision::Allowed(_)
            | QuotaDecision::FailedOpen(_) => None,
        }
    }

    pub(crate) fn as_response(&self) -> AdmissionRejectionResponse {
        AdmissionRejectionResponse {
            status: self.status,
            body: self.body,
            www_authenticate: None,
            retry_after_seconds: self.retry_after_seconds,
        }
    }
}

fn quota_response_body(reason: QuotaDenyReason) -> &'static [u8] {
    match reason {
        QuotaDenyReason::BurstQuotaExhausted => b"burst quota exhausted\n",
        QuotaDenyReason::SustainedQuotaExhausted => b"sustained quota exhausted\n",
        QuotaDenyReason::SelectorIdentityMissing => b"quota selector identity missing\n",
        QuotaDenyReason::SelectorIdentityInvalid => b"quota selector identity invalid\n",
        QuotaDenyReason::BackendTimeout => b"quota backend timed out\n",
        QuotaDenyReason::BackendUnavailable => b"quota backend unavailable\n",
        QuotaDenyReason::BackendError => b"quota backend error\n",
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn execute_forwarding_post_auth_admission(
    resilience: &RuntimeResilience,
    pending_forward: &PendingForward,
    upstream_pool: Option<&Arc<RwLock<UpstreamPool>>>,
    backend_index: Option<usize>,
    upstream_inflight: &HashMap<String, Arc<Semaphore>>,
    global_inflight: Arc<Semaphore>,
    inflight_acquire_wait: Duration,
) -> PostAuthAdmissionExecution {
    if let Some(rejection) = evaluate_forwarding_post_auth_quota_policy(resilience, pending_forward)
    {
        return PostAuthAdmissionExecution::Rejected(rejection);
    }

    let upstream_name = pending_forward.upstream_name.as_ref();
    let adaptive_permit = match resilience.adaptive_admission.try_acquire() {
        Some(permit) => permit,
        None => {
            return PostAuthAdmissionExecution::Rejected(PostAuthAdmissionRejection::Overloaded(
                overloaded(
                    OverloadDecisionReason::AdaptiveAdmission,
                    resilience.shed_retry_after_seconds,
                ),
            ));
        }
    };

    let route_queue_permit = match resilience.route_queue.try_acquire(upstream_name) {
        Ok(permit) => permit,
        Err(rejection) => {
            return PostAuthAdmissionExecution::Rejected(PostAuthAdmissionRejection::Overloaded(
                overload_from_route_queue_rejection(rejection, resilience.shed_retry_after_seconds),
            ));
        }
    };

    let (global_permit, waited_for_global_permit) =
        match try_acquire_owned_with_micro_wait(global_inflight, inflight_acquire_wait) {
            Ok(value) => value,
            Err(_) => {
                return PostAuthAdmissionExecution::Rejected(
                    PostAuthAdmissionRejection::Overloaded(overloaded(
                        OverloadDecisionReason::GlobalInflight,
                        resilience.shed_retry_after_seconds,
                    )),
                );
            }
        };

    let (upstream_permit, waited_for_upstream_permit) =
        match upstream_inflight.get(upstream_name).cloned() {
            Some(semaphore) => {
                match try_acquire_owned_with_micro_wait(semaphore, inflight_acquire_wait) {
                    Ok(value) => value,
                    Err(_) => {
                        return PostAuthAdmissionExecution::Rejected(
                            PostAuthAdmissionRejection::Overloaded(overloaded(
                                OverloadDecisionReason::UpstreamInflight,
                                resilience.shed_retry_after_seconds,
                            )),
                        );
                    }
                }
            }
            None => {
                return PostAuthAdmissionExecution::Rejected(PostAuthAdmissionRejection::Failed(
                    PostAuthAdmissionFailure {
                        status: StatusCode::SERVICE_UNAVAILABLE,
                        body: b"upstream admission limiter unavailable\n",
                        overload_reason: Some(OverloadDecisionReason::UpstreamInflight),
                        route_outcome: Some(RouteOutcome::OverloadShed),
                        observe_adaptive_overload: true,
                    },
                ));
            }
        };

    let backend_index = backend_index.unwrap_or(pending_forward.backend_index);
    let Some(upstream_pool) = upstream_pool.cloned() else {
        return PostAuthAdmissionExecution::Rejected(PostAuthAdmissionRejection::Failed(
            PostAuthAdmissionFailure {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                body: b"missing upstream pool\n",
                overload_reason: None,
                route_outcome: None,
                observe_adaptive_overload: false,
            },
        ));
    };

    let backend_healthy = upstream_pool
        .read()
        .ok()
        .is_some_and(|pool| pool.is_backend_healthy(backend_index));
    if !backend_healthy {
        return PostAuthAdmissionExecution::Rejected(PostAuthAdmissionRejection::Failed(
            PostAuthAdmissionFailure {
                status: StatusCode::SERVICE_UNAVAILABLE,
                body: b"selected backend no longer healthy\n",
                overload_reason: None,
                route_outcome: Some(RouteOutcome::Failure),
                observe_adaptive_overload: false,
            },
        ));
    }

    PostAuthAdmissionExecution::Ready(PostAuthAdmissionReady {
        backend_index,
        upstream_pool,
        global_permit,
        upstream_permit,
        adaptive_permit,
        route_queue_permit,
        waited_for_global_permit,
        waited_for_upstream_permit,
    })
}

fn evaluate_forwarding_post_auth_quota_policy(
    resilience: &RuntimeResilience,
    pending_forward: &PendingForward,
) -> Option<PostAuthAdmissionRejection> {
    runtime_handle()?;

    let mut effective_headers = pending_forward.headers.as_ref().clone();
    apply_auth_request_mutations(
        &mut effective_headers,
        &pending_forward.auth_header_mutations,
    );
    let header_lookup = |name: &str| {
        effective_headers
            .iter()
            .find(|header| header.name().eq_ignore_ascii_case(name.as_bytes()))
            .and_then(|header| std::str::from_utf8(header.value()).ok())
            .map(str::to_string)
    };
    let quota_context = QuotaIdentityContext::new(
        Some(pending_forward.upstream_name.as_ref()),
        pending_forward.method.as_ref(),
        pending_forward.path.as_ref(),
        pending_forward.authority.as_deref(),
        None,
        Some(pending_forward.client_addr),
        Some(&header_lookup),
    );

    block_on_admission_future(evaluate_post_auth_quota_policy(resilience, &quota_context))
        .flatten()
        .map(PostAuthAdmissionRejection::Quota)
}

pub(crate) async fn evaluate_post_auth_quota_policy(
    resilience: &RuntimeResilience,
    quota_context: &QuotaIdentityContext<'_>,
) -> Option<QuotaRejectedDecision> {
    let backend = resilience.quota_backend.as_ref()?;
    match evaluate_admission_quota(resilience.quota.as_ref(), backend.as_ref(), quota_context).await
    {
        QuotaDecision::NotApplied | QuotaDecision::Allowed(_) | QuotaDecision::FailedOpen(_) => {
            None
        }
        QuotaDecision::ShadowDenied(denial) => {
            log::debug!(
                "quota shadow deny observed: policy={} reason={}",
                denial.policy_name,
                denial.reason.slug()
            );
            None
        }
        denied => QuotaRejectedDecision::from_quota_decision(denied),
    }
}

pub(super) fn try_acquire_owned_with_micro_wait(
    semaphore: Arc<Semaphore>,
    _wait_budget: Duration,
) -> Result<(OwnedSemaphorePermit, bool), TryAcquireError> {
    // Never block the synchronous QUIC worker thread: acquire immediately or
    // shed. A blocking wait here stalls every connection on the shard.
    semaphore.try_acquire_owned().map(|permit| (permit, false))
}

fn block_on_admission_future<F>(future: F) -> Option<F::Output>
where
    F: Future,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        return match handle.runtime_flavor() {
            RuntimeFlavor::MultiThread => Some(block_in_place(|| handle.block_on(future))),
            RuntimeFlavor::CurrentThread => None,
            _engine => None,
        };
    }

    let handle = runtime_handle()?;
    Some(handle.block_on(future))
}

pub(super) fn api_key_is_authorized(
    policy: &RuntimeUpstreamPolicy,
    header_lookup: Option<&LbHeaderLookup<'_>>,
) -> bool {
    impulse_policy::api_key_is_authorized(
        policy.upstream_auth.api_key.as_ref().map(|api_key| {
            impulse_policy::ApiKeyPolicyInput::new(&api_key.header_name, &api_key.keys)
        }),
        header_lookup,
    )
}

pub(super) fn jwt_is_authorized(
    policy: &RuntimeUpstreamPolicy,
    header_lookup: Option<&LbHeaderLookup<'_>>,
) -> bool {
    let Some(jwt) = policy.upstream_auth.jwt.as_ref() else {
        return true;
    };
    let Some(raw) = header_lookup.and_then(|lookup| lookup(http::header::AUTHORIZATION.as_str()))
    else {
        return false;
    };
    let Some(token) = QUICListener::bearer_token_from_authorization_value(&raw) else {
        return false;
    };
    let claims = match validate_jwt_token(token.as_str(), jwt, SystemTime::now()) {
        Ok(validated) => validated.claims,
        Err(failure) => {
            observe_jwt_validation_failure(jwt, token.as_str(), &failure);
            log_jwt_validation_rejection(jwt, token.as_str(), &failure);
            return false;
        }
    };
    jwt_claims_satisfy_rbac(policy, &claims)
}
fn overloaded(reason: OverloadDecisionReason, retry_after_seconds: u32) -> OverloadDecision {
    match overload_decision(reason, retry_after_seconds) {
        AdmissionPolicyDecision::Overloaded(decision) => decision,
        _ => unreachable!("overload decision helper always returns overloaded"),
    }
}

fn overload_from_route_queue_rejection(
    rejection: RouteQueueRejection,
    retry_after_seconds: u32,
) -> OverloadDecision {
    match overload_decision_for_route_queue_rejection(rejection, retry_after_seconds) {
        AdmissionPolicyDecision::Overloaded(decision) => decision,
        _ => unreachable!("route queue overload helper always returns overloaded"),
    }
}
#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc, time::Duration};

    use base64::{Engine as _engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use boring::{
        hash::MessageDigest,
        pkey::{PKey, Private},
        rsa::{Padding, Rsa},
        sign::Signer,
    };
    use bytes::Bytes;
    use http_body_util::Full;
    use impulse_config::{
        config::{
            Backend, Config, DistributedQuotaPolicy, DistributedQuotaSelector,
            DistributedQuotaSelectorSource, DistributedQuotaWindow, ForwardedHeaderPolicy,
            HealthCheck, JwksStartupBehavior, JwtAlgorithm, JwtAuth, Listen, LoadBalancing,
            QuotaCounterBackend, Resilience, RouteAuth, RouteMatch, ScopedRateLimit,
            ScopedRateLimitScope, Tls, Upstream, UpstreamHostPolicy,
        },
        runtime::{RuntimeApiKeyAuth, RuntimeAuthPolicy, RuntimeConfig, RuntimeJwtAuth},
    };
    use tokio::sync::Semaphore;

    use super::*;
    use crate::{
        quic_listener::admission::{
            jwks_refresh::collect_jwks_body_bounded, jwt::parse_jose_header,
        },
        resilience::runtime::RuntimeResilience,
    };

    fn test_policy_with_api_key() -> RuntimeUpstreamPolicy {
        RuntimeUpstreamPolicy {
            upstream_auth: RuntimeAuthPolicy {
                api_key: Some(RuntimeApiKeyAuth {
                    header_name: "x-api-key".to_string(),
                    keys: vec!["secret".to_string()],
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
        }
    }

    fn test_policy_with_jwt(
        secret: &str,
        required_scopes: Vec<&str>,
        required_roles: Vec<&str>,
    ) -> RuntimeUpstreamPolicy {
        RuntimeUpstreamPolicy {
            upstream_auth: RuntimeAuthPolicy {
                api_key: None,
                jwt: Some(RuntimeJwtAuth {
                    secret: secret.to_string(),
                    issuer: Some("issuer-1".to_string()),
                    audience: Some("aud-1".to_string()),
                    clock_skew: Duration::from_secs(30),
                    ..RuntimeJwtAuth::default()
                }),
                external_auth: None,
                required_scopes: required_scopes.into_iter().map(str::to_string).collect(),
                required_roles: required_roles.into_iter().map(str::to_string).collect(),
            },
            host: Default::default(),
            forwarded_headers: Default::default(),
            response_cache: Default::default(),
            response_compression: Default::default(),
            protocol: Default::default(),
        }
    }

    fn test_hs256_jwt(secret: &str, claims: serde_json::Value, alg: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({ "alg": alg, "typ": "JWT" }))
                .expect("serialize header"),
        );
        let payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("serialize claims"));
        let signing_input = format!("{header}.{payload}");
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("mac");
        mac.update(signing_input.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{signing_input}.{signature}")
    }

    fn test_rs256_jwt(key: &PKey<Private>, kid: &str, claims: serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "alg": "RS256",
                "typ": "JWT",
                "kid": kid,
            }))
            .expect("serialize header"),
        );
        let payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("serialize claims"));
        let signing_input = format!("{header}.{payload}");
        let mut signer = Signer::new(MessageDigest::sha256(), key).expect("rsa signer");
        signer.set_rsa_padding(Padding::PKCS1).expect("rsa padding");
        signer
            .update(signing_input.as_bytes())
            .expect("rsa signing input");
        let signature = URL_SAFE_NO_PAD.encode(signer.sign_to_vec().expect("rsa signature"));
        format!("{signing_input}.{signature}")
    }

    fn test_rsa_public_jwk(key: &PKey<Private>, kid: &str) -> Value {
        let rsa = key.rsa().expect("rsa key");
        serde_json::json!({
            "kty": "RSA",
            "kid": kid,
            "alg": "RS256",
            "use": "sig",
            "key_ops": ["verify"],
            "n": URL_SAFE_NO_PAD.encode(rsa.n().to_vec()),
            "e": URL_SAFE_NO_PAD.encode(rsa.e().to_vec()),
        })
    }

    fn test_runtime_resilience(
        configure: impl FnOnce(&mut Resilience),
        global_limit: usize,
    ) -> RuntimeResilience {
        let mut config = Resilience::default();
        configure(&mut config);
        RuntimeResilience::from_config(&config, global_limit)
    }

    fn test_upstream_pool() -> Arc<RwLock<UpstreamPool>> {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "api".to_string(),
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
                    host: None,
                    path_prefix: Some("/".to_string()),
                    method: None,
                },
                backends: vec![Backend {
                    id: "a".to_string(),
                    address: "http://127.0.0.1:8080".to_string(),
                    weight: 1,
                    health_check: Some(HealthCheck {
                        path: "/health".to_string(),
                        interval: 1,
                        timeout_ms: 1000,
                        failure_threshold: 1,
                        success_threshold: 1,
                        cooldown_ms: 0,
                    }),
                }],
            },
        );

        let runtime = RuntimeConfig::from_config(&Config {
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
            resilience: Default::default(),
            security: Default::default(),
        })
        .expect("runtime config");

        Arc::new(RwLock::new(
            crate::quic_listener::upstream_pool_from_runtime(
                runtime.upstreams.get("api").expect("upstream"),
            )
            .expect("pool"),
        ))
    }

    fn test_upstream_inflight() -> HashMap<String, Arc<Semaphore>> {
        HashMap::from([(String::from("api"), Arc::new(Semaphore::new(1)))])
    }

    fn test_runtime_config_with_jwks_auth(jwt: JwtAuth) -> RuntimeConfig {
        RuntimeConfig::from_config(&Config {
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
            upstream: HashMap::from([(
                "api".to_string(),
                Upstream {
                    load_balancing: LoadBalancing {
                        lb_type: "round-robin".to_string(),
                        key: None,
                    },
                    auth: RouteAuth {
                        api_key: None,
                        jwt: Some(jwt),
                        external_auth: None,
                        required_scopes: Vec::new(),
                        required_roles: Vec::new(),
                    },
                    host_policy: UpstreamHostPolicy::default(),
                    forwarded_headers: ForwardedHeaderPolicy::default(),
                    compression: Default::default(),
                    cache: Default::default(),
                    tls: None,
                    route: RouteMatch {
                        host: None,
                        path_prefix: Some("/".to_string()),
                        method: None,
                    },
                    backends: vec![Backend {
                        id: "a".to_string(),
                        address: "http://127.0.0.1:8080".to_string(),
                        weight: 1,
                        health_check: None,
                    }],
                },
            )]),
            load_balancing: None,
            upstream_tls: Default::default(),
            secrets: Default::default(),
            log: Default::default(),
            performance: Default::default(),
            observability: Default::default(),
            resilience: Default::default(),
            security: Default::default(),
        })
        .expect("runtime config")
    }

    fn test_jwks_source(
        jwks_url: &str,
        allowed_algorithms: Vec<JwtAlgorithm>,
    ) -> JwtJwksSourceConfig {
        JwtJwksSourceConfig {
            source_identity: jwks_source_identity_for_test(jwks_url),
            jwks_url: jwks_url.to_string(),
            allowed_algorithms,
            refresh_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(1),
            cache_ttl: Duration::from_secs(60),
            stale_if_error: Duration::from_secs(60),
            startup_behavior: JwksStartupBehavior::AllowDegraded,
        }
    }

    mod admission_rejection_contracts {
        use super::*;

        #[test]
        fn overload_reasons_map_to_stable_metrics_labels_and_response_bodies() {
            let cases = [
                (
                    OverloadDecisionReason::Brownout,
                    "brownout",
                    b"brownout active, non-core route shed\n".as_slice(),
                ),
                (
                    OverloadDecisionReason::AdaptiveAdmission,
                    "adaptive_admission",
                    b"adaptive admission overload\n".as_slice(),
                ),
                (
                    OverloadDecisionReason::RouteCap,
                    "route_cap",
                    b"route queue cap exceeded\n".as_slice(),
                ),
                (
                    OverloadDecisionReason::RouteGlobalCap,
                    "route_global_cap",
                    b"global queue cap exceeded\n".as_slice(),
                ),
                (
                    OverloadDecisionReason::GlobalInflight,
                    "global_inflight",
                    b"overloaded, retry later\n".as_slice(),
                ),
                (
                    OverloadDecisionReason::UpstreamInflight,
                    "upstream_inflight",
                    b"upstream overloaded, retry later\n".as_slice(),
                ),
            ];

            for (reason, label, body) in cases {
                assert_eq!(overload_metrics_reason(reason).reason_label(), label);
                assert_eq!(reason.response_body(), body);
            }
        }

        #[test]
        fn unauthorized_and_overload_rejections_have_distinct_outward_mapping() {
            let policy = test_policy_with_api_key();
            let unauthorized =
                admission_rejection_response(&evaluate_forwarding_pre_admission_policy(
                    &policy,
                    None,
                    &BrownoutController::new(false, 100, 50, Vec::new()),
                    0,
                    "api",
                    "GET",
                    "/resource",
                    Some("api.example.com"),
                    "198.51.100.10:443".parse().expect("client addr"),
                    7,
                    &ScopedRateLimiters::new(&[]),
                ))
                .expect("unauthorized response");
            assert_eq!(unauthorized.status, StatusCode::UNAUTHORIZED);
            assert_eq!(unauthorized.body, b"unauthorized\n");
            assert_eq!(unauthorized.www_authenticate, Some("ApiKey"));
            assert_eq!(unauthorized.retry_after_seconds, None);

            let overload = admission_rejection_response(&evaluate_brownout_policy(
                &BrownoutController::new(true, 50, 25, vec![String::from("core")]),
                90,
                "api",
                7,
            ))
            .expect("overload response");
            assert_eq!(overload.status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(overload.body, b"brownout active, non-core route shed\n");
            assert_eq!(overload.www_authenticate, None);
            assert_eq!(overload.retry_after_seconds, Some(7));
        }
    }

    mod local_auth_policy_contracts {
        use super::*;

        #[test]
        fn local_auth_policy_returns_api_key_challenge_when_key_is_missing() {
            let decision = evaluate_local_auth_policy(&test_policy_with_api_key(), None);

            assert_eq!(
                decision,
                AdmissionPolicyDecision::Unauthorized(UnauthorizedDecision {
                    challenge: AuthChallengeKind::ApiKey,
                    status: StatusCode::UNAUTHORIZED,
                    body: b"unauthorized\n",
                })
            );
        }

        #[test]
        fn local_auth_policy_admits_when_api_key_matches() {
            let headers = HashMap::from([("x-api-key".to_string(), "secret".to_string())]);
            let lookup = |name: &str| headers.get(&name.to_ascii_lowercase()).cloned();

            let decision = evaluate_local_auth_policy(&test_policy_with_api_key(), Some(&lookup));

            assert_eq!(decision, AdmissionPolicyDecision::AdmitReady);
        }

        #[test]
        fn local_auth_policy_returns_bearer_challenge_for_missing_or_invalid_jwt() {
            let policy = test_policy_with_jwt("jwt-secret", vec!["payments:read"], vec!["admin"]);

            let missing = evaluate_local_auth_policy(&policy, None);
            assert_eq!(
                missing,
                AdmissionPolicyDecision::Unauthorized(UnauthorizedDecision {
                    challenge: AuthChallengeKind::Bearer,
                    status: StatusCode::UNAUTHORIZED,
                    body: b"unauthorized\n",
                })
            );

            let invalid_headers = HashMap::from([(
                "authorization".to_string(),
                "Bearer invalid.jwt.token".to_string(),
            )]);
            let invalid_lookup =
                |name: &str| invalid_headers.get(&name.to_ascii_lowercase()).cloned();

            let invalid = evaluate_local_auth_policy(&policy, Some(&invalid_lookup));
            assert_eq!(
                invalid,
                AdmissionPolicyDecision::Unauthorized(UnauthorizedDecision {
                    challenge: AuthChallengeKind::Bearer,
                    status: StatusCode::UNAUTHORIZED,
                    body: b"unauthorized\n",
                })
            );
        }

        #[test]
        fn local_auth_policy_admits_valid_jwt_when_claims_satisfy_rbac() {
            let token = test_hs256_jwt(
                "jwt-secret",
                serde_json::json!({
                    "iss": "issuer-1",
                    "aud": "aud-1",
                    "exp": 4_000_000_000u64,
                    "scope": "payments:read transfers:write",
                    "roles": ["admin", "ops"],
                }),
                "HS256",
            );
            let headers = HashMap::from([("authorization".to_string(), format!("Bearer {token}"))]);
            let lookup = |name: &str| headers.get(&name.to_ascii_lowercase()).cloned();

            let decision = evaluate_local_auth_policy(
                &test_policy_with_jwt("jwt-secret", vec!["payments:read"], vec!["admin"]),
                Some(&lookup),
            );

            assert_eq!(decision, AdmissionPolicyDecision::AdmitReady);
        }
    }

    mod scoped_rate_limit_policy_contracts {
        use super::*;

        fn test_scoped_rate_limits() -> ScopedRateLimiters {
            ScopedRateLimiters::new(&[ScopedRateLimit {
                name: "tenant-cap".to_string(),
                scope: ScopedRateLimitScope::Tenant,
                requests_per_sec: 1,
                burst: 1,
                key: Some("header:x-tenant-id".to_string()),
                route_allowlist: vec!["payments".to_string()],
                idle_ttl_secs: 60,
            }])
        }

        fn test_client_addr() -> SocketAddr {
            "198.51.100.10:443".parse().expect("client addr")
        }

        #[test]
        fn scoped_rate_limit_policy_admits_when_rule_does_not_reject() {
            let rate_limits = test_scoped_rate_limits();
            let headers = HashMap::from([("x-tenant-id".to_string(), "tenant-a".to_string())]);
            let lookup = |name: &str| headers.get(&name.to_ascii_lowercase()).cloned();

            let allowed = evaluate_scoped_rate_limit_policy(
                &rate_limits,
                "payments",
                "GET",
                "/resource",
                Some("api.example.com"),
                test_client_addr(),
                Some(&lookup),
            );
            let no_key = evaluate_scoped_rate_limit_policy(
                &rate_limits,
                "payments",
                "GET",
                "/resource",
                Some("api.example.com"),
                test_client_addr(),
                None,
            );
            let wrong_route = evaluate_scoped_rate_limit_policy(
                &rate_limits,
                "admin",
                "GET",
                "/resource",
                Some("api.example.com"),
                test_client_addr(),
                Some(&lookup),
            );

            assert_eq!(allowed, AdmissionPolicyDecision::AdmitReady);
            assert_eq!(no_key, AdmissionPolicyDecision::AdmitReady);
            assert_eq!(wrong_route, AdmissionPolicyDecision::AdmitReady);
        }

        #[test]
        fn scoped_rate_limit_policy_returns_typed_rejection_for_exhausted_bucket() {
            let rate_limits = test_scoped_rate_limits();
            let headers = HashMap::from([("x-tenant-id".to_string(), "tenant-a".to_string())]);
            let lookup = |name: &str| headers.get(&name.to_ascii_lowercase()).cloned();

            let first = evaluate_scoped_rate_limit_policy(
                &rate_limits,
                "payments",
                "GET",
                "/resource",
                Some("api.example.com"),
                test_client_addr(),
                Some(&lookup),
            );
            let second = evaluate_scoped_rate_limit_policy(
                &rate_limits,
                "payments",
                "GET",
                "/resource",
                Some("api.example.com"),
                test_client_addr(),
                Some(&lookup),
            );

            assert_eq!(first, AdmissionPolicyDecision::AdmitReady);
            assert_eq!(
                second,
                AdmissionPolicyDecision::RateLimited(RateLimitedDecision {
                    rule_name: "tenant-cap".to_string(),
                    route: "payments".to_string(),
                    status: StatusCode::TOO_MANY_REQUESTS,
                    body: b"request rate limited\n",
                    retry_after_seconds: 1,
                })
            );
        }

        #[test]
        fn scoped_rate_limit_policy_preserves_legacy_default_key_fallback() {
            let rate_limits = test_scoped_rate_limits();

            let first = evaluate_scoped_rate_limit_policy(
                &rate_limits,
                "payments",
                "GET",
                "/resource",
                Some("api.example.com"),
                test_client_addr(),
                None,
            );
            let second = evaluate_scoped_rate_limit_policy(
                &rate_limits,
                "payments",
                "GET",
                "/resource",
                Some("api.example.com"),
                test_client_addr(),
                None,
            );

            assert_eq!(first, AdmissionPolicyDecision::AdmitReady);
            assert_eq!(
                second,
                AdmissionPolicyDecision::RateLimited(RateLimitedDecision {
                    rule_name: "tenant-cap".to_string(),
                    route: "payments".to_string(),
                    status: StatusCode::TOO_MANY_REQUESTS,
                    body: b"request rate limited\n",
                    retry_after_seconds: 1,
                })
            );
        }
    }

    mod brownout_and_overload_policy_contracts {
        use super::*;

        #[test]
        fn brownout_policy_sheds_non_core_routes_and_preserves_core_routes() {
            let brownout = BrownoutController::new(true, 50, 25, vec![String::from("core")]);

            let core = evaluate_brownout_policy(&brownout, 90, "core", 9);
            let non_core = evaluate_brownout_policy(&brownout, 90, "payments", 9);

            assert_eq!(core, AdmissionPolicyDecision::AdmitReady);
            assert_eq!(
                non_core,
                AdmissionPolicyDecision::Overloaded(OverloadDecision {
                    reason: OverloadDecisionReason::Brownout,
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    body: b"brownout active, non-core route shed\n",
                    retry_after_seconds: 9,
                })
            );
        }

        #[test]
        fn overload_mapping_preserves_route_queue_reasons_and_shared_response_shape() {
            let route_cap =
                overload_decision_for_route_queue_rejection(RouteQueueRejection::RouteCap, 0);
            let global_cap =
                overload_decision_for_route_queue_rejection(RouteQueueRejection::GlobalCap, 3);

            assert_eq!(
                route_cap,
                AdmissionPolicyDecision::Overloaded(OverloadDecision {
                    reason: OverloadDecisionReason::RouteCap,
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    body: b"route queue cap exceeded\n",
                    retry_after_seconds: 1,
                })
            );
            assert_eq!(
                global_cap,
                AdmissionPolicyDecision::Overloaded(OverloadDecision {
                    reason: OverloadDecisionReason::RouteGlobalCap,
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    body: b"global queue cap exceeded\n",
                    retry_after_seconds: 3,
                })
            );

            let mapped = admission_rejection_response(&global_cap).expect("rejection mapping");
            assert_eq!(mapped.status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(mapped.body, b"global queue cap exceeded\n");
            assert_eq!(mapped.www_authenticate, None);
            assert_eq!(mapped.retry_after_seconds, Some(3));
        }
    }

    mod post_auth_admission_execution {
        use impulse_config::config::QuotaBackendFailurePolicy;

        use super::*;

        fn test_pending_forward_for_api(headers: Vec<quiche::h3::Header>) -> PendingForward {
            PendingForward::sample_for_test(headers)
        }

        fn execute_post_auth_for_api(
            resilience: &RuntimeResilience,
            pending_forward: &PendingForward,
            upstream_pool: Option<&Arc<RwLock<UpstreamPool>>>,
            backend_index: Option<usize>,
            upstream_inflight: &HashMap<String, Arc<Semaphore>>,
            global_inflight: Arc<Semaphore>,
        ) -> PostAuthAdmissionExecution {
            execute_forwarding_post_auth_admission(
                resilience,
                pending_forward,
                upstream_pool,
                backend_index,
                upstream_inflight,
                global_inflight,
                Duration::ZERO,
            )
        }

        #[test]
        fn post_auth_admission_rejects_adaptive_admission_overload() {
            let resilience = test_runtime_resilience(
                |config| {
                    config.adaptive_admission.enabled = true;
                    config.adaptive_admission.min_limit = 1;
                    config.adaptive_admission.max_limit = Some(1);
                },
                8,
            );
            let _held = resilience
                .adaptive_admission
                .clone()
                .try_acquire()
                .expect("held permit");
            let pending_forward = test_pending_forward_for_api(vec![]);

            let result = execute_post_auth_for_api(
                &resilience,
                &pending_forward,
                Some(&test_upstream_pool()),
                Some(0),
                &test_upstream_inflight(),
                Arc::new(Semaphore::new(1)),
            );
            match &result {
                PostAuthAdmissionExecution::Ready(_) => eprintln!("fail_open result: ready"),
                PostAuthAdmissionExecution::Rejected(PostAuthAdmissionRejection::Quota(
                    decision,
                )) => eprintln!(
                    "fail_open result: quota policy={} reason={:?} status={}",
                    decision.policy_name, decision.reason, decision.status
                ),
                PostAuthAdmissionExecution::Rejected(PostAuthAdmissionRejection::Overloaded(
                    decision,
                )) => eprintln!(
                    "fail_open result: overload reason={:?} status={} body={}",
                    decision.reason,
                    decision.status,
                    String::from_utf8_lossy(decision.body)
                ),
                PostAuthAdmissionExecution::Rejected(PostAuthAdmissionRejection::Failed(
                    failure,
                )) => eprintln!(
                    "fail_open result: failed status={} body={}",
                    failure.status,
                    String::from_utf8_lossy(failure.body)
                ),
            }

            assert!(matches!(
                result,
                PostAuthAdmissionExecution::Rejected(PostAuthAdmissionRejection::Overloaded(
                    OverloadDecision {
                        reason: OverloadDecisionReason::AdaptiveAdmission,
                        ..
                    }
                ))
            ));
        }

        #[test]
        fn post_auth_admission_bypasses_adaptive_limit_when_disabled() {
            let resilience = test_runtime_resilience(
                |config| {
                    config.adaptive_admission.enabled = false;
                    config.adaptive_admission.min_limit = 1;
                    config.adaptive_admission.max_limit = Some(1);
                },
                8,
            );
            let _held = resilience
                .adaptive_admission
                .clone()
                .try_acquire()
                .expect("held permit");
            let pending_forward = test_pending_forward_for_api(vec![]);

            let result = execute_post_auth_for_api(
                &resilience,
                &pending_forward,
                Some(&test_upstream_pool()),
                Some(0),
                &test_upstream_inflight(),
                Arc::new(Semaphore::new(1)),
            );

            assert!(matches!(result, PostAuthAdmissionExecution::Ready(_)));
        }

        #[test]
        fn post_auth_admission_rejects_route_cap_and_global_cap_with_distinct_reasons() {
            let route_cap = test_runtime_resilience(
                |config| {
                    config.route_queue.default_cap = 2;
                    config.route_queue.global_cap = 4;
                    config.route_queue.caps.insert(String::from("api"), 1);
                },
                8,
            );
            let _route_held = route_cap
                .route_queue
                .clone()
                .try_acquire("api")
                .expect("route permit");
            let pending_forward = test_pending_forward_for_api(vec![]);
            let route_result = execute_post_auth_for_api(
                &route_cap,
                &pending_forward,
                Some(&test_upstream_pool()),
                Some(0),
                &test_upstream_inflight(),
                Arc::new(Semaphore::new(1)),
            );
            assert!(matches!(
                route_result,
                PostAuthAdmissionExecution::Rejected(PostAuthAdmissionRejection::Overloaded(
                    OverloadDecision {
                        reason: OverloadDecisionReason::RouteCap,
                        ..
                    }
                ))
            ));

            let global_cap = test_runtime_resilience(
                |config| {
                    config.route_queue.default_cap = 4;
                    config.route_queue.global_cap = 1;
                },
                8,
            );
            let _global_route_held = global_cap
                .route_queue
                .clone()
                .try_acquire("other")
                .expect("global route permit");
            let global_result = execute_post_auth_for_api(
                &global_cap,
                &pending_forward,
                Some(&test_upstream_pool()),
                Some(0),
                &test_upstream_inflight(),
                Arc::new(Semaphore::new(1)),
            );
            assert!(matches!(
                global_result,
                PostAuthAdmissionExecution::Rejected(PostAuthAdmissionRejection::Overloaded(
                    OverloadDecision {
                        reason: OverloadDecisionReason::RouteGlobalCap,
                        ..
                    }
                ))
            ));
        }

        #[test]
        fn post_auth_admission_rejects_global_and_upstream_inflight_with_distinct_reasons() {
            let resilience = test_runtime_resilience(|_| {}, 8);
            let global_inflight = Arc::new(Semaphore::new(1));
            let _global_held = global_inflight
                .clone()
                .try_acquire_owned()
                .expect("global permit");
            let pending_forward = test_pending_forward_for_api(vec![]);
            let global_result = execute_post_auth_for_api(
                &resilience,
                &pending_forward,
                Some(&test_upstream_pool()),
                Some(0),
                &test_upstream_inflight(),
                Arc::clone(&global_inflight),
            );
            assert!(matches!(
                global_result,
                PostAuthAdmissionExecution::Rejected(PostAuthAdmissionRejection::Overloaded(
                    OverloadDecision {
                        reason: OverloadDecisionReason::GlobalInflight,
                        ..
                    }
                ))
            ));

            let resilience = test_runtime_resilience(|_| {}, 8);
            let upstream_inflight = test_upstream_inflight();
            let _upstream_held = upstream_inflight
                .get("api")
                .expect("api semaphore")
                .clone()
                .try_acquire_owned()
                .expect("upstream permit");
            let upstream_result = execute_post_auth_for_api(
                &resilience,
                &pending_forward,
                Some(&test_upstream_pool()),
                Some(0),
                &upstream_inflight,
                Arc::new(Semaphore::new(1)),
            );
            assert!(matches!(
                upstream_result,
                PostAuthAdmissionExecution::Rejected(PostAuthAdmissionRejection::Overloaded(
                    OverloadDecision {
                        reason: OverloadDecisionReason::UpstreamInflight,
                        ..
                    }
                ))
            ));
        }

        #[test]
        fn missing_upstream_limiter_preserves_overload_reason_in_failure_mapping() {
            let resilience = test_runtime_resilience(|_| {}, 8);
            let pending_forward = test_pending_forward_for_api(vec![]);

            let result = execute_post_auth_for_api(
                &resilience,
                &pending_forward,
                Some(&test_upstream_pool()),
                Some(0),
                &HashMap::new(),
                Arc::new(Semaphore::new(1)),
            );

            assert!(matches!(
                result,
                PostAuthAdmissionExecution::Rejected(PostAuthAdmissionRejection::Failed(
                    PostAuthAdmissionFailure {
                        status: StatusCode::SERVICE_UNAVAILABLE,
                        overload_reason: Some(OverloadDecisionReason::UpstreamInflight),
                        route_outcome: Some(RouteOutcome::OverloadShed),
                        observe_adaptive_overload: true,
                        ..
                    }
                ))
            ));
        }

        #[test]
        fn post_auth_admission_ready_result_reports_no_wait_when_permits_are_immediate() {
            let resilience = test_runtime_resilience(|_| {}, 8);
            let pool = test_upstream_pool();
            let pending_forward = test_pending_forward_for_api(vec![]);

            let (permit, waited) =
                try_acquire_owned_with_micro_wait(Arc::new(Semaphore::new(1)), Duration::ZERO)
                    .expect("permit");
            assert!(!waited);
            drop(permit);

            let result = execute_post_auth_for_api(
                &resilience,
                &pending_forward,
                Some(&pool),
                Some(0),
                &test_upstream_inflight(),
                Arc::new(Semaphore::new(1)),
            );

            match result {
                PostAuthAdmissionExecution::Ready(ready) => {
                    assert_eq!(ready.backend_index, 0);
                    assert!(!ready.waited_for_global_permit);
                    assert!(!ready.waited_for_upstream_permit);
                }
                PostAuthAdmissionExecution::Rejected(_) => {
                    panic!("expected successful admission without waits")
                }
            }
        }

        #[test]
        fn post_auth_admission_enforces_quota_before_overload_with_composite_identity() {
            let resilience = test_runtime_resilience(
                |config| {
                    config.adaptive_admission.enabled = true;
                    config.adaptive_admission.min_limit = 1;
                    config.adaptive_admission.max_limit = Some(1);
                    config.quota.enabled = true;
                    config.quota.backend = QuotaCounterBackend::InMemory {
                        key_prefix: "impulse:test:quota".to_string(),
                    };
                    config.quota.policies = vec![DistributedQuotaPolicy {
                        name: "tenant-token-client-burst".to_string(),
                        route_allowlist: vec!["api".to_string()],
                        selector: DistributedQuotaSelector {
                            route: true,
                            tenant: Some(DistributedQuotaSelectorSource {
                                key: "header:x-tenant-id".to_string(),
                            }),
                            token: Some(DistributedQuotaSelectorSource {
                                key: "bearer_token".to_string(),
                            }),
                            client: Some(DistributedQuotaSelectorSource {
                                key: "client_ip".to_string(),
                            }),
                        },
                        burst: Some(DistributedQuotaWindow {
                            requests: 1,
                            window_secs: 1,
                        }),
                        sustained: None,
                    }];
                },
                8,
            );
            let pending_forward = test_pending_forward_for_api(vec![
                quiche::h3::Header::new(b"authorization", b"Bearer token-123"),
                quiche::h3::Header::new(b"x-tenant-id", b"tenant-a"),
            ]);

            let first = execute_post_auth_for_api(
                &resilience,
                &pending_forward,
                Some(&test_upstream_pool()),
                Some(0),
                &HashMap::from([(String::from("api"), Arc::new(Semaphore::new(2)))]),
                Arc::new(Semaphore::new(2)),
            );
            assert!(matches!(first, PostAuthAdmissionExecution::Ready(_)));
            drop(first);

            let _adaptive_held = resilience
                .adaptive_admission
                .clone()
                .try_acquire()
                .expect("held adaptive permit");

            let second = execute_post_auth_for_api(
                &resilience,
                &pending_forward,
                Some(&test_upstream_pool()),
                Some(0),
                &HashMap::from([(String::from("api"), Arc::new(Semaphore::new(2)))]),
                Arc::new(Semaphore::new(2)),
            );

            assert!(matches!(
                second,
                PostAuthAdmissionExecution::Rejected(PostAuthAdmissionRejection::Quota(
                    QuotaRejectedDecision {
                        policy_name,
                        reason: QuotaDenyReason::BurstQuotaExhausted,
                        status: StatusCode::TOO_MANY_REQUESTS,
                        body: b"burst quota exhausted\n",
                        retry_after_seconds: Some(1),
                    }
                )) if policy_name == "tenant-token-client-burst"
            ));
        }

        #[test]
        fn post_auth_admission_fail_open_quota_backend_errors_preserve_overload_classification() {
            let resilience = test_runtime_resilience(
                |config| {
                    config.adaptive_admission.enabled = true;
                    config.adaptive_admission.min_limit = 1;
                    config.adaptive_admission.max_limit = Some(1);
                    config.quota.enabled = true;
                    config.quota.backend_failure_policy = QuotaBackendFailurePolicy::FailOpen;
                    config.quota.backend = QuotaCounterBackend::Redis {
                        url: "://bad-redis-url".to_string(),
                        key_prefix: "impulse:test:quota".to_string(),
                        connect_timeout_ms: 250,
                        command_timeout_ms: 100,
                        max_inflight: 8,
                    };
                    config.quota.policies = vec![DistributedQuotaPolicy {
                        name: "tenant-contract".to_string(),
                        route_allowlist: vec!["api".to_string()],
                        selector: DistributedQuotaSelector {
                            route: true,
                            tenant: Some(DistributedQuotaSelectorSource {
                                key: "header:x-tenant-id".to_string(),
                            }),
                            token: None,
                            client: None,
                        },
                        burst: Some(DistributedQuotaWindow {
                            requests: 50,
                            window_secs: 1,
                        }),
                        sustained: None,
                    }];
                },
                8,
            );
            let _held = resilience
                .adaptive_admission
                .clone()
                .try_acquire()
                .expect("held adaptive permit");
            let pending_forward = test_pending_forward_for_api(vec![quiche::h3::Header::new(
                b"x-tenant-id",
                b"tenant-a",
            )]);

            let result = execute_post_auth_for_api(
                &resilience,
                &pending_forward,
                Some(&test_upstream_pool()),
                Some(0),
                &test_upstream_inflight(),
                Arc::new(Semaphore::new(1)),
            );

            assert!(matches!(
                result,
                PostAuthAdmissionExecution::Rejected(PostAuthAdmissionRejection::Overloaded(
                    OverloadDecision {
                        reason: OverloadDecisionReason::AdaptiveAdmission,
                        status: StatusCode::SERVICE_UNAVAILABLE,
                        body: b"adaptive admission overload\n",
                        ..
                    }
                ))
            ));
        }

        #[test]
        fn post_auth_admission_fail_closed_quota_backend_errors_reject_before_overload() {
            let resilience = test_runtime_resilience(
                |config| {
                    config.adaptive_admission.enabled = true;
                    config.adaptive_admission.min_limit = 1;
                    config.adaptive_admission.max_limit = Some(1);
                    config.quota.enabled = true;
                    config.quota.backend_failure_policy = QuotaBackendFailurePolicy::FailClosed;
                    config.quota.backend = QuotaCounterBackend::Redis {
                        url: "://bad-redis-url".to_string(),
                        key_prefix: "impulse:test:quota".to_string(),
                        connect_timeout_ms: 250,
                        command_timeout_ms: 100,
                        max_inflight: 8,
                    };
                    config.quota.policies = vec![DistributedQuotaPolicy {
                        name: "tenant-contract".to_string(),
                        route_allowlist: vec!["api".to_string()],
                        selector: DistributedQuotaSelector {
                            route: true,
                            tenant: Some(DistributedQuotaSelectorSource {
                                key: "header:x-tenant-id".to_string(),
                            }),
                            token: None,
                            client: None,
                        },
                        burst: Some(DistributedQuotaWindow {
                            requests: 50,
                            window_secs: 1,
                        }),
                        sustained: None,
                    }];
                },
                8,
            );
            let _held = resilience
                .adaptive_admission
                .clone()
                .try_acquire()
                .expect("held adaptive permit");
            let pending_forward = test_pending_forward_for_api(vec![quiche::h3::Header::new(
                b"x-tenant-id",
                b"tenant-a",
            )]);

            let result = execute_post_auth_for_api(
                &resilience,
                &pending_forward,
                Some(&test_upstream_pool()),
                Some(0),
                &test_upstream_inflight(),
                Arc::new(Semaphore::new(1)),
            );

            assert!(matches!(
                result,
                PostAuthAdmissionExecution::Rejected(PostAuthAdmissionRejection::Quota(
                    QuotaRejectedDecision {
                        policy_name,
                        reason: QuotaDenyReason::BackendError,
                        status: StatusCode::SERVICE_UNAVAILABLE,
                        body: b"quota backend error\n",
                        retry_after_seconds: None,
                    }
                )) if policy_name == "tenant-contract"
            ));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn jwks_body_collection_rejects_oversized_documents() {
        let oversized_body = Full::new(Bytes::from(vec![b'x'; MAX_JWKS_BODY_BYTES + 1]));

        let failure = collect_jwks_body_bounded(oversized_body)
            .await
            .expect_err("oversized jwks body must be rejected");

        assert_eq!(failure.reason, JwtJwksFetchFailureReason::MalformedDocument);
        assert!(failure.to_string().contains(&format!(
            "jwks document exceeded {} bytes",
            MAX_JWKS_BODY_BYTES
        )));
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial(jwks_cache)]
    async fn startup_jwks_refresh_populates_active_key_set() {
        let jwks_url = "https://issuer.example.com/startup-jwks.json";
        clear_jwks_cache_for_test(jwks_url);
        let source_identity = jwks_source_identity_for_test(jwks_url);
        let rsa = Rsa::generate(2048).expect("rsa key");
        let key = PKey::from_rsa(rsa).expect("rsa pkey");
        let source = JwtJwksSourceConfig {
            source_identity: source_identity.clone(),
            jwks_url: jwks_url.to_string(),
            allowed_algorithms: vec![JwtAlgorithm::Rs256],
            refresh_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(1),
            cache_ttl: Duration::from_secs(60),
            stale_if_error: Duration::from_secs(60),
            startup_behavior: JwksStartupBehavior::RequireReady,
        };
        JwtJwksSharedCache::shared().register_source(source.clone());
        script_jwks_fetches_for_test(
            jwks_url,
            vec![Ok(serde_json::json!({
                "keys": [test_rsa_public_jwk(&key, "startup-key")]
            }))],
        );

        refresh_jwks_source_once(source.clone(), "startup")
            .await
            .expect("startup refresh");

        let snapshot = JwtJwksSharedCache::shared()
            .snapshot(&source.source_identity, Instant::now())
            .expect("cache snapshot");
        assert_eq!(snapshot.state, JwtJwksCacheState::Fresh);
        assert_eq!(snapshot.active_keys.len(), 1);
    }

    #[test]
    #[serial(jwks_cache)]
    fn require_ready_startup_preflight_fails_when_jwks_is_unreachable() {
        let jwks_url = "https://issuer.example.com/require-ready-failure.json";
        clear_jwks_cache_for_test(jwks_url);
        script_jwks_fetches_for_test(
            jwks_url,
            vec![Err(JwtJwksFetchFailure::request_failed(
                "scripted startup outage".to_string(),
            ))],
        );
        let runtime_config = test_runtime_config_with_jwks_auth(JwtAuth {
            secret: String::new(),
            allowed_algorithms: vec![JwtAlgorithm::Rs256],
            jwks_url: Some(jwks_url.to_string()),
            jwks_request_timeout_ms: 1000,
            jwks_refresh_interval_secs: 60,
            jwks_cache_ttl_secs: 60,
            jwks_stale_if_error_secs: 60,
            jwks_startup_behavior: JwksStartupBehavior::RequireReady,
            ..JwtAuth::default()
        });

        let error =
            QUICListener::initialize_jwks_startup(&runtime_config).expect_err("startup must fail");

        assert!(error.to_string().contains("startup_behavior=require_ready"));
        clear_jwks_cache_for_test(jwks_url);
    }

    #[test]
    #[serial(jwks_cache)]
    fn startup_preflight_without_jwks_does_not_evict_unrelated_cached_sources() {
        let jwks_url = "https://issuer.example.com/preflight-keeps-live-cache.json";
        clear_jwks_cache_for_test(jwks_url);
        let source_identity = jwks_source_identity_for_test(jwks_url);
        let source = JwtJwksSourceConfig {
            source_identity: source_identity.clone(),
            jwks_url: jwks_url.to_string(),
            allowed_algorithms: vec![JwtAlgorithm::Rs256],
            refresh_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(1),
            cache_ttl: Duration::from_secs(60),
            stale_if_error: Duration::from_secs(60),
            startup_behavior: JwksStartupBehavior::AllowDegraded,
        };
        let cache_now = Instant::now();
        JwtJwksSharedCache::shared().upsert(
            &source_identity,
            JwtJwksCacheEntry {
                source: source.clone(),
                state: JwtJwksCacheState::Fresh,
                active_keys: vec![JwtJwksActiveKey {
                    key: RuntimeJwtVerificationKey::Pem {
                        kid: Some("persisted-kid".to_string()),
                        alg: Some(JwtAlgorithm::Rs256),
                        public_key_pem: "persisted-pem".to_string(),
                    },
                    retained_until: None,
                }],
                refresh_in_flight: false,
                last_refresh_started_at: Some(cache_now - Duration::from_secs(5)),
                last_refresh_started_wall: Some(SystemTime::now() - Duration::from_secs(5)),
                last_refresh_completed_at: Some(cache_now - Duration::from_secs(5)),
                last_refresh_completed_wall: Some(SystemTime::now() - Duration::from_secs(5)),
                last_success_at: Some(cache_now - Duration::from_secs(5)),
                last_success_wall: Some(SystemTime::now() - Duration::from_secs(5)),
                last_failure_at: None,
                last_failure_wall: None,
                last_error: None,
                last_failure_reason: None,
                next_on_demand_refresh_at: None,
            },
        );

        let runtime_config = RuntimeConfig::from_config(&Config {
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
            upstream: HashMap::from([(
                "api".to_string(),
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
                        host: None,
                        path_prefix: Some("/".to_string()),
                        method: None,
                    },
                    backends: vec![Backend {
                        id: "a".to_string(),
                        address: "http://127.0.0.1:8080".to_string(),
                        weight: 1,
                        health_check: None,
                    }],
                },
            )]),
            load_balancing: None,
            upstream_tls: Default::default(),
            secrets: Default::default(),
            log: Default::default(),
            performance: Default::default(),
            observability: Default::default(),
            resilience: Default::default(),
            security: Default::default(),
        })
        .expect("runtime config without jwks");

        QUICListener::initialize_jwks_startup(&runtime_config).expect("preflight without jwks");

        let snapshot = JwtJwksSharedCache::shared()
            .snapshot(&source_identity, Instant::now())
            .expect("unrelated cached jwks source must remain available");
        assert_eq!(snapshot.state, JwtJwksCacheState::Fresh);
        assert_eq!(snapshot.active_keys.len(), 1);

        clear_jwks_cache_for_test(jwks_url);
    }

    #[test]
    fn runtime_jwks_sources_merge_same_url_policies_deterministically() {
        let jwks_url = "https://issuer.example.com/shared-jwks.json?token=secret";
        let mut config = test_runtime_config_with_jwks_auth(JwtAuth {
            secret: String::new(),
            allowed_algorithms: vec![JwtAlgorithm::Rs256],
            jwks_url: Some(jwks_url.to_string()),
            jwks_request_timeout_ms: 1000,
            jwks_refresh_interval_secs: 60,
            jwks_cache_ttl_secs: 300,
            jwks_stale_if_error_secs: 60,
            jwks_startup_behavior: JwksStartupBehavior::AllowDegraded,
            ..JwtAuth::default()
        });
        config
            .upstreams
            .insert("api-2".to_string(), config.upstreams["api"].clone());
        config
            .upstreams
            .get_mut("api-2")
            .expect("api-2")
            .policy
            .upstream_auth
            .jwt = Some(RuntimeJwtAuth {
            secret: String::new(),
            allowed_algorithms: vec![JwtAlgorithm::Es256],
            jwks_url: Some(jwks_url.to_string()),
            jwks_request_timeout: Duration::from_secs(5),
            jwks_refresh_interval: Duration::from_secs(15),
            jwks_cache_ttl: Duration::from_secs(120),
            jwks_stale_if_error: Duration::from_secs(180),
            jwks_startup_behavior: JwksStartupBehavior::RequireReady,
            ..RuntimeJwtAuth::default()
        });

        let sources = runtime_jwks_sources(&config);
        assert_eq!(sources.len(), 1);
        assert_eq!(
            sources[0].source_identity,
            jwks_source_identity_for_test(jwks_url)
        );
        assert_eq!(sources[0].jwks_url, jwks_url);
        assert_eq!(
            sources[0].allowed_algorithms,
            vec![JwtAlgorithm::Es256, JwtAlgorithm::Rs256]
        );
        assert_eq!(sources[0].refresh_interval, Duration::from_secs(15));
        assert_eq!(sources[0].request_timeout, Duration::from_secs(5));
        assert_eq!(sources[0].cache_ttl, Duration::from_secs(120));
        assert_eq!(sources[0].stale_if_error, Duration::from_secs(180));
        assert_eq!(
            sources[0].startup_behavior,
            JwksStartupBehavior::RequireReady
        );
        assert_eq!(
            sources[0].public_endpoint(),
            "https://issuer.example.com/shared-jwks.json"
        );
    }

    #[test]
    fn jwks_cache_reconcile_evicts_removed_sources() {
        let active_url = "https://issuer.example.com/reconcile-active.json";
        let removed_url = "https://issuer.example.com/reconcile-removed.json";
        let active = test_jwks_source(active_url, vec![JwtAlgorithm::Rs256]);
        let removed = test_jwks_source(removed_url, vec![JwtAlgorithm::Es256]);

        let cache = JwtJwksSharedCache {
            entries: RwLock::new(HashMap::new()),
        };
        cache.register_source(active.clone());
        cache.register_source(removed.clone());

        cache.reconcile_sources([&active]);

        assert!(
            cache
                .snapshot(&active.source_identity, Instant::now())
                .is_some(),
            "active source must remain in cache"
        );
        assert!(
            cache
                .snapshot(&removed.source_identity, Instant::now())
                .is_none(),
            "removed source must be evicted from cache"
        );
    }

    #[test]
    fn jwks_cache_reconcile_updates_active_source_in_place_without_resetting_state() {
        let jwks_url = "https://issuer.example.com/reconcile-update.json";
        let original = test_jwks_source(jwks_url, vec![JwtAlgorithm::Rs256]);
        let cache_now = Instant::now();
        let cache = JwtJwksSharedCache {
            entries: RwLock::new(HashMap::new()),
        };
        cache.upsert(
            &original.source_identity,
            JwtJwksCacheEntry {
                source: original.clone(),
                state: JwtJwksCacheState::RefreshFailedRetained,
                active_keys: vec![JwtJwksActiveKey {
                    key: RuntimeJwtVerificationKey::Pem {
                        kid: Some("persisted-kid".to_string()),
                        alg: Some(JwtAlgorithm::Rs256),
                        public_key_pem: "persisted-pem".to_string(),
                    },
                    retained_until: None,
                }],
                refresh_in_flight: true,
                last_refresh_started_at: Some(cache_now - Duration::from_secs(5)),
                last_refresh_started_wall: Some(SystemTime::now() - Duration::from_secs(5)),
                last_refresh_completed_at: Some(cache_now - Duration::from_secs(30)),
                last_refresh_completed_wall: Some(SystemTime::now() - Duration::from_secs(30)),
                last_success_at: Some(cache_now - Duration::from_secs(30)),
                last_success_wall: Some(SystemTime::now() - Duration::from_secs(30)),
                last_failure_at: Some(cache_now - Duration::from_secs(5)),
                last_failure_wall: Some(SystemTime::now() - Duration::from_secs(5)),
                last_error: Some("request_failed: retained".to_string()),
                last_failure_reason: Some(JwtJwksFetchFailureReason::RequestFailed),
                next_on_demand_refresh_at: Some(cache_now + Duration::from_secs(10)),
            },
        );

        let mut updated = original.clone();
        updated.allowed_algorithms = vec![JwtAlgorithm::Es256, JwtAlgorithm::Rs256];
        updated.refresh_interval = Duration::from_secs(15);
        updated.request_timeout = Duration::from_secs(3);
        updated.cache_ttl = Duration::from_secs(120);
        updated.stale_if_error = Duration::from_secs(180);
        updated.startup_behavior = JwksStartupBehavior::RequireReady;

        cache.reconcile_sources([&updated]);

        let entries = cache.entries.read().expect("jwks cache read lock");
        let entry = entries
            .get(&updated.source_identity)
            .expect("active source entry");
        assert!(entry.refresh_in_flight);
        assert_eq!(entry.state, JwtJwksCacheState::RefreshFailedRetained);
        assert_eq!(entry.active_keys.len(), 1);
        assert_eq!(
            entry.last_failure_reason,
            Some(JwtJwksFetchFailureReason::RequestFailed)
        );
        assert_eq!(entry.source.allowed_algorithms, updated.allowed_algorithms);
        assert_eq!(entry.source.refresh_interval, updated.refresh_interval);
        assert_eq!(entry.source.request_timeout, updated.request_timeout);
        assert_eq!(entry.source.cache_ttl, original.cache_ttl);
        assert_eq!(entry.source.stale_if_error, updated.stale_if_error);
        assert_eq!(entry.source.startup_behavior, updated.startup_behavior);
        assert_eq!(
            entry.last_error.as_deref(),
            Some("request_failed: retained")
        );
    }

    #[test]
    #[serial(jwks_cache)]
    fn stale_jwks_cache_beyond_configured_limit_rejects_requests() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let jwks_url = "https://issuer.example.com/expired-stale-jwks.json";
        clear_jwks_cache_for_test(jwks_url);
        let source_identity = jwks_source_identity_for_test(jwks_url);

        let key = PKey::from_rsa(Rsa::generate(2048).expect("rsa")).expect("pkey");
        let source = JwtJwksSourceConfig {
            source_identity: source_identity.clone(),
            jwks_url: jwks_url.to_string(),
            allowed_algorithms: vec![JwtAlgorithm::Rs256],
            refresh_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(1),
            cache_ttl: Duration::from_secs(60),
            stale_if_error: Duration::from_secs(60),
            startup_behavior: JwksStartupBehavior::AllowDegraded,
        };
        let cache_now = Instant::now();
        JwtJwksSharedCache::shared().upsert(
            &source_identity,
            JwtJwksCacheEntry {
                source,
                state: JwtJwksCacheState::Stale,
                active_keys: vec![JwtJwksActiveKey {
                    key: RuntimeJwtVerificationKey::Jwk {
                        kid: Some("expired-kid".to_string()),
                        alg: Some(JwtAlgorithm::Rs256),
                        jwk: test_rsa_public_jwk(&key, "expired-kid").to_string(),
                    },
                    retained_until: Some(cache_now - Duration::from_secs(1)),
                }],
                refresh_in_flight: false,
                last_refresh_started_at: Some(cache_now - Duration::from_secs(121)),
                last_refresh_started_wall: Some(SystemTime::now() - Duration::from_secs(121)),
                last_refresh_completed_at: Some(cache_now - Duration::from_secs(121)),
                last_refresh_completed_wall: Some(SystemTime::now() - Duration::from_secs(121)),
                last_success_at: Some(cache_now - Duration::from_secs(121)),
                last_success_wall: Some(SystemTime::now() - Duration::from_secs(121)),
                last_failure_at: Some(cache_now - Duration::from_secs(1)),
                last_failure_wall: Some(SystemTime::now() - Duration::from_secs(1)),
                last_error: Some("request_failed: jwks refresh kept failing".to_string()),
                last_failure_reason: Some(JwtJwksFetchFailureReason::RequestFailed),
                next_on_demand_refresh_at: None,
            },
        );

        let token = test_rs256_jwt(
            &key,
            "expired-kid",
            serde_json::json!({
                "iss": "issuer-1",
                "aud": "aud-1",
                "exp": 4_000_000_000u64,
            }),
        );
        let jwt = RuntimeJwtAuth {
            issuer: Some("issuer-1".to_string()),
            audience: Some("aud-1".to_string()),
            allowed_algorithms: vec![JwtAlgorithm::Rs256],
            require_kid: true,
            jwks_url: Some(jwks_url.to_string()),
            clock_skew: Duration::from_secs(30),
            ..RuntimeJwtAuth::default()
        };

        let failure = validate_jwt_token(token.as_str(), &jwt, now)
            .expect_err("stale jwks beyond configured limit must reject");
        assert_eq!(
            failure.reason,
            JwtValidationFailureReason::KeySourceUnavailable
        );

        clear_jwks_cache_for_test(jwks_url);
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial(jwks_cache)]
    async fn refresh_transport_failure_retains_last_known_good_keys_and_keeps_validating() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let jwks_url = "https://issuer.example.com/refresh-failure-retention-jwks.json";
        clear_jwks_cache_for_test(jwks_url);
        let source_identity = jwks_source_identity_for_test(jwks_url);

        let key = PKey::from_rsa(Rsa::generate(2048).expect("rsa")).expect("pkey");
        let source = JwtJwksSourceConfig {
            source_identity: source_identity.clone(),
            jwks_url: jwks_url.to_string(),
            allowed_algorithms: vec![JwtAlgorithm::Rs256],
            refresh_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(1),
            cache_ttl: Duration::from_secs(60),
            stale_if_error: Duration::from_secs(60),
            startup_behavior: JwksStartupBehavior::AllowDegraded,
        };
        JwtJwksSharedCache::shared().register_source(source.clone());
        script_jwks_fetches_for_test(
            jwks_url,
            vec![
                Ok(serde_json::json!({ "keys": [test_rsa_public_jwk(&key, "retained-kid")] })),
                Err(JwtJwksFetchFailure::request_failed(
                    "connection refused".to_string(),
                )),
            ],
        );

        refresh_jwks_source_once(source.clone(), "startup")
            .await
            .expect("initial refresh");
        refresh_jwks_source_once(source.clone(), "periodic")
            .await
            .expect_err("transport failure must surface");

        let snapshot = JwtJwksSharedCache::shared()
            .snapshot(&source.source_identity, Instant::now())
            .expect("snapshot after transport failure");
        assert_eq!(snapshot.state, JwtJwksCacheState::RefreshFailedRetained);
        assert_eq!(snapshot.active_keys.len(), 1);
        assert_eq!(
            snapshot.last_failure_reason,
            Some(JwtJwksFetchFailureReason::RequestFailed)
        );

        // A failed refresh must never revoke working keys: the last-known-good
        // set keeps validating tokens until the staleness window expires.
        let jwt = RuntimeJwtAuth {
            issuer: Some("issuer-1".to_string()),
            audience: Some("aud-1".to_string()),
            allowed_algorithms: vec![JwtAlgorithm::Rs256],
            require_kid: true,
            jwks_url: Some(jwks_url.to_string()),
            clock_skew: Duration::from_secs(30),
            ..RuntimeJwtAuth::default()
        };
        let token = test_rs256_jwt(
            &key,
            "retained-kid",
            serde_json::json!({
                "iss": "issuer-1",
                "aud": "aud-1",
                "exp": 4_000_000_000u64,
            }),
        );
        let validated = validate_jwt_token(token.as_str(), &jwt, now)
            .expect("retained keys must keep validating after refresh failure");
        assert_eq!(validated.algorithm, JwtAlgorithm::Rs256);

        clear_jwks_cache_for_test(jwks_url);
    }

    #[test]
    fn jose_header_parsing_maps_supported_algorithms_and_rejects_the_rest() {
        let parsed = parse_jose_header(br#"{"alg":"RS256","typ":"JWT","kid":"key-1"}"#)
            .expect("supported header");
        assert_eq!(parsed.algorithm, JwtAlgorithm::Rs256);
        assert_eq!(parsed.kid.as_deref(), Some("key-1"));

        let without_kid = parse_jose_header(br#"{"alg":"ES256"}"#).expect("header without kid");
        assert_eq!(without_kid.algorithm, JwtAlgorithm::Es256);
        assert_eq!(without_kid.kid, None);

        // `alg: none` and unknown algorithms must never resolve to a
        // verification mode, otherwise signature checking can be skipped.
        for header in [
            br#"{"alg":"none"}"#.as_slice(),
            br#"{"alg":"HS512"}"#.as_slice(),
        ] {
            assert_eq!(
                parse_jose_header(header)
                    .expect_err("unsupported alg must be rejected")
                    .reason,
                JwtValidationFailureReason::UnsupportedAlgorithm
            );
        }

        assert_eq!(
            parse_jose_header(br#"{"typ":"JWT"}"#)
                .expect_err("missing alg must be rejected")
                .reason,
            JwtValidationFailureReason::MissingAlgorithm
        );
        assert_eq!(
            parse_jose_header(b"not-json")
                .expect_err("malformed header must be rejected")
                .reason,
            JwtValidationFailureReason::MalformedHeader
        );
    }

    #[test]
    fn static_key_parsing_reports_distinct_failures_for_pem_and_jwk_material() {
        assert_eq!(
            parse_pem_verification_key("-----BEGIN PUBLIC KEY-----\nnope\n", JwtAlgorithm::Rs256)
                .expect_err("malformed pem must be rejected")
                .reason,
            JwtValidationFailureReason::PemKeyParseFailed
        );
        assert_eq!(
            parse_jwk_verification_key("{not json", JwtAlgorithm::Rs256)
                .expect_err("malformed jwk must be rejected")
                .reason,
            JwtValidationFailureReason::JwkKeyParseFailed
        );
        assert_eq!(
            parse_jwk_verification_key(r#"{"kty":"EC","crv":"P-256"}"#, JwtAlgorithm::Rs256)
                .expect_err("kty mismatch must be rejected")
                .reason,
            JwtValidationFailureReason::InvalidKeyType
        );

        let ec_key =
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("p256 group"))
                .expect("p256 key");
        let ec_pem = String::from_utf8(ec_key.public_key_to_pem().expect("ec pem")).expect("utf8");
        assert_eq!(
            parse_pem_verification_key(&ec_pem, JwtAlgorithm::Rs256)
                .expect_err("ec key must not satisfy rs256")
                .reason,
            JwtValidationFailureReason::InvalidKeyType
        );
        assert!(parse_pem_verification_key(&ec_pem, JwtAlgorithm::Es256).is_ok());
    }

    #[test]
    fn cache_state_transitions_track_ttl_staleness_and_retention_windows() {
        let start = Instant::now();
        let mut entry = JwtJwksCacheEntry {
            source: JwtJwksSourceConfig {
                source_identity: "transitions".to_string(),
                jwks_url: "https://issuer.example.com/transitions.json".to_string(),
                allowed_algorithms: vec![JwtAlgorithm::Rs256],
                refresh_interval: Duration::from_secs(60),
                request_timeout: Duration::from_secs(1),
                cache_ttl: Duration::from_secs(60),
                stale_if_error: Duration::from_secs(60),
                startup_behavior: JwksStartupBehavior::AllowDegraded,
            },
            state: JwtJwksCacheState::NeverFetched,
            active_keys: Vec::new(),
            refresh_in_flight: false,
            last_refresh_started_at: None,
            last_refresh_started_wall: None,
            last_refresh_completed_at: None,
            last_refresh_completed_wall: None,
            last_success_at: None,
            last_success_wall: None,
            last_failure_at: None,
            last_failure_wall: None,
            last_error: None,
            last_failure_reason: None,
            next_on_demand_refresh_at: None,
        };

        assert_eq!(
            entry.effective_state(start),
            JwtJwksCacheState::NeverFetched
        );

        entry.active_keys = vec![JwtJwksActiveKey {
            key: RuntimeJwtVerificationKey::Pem {
                kid: Some("k1".to_string()),
                alg: Some(JwtAlgorithm::Rs256),
                public_key_pem: "pem".to_string(),
            },
            retained_until: None,
        }];
        entry.state = JwtJwksCacheState::Fresh;
        entry.last_success_at = Some(start);

        assert_eq!(entry.effective_state(start), JwtJwksCacheState::Fresh);
        assert_eq!(
            entry.effective_state(start + Duration::from_secs(90)),
            JwtJwksCacheState::Stale
        );
        assert_eq!(
            entry.effective_state(start + Duration::from_secs(200)),
            JwtJwksCacheState::EmptyUnusable
        );

        // Retention states survive the TTL window instead of being reported as
        // fresh, so operators keep seeing why the set is degraded.
        entry.state = JwtJwksCacheState::RefreshFailedRetained;
        assert_eq!(
            entry.effective_state(start),
            JwtJwksCacheState::RefreshFailedRetained
        );
        entry.state = JwtJwksCacheState::QuarantinedRetained;
        assert_eq!(
            entry.effective_state(start + Duration::from_secs(90)),
            JwtJwksCacheState::QuarantinedRetained
        );
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial(jwks_cache)]
    async fn unknown_kid_rejects_current_request_and_triggers_refresh_hint() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let jwks_url = "https://issuer.example.com/on-demand-jwks.json";
        clear_jwks_cache_for_test(jwks_url);

        let first_rsa = Rsa::generate(2048).expect("first rsa");
        let first_key = PKey::from_rsa(first_rsa).expect("first pkey");
        let second_rsa = Rsa::generate(2048).expect("second rsa");
        let second_key = PKey::from_rsa(second_rsa).expect("second pkey");

        prime_jwks_cache_for_test(
            jwks_url,
            false,
            vec![RuntimeJwtVerificationKey::Jwk {
                kid: Some("known-kid".to_string()),
                alg: Some(JwtAlgorithm::Rs256),
                jwk: serde_json::json!({
                    "kty": "RSA",
                    "kid": "known-kid",
                    "alg": "RS256",
                    "use": "sig",
                    "key_ops": ["verify"],
                    "n": URL_SAFE_NO_PAD.encode(first_key.rsa().expect("rsa").n().to_vec()),
                    "e": URL_SAFE_NO_PAD.encode(first_key.rsa().expect("rsa").e().to_vec()),
                })
                .to_string(),
            }],
        );
        script_jwks_fetches_for_test(
            jwks_url,
            vec![Ok(serde_json::json!({
                "keys": [
                    test_rsa_public_jwk(&first_key, "known-kid"),
                    test_rsa_public_jwk(&second_key, "rotated-kid"),
                ]
            }))],
        );

        let jwt = RuntimeJwtAuth {
            issuer: Some("issuer-1".to_string()),
            audience: Some("aud-1".to_string()),
            allowed_algorithms: vec![JwtAlgorithm::Rs256],
            require_kid: true,
            jwks_url: Some(jwks_url.to_string()),
            jwks_refresh_interval: Duration::from_secs(60),
            jwks_request_timeout: Duration::from_secs(1),
            jwks_cache_ttl: Duration::from_secs(60),
            jwks_stale_if_error: Duration::from_secs(60),
            clock_skew: Duration::from_secs(30),
            ..RuntimeJwtAuth::default()
        };
        let token = test_rs256_jwt(
            &second_key,
            "rotated-kid",
            serde_json::json!({
                "iss": "issuer-1",
                "aud": "aud-1",
                "exp": 4_000_000_000u64,
            }),
        );

        let failure = validate_jwt_token(token.as_str(), &jwt, now)
            .expect_err("current request must reject unknown kid");
        assert_eq!(
            failure.reason,
            JwtValidationFailureReason::MissingVerificationKey
        );

        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if validate_jwt_token(token.as_str(), &jwt, now).is_ok() {
                clear_jwks_cache_for_test(jwks_url);
                return;
            }
        }

        panic!("on-demand jwks refresh did not publish the rotated kid");
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial(jwks_cache)]
    async fn refresh_retains_temporarily_dropped_old_key_during_rollover_overlap() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let jwks_url = "https://issuer.example.com/rollover-overlap-jwks.json";
        clear_jwks_cache_for_test(jwks_url);
        let source_identity = jwks_source_identity_for_test(jwks_url);

        let old_key = PKey::from_rsa(Rsa::generate(2048).expect("old rsa")).expect("old pkey");
        let new_key = PKey::from_rsa(Rsa::generate(2048).expect("new rsa")).expect("new pkey");
        let source = JwtJwksSourceConfig {
            source_identity: source_identity.clone(),
            jwks_url: jwks_url.to_string(),
            allowed_algorithms: vec![JwtAlgorithm::Rs256],
            refresh_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(1),
            cache_ttl: Duration::from_secs(60),
            stale_if_error: Duration::from_secs(60),
            startup_behavior: JwksStartupBehavior::AllowDegraded,
        };
        JwtJwksSharedCache::shared().register_source(source.clone());
        script_jwks_fetches_for_test(
            jwks_url,
            vec![
                Ok(serde_json::json!({ "keys": [test_rsa_public_jwk(&old_key, "old-kid")] })),
                Ok(serde_json::json!({ "keys": [test_rsa_public_jwk(&new_key, "new-kid")] })),
            ],
        );

        refresh_jwks_source_once(source.clone(), "startup")
            .await
            .expect("initial refresh");
        refresh_jwks_source_once(source.clone(), "periodic")
            .await
            .expect("rollover refresh");

        let jwt = RuntimeJwtAuth {
            issuer: Some("issuer-1".to_string()),
            audience: Some("aud-1".to_string()),
            allowed_algorithms: vec![JwtAlgorithm::Rs256],
            require_kid: true,
            jwks_url: Some(jwks_url.to_string()),
            clock_skew: Duration::from_secs(30),
            ..RuntimeJwtAuth::default()
        };
        let old_token = test_rs256_jwt(
            &old_key,
            "old-kid",
            serde_json::json!({ "iss": "issuer-1", "aud": "aud-1", "exp": 4_000_000_000u64 }),
        );
        let new_token = test_rs256_jwt(
            &new_key,
            "new-kid",
            serde_json::json!({ "iss": "issuer-1", "aud": "aud-1", "exp": 4_000_000_000u64 }),
        );

        assert!(validate_jwt_token(old_token.as_str(), &jwt, now).is_ok());
        assert!(validate_jwt_token(new_token.as_str(), &jwt, now).is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial(jwks_cache)]
    async fn refresh_replaces_key_material_when_issuer_reuses_existing_kid() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let jwks_url = "https://issuer.example.com/reused-kid-jwks.json";
        clear_jwks_cache_for_test(jwks_url);
        let source_identity = jwks_source_identity_for_test(jwks_url);

        let old_key = PKey::from_rsa(Rsa::generate(2048).expect("old rsa")).expect("old pkey");
        let new_key = PKey::from_rsa(Rsa::generate(2048).expect("new rsa")).expect("new pkey");
        let source = JwtJwksSourceConfig {
            source_identity: source_identity.clone(),
            jwks_url: jwks_url.to_string(),
            allowed_algorithms: vec![JwtAlgorithm::Rs256],
            refresh_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(1),
            cache_ttl: Duration::from_secs(60),
            stale_if_error: Duration::from_secs(60),
            startup_behavior: JwksStartupBehavior::AllowDegraded,
        };
        JwtJwksSharedCache::shared().register_source(source.clone());
        script_jwks_fetches_for_test(
            jwks_url,
            vec![
                Ok(serde_json::json!({ "keys": [test_rsa_public_jwk(&old_key, "shared-kid")] })),
                Ok(serde_json::json!({ "keys": [test_rsa_public_jwk(&new_key, "shared-kid")] })),
            ],
        );

        refresh_jwks_source_once(source.clone(), "startup")
            .await
            .expect("initial refresh");
        refresh_jwks_source_once(source.clone(), "periodic")
            .await
            .expect("replacement refresh");

        let jwt = RuntimeJwtAuth {
            issuer: Some("issuer-1".to_string()),
            audience: Some("aud-1".to_string()),
            allowed_algorithms: vec![JwtAlgorithm::Rs256],
            require_kid: true,
            jwks_url: Some(jwks_url.to_string()),
            clock_skew: Duration::from_secs(30),
            ..RuntimeJwtAuth::default()
        };
        let old_token = test_rs256_jwt(
            &old_key,
            "shared-kid",
            serde_json::json!({ "iss": "issuer-1", "aud": "aud-1", "exp": 4_000_000_000u64 }),
        );
        let new_token = test_rs256_jwt(
            &new_key,
            "shared-kid",
            serde_json::json!({ "iss": "issuer-1", "aud": "aud-1", "exp": 4_000_000_000u64 }),
        );

        let old_failure = validate_jwt_token(old_token.as_str(), &jwt, now)
            .expect_err("old material under reused kid must stop validating");
        assert_eq!(
            old_failure.reason,
            JwtValidationFailureReason::SignatureInvalid
        );
        assert!(validate_jwt_token(new_token.as_str(), &jwt, now).is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial(jwks_cache)]
    async fn empty_or_broken_refresh_quarantines_replacement_and_retains_last_known_good_keys() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let jwks_url = "https://issuer.example.com/quarantine-jwks.json";
        clear_jwks_cache_for_test(jwks_url);
        let source_identity = jwks_source_identity_for_test(jwks_url);

        let key = PKey::from_rsa(Rsa::generate(2048).expect("rsa")).expect("pkey");
        let source = JwtJwksSourceConfig {
            source_identity: source_identity.clone(),
            jwks_url: jwks_url.to_string(),
            allowed_algorithms: vec![JwtAlgorithm::Rs256],
            refresh_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(1),
            cache_ttl: Duration::from_secs(60),
            stale_if_error: Duration::from_secs(60),
            startup_behavior: JwksStartupBehavior::AllowDegraded,
        };
        JwtJwksSharedCache::shared().register_source(source.clone());
        script_jwks_fetches_for_test(
            jwks_url,
            vec![
                Ok(serde_json::json!({ "keys": [test_rsa_public_jwk(&key, "stable-kid")] })),
                Ok(serde_json::json!({ "keys": [] })),
                Err(JwtJwksFetchFailure::malformed_document(
                    "duplicate or broken jwks",
                )),
            ],
        );

        refresh_jwks_source_once(source.clone(), "startup")
            .await
            .expect("initial refresh");
        refresh_jwks_source_once(source.clone(), "periodic")
            .await
            .expect("empty replacement refresh");
        let after_empty = JwtJwksSharedCache::shared()
            .snapshot(&source.source_identity, Instant::now())
            .expect("snapshot after empty");
        assert_eq!(after_empty.state, JwtJwksCacheState::QuarantinedRetained);
        assert_eq!(after_empty.active_keys.len(), 1);

        let _ = refresh_jwks_source_once(source.clone(), "periodic").await;
        let after_broken = JwtJwksSharedCache::shared()
            .snapshot(&source.source_identity, Instant::now())
            .expect("snapshot after broken");
        assert!(matches!(
            after_broken.state,
            JwtJwksCacheState::QuarantinedRetained | JwtJwksCacheState::RefreshFailedRetained
        ));

        let jwt = RuntimeJwtAuth {
            issuer: Some("issuer-1".to_string()),
            audience: Some("aud-1".to_string()),
            allowed_algorithms: vec![JwtAlgorithm::Rs256],
            require_kid: true,
            jwks_url: Some(jwks_url.to_string()),
            clock_skew: Duration::from_secs(30),
            ..RuntimeJwtAuth::default()
        };
        let token = test_rs256_jwt(
            &key,
            "stable-kid",
            serde_json::json!({ "iss": "issuer-1", "aud": "aud-1", "exp": 4_000_000_000u64 }),
        );
        assert!(validate_jwt_token(token.as_str(), &jwt, now).is_ok());
    }
}
