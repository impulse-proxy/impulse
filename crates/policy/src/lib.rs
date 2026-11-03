//! Protocol-neutral traffic-policy contracts and evaluation services.
//!
//! Ingress adapters provide borrowed request views. Protocol parsing,
//! configuration loading, and response emission remain with their owners.

#![forbid(unsafe_code)]
#![deny(unused_crate_dependencies)]
#![warn(unreachable_pub)]

mod adaptive_admission;
mod api_key;
mod brownout;
mod external_auth;
pub mod jwks;
mod jwt;
pub mod quota;
mod request;
mod response_cache;
mod response_compression;
mod scoped_rate_limit;

pub use adaptive_admission::{AdaptiveAdmission, AdaptivePermit, evaluate_adaptive_admission};
pub use api_key::{ApiKeyPolicyInput, api_key_is_authorized};
pub use brownout::{BrownoutController, evaluate_brownout_admission};
pub use external_auth::{
    ExternalAuthChallengeResponse, ExternalAuthCompletion, ExternalAuthDecision,
    ExternalAuthDenyResponse, ExternalAuthExecutionPolicy, ExternalAuthFailureDisposition,
    ExternalAuthFailureMode, ExternalAuthPlan, ExternalAuthPolicy, ExternalAuthRedirectResponse,
    ExternalAuthRequestHeader, ExternalAuthResponseMetadata, ExternalAuthResult,
    ExternalAuthStateTransition, ExternalAuthTaskConfig, allowed_external_auth_headers,
    canonicalize_external_auth_mutations, evaluate_external_auth_completion,
    external_auth_allow_mutations, map_http_external_auth_response, merge_external_auth_mutations,
    resolve_external_auth_state_transition,
};
pub use jwt::{
    JwtAlgorithm, JwtAllowedAlgorithms, JwtClaimsRequirements, JwtPolicyInput,
    JwtValidationFailure, JwtValidationFailureReason, JwtVerificationKey, ParsedJoseHeader,
    ParsedJwt, ValidatedJwt, jwt_claims_satisfy_requirements, parse_jose_header, parse_jwt,
    validate_parsed_jwt,
};
pub use request::{RequestHeaderLookup, RequestView};
pub use response_cache::{
    CanonicalResponseCacheKey, ResponseCacheAuthInput, ResponseCacheBypassReason,
    ResponseCacheKeyInput, ResponseCachePolicyInput, ResponseCacheRepresentation,
    ResponseCacheRequestEligibilityInput, ResponseCacheResponseEligibilityInput,
    canonical_response_cache_key, evaluate_cache_request_eligibility,
    evaluate_cache_response_eligibility, response_cache_ttl, route_auth_requires_cache_bypass,
};
pub use response_compression::{
    ResponseCompressionAction, ResponseCompressionBypassReason, ResponseCompressionEvaluation,
    ResponseCompressionInput, ResponseCompressionPolicyInput, apply_gzip_response_headers,
    ensure_vary_accept_encoding, evaluate_response_compression,
};
pub use scoped_rate_limit::{
    RequestKeySpec, ScopedRateLimitEvaluation, ScopedRateLimitHeaderLookup,
    ScopedRateLimitIdentity, ScopedRateLimitKeyExtraction, evaluate_scoped_rate_limit,
    extract_scoped_rate_limit_key,
};
