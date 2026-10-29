//! Protocol-neutral traffic-policy contracts and evaluation services.
//!
//! Ingress adapters provide borrowed request views. Protocol parsing,
//! configuration loading, and response emission remain with their owners.

#![forbid(unsafe_code)]
#![deny(unused_crate_dependencies)]
#![warn(unreachable_pub)]

mod api_key;
mod external_auth;
pub mod jwks;
mod jwt;
mod request;

pub use api_key::{ApiKeyPolicyInput, api_key_is_authorized};
pub use external_auth::{
    ExternalAuthChallengeResponse, ExternalAuthCompletion, ExternalAuthDecision,
    ExternalAuthDenyResponse, ExternalAuthExecutionPolicy, ExternalAuthFailureDisposition,
    ExternalAuthPlan, ExternalAuthRedirectResponse, ExternalAuthResponseMetadata,
    ExternalAuthResult, ExternalAuthStateTransition, ExternalAuthTaskConfig,
    allowed_external_auth_headers, canonicalize_external_auth_mutations,
    evaluate_external_auth_completion, external_auth_allow_mutations,
    map_http_external_auth_response, merge_external_auth_mutations,
    resolve_external_auth_state_transition,
};
pub use jwt::{
    JwtAlgorithm, JwtAllowedAlgorithms, JwtClaimsRequirements, JwtPolicyInput,
    JwtValidationFailure, JwtValidationFailureReason, JwtVerificationKey, ParsedJoseHeader,
    ParsedJwt, ValidatedJwt, jwt_claims_satisfy_requirements, parse_jose_header, parse_jwt,
    validate_parsed_jwt,
};
pub use request::{RequestHeaderLookup, RequestView};
