//! Protocol-neutral traffic-policy contracts and evaluation services.
//!
//! Ingress adapters provide borrowed request views. Protocol parsing,
//! configuration loading, and response emission remain with their owners.

#![forbid(unsafe_code)]
#![deny(unused_crate_dependencies)]
#![warn(unreachable_pub)]

mod api_key;
pub mod jwks;
mod jwt;
mod request;

pub use api_key::{ApiKeyPolicyInput, api_key_is_authorized};
pub use jwt::{
    JwtAlgorithm, JwtAllowedAlgorithms, JwtClaimsRequirements, JwtPolicyInput,
    JwtValidationFailure, JwtValidationFailureReason, JwtVerificationKey, ParsedJoseHeader,
    ParsedJwt, ValidatedJwt, jwt_claims_satisfy_requirements, parse_jose_header, parse_jwt,
    validate_parsed_jwt,
};
pub use request::{RequestHeaderLookup, RequestView};
