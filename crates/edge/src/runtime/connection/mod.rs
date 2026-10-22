//! Request/response execution state shared across listener paths.
//!
//! This module owns the canonical connection-domain types that the ingress
//! paths use: auth decisions, request/response envelopes,
//! stream state, and outcome recording. Body guardrails remain crate-private so
//! callers depend on the stable execution types rather than the enforcement
//! internals.

pub(crate) mod auth;
pub(crate) mod guardrails;
pub(crate) mod outcome;
pub(crate) mod quic;
pub(crate) mod rate_limit;
pub(crate) mod request;
pub(crate) mod response;
pub(crate) mod stream;

pub(crate) use rate_limit::{PerSourceTokenBucket, TokenBucket};
