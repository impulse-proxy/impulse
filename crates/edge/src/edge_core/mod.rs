//! Protocol-neutral request execution and shared routing.
//!
//! Ingress implementations translate protocol state into this boundary. They
//! do not own routing or request-policy execution.

pub(crate) mod body_guardrails;
pub(crate) mod request_execution;
pub(crate) mod request_validation;
pub(crate) mod response_processing;
pub(crate) mod retry;
pub mod routing;
