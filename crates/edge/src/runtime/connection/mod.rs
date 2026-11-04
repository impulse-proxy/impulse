//! Request/response execution state shared across listener paths.
//!
//! This module owns the canonical connection-domain types that the ingress
//! paths use: auth decisions, request/response envelopes,
//! stream state, and outcome recording. Protocol-neutral body guardrails live
//! in `edge_core`; ingress adapters retain protocol I/O ownership.

pub(crate) mod auth;
pub(crate) mod outcome;
pub(crate) mod plugin;
pub(crate) mod quic;
pub(crate) mod request;
pub(crate) mod response;
pub(crate) mod stream;
