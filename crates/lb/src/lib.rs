//! Load-balancing primitives for runtime-selected backend picking.
//!
//! Canonical consumers should depend on [`upstream_pool`],
//! [`alternate_backend`], and [`health`]. Selection implementations remain
//! private behind those runtime entrypoints.

mod algorithms;
pub mod alternate_backend;
mod backend;
mod backend_pool;
pub mod health;
mod input;
mod load_balancing;
pub mod pingora_backend;
mod pingora_discovery;
#[cfg(test)]
pub(crate) mod test_support;
pub mod upstream_pool;

pub use health::HealthTransition;
pub use input::{
    BackendHealthInput, BackendInput, BackendWeight, LoadBalancingStrategy, RequestKeyInput,
};
