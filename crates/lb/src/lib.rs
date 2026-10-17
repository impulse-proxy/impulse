//! Load-balancing primitives for runtime-selected backend picking.
//!
//! Canonical consumers should depend on [`upstream_pool`], [`load_balancing`],
//! [`alternate_backend`], and [`health`]. The remaining modules are kept
//! private as implementation substrate and are not intended as orchestration
//! entrypoints.

mod algorithms;
pub mod alternate_backend;
mod backend;
mod backend_pool;
pub mod hash;
pub mod health;
pub mod load_balancing;
pub mod pingora_backend;
#[cfg(test)]
pub(crate) mod test_support;
pub mod upstream_pool;

pub use health::HealthTransition;
