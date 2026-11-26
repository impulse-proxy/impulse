//! Load-balancing integration for Pingora-owned backend views and selection.

mod backend;
mod backend_pool;
pub mod health;
mod input;
pub mod pingora_backend;
mod pingora_discovery;
#[cfg(test)]
#[path = "tests/support.rs"]
mod test_support;
pub mod upstream_pool;

pub use input::{
    BackendHealthInput, BackendInput, BackendSelectionInput, BackendWeight, LoadBalancingStrategy,
    RequestKeyInput,
};
