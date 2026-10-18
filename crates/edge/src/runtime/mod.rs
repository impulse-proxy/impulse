//! Runtime ownership and state model for the edge data plane.
//!
//! External callers should treat this module as the source of stable runtime
//! state types. Connection plumbing, generation swaps, and TLS/task internals
//! remain crate-private implementation details.

pub mod activation;
pub mod backend;
pub mod bundle;
pub(crate) mod connection;
pub(crate) mod generation;
pub mod listener;
pub mod policy;
pub mod privilege_drop;
pub mod shared_state;
pub(crate) mod tasks;
pub(crate) mod tls;
