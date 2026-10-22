//! Backend lifecycle state exposed to the rest of the edge runtime.
//!
//! External consumers should rely on the stable resolution, snapshot, and
//! inventory types. Lifecycle mutation coordinators remain internal
//! implementation details.

pub mod event;
pub(crate) mod lifecycle;
pub mod resolution;
pub mod state;
pub mod store;
