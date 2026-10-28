//! Protocol-neutral traffic-policy contracts and evaluation services.
//!
//! Ingress adapters provide borrowed request views. Protocol parsing,
//! configuration loading, and response emission remain with their owners.

#![forbid(unsafe_code)]
#![deny(unused_crate_dependencies)]
#![warn(unreachable_pub)]

mod api_key;
mod request;

pub use api_key::{ApiKeyPolicyInput, api_key_is_authorized};
pub use request::{RequestHeaderLookup, RequestView};
