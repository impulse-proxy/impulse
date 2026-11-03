//! Operational service boundaries for Impulse.

#![forbid(unsafe_code)]
#![deny(unused_crate_dependencies)]
#![warn(unreachable_pub)]

pub mod administrative;
mod control_api;
mod metrics;
pub mod watchdog;

pub use control_api::{
    ConnectionSlotGuard, ControlApiConnectionError, ControlApiConnectionService,
    ControlApiRequestService, ControlApiResponse, accept_control_api_tls,
    control_api_internal_error_response, run_control_api_blocking,
    stale_control_api_connection_response, try_claim_control_api_connection_slot,
};
pub use metrics::{MetricsConnectionError, MetricsHttpService, MetricsResponse, MetricsSource};
