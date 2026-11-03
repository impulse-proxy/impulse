use std::{
    sync::{Arc, atomic::AtomicUsize},
    time::Duration,
};

use impulse_config::config::MetricsEndpoint;
use impulse_errors::ProxyError;
use impulse_operations::{
    ConnectionSlotGuard, MetricsConnectionError, MetricsHttpService, MetricsSource,
    try_claim_control_api_connection_slot,
};
use log::{debug, error, info};
use rustls::ServerConfig as RustlsServerConfig;

use super::{
    Http3Service, runtime_handle,
    runtime_state::{ControlPlaneStartup, MetricsServiceCtx},
};
use crate::Metrics;

pub(super) mod service;
mod state;
