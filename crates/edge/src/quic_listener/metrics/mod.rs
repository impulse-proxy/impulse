use std::{
    sync::{Arc, atomic::AtomicUsize},
    time::Duration,
};

use ::http::{Response, StatusCode};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use impulse_config::config::MetricsEndpoint;
use impulse_errors::ProxyError;
use log::{debug, error, info};
use rustls::ServerConfig as RustlsServerConfig;
use tokio_rustls::TlsAcceptor;

use super::{
    QUICListener,
    runtime_endpoint::RuntimeConnectionSlotGuard,
    runtime_handle,
    runtime_state::{ControlPlaneStartup, MetricsServiceCtx},
    spawn_supervised_async_task,
};
use crate::Metrics;

mod http;
mod service;
mod state;
