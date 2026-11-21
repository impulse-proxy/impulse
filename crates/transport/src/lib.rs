//! Canonical upstream transport façade.
//!
//! HTTP/3 adapters use [`UpstreamRequestExecutor`] for backend exchanges.
//! Pingora `HttpProxy` routes (HTTP/1 and HTTP/2) get a configured peer from
//! [`UpstreamTransportPool::pingora_proxy_peer`] and let Pingora own the
//! exchange. Pool lifecycle operations remain available through
//! [`UpstreamTransportPool`] to runtime owners.

mod connection_identity;
mod exchange;
mod input;
mod pingora_failure;
mod pingora_h1;
mod pingora_h2;
mod pingora_peer;
mod pingora_pool;
mod request_executor;
mod runtime_config;
mod transport_pool;

pub use connection_identity::PingoraBackendHealthIdentity;
pub(crate) use connection_identity::PingoraUpstreamConnectionIdentity;
pub use exchange::{
    UpstreamBody, UpstreamBodyFrame, UpstreamExchangeRequest, UpstreamExchangeResponse,
    UpstreamRequestHead, UpstreamResponseHead, UpstreamTunnel, UpstreamTunnelCompletion,
    UpstreamTunnelIo, UpstreamUpgrade,
};
pub use input::{
    UpstreamConnectionLimitsInput, UpstreamEndpointInput, UpstreamProtocol, UpstreamProxyInput,
    UpstreamTimeoutInput, UpstreamTlsInput, UpstreamTransportInput,
};
pub use pingora_failure::{classify_pingora_h1_error, classify_pingora_h2_error};
pub use request_executor::UpstreamRequestExecutor;
pub use runtime_config::SharedDnsResolver;
pub use transport_pool::UpstreamTransportPool;
