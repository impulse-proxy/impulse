//! Canonical upstream transport façade.
//!
//! Callers should depend on this crate for backend request execution, backend
//! client rotation, DNS cache coordination, and transport-scoped connection
//! policy application. Protocol-specific Pingora sessions remain internal
//! details behind [`UpstreamRequestExecutor`]. Pool lifecycle operations remain
//! available through [`UpstreamTransportPool`] to runtime owners.

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
