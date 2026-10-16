//! Canonical upstream transport façade.
//!
//! Callers should depend on this crate for backend request execution, backend
//! client rotation, DNS cache coordination, and transport-scoped connection
//! policy application. Protocol-specific Pingora sessions remain internal
//! details behind [`UpstreamTransportPool`].

mod client_rotation;
mod connection_identity;
mod exchange;
mod pingora_failure;
mod pingora_h1;
mod pingora_h2;
mod pingora_peer;
mod pingora_pool;
mod runtime_config;
mod transport_pool;

pub use connection_identity::{PingoraUpstreamConnectionIdentity, PingoraUpstreamProxyIdentity};
pub use exchange::{
    UpstreamBodyFrame, UpstreamCancellation, UpstreamConnectionReuse, UpstreamExchangeCompletion,
    UpstreamExchangeLifecycle, UpstreamExchangeOutcome, UpstreamExchangeRequest,
    UpstreamExchangeResponse, UpstreamInflightPermit, UpstreamRequestBody, UpstreamRequestHead,
    UpstreamResponseBody, UpstreamResponseHead, UpstreamTrailers, UpstreamTunnel, UpstreamTunnelIo,
    UpstreamUpgrade,
};
pub use runtime_config::{SharedDnsResolver, TlsClientConfig};
pub use transport_pool::{TransportClientRotation, UpstreamTransportPool};
