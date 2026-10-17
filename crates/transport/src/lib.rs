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
    UpstreamBody, UpstreamBodyFrame, UpstreamCancellation, UpstreamConnectionReuse,
    UpstreamExchangeCompletion, UpstreamExchangeLifecycle, UpstreamExchangeOutcome,
    UpstreamExchangeRequest, UpstreamExchangeResponse, UpstreamInflightPermit, UpstreamRequestHead,
    UpstreamResponseHead, UpstreamTunnel, UpstreamTunnelIo, UpstreamUpgrade,
};
pub use pingora_failure::{classify_pingora_h1_error, classify_pingora_h2_error};
pub use runtime_config::{SharedDnsResolver, TlsClientConfig};
pub use transport_pool::{TransportClientRotation, UpstreamTransportPool};
