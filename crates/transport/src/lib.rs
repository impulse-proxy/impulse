//! Canonical upstream transport façade.
//!
//! Callers should depend on this crate for backend request execution, backend
//! client rotation, DNS cache coordination, and transport-scoped connection
//! policy application. Protocol-specific H1/H2 client and pool implementations
//! remain internal details behind [`UpstreamTransportPool`].

mod client_rotation;
mod exchange;
mod h1_client;
mod h1_pool;
mod h2_client;
mod h2_pool;
mod pingora_peer;
mod transport_pool;

pub use exchange::{
    UpstreamBodyFrame, UpstreamCancellation, UpstreamConnectionReuse, UpstreamExchangeCompletion,
    UpstreamExchangeLifecycle, UpstreamExchangeOutcome, UpstreamExchangeRequest,
    UpstreamExchangeResponse, UpstreamInflightPermit, UpstreamRequestBody, UpstreamRequestHead,
    UpstreamResponseBody, UpstreamResponseHead, UpstreamTrailers, UpstreamTunnel, UpstreamTunnelIo,
    UpstreamUpgrade,
};
pub use h2_client::{ConnectObservation, ConnectObserver, SharedDnsResolver, TlsClientConfig};
pub use pingora_peer::build_pingora_http_peer;
pub use transport_pool::{
    BackendUpgradeLease, BackendUpgradeResponse, TransportClientRotation, UpstreamTransportPool,
};
