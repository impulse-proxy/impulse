//! Canonical upstream transport façade.
//!
//! HTTP/3 adapters use [`UpstreamTransportPool::execute_http3_exchange`] for
//! backend exchanges.
//! Pingora `HttpProxy` routes (HTTP/1 and HTTP/2) get a configured peer from
//! [`UpstreamTransportPool::pingora_proxy_peer`] and let Pingora own the
//! exchange and its idle connection lifecycle.

mod connection_identity;
mod exchange;
mod input;
mod pingora_failure;
mod pingora_h1;
mod pingora_h2;
mod pingora_peer;
mod runtime_config;
mod transport_pool;

pub use connection_identity::PingoraBackendHealthIdentity;
pub(crate) use connection_identity::PingoraUpstreamConnectionIdentity;
pub use input::{
    UpstreamConnectionLimitsInput, UpstreamEndpointInput, UpstreamH2FlowControlInput,
    UpstreamProtocol, UpstreamProxyInput, UpstreamTimeoutInput, UpstreamTlsInput,
    UpstreamTransportInput,
};
pub use pingora_failure::{classify_pingora_h1_error, classify_pingora_h2_error};
pub use runtime_config::SharedDnsResolver;
pub use transport_pool::UpstreamTransportPool;

/// Exchange adaptation for HTTP/3 ingress and cases that transfer ownership
/// of an upstream body, tunnel, or upgrade across the transport boundary.
pub mod http3 {
    pub use crate::exchange::{
        UpstreamBody, UpstreamBodyFrame, UpstreamExchangeRequest, UpstreamExchangeResponse,
        UpstreamRequestHead, UpstreamResponseHead, UpstreamTunnel, UpstreamTunnelCompletion,
        UpstreamTunnelIo, UpstreamUpgrade,
    };
}
