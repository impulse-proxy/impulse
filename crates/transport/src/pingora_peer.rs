use std::net::{SocketAddr, ToSocketAddrs};

use impulse_config::{
    backend_endpoint::BackendScheme,
    runtime::{
        RuntimeBackendConnectionPolicy, RuntimeBackendEndpoint, RuntimeBackendTransportKind,
    },
};
use pingora_core::upstreams::peer::{ALPN, HttpPeer};

/// Build a Pingora peer from an already validated runtime backend.
pub fn build_pingora_http_peer(
    endpoint: &RuntimeBackendEndpoint,
    connection_policy: &RuntimeBackendConnectionPolicy,
) -> Result<HttpPeer, String> {
    build_pingora_http_peer_with_address(endpoint, connection_policy).map(|(peer, _)| peer)
}

pub(crate) fn build_pingora_http_peer_with_address(
    endpoint: &RuntimeBackendEndpoint,
    connection_policy: &RuntimeBackendConnectionPolicy,
) -> Result<(HttpPeer, SocketAddr), String> {
    let address = (endpoint.authority_host.as_str(), endpoint.authority_port)
        .to_socket_addrs()
        .map_err(|error| {
            format!(
                "failed to resolve backend '{}': {error}",
                endpoint.canonical.authority()
            )
        })?
        .next()
        .ok_or_else(|| {
            format!(
                "backend '{}' resolved without an address",
                endpoint.canonical.authority()
            )
        })?;
    let tls = endpoint.canonical.scheme() == BackendScheme::Https;
    let mut peer = HttpPeer::new(
        address,
        tls,
        tls.then(|| endpoint.authority_host.clone())
            .unwrap_or_default(),
    );
    peer.options.connection_timeout = Some(connection_policy.connect_timeout);
    peer.options.total_connection_timeout = Some(connection_policy.connect_timeout);
    peer.options.read_timeout = Some(connection_policy.execution_timeout);
    peer.options.write_timeout = Some(connection_policy.execution_timeout);
    peer.options.idle_timeout = Some(connection_policy.pool_idle_timeout);
    peer.options.alpn = match endpoint.transport_kind {
        RuntimeBackendTransportKind::Http1 => ALPN::H1,
        RuntimeBackendTransportKind::H2 => ALPN::H2,
    };
    peer.options.max_h2_streams = connection_policy.max_inflight;
    Ok((peer, address))
}
