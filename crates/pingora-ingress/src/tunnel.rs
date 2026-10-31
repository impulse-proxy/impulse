use impulse_contracts::TunnelMode;
use pingora_core::upstreams::peer::{ALPN, HttpPeer};
use pingora_proxy::{HttpProxy, ProxyHttp};

pub fn classify_tunnel(method: &str, websocket_tunnel: bool) -> TunnelMode {
    if websocket_tunnel {
        TunnelMode::Websocket
    } else if method.eq_ignore_ascii_case("CONNECT") {
        TunnelMode::Connect
    } else {
        TunnelMode::None
    }
}

pub fn configure_tunnel_proxy<S: ProxyHttp>(proxy: &mut HttpProxy<S>) {
    let mut options = proxy.server_options.take().unwrap_or_default();
    options.allow_connect_method_proxying = true;
    proxy.server_options = Some(options);
}

pub fn configure_tunnel_peer(mode: TunnelMode, peer: &mut HttpPeer) {
    if mode.is_tunnel() {
        peer.options.alpn = ALPN::H1;
    }
}

pub fn tunnel_response_established(
    mode: TunnelMode,
    method: &str,
    status: http::StatusCode,
) -> bool {
    mode.established_by(method, status)
}

pub fn tunnel_cache_flags(mode: TunnelMode) -> (bool, bool) {
    (mode == TunnelMode::Websocket, mode == TunnelMode::Connect)
}
