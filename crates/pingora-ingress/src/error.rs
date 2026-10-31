use impulse_errors::ProxyError;
use pingora_core::{
    Error, ErrorType, RetryType,
    upstreams::peer::{ALPN, HttpPeer},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PingoraUpstreamProtocol {
    Http1,
    Http2,
}

pub fn pingora_peer_protocol(peer: &HttpPeer) -> PingoraUpstreamProtocol {
    if matches!(peer.options.alpn, ALPN::H2) {
        PingoraUpstreamProtocol::Http2
    } else {
        PingoraUpstreamProtocol::Http1
    }
}

pub fn classify_pingora_proxy_error(
    error: &Error,
    protocol: PingoraUpstreamProtocol,
    reused: bool,
) -> ProxyError {
    let detail = error.to_string();
    match &error.etype {
        ErrorType::ConnectTimedout
        | ErrorType::TLSHandshakeTimedout
        | ErrorType::ReadTimedout
        | ErrorType::WriteTimedout => ProxyError::Timeout,
        ErrorType::TLSWantX509Lookup
        | ErrorType::TLSHandshakeFailure
        | ErrorType::InvalidCert
        | ErrorType::HandshakeError => ProxyError::Tls(detail),
        _ if protocol == PingoraUpstreamProtocol::Http2
            && (matches!(error.retry, RetryType::Decided(true))
                || matches!(error.retry, RetryType::ReusedOnly) && reused) =>
        {
            ProxyError::Transport(detail)
        }
        ErrorType::InvalidHTTPHeader
        | ErrorType::H1Error
        | ErrorType::H2Error
        | ErrorType::H2Downgrade
        | ErrorType::InvalidH2
        | ErrorType::HTTPStatus(_) => ProxyError::Protocol(detail),
        _ => ProxyError::Transport(detail),
    }
}
