use impulse_errors::ProxyError;
use pingora_core::{Error, ErrorType, RetryType};

pub fn classify_pingora_h1_error(error: &Error) -> ProxyError {
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
        ErrorType::InvalidHTTPHeader
        | ErrorType::H1Error
        | ErrorType::H2Error
        | ErrorType::H2Downgrade
        | ErrorType::InvalidH2
        | ErrorType::HTTPStatus(_) => ProxyError::Protocol(detail),
        _ => ProxyError::Transport(detail),
    }
}

pub fn classify_pingora_h2_error(error: &Error, reused: bool) -> ProxyError {
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
        _ if matches!(error.retry, RetryType::Decided(true))
            || matches!(error.retry, RetryType::ReusedOnly) && reused =>
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
