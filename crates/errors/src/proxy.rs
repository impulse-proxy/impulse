//! Canonical proxy and upstream error classification surface.

use std::{borrow::Cow, fmt};

use thiserror::Error;

use crate::{
    BridgeError, PoolError, UpstreamErrorCategory, UpstreamErrorClassification,
    UpstreamHealthFailureMapping, UpstreamRetryability, UpstreamTlsReason, classify_retryability,
};

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("bridge error: {0}")]
    Bridge(#[from] BridgeError),

    #[error("pool error: {0}")]
    Pool(#[from] PoolError),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("transport error: {0}")]
    RequestTransport(RequestFailure),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("protocol error: {0}")]
    RequestProtocol(RequestFailure),

    #[error("backend timeout")]
    Timeout,

    #[error("TLS error: {0}")]
    Tls(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestFailure {
    EmptyMethodOrPath,
    NoRoute,
    MissingUpstreamDisplayName,
    MissingRouteRuntime,
    MissingUpstreamPool,
    MissingUpstreamSelector,
    UpstreamPoolLockPoisoned,
    NoHealthyServers,
    InvalidBackendIndex,
    UnknownBackendTransportIdentity,
    MissingDeferredForwardSnapshot,
    MissingUpstreamRoute,
    EarlyDataRejected,
    RequestBodyTooLarge,
    RequestTrailersRequireHttp2,
    UpstreamRuntimeUnavailable,
    RuntimeUnavailable,
    UpstreamTunnelTaskStopped,
    UpstreamPoolDraining,
    Http1RequestAlreadyWritten,
    RequestBodyExceedsDeclaredFraming,
    Http1RequestTrailersUnsupported,
    Http2RequestAlreadyWritten,
    Http2FramesAfterTrailers,
    Http2RequestBodyAlreadyComplete,
    Http2ResponseStreamNotClosed,
    MissingUpgradeTunnel,
    UnexpectedTunnelMode,
    PluginsAlreadyExecuted,
    RequestCompletedWithoutResponse,
    AdmissionResponseNotDelivered,
}

impl RequestFailure {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmptyMethodOrPath => "empty method or path",
            Self::NoRoute => "no route",
            Self::MissingUpstreamDisplayName => "upstream display name not found",
            Self::MissingRouteRuntime => "upstream runtime not found",
            Self::MissingUpstreamPool => "upstream pool not found",
            Self::MissingUpstreamSelector => "upstream selector not found",
            Self::UpstreamPoolLockPoisoned => "upstream pool lock poisoned",
            Self::NoHealthyServers => "no healthy servers",
            Self::InvalidBackendIndex => "invalid backend index",
            Self::UnknownBackendTransportIdentity => "unknown backend transport identity",
            Self::MissingDeferredForwardSnapshot => "missing deferred forward snapshot",
            Self::MissingUpstreamRoute => "missing upstream route",
            Self::EarlyDataRejected => "request blocked by early-data policy",
            Self::RequestBodyTooLarge => "request body too large",
            Self::RequestTrailersRequireHttp2 => "request trailers require an HTTP/2 upstream",
            Self::UpstreamRuntimeUnavailable => "upstream runtime unavailable",
            Self::RuntimeUnavailable => "runtime unavailable",
            Self::UpstreamTunnelTaskStopped => "upstream tunnel task stopped",
            Self::UpstreamPoolDraining => "Pingora upstream pool is draining",
            Self::Http1RequestAlreadyWritten => "Pingora HTTP/1 request has already been written",
            Self::RequestBodyExceedsDeclaredFraming => "request body exceeds its declared framing",
            Self::Http1RequestTrailersUnsupported => {
                "Pingora 0.9 cannot forward HTTP/1 request trailers"
            }
            Self::Http2RequestAlreadyWritten => "Pingora HTTP/2 request has already been written",
            Self::Http2FramesAfterTrailers => "request body contains frames after HTTP/2 trailers",
            Self::Http2RequestBodyAlreadyComplete => {
                "Pingora HTTP/2 request body is already complete"
            }
            Self::Http2ResponseStreamNotClosed => {
                "Pingora HTTP/2 response ended without closing its stream"
            }
            Self::MissingUpgradeTunnel => "HTTP/1 upgrade response did not provide a tunnel",
            Self::UnexpectedTunnelMode => "WebSocket exchange returned a CONNECT tunnel lease",
            Self::PluginsAlreadyExecuted => "request plugins executed more than once",
            Self::RequestCompletedWithoutResponse => "request completed without a response",
            Self::AdmissionResponseNotDelivered => {
                "admission response did not reach the downstream"
            }
        }
    }
}

impl fmt::Display for RequestFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for RequestFailure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamProxyErrorKind {
    Transport,
    Timeout,
    Protocol,
    Tls,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassifiedUpstreamProxyError {
    pub kind: UpstreamProxyErrorKind,
    pub detail: Cow<'static, str>,
    pub classification: UpstreamErrorClassification,
    pub health_failure: Option<UpstreamHealthFailureMapping>,
    pub retryability: UpstreamRetryability,
}

fn classify_tls_detail(detail: &str) -> UpstreamErrorClassification {
    let classification = crate::classify_upstream_error_detail(detail, true);
    if matches!(classification.category, UpstreamErrorCategory::Transport) {
        UpstreamErrorClassification::tls(UpstreamTlsReason::Handshake)
    } else {
        classification
    }
}

fn passive_health_failure_for_classification(
    classification: UpstreamErrorClassification,
) -> Option<UpstreamHealthFailureMapping> {
    match classification.category {
        UpstreamErrorCategory::Tls | UpstreamErrorCategory::Protocol => None,
        UpstreamErrorCategory::Timeout | UpstreamErrorCategory::Transport => {
            Some(classification.health_failure_mapping())
        }
    }
}

pub fn classify_upstream_proxy_error(err: &ProxyError) -> Option<ClassifiedUpstreamProxyError> {
    match err {
        ProxyError::Transport(detail) => {
            let classification = UpstreamErrorClassification::transport();
            Some(ClassifiedUpstreamProxyError {
                kind: UpstreamProxyErrorKind::Transport,
                detail: Cow::Owned(detail.clone()),
                classification,
                health_failure: passive_health_failure_for_classification(classification),
                retryability: classify_retryability(err),
            })
        }
        ProxyError::RequestTransport(failure) => {
            let classification = UpstreamErrorClassification::transport();
            Some(ClassifiedUpstreamProxyError {
                kind: UpstreamProxyErrorKind::Transport,
                detail: Cow::Borrowed(failure.as_str()),
                classification,
                health_failure: passive_health_failure_for_classification(classification),
                retryability: classify_retryability(err),
            })
        }
        ProxyError::Timeout => {
            let classification = UpstreamErrorClassification::timeout();
            Some(ClassifiedUpstreamProxyError {
                kind: UpstreamProxyErrorKind::Timeout,
                detail: Cow::Borrowed("backend timeout"),
                classification,
                health_failure: passive_health_failure_for_classification(classification),
                retryability: classify_retryability(err),
            })
        }
        ProxyError::Protocol(detail) => Some(ClassifiedUpstreamProxyError {
            kind: UpstreamProxyErrorKind::Protocol,
            detail: Cow::Owned(detail.clone()),
            classification: UpstreamErrorClassification::protocol(),
            health_failure: None,
            retryability: classify_retryability(err),
        }),
        ProxyError::RequestProtocol(failure) => Some(ClassifiedUpstreamProxyError {
            kind: UpstreamProxyErrorKind::Protocol,
            detail: Cow::Borrowed(failure.as_str()),
            classification: UpstreamErrorClassification::protocol(),
            health_failure: None,
            retryability: classify_retryability(err),
        }),
        ProxyError::Tls(detail) => Some(ClassifiedUpstreamProxyError {
            kind: UpstreamProxyErrorKind::Tls,
            detail: Cow::Owned(detail.clone()),
            classification: classify_tls_detail(detail),
            health_failure: None,
            retryability: classify_retryability(err),
        }),
        ProxyError::Bridge(_)
        | ProxyError::Pool(PoolError::UnknownBackend(_))
        | ProxyError::Pool(PoolError::BackendOverloaded(_))
        | ProxyError::Pool(PoolError::CircuitOpen(_))
        | ProxyError::Pool(PoolError::InflightLimiterClosed) => None,
    }
}

#[cfg(test)]
mod tests {
    use impulse_contracts::{HealthFailureReason, UpstreamRetryReason, UpstreamTerminalErrorKind};

    use super::{ProxyError, UpstreamProxyErrorKind, classify_upstream_proxy_error};
    use crate::{
        BridgeError, PoolError, UpstreamErrorCategory, UpstreamErrorClassification,
        UpstreamHealthFailureMapping, UpstreamRetryability, UpstreamTlsReason,
    };

    #[test]
    fn display_covers_proxy_error_variants() {
        assert_eq!(
            ProxyError::Bridge(BridgeError::InvalidMethod).to_string(),
            "bridge error: invalid HTTP method"
        );
        assert_eq!(
            ProxyError::Pool(PoolError::UnknownBackend("api-a".to_string())).to_string(),
            "pool error: unknown backend: api-a"
        );
        assert_eq!(
            ProxyError::Transport("connection reset by peer".to_string()).to_string(),
            "transport error: connection reset by peer"
        );
        assert_eq!(ProxyError::Timeout.to_string(), "backend timeout");
        assert_eq!(
            ProxyError::Protocol("bad response frame".to_string()).to_string(),
            "protocol error: bad response frame"
        );
        assert_eq!(
            ProxyError::Tls("unknown issuer".to_string()).to_string(),
            "TLS error: unknown issuer"
        );
    }

    #[test]
    fn bridge_and_non_send_pool_errors_have_no_upstream_category() {
        assert_eq!(
            classify_upstream_proxy_error(&ProxyError::Bridge(BridgeError::InvalidHeader)),
            None
        );
        assert_eq!(
            classify_upstream_proxy_error(&ProxyError::Pool(PoolError::UnknownBackend(
                "api-a".to_string(),
            ))),
            None
        );
        assert_eq!(
            classify_upstream_proxy_error(&ProxyError::Pool(PoolError::BackendOverloaded(
                "api-b".to_string(),
            ))),
            None
        );
        assert_eq!(
            classify_upstream_proxy_error(&ProxyError::Pool(PoolError::CircuitOpen(
                "api-c".to_string(),
            ))),
            None
        );
        assert_eq!(
            classify_upstream_proxy_error(&ProxyError::Pool(PoolError::InflightLimiterClosed)),
            None
        );
    }

    #[test]
    fn transport_timeout_protocol_and_tls_map_to_expected_categories() {
        let transport = classify_upstream_proxy_error(&ProxyError::Transport(
            "connection reset by peer".to_string(),
        ))
        .expect("transport should classify");
        assert_eq!(transport.kind, UpstreamProxyErrorKind::Transport);
        assert_eq!(transport.detail, "connection reset by peer");
        assert_eq!(
            transport.classification,
            UpstreamErrorClassification::transport()
        );
        assert_eq!(
            transport.health_failure,
            Some(UpstreamHealthFailureMapping {
                failure_reason: HealthFailureReason::Transport,
                metrics_reason: "transport",
            })
        );
        assert_eq!(
            transport.retryability,
            UpstreamRetryability::Retryable(UpstreamRetryReason::Transport)
        );

        let timeout =
            classify_upstream_proxy_error(&ProxyError::Timeout).expect("timeout should classify");
        assert_eq!(timeout.kind, UpstreamProxyErrorKind::Timeout);
        assert_eq!(timeout.detail, "backend timeout");
        assert_eq!(
            timeout.classification,
            UpstreamErrorClassification::timeout()
        );
        assert_eq!(
            timeout.health_failure,
            Some(UpstreamHealthFailureMapping {
                failure_reason: HealthFailureReason::Timeout,
                metrics_reason: "timeout",
            })
        );
        assert_eq!(
            timeout.retryability,
            UpstreamRetryability::Retryable(UpstreamRetryReason::Timeout)
        );

        let protocol =
            classify_upstream_proxy_error(&ProxyError::Protocol("bad response frame".to_string()))
                .expect("protocol should classify");
        assert_eq!(protocol.kind, UpstreamProxyErrorKind::Protocol);
        assert_eq!(protocol.detail, "bad response frame");
        assert_eq!(
            protocol.classification.category,
            UpstreamErrorCategory::Protocol
        );
        assert_eq!(protocol.health_failure, None);
        assert_eq!(
            protocol.retryability,
            UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Protocol)
        );

        let tls = classify_upstream_proxy_error(&ProxyError::Tls("unknown issuer".to_string()))
            .expect("tls should classify");
        assert_eq!(tls.kind, UpstreamProxyErrorKind::Tls);
        assert_eq!(tls.detail, "unknown issuer");
        assert_eq!(
            tls.classification,
            UpstreamErrorClassification::tls(UpstreamTlsReason::UnknownIssuer)
        );
        assert_eq!(tls.health_failure, None);
        assert_eq!(
            tls.retryability,
            UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Tls)
        );

        let generic_tls = classify_upstream_proxy_error(&ProxyError::Tls("boom".to_string()))
            .expect("generic tls should classify");
        assert_eq!(
            generic_tls.classification,
            UpstreamErrorClassification::tls(UpstreamTlsReason::Handshake)
        );
    }

    #[test]
    fn bridge_and_protocol_boundaries_remain_explicit_for_proxy_classification() {
        assert_eq!(
            classify_upstream_proxy_error(&ProxyError::Bridge(BridgeError::InvalidHeader)),
            None
        );

        let protocol =
            classify_upstream_proxy_error(&ProxyError::Protocol("malformed headers".to_string()))
                .expect("protocol should classify");
        assert_eq!(protocol.kind, UpstreamProxyErrorKind::Protocol);
        assert_eq!(
            protocol.classification,
            UpstreamErrorClassification::protocol()
        );
        assert_eq!(protocol.health_failure, None);
        assert_eq!(
            protocol.retryability,
            UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Protocol)
        );
    }
}
