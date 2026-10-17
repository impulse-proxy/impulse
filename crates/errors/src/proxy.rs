//! Canonical proxy and upstream error classification surface.

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

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("backend timeout")]
    Timeout,

    #[error("TLS error: {0}")]
    Tls(String),
}

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
    pub detail: String,
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
                detail: detail.clone(),
                classification,
                health_failure: passive_health_failure_for_classification(classification),
                retryability: classify_retryability(err),
            })
        }
        ProxyError::Timeout => {
            let classification = UpstreamErrorClassification::timeout();
            Some(ClassifiedUpstreamProxyError {
                kind: UpstreamProxyErrorKind::Timeout,
                detail: err.to_string(),
                classification,
                health_failure: passive_health_failure_for_classification(classification),
                retryability: classify_retryability(err),
            })
        }
        ProxyError::Protocol(detail) => Some(ClassifiedUpstreamProxyError {
            kind: UpstreamProxyErrorKind::Protocol,
            detail: detail.clone(),
            classification: UpstreamErrorClassification::protocol(),
            health_failure: None,
            retryability: classify_retryability(err),
        }),
        ProxyError::Tls(detail) => Some(ClassifiedUpstreamProxyError {
            kind: UpstreamProxyErrorKind::Tls,
            detail: detail.clone(),
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
    use impulse_lb::health::HealthFailureReason;

    use super::{ProxyError, UpstreamProxyErrorKind, classify_upstream_proxy_error};
    use crate::{
        BridgeError, PoolError, UpstreamErrorCategory, UpstreamErrorClassification,
        UpstreamHealthFailureMapping, UpstreamRetryReason, UpstreamRetryability,
        UpstreamTerminalErrorKind, UpstreamTlsReason,
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
