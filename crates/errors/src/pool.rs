use thiserror::Error;

#[derive(Debug, Error)]
pub enum PoolError {
    #[error("unknown backend: {0}")]
    UnknownBackend(String),

    #[error("backend overloaded: {0}")]
    BackendOverloaded(String),

    #[error("backend circuit open: {0}")]
    CircuitOpen(String),

    #[error("backend inflight limiter closed")]
    InflightLimiterClosed,
}

#[cfg(test)]
mod tests {
    use super::PoolError;
    use crate::{ProxyError, UpstreamRetryReason, UpstreamRetryability, classify_retryability};

    #[test]
    fn display_covers_named_pool_variants() {
        assert_eq!(
            PoolError::UnknownBackend("api-a".to_string()).to_string(),
            "unknown backend: api-a"
        );
        assert_eq!(
            PoolError::BackendOverloaded("api-b".to_string()).to_string(),
            "backend overloaded: api-b"
        );
        assert_eq!(
            PoolError::CircuitOpen("api-c".to_string()).to_string(),
            "backend circuit open: api-c"
        );
        assert_eq!(
            PoolError::InflightLimiterClosed.to_string(),
            "backend inflight limiter closed"
        );
    }

    #[test]
    fn retryability_classifies_pool_errors_as_pool_retryable() {
        assert_eq!(
            classify_retryability(&ProxyError::Pool(PoolError::UnknownBackend(
                "api-a".to_string(),
            ))),
            UpstreamRetryability::Retryable(UpstreamRetryReason::Pool)
        );
        assert_eq!(
            classify_retryability(&ProxyError::Pool(PoolError::BackendOverloaded(
                "api-b".to_string(),
            ))),
            UpstreamRetryability::Retryable(UpstreamRetryReason::Pool)
        );
        assert_eq!(
            classify_retryability(&ProxyError::Pool(PoolError::CircuitOpen(
                "api-c".to_string()
            ))),
            UpstreamRetryability::Retryable(UpstreamRetryReason::Pool)
        );
        assert_eq!(
            classify_retryability(&ProxyError::Pool(PoolError::InflightLimiterClosed)),
            UpstreamRetryability::Retryable(UpstreamRetryReason::Pool)
        );
    }
}
