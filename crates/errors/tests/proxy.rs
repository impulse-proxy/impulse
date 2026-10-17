use impulse_errors::{
    PoolError, ProxyError, RetryPolicyDecision, RetryPolicyDenialReason, RetryPolicyFacts,
    UpstreamErrorClassification, UpstreamHealthFailureMapping, UpstreamProxyErrorKind,
    UpstreamRetryReason, UpstreamRetryability, UpstreamTerminalErrorKind, UpstreamTlsReason,
    classify_retryability, classify_upstream_proxy_error, evaluate_retry_policy,
};
use impulse_lb::alternate_backend::AlternateBackendFailureReason;

#[test]
fn pool_and_transport_errors_have_distinct_display_text() {
    let pool = ProxyError::Pool(PoolError::UnknownBackend("api-a".to_string()));
    let transport = ProxyError::Transport("api-a".to_string());

    assert_eq!(pool.to_string(), "pool error: unknown backend: api-a");
    assert_eq!(transport.to_string(), "transport error: api-a");
}

#[test]
fn overloaded_pool_error_keeps_pool_specific_prefix() {
    let err = ProxyError::Pool(PoolError::BackendOverloaded("api-b".to_string()));

    assert_eq!(err.to_string(), "pool error: backend overloaded: api-b");
}

#[test]
fn retryability_classification_distinguishes_retryable_and_terminal_errors() {
    assert_eq!(
        classify_retryability(&ProxyError::Timeout),
        UpstreamRetryability::Retryable(UpstreamRetryReason::Timeout)
    );
    assert_eq!(
        classify_retryability(&ProxyError::Transport("reset".to_string())),
        UpstreamRetryability::Retryable(UpstreamRetryReason::Transport)
    );
    assert_eq!(
        classify_retryability(&ProxyError::Pool(PoolError::UnknownBackend(
            "api-a".to_string()
        ))),
        UpstreamRetryability::Retryable(UpstreamRetryReason::Pool)
    );
    assert_eq!(
        classify_retryability(&ProxyError::Tls("bad cert".to_string())),
        UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Tls)
    );
    assert_eq!(
        classify_retryability(&ProxyError::Protocol("bad frame".to_string())),
        UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Protocol)
    );
}

#[test]
fn retry_policy_evaluation_preserves_existing_denial_behavior() {
    assert_eq!(
        evaluate_retry_policy(RetryPolicyFacts {
            retryability: UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Protocol),
            method_idempotent: true,
            request_body_replayable: true,
            attempt_count: 0,
            max_attempts: 1,
            budget_available: true,
            alternate_backend_available: true,
            alternate_backend_failure: None,
        }),
        RetryPolicyDecision::DoNotRetry {
            denial: Some(RetryPolicyDenialReason::TerminalError(
                UpstreamTerminalErrorKind::Protocol,
            )),
        }
    );
    assert_eq!(
        evaluate_retry_policy(RetryPolicyFacts {
            retryability: UpstreamRetryability::Retryable(UpstreamRetryReason::Transport),
            method_idempotent: true,
            request_body_replayable: false,
            attempt_count: 0,
            max_attempts: 1,
            budget_available: true,
            alternate_backend_available: true,
            alternate_backend_failure: None,
        }),
        RetryPolicyDecision::DoNotRetry {
            denial: Some(RetryPolicyDenialReason::RequestBodyNotReplayable),
        }
    );
    assert_eq!(
        evaluate_retry_policy(RetryPolicyFacts {
            retryability: UpstreamRetryability::Retryable(UpstreamRetryReason::Pool),
            method_idempotent: true,
            request_body_replayable: true,
            attempt_count: 0,
            max_attempts: 1,
            budget_available: false,
            alternate_backend_available: true,
            alternate_backend_failure: None,
        }),
        RetryPolicyDecision::DoNotRetry {
            denial: Some(RetryPolicyDenialReason::BudgetDenied),
        }
    );
    assert_eq!(
        evaluate_retry_policy(RetryPolicyFacts {
            retryability: UpstreamRetryability::Retryable(UpstreamRetryReason::Timeout),
            method_idempotent: true,
            request_body_replayable: true,
            attempt_count: 0,
            max_attempts: 1,
            budget_available: true,
            alternate_backend_available: true,
            alternate_backend_failure: None,
        }),
        RetryPolicyDecision::Retry {
            reason: UpstreamRetryReason::Timeout,
        }
    );

    assert_eq!(
        evaluate_retry_policy(RetryPolicyFacts {
            retryability: UpstreamRetryability::Retryable(UpstreamRetryReason::Timeout),
            method_idempotent: true,
            request_body_replayable: true,
            attempt_count: 0,
            max_attempts: 1,
            budget_available: true,
            alternate_backend_available: false,
            alternate_backend_failure: Some(AlternateBackendFailureReason::NoHealthyBackends),
        }),
        RetryPolicyDecision::DoNotRetry {
            denial: Some(RetryPolicyDenialReason::AlternateBackendUnavailable(
                AlternateBackendFailureReason::NoHealthyBackends,
            )),
        }
    );
}

#[test]
fn upstream_proxy_error_classification_preserves_tls_error_details() {
    let err = ProxyError::Tls("tls handshake failed: unknown issuer".to_string());
    let classified = classify_upstream_proxy_error(&err).expect("classified upstream error");

    assert_eq!(classified.kind, UpstreamProxyErrorKind::Tls);
    assert_eq!(
        classified.classification,
        UpstreamErrorClassification::tls(UpstreamTlsReason::UnknownIssuer)
    );
    assert!(classified.health_failure.is_none());
    assert_eq!(
        classified.retryability,
        UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Tls)
    );
}

#[test]
fn upstream_proxy_error_classification_marks_timeout_as_retryable_health_failure() {
    let classified =
        classify_upstream_proxy_error(&ProxyError::Timeout).expect("classified timeout");

    assert_eq!(classified.kind, UpstreamProxyErrorKind::Timeout);
    assert_eq!(
        classified.classification,
        UpstreamErrorClassification::timeout()
    );
    assert_eq!(
        classified.health_failure,
        Some(UpstreamHealthFailureMapping {
            failure_reason: impulse_lb::health::HealthFailureReason::Timeout,
            metrics_reason: "timeout",
        })
    );
    assert_eq!(
        classified.retryability,
        UpstreamRetryability::Retryable(UpstreamRetryReason::Timeout)
    );
}

#[test]
fn upstream_proxy_error_classification_covers_protocol_and_transport_cases() {
    let transport =
        classify_upstream_proxy_error(&ProxyError::Transport("connection reset".into()))
            .expect("classified transport");
    assert_eq!(transport.kind, UpstreamProxyErrorKind::Transport);
    assert_eq!(
        transport.classification,
        UpstreamErrorClassification::transport()
    );
    assert_eq!(
        transport.health_failure,
        Some(UpstreamHealthFailureMapping {
            failure_reason: impulse_lb::health::HealthFailureReason::Transport,
            metrics_reason: "transport",
        })
    );
    assert_eq!(
        transport.retryability,
        UpstreamRetryability::Retryable(UpstreamRetryReason::Transport)
    );

    let protocol = classify_upstream_proxy_error(&ProxyError::Protocol("bad frame".into()))
        .expect("classified protocol");
    assert_eq!(protocol.kind, UpstreamProxyErrorKind::Protocol);
    assert_eq!(
        protocol.classification,
        UpstreamErrorClassification::protocol()
    );
    assert!(protocol.health_failure.is_none());
    assert_eq!(
        protocol.retryability,
        UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Protocol)
    );
}
