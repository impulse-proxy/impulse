use impulse_lb::alternate_backend::AlternateBackendFailureReason;

use crate::ProxyError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamRetryReason {
    Timeout,
    Transport,
    Pool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamTerminalErrorKind {
    Tls,
    Protocol,
    Bridge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamRetryability {
    Retryable(UpstreamRetryReason),
    Terminal(UpstreamTerminalErrorKind),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryPolicyDenialReason {
    TerminalError(UpstreamTerminalErrorKind),
    MethodNotIdempotent,
    RequestBodyNotReplayable,
    AttemptLimitReached,
    BudgetDenied,
    AlternateBackendUnavailable(AlternateBackendFailureReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicyFacts {
    pub retryability: UpstreamRetryability,
    pub method_idempotent: bool,
    pub request_body_replayable: bool,
    pub attempt_count: u8,
    pub max_attempts: u8,
    pub budget_available: bool,
    pub alternate_backend_available: bool,
    pub alternate_backend_failure: Option<AlternateBackendFailureReason>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryPolicyDecision {
    Retry {
        reason: UpstreamRetryReason,
    },
    DoNotRetry {
        denial: Option<RetryPolicyDenialReason>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryAttemptTelemetryReason {
    Timeout,
    Transport,
    Pool,
}

impl From<UpstreamRetryReason> for RetryAttemptTelemetryReason {
    fn from(value: UpstreamRetryReason) -> Self {
        match value {
            UpstreamRetryReason::Timeout => Self::Timeout,
            UpstreamRetryReason::Transport => Self::Transport,
            UpstreamRetryReason::Pool => Self::Pool,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HedgePolicyFacts {
    pub hedging_configured: bool,
    pub method_allowed: bool,
    pub request_body_replayable: bool,
    pub tunnel_request: bool,
    pub alternate_backend_available: bool,
    pub alternate_backend_failure: Option<AlternateBackendFailureReason>,
    pub budget_available: bool,
    pub primary_state: HedgePrimaryState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HedgePrimaryState {
    InFlightBeforeDelay,
    InFlightAfterDelay,
    Completed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HedgePolicyDenialReason {
    HedgingDisabled,
    PrimaryRequestCompleted,
    RequestBodyNotReplayable,
    TunnelRequest,
    MethodNotAllowed,
    AlternateBackendUnavailable(AlternateBackendFailureReason),
    BudgetDenied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HedgePolicyDecision {
    WaitForPrimary,
    Hedge { reason: HedgeTriggerTelemetryReason },
    DoNotHedge { denial: HedgePolicyDenialReason },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HedgeTriggerTelemetryReason {
    DelayElapsed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HedgeOutcomeTelemetryReason {
    PrimaryWonAfterTrigger,
    HedgeWon,
}

pub fn is_idempotent_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "PUT" | "DELETE" | "OPTIONS" | "TRACE"
    )
}

pub fn classify_retryability(err: &ProxyError) -> UpstreamRetryability {
    match err {
        ProxyError::Transport(_) => UpstreamRetryability::Retryable(UpstreamRetryReason::Transport),
        ProxyError::Timeout => UpstreamRetryability::Retryable(UpstreamRetryReason::Timeout),
        ProxyError::Pool(_) => UpstreamRetryability::Retryable(UpstreamRetryReason::Pool),
        ProxyError::Tls(_) => UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Tls),
        ProxyError::Protocol(_) => {
            UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Protocol)
        }
        ProxyError::Bridge(_) => UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Bridge),
    }
}

pub fn evaluate_retry_policy(input: RetryPolicyFacts) -> RetryPolicyDecision {
    match input.retryability {
        UpstreamRetryability::Terminal(kind) => RetryPolicyDecision::DoNotRetry {
            denial: Some(RetryPolicyDenialReason::TerminalError(kind)),
        },
        UpstreamRetryability::Retryable(reason) => {
            if !input.method_idempotent {
                RetryPolicyDecision::DoNotRetry {
                    denial: Some(RetryPolicyDenialReason::MethodNotIdempotent),
                }
            } else if !input.request_body_replayable {
                RetryPolicyDecision::DoNotRetry {
                    denial: Some(RetryPolicyDenialReason::RequestBodyNotReplayable),
                }
            } else if input.attempt_count >= input.max_attempts {
                RetryPolicyDecision::DoNotRetry {
                    denial: Some(RetryPolicyDenialReason::AttemptLimitReached),
                }
            } else if !input.budget_available {
                RetryPolicyDecision::DoNotRetry {
                    denial: Some(RetryPolicyDenialReason::BudgetDenied),
                }
            } else if !input.alternate_backend_available {
                RetryPolicyDecision::DoNotRetry {
                    denial: Some(RetryPolicyDenialReason::AlternateBackendUnavailable(
                        input
                            .alternate_backend_failure
                            .unwrap_or(AlternateBackendFailureReason::OnlyExcludedBackendsHealthy),
                    )),
                }
            } else {
                RetryPolicyDecision::Retry { reason }
            }
        }
    }
}

pub fn evaluate_hedge_policy(input: HedgePolicyFacts) -> HedgePolicyDecision {
    if !input.hedging_configured {
        return HedgePolicyDecision::DoNotHedge {
            denial: HedgePolicyDenialReason::HedgingDisabled,
        };
    }

    if !input.method_allowed {
        return HedgePolicyDecision::DoNotHedge {
            denial: HedgePolicyDenialReason::MethodNotAllowed,
        };
    }

    if !input.request_body_replayable {
        return HedgePolicyDecision::DoNotHedge {
            denial: HedgePolicyDenialReason::RequestBodyNotReplayable,
        };
    }

    if input.tunnel_request {
        return HedgePolicyDecision::DoNotHedge {
            denial: HedgePolicyDenialReason::TunnelRequest,
        };
    }

    if !input.alternate_backend_available {
        return HedgePolicyDecision::DoNotHedge {
            denial: HedgePolicyDenialReason::AlternateBackendUnavailable(
                input
                    .alternate_backend_failure
                    .unwrap_or(AlternateBackendFailureReason::OnlyExcludedBackendsHealthy),
            ),
        };
    }

    match input.primary_state {
        HedgePrimaryState::Completed => HedgePolicyDecision::DoNotHedge {
            denial: HedgePolicyDenialReason::PrimaryRequestCompleted,
        },
        HedgePrimaryState::InFlightBeforeDelay => HedgePolicyDecision::WaitForPrimary,
        HedgePrimaryState::InFlightAfterDelay => {
            if !input.budget_available {
                HedgePolicyDecision::DoNotHedge {
                    denial: HedgePolicyDenialReason::BudgetDenied,
                }
            } else {
                HedgePolicyDecision::Hedge {
                    reason: HedgeTriggerTelemetryReason::DelayElapsed,
                }
            }
        }
    }
}

pub fn is_retryable(err: &ProxyError) -> bool {
    matches!(
        classify_retryability(err),
        UpstreamRetryability::Retryable(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BridgeError, PoolError, ProxyError};

    fn retry_facts() -> RetryPolicyFacts {
        RetryPolicyFacts {
            retryability: UpstreamRetryability::Retryable(UpstreamRetryReason::Timeout),
            method_idempotent: true,
            request_body_replayable: true,
            attempt_count: 0,
            max_attempts: 1,
            budget_available: true,
            alternate_backend_available: true,
            alternate_backend_failure: None,
        }
    }

    #[test]
    fn idempotent_method_helper_matches_expected_methods() {
        assert!(is_idempotent_method("GET"));
        assert!(is_idempotent_method("delete"));
        assert!(!is_idempotent_method("POST"));
        assert!(!is_idempotent_method("PATCH"));
    }

    #[test]
    fn terminal_errors_return_explicit_denial() {
        let mut facts = retry_facts();
        facts.retryability = UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Tls);

        assert_eq!(
            evaluate_retry_policy(facts),
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::TerminalError(
                    UpstreamTerminalErrorKind::Tls
                )),
            }
        );
    }

    #[test]
    fn method_idempotency_blocks_retry() {
        let mut facts = retry_facts();
        facts.method_idempotent = false;

        assert_eq!(
            evaluate_retry_policy(facts),
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::MethodNotIdempotent),
            }
        );
    }

    #[test]
    fn request_body_replayability_blocks_retry() {
        let mut facts = retry_facts();
        facts.request_body_replayable = false;

        assert_eq!(
            evaluate_retry_policy(facts),
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::RequestBodyNotReplayable),
            }
        );
    }

    #[test]
    fn attempt_limit_blocks_retry() {
        let mut facts = retry_facts();
        facts.attempt_count = 1;

        assert_eq!(
            evaluate_retry_policy(facts),
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::AttemptLimitReached),
            }
        );
    }

    #[test]
    fn unhealthy_alternate_backend_blocks_retry() {
        let mut facts = retry_facts();
        facts.alternate_backend_available = false;
        facts.alternate_backend_failure = Some(AlternateBackendFailureReason::NoHealthyBackends);

        assert_eq!(
            evaluate_retry_policy(facts),
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::AlternateBackendUnavailable(
                    AlternateBackendFailureReason::NoHealthyBackends,
                )),
            }
        );
    }

    #[test]
    fn missing_alternate_backend_reason_defaults_to_only_excluded_backends_healthy() {
        let mut facts = retry_facts();
        facts.alternate_backend_available = false;
        facts.alternate_backend_failure = None;

        assert_eq!(
            evaluate_retry_policy(facts),
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::AlternateBackendUnavailable(
                    AlternateBackendFailureReason::OnlyExcludedBackendsHealthy,
                )),
            }
        );
    }

    #[test]
    fn budget_denied_blocks_retry() {
        let mut facts = retry_facts();
        facts.budget_available = false;

        assert_eq!(
            evaluate_retry_policy(facts),
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::BudgetDenied),
            }
        );
    }

    #[test]
    fn retry_denial_precedence_stays_stable_before_budget_or_alternate_checks() {
        let mut facts = retry_facts();
        facts.method_idempotent = false;
        facts.request_body_replayable = false;
        facts.budget_available = false;
        facts.alternate_backend_available = false;
        facts.alternate_backend_failure = Some(AlternateBackendFailureReason::NoHealthyBackends);

        assert_eq!(
            evaluate_retry_policy(facts),
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::MethodNotIdempotent),
            }
        );

        let mut replayability_after_method = retry_facts();
        replayability_after_method.request_body_replayable = false;
        replayability_after_method.budget_available = false;
        replayability_after_method.alternate_backend_available = false;
        replayability_after_method.alternate_backend_failure =
            Some(AlternateBackendFailureReason::NoHealthyBackends);

        assert_eq!(
            evaluate_retry_policy(replayability_after_method),
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::RequestBodyNotReplayable),
            }
        );
    }

    #[test]
    fn retry_denial_reasons_remain_distinct_across_attempt_budget_and_alternate_gates() {
        let mut attempt_limited = retry_facts();
        attempt_limited.attempt_count = attempt_limited.max_attempts;
        assert_eq!(
            evaluate_retry_policy(attempt_limited),
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::AttemptLimitReached),
            }
        );

        let mut budget_denied = retry_facts();
        budget_denied.budget_available = false;
        assert_eq!(
            evaluate_retry_policy(budget_denied),
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::BudgetDenied),
            }
        );

        let mut no_alternate = retry_facts();
        no_alternate.alternate_backend_available = false;
        no_alternate.alternate_backend_failure =
            Some(AlternateBackendFailureReason::NoHealthyBackends);
        assert_eq!(
            evaluate_retry_policy(no_alternate),
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::AlternateBackendUnavailable(
                    AlternateBackendFailureReason::NoHealthyBackends,
                )),
            }
        );
    }

    #[test]
    fn retryable_transport_allows_retry() {
        let mut facts = retry_facts();
        facts.retryability = UpstreamRetryability::Retryable(UpstreamRetryReason::Transport);

        assert_eq!(
            evaluate_retry_policy(facts),
            RetryPolicyDecision::Retry {
                reason: UpstreamRetryReason::Transport,
            }
        );
    }

    #[test]
    fn retryable_pool_allows_retry() {
        let mut facts = retry_facts();
        facts.retryability = UpstreamRetryability::Retryable(UpstreamRetryReason::Pool);

        assert_eq!(
            evaluate_retry_policy(facts),
            RetryPolicyDecision::Retry {
                reason: UpstreamRetryReason::Pool,
            }
        );
    }

    #[test]
    fn retry_attempt_telemetry_reason_matches_upstream_retry_reason() {
        assert_eq!(
            RetryAttemptTelemetryReason::from(UpstreamRetryReason::Timeout),
            RetryAttemptTelemetryReason::Timeout
        );
        assert_eq!(
            RetryAttemptTelemetryReason::from(UpstreamRetryReason::Transport),
            RetryAttemptTelemetryReason::Transport
        );
        assert_eq!(
            RetryAttemptTelemetryReason::from(UpstreamRetryReason::Pool),
            RetryAttemptTelemetryReason::Pool
        );
    }

    #[test]
    fn retry_attempt_telemetry_reasons_remain_stable_for_all_retryable_classes() {
        let cases = [
            (
                classify_retryability(&ProxyError::Timeout),
                Some(RetryAttemptTelemetryReason::Timeout),
            ),
            (
                classify_retryability(&ProxyError::Transport("connection reset".into())),
                Some(RetryAttemptTelemetryReason::Transport),
            ),
            (
                classify_retryability(&ProxyError::Pool(PoolError::UnknownBackend(
                    "missing".to_string(),
                ))),
                Some(RetryAttemptTelemetryReason::Pool),
            ),
            (
                classify_retryability(&ProxyError::Protocol("bad frame".into())),
                None,
            ),
        ];

        for (retryability, expected) in cases {
            let mapped = match retryability {
                UpstreamRetryability::Retryable(reason) => {
                    Some(RetryAttemptTelemetryReason::from(reason))
                }
                UpstreamRetryability::Terminal(_) => None,
            };
            assert_eq!(mapped, expected);
        }
    }

    #[test]
    fn retryable_timeout_allows_retry() {
        assert_eq!(
            evaluate_retry_policy(retry_facts()),
            RetryPolicyDecision::Retry {
                reason: UpstreamRetryReason::Timeout,
            }
        );
    }

    #[test]
    fn failure_classes_permit_or_deny_retry_according_to_policy() {
        assert_eq!(
            evaluate_retry_policy(RetryPolicyFacts {
                retryability: classify_retryability(&ProxyError::Timeout),
                ..retry_facts()
            }),
            RetryPolicyDecision::Retry {
                reason: UpstreamRetryReason::Timeout,
            }
        );
        assert_eq!(
            evaluate_retry_policy(RetryPolicyFacts {
                retryability: classify_retryability(&ProxyError::Transport(
                    "connection reset".into()
                )),
                ..retry_facts()
            }),
            RetryPolicyDecision::Retry {
                reason: UpstreamRetryReason::Transport,
            }
        );
        assert_eq!(
            evaluate_retry_policy(RetryPolicyFacts {
                retryability: classify_retryability(&ProxyError::Protocol(
                    "bad response frame".into()
                )),
                ..retry_facts()
            }),
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::TerminalError(
                    UpstreamTerminalErrorKind::Protocol
                )),
            }
        );
        assert_eq!(
            evaluate_retry_policy(RetryPolicyFacts {
                retryability: classify_retryability(&ProxyError::Bridge(
                    BridgeError::InvalidHeader
                )),
                ..retry_facts()
            }),
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::TerminalError(
                    UpstreamTerminalErrorKind::Bridge
                )),
            }
        );
    }

    #[test]
    fn classify_retryability_keeps_retryable_and_terminal_classes_explicit() {
        assert_eq!(
            classify_retryability(&ProxyError::Transport("connection reset".to_string())),
            UpstreamRetryability::Retryable(UpstreamRetryReason::Transport)
        );
        assert_eq!(
            classify_retryability(&ProxyError::Timeout),
            UpstreamRetryability::Retryable(UpstreamRetryReason::Timeout)
        );
        assert_eq!(
            classify_retryability(&ProxyError::Pool(PoolError::UnknownBackend(
                "missing".to_string()
            ))),
            UpstreamRetryability::Retryable(UpstreamRetryReason::Pool)
        );
        assert_eq!(
            classify_retryability(&ProxyError::Protocol("bad response frame".to_string())),
            UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Protocol)
        );
        assert_eq!(
            classify_retryability(&ProxyError::Bridge(BridgeError::InvalidHeader)),
            UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Bridge)
        );
        assert_eq!(
            classify_retryability(&ProxyError::Tls("unknown issuer".to_string())),
            UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Tls)
        );
    }

    #[test]
    fn classify_retryability_keeps_pool_paths_retryable() {
        assert_eq!(
            classify_retryability(&ProxyError::Pool(PoolError::InflightLimiterClosed)),
            UpstreamRetryability::Retryable(UpstreamRetryReason::Pool)
        );
        assert_eq!(
            classify_retryability(&ProxyError::Pool(PoolError::BackendOverloaded(
                "busy".to_string()
            ))),
            UpstreamRetryability::Retryable(UpstreamRetryReason::Pool)
        );

        assert!(is_retryable(&ProxyError::Pool(PoolError::UnknownBackend(
            "missing".to_string()
        ))));
    }

    #[test]
    fn test_is_retryable_bridge_error_returns_false() {
        assert!(!is_retryable(&ProxyError::Bridge(
            BridgeError::InvalidMethod
        )));
    }

    #[test]
    fn test_is_retryable_protocol_error_returns_false() {
        assert!(!is_retryable(&ProxyError::Protocol(
            "protocol failure".into()
        )));
    }

    #[test]
    fn test_is_retryable_tls_error_returns_false() {
        assert!(!is_retryable(&ProxyError::Tls("tls failure".into())));
    }

    fn hedge_facts() -> HedgePolicyFacts {
        HedgePolicyFacts {
            hedging_configured: true,
            method_allowed: true,
            request_body_replayable: true,
            tunnel_request: false,
            alternate_backend_available: true,
            alternate_backend_failure: None,
            budget_available: true,
            primary_state: HedgePrimaryState::InFlightAfterDelay,
        }
    }

    #[test]
    fn hedge_policy_waits_for_primary_before_delay() {
        let mut facts = hedge_facts();
        facts.primary_state = HedgePrimaryState::InFlightBeforeDelay;

        assert_eq!(
            evaluate_hedge_policy(facts),
            HedgePolicyDecision::WaitForPrimary
        );
    }

    #[test]
    fn hedge_policy_triggers_after_delay_when_eligible() {
        assert_eq!(
            evaluate_hedge_policy(hedge_facts()),
            HedgePolicyDecision::Hedge {
                reason: HedgeTriggerTelemetryReason::DelayElapsed,
            }
        );
    }

    #[test]
    fn hedge_policy_rejects_non_replayable_requests() {
        let mut facts = hedge_facts();
        facts.request_body_replayable = false;

        assert_eq!(
            evaluate_hedge_policy(facts),
            HedgePolicyDecision::DoNotHedge {
                denial: HedgePolicyDenialReason::RequestBodyNotReplayable,
            }
        );
    }

    #[test]
    fn hedge_policy_rejects_when_disabled() {
        let mut facts = hedge_facts();
        facts.hedging_configured = false;

        assert_eq!(
            evaluate_hedge_policy(facts),
            HedgePolicyDecision::DoNotHedge {
                denial: HedgePolicyDenialReason::HedgingDisabled,
            }
        );
    }

    #[test]
    fn hedge_policy_rejects_method_not_allowed() {
        let mut facts = hedge_facts();
        facts.method_allowed = false;

        assert_eq!(
            evaluate_hedge_policy(facts),
            HedgePolicyDecision::DoNotHedge {
                denial: HedgePolicyDenialReason::MethodNotAllowed,
            }
        );
    }

    #[test]
    fn hedge_policy_rejects_tunnel_requests() {
        let mut facts = hedge_facts();
        facts.tunnel_request = true;

        assert_eq!(
            evaluate_hedge_policy(facts),
            HedgePolicyDecision::DoNotHedge {
                denial: HedgePolicyDenialReason::TunnelRequest,
            }
        );
    }

    #[test]
    fn hedge_policy_rejects_when_no_alternate_backend_is_available() {
        let mut facts = hedge_facts();
        facts.alternate_backend_available = false;
        facts.alternate_backend_failure = Some(AlternateBackendFailureReason::NoHealthyBackends);

        assert_eq!(
            evaluate_hedge_policy(facts),
            HedgePolicyDecision::DoNotHedge {
                denial: HedgePolicyDenialReason::AlternateBackendUnavailable(
                    AlternateBackendFailureReason::NoHealthyBackends,
                ),
            }
        );
    }

    #[test]
    fn hedge_policy_defaults_alternate_backend_failure_reason_when_missing() {
        let mut facts = hedge_facts();
        facts.alternate_backend_available = false;
        facts.alternate_backend_failure = None;

        assert_eq!(
            evaluate_hedge_policy(facts),
            HedgePolicyDecision::DoNotHedge {
                denial: HedgePolicyDenialReason::AlternateBackendUnavailable(
                    AlternateBackendFailureReason::OnlyExcludedBackendsHealthy,
                ),
            }
        );
    }

    #[test]
    fn hedge_policy_rejects_completed_primary() {
        let mut facts = hedge_facts();
        facts.primary_state = HedgePrimaryState::Completed;

        assert_eq!(
            evaluate_hedge_policy(facts),
            HedgePolicyDecision::DoNotHedge {
                denial: HedgePolicyDenialReason::PrimaryRequestCompleted,
            }
        );
    }

    #[test]
    fn hedge_policy_rejects_when_budget_denied_after_delay() {
        let mut facts = hedge_facts();
        facts.budget_available = false;

        assert_eq!(
            evaluate_hedge_policy(facts),
            HedgePolicyDecision::DoNotHedge {
                denial: HedgePolicyDenialReason::BudgetDenied,
            }
        );
    }

    #[test]
    fn hedge_policy_suppression_precedence_prefers_primary_completion_over_budget_denial() {
        let facts = HedgePolicyFacts {
            budget_available: false,
            primary_state: HedgePrimaryState::Completed,
            ..hedge_facts()
        };

        assert_eq!(
            evaluate_hedge_policy(facts),
            HedgePolicyDecision::DoNotHedge {
                denial: HedgePolicyDenialReason::PrimaryRequestCompleted,
            }
        );
    }

    #[test]
    fn hedge_policy_trigger_and_outcome_telemetry_reasons_remain_stable() {
        let trigger = evaluate_hedge_policy(hedge_facts());
        assert_eq!(
            trigger,
            HedgePolicyDecision::Hedge {
                reason: HedgeTriggerTelemetryReason::DelayElapsed,
            }
        );
        assert_eq!(
            HedgeOutcomeTelemetryReason::PrimaryWonAfterTrigger,
            HedgeOutcomeTelemetryReason::PrimaryWonAfterTrigger
        );
        assert_eq!(
            HedgeOutcomeTelemetryReason::HedgeWon,
            HedgeOutcomeTelemetryReason::HedgeWon
        );
    }

    #[test]
    fn hedge_denial_reasons_remain_distinct_by_scenario() {
        assert_eq!(
            evaluate_hedge_policy(HedgePolicyFacts {
                hedging_configured: false,
                ..hedge_facts()
            }),
            HedgePolicyDecision::DoNotHedge {
                denial: HedgePolicyDenialReason::HedgingDisabled,
            }
        );
        assert_eq!(
            evaluate_hedge_policy(HedgePolicyFacts {
                method_allowed: false,
                ..hedge_facts()
            }),
            HedgePolicyDecision::DoNotHedge {
                denial: HedgePolicyDenialReason::MethodNotAllowed,
            }
        );
        assert_eq!(
            evaluate_hedge_policy(HedgePolicyFacts {
                request_body_replayable: false,
                ..hedge_facts()
            }),
            HedgePolicyDecision::DoNotHedge {
                denial: HedgePolicyDenialReason::RequestBodyNotReplayable,
            }
        );
        assert_eq!(
            evaluate_hedge_policy(HedgePolicyFacts {
                tunnel_request: true,
                ..hedge_facts()
            }),
            HedgePolicyDecision::DoNotHedge {
                denial: HedgePolicyDenialReason::TunnelRequest,
            }
        );
        assert_eq!(
            evaluate_hedge_policy(HedgePolicyFacts {
                alternate_backend_available: false,
                alternate_backend_failure: Some(AlternateBackendFailureReason::NoHealthyBackends),
                ..hedge_facts()
            }),
            HedgePolicyDecision::DoNotHedge {
                denial: HedgePolicyDenialReason::AlternateBackendUnavailable(
                    AlternateBackendFailureReason::NoHealthyBackends
                ),
            }
        );
    }
}
