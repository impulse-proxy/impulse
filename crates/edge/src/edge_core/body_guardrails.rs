//! Protocol-neutral request and response body guardrails.

use std::time::Duration;

pub(crate) const REQUEST_BODY_TOO_LARGE_BODY: &[u8] = b"request body too large\n";
pub(crate) const RESPONSE_BODY_TOO_LARGE_BODY: &[u8] = b"upstream response body too large\n";

/// Shared limits for request-body ingress handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RequestBodyGuardrailConfig {
    pub idle_timeout: Duration,
    pub total_timeout: Duration,
    pub max_body_bytes: usize,
    pub max_buffered_bytes: usize,
}

/// Point-in-time request-body state evaluated against ingress guardrails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RequestBodyGuardrailInput {
    pub elapsed: Duration,
    pub idle_for: Duration,
    pub bytes_received: usize,
    pub buffered_bytes: usize,
    pub next_chunk_bytes: usize,
    pub declared_content_length: Option<usize>,
    pub exempt_from_body_size_cap: bool,
}

/// Shared limits for response-body egress handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResponseBodyGuardrailConfig {
    pub idle_timeout: Duration,
    pub total_timeout: Duration,
    pub max_body_bytes: usize,
    pub unknown_length_prebuffer_bytes: usize,
    pub chunk_bytes: usize,
}

/// Point-in-time response-body state evaluated against egress guardrails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResponseBodyGuardrailInput {
    pub elapsed: Duration,
    pub idle_for: Duration,
    pub bytes_received: usize,
    pub prebuffered_bytes: usize,
    pub next_chunk_bytes: usize,
    pub declared_content_length: Option<usize>,
    pub headers_emitted: bool,
    pub progressive_emission_allowed: bool,
    pub body_forwarding_enabled: bool,
    pub exempt_from_body_size_cap: bool,
}

fn response_body_progress_observed(input: ResponseBodyGuardrailInput) -> bool {
    input.bytes_received > 0 || input.next_chunk_bytes > 0
}

/// Canonical timeout reasons shared by request and response body handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyTimeoutKind {
    Idle,
    Total,
}

/// Canonical body-size and buffering rejection reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyLimitKind {
    BodySize,
    BufferedBody,
    UnknownLengthPrebuffer,
}

/// Policy describing how response body bytes may be emitted downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProgressiveEmissionPolicy {
    StreamProgressively,
    PrebufferUntilValidated,
    SuppressBody,
}

/// Canonical decision for request-body ingress guardrails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestBodyGuardrailDecision {
    Continue,
    Timeout { kind: BodyTimeoutKind },
    Reject { kind: BodyLimitKind },
}

/// Canonical decision for response-body egress guardrails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResponseBodyGuardrailDecision {
    Continue { streaming: ResponseStreamingPolicy },
    Timeout { kind: BodyTimeoutKind },
    Reject { kind: BodyLimitKind },
}

/// Explicit chunk-emission sizing policy for progressive downstream writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResponseChunkEmissionPolicy {
    Passthrough,
    FixedSize { max_chunk_bytes: usize },
}

/// Canonical streaming policy for a response body once guardrails pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResponseStreamingPolicy {
    pub emission: ProgressiveEmissionPolicy,
    pub chunk_emission: ResponseChunkEmissionPolicy,
    pub wait_timeout: Duration,
}

/// Canonical request-body accounting state after an ingress step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RequestBodyIngressState {
    pub bytes_received: usize,
    pub buffered_bytes: usize,
}

/// Canonical response-body accounting state after an egress step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResponseBodyEgressState {
    pub bytes_received: usize,
    pub prebuffered_bytes: usize,
}

/// Shared result for a validated response-body streaming step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EvaluatedResponseBodyGuardrail {
    pub streaming: ResponseStreamingPolicy,
    pub next_state: ResponseBodyEgressState,
}

pub(crate) fn evaluate_request_body_timeouts(
    config: RequestBodyGuardrailConfig,
    input: RequestBodyGuardrailInput,
) -> RequestBodyGuardrailDecision {
    if input.elapsed >= config.total_timeout {
        return RequestBodyGuardrailDecision::Timeout {
            kind: BodyTimeoutKind::Total,
        };
    }

    if input.idle_for >= config.idle_timeout {
        return RequestBodyGuardrailDecision::Timeout {
            kind: BodyTimeoutKind::Idle,
        };
    }

    RequestBodyGuardrailDecision::Continue
}

fn evaluate_request_body_ingress(
    config: RequestBodyGuardrailConfig,
    input: RequestBodyGuardrailInput,
) -> RequestBodyGuardrailDecision {
    if input
        .declared_content_length
        .is_some_and(|length| !input.exempt_from_body_size_cap && length > config.max_body_bytes)
    {
        return RequestBodyGuardrailDecision::Reject {
            kind: BodyLimitKind::BodySize,
        };
    }

    let next_total = input.bytes_received.saturating_add(input.next_chunk_bytes);
    if !input.exempt_from_body_size_cap && next_total > config.max_body_bytes {
        return RequestBodyGuardrailDecision::Reject {
            kind: BodyLimitKind::BodySize,
        };
    }

    let next_buffered = input.buffered_bytes.saturating_add(input.next_chunk_bytes);
    if next_buffered > config.max_buffered_bytes {
        let kind = if input.declared_content_length.is_some() {
            BodyLimitKind::BufferedBody
        } else {
            BodyLimitKind::UnknownLengthPrebuffer
        };
        return RequestBodyGuardrailDecision::Reject { kind };
    }

    RequestBodyGuardrailDecision::Continue
}

pub(crate) fn checked_request_body_ingress(
    config: RequestBodyGuardrailConfig,
    input: RequestBodyGuardrailInput,
) -> Result<RequestBodyIngressState, RequestBodyGuardrailDecision> {
    let decision = evaluate_request_body_ingress(config, input);
    if !matches!(decision, RequestBodyGuardrailDecision::Continue) {
        return Err(decision);
    }

    Ok(RequestBodyIngressState {
        bytes_received: input.bytes_received.saturating_add(input.next_chunk_bytes),
        buffered_bytes: input.buffered_bytes.saturating_add(input.next_chunk_bytes),
    })
}

pub(crate) fn response_body_limit_reason(kind: BodyLimitKind) -> &'static str {
    match kind {
        BodyLimitKind::BodySize => "upstream response body too large",
        BodyLimitKind::BufferedBody => "upstream response buffered body limit exceeded",
        BodyLimitKind::UnknownLengthPrebuffer => "unknown-length response prebuffer limit exceeded",
    }
}

pub(crate) fn is_unknown_length_response_prebuffer_reason(reason: &str) -> bool {
    reason == response_body_limit_reason(BodyLimitKind::UnknownLengthPrebuffer)
}

fn response_wait_timeout(
    config: ResponseBodyGuardrailConfig,
    input: ResponseBodyGuardrailInput,
) -> Duration {
    let idle_remaining = config.idle_timeout.saturating_sub(input.idle_for);
    if response_body_progress_observed(input) {
        idle_remaining
    } else {
        idle_remaining.min(config.total_timeout.saturating_sub(input.elapsed))
    }
}

fn resolve_progressive_emission_policy(
    input: ResponseBodyGuardrailInput,
) -> ProgressiveEmissionPolicy {
    if !input.body_forwarding_enabled {
        return ProgressiveEmissionPolicy::SuppressBody;
    }

    if !input.progressive_emission_allowed
        || input.headers_emitted
        || input.declared_content_length.is_some()
        || input.exempt_from_body_size_cap
    {
        return ProgressiveEmissionPolicy::StreamProgressively;
    }

    ProgressiveEmissionPolicy::PrebufferUntilValidated
}

fn evaluate_response_body_guardrails(
    config: ResponseBodyGuardrailConfig,
    input: ResponseBodyGuardrailInput,
) -> ResponseBodyGuardrailDecision {
    if !response_body_progress_observed(input) && input.elapsed >= config.total_timeout {
        return ResponseBodyGuardrailDecision::Timeout {
            kind: BodyTimeoutKind::Total,
        };
    }

    if input.idle_for >= config.idle_timeout {
        return ResponseBodyGuardrailDecision::Timeout {
            kind: BodyTimeoutKind::Idle,
        };
    }

    let emission = resolve_progressive_emission_policy(input);
    if input.body_forwarding_enabled && !input.exempt_from_body_size_cap {
        if input
            .declared_content_length
            .is_some_and(|length| length > config.max_body_bytes)
        {
            return ResponseBodyGuardrailDecision::Reject {
                kind: BodyLimitKind::BodySize,
            };
        }

        let next_total = input.bytes_received.saturating_add(input.next_chunk_bytes);
        if next_total > config.max_body_bytes {
            return ResponseBodyGuardrailDecision::Reject {
                kind: BodyLimitKind::BodySize,
            };
        }

        if matches!(emission, ProgressiveEmissionPolicy::PrebufferUntilValidated)
            && input
                .prebuffered_bytes
                .saturating_add(input.next_chunk_bytes)
                > config.unknown_length_prebuffer_bytes
        {
            return ResponseBodyGuardrailDecision::Reject {
                kind: BodyLimitKind::UnknownLengthPrebuffer,
            };
        }
    }

    let chunk_emission = match emission {
        ProgressiveEmissionPolicy::SuppressBody => ResponseChunkEmissionPolicy::Passthrough,
        ProgressiveEmissionPolicy::StreamProgressively
        | ProgressiveEmissionPolicy::PrebufferUntilValidated => {
            ResponseChunkEmissionPolicy::FixedSize {
                max_chunk_bytes: config.chunk_bytes.max(1),
            }
        }
    };

    ResponseBodyGuardrailDecision::Continue {
        streaming: ResponseStreamingPolicy {
            emission,
            chunk_emission,
            wait_timeout: response_wait_timeout(config, input),
        },
    }
}

pub(crate) fn checked_response_body_guardrails(
    config: ResponseBodyGuardrailConfig,
    input: ResponseBodyGuardrailInput,
) -> Result<EvaluatedResponseBodyGuardrail, ResponseBodyGuardrailDecision> {
    let decision = evaluate_response_body_guardrails(config, input);
    let ResponseBodyGuardrailDecision::Continue { streaming } = decision else {
        return Err(decision);
    };

    let next_bytes_received = input.bytes_received.saturating_add(input.next_chunk_bytes);
    let next_prebuffered_bytes = match streaming.emission {
        ProgressiveEmissionPolicy::PrebufferUntilValidated => input
            .prebuffered_bytes
            .saturating_add(input.next_chunk_bytes),
        ProgressiveEmissionPolicy::StreamProgressively
        | ProgressiveEmissionPolicy::SuppressBody => 0,
    };

    Ok(EvaluatedResponseBodyGuardrail {
        streaming,
        next_state: ResponseBodyEgressState {
            bytes_received: next_bytes_received,
            prebuffered_bytes: next_prebuffered_bytes,
        },
    })
}

pub(crate) fn response_chunk_ranges(
    data_len: usize,
    policy: ResponseChunkEmissionPolicy,
) -> Vec<(usize, usize)> {
    match policy {
        ResponseChunkEmissionPolicy::Passthrough => vec![(0, data_len)],
        ResponseChunkEmissionPolicy::FixedSize { max_chunk_bytes } => {
            let chunk_bytes = max_chunk_bytes.max(1);
            (0..data_len)
                .step_by(chunk_bytes)
                .map(|start| (start, (start + chunk_bytes).min(data_len)))
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod request_body_ingress {
        use super::*;

        #[test]
        fn request_body_timeout_checks_continue_before_idle_or_total_limits() {
            let decision = evaluate_request_body_timeouts(
                RequestBodyGuardrailConfig {
                    idle_timeout: Duration::from_secs(5),
                    total_timeout: Duration::from_secs(30),
                    max_body_bytes: usize::MAX,
                    max_buffered_bytes: usize::MAX,
                },
                RequestBodyGuardrailInput {
                    elapsed: Duration::from_secs(4),
                    idle_for: Duration::from_secs(2),
                    bytes_received: 0,
                    buffered_bytes: 0,
                    next_chunk_bytes: 0,
                    declared_content_length: None,
                    exempt_from_body_size_cap: false,
                },
            );

            assert_eq!(decision, RequestBodyGuardrailDecision::Continue);
        }

        #[test]
        fn request_body_idle_timeout_rejects() {
            let decision = evaluate_request_body_timeouts(
                RequestBodyGuardrailConfig {
                    idle_timeout: Duration::from_secs(5),
                    total_timeout: Duration::from_secs(30),
                    max_body_bytes: usize::MAX,
                    max_buffered_bytes: usize::MAX,
                },
                RequestBodyGuardrailInput {
                    elapsed: Duration::from_secs(4),
                    idle_for: Duration::from_secs(5),
                    bytes_received: 0,
                    buffered_bytes: 0,
                    next_chunk_bytes: 0,
                    declared_content_length: None,
                    exempt_from_body_size_cap: false,
                },
            );

            assert_eq!(
                decision,
                RequestBodyGuardrailDecision::Timeout {
                    kind: BodyTimeoutKind::Idle,
                }
            );
        }

        #[test]
        fn request_body_total_timeout_rejects() {
            let decision = evaluate_request_body_timeouts(
                RequestBodyGuardrailConfig {
                    idle_timeout: Duration::from_secs(5),
                    total_timeout: Duration::from_secs(30),
                    max_body_bytes: usize::MAX,
                    max_buffered_bytes: usize::MAX,
                },
                RequestBodyGuardrailInput {
                    elapsed: Duration::from_secs(30),
                    idle_for: Duration::from_secs(1),
                    bytes_received: 0,
                    buffered_bytes: 0,
                    next_chunk_bytes: 0,
                    declared_content_length: None,
                    exempt_from_body_size_cap: false,
                },
            );

            assert_eq!(
                decision,
                RequestBodyGuardrailDecision::Timeout {
                    kind: BodyTimeoutKind::Total,
                }
            );
        }

        #[test]
        fn request_body_size_cap_respects_connect_exemption() {
            let config = RequestBodyGuardrailConfig {
                idle_timeout: Duration::from_secs(5),
                total_timeout: Duration::from_secs(30),
                max_body_bytes: 16,
                max_buffered_bytes: usize::MAX,
            };
            let input = RequestBodyGuardrailInput {
                elapsed: Duration::ZERO,
                idle_for: Duration::ZERO,
                bytes_received: 12,
                buffered_bytes: 0,
                next_chunk_bytes: 8,
                declared_content_length: None,
                exempt_from_body_size_cap: true,
            };

            assert_eq!(
                evaluate_request_body_ingress(config, input),
                RequestBodyGuardrailDecision::Continue
            );
        }

        #[test]
        fn request_body_unknown_length_prebuffer_cap_rejects() {
            let decision = evaluate_request_body_ingress(
                RequestBodyGuardrailConfig {
                    idle_timeout: Duration::from_secs(5),
                    total_timeout: Duration::from_secs(30),
                    max_body_bytes: usize::MAX,
                    max_buffered_bytes: 10,
                },
                RequestBodyGuardrailInput {
                    elapsed: Duration::ZERO,
                    idle_for: Duration::ZERO,
                    bytes_received: 0,
                    buffered_bytes: 6,
                    next_chunk_bytes: 5,
                    declared_content_length: None,
                    exempt_from_body_size_cap: false,
                },
            );

            assert_eq!(
                decision,
                RequestBodyGuardrailDecision::Reject {
                    kind: BodyLimitKind::UnknownLengthPrebuffer,
                }
            );
        }

        #[test]
        fn request_body_declared_length_cap_rejects() {
            let decision = evaluate_request_body_ingress(
                RequestBodyGuardrailConfig {
                    idle_timeout: Duration::from_secs(5),
                    total_timeout: Duration::from_secs(30),
                    max_body_bytes: 16,
                    max_buffered_bytes: usize::MAX,
                },
                RequestBodyGuardrailInput {
                    elapsed: Duration::ZERO,
                    idle_for: Duration::ZERO,
                    bytes_received: 0,
                    buffered_bytes: 0,
                    next_chunk_bytes: 0,
                    declared_content_length: Some(17),
                    exempt_from_body_size_cap: false,
                },
            );

            assert_eq!(
                decision,
                RequestBodyGuardrailDecision::Reject {
                    kind: BodyLimitKind::BodySize,
                }
            );
        }

        #[test]
        fn request_body_running_total_cap_rejects() {
            let decision = evaluate_request_body_ingress(
                RequestBodyGuardrailConfig {
                    idle_timeout: Duration::from_secs(5),
                    total_timeout: Duration::from_secs(30),
                    max_body_bytes: 16,
                    max_buffered_bytes: usize::MAX,
                },
                RequestBodyGuardrailInput {
                    elapsed: Duration::ZERO,
                    idle_for: Duration::ZERO,
                    bytes_received: 12,
                    buffered_bytes: 0,
                    next_chunk_bytes: 5,
                    declared_content_length: None,
                    exempt_from_body_size_cap: false,
                },
            );

            assert_eq!(
                decision,
                RequestBodyGuardrailDecision::Reject {
                    kind: BodyLimitKind::BodySize,
                }
            );
        }

        #[test]
        fn request_body_declared_length_over_buffer_cap_rejects_as_buffered_body() {
            let decision = evaluate_request_body_ingress(
                RequestBodyGuardrailConfig {
                    idle_timeout: Duration::from_secs(5),
                    total_timeout: Duration::from_secs(30),
                    max_body_bytes: 64,
                    max_buffered_bytes: 8,
                },
                RequestBodyGuardrailInput {
                    elapsed: Duration::ZERO,
                    idle_for: Duration::ZERO,
                    bytes_received: 0,
                    buffered_bytes: 6,
                    next_chunk_bytes: 3,
                    declared_content_length: Some(32),
                    exempt_from_body_size_cap: false,
                },
            );

            assert_eq!(
                decision,
                RequestBodyGuardrailDecision::Reject {
                    kind: BodyLimitKind::BufferedBody,
                }
            );
        }

        #[test]
        fn checked_request_body_ingress_returns_next_accounting_state() {
            let next_state = checked_request_body_ingress(
                RequestBodyGuardrailConfig {
                    idle_timeout: Duration::from_secs(5),
                    total_timeout: Duration::from_secs(30),
                    max_body_bytes: 64,
                    max_buffered_bytes: 32,
                },
                RequestBodyGuardrailInput {
                    elapsed: Duration::ZERO,
                    idle_for: Duration::ZERO,
                    bytes_received: 7,
                    buffered_bytes: 3,
                    next_chunk_bytes: 5,
                    declared_content_length: None,
                    exempt_from_body_size_cap: false,
                },
            )
            .expect("request ingress should pass");

            assert_eq!(
                next_state,
                RequestBodyIngressState {
                    bytes_received: 12,
                    buffered_bytes: 8,
                }
            );
        }

        #[test]
        fn checked_request_body_ingress_returns_stable_reject_without_next_state() {
            let rejection = checked_request_body_ingress(
                RequestBodyGuardrailConfig {
                    idle_timeout: Duration::from_secs(5),
                    total_timeout: Duration::from_secs(30),
                    max_body_bytes: 16,
                    max_buffered_bytes: 32,
                },
                RequestBodyGuardrailInput {
                    elapsed: Duration::ZERO,
                    idle_for: Duration::ZERO,
                    bytes_received: 12,
                    buffered_bytes: 0,
                    next_chunk_bytes: 5,
                    declared_content_length: None,
                    exempt_from_body_size_cap: false,
                },
            )
            .expect_err("oversized request body should reject");

            assert_eq!(
                rejection,
                RequestBodyGuardrailDecision::Reject {
                    kind: BodyLimitKind::BodySize,
                }
            );
        }
    }

    mod response_body_egress {
        use super::*;

        #[test]
        fn response_body_guardrails_continue_without_reject_when_under_limits() {
            let decision = evaluate_response_body_guardrails(
                ResponseBodyGuardrailConfig {
                    idle_timeout: Duration::from_secs(5),
                    total_timeout: Duration::from_secs(30),
                    max_body_bytes: 64,
                    unknown_length_prebuffer_bytes: 16,
                    chunk_bytes: 8,
                },
                ResponseBodyGuardrailInput {
                    elapsed: Duration::from_secs(1),
                    idle_for: Duration::from_secs(1),
                    bytes_received: 2,
                    prebuffered_bytes: 0,
                    next_chunk_bytes: 2,
                    declared_content_length: Some(12),
                    headers_emitted: false,
                    progressive_emission_allowed: true,
                    body_forwarding_enabled: true,
                    exempt_from_body_size_cap: false,
                },
            );

            assert_eq!(
                decision,
                ResponseBodyGuardrailDecision::Continue {
                    streaming: ResponseStreamingPolicy {
                        emission: ProgressiveEmissionPolicy::StreamProgressively,
                        chunk_emission: ResponseChunkEmissionPolicy::FixedSize {
                            max_chunk_bytes: 8
                        },
                        wait_timeout: Duration::from_secs(4),
                    },
                }
            );
        }

        #[test]
        fn response_body_prefers_prebuffer_for_unknown_length_before_headers() {
            let decision = evaluate_response_body_guardrails(
                ResponseBodyGuardrailConfig {
                    idle_timeout: Duration::from_secs(5),
                    total_timeout: Duration::from_secs(30),
                    max_body_bytes: 64,
                    unknown_length_prebuffer_bytes: 16,
                    chunk_bytes: 8,
                },
                ResponseBodyGuardrailInput {
                    elapsed: Duration::from_secs(1),
                    idle_for: Duration::from_secs(1),
                    bytes_received: 0,
                    prebuffered_bytes: 0,
                    next_chunk_bytes: 0,
                    declared_content_length: None,
                    headers_emitted: false,
                    progressive_emission_allowed: true,
                    body_forwarding_enabled: true,
                    exempt_from_body_size_cap: false,
                },
            );

            assert_eq!(
                decision,
                ResponseBodyGuardrailDecision::Continue {
                    streaming: ResponseStreamingPolicy {
                        emission: ProgressiveEmissionPolicy::PrebufferUntilValidated,
                        chunk_emission: ResponseChunkEmissionPolicy::FixedSize {
                            max_chunk_bytes: 8
                        },
                        wait_timeout: Duration::from_secs(4),
                    },
                }
            );
        }

        #[test]
        fn response_body_declared_length_cap_rejects() {
            let decision = evaluate_response_body_guardrails(
                ResponseBodyGuardrailConfig {
                    idle_timeout: Duration::from_secs(5),
                    total_timeout: Duration::from_secs(30),
                    max_body_bytes: 16,
                    unknown_length_prebuffer_bytes: 8,
                    chunk_bytes: 8,
                },
                ResponseBodyGuardrailInput {
                    elapsed: Duration::ZERO,
                    idle_for: Duration::ZERO,
                    bytes_received: 0,
                    prebuffered_bytes: 0,
                    next_chunk_bytes: 0,
                    declared_content_length: Some(17),
                    headers_emitted: false,
                    progressive_emission_allowed: true,
                    body_forwarding_enabled: true,
                    exempt_from_body_size_cap: false,
                },
            );

            assert_eq!(
                decision,
                ResponseBodyGuardrailDecision::Reject {
                    kind: BodyLimitKind::BodySize,
                }
            );
        }

        #[test]
        fn response_body_unknown_length_prebuffer_cap_rejects() {
            let decision = evaluate_response_body_guardrails(
                ResponseBodyGuardrailConfig {
                    idle_timeout: Duration::from_secs(5),
                    total_timeout: Duration::from_secs(30),
                    max_body_bytes: 64,
                    unknown_length_prebuffer_bytes: 10,
                    chunk_bytes: 4,
                },
                ResponseBodyGuardrailInput {
                    elapsed: Duration::from_secs(1),
                    idle_for: Duration::from_secs(1),
                    bytes_received: 6,
                    prebuffered_bytes: 6,
                    next_chunk_bytes: 5,
                    declared_content_length: None,
                    headers_emitted: false,
                    progressive_emission_allowed: true,
                    body_forwarding_enabled: true,
                    exempt_from_body_size_cap: false,
                },
            );

            assert_eq!(
                decision,
                ResponseBodyGuardrailDecision::Reject {
                    kind: BodyLimitKind::UnknownLengthPrebuffer,
                }
            );
        }

        #[test]
        fn response_body_total_timeout_rejects() {
            let decision = evaluate_response_body_guardrails(
                ResponseBodyGuardrailConfig {
                    idle_timeout: Duration::from_secs(5),
                    total_timeout: Duration::from_secs(30),
                    max_body_bytes: 64,
                    unknown_length_prebuffer_bytes: 16,
                    chunk_bytes: 8,
                },
                ResponseBodyGuardrailInput {
                    elapsed: Duration::from_secs(30),
                    idle_for: Duration::from_secs(1),
                    bytes_received: 0,
                    prebuffered_bytes: 0,
                    next_chunk_bytes: 0,
                    declared_content_length: None,
                    headers_emitted: false,
                    progressive_emission_allowed: true,
                    body_forwarding_enabled: true,
                    exempt_from_body_size_cap: false,
                },
            );

            assert_eq!(
                decision,
                ResponseBodyGuardrailDecision::Timeout {
                    kind: BodyTimeoutKind::Total,
                }
            );
        }

        #[test]
        fn response_body_total_timeout_is_ignored_after_progress() {
            let decision = evaluate_response_body_guardrails(
                ResponseBodyGuardrailConfig {
                    idle_timeout: Duration::from_secs(5),
                    total_timeout: Duration::from_secs(30),
                    max_body_bytes: 64,
                    unknown_length_prebuffer_bytes: 16,
                    chunk_bytes: 8,
                },
                ResponseBodyGuardrailInput {
                    elapsed: Duration::from_secs(30),
                    idle_for: Duration::from_secs(1),
                    bytes_received: 1,
                    prebuffered_bytes: 0,
                    next_chunk_bytes: 0,
                    declared_content_length: None,
                    headers_emitted: false,
                    progressive_emission_allowed: true,
                    body_forwarding_enabled: true,
                    exempt_from_body_size_cap: false,
                },
            );

            assert_eq!(
                decision,
                ResponseBodyGuardrailDecision::Continue {
                    streaming: ResponseStreamingPolicy {
                        emission: ProgressiveEmissionPolicy::PrebufferUntilValidated,
                        chunk_emission: ResponseChunkEmissionPolicy::FixedSize {
                            max_chunk_bytes: 8
                        },
                        wait_timeout: Duration::from_secs(4),
                    },
                }
            );
        }

        #[test]
        fn response_body_idle_timeout_rejects() {
            let decision = evaluate_response_body_guardrails(
                ResponseBodyGuardrailConfig {
                    idle_timeout: Duration::from_secs(5),
                    total_timeout: Duration::from_secs(30),
                    max_body_bytes: 64,
                    unknown_length_prebuffer_bytes: 16,
                    chunk_bytes: 8,
                },
                ResponseBodyGuardrailInput {
                    elapsed: Duration::from_secs(4),
                    idle_for: Duration::from_secs(5),
                    bytes_received: 0,
                    prebuffered_bytes: 0,
                    next_chunk_bytes: 0,
                    declared_content_length: None,
                    headers_emitted: false,
                    progressive_emission_allowed: true,
                    body_forwarding_enabled: true,
                    exempt_from_body_size_cap: false,
                },
            );

            assert_eq!(
                decision,
                ResponseBodyGuardrailDecision::Timeout {
                    kind: BodyTimeoutKind::Idle,
                }
            );
        }

        #[test]
        fn response_body_known_length_streams_progressively() {
            let decision = evaluate_response_body_guardrails(
                ResponseBodyGuardrailConfig {
                    idle_timeout: Duration::from_secs(5),
                    total_timeout: Duration::from_secs(30),
                    max_body_bytes: 64,
                    unknown_length_prebuffer_bytes: 16,
                    chunk_bytes: 8,
                },
                ResponseBodyGuardrailInput {
                    elapsed: Duration::from_secs(1),
                    idle_for: Duration::from_secs(1),
                    bytes_received: 0,
                    prebuffered_bytes: 0,
                    next_chunk_bytes: 0,
                    declared_content_length: Some(12),
                    headers_emitted: false,
                    progressive_emission_allowed: true,
                    body_forwarding_enabled: true,
                    exempt_from_body_size_cap: false,
                },
            );

            assert_eq!(
                decision,
                ResponseBodyGuardrailDecision::Continue {
                    streaming: ResponseStreamingPolicy {
                        emission: ProgressiveEmissionPolicy::StreamProgressively,
                        chunk_emission: ResponseChunkEmissionPolicy::FixedSize {
                            max_chunk_bytes: 8
                        },
                        wait_timeout: Duration::from_secs(4),
                    },
                }
            );
        }

        #[test]
        fn response_body_streams_progressively_when_progressive_emission_is_disabled() {
            let decision = evaluate_response_body_guardrails(
                ResponseBodyGuardrailConfig {
                    idle_timeout: Duration::from_secs(5),
                    total_timeout: Duration::from_secs(30),
                    max_body_bytes: 64,
                    unknown_length_prebuffer_bytes: 16,
                    chunk_bytes: 8,
                },
                ResponseBodyGuardrailInput {
                    elapsed: Duration::from_secs(1),
                    idle_for: Duration::from_secs(1),
                    bytes_received: 0,
                    prebuffered_bytes: 0,
                    next_chunk_bytes: 0,
                    declared_content_length: None,
                    headers_emitted: false,
                    progressive_emission_allowed: false,
                    body_forwarding_enabled: true,
                    exempt_from_body_size_cap: false,
                },
            );

            assert_eq!(
                decision,
                ResponseBodyGuardrailDecision::Continue {
                    streaming: ResponseStreamingPolicy {
                        emission: ProgressiveEmissionPolicy::StreamProgressively,
                        chunk_emission: ResponseChunkEmissionPolicy::FixedSize {
                            max_chunk_bytes: 8
                        },
                        wait_timeout: Duration::from_secs(4),
                    },
                }
            );
        }

        #[test]
        fn response_body_suppresses_emission_when_body_is_disabled() {
            let decision = evaluate_response_body_guardrails(
                ResponseBodyGuardrailConfig {
                    idle_timeout: Duration::from_secs(5),
                    total_timeout: Duration::from_secs(30),
                    max_body_bytes: 64,
                    unknown_length_prebuffer_bytes: 16,
                    chunk_bytes: 8,
                },
                ResponseBodyGuardrailInput {
                    elapsed: Duration::from_secs(1),
                    idle_for: Duration::from_secs(1),
                    bytes_received: 0,
                    prebuffered_bytes: 0,
                    next_chunk_bytes: 0,
                    declared_content_length: None,
                    headers_emitted: false,
                    progressive_emission_allowed: true,
                    body_forwarding_enabled: false,
                    exempt_from_body_size_cap: false,
                },
            );

            assert_eq!(
                decision,
                ResponseBodyGuardrailDecision::Continue {
                    streaming: ResponseStreamingPolicy {
                        emission: ProgressiveEmissionPolicy::SuppressBody,
                        chunk_emission: ResponseChunkEmissionPolicy::Passthrough,
                        wait_timeout: Duration::from_secs(4),
                    },
                }
            );
        }

        #[test]
        fn checked_response_body_guardrails_returns_next_streaming_state() {
            let evaluated = checked_response_body_guardrails(
                ResponseBodyGuardrailConfig {
                    idle_timeout: Duration::from_secs(5),
                    total_timeout: Duration::from_secs(30),
                    max_body_bytes: 64,
                    unknown_length_prebuffer_bytes: 16,
                    chunk_bytes: 4,
                },
                ResponseBodyGuardrailInput {
                    elapsed: Duration::from_secs(1),
                    idle_for: Duration::from_secs(1),
                    bytes_received: 5,
                    prebuffered_bytes: 5,
                    next_chunk_bytes: 3,
                    declared_content_length: None,
                    headers_emitted: false,
                    progressive_emission_allowed: true,
                    body_forwarding_enabled: true,
                    exempt_from_body_size_cap: false,
                },
            )
            .expect("response egress should pass");

            assert_eq!(
                evaluated,
                EvaluatedResponseBodyGuardrail {
                    streaming: ResponseStreamingPolicy {
                        emission: ProgressiveEmissionPolicy::PrebufferUntilValidated,
                        chunk_emission: ResponseChunkEmissionPolicy::FixedSize {
                            max_chunk_bytes: 4
                        },
                        wait_timeout: Duration::from_secs(4),
                    },
                    next_state: ResponseBodyEgressState {
                        bytes_received: 8,
                        prebuffered_bytes: 8,
                    },
                }
            );
        }

        #[test]
        fn checked_response_body_guardrails_returns_stable_reject_without_next_state() {
            let rejection = checked_response_body_guardrails(
                ResponseBodyGuardrailConfig {
                    idle_timeout: Duration::from_secs(5),
                    total_timeout: Duration::from_secs(30),
                    max_body_bytes: 16,
                    unknown_length_prebuffer_bytes: 8,
                    chunk_bytes: 4,
                },
                ResponseBodyGuardrailInput {
                    elapsed: Duration::ZERO,
                    idle_for: Duration::ZERO,
                    bytes_received: 12,
                    prebuffered_bytes: 0,
                    next_chunk_bytes: 5,
                    declared_content_length: None,
                    headers_emitted: true,
                    progressive_emission_allowed: true,
                    body_forwarding_enabled: true,
                    exempt_from_body_size_cap: false,
                },
            )
            .expect_err("oversized response body should reject");

            assert_eq!(
                rejection,
                ResponseBodyGuardrailDecision::Reject {
                    kind: BodyLimitKind::BodySize,
                }
            );
        }
    }

    mod response_chunking {
        use super::*;

        #[test]
        fn response_chunk_ranges_follow_fixed_size_policy() {
            assert_eq!(
                response_chunk_ranges(
                    10,
                    ResponseChunkEmissionPolicy::FixedSize { max_chunk_bytes: 4 }
                ),
                vec![(0, 4), (4, 8), (8, 10)]
            );
        }

        #[test]
        fn response_chunk_ranges_passthrough_policy_keeps_single_chunk() {
            assert_eq!(
                response_chunk_ranges(10, ResponseChunkEmissionPolicy::Passthrough),
                vec![(0, 10)]
            );
        }

        #[test]
        fn response_chunk_ranges_use_minimum_chunk_size_of_one() {
            assert_eq!(
                response_chunk_ranges(
                    3,
                    ResponseChunkEmissionPolicy::FixedSize { max_chunk_bytes: 0 }
                ),
                vec![(0, 1), (1, 2), (2, 3)]
            );
        }
    }
}
