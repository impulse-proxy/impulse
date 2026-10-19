use bytes::Bytes;
use http::StatusCode;
use impulse_errors::{
    HedgeOutcomeTelemetryReason, HedgeTriggerTelemetryReason, ProxyError,
    RetryAttemptTelemetryReason, RetryPolicyDenialReason,
};
use impulse_transport::UpstreamBody;
use tokio::sync::mpsc;

use crate::{
    OverloadShedReason,
    runtime::connection::{guardrails::ResponseBodyGuardrailConfig, stream::TimeoutReason},
};

pub(crate) enum ForwardSuccess {
    Response {
        status: http::StatusCode,
        headers: http::HeaderMap,
        body: UpstreamBody,
    },
    Tunnel {
        status: http::StatusCode,
        headers: http::HeaderMap,
        response_chunk_rx: mpsc::Receiver<ResponseChunk>,
    },
}

pub(crate) type ForwardResult = Result<ForwardSuccess, ProxyError>;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RetryTelemetry {
    pub(crate) count: u8,
    pub(crate) attempt_reason: Option<RetryAttemptTelemetryReason>,
    pub(crate) denial_reason: Option<RetryPolicyDenialReason>,
}

impl RetryTelemetry {
    pub(crate) fn record_attempt(&mut self, reason: RetryAttemptTelemetryReason) {
        self.count = self.count.saturating_add(1);
        self.attempt_reason = Some(reason);
    }

    pub(crate) fn record_denial(&mut self, denial_reason: Option<RetryPolicyDenialReason>) {
        if self.denial_reason.is_none() {
            self.denial_reason = denial_reason;
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ForwardingPolicyTelemetry {
    pub(crate) hedge: HedgeTelemetry,
    pub(crate) retry: RetryTelemetry,
}

pub(crate) struct UpstreamResult {
    pub(crate) forward: ForwardResult,
    pub(crate) policy: ForwardingPolicyTelemetry,
}

/// A chunk of the upstream response being streamed back to the client.
#[derive(Debug)]
pub(crate) enum ResponseChunk {
    /// Emit downstream response headers (used when headers are deferred until
    /// body-size validation completes).
    Start {
        status: http::StatusCode,
        headers: Vec<(Vec<u8>, Vec<u8>)>,
    },
    Data(Bytes),
    Trailers {
        headers: Vec<(Vec<u8>, Vec<u8>)>,
    },
    End,
    Error(ProxyError),
    Timeout(TimeoutReason),
}

#[derive(Clone)]
pub(crate) struct ResponseStartMetadata {
    pub(crate) status: StatusCode,
    pub(crate) headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub(crate) headers_deferred: bool,
}

impl ResponseStartMetadata {
    pub(crate) fn response_headers_sent(&self) -> bool {
        !self.headers_deferred
    }
}

pub(crate) enum ImmediateResponseStart {
    NormalizedHeadersOnly,
    SyntheticBody(&'static [u8]),
}

pub(crate) struct ResponseBodyPumpPlan {
    pub(crate) guardrails: ResponseBodyGuardrailConfig,
    pub(crate) upstream_content_length: Option<usize>,
    pub(crate) body_forwarding_enabled: bool,
    pub(crate) progressive_emission_allowed: bool,
    pub(crate) defer_headers_until_body_validated: bool,
    pub(crate) tunnel_response: bool,
    pub(crate) compress_response: bool,
}

pub(crate) enum ResponseStartObservation {
    Status {
        status: StatusCode,
    },
    ProxyError {
        status: StatusCode,
        error: ProxyError,
        overload_reason: Option<OverloadShedReason>,
    },
}

pub(crate) enum ResponseStartDecision {
    ImmediateTerminal {
        metadata: ResponseStartMetadata,
        terminal: ImmediateResponseStart,
        observation: ResponseStartObservation,
    },
    StreamingPrebuilt {
        metadata: ResponseStartMetadata,
        response_chunk_rx: mpsc::Receiver<ResponseChunk>,
        observation: ResponseStartObservation,
    },
    StreamingBodyPump {
        metadata: ResponseStartMetadata,
        response_body: UpstreamBody,
        pump: ResponseBodyPumpPlan,
        observation: ResponseStartObservation,
    },
    BackendFailure(ProxyError),
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct HedgeTelemetry {
    pub(crate) trigger_reason: Option<HedgeTriggerTelemetryReason>,
    pub(crate) outcome_reason: Option<HedgeOutcomeTelemetryReason>,
    pub(crate) primary_late_ms: u64,
}

impl HedgeTelemetry {
    pub(crate) fn record_trigger(&mut self, reason: HedgeTriggerTelemetryReason) {
        self.trigger_reason = Some(reason);
    }

    pub(crate) fn record_outcome(&mut self, reason: HedgeOutcomeTelemetryReason) {
        self.outcome_reason = Some(reason);
    }

    pub(crate) fn observe_primary_late_ms(&mut self, late_ms: u64) {
        self.primary_late_ms = late_ms;
    }
}

#[cfg(test)]
mod tests {
    mod retry_policy_telemetry {
        use impulse_errors::{RetryAttemptTelemetryReason, RetryPolicyDenialReason};

        use super::super::RetryTelemetry;

        #[test]
        fn retry_telemetry_tracks_attempt_count_and_reason() {
            let mut telemetry = RetryTelemetry::default();

            telemetry.record_attempt(RetryAttemptTelemetryReason::Timeout);
            telemetry.record_attempt(RetryAttemptTelemetryReason::Transport);

            assert_eq!(telemetry.count, 2);
            assert_eq!(
                telemetry.attempt_reason,
                Some(RetryAttemptTelemetryReason::Transport)
            );
        }

        #[test]
        fn retry_telemetry_preserves_first_denial_reason() {
            let mut telemetry = RetryTelemetry::default();

            telemetry.record_denial(Some(RetryPolicyDenialReason::BudgetDenied));
            telemetry.record_denial(Some(RetryPolicyDenialReason::AttemptLimitReached));

            assert_eq!(
                telemetry.denial_reason,
                Some(RetryPolicyDenialReason::BudgetDenied)
            );
        }

        #[test]
        fn retry_denial_does_not_count_as_executed_retry_attempt() {
            let mut telemetry = RetryTelemetry::default();

            telemetry.record_denial(Some(RetryPolicyDenialReason::BudgetDenied));

            assert_eq!(telemetry.count, 0);
            assert_eq!(telemetry.attempt_reason, None);
            assert_eq!(
                telemetry.denial_reason,
                Some(RetryPolicyDenialReason::BudgetDenied)
            );
        }
    }

    mod hedge_policy_telemetry {
        use impulse_errors::{HedgeOutcomeTelemetryReason, HedgeTriggerTelemetryReason};

        use super::super::HedgeTelemetry;

        #[test]
        fn hedge_telemetry_records_typed_trigger_and_outcome() {
            let mut telemetry = HedgeTelemetry::default();

            telemetry.record_trigger(HedgeTriggerTelemetryReason::DelayElapsed);
            telemetry.record_outcome(HedgeOutcomeTelemetryReason::HedgeWon);
            telemetry.observe_primary_late_ms(42);

            assert_eq!(
                telemetry.trigger_reason,
                Some(HedgeTriggerTelemetryReason::DelayElapsed)
            );
            assert_eq!(
                telemetry.outcome_reason,
                Some(HedgeOutcomeTelemetryReason::HedgeWon)
            );
            assert_eq!(telemetry.primary_late_ms, 42);
        }

        #[test]
        fn hedge_telemetry_keeps_primary_win_and_hedge_win_outcomes_distinct() {
            let mut primary_won = HedgeTelemetry::default();
            primary_won.record_trigger(HedgeTriggerTelemetryReason::DelayElapsed);
            primary_won.record_outcome(HedgeOutcomeTelemetryReason::PrimaryWonAfterTrigger);

            let mut hedge_won = HedgeTelemetry::default();
            hedge_won.record_trigger(HedgeTriggerTelemetryReason::DelayElapsed);
            hedge_won.record_outcome(HedgeOutcomeTelemetryReason::HedgeWon);

            assert_eq!(
                primary_won.outcome_reason,
                Some(HedgeOutcomeTelemetryReason::PrimaryWonAfterTrigger)
            );
            assert_eq!(
                hedge_won.outcome_reason,
                Some(HedgeOutcomeTelemetryReason::HedgeWon)
            );
        }
    }
}
