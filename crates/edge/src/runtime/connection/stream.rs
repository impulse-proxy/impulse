use std::{collections::VecDeque, sync::Arc, time::Instant};

use bytes::Bytes;
use http::StatusCode;
pub use impulse_contracts::CompletionReason;
pub(crate) use impulse_contracts::{
    BackendFailureReason, CancellationReason, RejectionReason, TerminalReason, TimeoutReason,
};
use impulse_errors::ProxyError;
use tokio::{
    sync::{OwnedSemaphorePermit, mpsc, oneshot},
    task::AbortHandle,
};
use tracing::Span;

use crate::{
    OverloadShedReason,
    edge_core::request_execution::TerminalOutcomeGuard,
    resilience::{adaptive_admission::AdaptivePermit, route_queue::RouteQueuePermit},
    runtime::connection::{
        auth::{ExternalAuthFailureDisposition, ExternalAuthResult},
        request::PendingForward,
        response::{ResponseChunk, UpstreamResult},
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamPhase {
    /// Still receiving request headers/body from the QUIC client.
    ReceivingRequest,
    /// Request fully received; waiting for the upstream response.
    AwaitingUpstream,
    /// Upstream responded; streaming response back to the QUIC client.
    SendingResponse,
    /// Stream finished cleanly.
    Completed,
    /// Stream terminated.
    Terminal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamAdmissionState {
    /// Request admission is still pending an external auth/authz decision.
    WaitingForAuth,
    /// Request cleared admission checks and may proceed to upstream forwarding.
    ReadyToForward,
    /// Request was denied by admission/auth checks and should not be forwarded.
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelMode {
    None,
    Connect,
    Websocket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestMode {
    Normal,
    Bodyless,
    HeadLike,
    ConnectTunnel,
    WebsocketTunnel,
}

impl RequestMode {
    pub fn from_intake(
        tunnel_mode: TunnelMode,
        method: &str,
        content_length: Option<usize>,
    ) -> Self {
        match tunnel_mode {
            TunnelMode::Connect => Self::ConnectTunnel,
            TunnelMode::Websocket => Self::WebsocketTunnel,
            TunnelMode::None
                if content_length.unwrap_or(0) == 0 && method.eq_ignore_ascii_case("HEAD") =>
            {
                Self::HeadLike
            }
            TunnelMode::None
                if content_length.unwrap_or(0) == 0 && method.eq_ignore_ascii_case("GET") =>
            {
                Self::Bodyless
            }
            TunnelMode::None => Self::Normal,
        }
    }

    pub fn is_tunnel(self) -> bool {
        matches!(self, Self::ConnectTunnel | Self::WebsocketTunnel)
    }

    pub fn suppresses_response_body(self) -> bool {
        matches!(self, Self::HeadLike)
    }

    pub fn bodyless_mode(self) -> bool {
        matches!(self, Self::Bodyless | Self::HeadLike)
    }

    pub fn tunnel_mode(self) -> TunnelMode {
        match self {
            Self::Normal | Self::Bodyless | Self::HeadLike => TunnelMode::None,
            Self::ConnectTunnel => TunnelMode::Connect,
            Self::WebsocketTunnel => TunnelMode::Websocket,
        }
    }

    pub fn initial_body_state(self) -> RequestBodyState {
        if self.bodyless_mode() {
            RequestBodyState::FinReceived
        } else {
            RequestBodyState::Open
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestBodyState {
    Open,
    Buffered,
    FinReceived,
    ClosedToUpstream,
}

impl RequestBodyState {
    pub fn from_runtime(
        request_fin_received: bool,
        has_buffered_body: bool,
        forward_open: bool,
    ) -> Self {
        if forward_open {
            if has_buffered_body {
                Self::Buffered
            } else if request_fin_received {
                Self::FinReceived
            } else {
                Self::Open
            }
        } else if request_fin_received {
            Self::ClosedToUpstream
        } else if has_buffered_body {
            Self::Buffered
        } else {
            Self::Open
        }
    }

    pub fn on_buffered(self) -> Self {
        match self {
            Self::ClosedToUpstream => Self::ClosedToUpstream,
            _ => Self::Buffered,
        }
    }

    pub fn on_downstream_finished(self) -> Self {
        match self {
            Self::ClosedToUpstream => Self::ClosedToUpstream,
            _ => Self::FinReceived,
        }
    }

    pub fn on_forward_closed(self) -> Self {
        Self::ClosedToUpstream
    }

    pub fn request_fin_received(self) -> bool {
        matches!(self, Self::FinReceived | Self::ClosedToUpstream)
    }

    pub fn can_accept_downstream_body(self) -> bool {
        matches!(self, Self::Open | Self::Buffered)
    }

    pub fn forwarding_complete(self) -> bool {
        matches!(self, Self::ClosedToUpstream)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseEmissionState {
    DeferredHeaders,
    HeadersSent,
    StreamingBody,
    TrailersPending,
    EndPending,
}

#[derive(Debug)]
pub(crate) enum ResponseBackpressureState {
    Ready,
    Blocked(ResponseChunk),
}

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub request_id: impulse_contracts::RequestId,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub traceparent: Option<String>,
    pub trace_span: Option<Span>,
    pub method: String,
    pub path: String,
    pub authority: Option<String>,
    pub start: Instant,
    pub total_request_deadline: Instant,
    pub(crate) terminal_outcome: TerminalOutcomeGuard,
}

#[derive(Debug, Clone)]
pub struct RoutingSnapshot {
    pub backend_addr: String,
    pub backend_index: usize,
    pub upstream_name: String,
    pub route_reason: String,
    pub route_path_len: usize,
    pub route_host_specific: bool,
    pub backend_lb: Option<String>,
}

pub struct RequestIntakeState {
    pub context: RequestContext,
    pub request_mode: RequestMode,
    pub request_body: RequestBodyState,
}

pub struct AwaitingAuthState {
    pub context: RequestContext,
    pub routing: RoutingSnapshot,
    pub request_mode: RequestMode,
    pub request_body: RequestBodyState,
    pub request_body_runtime: RequestBodyRuntime,
    pub pending_forward: Arc<PendingForward>,
    pub(crate) auth_result_rx: oneshot::Receiver<ExternalAuthResult>,
    pub auth_abort: AbortHandle,
    pub auth_deadline: Instant,
    pub(crate) auth_disposition: ExternalAuthFailureDisposition,
}

impl AwaitingAuthState {
    pub(crate) fn poll_non_blocking(&mut self, now: Instant) -> Option<ExternalAuthResult> {
        if now >= self.auth_deadline {
            return Some(Err(ProxyError::Timeout));
        }

        match self.auth_result_rx.try_recv() {
            Ok(result) => Some(result),
            Err(oneshot::error::TryRecvError::Empty) => None,
            Err(oneshot::error::TryRecvError::Closed) => Some(Err(ProxyError::Transport(
                "external auth task dropped sender".into(),
            ))),
        }
    }
}

pub struct DispatchReadyState {
    pub context: RequestContext,
    pub routing: RoutingSnapshot,
    pub request_mode: RequestMode,
    pub request_body: RequestBodyState,
    pub request_body_runtime: RequestBodyRuntime,
    pub pending_forward: Arc<PendingForward>,
}

pub struct RequestBodyRuntime {
    pub body_buf: VecDeque<Bytes>,
    pub body_buf_bytes: usize,
    pub body_bytes_received: usize,
    pub last_body_activity: Instant,
    pub request_fin_received: bool,
}

impl RequestBodyRuntime {
    pub fn empty(now: Instant) -> Self {
        Self {
            body_buf: VecDeque::new(),
            body_buf_bytes: 0,
            body_bytes_received: 0,
            last_body_activity: now,
            request_fin_received: false,
        }
    }
}

pub struct AdmissionPermits {
    pub global: OwnedSemaphorePermit,
    pub upstream: OwnedSemaphorePermit,
    pub adaptive: AdaptivePermit,
    pub route_queue: RouteQueuePermit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendAccountingState {
    pub response_status: Option<StatusCode>,
    pub finalized: bool,
}

impl BackendAccountingState {
    pub fn should_finalize(self) -> bool {
        !self.finalized
    }
}

pub struct BackendDispatchState {
    pub body_tx: Option<mpsc::Sender<Bytes>>,
    pub(crate) upstream_result_rx: oneshot::Receiver<UpstreamResult>,
    pub backend_accounting: BackendAccountingState,
}

pub struct AdmittedState {
    pub context: RequestContext,
    pub routing: RoutingSnapshot,
    pub request_mode: RequestMode,
    pub request_body: RequestBodyState,
    pub request_body_runtime: RequestBodyRuntime,
    pub pending_forward: Arc<PendingForward>,
    pub permits: AdmissionPermits,
}

pub struct AwaitingUpstreamState {
    pub context: RequestContext,
    pub routing: RoutingSnapshot,
    pub request_mode: RequestMode,
    pub request_body: RequestBodyState,
    pub request_body_runtime: RequestBodyRuntime,
    pub pending_forward: Arc<PendingForward>,
    pub permits: AdmissionPermits,
    pub dispatch: BackendDispatchState,
}

pub struct ResponseStreamingState {
    pub context: RequestContext,
    pub routing: RoutingSnapshot,
    pub request_mode: RequestMode,
    pub request_body_runtime: RequestBodyRuntime,
    pub permits: AdmissionPermits,
    pub final_status: StatusCode,
    pub emission: ResponseEmissionState,
    pub(crate) response_chunk_rx: mpsc::Receiver<ResponseChunk>,
    pub(crate) backpressure: ResponseBackpressureState,
    pub backend_accounting: BackendAccountingState,
}

#[derive(Debug, Clone)]
pub struct TerminalSnapshot {
    pub context: RequestContext,
    pub routing: Option<RoutingSnapshot>,
    pub request_mode: RequestMode,
    pub response_status: Option<StatusCode>,
    pub overload_reason: Option<OverloadShedReason>,
    pub backend_accounting: Option<BackendAccountingState>,
}

pub struct CompletedState {
    pub reason: CompletionReason,
    pub snapshot: TerminalSnapshot,
}

pub struct CancelledState {
    pub reason: CancellationReason,
    pub snapshot: TerminalSnapshot,
}

pub struct TimedOutState {
    pub reason: TimeoutReason,
    pub snapshot: TerminalSnapshot,
}

pub struct RejectedState {
    pub reason: RejectionReason,
    pub snapshot: TerminalSnapshot,
}

pub struct BackendFailedState {
    pub reason: BackendFailureReason,
    pub snapshot: TerminalSnapshot,
}

pub enum TerminalState {
    Completed(CompletedState),
    Cancelled(CancelledState),
    TimedOut(TimedOutState),
    Rejected(RejectedState),
    BackendFailed(BackendFailedState),
}

impl TerminalState {
    pub(crate) fn from_reason(reason: TerminalReason, snapshot: TerminalSnapshot) -> Self {
        match reason {
            TerminalReason::Completed(reason) => {
                Self::Completed(CompletedState { reason, snapshot })
            }
            TerminalReason::Cancelled(reason) => {
                Self::Cancelled(CancelledState { reason, snapshot })
            }
            TerminalReason::TimedOut(reason) => Self::TimedOut(TimedOutState { reason, snapshot }),
            TerminalReason::Rejected(reason) => Self::Rejected(RejectedState { reason, snapshot }),
            TerminalReason::BackendFailed(reason) => {
                Self::BackendFailed(BackendFailedState { reason, snapshot })
            }
        }
    }

    pub fn terminal_status(&self) -> Option<StatusCode> {
        match self {
            Self::Completed(state) => state.snapshot.response_status,
            Self::Cancelled(state) => state.snapshot.response_status,
            Self::TimedOut(state) => state.snapshot.response_status,
            Self::Rejected(state) => state.snapshot.response_status,
            Self::BackendFailed(state) => state.snapshot.response_status,
        }
    }

    pub fn should_finalize_backend_accounting(&self) -> bool {
        match self {
            Self::Completed(state) => state
                .snapshot
                .backend_accounting
                .is_some_and(BackendAccountingState::should_finalize),
            Self::Cancelled(state) => state
                .snapshot
                .backend_accounting
                .is_some_and(BackendAccountingState::should_finalize),
            Self::TimedOut(state) => state
                .snapshot
                .backend_accounting
                .is_some_and(BackendAccountingState::should_finalize),
            Self::Rejected(state) => state
                .snapshot
                .backend_accounting
                .is_some_and(BackendAccountingState::should_finalize),
            Self::BackendFailed(state) => state
                .snapshot
                .backend_accounting
                .is_some_and(BackendAccountingState::should_finalize),
        }
    }
}

pub enum RequestExecutionState {
    Intake(RequestIntakeState),
    AwaitingAuth(AwaitingAuthState),
    DispatchReady(DispatchReadyState),
    Admitted(AdmittedState),
    AwaitingUpstream(AwaitingUpstreamState),
    StreamingResponse(ResponseStreamingState),
    Terminal(TerminalState),
}

impl RequestExecutionState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminal(_))
    }

    pub fn terminal_status(&self) -> Option<StatusCode> {
        match self {
            Self::Terminal(state) => state.terminal_status(),
            _ => None,
        }
    }

    pub fn should_finalize_backend_accounting(&self) -> bool {
        match self {
            Self::AwaitingUpstream(state) => state.dispatch.backend_accounting.should_finalize(),
            Self::StreamingResponse(state) => state.backend_accounting.should_finalize(),
            Self::Terminal(state) => state.should_finalize_backend_accounting(),
            Self::Intake(_)
            | Self::AwaitingAuth(_)
            | Self::DispatchReady(_)
            | Self::Admitted(_) => false,
        }
    }

    pub fn can_accept_request_body(&self) -> bool {
        match self {
            Self::Intake(state) => state.request_body.can_accept_downstream_body(),
            Self::AwaitingAuth(state) => state.request_body.can_accept_downstream_body(),
            Self::DispatchReady(state) => state.request_body.can_accept_downstream_body(),
            Self::Admitted(state) => state.request_body.can_accept_downstream_body(),
            Self::AwaitingUpstream(state) => state.request_body.can_accept_downstream_body(),
            Self::StreamingResponse(_) | Self::Terminal(_) => false,
        }
    }

    pub fn can_poll_upstream(&self) -> bool {
        match self {
            Self::AwaitingUpstream(state) => {
                state.request_mode.is_tunnel() || state.request_body.forwarding_complete()
            }
            _ => false,
        }
    }

    pub fn can_emit_response(&self) -> bool {
        matches!(self, Self::StreamingResponse(_))
    }

    pub fn phase(&self) -> StreamPhase {
        match self {
            Self::Intake(_)
            | Self::AwaitingAuth(_)
            | Self::DispatchReady(_)
            | Self::Admitted(_) => StreamPhase::ReceivingRequest,
            Self::AwaitingUpstream(_) => StreamPhase::AwaitingUpstream,
            Self::StreamingResponse(_) => StreamPhase::SendingResponse,
            Self::Terminal(TerminalState::Completed(_)) => StreamPhase::Completed,
            Self::Terminal(_) => StreamPhase::Terminal,
        }
    }

    pub fn admission_state(&self) -> StreamAdmissionState {
        match self {
            Self::AwaitingAuth(_) => StreamAdmissionState::WaitingForAuth,
            Self::DispatchReady(_)
            | Self::Admitted(_)
            | Self::AwaitingUpstream(_)
            | Self::StreamingResponse(_) => StreamAdmissionState::ReadyToForward,
            Self::Terminal(TerminalState::Rejected(_)) => StreamAdmissionState::Denied,
            Self::Intake(_) | Self::Terminal(_) => StreamAdmissionState::ReadyToForward,
        }
    }
}
