use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Instant,
};

use bytes::Bytes;
use impulse_config::config::{ForwardedHeaderPolicy, UpstreamHostPolicy};
use impulse_lb::upstream_pool::UpstreamPool;
use tokio::sync::{mpsc, oneshot};
use tracing::Span;

use crate::{
    Metrics, OverloadShedReason,
    request_pipeline::TerminalOutcomeGuard,
    runtime::connection::{
        auth::{ExternalAuthResult, PendingHeaderMutation},
        outcome::{
            BackendRequestFinishInput, finalize_backend_request_cleanup,
            observe_terminal_request_outcome,
        },
        response::{ResponseChunk, UpstreamResult},
        stream::{
            AdmissionPermits, AdmittedState, AwaitingAuthState, AwaitingUpstreamState,
            BackendAccountingState, BackendDispatchState, BackendFailureReason, CancellationReason,
            CancelledState, CompletionReason, DispatchReadyState, RequestBodyRuntime,
            RequestBodyState, RequestContext, RequestExecutionState, RequestMode,
            ResponseBackpressureState, ResponseEmissionState, ResponseStreamingState,
            StreamAdmissionState, StreamPhase, TerminalReason, TerminalSnapshot, TerminalState,
            TimeoutReason, TunnelMode,
        },
    },
};

pub struct RequestEnvelope {
    pub request_id: u64,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub traceparent: Option<String>,
    pub trace_span: Option<Span>,

    pub method: String,
    pub path: String,
    pub authority: Option<String>,
    /// Resolved backend address and index (for health marking on response).
    pub backend_addr: Option<String>,
    pub backend_index: Option<usize>,
    pub upstream_name: Option<String>,
    pub route_reason: Option<String>,
    pub route_path_len: Option<usize>,
    pub route_host_specific: Option<bool>,
    pub backend_lb: Option<String>,
    pub upstream_pool: Option<Arc<RwLock<UpstreamPool>>>,
    pub routing_transparency_enabled: bool,
    pub routing_transparency_include_reason: bool,
    pub response_status: Option<u16>,
    pub start: Instant,
    pub total_request_deadline: Instant,
    pub bodyless_mode: bool,
    pub tunnel_mode: TunnelMode,

    pub retry_count: u8,
    pub error_kind: Option<&'static str>,
    pub terminal_overload_reason: Option<OverloadShedReason>,
    pub(crate) terminal_outcome: TerminalOutcomeGuard,
    pub(crate) empty_request_body_runtime: RequestBodyRuntime,
    pub execution: RequestExecutionState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RequestStateError {
    InvalidTransition {
        from: StreamPhase,
        attempted: &'static str,
    },
}

impl RequestStateError {
    pub(crate) fn attempted(&self) -> &'static str {
        match self {
            Self::InvalidTransition { attempted, .. } => attempted,
        }
    }
}

impl RequestEnvelope {
    pub fn request_id(&self) -> u64 {
        self.request_id
    }

    pub fn set_terminal_overload_reason(&mut self, reason: Option<OverloadShedReason>) {
        self.terminal_overload_reason = reason;
    }

    pub(crate) fn from_dispatch_ready_state(
        state: DispatchReadyState,
        upstream_pool: Arc<RwLock<UpstreamPool>>,
        routing_transparency_enabled: bool,
        routing_transparency_include_reason: bool,
        retry_count: u8,
        error_kind: Option<&'static str>,
    ) -> Self {
        let DispatchReadyState {
            context,
            routing,
            request_mode,
            request_body: _,
            request_body_runtime: _,
            pending_forward: _,
        } = &state;

        Self {
            request_id: context.request_id,
            trace_id: context.trace_id.clone(),
            span_id: context.span_id.clone(),
            traceparent: context.traceparent.clone(),
            trace_span: context.trace_span.clone(),
            method: context.method.clone(),
            path: context.path.clone(),
            authority: context.authority.clone(),
            backend_addr: Some(routing.backend_addr.clone()),
            backend_index: Some(routing.backend_index),
            upstream_name: Some(routing.upstream_name.clone()),
            route_reason: Some(routing.route_reason.clone()),
            route_path_len: Some(routing.route_path_len),
            route_host_specific: Some(routing.route_host_specific),
            backend_lb: routing.backend_lb.clone(),
            upstream_pool: Some(upstream_pool),
            routing_transparency_enabled,
            routing_transparency_include_reason,
            response_status: None,
            start: context.start,
            total_request_deadline: context.total_request_deadline,
            bodyless_mode: request_mode.bodyless_mode(),
            tunnel_mode: request_mode.tunnel_mode(),
            retry_count,
            error_kind,
            terminal_overload_reason: None,
            terminal_outcome: context.terminal_outcome.clone(),
            empty_request_body_runtime: RequestBodyRuntime::empty(context.start),
            execution: RequestExecutionState::DispatchReady(state),
        }
    }

    pub(crate) fn from_awaiting_auth_state(
        state: AwaitingAuthState,
        upstream_pool: Arc<RwLock<UpstreamPool>>,
        routing_transparency_enabled: bool,
        routing_transparency_include_reason: bool,
        retry_count: u8,
        error_kind: Option<&'static str>,
    ) -> Self {
        let AwaitingAuthState {
            context,
            routing,
            request_mode,
            request_body: _,
            request_body_runtime: _,
            pending_forward: _,
            auth_result_rx: _,
            auth_abort: _,
            auth_deadline: _,
            auth_disposition: _,
        } = &state;

        Self {
            request_id: context.request_id,
            trace_id: context.trace_id.clone(),
            span_id: context.span_id.clone(),
            traceparent: context.traceparent.clone(),
            trace_span: context.trace_span.clone(),
            method: context.method.clone(),
            path: context.path.clone(),
            authority: context.authority.clone(),
            backend_addr: Some(routing.backend_addr.clone()),
            backend_index: Some(routing.backend_index),
            upstream_name: Some(routing.upstream_name.clone()),
            route_reason: Some(routing.route_reason.clone()),
            route_path_len: Some(routing.route_path_len),
            route_host_specific: Some(routing.route_host_specific),
            backend_lb: routing.backend_lb.clone(),
            upstream_pool: Some(upstream_pool),
            routing_transparency_enabled,
            routing_transparency_include_reason,
            response_status: None,
            start: context.start,
            total_request_deadline: context.total_request_deadline,
            bodyless_mode: request_mode.bodyless_mode(),
            tunnel_mode: request_mode.tunnel_mode(),
            retry_count,
            error_kind,
            terminal_overload_reason: None,
            terminal_outcome: context.terminal_outcome.clone(),
            empty_request_body_runtime: RequestBodyRuntime::empty(context.start),
            execution: RequestExecutionState::AwaitingAuth(state),
        }
    }

    pub fn mark_terminal_outcome_recorded(&mut self) {
        self.terminal_outcome.record();
    }

    #[cfg(test)]
    pub(crate) fn terminal_outcome_recorded(&self) -> bool {
        self.terminal_outcome.is_recorded()
    }

    pub fn phase(&self) -> StreamPhase {
        self.execution.phase()
    }

    pub fn admission_state(&self) -> StreamAdmissionState {
        self.execution.admission_state()
    }

    pub fn request_fin_received(&self) -> bool {
        self.request_body_state().request_fin_received()
    }

    pub fn set_request_fin_received(&mut self, value: bool) {
        self.request_body_runtime_mut().request_fin_received = value;
    }

    pub fn request_mode(&self) -> RequestMode {
        match &self.execution {
            RequestExecutionState::Intake(state) => state.request_mode,
            RequestExecutionState::AwaitingAuth(state) => state.request_mode,
            RequestExecutionState::DispatchReady(state) => state.request_mode,
            RequestExecutionState::Admitted(state) => state.request_mode,
            RequestExecutionState::AwaitingUpstream(state) => state.request_mode,
            RequestExecutionState::StreamingResponse(state) => state.request_mode,
            RequestExecutionState::Terminal(state) => terminal_request_mode(state),
        }
    }

    pub fn request_body_state(&self) -> RequestBodyState {
        match &self.execution {
            RequestExecutionState::Intake(state) => state.request_body,
            RequestExecutionState::AwaitingAuth(state) => state.request_body,
            RequestExecutionState::DispatchReady(state) => state.request_body,
            RequestExecutionState::Admitted(state) => state.request_body,
            RequestExecutionState::AwaitingUpstream(state) => state.request_body,
            RequestExecutionState::StreamingResponse(_) => RequestBodyState::from_runtime(
                self.request_body_runtime().request_fin_received,
                !self.request_body_runtime().body_buf.is_empty(),
                self.body_tx().is_some(),
            ),
            RequestExecutionState::Terminal(state) => terminal_request_mode(state)
                .initial_body_state()
                .on_forward_closed(),
        }
    }

    pub fn set_request_body_state(&mut self, next: RequestBodyState) {
        self.request_body_runtime_mut().request_fin_received = next.request_fin_received();
        match &mut self.execution {
            RequestExecutionState::Intake(state) => state.request_body = next,
            RequestExecutionState::AwaitingAuth(state) => state.request_body = next,
            RequestExecutionState::DispatchReady(state) => state.request_body = next,
            RequestExecutionState::Admitted(state) => state.request_body = next,
            RequestExecutionState::AwaitingUpstream(state) => state.request_body = next,
            RequestExecutionState::StreamingResponse(_) | RequestExecutionState::Terminal(_) => {}
        }
    }

    pub fn refresh_request_body_state(&mut self) -> RequestBodyState {
        let next = RequestBodyState::from_runtime(
            self.request_body_runtime().request_fin_received,
            !self.request_body_runtime().body_buf.is_empty(),
            self.body_tx().is_some(),
        );
        self.set_request_body_state(next);
        next
    }

    pub fn transition_request_body_buffered(&mut self) -> RequestBodyState {
        let next = self.request_body_state().on_buffered();
        self.set_request_body_state(next);
        next
    }

    pub fn transition_request_body_finished(&mut self) -> RequestBodyState {
        let next = self.request_body_state().on_downstream_finished();
        self.set_request_body_state(next);
        next
    }

    pub fn transition_request_body_forward_closed(&mut self) -> RequestBodyState {
        self.clear_body_tx();
        self.refresh_request_body_state()
    }

    pub fn should_close_request_body_forwarding(&self) -> bool {
        matches!(self.request_body_state(), RequestBodyState::FinReceived)
            && self.body_buf().is_empty()
            && self.body_tx().is_some()
    }

    pub fn can_accept_request_body(&self) -> bool {
        self.execution.can_accept_request_body()
    }

    pub fn can_poll_upstream(&self) -> bool {
        self.execution.can_poll_upstream()
    }

    pub fn can_poll_upstream_result(&self) -> bool {
        match &self.execution {
            RequestExecutionState::AwaitingUpstream(_) => {
                self.has_upstream_result_rx() && self.execution.can_poll_upstream()
            }
            _ => false,
        }
    }

    pub fn total_request_timeout_reason(&self) -> TimeoutReason {
        match &self.execution {
            RequestExecutionState::AwaitingAuth(_) => TimeoutReason::ExternalAuth,
            RequestExecutionState::StreamingResponse(_) => TimeoutReason::ResponseBodyTotal,
            RequestExecutionState::AwaitingUpstream(state) => {
                Self::pre_response_timeout_reason(state.request_mode, state.request_body)
            }
            RequestExecutionState::DispatchReady(state) => {
                Self::pre_response_timeout_reason(state.request_mode, state.request_body)
            }
            RequestExecutionState::Admitted(state) => {
                Self::pre_response_timeout_reason(state.request_mode, state.request_body)
            }
            RequestExecutionState::Intake(_) => TimeoutReason::RequestBodyTotal,
            RequestExecutionState::Terminal(state) => match state {
                TerminalState::TimedOut(state) => state.reason,
                _ => TimeoutReason::TotalRequest,
            },
        }
    }

    /// For pre-response states, requests still reading the client body time out
    /// under the request-body bucket; once intake is complete (or for tunnels)
    /// they time out under the await-upstream bucket.
    fn pre_response_timeout_reason(
        request_mode: RequestMode,
        request_body: RequestBodyState,
    ) -> TimeoutReason {
        if request_mode.is_tunnel() || request_body.request_fin_received() {
            TimeoutReason::AwaitingUpstream
        } else {
            TimeoutReason::RequestBodyTotal
        }
    }

    pub fn upstream_timeout_reason(&self) -> TimeoutReason {
        match &self.execution {
            RequestExecutionState::StreamingResponse(_) => TimeoutReason::ResponseBodyTotal,
            RequestExecutionState::AwaitingUpstream(_)
            | RequestExecutionState::DispatchReady(_)
            | RequestExecutionState::Admitted(_)
            | RequestExecutionState::AwaitingAuth(_) => TimeoutReason::AwaitingUpstream,
            RequestExecutionState::Intake(_) | RequestExecutionState::Terminal(_) => {
                TimeoutReason::AwaitingUpstream
            }
        }
    }

    pub fn body_tx(&self) -> Option<&mpsc::Sender<Bytes>> {
        match &self.execution {
            RequestExecutionState::AwaitingUpstream(state) => state.dispatch.body_tx.as_ref(),
            _ => None,
        }
    }

    pub fn clear_body_tx(&mut self) {
        if let RequestExecutionState::AwaitingUpstream(state) = &mut self.execution {
            state.dispatch.body_tx = None;
        }
        self.refresh_request_body_state();
    }

    pub fn body_buf(&self) -> &VecDeque<Bytes> {
        &self.request_body_runtime().body_buf
    }

    pub fn body_buf_mut(&mut self) -> &mut VecDeque<Bytes> {
        &mut self.request_body_runtime_mut().body_buf
    }

    pub fn body_buf_bytes(&self) -> usize {
        self.request_body_runtime().body_buf_bytes
    }

    pub fn set_body_buf_bytes(&mut self, value: usize) {
        self.request_body_runtime_mut().body_buf_bytes = value;
    }

    pub fn body_bytes_received(&self) -> usize {
        self.request_body_runtime().body_bytes_received
    }

    pub fn set_body_bytes_received(&mut self, value: usize) {
        self.request_body_runtime_mut().body_bytes_received = value;
    }

    pub fn last_body_activity(&self) -> Instant {
        self.request_body_runtime().last_body_activity
    }

    pub fn set_last_body_activity(&mut self, value: Instant) {
        self.request_body_runtime_mut().last_body_activity = value;
    }

    pub fn pending_forward(&self) -> Option<&Arc<PendingForward>> {
        match &self.execution {
            RequestExecutionState::AwaitingAuth(state) => Some(&state.pending_forward),
            RequestExecutionState::DispatchReady(state) => Some(&state.pending_forward),
            RequestExecutionState::Admitted(state) => Some(&state.pending_forward),
            RequestExecutionState::AwaitingUpstream(state) => Some(&state.pending_forward),
            RequestExecutionState::Intake(_)
            | RequestExecutionState::StreamingResponse(_)
            | RequestExecutionState::Terminal(_) => None,
        }
    }

    pub fn pending_forward_mut(&mut self) -> Option<&mut Arc<PendingForward>> {
        match &mut self.execution {
            RequestExecutionState::AwaitingAuth(state) => Some(&mut state.pending_forward),
            RequestExecutionState::DispatchReady(state) => Some(&mut state.pending_forward),
            RequestExecutionState::Admitted(state) => Some(&mut state.pending_forward),
            RequestExecutionState::AwaitingUpstream(state) => Some(&mut state.pending_forward),
            RequestExecutionState::Intake(_)
            | RequestExecutionState::StreamingResponse(_)
            | RequestExecutionState::Terminal(_) => None,
        }
    }

    pub(crate) fn poll_awaiting_auth_non_blocking(
        &mut self,
        now: Instant,
    ) -> Option<ExternalAuthResult> {
        match &mut self.execution {
            RequestExecutionState::AwaitingAuth(state) => state.poll_non_blocking(now),
            _ => None,
        }
    }

    pub(crate) fn upstream_result_rx_mut(
        &mut self,
    ) -> Option<&mut oneshot::Receiver<UpstreamResult>> {
        match &mut self.execution {
            RequestExecutionState::AwaitingUpstream(state) => {
                Some(&mut state.dispatch.upstream_result_rx)
            }
            _ => None,
        }
    }

    pub(crate) fn response_chunk_rx_mut(&mut self) -> Option<&mut mpsc::Receiver<ResponseChunk>> {
        match &mut self.execution {
            RequestExecutionState::StreamingResponse(state) => Some(&mut state.response_chunk_rx),
            _ => None,
        }
    }

    pub fn has_upstream_result_rx(&self) -> bool {
        matches!(&self.execution, RequestExecutionState::AwaitingUpstream(_))
    }

    pub fn has_response_chunk_rx(&self) -> bool {
        matches!(&self.execution, RequestExecutionState::StreamingResponse(_))
    }

    pub fn response_headers_sent(&self) -> bool {
        match &self.execution {
            RequestExecutionState::StreamingResponse(state) => {
                !matches!(state.emission, ResponseEmissionState::DeferredHeaders)
            }
            _ => false,
        }
    }

    pub fn set_response_headers_sent(&mut self, sent: bool) {
        if let RequestExecutionState::StreamingResponse(state) = &mut self.execution {
            state.emission = if sent {
                ResponseEmissionState::HeadersSent
            } else {
                ResponseEmissionState::DeferredHeaders
            };
        }
    }

    pub(crate) fn take_pending_chunk(&mut self) -> Option<ResponseChunk> {
        match &mut self.execution {
            RequestExecutionState::StreamingResponse(state) => {
                match std::mem::replace(&mut state.backpressure, ResponseBackpressureState::Ready) {
                    ResponseBackpressureState::Ready => None,
                    ResponseBackpressureState::Blocked(chunk) => Some(chunk),
                }
            }
            _ => None,
        }
    }

    pub(crate) fn set_pending_chunk(&mut self, chunk: Option<ResponseChunk>) {
        if let RequestExecutionState::StreamingResponse(state) = &mut self.execution {
            state.backpressure = match chunk {
                Some(chunk) => ResponseBackpressureState::Blocked(chunk),
                None => ResponseBackpressureState::Ready,
            };
        }
    }

    pub fn has_pending_chunk(&self) -> bool {
        match &self.execution {
            RequestExecutionState::StreamingResponse(state) => {
                matches!(state.backpressure, ResponseBackpressureState::Blocked(_))
            }
            _ => false,
        }
    }

    pub fn response_emission_state(&self) -> Option<ResponseEmissionState> {
        match &self.execution {
            RequestExecutionState::StreamingResponse(state) => Some(state.emission),
            _ => None,
        }
    }

    pub fn set_response_emission_state(&mut self, emission: ResponseEmissionState) {
        if let RequestExecutionState::StreamingResponse(state) = &mut self.execution {
            state.emission = emission;
        }
    }

    pub fn backend_request_started(&self) -> bool {
        match &self.execution {
            RequestExecutionState::Admitted(_) => false,
            RequestExecutionState::AwaitingUpstream(_)
            | RequestExecutionState::StreamingResponse(_) => true,
            _ => false,
        }
    }

    pub fn backend_request_finished(&self) -> bool {
        match &self.execution {
            RequestExecutionState::AwaitingUpstream(state) => {
                state.dispatch.backend_accounting.finalized
            }
            RequestExecutionState::StreamingResponse(state) => state.backend_accounting.finalized,
            _ => false,
        }
    }

    pub fn set_backend_request_state(&mut self, started: bool, finished: bool) {
        match &mut self.execution {
            RequestExecutionState::AwaitingUpstream(state) => {
                state.dispatch.backend_accounting.finalized = started && finished;
            }
            RequestExecutionState::StreamingResponse(state) => {
                state.backend_accounting.finalized = started && finished;
            }
            _ => {}
        }
    }

    pub fn has_global_inflight_permit(&self) -> bool {
        matches!(
            &self.execution,
            RequestExecutionState::Admitted(_)
                | RequestExecutionState::AwaitingUpstream(_)
                | RequestExecutionState::StreamingResponse(_)
        )
    }

    pub fn has_upstream_inflight_permit(&self) -> bool {
        matches!(
            &self.execution,
            RequestExecutionState::Admitted(_)
                | RequestExecutionState::AwaitingUpstream(_)
                | RequestExecutionState::StreamingResponse(_)
        )
    }

    pub fn has_adaptive_admission_permit(&self) -> bool {
        matches!(
            &self.execution,
            RequestExecutionState::Admitted(_)
                | RequestExecutionState::AwaitingUpstream(_)
                | RequestExecutionState::StreamingResponse(_)
        )
    }

    pub fn has_route_queue_permit(&self) -> bool {
        matches!(
            &self.execution,
            RequestExecutionState::Admitted(_)
                | RequestExecutionState::AwaitingUpstream(_)
                | RequestExecutionState::StreamingResponse(_)
        )
    }

    pub(crate) fn transition_to_admitted(
        &mut self,
        permits: AdmissionPermits,
    ) -> Result<(), RequestStateError> {
        let snapshot = self.terminal_snapshot();
        let state = match std::mem::replace(
            &mut self.execution,
            RequestExecutionState::Terminal(TerminalState::Cancelled(CancelledState {
                reason: CancellationReason::OperatorAbort,
                snapshot,
            })),
        ) {
            RequestExecutionState::DispatchReady(state) => state,
            other => {
                self.execution = other;
                return Err(RequestStateError::InvalidTransition {
                    from: self.phase(),
                    attempted: "transition_to_admitted",
                });
            }
        };
        self.execution = RequestExecutionState::Admitted(AdmittedState {
            context: state.context,
            routing: state.routing,
            request_mode: state.request_mode,
            request_body: state.request_body,
            request_body_runtime: state.request_body_runtime,
            pending_forward: state.pending_forward,
            permits,
        });
        Ok(())
    }

    pub(crate) fn transition_admitted_to_awaiting_upstream(
        &mut self,
        body_tx: Option<mpsc::Sender<Bytes>>,
        upstream_result_rx: oneshot::Receiver<UpstreamResult>,
    ) -> Result<(), RequestStateError> {
        let snapshot = self.terminal_snapshot();
        let admitted = match std::mem::replace(
            &mut self.execution,
            RequestExecutionState::Terminal(TerminalState::Cancelled(CancelledState {
                reason: CancellationReason::OperatorAbort,
                snapshot,
            })),
        ) {
            RequestExecutionState::Admitted(state) => state,
            other => {
                self.execution = other;
                return Err(RequestStateError::InvalidTransition {
                    from: self.phase(),
                    attempted: "transition_admitted_to_awaiting_upstream",
                });
            }
        };
        let dispatch_body_tx = if admitted.request_body_runtime.request_fin_received
            && admitted.request_body_runtime.body_buf.is_empty()
        {
            None
        } else {
            body_tx
        };
        let backend_accounting = BackendAccountingState {
            response_status: None,
            finalized: false,
        };
        let AdmittedState {
            context,
            routing,
            request_mode,
            request_body: _,
            request_body_runtime,
            pending_forward,
            permits,
        } = admitted;
        let request_body = RequestBodyState::from_runtime(
            request_body_runtime.request_fin_received,
            !request_body_runtime.body_buf.is_empty(),
            dispatch_body_tx.is_some(),
        );
        self.execution = RequestExecutionState::AwaitingUpstream(AwaitingUpstreamState {
            context,
            routing,
            request_mode,
            request_body,
            request_body_runtime,
            pending_forward,
            permits,
            dispatch: BackendDispatchState {
                body_tx: dispatch_body_tx,
                upstream_result_rx,
                backend_accounting,
            },
        });
        Ok(())
    }

    pub(crate) fn transition_to_streaming_response(
        &mut self,
        response_chunk_rx: mpsc::Receiver<ResponseChunk>,
        emission: ResponseEmissionState,
        final_status: http::StatusCode,
    ) -> Result<(), RequestStateError> {
        let snapshot = self.terminal_snapshot();
        match std::mem::replace(
            &mut self.execution,
            RequestExecutionState::Terminal(TerminalState::Cancelled(CancelledState {
                reason: CancellationReason::OperatorAbort,
                snapshot,
            })),
        ) {
            RequestExecutionState::AwaitingUpstream(state) => {
                self.execution = RequestExecutionState::StreamingResponse(ResponseStreamingState {
                    context: state.context,
                    routing: state.routing,
                    request_mode: state.request_mode,
                    request_body_runtime: state.request_body_runtime,
                    permits: state.permits,
                    final_status,
                    emission,
                    response_chunk_rx,
                    backpressure: ResponseBackpressureState::Ready,
                    backend_accounting: state.dispatch.backend_accounting,
                });
                Ok(())
            }
            other => {
                self.execution = other;
                Err(RequestStateError::InvalidTransition {
                    from: self.phase(),
                    attempted: "transition_to_streaming_response",
                })
            }
        }
    }

    pub(crate) fn transition_streaming_to_completed(
        &mut self,
        reason: CompletionReason,
        metrics: &Metrics,
    ) {
        self.transition_to_terminal_with_cleanup(TerminalReason::Completed(reason), metrics);
    }

    pub(crate) fn transition_streaming_to_backend_failed(
        &mut self,
        reason: BackendFailureReason,
        metrics: &Metrics,
    ) {
        self.transition_to_terminal_with_cleanup(TerminalReason::BackendFailed(reason), metrics);
    }

    pub(crate) fn transition_streaming_to_timed_out(
        &mut self,
        reason: TimeoutReason,
        metrics: &Metrics,
    ) {
        self.transition_to_terminal_with_cleanup(TerminalReason::TimedOut(reason), metrics);
    }

    pub fn transition_to_terminal(
        &mut self,
        terminal: crate::runtime::connection::stream::TerminalState,
    ) {
        self.execution = RequestExecutionState::Terminal(terminal);
    }

    pub(crate) fn transition_awaiting_auth_to_dispatch_ready<I>(
        &mut self,
        mutations: I,
    ) -> Result<(), RequestStateError>
    where
        I: IntoIterator<Item = PendingHeaderMutation>,
    {
        let state = match self.take_awaiting_auth_state() {
            Some(state) => {
                let mut state = state;
                crate::runtime::connection::auth::merge_auth_request_mutations(
                    &mut Arc::make_mut(&mut state.pending_forward).auth_header_mutations,
                    mutations,
                );
                state
            }
            None => {
                return Err(RequestStateError::InvalidTransition {
                    from: self.phase(),
                    attempted: "transition_awaiting_auth_to_dispatch_ready",
                });
            }
        };
        self.execution = RequestExecutionState::DispatchReady(DispatchReadyState {
            context: state.context,
            routing: state.routing,
            request_mode: state.request_mode,
            request_body: state.request_body,
            request_body_runtime: state.request_body_runtime,
            pending_forward: state.pending_forward,
        });
        Ok(())
    }

    pub(crate) fn take_awaiting_auth_state(&mut self) -> Option<AwaitingAuthState> {
        let placeholder =
            RequestExecutionState::Terminal(TerminalState::Cancelled(CancelledState {
                reason: CancellationReason::OperatorAbort,
                snapshot: self.terminal_snapshot(),
            }));
        match std::mem::replace(&mut self.execution, placeholder) {
            RequestExecutionState::AwaitingAuth(state) => {
                state.auth_abort.abort();
                Some(state)
            }
            other => {
                self.execution = other;
                None
            }
        }
    }

    pub(crate) fn transition_to_terminal_with_cleanup(
        &mut self,
        reason: TerminalReason,
        metrics: &Metrics,
    ) -> StreamPhase {
        let prior_phase = self.phase();
        if self.execution.is_terminal() {
            return prior_phase;
        }

        let snapshot = self.terminal_snapshot();
        let terminal_state = reason.into_terminal_state(snapshot.clone());
        if self.terminal_outcome.record() {
            let _ = observe_terminal_request_outcome(metrics, &terminal_state);
        }
        let should_finalize_backend = self.execution.should_finalize_backend_accounting();
        let buffered_body_bytes = Self::buffered_request_body_bytes(&self.execution);
        let finalize_status = reason
            .terminal_status(&snapshot)
            .or(snapshot.response_status)
            .map(|status| status.as_u16())
            .or(Some(503));

        let placeholder =
            RequestExecutionState::Terminal(TerminalState::Cancelled(CancelledState {
                reason: CancellationReason::OperatorAbort,
                snapshot: snapshot.clone(),
            }));
        let prior_execution = std::mem::replace(&mut self.execution, placeholder);

        if let RequestExecutionState::AwaitingAuth(state) = &prior_execution {
            state.auth_abort.abort();
        }

        if should_finalize_backend {
            let _ = finalize_backend_request_cleanup(
                BackendRequestFinishInput {
                    upstream_pool: self.upstream_pool.as_ref(),
                    backend_index: self.backend_index,
                    elapsed: self.start.elapsed(),
                    status: finalize_status,
                },
                true,
            );
        }

        if buffered_body_bytes > 0 {
            metrics.release_request_buffer(buffered_body_bytes);
        }

        self.execution = RequestExecutionState::Terminal(terminal_state);
        prior_phase
    }

    fn request_body_runtime(&self) -> &RequestBodyRuntime {
        match &self.execution {
            RequestExecutionState::Intake(_) => &self.empty_request_body_runtime,
            RequestExecutionState::AwaitingAuth(state) => &state.request_body_runtime,
            RequestExecutionState::DispatchReady(state) => &state.request_body_runtime,
            RequestExecutionState::Admitted(state) => &state.request_body_runtime,
            RequestExecutionState::AwaitingUpstream(state) => &state.request_body_runtime,
            RequestExecutionState::StreamingResponse(state) => &state.request_body_runtime,
            RequestExecutionState::Terminal(_) => &self.empty_request_body_runtime,
        }
    }

    fn request_body_runtime_mut(&mut self) -> &mut RequestBodyRuntime {
        match &mut self.execution {
            RequestExecutionState::Intake(_) => &mut self.empty_request_body_runtime,
            RequestExecutionState::AwaitingAuth(state) => &mut state.request_body_runtime,
            RequestExecutionState::DispatchReady(state) => &mut state.request_body_runtime,
            RequestExecutionState::Admitted(state) => &mut state.request_body_runtime,
            RequestExecutionState::AwaitingUpstream(state) => &mut state.request_body_runtime,
            RequestExecutionState::StreamingResponse(state) => &mut state.request_body_runtime,
            RequestExecutionState::Terminal(_) => &mut self.empty_request_body_runtime,
        }
    }

    fn buffered_request_body_bytes(execution: &RequestExecutionState) -> usize {
        match execution {
            RequestExecutionState::AwaitingAuth(state) => state.request_body_runtime.body_buf_bytes,
            RequestExecutionState::DispatchReady(state) => {
                state.request_body_runtime.body_buf_bytes
            }
            RequestExecutionState::Admitted(state) => state.request_body_runtime.body_buf_bytes,
            RequestExecutionState::AwaitingUpstream(state) => {
                state.request_body_runtime.body_buf_bytes
            }
            RequestExecutionState::StreamingResponse(state) => {
                state.request_body_runtime.body_buf_bytes
            }
            RequestExecutionState::Intake(_) | RequestExecutionState::Terminal(_) => 0,
        }
    }

    fn terminal_snapshot(&self) -> TerminalSnapshot {
        let routing = match &self.execution {
            RequestExecutionState::AwaitingAuth(state) => Some(state.routing.clone()),
            RequestExecutionState::DispatchReady(state) => Some(state.routing.clone()),
            RequestExecutionState::Admitted(state) => Some(state.routing.clone()),
            RequestExecutionState::AwaitingUpstream(state) => Some(state.routing.clone()),
            RequestExecutionState::StreamingResponse(state) => Some(state.routing.clone()),
            RequestExecutionState::Intake(_) => None,
            RequestExecutionState::Terminal(state) => match state {
                TerminalState::Completed(state) => state.snapshot.routing.clone(),
                TerminalState::Cancelled(state) => state.snapshot.routing.clone(),
                TerminalState::TimedOut(state) => state.snapshot.routing.clone(),
                TerminalState::Rejected(state) => state.snapshot.routing.clone(),
                TerminalState::BackendFailed(state) => state.snapshot.routing.clone(),
            },
        };

        TerminalSnapshot {
            context: RequestContext {
                request_id: self.request_id,
                trace_id: self.trace_id.clone(),
                span_id: self.span_id.clone(),
                traceparent: self.traceparent.clone(),
                trace_span: self.trace_span.clone(),
                method: self.method.clone(),
                path: self.path.clone(),
                authority: self.authority.clone(),
                start: self.start,
                total_request_deadline: self.total_request_deadline,
                terminal_outcome: self.terminal_outcome.clone(),
            },
            routing,
            request_mode: RequestMode::from_intake(self.tunnel_mode, &self.method, None),
            response_status: self
                .response_status
                .and_then(|status| http::StatusCode::from_u16(status).ok()),
            overload_reason: self.terminal_overload_reason,
            backend_accounting: match &self.execution {
                RequestExecutionState::AwaitingUpstream(state) => {
                    Some(state.dispatch.backend_accounting)
                }
                RequestExecutionState::StreamingResponse(state) => Some(state.backend_accounting),
                _ => None,
            },
        }
    }
}

fn terminal_request_mode(state: &TerminalState) -> RequestMode {
    match state {
        TerminalState::Completed(state) => state.snapshot.request_mode,
        TerminalState::Cancelled(state) => state.snapshot.request_mode,
        TerminalState::TimedOut(state) => state.snapshot.request_mode,
        TerminalState::Rejected(state) => state.snapshot.request_mode,
        TerminalState::BackendFailed(state) => state.snapshot.request_mode,
    }
}

#[derive(Debug, Clone)]
pub struct PendingForward {
    pub method: Arc<str>,
    pub path: Arc<str>,
    pub authority: Option<Arc<str>>,
    pub headers: Arc<Vec<quiche::h3::Header>>,
    pub upstream_name: Arc<str>,
    pub route_reason: Arc<str>,
    pub route_path_len: usize,
    pub route_host_specific: bool,
    pub backend_addr: Arc<str>,
    pub backend_index: usize,
    pub backend_lb: Option<Arc<str>>,
    pub client_addr: SocketAddr,
    pub request_id: u64,
    pub trace_id: Option<Arc<str>>,
    pub span_id: Option<Arc<str>>,
    pub traceparent: Option<Arc<str>>,
    pub host_policy: UpstreamHostPolicy,
    pub forwarded_header_policy: ForwardedHeaderPolicy,
    pub(crate) auth_header_mutations: Vec<PendingHeaderMutation>,
}

#[cfg(test)]
impl PendingForward {
    /// Baseline forward for tests: a plain GET with default host and forwarded
    /// policies. Override individual fields with struct update syntax so adding a
    /// field to `PendingForward` only touches this constructor.
    pub(crate) fn sample_for_test(headers: Vec<quiche::h3::Header>) -> Self {
        Self {
            method: Arc::<str>::from("GET"),
            path: Arc::<str>::from("/v1/chat"),
            authority: Some(Arc::<str>::from("api.example.com")),
            headers: Arc::new(headers),
            upstream_name: Arc::<str>::from("api"),
            route_reason: Arc::<str>::from("path_prefix"),
            route_path_len: 8,
            route_host_specific: true,
            backend_addr: Arc::<str>::from("backend.internal:443"),
            backend_index: 0,
            backend_lb: None,
            client_addr: "203.0.113.55:43210".parse().expect("client addr"),
            request_id: 17,
            trace_id: None,
            span_id: None,
            traceparent: None,
            host_policy: UpstreamHostPolicy::default(),
            forwarded_header_policy: ForwardedHeaderPolicy::default(),
            auth_header_mutations: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, atomic::Ordering},
        time::{Duration, Instant},
    };

    use bytes::Bytes;
    use http::StatusCode;
    use tokio::sync::{Semaphore, mpsc, oneshot};

    use super::*;
    use crate::resilience::{
        adaptive_admission::AdaptiveAdmission, route_queue::RouteQueueLimiter,
    };

    fn make_request_context(start: Instant) -> RequestContext {
        RequestContext {
            request_id: 42,
            trace_id: None,
            span_id: None,
            traceparent: None,
            trace_span: None,
            method: "POST".into(),
            path: "/upload".into(),
            authority: Some("example.com".into()),
            start,
            total_request_deadline: start + Duration::from_secs(30),
            terminal_outcome: TerminalOutcomeGuard::default(),
        }
    }

    fn make_routing_snapshot() -> crate::runtime::connection::stream::RoutingSnapshot {
        crate::runtime::connection::stream::RoutingSnapshot {
            backend_addr: "http://127.0.0.1:8080".into(),
            backend_index: 0,
            upstream_name: "api".into(),
            route_reason: "path_prefix".into(),
            route_path_len: 1,
            route_host_specific: false,
            backend_lb: None,
        }
    }

    fn make_pending_forward() -> Arc<PendingForward> {
        Arc::new(PendingForward {
            method: Arc::<str>::from("POST"),
            path: Arc::<str>::from("/upload"),
            authority: Some(Arc::<str>::from("example.com")),
            upstream_name: Arc::<str>::from("api"),
            route_path_len: 1,
            route_host_specific: false,
            backend_addr: Arc::<str>::from("http://127.0.0.1:8080"),
            client_addr: "127.0.0.1:443".parse().expect("client addr"),
            request_id: 42,
            ..PendingForward::sample_for_test(vec![quiche::h3::Header::new(b":method", b"POST")])
        })
    }

    fn make_admitted_envelope(
        start: Instant,
        body_buf: VecDeque<Bytes>,
        body_buf_bytes: usize,
        request_fin_received: bool,
    ) -> (
        RequestEnvelope,
        Arc<Semaphore>,
        Arc<Semaphore>,
        Arc<AdaptiveAdmission>,
        Arc<RouteQueueLimiter>,
    ) {
        let global_sem = Arc::new(Semaphore::new(1));
        let upstream_sem = Arc::new(Semaphore::new(1));
        let adaptive = Arc::new(AdaptiveAdmission::new(false, 1, 100, 1, 1, 1000));
        let route_limiter = Arc::new(RouteQueueLimiter::new(100, 1000, Default::default()));
        let context = make_request_context(start);
        let routing = make_routing_snapshot();

        let req = RequestEnvelope {
            request_id: context.request_id,
            trace_id: context.trace_id.clone(),
            span_id: context.span_id.clone(),
            traceparent: context.traceparent.clone(),
            trace_span: context.trace_span.clone(),
            method: context.method.clone(),
            path: context.path.clone(),
            authority: context.authority.clone(),
            backend_addr: Some(routing.backend_addr.clone()),
            backend_index: Some(routing.backend_index),
            upstream_name: Some(routing.upstream_name.clone()),
            route_reason: Some(routing.route_reason.clone()),
            route_path_len: Some(routing.route_path_len),
            route_host_specific: Some(routing.route_host_specific),
            backend_lb: routing.backend_lb.clone(),
            upstream_pool: None,
            routing_transparency_enabled: false,
            routing_transparency_include_reason: false,
            response_status: None,
            start,
            total_request_deadline: context.total_request_deadline,
            bodyless_mode: false,
            tunnel_mode: TunnelMode::None,
            retry_count: 0,
            error_kind: None,
            terminal_overload_reason: None,
            terminal_outcome: context.terminal_outcome.clone(),
            empty_request_body_runtime: RequestBodyRuntime::empty(start),
            execution: RequestExecutionState::Admitted(AdmittedState {
                context,
                routing,
                request_mode: RequestMode::Normal,
                request_body: RequestBodyState::Open,
                request_body_runtime: RequestBodyRuntime {
                    body_buf,
                    body_buf_bytes,
                    body_bytes_received: body_buf_bytes,
                    last_body_activity: start,
                    request_fin_received,
                },
                pending_forward: make_pending_forward(),
                permits: AdmissionPermits {
                    global: global_sem
                        .clone()
                        .try_acquire_owned()
                        .expect("global permit"),
                    upstream: upstream_sem
                        .clone()
                        .try_acquire_owned()
                        .expect("upstream permit"),
                    adaptive: adaptive.try_acquire().expect("adaptive permit"),
                    route_queue: route_limiter
                        .try_acquire("test")
                        .expect("route queue permit"),
                },
            }),
        };

        (req, global_sem, upstream_sem, adaptive, route_limiter)
    }

    #[test]
    fn transition_to_terminal_releases_buffer_and_records_once() {
        let metrics = Metrics::default();
        let start = Instant::now();
        let mut body_buf = VecDeque::new();
        body_buf.push_back(Bytes::from_static(b"payload"));
        let (mut req, global_sem, upstream_sem, _adaptive, route_limiter) =
            make_admitted_envelope(start, body_buf, 7, false);

        assert!(metrics.try_reserve_request_buffer(7, 64));

        let phase = req.transition_to_terminal_with_cleanup(
            TerminalReason::Rejected(
                crate::runtime::connection::stream::RejectionReason::RequestBodyTooLarge,
            ),
            &metrics,
        );

        assert_eq!(phase, StreamPhase::ReceivingRequest);
        assert_eq!(req.phase(), StreamPhase::Terminal);
        assert!(req.terminal_outcome_recorded());
        assert_eq!(metrics.request_buffered_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.requests_failure.load(Ordering::Relaxed), 1);
        assert_eq!(global_sem.available_permits(), 1);
        assert_eq!(upstream_sem.available_permits(), 1);
        assert!(route_limiter.try_acquire("test").is_ok());

        let second_phase = req.transition_to_terminal_with_cleanup(
            TerminalReason::Cancelled(CancellationReason::ClientReset),
            &metrics,
        );

        assert_eq!(second_phase, StreamPhase::Terminal);
        assert_eq!(metrics.request_buffered_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.requests_failure.load(Ordering::Relaxed), 1);
        assert_eq!(global_sem.available_permits(), 1);
        assert_eq!(upstream_sem.available_permits(), 1);
    }

    #[test]
    fn transition_to_terminal_does_not_record_duplicate_outcome() {
        let metrics = Metrics::default();
        let start = Instant::now();
        let (mut req, global_sem, upstream_sem, _adaptive, route_limiter) =
            make_admitted_envelope(start, VecDeque::new(), 0, true);
        let (_result_tx, result_rx) = oneshot::channel();
        let (_chunk_tx, chunk_rx) = mpsc::channel(1);

        req.transition_admitted_to_awaiting_upstream(None, result_rx)
            .expect("admitted to awaiting upstream");
        req.transition_to_streaming_response(
            chunk_rx,
            ResponseEmissionState::HeadersSent,
            StatusCode::OK,
        )
        .expect("awaiting upstream to streaming response");
        req.mark_terminal_outcome_recorded();

        let phase = req.transition_to_terminal_with_cleanup(
            TerminalReason::BackendFailed(BackendFailureReason::ResponseStreamAborted),
            &metrics,
        );

        assert_eq!(phase, StreamPhase::SendingResponse);
        assert_eq!(req.phase(), StreamPhase::Terminal);
        assert!(req.terminal_outcome_recorded());
        assert_eq!(metrics.requests_failure.load(Ordering::Relaxed), 0);
        assert_eq!(global_sem.available_permits(), 1);
        assert_eq!(upstream_sem.available_permits(), 1);
        assert!(route_limiter.try_acquire("test").is_ok());
    }

    #[test]
    fn invalid_transitions_return_error_instead_of_panicking() {
        let start = Instant::now();
        let context = make_request_context(start);
        let mut dispatch_ready = RequestEnvelope {
            request_id: 1,
            trace_id: None,
            span_id: None,
            traceparent: None,
            trace_span: None,
            method: "GET".into(),
            path: "/".into(),
            authority: None,
            backend_addr: None,
            backend_index: None,
            upstream_name: None,
            route_reason: None,
            route_path_len: None,
            route_host_specific: None,
            backend_lb: None,
            upstream_pool: None,
            routing_transparency_enabled: false,
            routing_transparency_include_reason: false,
            response_status: None,
            start,
            total_request_deadline: start,
            bodyless_mode: false,
            tunnel_mode: TunnelMode::None,
            retry_count: 0,
            error_kind: None,
            terminal_overload_reason: None,
            terminal_outcome: context.terminal_outcome.clone(),
            empty_request_body_runtime: RequestBodyRuntime::empty(start),
            execution: RequestExecutionState::DispatchReady(DispatchReadyState {
                context,
                routing: make_routing_snapshot(),
                request_mode: RequestMode::Normal,
                request_body: RequestBodyState::Open,
                request_body_runtime: RequestBodyRuntime::empty(start),
                pending_forward: make_pending_forward(),
            }),
        };
        let err = dispatch_ready
            .transition_admitted_to_awaiting_upstream(None, oneshot::channel().1)
            .expect_err("dispatch-ready must reject admitted-only transition");
        assert_eq!(
            err,
            RequestStateError::InvalidTransition {
                from: StreamPhase::ReceivingRequest,
                attempted: "transition_admitted_to_awaiting_upstream",
            }
        );

        let (mut admitted, ..) = make_admitted_envelope(start, VecDeque::new(), 0, false);
        let err = admitted
            .transition_to_streaming_response(
                mpsc::channel(1).1,
                ResponseEmissionState::HeadersSent,
                StatusCode::OK,
            )
            .expect_err("admitted must reject streaming transition");
        assert_eq!(
            err,
            RequestStateError::InvalidTransition {
                from: StreamPhase::ReceivingRequest,
                attempted: "transition_to_streaming_response",
            }
        );
    }

    #[test]
    fn terminal_body_runtime_access_uses_empty_fallback() {
        let metrics = Metrics::default();
        let start = Instant::now();
        let (mut req, ..) = make_admitted_envelope(start, VecDeque::new(), 0, false);

        req.transition_to_terminal_with_cleanup(
            TerminalReason::Cancelled(CancellationReason::ClientReset),
            &metrics,
        );

        req.set_request_fin_received(true);
        req.set_body_buf_bytes(99);
        req.set_body_bytes_received(77);
        req.set_last_body_activity(start + std::time::Duration::from_secs(1));

        // Terminal request-body state always derives to `ClosedToUpstream`, which
        // reports fin-received regardless of the (no-op) runtime flag set above.
        assert!(req.request_fin_received());
        assert!(req.body_buf().is_empty());
        assert_eq!(req.body_buf_bytes(), 99);
        assert_eq!(req.body_bytes_received(), 77);
        assert_eq!(
            req.last_body_activity(),
            start + std::time::Duration::from_secs(1)
        );
        assert_eq!(req.request_body_state(), RequestBodyState::ClosedToUpstream);
    }
}
