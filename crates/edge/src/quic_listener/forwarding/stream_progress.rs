use super::{orchestration_service::ForwardingOrchestrationService, *};
use crate::runtime::connection::{
    guardrails::{
        BodyLimitKind, BodyTimeoutKind, RequestBodyGuardrailConfig, RequestBodyGuardrailDecision,
        RequestBodyGuardrailInput, checked_request_body_ingress, evaluate_request_body_timeouts,
    },
    response::ForwardingPolicyTelemetry,
    stream::{CompletionReason, RequestBodyState, TimeoutReason},
};

impl QUICListener {
    pub(in crate::quic_listener) fn push_request_chunk(
        req: &mut RequestEnvelope,
        chunk: Bytes,
        metrics: &Metrics,
        max_request_body_bytes: usize,
        request_buffer_global_cap_bytes: usize,
    ) -> Result<(), RequestBufferError> {
        let chunk_len = chunk.len();
        if !metrics.try_reserve_request_buffer(chunk_len, request_buffer_global_cap_bytes) {
            return Err(RequestBufferError::Global);
        }

        let next_state = checked_request_body_ingress(
            RequestBodyGuardrailConfig {
                idle_timeout: Duration::ZERO,
                total_timeout: Duration::ZERO,
                max_body_bytes: max_request_body_bytes,
                max_buffered_bytes: max_request_body_bytes,
            },
            RequestBodyGuardrailInput {
                elapsed: Duration::ZERO,
                idle_for: Duration::ZERO,
                // The ingress path already advanced total bytes_received for this
                // downstream read before chunk buffering begins. Subtract the
                // current chunk here so total-body cap validation is not applied
                // twice when backpressure forces buffering.
                bytes_received: req.body_bytes_received().saturating_sub(chunk_len),
                buffered_bytes: req.body_buf_bytes(),
                next_chunk_bytes: chunk_len,
                declared_content_length: None,
                exempt_from_body_size_cap: false,
            },
        );
        let Ok(next_state) = next_state else {
            metrics.release_request_buffer(chunk_len);
            return Err(match next_state {
                Err(RequestBodyGuardrailDecision::Reject {
                    kind: BodyLimitKind::BodySize,
                }) => RequestBufferError::BodySize,
                Err(RequestBodyGuardrailDecision::Reject { .. }) => RequestBufferError::Stream,
                Err(other) => unreachable!(
                    "request ingress should not timeout in enqueue path: {:?}",
                    other
                ),
                Ok(_) => unreachable!("handled Ok state before request buffer error mapping"),
            });
        };
        req.set_body_buf_bytes(next_state.buffered_bytes);
        req.body_buf_mut().push_back(chunk);
        req.transition_request_body_buffered();
        Ok(())
    }

    pub(in crate::quic_listener) fn enqueue_request_chunk(
        req: &mut RequestEnvelope,
        chunk: Bytes,
        metrics: &Metrics,
        max_request_body_bytes: usize,
        request_buffer_global_cap_bytes: usize,
    ) -> Result<(), RequestBufferError> {
        if !req.can_accept_request_body() {
            return Ok(());
        }

        if let Some(tx) = req.body_tx().cloned() {
            match tx.try_send(chunk) {
                Ok(()) => Ok(()),
                Err(TrySendError::Full(chunk)) => Self::push_request_chunk(
                    req,
                    chunk,
                    metrics,
                    max_request_body_bytes,
                    request_buffer_global_cap_bytes,
                ),
                Err(TrySendError::Closed(_chunk)) => {
                    if req.body_buf_bytes() > 0 {
                        metrics.release_request_buffer(req.body_buf_bytes());
                    }
                    req.body_buf_mut().clear();
                    req.set_body_buf_bytes(0);
                    req.transition_request_body_forward_closed();
                    Ok(())
                }
            }
        } else {
            Self::push_request_chunk(
                req,
                chunk,
                metrics,
                max_request_body_bytes,
                request_buffer_global_cap_bytes,
            )
        }
    }

    pub(in crate::quic_listener) fn flush_request_buffer(
        req: &mut RequestEnvelope,
        metrics: &Metrics,
    ) -> RequestBodyState {
        let Some(tx) = req.body_tx().cloned() else {
            return req.refresh_request_body_state();
        };

        loop {
            let Some(chunk) = req.body_buf_mut().pop_front() else {
                break;
            };
            let len = chunk.len();
            match tx.try_send(chunk) {
                Ok(()) => {
                    req.set_body_buf_bytes(req.body_buf_bytes().saturating_sub(len));
                    metrics.release_request_buffer(len);
                }
                Err(TrySendError::Full(chunk)) => {
                    req.body_buf_mut().push_front(chunk);
                    break;
                }
                Err(TrySendError::Closed(_chunk)) => {
                    if req.body_buf_bytes() > 0 {
                        metrics.release_request_buffer(req.body_buf_bytes());
                    }
                    req.body_buf_mut().clear();
                    req.set_body_buf_bytes(0);
                    req.transition_request_body_forward_closed();
                    break;
                }
            }
        }

        if req.should_close_request_body_forwarding() {
            return req.transition_request_body_forward_closed();
        }

        let next = req.refresh_request_body_state();
        if matches!(next, RequestBodyState::FinReceived) && req.body_tx().is_some() {
            // A finished request can drain its last buffered chunk in this call.
            // Close the upstream body sender immediately so the backend sees EOF
            // without waiting for another progress pass that may never re-enter
            // the request-body branch.
            return req.transition_request_body_forward_closed();
        }

        next
    }

    /// Advance all in-flight streams without blocking.
    ///
    /// Called after every packet-driven `handle_h3` pass and from
    /// `handle_timeouts` so progress continues even when no new client
    /// packets arrive.
    ///
    /// Per stream, in order:
    /// 1. Drain request body buffer -> body channel (`try_send`).
    /// 2. Close body channel once FIN received and buffer empty.
    /// 3. Poll `upstream_result_rx` (`try_recv`).
    ///    - Error result  -> send error response, mark terminal.
    ///    - Ok result     -> send H3 response headers, spawn body-pump task,
    ///      store `response_chunk_rx`, transition to SendingResponse.
    /// 4. Flush `response_chunk_rx` chunks into H3 (`try_recv` loop).
    ///    - `Data`     -> `h3.send_body(..., false)`
    ///    - `Trailers` -> `h3.send_additional_headers(..., true, false)`
    ///    - `End`      -> `h3.send_body(..., true)`, mark Completed
    ///    - `Error`    -> send 502, mark Failed
    /// 5. Remove streams in terminal phase (Completed / Failed).
    pub(in crate::quic_listener) fn advance_streams_non_blocking(
        streams: &mut HashMap<u64, RequestEnvelope>,
        quic: &mut quiche::Connection,
        h3: &mut quiche::h3::Connection,
        exec_ctx: &ForwardingExecutionCtx<'_>,
        shared_ctx: &ForwardingSharedCtx<'_>,
        progress_config: &StreamProgressConfig,
    ) -> Result<(), quiche::h3::Error> {
        let metrics = shared_ctx.metrics.as_ref();
        let resilience = shared_ctx.resilience;
        let stream_ids: Vec<u64> = streams.keys().copied().collect();

        for stream_id in stream_ids {
            let now = Instant::now();
            if let Some(req) = streams.get(&stream_id)
                && req.can_accept_request_body()
            {
                let timeout_decision = evaluate_request_body_timeouts(
                    RequestBodyGuardrailConfig {
                        idle_timeout: progress_config.client_body_idle_timeout,
                        total_timeout: req
                            .total_request_deadline
                            .checked_duration_since(req.start)
                            .unwrap_or_default(),
                        max_body_bytes: usize::MAX,
                        max_buffered_bytes: usize::MAX,
                    },
                    RequestBodyGuardrailInput {
                        elapsed: req.start.elapsed(),
                        idle_for: now.saturating_duration_since(req.last_body_activity()),
                        bytes_received: req.body_bytes_received(),
                        buffered_bytes: req.body_buf_bytes(),
                        next_chunk_bytes: 0,
                        declared_content_length: None,
                        exempt_from_body_size_cap: false,
                    },
                );

                if matches!(
                    timeout_decision,
                    RequestBodyGuardrailDecision::Timeout {
                        kind: BodyTimeoutKind::Total,
                    }
                ) {
                    if let Err(protocol_err) = Self::handle_forward_result(
                        h3,
                        quic,
                        stream_id,
                        req,
                        Err(ProxyError::Timeout),
                        shared_ctx,
                    ) {
                        error!(
                            "failed to emit timeout response for stream {}: {:?}",
                            stream_id, protocol_err
                        );
                    }
                    resilience
                        .adaptive_admission
                        .observe(req.start.elapsed(), true);
                    if let Some(req) = streams.get_mut(&stream_id) {
                        terminalize_stream(
                            req,
                            TerminalReason::TimedOut(TimeoutReason::RequestBodyTotal),
                            metrics,
                        );
                    }
                    streams.remove(&stream_id);
                    continue;
                }

                if matches!(
                    timeout_decision,
                    RequestBodyGuardrailDecision::Timeout {
                        kind: BodyTimeoutKind::Idle,
                    }
                ) {
                    metrics.inc_timeout();
                    let _ = crate::runtime::connection::outcome::observe_proxy_error_outcome(
                        metrics,
                        crate::runtime::connection::outcome::RouteOutcomeTarget {
                            route: req.upstream_name.as_deref().unwrap_or("unrouted"),
                        },
                        Some(crate::runtime::connection::outcome::BackendOutcomeTarget {
                            upstream: req.upstream_name.as_deref().unwrap_or("unrouted"),
                            backend_addr: req.backend_addr.as_deref(),
                            backend_index: req.backend_index,
                        }),
                        req.start.elapsed(),
                        Some(http::StatusCode::REQUEST_TIMEOUT),
                        &ProxyError::Timeout,
                        None,
                    );
                    let _ = Self::send_simple_response(
                        h3,
                        quic,
                        stream_id,
                        http::StatusCode::REQUEST_TIMEOUT,
                        b"request body idle timeout\n",
                    );
                    resilience
                        .adaptive_admission
                        .observe(req.start.elapsed(), true);
                    if let Some(req) = streams.get_mut(&stream_id) {
                        req.mark_terminal_outcome_recorded();
                        terminalize_stream(
                            req,
                            TerminalReason::TimedOut(TimeoutReason::RequestBodyIdle),
                            metrics,
                        );
                    }
                    streams.remove(&stream_id);
                    continue;
                }
            }

            if let Some(req) = streams.get(&stream_id)
                && now >= req.total_request_deadline
            {
                if let Err(protocol_err) = Self::handle_forward_result(
                    h3,
                    quic,
                    stream_id,
                    req,
                    Err(ProxyError::Timeout),
                    shared_ctx,
                ) {
                    error!(
                        "failed to emit timeout response for stream {}: {:?}",
                        stream_id, protocol_err
                    );
                }
                resilience
                    .adaptive_admission
                    .observe(req.start.elapsed(), true);
                if let Some(req) = streams.get_mut(&stream_id) {
                    terminalize_stream(
                        req,
                        TerminalReason::TimedOut(req.total_request_timeout_reason()),
                        metrics,
                    );
                }
                streams.remove(&stream_id);
                continue;
            }

            if let Some(req) = streams.get_mut(&stream_id) {
                let _ = Self::flush_request_buffer(req, metrics);
            }

            let auth_ready = streams
                .get_mut(&stream_id)
                .and_then(|req| req.poll_awaiting_auth_non_blocking(now));

            if let Some(auth_result) = auth_ready {
                let keep_stream = if let Some(req) = streams.get_mut(&stream_id) {
                    Self::complete_auth_result(
                        stream_id,
                        req,
                        auth_result,
                        h3,
                        quic,
                        exec_ctx,
                        shared_ctx,
                    )?
                } else {
                    false
                };
                if !keep_stream {
                    if let Some(req) = streams.get_mut(&stream_id)
                        && !req.execution.is_terminal()
                    {
                        terminalize_stream(
                            req,
                            TerminalReason::Cancelled(CancellationReason::OperatorAbort),
                            metrics,
                        );
                    }
                    streams.remove(&stream_id);
                    continue;
                }
            }

            let can_poll_upstream = streams
                .get(&stream_id)
                .is_some_and(can_poll_upstream_result);
            let upstream_ready: Option<UpstreamResult> = if can_poll_upstream {
                streams
                    .get_mut(&stream_id)
                    .and_then(RequestEnvelope::upstream_result_rx_mut)
                    .and_then(|rx| match rx.try_recv() {
                        Ok(result) => Some(result),
                        Err(oneshot::error::TryRecvError::Empty) => None,
                        Err(oneshot::error::TryRecvError::Closed) => Some(UpstreamResult {
                            forward: Err(ProxyError::Transport(
                                "upstream task dropped sender".into(),
                            )),
                            policy: ForwardingPolicyTelemetry::default(),
                        }),
                    })
            } else {
                None
            };

            if let Some(forward_result) = upstream_ready {
                ForwardingOrchestrationService::record_policy_metrics(
                    metrics,
                    &forward_result.policy,
                );

                if let Some(req) = streams.get_mut(&stream_id) {
                    req.retry_count = forward_result.policy.retry.count;
                    req.error_kind = match &forward_result.forward {
                        Err(ProxyError::Timeout) => Some("timeout"),
                        Err(ProxyError::Tls(_)) => Some("tls"),
                        Err(ProxyError::Transport(_)) => Some("transport"),
                        Err(ProxyError::Pool(_)) => Some("pool"),
                        Err(ProxyError::Protocol(_)) => Some("protocol"),
                        Err(ProxyError::Bridge(_)) => Some("bridge"),
                        Ok(_) => None,
                    };
                }
                match forward_result.forward {
                    Ok(success) => {
                        let decision = if let Some(req) = streams.get(&stream_id) {
                            Self::prepare_response_start_decision(
                                req,
                                success,
                                progress_config,
                                metrics,
                            )
                        } else {
                            continue;
                        };
                        let immediate_terminal = if let Some(req) = streams.get_mut(&stream_id) {
                            match Self::apply_response_start_decision(
                                stream_id, req, decision, quic, h3, shared_ctx,
                            ) {
                                Ok(immediate_terminal) => immediate_terminal,
                                Err(err) => {
                                    if let Err(protocol_err) = Self::handle_forward_result(
                                        h3,
                                        quic,
                                        stream_id,
                                        req,
                                        Err(err),
                                        shared_ctx,
                                    ) {
                                        error!(
                                            "failed to emit recoverable response-start error on stream {}: {:?}",
                                            stream_id, protocol_err
                                        );
                                    }
                                    resilience
                                        .adaptive_admission
                                        .observe(req.start.elapsed(), true);
                                    true
                                }
                            }
                        } else {
                            false
                        };
                        if immediate_terminal {
                            if let Some(req) = streams.get_mut(&stream_id)
                                && !req.execution.is_terminal()
                            {
                                terminalize_stream(
                                    req,
                                    TerminalReason::Completed(CompletionReason::ImmediateResponse),
                                    metrics,
                                );
                            }
                            streams.remove(&stream_id);
                            continue;
                        }
                    }
                    Err(err) => {
                        let terminal_reason = match &err {
                            ProxyError::Timeout => streams.get(&stream_id).map_or(
                                TerminalReason::TimedOut(TimeoutReason::AwaitingUpstream),
                                |req| TerminalReason::TimedOut(req.upstream_timeout_reason()),
                            ),
                            other => TerminalReason::BackendFailed(
                                backend_failure_reason_for_proxy_error(other),
                            ),
                        };
                        if let Some(req) = streams.get(&stream_id) {
                            if let Err(protocol_err) = Self::handle_forward_result(
                                h3,
                                quic,
                                stream_id,
                                req,
                                Err(err),
                                shared_ctx,
                            ) {
                                error!(
                                    "failed to emit recoverable forward error response on stream {}: {:?}",
                                    stream_id, protocol_err
                                );
                            }
                            resilience
                                .adaptive_admission
                                .observe(req.start.elapsed(), true);
                        }
                        if let Some(req) = streams.get_mut(&stream_id) {
                            terminalize_stream(req, terminal_reason, metrics);
                        }
                        streams.remove(&stream_id);
                        continue;
                    }
                }
            }

            let terminal = if let Some(req) = streams.get_mut(&stream_id) {
                Self::flush_response_chunks(stream_id, req, quic, h3, shared_ctx)
            } else {
                false
            };

            if terminal {
                if let Some(req) = streams.get_mut(&stream_id)
                    && !req.execution.is_terminal()
                {
                    terminalize_stream(
                        req,
                        TerminalReason::Cancelled(CancellationReason::OperatorAbort),
                        metrics,
                    );
                }
                streams.remove(&stream_id);
            }
        }

        Ok(())
    }
}
