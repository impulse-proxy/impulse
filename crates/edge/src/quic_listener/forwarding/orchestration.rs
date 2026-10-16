use http_body_util::Full;

use super::{
    prepare::{RequestFinalizationConfig, RequestRoutingInput, StartedRequestEnvelope},
    *,
};
use crate::runtime::connection::{
    guardrails::{
        BodyLimitKind, REQUEST_BODY_TOO_LARGE_BODY, RequestBodyGuardrailConfig,
        RequestBodyGuardrailDecision, RequestBodyGuardrailInput, checked_request_body_ingress,
    },
    outcome::{
        BackendOutcomeTarget, RouteOutcomeTarget, observe_admission_outcome,
        observe_proxy_error_outcome,
    },
    stream::{
        AdmissionPermits, BackendFailureReason, CancellationReason, RejectionReason, TerminalReason,
    },
};

impl QUICListener {
    pub(super) fn materialize_forward_after_auth(
        stream_id: u64,
        req: &mut RequestEnvelope,
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        exec_ctx: &ForwardingExecutionCtx<'_>,
        shared_ctx: &ForwardingSharedCtx<'_>,
    ) -> Result<bool, quiche::h3::Error> {
        let metrics = shared_ctx.metrics.as_ref();
        let resilience = shared_ctx.resilience;
        let Some(pending_forward) = req.pending_forward().cloned() else {
            let _ = observe_proxy_error_outcome(
                metrics,
                RouteOutcomeTarget::UNROUTED,
                None,
                req.start.elapsed(),
                Some(http::StatusCode::INTERNAL_SERVER_ERROR),
                &ProxyError::Transport("missing deferred forward snapshot".into()),
                None,
            );
            Self::send_simple_response(
                h3,
                quic,
                stream_id,
                http::StatusCode::INTERNAL_SERVER_ERROR,
                b"missing deferred forward snapshot\n",
            )?;
            terminalize_stream(
                req,
                TerminalReason::Rejected(RejectionReason::ValidationFailed),
                metrics,
            );
            return Ok(false);
        };
        let Some(upstream_name) = req.upstream_name.clone() else {
            let _ = observe_proxy_error_outcome(
                metrics,
                RouteOutcomeTarget::UNROUTED,
                None,
                req.start.elapsed(),
                Some(http::StatusCode::INTERNAL_SERVER_ERROR),
                &ProxyError::Transport("missing upstream route".into()),
                None,
            );
            Self::send_simple_response(
                h3,
                quic,
                stream_id,
                http::StatusCode::INTERNAL_SERVER_ERROR,
                b"missing upstream route\n",
            )?;
            terminalize_stream(
                req,
                TerminalReason::Rejected(RejectionReason::ValidationFailed),
                metrics,
            );
            return Ok(false);
        };

        let (
            backend_index,
            upstream_pool,
            global_permit,
            upstream_permit,
            adaptive_permit,
            route_queue_permit,
        ) = match crate::quic_listener::admission::execute_forwarding_post_auth_admission(
            resilience,
            pending_forward.as_ref(),
            req.upstream_pool.as_ref(),
            req.backend_index,
            exec_ctx.upstream_inflight,
            Arc::clone(&exec_ctx.global_inflight),
            exec_ctx.inflight_acquire_wait,
        ) {
            crate::quic_listener::admission::PostAuthAdmissionExecution::Rejected(
                crate::quic_listener::admission::PostAuthAdmissionRejection::Quota(decision),
            ) => {
                if decision.status == http::StatusCode::TOO_MANY_REQUESTS {
                    metrics.inc_request_rate_limited();
                }
                let _ = observe_admission_outcome(
                    metrics,
                    RouteOutcomeTarget {
                        route: &upstream_name,
                    },
                    Some(BackendOutcomeTarget {
                        upstream: &upstream_name,
                        backend_addr: Some(pending_forward.backend_addr.as_ref()),
                        backend_index: Some(pending_forward.backend_index),
                    }),
                    req.start.elapsed(),
                    decision.status,
                    crate::runtime::connection::outcome::AdmissionOutcomeClass::QuotaDenied,
                );
                Self::send_admission_rejection_response(
                    h3,
                    quic,
                    stream_id,
                    &decision.as_response(),
                )?;
                req.mark_terminal_outcome_recorded();
                terminalize_stream(
                    req,
                    TerminalReason::Rejected(RejectionReason::QuotaDenied),
                    metrics,
                );
                return Ok(false);
            }
            crate::quic_listener::admission::PostAuthAdmissionExecution::Ready(ready) => {
                if ready.waited_for_global_permit {
                    metrics.inc_inflight_wait_admit_global();
                }
                if ready.waited_for_upstream_permit {
                    metrics.inc_inflight_wait_admit_upstream();
                }
                (
                    ready.backend_index,
                    ready.upstream_pool,
                    ready.global_permit,
                    ready.upstream_permit,
                    ready.adaptive_permit,
                    ready.route_queue_permit,
                )
            }
            crate::quic_listener::admission::PostAuthAdmissionExecution::Rejected(
                crate::quic_listener::admission::PostAuthAdmissionRejection::Overloaded(decision),
            ) => {
                let _ = observe_admission_outcome(
                    metrics,
                    RouteOutcomeTarget {
                        route: &upstream_name,
                    },
                    Some(BackendOutcomeTarget {
                        upstream: &upstream_name,
                        backend_addr: Some(pending_forward.backend_addr.as_ref()),
                        backend_index: Some(pending_forward.backend_index),
                    }),
                    req.start.elapsed(),
                    http::StatusCode::SERVICE_UNAVAILABLE,
                    crate::runtime::connection::outcome::AdmissionOutcomeClass::OverloadShed {
                        reason: Some(decision.reason.metrics_reason()),
                    },
                );
                Self::send_overload_response(
                    h3,
                    quic,
                    stream_id,
                    decision.body,
                    decision.retry_after_seconds,
                )?;
                resilience
                    .adaptive_admission
                    .observe(req.start.elapsed(), true);
                req.set_terminal_overload_reason(Some(decision.reason.metrics_reason()));
                req.mark_terminal_outcome_recorded();
                terminalize_stream(
                    req,
                    TerminalReason::Rejected(RejectionReason::Overloaded),
                    metrics,
                );
                return Ok(false);
            }
            crate::quic_listener::admission::PostAuthAdmissionExecution::Rejected(
                crate::quic_listener::admission::PostAuthAdmissionRejection::Failed(decision),
            ) => {
                let outcome = if let Some(reason) = decision.overload_reason {
                    crate::runtime::connection::outcome::AdmissionOutcomeClass::OverloadShed {
                        reason: Some(reason.metrics_reason()),
                    }
                } else {
                    crate::runtime::connection::outcome::AdmissionOutcomeClass::Failed {
                        timed_out: matches!(decision.route_outcome, Some(RouteOutcome::Timeout)),
                    }
                };
                let _ = observe_admission_outcome(
                    metrics,
                    RouteOutcomeTarget {
                        route: &upstream_name,
                    },
                    Some(BackendOutcomeTarget {
                        upstream: &upstream_name,
                        backend_addr: Some(pending_forward.backend_addr.as_ref()),
                        backend_index: Some(pending_forward.backend_index),
                    }),
                    req.start.elapsed(),
                    decision.status,
                    outcome,
                );
                Self::send_simple_response(h3, quic, stream_id, decision.status, decision.body)?;
                if decision.observe_adaptive_overload {
                    resilience
                        .adaptive_admission
                        .observe(req.start.elapsed(), true);
                }
                if let Some(reason) = decision.overload_reason {
                    req.set_terminal_overload_reason(Some(reason.metrics_reason()));
                }
                req.mark_terminal_outcome_recorded();
                terminalize_stream(
                    req,
                    TerminalReason::Rejected(rejection_reason_for_status(decision.status)),
                    metrics,
                );
                return Ok(false);
            }
        };
        if let Err(state_err) = req.transition_to_admitted(AdmissionPermits {
            global: global_permit,
            upstream: upstream_permit,
            adaptive: adaptive_permit,
            route_queue: route_queue_permit,
        }) {
            let proxy_err = ProxyError::Transport(format!(
                "invalid request execution transition: {} from {:?}",
                state_err.attempted(),
                req.phase(),
            ));
            let _ = observe_proxy_error_outcome(
                metrics,
                RouteOutcomeTarget {
                    route: &upstream_name,
                },
                Some(BackendOutcomeTarget {
                    upstream: &upstream_name,
                    backend_addr: Some(pending_forward.backend_addr.as_ref()),
                    backend_index: Some(backend_index),
                }),
                req.start.elapsed(),
                Some(http::StatusCode::INTERNAL_SERVER_ERROR),
                &proxy_err,
                None,
            );
            error!("admission state transition failed: {:?}", state_err);
            Self::send_simple_response(
                h3,
                quic,
                stream_id,
                http::StatusCode::INTERNAL_SERVER_ERROR,
                b"internal server error\n",
            )?;
            terminalize_stream(
                req,
                TerminalReason::Rejected(RejectionReason::ValidationFailed),
                metrics,
            );
            return Ok(false);
        }

        let Some(backend_endpoint) = exec_ctx
            .backend_endpoints
            .get(pending_forward.backend_addr.as_ref())
            .cloned()
        else {
            let _ = observe_proxy_error_outcome(
                metrics,
                RouteOutcomeTarget {
                    route: &upstream_name,
                },
                Some(BackendOutcomeTarget {
                    upstream: &upstream_name,
                    backend_addr: Some(pending_forward.backend_addr.as_ref()),
                    backend_index: Some(backend_index),
                }),
                req.start.elapsed(),
                Some(http::StatusCode::BAD_GATEWAY),
                &ProxyError::Transport("unknown backend endpoint".into()),
                None,
            );
            Self::send_simple_response(
                h3,
                quic,
                stream_id,
                http::StatusCode::BAD_GATEWAY,
                b"unknown backend endpoint\n",
            )?;
            terminalize_stream(
                req,
                TerminalReason::BackendFailed(BackendFailureReason::DispatchSpawnFailed),
                metrics,
            );
            return Ok(false);
        };

        let request_mode = req.request_mode();
        let websocket_h1_tunnel = req.tunnel_mode == TunnelMode::Websocket
            && backend_endpoint.scheme() == BackendScheme::Http;
        let (body_tx, websocket_tunnel_body_rx, request_body) = if request_mode.bodyless_mode() {
            (None, None, Some(BoxBody::new(Full::new(Bytes::new()))))
        } else if websocket_h1_tunnel {
            let (tx, rx) = mpsc::channel::<Bytes>(REQUEST_CHUNK_CHANNEL_CAPACITY);
            (Some(tx), Some(rx), None)
        } else {
            let (tx, channel_body) = ChannelBody::channel(REQUEST_CHUNK_CHANNEL_CAPACITY);
            (Some(tx), None, Some(channel_body.boxed()))
        };

        let request = if websocket_h1_tunnel {
            None
        } else {
            match pending_forward.build_request(
                &backend_endpoint,
                request_body.unwrap_or_else(|| BoxBody::new(Full::new(Bytes::new()))),
                None,
            ) {
                Ok(request) => Some(request),
                Err(err) => {
                    let err_text = err.to_string();
                    let _ = observe_proxy_error_outcome(
                        metrics,
                        RouteOutcomeTarget {
                            route: &upstream_name,
                        },
                        Some(BackendOutcomeTarget {
                            upstream: &upstream_name,
                            backend_addr: Some(pending_forward.backend_addr.as_ref()),
                            backend_index: Some(backend_index),
                        }),
                        req.start.elapsed(),
                        Some(http::StatusCode::BAD_REQUEST),
                        &err,
                        None,
                    );
                    Self::send_simple_response(
                        h3,
                        quic,
                        stream_id,
                        http::StatusCode::BAD_REQUEST,
                        b"invalid request\n",
                    )?;
                    error!("failed to build upstream request after auth: {}", err_text);
                    resilience
                        .adaptive_admission
                        .observe(req.start.elapsed(), true);
                    terminalize_stream(
                        req,
                        TerminalReason::Rejected(RejectionReason::ValidationFailed),
                        metrics,
                    );
                    return Ok(false);
                }
            }
        };

        let result_rx = match Self::spawn_upstream_forward_task(
            req,
            Arc::clone(&pending_forward),
            backend_endpoint,
            request,
            websocket_tunnel_body_rx,
            exec_ctx,
            shared_ctx,
        ) {
            Ok(result_rx) => result_rx,
            Err(err) => {
                let _ = observe_proxy_error_outcome(
                    metrics,
                    RouteOutcomeTarget {
                        route: &upstream_name,
                    },
                    Some(BackendOutcomeTarget {
                        upstream: &upstream_name,
                        backend_addr: Some(pending_forward.backend_addr.as_ref()),
                        backend_index: Some(backend_index),
                    }),
                    req.start.elapsed(),
                    Some(http::StatusCode::SERVICE_UNAVAILABLE),
                    &ProxyError::Transport("upstream runtime unavailable".into()),
                    None,
                );
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::SERVICE_UNAVAILABLE,
                    b"upstream runtime unavailable\n",
                )?;
                error!("failed to spawn upstream task after auth: {}", err);
                resilience
                    .adaptive_admission
                    .observe(req.start.elapsed(), true);
                terminalize_stream(
                    req,
                    TerminalReason::BackendFailed(BackendFailureReason::DispatchSpawnFailed),
                    metrics,
                );
                return Ok(false);
            }
        };
        if let Ok(pool) = upstream_pool.write() {
            pool.begin_request_for_accounting(backend_index);
        }
        if let Err(state_err) = req.transition_admitted_to_awaiting_upstream(body_tx, result_rx) {
            let proxy_err = ProxyError::Transport(format!(
                "invalid request execution transition: {} from {:?}",
                state_err.attempted(),
                req.phase(),
            ));
            let _ = observe_proxy_error_outcome(
                metrics,
                RouteOutcomeTarget {
                    route: &upstream_name,
                },
                Some(BackendOutcomeTarget {
                    upstream: &upstream_name,
                    backend_addr: Some(pending_forward.backend_addr.as_ref()),
                    backend_index: Some(backend_index),
                }),
                req.start.elapsed(),
                Some(http::StatusCode::INTERNAL_SERVER_ERROR),
                &proxy_err,
                None,
            );
            error!("dispatch state transition failed: {:?}", state_err);
            Self::send_simple_response(
                h3,
                quic,
                stream_id,
                http::StatusCode::INTERNAL_SERVER_ERROR,
                b"internal server error\n",
            )?;
            terminalize_stream(
                req,
                TerminalReason::Rejected(RejectionReason::ValidationFailed),
                metrics,
            );
            return Ok(false);
        }
        let _ = Self::flush_request_buffer(req, metrics);
        Ok(true)
    }

    pub(in crate::quic_listener) fn flush_send(
        socket: &UdpSocket,
        send_buf: &mut [u8],
        connection: &mut QuicConnection,
    ) {
        let mut packet_count = 0;

        loop {
            match connection.quic.send(send_buf) {
                Ok((write, send_info)) => {
                    packet_count += 1;
                    debug!("Sending {} bytes to {}", write, send_info.to);
                    if let Err(e) = socket.send_to(&send_buf[..write], send_info.to) {
                        error!("Failed to send UDP packet: {:?}", e);
                        break;
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    error!("QUIC send failed: {:?}", e);
                    break;
                }
            }
        }

        if packet_count > 0 {
            debug!("Sent {} packets", packet_count);
        }
    }

    pub(in crate::quic_listener) fn handle_h3(
        connection: &mut QuicConnection,
        shared_ctx: &ForwardingSharedCtx<'_>,
        exec_ctx: &ForwardingExecutionCtx<'_>,
        progress_config: &StreamProgressConfig,
        request_config: &H3RequestHandlingConfig,
    ) -> Result<(), quiche::h3::Error> {
        let mut body_buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];
        let metrics = shared_ctx.metrics.as_ref();
        let resilience = shared_ctx.resilience;
        let request_finalization = &request_config.request_finalization;
        let routing_transparency_enabled = request_finalization.routing_transparency_enabled;
        let routing_transparency_include_reason =
            request_finalization.routing_transparency_include_reason;
        let backend_total_request_timeout = request_finalization.backend_total_request_timeout;
        let tracing_enabled = request_config.tracing_enabled;
        let max_request_body_bytes = request_config.max_request_body_bytes;
        let request_buffer_global_cap_bytes = request_config.request_buffer_global_cap_bytes;
        let max_streams_per_connection = request_config.max_streams_per_connection;

        if connection.h3.is_none() {
            connection.h3 = Some(quiche::h3::Connection::with_transport(
                &mut connection.quic,
                &connection.h3_config,
            )?);
        }

        let h3 = match connection.h3.as_mut() {
            Some(h3) => h3,
            None => return Ok(()),
        };

        loop {
            match h3.poll(&mut connection.quic) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    let request = match validate_request_headers(&list, resilience) {
                        Ok(request) => request,
                        Err((status, body, is_policy)) => {
                            metrics.inc_request_validation_reject();
                            if is_policy {
                                metrics.inc_policy_denied();
                            }
                            let _ = observe_proxy_error_outcome(
                                metrics,
                                RouteOutcomeTarget::UNROUTED,
                                None,
                                Duration::from_millis(0),
                                Some(status),
                                &ProxyError::Bridge(impulse_errors::BridgeError::InvalidHeader),
                                None,
                            );
                            let _ = Self::send_simple_response(
                                h3,
                                &mut connection.quic,
                                stream_id,
                                status,
                                body,
                            );
                            continue;
                        }
                    };
                    let method = request.method;
                    let path = request.path;
                    let authority = request.authority;
                    let content_length = request.content_length;
                    let websocket_tunnel = request.websocket_tunnel;
                    let tunnel_mode = if websocket_tunnel {
                        TunnelMode::Websocket
                    } else if is_connect_method(&method) {
                        TunnelMode::Connect
                    } else {
                        TunnelMode::None
                    };

                    metrics.inc_total();
                    let request_start = Instant::now();

                    if connection.quic.is_in_early_data() {
                        if resilience.early_data_allowed_for(&method) {
                            metrics.inc_early_data_accepted();
                        } else {
                            metrics.inc_early_data_rejected();
                            metrics.inc_policy_denied();
                            let _ = observe_proxy_error_outcome(
                                metrics,
                                RouteOutcomeTarget::UNROUTED,
                                None,
                                request_start.elapsed(),
                                Some(http::StatusCode::TOO_EARLY),
                                &ProxyError::Transport(
                                    "request blocked by early-data policy".into(),
                                ),
                                None,
                            );
                            Self::send_simple_response(
                                h3,
                                &mut connection.quic,
                                stream_id,
                                http::StatusCode::TOO_EARLY,
                                b"request blocked by early-data policy\n",
                            )?;
                            continue;
                        }
                    }

                    if connection.streams.len() >= max_streams_per_connection {
                        warn!(
                            "stream limit reached ({} streams), rejecting stream {}",
                            max_streams_per_connection, stream_id
                        );
                        Self::send_simple_response(
                            h3,
                            &mut connection.quic,
                            stream_id,
                            http::StatusCode::SERVICE_UNAVAILABLE,
                            b"too many concurrent streams\n",
                        )?;
                        continue;
                    }

                    let sticky_cid_key = hex::encode(connection.primary_scid.as_ref());
                    let quic_trace_id = connection.quic.trace_id().to_string();
                    let pre_auth = match Self::prepare_request_for_auth(
                        stream_id,
                        h3,
                        &mut connection.quic,
                        RequestRoutingInput {
                            peer_address: connection.peer_address,
                            sticky_cid_key: sticky_cid_key.as_str(),
                            intake: self::prepare::IntakeRequestDescriptor {
                                quic_trace_id: &quic_trace_id,
                                request_start,
                                method: &method,
                                path: &path,
                                authority: authority.as_deref(),
                                headers: &list,
                                content_length,
                                tunnel_mode,
                                tracing_enabled,
                            },
                        },
                        shared_ctx,
                    )? {
                        Some(pre_auth) => pre_auth,
                        None => continue,
                    };
                    let started_auth = match Self::start_request_auth(
                        stream_id,
                        h3,
                        &mut connection.quic,
                        request_start,
                        metrics,
                        pre_auth,
                        RequestFinalizationConfig {
                            routing_transparency_enabled,
                            routing_transparency_include_reason,
                            backend_total_request_timeout,
                        },
                    )? {
                        Some(started_auth) => started_auth,
                        None => continue,
                    };
                    let StartedRequestEnvelope {
                        envelope,
                        should_materialize_forward,
                    } = started_auth;
                    connection.streams.insert(stream_id, envelope);
                    if should_materialize_forward {
                        let keep_stream = if let Some(req) = connection.streams.get_mut(&stream_id)
                        {
                            Self::materialize_forward_after_auth(
                                stream_id,
                                req,
                                h3,
                                &mut connection.quic,
                                exec_ctx,
                                shared_ctx,
                            )?
                        } else {
                            false
                        };
                        if !keep_stream {
                            if let Some(req) = connection.streams.get_mut(&stream_id)
                                && !req.execution.is_terminal()
                            {
                                terminalize_stream(
                                    req,
                                    TerminalReason::Cancelled(CancellationReason::OperatorAbort),
                                    metrics,
                                );
                            }
                            connection.streams.remove(&stream_id);
                            continue;
                        }
                    }
                    if let Some(req) = connection.streams.get(&stream_id) {
                        debug!(
                            "request_id={} method={} path={} stream_id={}",
                            req.request_id, req.method, req.path, stream_id
                        );
                    }
                }
                Ok((stream_id, quiche::h3::Event::Data)) => loop {
                    match h3.recv_body(&mut connection.quic, stream_id, &mut body_buf) {
                        Ok(read) => {
                            let mut shed_due_to_buffer_pressure = false;
                            let mut reject_body_for_bodyless = None::<(String, Duration)>;
                            let mut payload_too_large = None::<(String, Duration)>;
                            if let Some(req) = connection.streams.get_mut(&stream_id) {
                                if read > 0 {
                                    req.set_last_body_activity(Instant::now());
                                }
                                if req.request_mode().bodyless_mode() && read > 0 {
                                    reject_body_for_bodyless = Some((
                                        req.upstream_name
                                            .clone()
                                            .unwrap_or_else(|| "unrouted".to_string()),
                                        req.start.elapsed(),
                                    ));
                                }
                                if reject_body_for_bodyless.is_none() {
                                    let next_state = checked_request_body_ingress(
                                        RequestBodyGuardrailConfig {
                                            idle_timeout: Duration::ZERO,
                                            total_timeout: Duration::ZERO,
                                            max_body_bytes: max_request_body_bytes,
                                            max_buffered_bytes: usize::MAX,
                                        },
                                        RequestBodyGuardrailInput {
                                            elapsed: req.start.elapsed(),
                                            idle_for: Instant::now().saturating_duration_since(
                                                req.last_body_activity(),
                                            ),
                                            bytes_received: req.body_bytes_received(),
                                            buffered_bytes: 0,
                                            next_chunk_bytes: read,
                                            declared_content_length: None,
                                            exempt_from_body_size_cap: is_connect_method(
                                                &req.method,
                                            ),
                                        },
                                    );
                                    match next_state {
                                        Err(RequestBodyGuardrailDecision::Reject {
                                            kind: BodyLimitKind::BodySize,
                                        }) => {
                                            payload_too_large = Some((
                                                req.upstream_name
                                                    .clone()
                                                    .unwrap_or_else(|| "unrouted".to_string()),
                                                req.start.elapsed(),
                                            ));
                                        }
                                        Ok(next_state) => {
                                            req.set_body_bytes_received(next_state.bytes_received);

                                            for chunk_slice in
                                                body_buf[..read].chunks(REQUEST_CHUNK_BYTES_LIMIT)
                                            {
                                                let chunk = Bytes::copy_from_slice(chunk_slice);
                                                if let Err(err) = Self::enqueue_request_chunk(
                                                    req,
                                                    chunk,
                                                    metrics,
                                                    max_request_body_bytes,
                                                    request_buffer_global_cap_bytes,
                                                ) {
                                                    if err == RequestBufferError::BodySize {
                                                        payload_too_large = Some((
                                                            req.upstream_name
                                                                .clone()
                                                                .unwrap_or_else(|| {
                                                                    "unrouted".to_string()
                                                                }),
                                                            req.start.elapsed(),
                                                        ));
                                                    } else {
                                                        shed_due_to_buffer_pressure = true;
                                                        metrics.inc_request_buffer_limit_reject();
                                                        if err == RequestBufferError::Global {
                                                            debug!(
                                                                "global request buffer cap reached"
                                                            );
                                                        }
                                                    }
                                                    break;
                                                }
                                            }
                                        }
                                        Err(RequestBodyGuardrailDecision::Reject {
                                            kind:
                                                BodyLimitKind::UnknownLengthPrebuffer
                                                | BodyLimitKind::BufferedBody,
                                        }) => {
                                            shed_due_to_buffer_pressure = true;
                                            metrics.inc_request_buffer_limit_reject();
                                        }
                                        Err(other) => {
                                            unreachable!(
                                                "request ingress should not timeout in data path: {:?}",
                                                other
                                            );
                                        }
                                    }
                                }
                            }
                            if let Some((route_label, elapsed)) = reject_body_for_bodyless {
                                let _ = observe_proxy_error_outcome(
                                    metrics,
                                    RouteOutcomeTarget {
                                        route: &route_label,
                                    },
                                    None,
                                    elapsed,
                                    Some(http::StatusCode::BAD_REQUEST),
                                    &ProxyError::Bridge(impulse_errors::BridgeError::InvalidHeader),
                                    None,
                                );
                                Self::send_simple_response(
                                    h3,
                                    &mut connection.quic,
                                    stream_id,
                                    http::StatusCode::BAD_REQUEST,
                                    b"request body not allowed for this request\n",
                                )?;
                                if let Some(req) = connection.streams.get_mut(&stream_id) {
                                    terminalize_stream(
                                        req,
                                        TerminalReason::Rejected(
                                            RejectionReason::RequestBodyNotAllowed,
                                        ),
                                        metrics,
                                    );
                                }
                                connection.streams.remove(&stream_id);
                                resilience.adaptive_admission.observe(elapsed, true);
                                break;
                            }
                            if let Some((route_label, elapsed)) = payload_too_large {
                                let _ = observe_proxy_error_outcome(
                                    metrics,
                                    RouteOutcomeTarget {
                                        route: &route_label,
                                    },
                                    None,
                                    elapsed,
                                    Some(http::StatusCode::PAYLOAD_TOO_LARGE),
                                    &ProxyError::Transport("request body too large".into()),
                                    None,
                                );
                                Self::send_simple_response(
                                    h3,
                                    &mut connection.quic,
                                    stream_id,
                                    http::StatusCode::PAYLOAD_TOO_LARGE,
                                    REQUEST_BODY_TOO_LARGE_BODY,
                                )?;
                                if let Some(req) = connection.streams.get_mut(&stream_id) {
                                    terminalize_stream(
                                        req,
                                        TerminalReason::Rejected(
                                            RejectionReason::RequestBodyTooLarge,
                                        ),
                                        metrics,
                                    );
                                }
                                connection.streams.remove(&stream_id);
                                resilience.adaptive_admission.observe(elapsed, true);
                                break;
                            }
                            if shed_due_to_buffer_pressure
                                && let Some(req) = connection.streams.get(&stream_id)
                            {
                                let _ = observe_proxy_error_outcome(
                                    metrics,
                                    RouteOutcomeTarget {
                                        route: req.upstream_name.as_deref().unwrap_or("unrouted"),
                                    },
                                    Some(BackendOutcomeTarget {
                                        upstream: req
                                            .upstream_name
                                            .as_deref()
                                            .unwrap_or("unrouted"),
                                        backend_addr: req.backend_addr.as_deref(),
                                        backend_index: req.backend_index,
                                    }),
                                    req.start.elapsed(),
                                    Some(http::StatusCode::SERVICE_UNAVAILABLE),
                                    &ProxyError::Pool(PoolError::BackendOverloaded(
                                        "request body backpressure overload".into(),
                                    )),
                                    Some(OverloadShedReason::RequestBufferCap),
                                );
                                Self::send_overload_response(
                                    h3,
                                    &mut connection.quic,
                                    stream_id,
                                    b"request body backpressure overload\n",
                                    resilience.shed_retry_after_seconds,
                                )?;
                                resilience
                                    .adaptive_admission
                                    .observe(req.start.elapsed(), true);
                                if let Some(req) = connection.streams.get_mut(&stream_id) {
                                    req.set_terminal_overload_reason(Some(
                                        OverloadShedReason::RequestBufferCap,
                                    ));
                                    req.mark_terminal_outcome_recorded();
                                    terminalize_stream(
                                        req,
                                        TerminalReason::Rejected(RejectionReason::Overloaded),
                                        metrics,
                                    );
                                }
                                connection.streams.remove(&stream_id);
                                break;
                            }
                        }
                        Err(quiche::h3::Error::Done) => break,
                        Err(err) => {
                            let rid = connection.streams.get(&stream_id).map(|r| r.request_id);
                            error!(
                                "request_id={} HTTP/3 recv_body protocol error on stream {}: {:?}",
                                rid.map_or_else(|| "-".to_string(), |id| id.to_string()),
                                stream_id,
                                err
                            );
                            if let Some(req) = connection.streams.get(&stream_id) {
                                let _ = observe_proxy_error_outcome(
                                    metrics,
                                    RouteOutcomeTarget {
                                        route: req.upstream_name.as_deref().unwrap_or("unrouted"),
                                    },
                                    Some(BackendOutcomeTarget {
                                        upstream: req
                                            .upstream_name
                                            .as_deref()
                                            .unwrap_or("unrouted"),
                                        backend_addr: req.backend_addr.as_deref(),
                                        backend_index: req.backend_index,
                                    }),
                                    req.start.elapsed(),
                                    Some(http::StatusCode::BAD_GATEWAY),
                                    &ProxyError::Protocol(format!(
                                        "recv_body protocol error on stream {}",
                                        stream_id
                                    )),
                                    None,
                                );
                                resilience
                                    .adaptive_admission
                                    .observe(req.start.elapsed(), true);
                            }
                            if let Some(req) = connection.streams.get_mut(&stream_id) {
                                terminalize_stream(
                                    req,
                                    TerminalReason::Rejected(RejectionReason::ValidationFailed),
                                    metrics,
                                );
                            }
                            connection.streams.remove(&stream_id);
                            let _ = Self::send_simple_response(
                                h3,
                                &mut connection.quic,
                                stream_id,
                                http::StatusCode::BAD_REQUEST,
                                b"malformed request stream\n",
                            );
                            break;
                        }
                    }
                },
                Ok((stream_id, quiche::h3::Event::Finished)) => {
                    if let Some(req) = connection.streams.get_mut(&stream_id) {
                        req.transition_request_body_finished();
                        let _ = Self::flush_request_buffer(req, metrics);
                    }
                }
                Ok((stream_id, quiche::h3::Event::Reset(error_code))) => {
                    if let Some(req) = connection.streams.get_mut(&stream_id) {
                        let phase = terminalize_stream(
                            req,
                            TerminalReason::Cancelled(CancellationReason::ClientReset),
                            metrics,
                        );
                        debug!(
                            "stream {} reset by client (error_code={}, phase={:?}): resources released",
                            stream_id, error_code, phase
                        );
                    }
                    connection.streams.remove(&stream_id);
                }
                Ok((_stream_id, quiche::h3::Event::PriorityUpdate)) => {}
                Ok((_stream_id, quiche::h3::Event::GoAway)) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(e) => return Err(e),
            }
        }

        Self::advance_streams_non_blocking(
            &mut connection.streams,
            &mut connection.quic,
            h3,
            exec_ctx,
            shared_ctx,
            progress_config,
        )?;

        Ok(())
    }
}
