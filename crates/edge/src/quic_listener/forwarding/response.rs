use bytes::Bytes;
use impulse_errors::{UpstreamProxyErrorKind, classify_upstream_proxy_error};
use impulse_transport::{UpstreamBody, UpstreamBodyFrame};
use tokio::sync::mpsc::error::TryRecvError;

use super::*;
use crate::runtime::connection::{
    auth::ExternalAuthDecision,
    guardrails::{
        BodyLimitKind, BodyTimeoutKind, ProgressiveEmissionPolicy, RESPONSE_BODY_TOO_LARGE_BODY,
        ResponseBodyGuardrailConfig, ResponseBodyGuardrailDecision, ResponseBodyGuardrailInput,
        checked_response_body_guardrails, is_unknown_length_response_prebuffer_reason,
        response_body_limit_reason, response_chunk_ranges,
    },
    response::{
        ImmediateResponseStart, ResponseBodyPumpPlan, ResponseChunk, ResponseStartDecision,
        ResponseStartMetadata, ResponseStartObservation,
    },
    stream::{BackendFailureReason, CompletionReason, ResponseEmissionState, TimeoutReason},
};

fn response_body_guardrail_chunk(decision: ResponseBodyGuardrailDecision) -> Option<ResponseChunk> {
    match decision {
        ResponseBodyGuardrailDecision::Continue { .. } => None,
        ResponseBodyGuardrailDecision::Timeout {
            kind: BodyTimeoutKind::Idle,
        } => Some(ResponseChunk::Timeout(TimeoutReason::ResponseBodyIdle)),
        ResponseBodyGuardrailDecision::Timeout {
            kind: BodyTimeoutKind::Total,
        } => Some(ResponseChunk::Timeout(TimeoutReason::ResponseBodyTotal)),
        ResponseBodyGuardrailDecision::Reject {
            kind: BodyLimitKind::BodySize,
        } => Some(ResponseChunk::Error(ProxyError::Pool(
            PoolError::BackendOverloaded(
                response_body_limit_reason(BodyLimitKind::BodySize).into(),
            ),
        ))),
        ResponseBodyGuardrailDecision::Reject {
            kind: BodyLimitKind::UnknownLengthPrebuffer,
        } => Some(ResponseChunk::Error(ProxyError::Pool(
            PoolError::BackendOverloaded(
                response_body_limit_reason(BodyLimitKind::UnknownLengthPrebuffer).into(),
            ),
        ))),
        ResponseBodyGuardrailDecision::Reject { .. } => Some(ResponseChunk::Error(
            ProxyError::Pool(PoolError::BackendOverloaded(
                response_body_limit_reason(BodyLimitKind::BufferedBody).into(),
            )),
        )),
    }
}

fn response_body_wait_timeout_reason(
    guardrails: ResponseBodyGuardrailConfig,
    body_started_at: tokio::time::Instant,
    _last_body_progress_at: tokio::time::Instant,
) -> TimeoutReason {
    if body_started_at.elapsed() >= guardrails.total_timeout {
        TimeoutReason::ResponseBodyTotal
    } else {
        TimeoutReason::ResponseBodyIdle
    }
}

fn simple_response_headers(status: http::StatusCode, body: &[u8]) -> Vec<quiche::h3::Header> {
    vec![
        quiche::h3::Header::new(b":status", status.as_str().as_bytes()),
        quiche::h3::Header::new(b"content-type", b"text/plain"),
        quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
    ]
}

fn overload_response_headers(body: &[u8], retry_after_seconds: u32) -> Vec<quiche::h3::Header> {
    let retry_after = retry_after_seconds.max(1).to_string();
    vec![
        quiche::h3::Header::new(
            b":status",
            http::StatusCode::SERVICE_UNAVAILABLE.as_str().as_bytes(),
        ),
        quiche::h3::Header::new(b"content-type", b"text/plain"),
        quiche::h3::Header::new(b"retry-after", retry_after.as_bytes()),
        quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
    ]
}

fn admission_rejection_headers(
    response: &crate::quic_listener::admission::AdmissionRejectionResponse,
) -> Vec<quiche::h3::Header> {
    let mut headers = vec![
        quiche::h3::Header::new(b":status", response.status.as_str().as_bytes()),
        quiche::h3::Header::new(b"content-type", b"text/plain"),
    ];
    if let Some(challenge) = response.www_authenticate {
        headers.push(quiche::h3::Header::new(
            b"www-authenticate",
            challenge.as_bytes(),
        ));
    }
    if let Some(retry_after_seconds) = response.retry_after_seconds {
        let retry_after = retry_after_seconds.max(1).to_string();
        headers.push(quiche::h3::Header::new(
            b"retry-after",
            retry_after.as_bytes(),
        ));
    }
    headers.push(quiche::h3::Header::new(
        b"content-length",
        response.body.len().to_string().as_bytes(),
    ));
    headers
}

#[cfg(test)]
fn response_headers_with_defaults(
    status: http::StatusCode,
    body: &[u8],
    headers: &[(String, String)],
) -> Vec<quiche::h3::Header> {
    response_headers_with_defaults_and_extra(status, body, headers, None)
}

#[cfg(test)]
fn response_headers_with_defaults_and_extra(
    status: http::StatusCode,
    body: &[u8],
    headers: &[(String, String)],
    extra_header: Option<(&str, &str)>,
) -> Vec<quiche::h3::Header> {
    response_headers_with_defaults_and_extra_bytes(
        status,
        body,
        headers
            .iter()
            .map(|(name, value)| (name.as_bytes(), value.as_bytes())),
        extra_header.map(|(name, value)| (name.as_bytes(), value.as_bytes())),
    )
}

fn response_headers_with_defaults_and_extra_bytes<'a, I>(
    status: http::StatusCode,
    body: &[u8],
    headers: I,
    extra_header: Option<(&'a [u8], &'a [u8])>,
) -> Vec<quiche::h3::Header>
where
    I: IntoIterator<Item = (&'a [u8], &'a [u8])>,
{
    let headers = headers.into_iter();
    let mut resp_headers =
        Vec::with_capacity(headers.size_hint().0 + usize::from(extra_header.is_some()) + 3);
    resp_headers.push(quiche::h3::Header::new(
        b":status",
        status.as_str().as_bytes(),
    ));
    let mut has_content_type = false;
    let mut has_content_length = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case(http::header::CONTENT_TYPE.as_str().as_bytes()) {
            has_content_type = true;
        }
        if name.eq_ignore_ascii_case(http::header::CONTENT_LENGTH.as_str().as_bytes()) {
            has_content_length = true;
        }
        resp_headers.push(quiche::h3::Header::new(name, value));
    }
    if let Some((name, value)) = extra_header {
        if name.eq_ignore_ascii_case(http::header::CONTENT_TYPE.as_str().as_bytes()) {
            has_content_type = true;
        }
        if name.eq_ignore_ascii_case(http::header::CONTENT_LENGTH.as_str().as_bytes()) {
            has_content_length = true;
        }
        resp_headers.push(quiche::h3::Header::new(name, value));
    }
    if !has_content_type {
        resp_headers.push(quiche::h3::Header::new(b"content-type", b"text/plain"));
    }
    if !has_content_length {
        resp_headers.push(quiche::h3::Header::new(
            b"content-length",
            body.len().to_string().as_bytes(),
        ));
    }
    resp_headers
}

impl QUICListener {
    #[allow(clippy::too_many_arguments)]
    fn fail_response_start_state_transition(
        stream_id: u64,
        req: &mut RequestEnvelope,
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        shared_ctx: &ForwardingSharedCtx<'_>,
        status: http::StatusCode,
        headers_sent: bool,
        attempted: &'static str,
    ) -> Result<bool, ProxyError> {
        let metrics = shared_ctx.metrics.as_ref();
        let proxy_err = ProxyError::Transport(format!(
            "invalid request execution transition: {} from {:?}",
            attempted,
            req.phase(),
        ));
        let _ = crate::runtime::connection::outcome::observe_proxy_error_outcome(
            metrics,
            Self::request_outcome_route_target(req),
            Self::request_outcome_backend_target(req),
            req.start.elapsed(),
            Some(http::StatusCode::INTERNAL_SERVER_ERROR),
            &proxy_err,
            None,
        );
        error!(
            "response start state transition failed on stream {}: {} from {:?}",
            stream_id,
            attempted,
            req.phase(),
        );
        if !headers_sent {
            Self::send_simple_response(
                h3,
                quic,
                stream_id,
                http::StatusCode::INTERNAL_SERVER_ERROR,
                b"internal server error\n",
            )
            .map_err(|err| {
                ProxyError::Protocol(format!(
                    "failed to send internal error response after state transition failure: {:?}",
                    err
                ))
            })?;
            req.response_status = Some(http::StatusCode::INTERNAL_SERVER_ERROR.as_u16());
        } else {
            req.response_status = Some(status.as_u16());
            let _ = h3.send_body(quic, stream_id, b"", true);
        }
        req.transition_to_terminal_with_cleanup(
            TerminalReason::BackendFailed(BackendFailureReason::UpstreamProtocol),
            metrics,
        );
        Ok(true)
    }

    fn response_start_header_block(
        status: http::StatusCode,
        headers: &[(Vec<u8>, Vec<u8>)],
    ) -> Vec<quiche::h3::Header> {
        let mut h3_headers = Vec::with_capacity(headers.len() + 1);
        h3_headers.push(quiche::h3::Header::new(
            b":status",
            status.as_str().as_bytes(),
        ));
        for (name, value) in headers {
            h3_headers.push(quiche::h3::Header::new(name, value));
        }
        h3_headers
    }

    fn into_deferred_response_start_chunk(
        metadata: ResponseStartMetadata,
    ) -> Option<ResponseChunk> {
        metadata.headers_deferred.then_some(ResponseChunk::Start {
            status: metadata.status,
            headers: metadata.headers,
        })
    }

    pub(super) fn prepare_response_start_decision(
        req: &RequestEnvelope,
        success: ForwardSuccess,
        progress_config: &StreamProgressConfig,
    ) -> ResponseStartDecision {
        let (status, resp_headers, response_body, prebuilt_response_chunk_rx) = match success {
            ForwardSuccess::Response {
                status,
                headers,
                body,
            } => (status, headers, Some(body), None),
            ForwardSuccess::Tunnel {
                status,
                headers,
                response_chunk_rx,
            } => (status, headers, None, Some(response_chunk_rx)),
        };
        let request_mode = req.request_mode();
        let tunnel_response = is_tunnel_response(req.tunnel_mode, status);
        let response_body_mode = if tunnel_response {
            ResponseBodyMode::TunnelSuccess
        } else if request_mode.suppresses_response_body() {
            ResponseBodyMode::HeadRequest
        } else {
            ResponseBodyMode::Normal
        };
        let upstream_content_length = resp_headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok());
        let normalized_response = normalize_upstream_response(ResponseNormalizationInput {
            upstream: impulse_bridge::response::UpstreamResponseView {
                status,
                headers: &resp_headers,
                trailers: None,
            },
            body_mode: response_body_mode,
            constraints: ResponseProtocolConstraints {
                protocol: ResponseNormalizationProtocol::Http3,
                strip_connection_headers: true,
                allow_trailers: true,
                preserve_upgrade: false,
            },
        });
        let body_forwarding_enabled = matches!(
            normalized_response.emission.body,
            ResponseBodyPolicy::Forward
        );
        let progressive_body_emission_allowed =
            !normalized_response.emission.emit_end_stream_on_headers;
        let response_guardrails = ResponseBodyGuardrailConfig {
            idle_timeout: progress_config.backend_body_idle_timeout,
            total_timeout: progress_config.backend_body_total_timeout,
            max_body_bytes: progress_config.max_response_body_bytes,
            unknown_length_prebuffer_bytes: progress_config.unknown_length_response_prebuffer_bytes,
            chunk_bytes: RESPONSE_CHUNK_BYTES_LIMIT,
        };
        let preflight_guardrail = checked_response_body_guardrails(
            response_guardrails,
            ResponseBodyGuardrailInput {
                elapsed: Duration::ZERO,
                idle_for: Duration::ZERO,
                bytes_received: 0,
                prebuffered_bytes: 0,
                next_chunk_bytes: 0,
                declared_content_length: upstream_content_length,
                headers_emitted: false,
                progressive_emission_allowed: progressive_body_emission_allowed,
                body_forwarding_enabled,
                exempt_from_body_size_cap: tunnel_response,
            },
        );
        if matches!(
            preflight_guardrail,
            Err(ResponseBodyGuardrailDecision::Reject {
                kind: BodyLimitKind::BodySize,
            })
        ) {
            return ResponseStartDecision::ImmediateTerminal {
                metadata: ResponseStartMetadata {
                    status: http::StatusCode::SERVICE_UNAVAILABLE,
                    headers: Vec::new(),
                    headers_deferred: false,
                },
                terminal: ImmediateResponseStart::SyntheticBody(RESPONSE_BODY_TOO_LARGE_BODY),
                observation: ResponseStartObservation::ProxyError {
                    status: http::StatusCode::SERVICE_UNAVAILABLE,
                    error: ProxyError::Pool(PoolError::BackendOverloaded(
                        "response prebuffer cap".into(),
                    )),
                    overload_reason: Some(OverloadShedReason::ResponsePrebufferCap),
                },
            };
        }

        let mut headers: Vec<(Vec<u8>, Vec<u8>)> = normalized_response
            .head
            .headers
            .iter()
            .map(|header| {
                (
                    header.name.as_str().as_bytes().to_vec(),
                    header.value.as_bytes().to_vec(),
                )
            })
            .collect();
        headers.push((
            b"alt-svc".to_vec(),
            format!("h3=\":{}\"; ma=86400", progress_config.listen_port).into_bytes(),
        ));

        let defer_headers_until_body_validated = matches!(
            preflight_guardrail,
            Ok(crate::runtime::connection::guardrails::EvaluatedResponseBodyGuardrail {
                streaming,
                ..
            }) if matches!(
                streaming.emission,
                ProgressiveEmissionPolicy::PrebufferUntilValidated
            )
        );
        let observation = ResponseStartObservation::Status { status };

        if normalized_response.emission.emit_end_stream_on_headers {
            return ResponseStartDecision::ImmediateTerminal {
                metadata: ResponseStartMetadata {
                    status,
                    headers,
                    headers_deferred: false,
                },
                terminal: ImmediateResponseStart::NormalizedHeadersOnly,
                observation,
            };
        }

        if let Some(response_chunk_rx) = prebuilt_response_chunk_rx {
            return ResponseStartDecision::StreamingPrebuilt {
                metadata: ResponseStartMetadata {
                    status,
                    headers,
                    headers_deferred: false,
                },
                response_chunk_rx,
                observation,
            };
        }

        let Some(response_body) = response_body else {
            return ResponseStartDecision::BackendFailure(ProxyError::Transport(
                "non-tunnel responses must carry an HTTP body stream".into(),
            ));
        };

        ResponseStartDecision::StreamingBodyPump {
            metadata: ResponseStartMetadata {
                status,
                headers,
                headers_deferred: defer_headers_until_body_validated,
            },
            response_body,
            pump: ResponseBodyPumpPlan {
                guardrails: response_guardrails,
                upstream_content_length,
                body_forwarding_enabled,
                progressive_emission_allowed: progressive_body_emission_allowed,
                defer_headers_until_body_validated,
                tunnel_response,
            },
            observation,
        }
    }

    /// Handle an already-resolved `ForwardResult`, applying health transitions
    /// and sending the H3 response.
    pub(super) fn handle_forward_result(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        req: &RequestEnvelope,
        result: ForwardResult,
        shared_ctx: &ForwardingSharedCtx<'_>,
    ) -> Result<(), quiche::h3::Error> {
        let metrics = shared_ctx.metrics.as_ref();
        let routing_index = shared_ctx.routing_index;
        let upstream_pools = shared_ctx.upstream_pools;
        let overload_retry_after_seconds = shared_ctx.resilience.shed_retry_after_seconds;
        let route_target = Self::request_outcome_route_target(req);
        let backend_target = Self::request_outcome_backend_target(req);

        let (backend_addr, backend_index) = match (&req.backend_addr, req.backend_index) {
            (Some(a), Some(i)) => (a.as_str(), i),
            _ => {
                let status = if req.method.is_empty() || req.path.is_empty() {
                    http::StatusCode::BAD_REQUEST
                } else {
                    http::StatusCode::SERVICE_UNAVAILABLE
                };
                let _ = crate::runtime::connection::outcome::observe_status_outcome(
                    metrics,
                    route_target,
                    backend_target,
                    req.start.elapsed(),
                    status,
                );
                return Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    status,
                    b"no upstream available\n",
                );
            }
        };

        let upstream_name = routing_index.lookup(&req.path, req.authority.as_deref());
        let upstream_pool = req
            .upstream_pool
            .as_ref()
            .cloned()
            .or_else(|| upstream_name.and_then(|n| upstream_pools.get(n)).cloned());

        match result {
            Ok(_) => {
                error!("Unexpected successful forward result in error handler path");
                metrics.inc_backend_error();
                let _ = crate::runtime::connection::outcome::observe_status_outcome(
                    metrics,
                    route_target,
                    backend_target,
                    req.start.elapsed(),
                    http::StatusCode::BAD_GATEWAY,
                );
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::BAD_GATEWAY,
                    b"unexpected upstream state\n",
                )
            }
            Err(ProxyError::Bridge(err)) => {
                error!("Bridge error: {:?}", err);
                let _ = crate::runtime::connection::outcome::observe_status_outcome(
                    metrics,
                    route_target,
                    backend_target,
                    req.start.elapsed(),
                    http::StatusCode::BAD_REQUEST,
                );
                Self::log_access(req, 400);
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::BAD_REQUEST,
                    b"invalid request\n",
                )
            }
            Err(ProxyError::Pool(PoolError::BackendOverloaded(reason))) => {
                let overload_reason = if is_unknown_length_response_prebuffer_reason(&reason) {
                    metrics.inc_response_prebuffer_limit_reject();
                    OverloadShedReason::ResponsePrebufferCap
                } else {
                    OverloadShedReason::BackendInflight
                };
                let overload_error = ProxyError::Pool(PoolError::BackendOverloaded(reason));
                let _ = crate::runtime::connection::outcome::observe_proxy_error_outcome(
                    metrics,
                    route_target,
                    backend_target,
                    req.start.elapsed(),
                    Some(http::StatusCode::SERVICE_UNAVAILABLE),
                    &overload_error,
                    Some(overload_reason),
                );
                Self::log_access(req, 503);
                Self::send_overload_response(
                    h3,
                    quic,
                    stream_id,
                    b"backend overloaded, retry later\n",
                    overload_retry_after_seconds,
                )
            }
            Err(ProxyError::Pool(PoolError::CircuitOpen(reason))) => {
                metrics.inc_circuit_breaker_rejected();
                let circuit_open = ProxyError::Pool(PoolError::CircuitOpen(reason));
                let _ = crate::runtime::connection::outcome::observe_proxy_error_outcome(
                    metrics,
                    route_target,
                    backend_target,
                    req.start.elapsed(),
                    Some(http::StatusCode::SERVICE_UNAVAILABLE),
                    &circuit_open,
                    Some(OverloadShedReason::CircuitOpen),
                );
                Self::log_access(req, 503);
                Self::send_overload_response(
                    h3,
                    quic,
                    stream_id,
                    b"backend circuit open, retry later\n",
                    overload_retry_after_seconds,
                )
            }
            Err(ProxyError::Pool(pool_err @ PoolError::InflightLimiterClosed))
            | Err(ProxyError::Pool(pool_err @ PoolError::UnknownBackend(_))) => {
                debug_assert!(Self::is_internal_pool_control_error(&pool_err));
                match &pool_err {
                    PoolError::InflightLimiterClosed => {
                        error!("Upstream pool inflight limiter closed");
                    }
                    PoolError::UnknownBackend(_) => {
                        error!("Upstream pool unknown backend");
                    }
                    _ => {}
                }
                metrics.inc_backend_error();
                let _ = crate::runtime::connection::outcome::observe_status_outcome(
                    metrics,
                    route_target,
                    backend_target,
                    req.start.elapsed(),
                    http::StatusCode::BAD_GATEWAY,
                );
                Self::log_access(req, 502);
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::BAD_GATEWAY,
                    b"upstream error\n",
                )
            }
            Err(err) => {
                let Some(classified) = classify_upstream_proxy_error(&err) else {
                    error!(
                        "request_id={} upstream={} backend={} unclassified forward error: {:?}",
                        req.request_id,
                        req.upstream_name.as_deref().unwrap_or("-"),
                        backend_addr,
                        err
                    );
                    metrics.inc_backend_error();
                    let _ = crate::runtime::connection::outcome::observe_status_outcome(
                        metrics,
                        route_target,
                        backend_target,
                        req.start.elapsed(),
                        http::StatusCode::BAD_GATEWAY,
                    );
                    Self::log_access(req, 502);
                    return Self::send_simple_response(
                        h3,
                        quic,
                        stream_id,
                        http::StatusCode::BAD_GATEWAY,
                        b"upstream error\n",
                    );
                };
                Self::log_classified_upstream_failure(
                    "data_plane",
                    Some(req.request_id),
                    req.upstream_name.as_deref(),
                    backend_addr,
                    &classified,
                );
                let _ =
                    crate::runtime::connection::outcome::observe_classified_backend_failure_and_log(
                        crate::runtime::connection::outcome::ClassifiedBackendFailureInput {
                            metrics_phase: "data_plane",
                            upstream_name: req.upstream_name.as_deref().unwrap_or("unknown"),
                            backend_addr,
                            backend_index,
                            upstream_pool: upstream_pool.as_ref(),
                            metrics,
                            classified: &classified,
                        },
                    );

                match classified.kind {
                    UpstreamProxyErrorKind::Timeout => {
                        metrics.inc_timeout();
                        let _ = crate::runtime::connection::outcome::observe_proxy_error_outcome(
                            metrics,
                            route_target,
                            backend_target,
                            req.start.elapsed(),
                            Some(http::StatusCode::SERVICE_UNAVAILABLE),
                            &err,
                            None,
                        );
                        Self::log_access(req, 503);
                        Self::send_simple_response(
                            h3,
                            quic,
                            stream_id,
                            http::StatusCode::SERVICE_UNAVAILABLE,
                            b"upstream timeout\n",
                        )
                    }
                    UpstreamProxyErrorKind::Tls => {
                        let _ = crate::runtime::connection::outcome::observe_status_outcome(
                            metrics,
                            route_target,
                            backend_target,
                            req.start.elapsed(),
                            http::StatusCode::INTERNAL_SERVER_ERROR,
                        );
                        Self::log_access(req, 500);
                        Self::send_simple_response(
                            h3,
                            quic,
                            stream_id,
                            http::StatusCode::INTERNAL_SERVER_ERROR,
                            b"internal server error\n",
                        )
                    }
                    UpstreamProxyErrorKind::Protocol => {
                        metrics.inc_backend_error();
                        let _ = crate::runtime::connection::outcome::observe_status_outcome(
                            metrics,
                            route_target,
                            backend_target,
                            req.start.elapsed(),
                            http::StatusCode::BAD_GATEWAY,
                        );
                        Self::log_access(req, 502);
                        Self::send_simple_response(
                            h3,
                            quic,
                            stream_id,
                            http::StatusCode::BAD_GATEWAY,
                            b"upstream protocol error\n",
                        )
                    }
                    UpstreamProxyErrorKind::Transport => {
                        metrics.inc_backend_error();
                        let _ = crate::runtime::connection::outcome::observe_status_outcome(
                            metrics,
                            route_target,
                            backend_target,
                            req.start.elapsed(),
                            http::StatusCode::BAD_GATEWAY,
                        );
                        Self::log_access(req, 502);
                        Self::send_simple_response(
                            h3,
                            quic,
                            stream_id,
                            http::StatusCode::BAD_GATEWAY,
                            b"upstream error\n",
                        )
                    }
                }
            }
        }
    }

    pub(super) fn send_simple_response(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        status: http::StatusCode,
        body: &[u8],
    ) -> Result<(), quiche::h3::Error> {
        let resp_headers = simple_response_headers(status, body);

        h3.send_response(quic, stream_id, &resp_headers, false)?;
        h3.send_body(quic, stream_id, body, true)?;
        Ok(())
    }

    pub(super) fn send_overload_response(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        body: &[u8],
        retry_after_seconds: u32,
    ) -> Result<(), quiche::h3::Error> {
        let resp_headers = overload_response_headers(body, retry_after_seconds);

        h3.send_response(quic, stream_id, &resp_headers, false)?;
        h3.send_body(quic, stream_id, body, true)?;
        Ok(())
    }

    pub(super) fn send_admission_rejection_response(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        response: &crate::quic_listener::admission::AdmissionRejectionResponse,
    ) -> Result<(), quiche::h3::Error> {
        let headers = admission_rejection_headers(response);

        h3.send_response(quic, stream_id, &headers, false)?;
        h3.send_body(quic, stream_id, response.body, true)?;
        Ok(())
    }

    fn send_response_with_headers_and_extra(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        status: http::StatusCode,
        body: &[u8],
        headers: &[(String, String)],
        extra_header: Option<(&str, &str)>,
    ) -> Result<(), quiche::h3::Error> {
        let resp_headers = response_headers_with_defaults_and_extra_bytes(
            status,
            body,
            headers
                .iter()
                .map(|(name, value)| (name.as_bytes(), value.as_bytes())),
            extra_header.map(|(name, value)| (name.as_bytes(), value.as_bytes())),
        );
        h3.send_response(quic, stream_id, &resp_headers, false)?;
        h3.send_body(quic, stream_id, body, true)?;
        Ok(())
    }

    pub(super) fn send_external_auth_decision_response(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        decision: &ExternalAuthDecision,
    ) -> Result<(), quiche::h3::Error> {
        match decision {
            ExternalAuthDecision::Allow { .. } => Ok(()),
            ExternalAuthDecision::Deny(response) => Self::send_response_with_headers_and_extra(
                h3,
                quic,
                stream_id,
                response.status,
                &response.body,
                &response.headers,
                None,
            ),
            ExternalAuthDecision::Redirect(response) => Self::send_response_with_headers_and_extra(
                h3,
                quic,
                stream_id,
                response.status,
                &[],
                &response.headers,
                Some((http::header::LOCATION.as_str(), response.location.as_str())),
            ),
            ExternalAuthDecision::Challenge(response) => {
                Self::send_response_with_headers_and_extra(
                    h3,
                    quic,
                    stream_id,
                    response.status,
                    &response.body,
                    &response.headers,
                    Some((
                        http::header::WWW_AUTHENTICATE.as_str(),
                        response.www_authenticate.as_str(),
                    )),
                )
            }
        }
    }

    fn send_response_start_headers(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        metadata: &ResponseStartMetadata,
        end_stream: bool,
    ) -> Result<(), ProxyError> {
        let h3_headers = Self::response_start_header_block(metadata.status, &metadata.headers);
        h3.send_response(quic, stream_id, &h3_headers, end_stream)
            .map_err(|err| {
                ProxyError::Protocol(format!("failed to send HTTP/3 response headers: {:?}", err))
            })
    }

    fn spawn_response_body_pump(
        req: &RequestEnvelope,
        response_body: UpstreamBody,
        deferred_start: Option<ResponseChunk>,
        pump: ResponseBodyPumpPlan,
    ) -> mpsc::Receiver<ResponseChunk> {
        let (chunk_tx, chunk_rx) = mpsc::channel::<ResponseChunk>(RESPONSE_CHUNK_CHANNEL_CAPACITY);
        let fail_tx = chunk_tx.clone();
        let fut = async move {
            let mut body = response_body;
            let mut deferred_start = deferred_start;
            let body_started_at = tokio::time::Instant::now();
            let mut last_body_progress_at = body_started_at;
            let mut response_bytes_received: usize = 0;
            let mut prebuffered_bytes: usize = 0;
            let mut buffered_chunks: Vec<Bytes> = Vec::new();
            let mut buffered_trailers: Option<Vec<(Vec<u8>, Vec<u8>)>> = None;
            loop {
                let wait_decision = checked_response_body_guardrails(
                    pump.guardrails,
                    ResponseBodyGuardrailInput {
                        elapsed: body_started_at.elapsed(),
                        idle_for: last_body_progress_at.elapsed(),
                        bytes_received: response_bytes_received,
                        prebuffered_bytes,
                        next_chunk_bytes: 0,
                        declared_content_length: pump.upstream_content_length,
                        headers_emitted: !pump.defer_headers_until_body_validated,
                        progressive_emission_allowed: pump.progressive_emission_allowed,
                        body_forwarding_enabled: pump.body_forwarding_enabled,
                        exempt_from_body_size_cap: pump.tunnel_response,
                    },
                );
                let streaming = match wait_decision {
                    Ok(evaluated) => evaluated.streaming,
                    other => {
                        if let Err(other) = other
                            && let Some(chunk) = response_body_guardrail_chunk(other)
                        {
                            let _ = chunk_tx.send(chunk).await;
                        }
                        return;
                    }
                };
                let frame_fut = body.recv();
                let result = tokio::time::timeout(streaming.wait_timeout, frame_fut).await;
                match result {
                    Err(_elapsed) => {
                        let _ = chunk_tx
                            .send(ResponseChunk::Timeout(response_body_wait_timeout_reason(
                                pump.guardrails,
                                body_started_at,
                                last_body_progress_at,
                            )))
                            .await;
                        return;
                    }
                    Ok(Some(Ok(frame))) => match frame {
                        UpstreamBodyFrame::Data(data) => {
                            if !data.is_empty() {
                                last_body_progress_at = tokio::time::Instant::now();
                            }
                            let data_decision = checked_response_body_guardrails(
                                pump.guardrails,
                                ResponseBodyGuardrailInput {
                                    elapsed: body_started_at.elapsed(),
                                    idle_for: last_body_progress_at.elapsed(),
                                    bytes_received: response_bytes_received,
                                    prebuffered_bytes,
                                    next_chunk_bytes: data.len(),
                                    declared_content_length: pump.upstream_content_length,
                                    headers_emitted: !pump.defer_headers_until_body_validated,
                                    progressive_emission_allowed: pump.progressive_emission_allowed,
                                    body_forwarding_enabled: pump.body_forwarding_enabled,
                                    exempt_from_body_size_cap: pump.tunnel_response,
                                },
                            );
                            let evaluated = match data_decision {
                                Ok(evaluated) => evaluated,
                                other => {
                                    if let Err(other) = other
                                        && let Some(chunk) = response_body_guardrail_chunk(other)
                                    {
                                        let _ = chunk_tx.send(chunk).await;
                                    }
                                    return;
                                }
                            };
                            let streaming = evaluated.streaming;
                            response_bytes_received = evaluated.next_state.bytes_received;
                            prebuffered_bytes = evaluated.next_state.prebuffered_bytes;
                            for (start, end) in
                                response_chunk_ranges(data.len(), streaming.chunk_emission)
                            {
                                let chunk = data.slice(start..end);
                                match streaming.emission {
                                    ProgressiveEmissionPolicy::PrebufferUntilValidated => {
                                        buffered_chunks.push(chunk);
                                    }
                                    ProgressiveEmissionPolicy::StreamProgressively => {
                                        if chunk_tx.send(ResponseChunk::Data(chunk)).await.is_err()
                                        {
                                            return;
                                        }
                                    }
                                    ProgressiveEmissionPolicy::SuppressBody => {}
                                }
                            }
                        }
                        UpstreamBodyFrame::Trailers(trailers) => {
                            let trailer_headers = collect_h3_trailers(&trailers);
                            if !trailer_headers.is_empty() {
                                if pump.defer_headers_until_body_validated {
                                    buffered_trailers = Some(trailer_headers);
                                } else if chunk_tx
                                    .send(ResponseChunk::Trailers {
                                        headers: trailer_headers,
                                    })
                                    .await
                                    .is_err()
                                {
                                    return;
                                }
                            }
                        }
                    },
                    Ok(Some(Err(error))) => {
                        let _ = chunk_tx.send(ResponseChunk::Error(error)).await;
                        return;
                    }
                    Ok(None) => {
                        if let Some(start) = deferred_start.take()
                            && chunk_tx.send(start).await.is_err()
                        {
                            return;
                        }
                        if pump.defer_headers_until_body_validated {
                            for chunk in buffered_chunks {
                                if chunk_tx.send(ResponseChunk::Data(chunk)).await.is_err() {
                                    return;
                                }
                            }
                        }
                        if let Some(headers) = buffered_trailers
                            && chunk_tx
                                .send(ResponseChunk::Trailers { headers })
                                .await
                                .is_err()
                        {
                            return;
                        }
                        let _ = chunk_tx.send(ResponseChunk::End).await;
                        return;
                    }
                }
            }
        };
        let spawned = match req.trace_span.clone() {
            Some(span) => spawn_async_task(fut.instrument(span), "body-pump"),
            None => spawn_async_task(fut, "body-pump"),
        };
        if !spawned {
            let _ = fail_tx.try_send(ResponseChunk::Error(ProxyError::Transport(
                "runtime unavailable".into(),
            )));
        }
        chunk_rx
    }

    fn observe_response_start_transition(
        req: &RequestEnvelope,
        observation: &ResponseStartObservation,
        shared_ctx: &ForwardingSharedCtx<'_>,
    ) {
        let metrics = shared_ctx.metrics.as_ref();
        let resilience = shared_ctx.resilience;
        match observation {
            ResponseStartObservation::Status { status } => {
                if let (Some(addr), Some(idx)) = (&req.backend_addr, req.backend_index) {
                    let _ = crate::runtime::connection::outcome::observe_backend_response_status_and_log(
                        crate::runtime::connection::outcome::BackendHealthObservationInput {
                            backend_addr: addr,
                            backend_index: idx,
                            upstream_pool: req.upstream_pool.as_ref(),
                            status: *status,
                        },
                    );
                }
                let _ = crate::runtime::connection::outcome::observe_status_outcome(
                    metrics,
                    Self::request_outcome_route_target(req),
                    Self::request_outcome_backend_target(req),
                    req.start.elapsed(),
                    *status,
                );
                resilience
                    .adaptive_admission
                    .observe(req.start.elapsed(), false);
                Self::log_access(req, status.as_u16());
            }
            ResponseStartObservation::ProxyError {
                status,
                error,
                overload_reason,
            } => {
                let _ = crate::runtime::connection::outcome::observe_proxy_error_outcome(
                    metrics,
                    Self::request_outcome_route_target(req),
                    Self::request_outcome_backend_target(req),
                    req.start.elapsed(),
                    Some(*status),
                    error,
                    *overload_reason,
                );
                resilience
                    .adaptive_admission
                    .observe(req.start.elapsed(), true);
                Self::log_access(req, status.as_u16());
            }
        }
    }

    pub(super) fn apply_response_start_decision(
        stream_id: u64,
        req: &mut RequestEnvelope,
        decision: ResponseStartDecision,
        quic: &mut quiche::Connection,
        h3: &mut quiche::h3::Connection,
        shared_ctx: &ForwardingSharedCtx<'_>,
    ) -> Result<bool, ProxyError> {
        let metrics = shared_ctx.metrics.as_ref();
        match decision {
            ResponseStartDecision::ImmediateTerminal {
                metadata,
                terminal,
                observation,
            } => {
                if let ResponseStartObservation::ProxyError {
                    overload_reason, ..
                } = &observation
                {
                    req.set_terminal_overload_reason(*overload_reason);
                }
                match terminal {
                    ImmediateResponseStart::NormalizedHeadersOnly => {
                        Self::send_response_start_headers(h3, quic, stream_id, &metadata, true)?;
                    }
                    ImmediateResponseStart::SyntheticBody(body) => {
                        Self::send_simple_response(h3, quic, stream_id, metadata.status, body)
                            .map_err(|err| {
                                ProxyError::Protocol(format!(
                                    "failed to send terminal response: {:?}",
                                    err
                                ))
                            })?;
                    }
                }
                req.response_status = Some(metadata.status.as_u16());
                req.mark_terminal_outcome_recorded();
                req.transition_streaming_to_completed(CompletionReason::ImmediateResponse, metrics);
                Self::observe_response_start_transition(req, &observation, shared_ctx);
                Ok(true)
            }
            ResponseStartDecision::StreamingPrebuilt {
                metadata,
                response_chunk_rx,
                observation,
            } => {
                Self::send_response_start_headers(h3, quic, stream_id, &metadata, false)?;
                req.response_status = Some(metadata.status.as_u16());
                if let Err(state_err) = req.transition_to_streaming_response(
                    response_chunk_rx,
                    ResponseEmissionState::HeadersSent,
                    metadata.status,
                ) {
                    return Self::fail_response_start_state_transition(
                        stream_id,
                        req,
                        h3,
                        quic,
                        shared_ctx,
                        metadata.status,
                        true,
                        state_err.attempted(),
                    );
                }
                Self::observe_response_start_transition(req, &observation, shared_ctx);
                Ok(false)
            }
            ResponseStartDecision::StreamingBodyPump {
                metadata,
                response_body,
                pump,
                observation,
            } => {
                let response_status = metadata.status;
                let response_headers_sent = metadata.response_headers_sent();
                if !metadata.headers_deferred {
                    Self::send_response_start_headers(h3, quic, stream_id, &metadata, false)?;
                }
                let deferred_start = Self::into_deferred_response_start_chunk(metadata);
                let chunk_rx =
                    Self::spawn_response_body_pump(req, response_body, deferred_start, pump);
                req.response_status = Some(response_status.as_u16());
                if let Err(state_err) = req.transition_to_streaming_response(
                    chunk_rx,
                    if response_headers_sent {
                        ResponseEmissionState::HeadersSent
                    } else {
                        ResponseEmissionState::DeferredHeaders
                    },
                    response_status,
                ) {
                    return Self::fail_response_start_state_transition(
                        stream_id,
                        req,
                        h3,
                        quic,
                        shared_ctx,
                        response_status,
                        response_headers_sent,
                        state_err.attempted(),
                    );
                }
                Self::observe_response_start_transition(req, &observation, shared_ctx);
                Ok(false)
            }
            ResponseStartDecision::BackendFailure(err) => Err(err),
        }
    }

    pub(super) fn flush_response_chunks(
        stream_id: u64,
        req: &mut RequestEnvelope,
        quic: &mut quiche::Connection,
        h3: &mut quiche::h3::Connection,
        shared_ctx: &ForwardingSharedCtx<'_>,
    ) -> bool {
        let metrics = shared_ctx.metrics.as_ref();
        let resilience = shared_ctx.resilience;
        let routing_index = shared_ctx.routing_index;
        let upstream_pools = shared_ctx.upstream_pools;
        let mut terminal = false;
        loop {
            let chunk = match req.take_pending_chunk() {
                Some(c) => c,
                None => {
                    let Some(rx) = req.response_chunk_rx_mut() else {
                        return false;
                    };
                    match rx.try_recv() {
                        Ok(c) => c,
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Disconnected) => {
                            req.transition_streaming_to_backend_failed(
                                BackendFailureReason::ResponseStreamAborted,
                                metrics,
                            );
                            terminal = true;
                            break;
                        }
                    }
                }
            };
            match chunk {
                ResponseChunk::Start { status, headers } => {
                    let h3_headers = Self::response_start_header_block(status, &headers);
                    match h3.send_response(quic, stream_id, &h3_headers, false) {
                        Ok(_) => {
                            req.set_response_emission_state(ResponseEmissionState::HeadersSent);
                        }
                        Err(quiche::h3::Error::StreamBlocked) => {
                            req.set_pending_chunk(Some(ResponseChunk::Start { status, headers }));
                            break;
                        }
                        Err(err) => {
                            error!(
                                "HTTP/3 send_response protocol error on stream {}: {:?}",
                                stream_id, err
                            );
                            metrics.inc_backend_error();
                            let _ = crate::runtime::connection::outcome::observe_status_outcome(
                                metrics,
                                Self::request_outcome_route_target(req),
                                Self::request_outcome_backend_target(req),
                                req.start.elapsed(),
                                status,
                            );
                            resilience
                                .adaptive_admission
                                .observe(req.start.elapsed(), true);
                            req.transition_streaming_to_backend_failed(
                                BackendFailureReason::ResponseWriteFailed,
                                metrics,
                            );
                            terminal = true;
                            break;
                        }
                    }
                }
                ResponseChunk::Data(data) => match h3.send_body(quic, stream_id, &data, false) {
                    Ok(_) => {
                        req.set_response_emission_state(ResponseEmissionState::StreamingBody);
                    }
                    Err(quiche::h3::Error::StreamBlocked) => {
                        req.set_pending_chunk(Some(ResponseChunk::Data(data)));
                        break;
                    }
                    Err(err) => {
                        error!(
                            "HTTP/3 send_body data protocol error on stream {}: {:?}",
                            stream_id, err
                        );
                        metrics.inc_backend_error();
                        let _ = crate::runtime::connection::outcome::observe_status_outcome(
                            metrics,
                            Self::request_outcome_route_target(req),
                            Self::request_outcome_backend_target(req),
                            req.start.elapsed(),
                            req.response_status
                                .and_then(|status| http::StatusCode::from_u16(status).ok())
                                .unwrap_or(http::StatusCode::BAD_GATEWAY),
                        );
                        resilience
                            .adaptive_admission
                            .observe(req.start.elapsed(), true);
                        req.transition_streaming_to_backend_failed(
                            BackendFailureReason::ResponseWriteFailed,
                            metrics,
                        );
                        terminal = true;
                        break;
                    }
                },
                ResponseChunk::Trailers { headers } => {
                    let mut h3_headers = Vec::with_capacity(headers.len());
                    for (name, value) in &headers {
                        h3_headers.push(quiche::h3::Header::new(name, value));
                    }
                    match h3.send_additional_headers(quic, stream_id, &h3_headers, false, false) {
                        Ok(_) => {
                            req.set_response_emission_state(ResponseEmissionState::TrailersPending);
                        }
                        Err(quiche::h3::Error::StreamBlocked) => {
                            req.set_pending_chunk(Some(ResponseChunk::Trailers { headers }));
                            break;
                        }
                        Err(err) => {
                            error!(
                                "HTTP/3 send_additional_headers protocol error on stream {}: {:?}",
                                stream_id, err
                            );
                            metrics.inc_backend_error();
                            let _ = crate::runtime::connection::outcome::observe_status_outcome(
                                metrics,
                                Self::request_outcome_route_target(req),
                                Self::request_outcome_backend_target(req),
                                req.start.elapsed(),
                                req.response_status
                                    .and_then(|status| http::StatusCode::from_u16(status).ok())
                                    .unwrap_or(http::StatusCode::BAD_GATEWAY),
                            );
                            resilience
                                .adaptive_admission
                                .observe(req.start.elapsed(), true);
                            req.transition_streaming_to_backend_failed(
                                BackendFailureReason::ResponseWriteFailed,
                                metrics,
                            );
                            terminal = true;
                            break;
                        }
                    }
                }
                ResponseChunk::End => match h3.send_body(quic, stream_id, b"", true) {
                    Ok(_) => {
                        req.set_response_emission_state(ResponseEmissionState::EndPending);
                        req.transition_streaming_to_completed(
                            CompletionReason::ResponseStreamFinished,
                            metrics,
                        );
                        terminal = true;
                        break;
                    }
                    Err(quiche::h3::Error::StreamBlocked) => {
                        req.set_pending_chunk(Some(ResponseChunk::End));
                        break;
                    }
                    Err(err) => {
                        error!(
                            "HTTP/3 send_body end protocol error on stream {}: {:?}",
                            stream_id, err
                        );
                        metrics.inc_backend_error();
                        let _ = crate::runtime::connection::outcome::observe_status_outcome(
                            metrics,
                            Self::request_outcome_route_target(req),
                            Self::request_outcome_backend_target(req),
                            req.start.elapsed(),
                            req.response_status
                                .and_then(|status| http::StatusCode::from_u16(status).ok())
                                .unwrap_or(http::StatusCode::BAD_GATEWAY),
                        );
                        resilience
                            .adaptive_admission
                            .observe(req.start.elapsed(), true);
                        req.transition_streaming_to_backend_failed(
                            BackendFailureReason::ResponseWriteFailed,
                            metrics,
                        );
                        terminal = true;
                        break;
                    }
                },
                ResponseChunk::Error(err) => {
                    let classified = classify_upstream_proxy_error(&err);
                    if !req.response_headers_sent() {
                        let (status, body): (http::StatusCode, &[u8]) =
                            match (&err, classified.as_ref()) {
                                (ProxyError::Pool(PoolError::BackendOverloaded(_)), _) => (
                                    http::StatusCode::SERVICE_UNAVAILABLE,
                                    b"upstream response body too large\n",
                                ),
                                (_, Some(classified))
                                    if classified.kind == UpstreamProxyErrorKind::Timeout =>
                                {
                                    (http::StatusCode::SERVICE_UNAVAILABLE, b"upstream timeout\n")
                                }
                                _ => (http::StatusCode::BAD_GATEWAY, b"upstream error\n"),
                            };
                        let _ = Self::send_simple_response(h3, quic, stream_id, status, body);
                    } else {
                        // The advertised response is incomplete, so a clean FIN would
                        // incorrectly present truncated bytes as a successful response.
                        let _ = quic.stream_shutdown(
                            stream_id,
                            quiche::Shutdown::Write,
                            0x102, // H3_INTERNAL_ERROR
                        );
                    }
                    let upstream_name = routing_index.lookup(&req.path, req.authority.as_deref());
                    let upstream_pool = upstream_name.and_then(|n| upstream_pools.get(n));
                    if let (Some(addr), Some(idx), Some(classified)) = (
                        req.backend_addr.as_deref(),
                        req.backend_index,
                        classified.as_ref(),
                    ) {
                        let _ = crate::runtime::connection::outcome::observe_classified_backend_failure_and_log(
                            crate::runtime::connection::outcome::ClassifiedBackendFailureInput {
                                metrics_phase: "data_plane",
                                upstream_name: upstream_name.unwrap_or("unknown"),
                                backend_addr: addr,
                                backend_index: idx,
                                upstream_pool,
                                metrics,
                                classified,
                            },
                        );
                    } else if let (Some(addr), Some(idx)) =
                        (req.backend_addr.as_deref(), req.backend_index)
                        && crate::runtime::connection::outcome::observe_backend_response_status_and_log(
                            crate::runtime::connection::outcome::BackendHealthObservationInput {
                                backend_addr: addr,
                                backend_index: idx,
                                upstream_pool,
                                status: req
                                    .response_status
                                    .and_then(|code| http::StatusCode::from_u16(code).ok())
                                    .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR),
                            },
                        ).is_some()
                    {
                    }
                    match err {
                        ProxyError::Timeout => {
                            metrics.inc_timeout();
                            let _ =
                                crate::runtime::connection::outcome::observe_proxy_error_outcome(
                                    metrics,
                                    Self::request_outcome_route_target(req),
                                    Self::request_outcome_backend_target(req),
                                    req.start.elapsed(),
                                    req.response_status
                                        .and_then(|status| http::StatusCode::from_u16(status).ok())
                                        .or(Some(http::StatusCode::SERVICE_UNAVAILABLE)),
                                    &err,
                                    None,
                                );
                            resilience
                                .adaptive_admission
                                .observe(req.start.elapsed(), true);
                            debug!(
                                "Upstream {} body timeout latency_ms {}",
                                req.backend_addr.as_deref().unwrap_or("?"),
                                req.start.elapsed().as_millis()
                            );
                        }
                        ProxyError::Pool(PoolError::BackendOverloaded(reason)) => {
                            let overload_reason =
                                if is_unknown_length_response_prebuffer_reason(&reason) {
                                    metrics.inc_response_prebuffer_limit_reject();
                                    OverloadShedReason::ResponsePrebufferCap
                                } else {
                                    OverloadShedReason::BackendInflight
                                };
                            let overload_error =
                                ProxyError::Pool(PoolError::BackendOverloaded(reason.clone()));
                            let _ =
                                crate::runtime::connection::outcome::observe_proxy_error_outcome(
                                    metrics,
                                    Self::request_outcome_route_target(req),
                                    Self::request_outcome_backend_target(req),
                                    req.start.elapsed(),
                                    req.response_status
                                        .and_then(|status| http::StatusCode::from_u16(status).ok())
                                        .or(Some(http::StatusCode::SERVICE_UNAVAILABLE)),
                                    &overload_error,
                                    Some(overload_reason),
                                );
                            resilience
                                .adaptive_admission
                                .observe(req.start.elapsed(), true);
                            error!(
                                "Upstream {} overload in response body path: {}",
                                req.backend_addr.as_deref().unwrap_or("?"),
                                reason
                            );
                        }
                        _ => {
                            metrics.inc_backend_error();
                            let _ =
                                crate::runtime::connection::outcome::observe_proxy_error_outcome(
                                    metrics,
                                    Self::request_outcome_route_target(req),
                                    Self::request_outcome_backend_target(req),
                                    req.start.elapsed(),
                                    req.response_status
                                        .and_then(|status| http::StatusCode::from_u16(status).ok())
                                        .or(Some(http::StatusCode::BAD_GATEWAY)),
                                    &err,
                                    None,
                                );
                            resilience
                                .adaptive_admission
                                .observe(req.start.elapsed(), true);
                            if let (Some(addr), Some(classified)) =
                                (req.backend_addr.as_deref(), classified.as_ref())
                            {
                                Self::log_classified_upstream_failure(
                                    "data_plane",
                                    Some(req.request_id),
                                    req.upstream_name.as_deref(),
                                    addr,
                                    classified,
                                );
                            } else {
                                error!(
                                    "Upstream {} body error: {:?}",
                                    req.backend_addr.as_deref().unwrap_or("?"),
                                    err
                                );
                            }
                        }
                    }
                    req.transition_streaming_to_backend_failed(
                        BackendFailureReason::ResponseStreamAborted,
                        metrics,
                    );
                    terminal = true;
                    break;
                }
                ResponseChunk::Timeout(reason) => {
                    metrics.inc_timeout();
                    let _ = crate::runtime::connection::outcome::observe_proxy_error_outcome(
                        metrics,
                        Self::request_outcome_route_target(req),
                        Self::request_outcome_backend_target(req),
                        req.start.elapsed(),
                        req.response_status
                            .and_then(|status| http::StatusCode::from_u16(status).ok())
                            .or(Some(http::StatusCode::SERVICE_UNAVAILABLE)),
                        &ProxyError::Timeout,
                        None,
                    );
                    if !req.response_headers_sent() {
                        let _ = Self::send_simple_response(
                            h3,
                            quic,
                            stream_id,
                            http::StatusCode::SERVICE_UNAVAILABLE,
                            b"upstream timeout\n",
                        );
                    } else {
                        let _ = h3.send_body(quic, stream_id, b"", true);
                    }
                    resilience
                        .adaptive_admission
                        .observe(req.start.elapsed(), true);
                    req.transition_streaming_to_timed_out(reason, metrics);
                    terminal = true;
                    break;
                }
            }
        }

        terminal
    }
}

#[cfg(test)]
mod tests {
    use quiche::h3::NameValue;

    use super::*;
    use crate::{
        quic_listener::admission::AdmissionRejectionResponse,
        runtime::connection::auth::{
            ExternalAuthChallengeResponse, ExternalAuthDenyResponse, ExternalAuthRedirectResponse,
        },
    };

    fn header_value<'a>(headers: &'a [quiche::h3::Header], name: &[u8]) -> Option<&'a [u8]> {
        headers
            .iter()
            .find(|header| header.name().eq_ignore_ascii_case(name))
            .map(|header| header.value())
    }

    #[test]
    fn simple_and_overload_local_responses_have_stable_wire_shape() {
        let simple = simple_response_headers(http::StatusCode::BAD_GATEWAY, b"upstream error\n");
        assert_eq!(header_value(&simple, b":status"), Some(&b"502"[..]));
        assert_eq!(
            header_value(&simple, b"content-type"),
            Some(&b"text/plain"[..])
        );
        assert_eq!(header_value(&simple, b"content-length"), Some(&b"15"[..]));

        let overload = overload_response_headers(b"busy\n", 0);
        assert_eq!(header_value(&overload, b":status"), Some(&b"503"[..]));
        assert_eq!(header_value(&overload, b"retry-after"), Some(&b"1"[..]));
        assert_eq!(header_value(&overload, b"content-length"), Some(&b"5"[..]));
    }

    #[test]
    fn admission_rejection_headers_preserve_only_supported_challenge_and_retry_metadata() {
        let auth = AdmissionRejectionResponse {
            status: http::StatusCode::UNAUTHORIZED,
            body: b"auth denied\n",
            www_authenticate: Some("Bearer realm=\"impulse\""),
            retry_after_seconds: None,
        };
        let auth_headers = admission_rejection_headers(&auth);
        assert_eq!(header_value(&auth_headers, b":status"), Some(&b"401"[..]));
        assert_eq!(
            header_value(&auth_headers, b"www-authenticate"),
            Some(&b"Bearer realm=\"impulse\""[..])
        );
        assert_eq!(header_value(&auth_headers, b"retry-after"), None);

        let overload = AdmissionRejectionResponse {
            status: http::StatusCode::SERVICE_UNAVAILABLE,
            body: b"overloaded\n",
            www_authenticate: None,
            retry_after_seconds: Some(0),
        };
        let overload_headers = admission_rejection_headers(&overload);
        assert_eq!(
            header_value(&overload_headers, b":status"),
            Some(&b"503"[..])
        );
        assert_eq!(header_value(&overload_headers, b"www-authenticate"), None);
        assert_eq!(
            header_value(&overload_headers, b"retry-after"),
            Some(&b"1"[..])
        );
    }

    #[test]
    fn response_headers_with_defaults_adds_only_missing_framing_headers() {
        let headers = response_headers_with_defaults(
            http::StatusCode::FORBIDDEN,
            b"denied\n",
            &[
                ("x-auth-reason".to_string(), "policy".to_string()),
                ("content-type".to_string(), "application/json".to_string()),
            ],
        );

        assert_eq!(header_value(&headers, b":status"), Some(&b"403"[..]));
        assert_eq!(
            header_value(&headers, b"content-type"),
            Some(&b"application/json"[..])
        );
        assert_eq!(header_value(&headers, b"content-length"), Some(&b"7"[..]));
        assert_eq!(
            header_value(&headers, b"x-auth-reason"),
            Some(&b"policy"[..])
        );
    }

    #[test]
    fn external_auth_deny_wire_shape_carries_allowed_headers_without_challenge_metadata() {
        let response = ExternalAuthDenyResponse {
            status: http::StatusCode::FORBIDDEN,
            headers: vec![("x-auth-reason".to_string(), "policy".to_string())],
            body: b"denied\n".to_vec(),
        };

        let headers =
            response_headers_with_defaults(response.status, &response.body, &response.headers);

        assert_eq!(header_value(&headers, b":status"), Some(&b"403"[..]));
        assert_eq!(
            header_value(&headers, b"x-auth-reason"),
            Some(&b"policy"[..])
        );
        assert_eq!(header_value(&headers, b"location"), None);
        assert_eq!(header_value(&headers, b"www-authenticate"), None);
    }

    #[test]
    fn external_auth_redirect_wire_shape_emits_location_and_zero_length_body() {
        let response = ExternalAuthRedirectResponse {
            status: http::StatusCode::TEMPORARY_REDIRECT,
            headers: vec![("x-auth-reason".to_string(), "login".to_string())],
            location: "https://login.example.com".to_string(),
        };

        let headers = response_headers_with_defaults_and_extra(
            response.status,
            &[],
            &response.headers,
            Some((http::header::LOCATION.as_str(), response.location.as_str())),
        );

        assert_eq!(header_value(&headers, b":status"), Some(&b"307"[..]));
        assert_eq!(
            header_value(&headers, b"location"),
            Some(&b"https://login.example.com"[..])
        );
        assert_eq!(header_value(&headers, b"content-length"), Some(&b"0"[..]));
        assert_eq!(header_value(&headers, b"www-authenticate"), None);
    }

    #[test]
    fn external_auth_challenge_wire_shape_emits_www_authenticate_with_body_length() {
        let response = ExternalAuthChallengeResponse {
            status: http::StatusCode::UNAUTHORIZED,
            headers: vec![("x-auth-reason".to_string(), "expired".to_string())],
            www_authenticate: "Bearer".to_string(),
            body: b"challenge\n".to_vec(),
        };

        let headers = response_headers_with_defaults_and_extra(
            response.status,
            &response.body,
            &response.headers,
            Some((
                http::header::WWW_AUTHENTICATE.as_str(),
                response.www_authenticate.as_str(),
            )),
        );

        assert_eq!(header_value(&headers, b":status"), Some(&b"401"[..]));
        assert_eq!(
            header_value(&headers, b"x-auth-reason"),
            Some(&b"expired"[..])
        );
        assert_eq!(
            header_value(&headers, b"www-authenticate"),
            Some(&b"Bearer"[..])
        );
        assert_eq!(header_value(&headers, b"content-length"), Some(&b"10"[..]));
    }

    #[test]
    fn external_auth_redirect_and_challenge_headers_match_historical_clone_contract() {
        let redirect = ExternalAuthRedirectResponse {
            status: http::StatusCode::TEMPORARY_REDIRECT,
            headers: vec![("x-auth-reason".to_string(), "login".to_string())],
            location: "https://login.example.com".to_string(),
        };
        let mut historical_redirect_headers = redirect.headers.clone();
        historical_redirect_headers.push((
            http::header::LOCATION.as_str().to_string(),
            redirect.location.clone(),
        ));
        let historical_redirect =
            response_headers_with_defaults(redirect.status, &[], &historical_redirect_headers);
        let current_redirect = response_headers_with_defaults_and_extra(
            redirect.status,
            &[],
            &redirect.headers,
            Some((http::header::LOCATION.as_str(), redirect.location.as_str())),
        );
        assert_eq!(current_redirect, historical_redirect);

        let challenge = ExternalAuthChallengeResponse {
            status: http::StatusCode::UNAUTHORIZED,
            headers: vec![("x-auth-reason".to_string(), "expired".to_string())],
            www_authenticate: "Bearer".to_string(),
            body: b"challenge\n".to_vec(),
        };
        let mut historical_challenge_headers = challenge.headers.clone();
        historical_challenge_headers.push((
            http::header::WWW_AUTHENTICATE.as_str().to_string(),
            challenge.www_authenticate.clone(),
        ));
        let historical_challenge = response_headers_with_defaults(
            challenge.status,
            &challenge.body,
            &historical_challenge_headers,
        );
        let current_challenge = response_headers_with_defaults_and_extra(
            challenge.status,
            &challenge.body,
            &challenge.headers,
            Some((
                http::header::WWW_AUTHENTICATE.as_str(),
                challenge.www_authenticate.as_str(),
            )),
        );
        assert_eq!(current_challenge, historical_challenge);
    }

    #[test]
    fn deferred_response_start_chunk_moves_headers_only_for_deferred_metadata() {
        let deferred = QUICListener::into_deferred_response_start_chunk(ResponseStartMetadata {
            status: http::StatusCode::OK,
            headers: vec![(b"x-test".to_vec(), b"1".to_vec())],
            headers_deferred: true,
        });
        let immediate = QUICListener::into_deferred_response_start_chunk(ResponseStartMetadata {
            status: http::StatusCode::OK,
            headers: vec![(b"x-test".to_vec(), b"1".to_vec())],
            headers_deferred: false,
        });

        match deferred {
            Some(ResponseChunk::Start { status, headers }) => {
                assert_eq!(status, http::StatusCode::OK);
                assert_eq!(headers, vec![(b"x-test".to_vec(), b"1".to_vec())]);
            }
            _ => panic!("deferred metadata must produce a start chunk"),
        }
        assert!(immediate.is_none());
    }
}
