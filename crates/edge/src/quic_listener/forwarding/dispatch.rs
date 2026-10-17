use std::convert::Infallible;

use impulse_config::runtime::RuntimeBackendTlsPolicy;
use impulse_errors::{
    HedgeOutcomeTelemetryReason, HedgePolicyDecision, RetryPolicyDecision, is_idempotent_method,
};
use impulse_lb::{
    alternate_backend::{
        AlternateBackendDecision, AlternateBackendFailureReason, choose_alternate_backend,
    },
    pingora_backend::GenerationSelector,
};
use impulse_transport::{
    UpstreamBodyFrame, UpstreamCancellation, UpstreamConnectionReuse, UpstreamExchangeCompletion,
    UpstreamExchangeOutcome, UpstreamExchangeRequest, UpstreamExchangeResponse,
    UpstreamRequestHead,
};

use super::{
    selection::{
        ForwardingSelectionService, MAX_UPSTREAM_RETRY_ATTEMPTS, RetryCoordinator,
        StableBackendSelection,
    },
    *,
};
use crate::{
    observability::{HedgeDecisionReason, RetryDecisionReason},
    runtime::connection::{request::PendingForward, response::ForwardingPolicyTelemetry},
};

pub(in crate::quic_listener) type UpstreamRequest = Request<BoxBody<Bytes, Infallible>>;

#[derive(Clone, Debug)]
enum ResolvedAlternateBackend {
    Selected {
        address: String,
    },
    Unavailable {
        reason: AlternateBackendFailureReason,
    },
}

impl ResolvedAlternateBackend {
    fn is_available(&self) -> bool {
        matches!(self, Self::Selected { .. })
    }

    fn failure_reason(&self) -> Option<AlternateBackendFailureReason> {
        match self {
            Self::Selected { .. } => None,
            Self::Unavailable { reason } => Some(*reason),
        }
    }
}

struct AlternateBodylessCandidate {
    backend: String,
    request: UpstreamRequest,
}

struct WebsocketTunnelForwardInput {
    backend: Arc<str>,
    endpoint: BackendEndpoint,
    pending_forward: Arc<PendingForward>,
    body_rx: mpsc::Receiver<Bytes>,
}

struct RetryExecutionCtx<'a> {
    request_id: u64,
    route_name: &'a str,
    policy: RetryCoordinator,
    policy_telemetry: &'a mut ForwardingPolicyTelemetry,
    retry_budget: &'a crate::resilience::retry_budget::RetryBudget,
    alternate_backend: Option<&'a ResolvedAlternateBackend>,
    backend_endpoints: &'a HashMap<String, BackendEndpoint>,
    pending_forward: &'a PendingForward,
    circuit_breakers: &'a crate::resilience::circuit_breaker::CircuitBreakers,
    transport: &'a UpstreamTransportPool,
}

fn alternate_backend_policy_state(
    alternate_backend: Option<&ResolvedAlternateBackend>,
) -> (bool, Option<AlternateBackendFailureReason>) {
    (
        alternate_backend.is_some_and(ResolvedAlternateBackend::is_available),
        alternate_backend.and_then(ResolvedAlternateBackend::failure_reason),
    )
}

impl QUICListener {
    async fn send_upstream_request(
        backend: &str,
        request: UpstreamRequest,
        circuit_breakers: &crate::resilience::circuit_breaker::CircuitBreakers,
        transport: &UpstreamTransportPool,
    ) -> Result<UpstreamExchangeResponse, ProxyError> {
        let breaker_permit =
            ForwardingSelectionService::allow_backend_request(circuit_breakers, backend)?;

        let (request, _cancellation, _completion) = Self::into_upstream_exchange_request(request)?;
        let send_result = transport.send_exchange(backend, request).await;
        if send_result.is_ok() {
            breaker_permit.record_success();
        } else {
            breaker_permit.record_failure();
        }
        send_result
    }

    pub(in crate::quic_listener) fn into_upstream_exchange_request(
        request: UpstreamRequest,
    ) -> Result<
        (
            UpstreamExchangeRequest,
            oneshot::Sender<()>,
            oneshot::Receiver<UpstreamExchangeCompletion>,
        ),
        ProxyError,
    > {
        let (parts, mut body) = request.into_parts();
        let (frames, frame_rx) = mpsc::channel(REQUEST_CHUNK_CHANNEL_CAPACITY);
        let body_pump = async move {
            while let Some(frame) = body.frame().await {
                let frame = match frame {
                    Ok(frame) => match frame.into_data() {
                        Ok(data) => UpstreamBodyFrame::Data(data),
                        Err(frame) => {
                            let Ok(headers) = frame.into_trailers() else {
                                continue;
                            };
                            UpstreamBodyFrame::Trailers(headers)
                        }
                    },
                    Err(never) => match never {},
                };
                if frames.send(Ok(frame)).await.is_err() {
                    return;
                }
            }
        };
        if !spawn_async_task(body_pump, "upstream-exchange-request-body") {
            return Err(ProxyError::Transport("runtime unavailable".into()));
        }
        let (cancellation, cancellation_signal) = oneshot::channel();
        let (completion_signal, completion) = oneshot::channel();
        Ok((
            UpstreamExchangeRequest {
                head: UpstreamRequestHead {
                    method: parts.method,
                    uri: parts.uri,
                    version: parts.version,
                    headers: parts.headers,
                },
                body: frame_rx,
                cancellation: UpstreamCancellation {
                    signal: cancellation_signal,
                },
                completion: completion_signal,
            },
            cancellation,
            completion,
        ))
    }

    async fn forward_http1_websocket_tunnel(
        input: WebsocketTunnelForwardInput,
        circuit_breakers: &crate::resilience::circuit_breaker::CircuitBreakers,
        transport: &UpstreamTransportPool,
    ) -> ForwardResult {
        let WebsocketTunnelForwardInput {
            backend,
            endpoint,
            pending_forward,
            mut body_rx,
        } = input;
        let request = pending_forward.build_http1_websocket_tunnel_request(&endpoint)?;
        let response =
            Self::send_upstream_request(backend.as_ref(), request, circuit_breakers, transport)
                .await?;

        if response.head.status != StatusCode::SWITCHING_PROTOCOLS {
            return Ok(ForwardSuccess::Response {
                status: response.head.status,
                headers: response.head.headers,
                body: response.body,
            });
        }

        let headers = response.head.headers;
        let upgrade = response.upgrade.ok_or_else(|| {
            ProxyError::Protocol("HTTP/1 upgrade response did not provide a tunnel".into())
        })?;
        let tunnel = upgrade
            .tunnel
            .await
            .map_err(|_| ProxyError::Transport("upstream tunnel task stopped".into()))??;
        let (chunk_tx, chunk_rx) = mpsc::channel(RESPONSE_CHUNK_CHANNEL_CAPACITY);
        let fut = async move {
            let impulse_transport::UpstreamTunnel { io, lifecycle } = tunnel;
            let (mut reader, mut writer) = tokio::io::split(io);
            let write_fut = async {
                while let Some(chunk) = body_rx.recv().await {
                    writer.write_all(&chunk).await?;
                }
                writer.shutdown().await
            };
            let read_fut = async {
                let mut buf = [0u8; RESPONSE_CHUNK_BYTES_LIMIT];
                loop {
                    match reader.read(&mut buf).await {
                        Ok(0) => return Ok::<(), std::io::Error>(()),
                        Ok(read) => {
                            if chunk_tx
                                .send(ResponseChunk::Data(Bytes::copy_from_slice(&buf[..read])))
                                .await
                                .is_err()
                            {
                                return Ok(());
                            }
                        }
                        Err(err) => return Err(err),
                    }
                }
            };
            match tokio::try_join!(write_fut, read_fut) {
                Ok(((), ())) => {
                    let _ = chunk_tx.send(ResponseChunk::End).await;
                    let _ = lifecycle.completion.send(UpstreamExchangeCompletion {
                        outcome: UpstreamExchangeOutcome::Completed,
                        connection_reuse: UpstreamConnectionReuse::Close,
                    });
                }
                Err(err) => {
                    let detail = err.to_string();
                    let _ = chunk_tx
                        .send(ResponseChunk::Error(ProxyError::Transport(detail.clone())))
                        .await;
                    let _ = lifecycle.completion.send(UpstreamExchangeCompletion {
                        outcome: UpstreamExchangeOutcome::Failed(ProxyError::Transport(detail)),
                        connection_reuse: UpstreamConnectionReuse::Close,
                    });
                }
            }
        };
        let _ = spawn_async_task(fut, "ws-h1-tunnel");

        Ok(ForwardSuccess::Tunnel {
            status: StatusCode::OK,
            headers,
            response_chunk_rx: chunk_rx,
        })
    }

    fn resolve_alternate_backend(
        upstream_pool: &Arc<RwLock<UpstreamPool>>,
        selector: &GenerationSelector<RuntimeBackendTlsPolicy>,
        generation: u64,
        lb_key: &str,
        primary_index: usize,
    ) -> ResolvedAlternateBackend {
        match ForwardingSelectionService::select_stable_backend(
            selector,
            upstream_pool,
            generation,
            lb_key,
            &[primary_index],
            false,
        ) {
            Ok(StableBackendSelection::Selected { address, .. }) => {
                return ResolvedAlternateBackend::Selected { address };
            }
            Ok(StableBackendSelection::NoCandidate) => {
                let reason = match upstream_pool.read() {
                    Ok(pool) if pool.membership_summary().healthy_backends == 0 => {
                        AlternateBackendFailureReason::NoHealthyBackends
                    }
                    Ok(_) => AlternateBackendFailureReason::OnlyExcludedBackendsHealthy,
                    Err(_) => AlternateBackendFailureReason::PoolUnavailable,
                };
                return ResolvedAlternateBackend::Unavailable { reason };
            }
            Ok(StableBackendSelection::UseExistingSelector) => {}
            Err(_) => {
                return ResolvedAlternateBackend::Unavailable {
                    reason: AlternateBackendFailureReason::PoolUnavailable,
                };
            }
        }

        let Ok(pool) = upstream_pool.read() else {
            return ResolvedAlternateBackend::Unavailable {
                reason: AlternateBackendFailureReason::PoolUnavailable,
            };
        };
        match choose_alternate_backend(&pool, &[primary_index], None) {
            AlternateBackendDecision::Select(choice) => {
                if let Some(address) = pool.backend_address(choice.index) {
                    ResolvedAlternateBackend::Selected {
                        address: address.to_string(),
                    }
                } else {
                    ResolvedAlternateBackend::Unavailable {
                        reason: AlternateBackendFailureReason::BackendAddressMissing,
                    }
                }
            }
            AlternateBackendDecision::DoNotSelect { denial } => {
                ResolvedAlternateBackend::Unavailable { reason: denial }
            }
        }
    }

    fn build_alternate_bodyless_candidate(
        alternate_backend: Option<&ResolvedAlternateBackend>,
        backend_endpoints: &HashMap<String, BackendEndpoint>,
        pending_forward: &PendingForward,
    ) -> Option<AlternateBodylessCandidate> {
        match alternate_backend? {
            ResolvedAlternateBackend::Selected { address } => {
                let endpoint = backend_endpoints.get(address)?;
                let request = pending_forward.build_bodyless_request(endpoint).ok()?;
                Some(AlternateBodylessCandidate {
                    backend: address.clone(),
                    request,
                })
            }
            ResolvedAlternateBackend::Unavailable { .. } => None,
        }
    }

    async fn retry_primary_error(
        primary_err: ProxyError,
        retry_ctx: RetryExecutionCtx<'_>,
    ) -> Result<UpstreamExchangeResponse, ProxyError> {
        let RetryExecutionCtx {
            request_id,
            route_name,
            policy,
            policy_telemetry,
            retry_budget,
            alternate_backend,
            backend_endpoints,
            pending_forward,
            circuit_breakers,
            transport,
        } = retry_ctx;
        let (alternate_backend_available, alternate_backend_failure) =
            alternate_backend_policy_state(alternate_backend);
        let retry_decision = policy.retry_after_error(
            &primary_err,
            policy_telemetry.retry.count,
            MAX_UPSTREAM_RETRY_ATTEMPTS,
            ForwardingSelectionService::retry_budget_available(
                &primary_err,
                route_name,
                retry_budget,
            ),
            alternate_backend_available,
            alternate_backend_failure,
        );
        let (retry_reason, canonical_retry_reason) = match retry_decision {
            RetryPolicyDecision::Retry { reason } => {
                (reason.into(), RetryDecisionReason::from(reason))
            }
            RetryPolicyDecision::DoNotRetry { denial } => {
                policy_telemetry.retry.record_denial(denial);
                // Phase 6: canonical operational reason (upstream=, decision=retry)
                // with the raw denial kept as debug-only detail.
                let reason = denial
                    .map(RetryDecisionReason::from)
                    .unwrap_or(RetryDecisionReason::RetryPolicyDisabled);
                debug!(
                    "retry decision: request_id={} upstream={} decision=denied reason={} detail={:?}",
                    request_id,
                    route_name,
                    reason.slug(),
                    denial
                );
                return Err(primary_err);
            }
        };

        let Some(AlternateBodylessCandidate {
            backend: retry_backend,
            request: retry_request,
        }) = Self::build_alternate_bodyless_candidate(
            alternate_backend,
            backend_endpoints,
            pending_forward,
        )
        else {
            return Err(primary_err);
        };

        policy_telemetry.retry.record_attempt(retry_reason);
        info!(
            "retry decision: request_id={} upstream={} decision=retry reason={} backend={}",
            request_id,
            route_name,
            canonical_retry_reason.slug(),
            retry_backend
        );
        Self::send_upstream_request(
            retry_backend.as_str(),
            retry_request,
            circuit_breakers,
            transport,
        )
        .await
    }

    pub(super) fn spawn_upstream_forward_task(
        req: &RequestEnvelope,
        pending_forward: Arc<PendingForward>,
        backend_endpoint: BackendEndpoint,
        request: Option<UpstreamRequest>,
        websocket_tunnel_body_rx: Option<mpsc::Receiver<Bytes>>,
        exec_ctx: &ForwardingExecutionCtx<'_>,
        shared_ctx: &ForwardingSharedCtx<'_>,
    ) -> Result<oneshot::Receiver<UpstreamResult>, ProxyError> {
        let resilience = shared_ctx.resilience;
        let circuit_breakers = Arc::clone(&resilience.circuit_breakers);
        let retry_budget = Arc::clone(&resilience.retry_budget);
        let backend_endpoints = Arc::clone(&exec_ctx.backend_endpoints);
        let transport = Arc::clone(&exec_ctx.transport_pool);
        let hedge_delay = resilience.hedging_delay;
        let alternate_backend = req.upstream_pool.as_ref().map(|upstream_pool| {
            shared_ctx
                .pingora_load_balancing
                .selector(pending_forward.upstream_name.as_ref())
                .map_or(
                    ResolvedAlternateBackend::Unavailable {
                        reason: AlternateBackendFailureReason::PoolUnavailable,
                    },
                    |selector| {
                        Self::resolve_alternate_backend(
                            upstream_pool,
                            selector,
                            shared_ctx.generation,
                            pending_forward.lb_key.as_ref(),
                            pending_forward.backend_index,
                        )
                    },
                )
        });
        let trace_span_for_upstream = req.trace_span.clone();
        let (result_tx, result_rx) = oneshot::channel::<UpstreamResult>();
        let tunnel_mode = req.tunnel_mode;
        let bodyless_mode = req.bodyless_mode;
        let request_id = req.request_id;
        let method_idempotent = is_idempotent_method(&req.method);
        let hedge_method_allowed = resilience.hedging_method_allowed(&req.method);
        let hedge_configured =
            resilience.hedging_route_enabled_for(pending_forward.upstream_name.as_ref());
        let hedge_tunnel_request = req.tunnel_mode != TunnelMode::None;
        let policy = RetryCoordinator::new(
            method_idempotent,
            bodyless_mode,
            hedge_method_allowed,
            hedge_configured,
            hedge_tunnel_request,
        );
        let fut = async move {
            let route_name = pending_forward.upstream_name.as_ref();
            let primary_backend = pending_forward.backend_addr.as_ref();
            let circuit_breakers = circuit_breakers.as_ref();
            let retry_budget = retry_budget.as_ref();
            let transport_pool = transport.as_ref();
            let mut policy_telemetry = ForwardingPolicyTelemetry::default();
            let result: ForwardResult = async {
                retry_budget.mark_primary(route_name);

                let forward_success: ForwardSuccess = if tunnel_mode == TunnelMode::Websocket
                    && backend_endpoint.scheme() == BackendScheme::Http
                {
                    let Some(body_rx) = websocket_tunnel_body_rx else {
                        return Err(ProxyError::Transport(
                            "websocket H1 tunnels require a downstream body channel".into(),
                        ));
                    };
                    Self::forward_http1_websocket_tunnel(WebsocketTunnelForwardInput {
                        backend: Arc::clone(&pending_forward.backend_addr),
                        endpoint: backend_endpoint.clone(),
                        pending_forward: Arc::clone(&pending_forward),
                        body_rx,
                    }, circuit_breakers, transport_pool)
                    .await?
                } else {
                    let request = request.ok_or_else(|| {
                        ProxyError::Transport(
                            "missing upstream request for non-websocket forward".into(),
                        )
                    })?;
                    let (alternate_backend_available, alternate_backend_failure) =
                        alternate_backend_policy_state(alternate_backend.as_ref());
                    let response: UpstreamExchangeResponse = match policy.hedge_before_delay(
                        alternate_backend_available,
                        alternate_backend_failure,
                    ) {
                        HedgePolicyDecision::WaitForPrimary => {
                            let hedge_candidate = Self::build_alternate_bodyless_candidate(
                                alternate_backend.as_ref(),
                                backend_endpoints.as_ref(),
                                pending_forward.as_ref(),
                            );

                            if let Some(AlternateBodylessCandidate {
                                backend: hedge_backend,
                                request: hedge_request,
                            }) = hedge_candidate
                            {
                                let primary_started = Instant::now();
                                let primary_fut = Self::send_upstream_request(
                                    primary_backend,
                                    request,
                                    circuit_breakers,
                                    transport_pool,
                                );
                                tokio::pin!(primary_fut);
                                let hedge_sleep = tokio::time::sleep(hedge_delay);
                                tokio::pin!(hedge_sleep);

                                if let Some(result) = tokio::select! {
                                    result = &mut primary_fut => Some(result),
                                    _ = &mut hedge_sleep => None,
                                } {
                                    result?
                                } else {
                                    match policy.hedge_after_delay(
                                        ForwardingSelectionService::retry_budget_available(
                                            &ProxyError::Timeout,
                                            route_name,
                                            retry_budget,
                                        ),
                                    ) {
                                        HedgePolicyDecision::Hedge { reason } => {
                                            policy_telemetry.hedge.record_trigger(reason);
                                            let hedge_fut = Self::send_upstream_request(
                                                hedge_backend.as_str(),
                                                hedge_request,
                                                circuit_breakers,
                                                transport_pool,
                                            );
                                            tokio::pin!(hedge_fut);
                                            tokio::select! {
                                                result = &mut primary_fut => {
                                                    match result {
                                                        Ok(response) => {
                                                            policy_telemetry
                                                                .hedge
                                                                .record_outcome(HedgeOutcomeTelemetryReason::PrimaryWonAfterTrigger);
                                                            response
                                                        }
                                                        Err(_primary_err) => {
                                                            policy_telemetry
                                                                .hedge
                                                                .record_outcome(HedgeOutcomeTelemetryReason::HedgeWon);
                                                            let elapsed_ms = primary_started.elapsed().as_millis() as u64;
                                                            let delay_ms = hedge_delay.as_millis() as u64;
                                                            policy_telemetry
                                                                .hedge
                                                                .observe_primary_late_ms(elapsed_ms.saturating_sub(delay_ms));
                                                            hedge_fut.await?
                                                        }
                                                    }
                                                }
                                                result = &mut hedge_fut => {
                                                    match result {
                                                        Ok(response) => {
                                                            policy_telemetry
                                                                .hedge
                                                                .record_outcome(HedgeOutcomeTelemetryReason::HedgeWon);
                                                            let elapsed_ms = primary_started.elapsed().as_millis() as u64;
                                                            let delay_ms = hedge_delay.as_millis() as u64;
                                                            policy_telemetry
                                                                .hedge
                                                                .observe_primary_late_ms(elapsed_ms.saturating_sub(delay_ms));
                                                            response
                                                        }
                                                        Err(_hedge_err) => {
                                                            policy_telemetry
                                                                .hedge
                                                                .record_outcome(HedgeOutcomeTelemetryReason::PrimaryWonAfterTrigger);
                                                            primary_fut.await?
                                                        }
                                                    }
                                                },
                                            }
                                        }
                                        HedgePolicyDecision::WaitForPrimary => primary_fut.await?,
                                        HedgePolicyDecision::DoNotHedge { denial } => {
                                            debug!(
                                                "hedge decision: request_id={} upstream={} decision=suppressed reason={} detail={:?}",
                                                request_id,
                                                route_name,
                                                HedgeDecisionReason::from(denial).slug(),
                                                denial
                                            );
                                            primary_fut.await?
                                        }
                                    }
                                }
                            } else {
                                Self::send_upstream_request(
                                    primary_backend,
                                    request,
                                    circuit_breakers,
                                    transport_pool,
                                )
                                .await?
                            }
                        }
                        HedgePolicyDecision::DoNotHedge { denial } => {
                            debug!(
                                "hedge decision: request_id={} upstream={} decision=denied reason={} detail={:?}",
                                request_id,
                                route_name,
                                HedgeDecisionReason::from(denial).slug(),
                                denial
                            );
                            match Self::send_upstream_request(
                                primary_backend,
                                request,
                                circuit_breakers,
                                transport_pool,
                            )
                            .await
                            {
                                Ok(response) => response,
                                Err(primary_err) => Self::retry_primary_error(
                                        primary_err,
                                        RetryExecutionCtx {
                                            request_id,
                                            route_name,
                                            policy,
                                            policy_telemetry: &mut policy_telemetry,
                                            retry_budget,
                                            alternate_backend: alternate_backend.as_ref(),
                                            backend_endpoints: backend_endpoints.as_ref(),
                                            pending_forward: pending_forward.as_ref(),
                                            circuit_breakers,
                                            transport: transport_pool,
                                        },
                                    )
                                    .await?,
                            }
                        }
                        HedgePolicyDecision::Hedge { reason } => {
                            debug!(
                                "hedge decision: request_id={} upstream={} decision=triggered reason={} detail={:?}",
                                request_id,
                                route_name,
                                HedgeDecisionReason::DelayElapsed.slug(),
                                reason
                            );
                            match Self::send_upstream_request(
                                primary_backend,
                                request,
                                circuit_breakers,
                                transport_pool,
                            )
                            .await
                            {
                                Ok(response) => response,
                                Err(primary_err) => Self::retry_primary_error(
                                        primary_err,
                                        RetryExecutionCtx {
                                            request_id,
                                            route_name,
                                            policy,
                                            policy_telemetry: &mut policy_telemetry,
                                            retry_budget,
                                            alternate_backend: alternate_backend.as_ref(),
                                            backend_endpoints: backend_endpoints.as_ref(),
                                            pending_forward: pending_forward.as_ref(),
                                            circuit_breakers,
                                            transport: transport_pool,
                                        },
                                    )
                                    .await?,
                            }
                        }
                    };

                    ForwardSuccess::Response {
                        status: response.head.status,
                        headers: response.head.headers,
                        body: response.body,
                    }
                };
                Ok(forward_success)
            }
            .await;
            let _ = result_tx.send(UpstreamResult {
                forward: result,
                policy: policy_telemetry,
            });
        };
        let spawned = match trace_span_for_upstream {
            Some(span) => spawn_async_task(fut.instrument(span), "upstream"),
            None => spawn_async_task(fut, "upstream"),
        };
        if !spawned {
            return Err(ProxyError::Transport(
                "dropping upstream task: no runtime available".into(),
            ));
        }
        Ok(result_rx)
    }
}
