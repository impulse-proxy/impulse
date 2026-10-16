use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use hyper::{
    body::Incoming,
    server::conn::{http1, http2},
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use impulse_config::runtime::ListenerRuntimeConfig;
use impulse_errors::ProxyError;
use log::{debug, error, info, warn};

use super::{
    context::{BootstrapDispatchCtx, BootstrapRequestCtx, BootstrapRuntimeCtx},
    dispatch::{BootstrapDispatchInput, dispatch_bootstrap_upstream},
    intake::{BootstrapRequestIntake, prepare_bootstrap_request_intake},
    outcome::observe_bootstrap_request_proxy_error,
    request::{
        BootstrapBuildRequestInput, BootstrapPolicyEvaluationInput, BootstrapRequestMode,
        BootstrapTerminalOutcome, build_bootstrap_upstream_request,
        evaluate_bootstrap_external_auth, evaluate_bootstrap_request_policy,
    },
    response::{BootstrapWritebackInput, boxed_full, write_bootstrap_response},
    startup::{
        PreparedBootstrapListenerStartup, prepare_bootstrap_listener_startup,
        spawn_bootstrap_listener_task,
    },
};
use crate::{
    REQUEST_ID_COUNTER,
    quic_listener::{
        PerSourceTokenBucket, QUICListener, runtime_endpoint::RuntimeConnectionSlotGuard,
    },
    request_pipeline::TerminalOutcomeGuard,
    runtime::{
        bundle::RuntimeBundleHandle,
        connection::guardrails::{
            BodyLimitKind, REQUEST_BODY_TOO_LARGE_BODY, RequestBodyGuardrailConfig,
            RequestBodyGuardrailDecision, RequestBodyGuardrailInput, checked_request_body_ingress,
        },
        listener::ShutdownSignal,
        shared_state::SharedRuntimeState,
    },
};

type BootstrapServiceFuture = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<
                    hyper::Response<
                        http_body_util::combinators::BoxBody<hyper::body::Bytes, Infallible>,
                    >,
                    hyper::Error,
                >,
            > + Send,
    >,
>;

pub(in crate::quic_listener) fn spawn_bootstrap_tls_listener(
    config: &ListenerRuntimeConfig,
    shared_state: &SharedRuntimeState,
    runtime_bundle: Option<Arc<RuntimeBundleHandle>>,
    shutdown_signal: Option<ShutdownSignal>,
) -> Result<(), ProxyError> {
    let PreparedBootstrapListenerStartup {
        bind,
        alt_svc_value,
        max_connections,
        connection_timeout,
        listener_label,
        listener,
        runtime_handle,
        runtime_bundle,
        shutdown_signal,
        startup_state,
    } = prepare_bootstrap_listener_startup(config, shared_state, runtime_bundle, shutdown_signal)?;

    spawn_bootstrap_listener_task(&runtime_handle, async move {
        info!(
            "Bootstrap TLS listener ready bind=https://{} protocol=tcp+tls",
            bind,
        );
        info!(
            "Bootstrap TLS listener alt_svc bind={} value={}",
            bind, alt_svc_value,
        );
        info!(
            "Bootstrap TLS listener limits bind={} max_connections={} connection_timeout_ms={}",
            bind,
            max_connections,
            connection_timeout.as_millis()
        );
        let active_connections = Arc::new(AtomicUsize::new(0));
        let mut source_rate_limiter = PerSourceTokenBucket::new(
            startup_state
                .listener_config
                .policies
                .transport
                .new_connections_per_sec,
            startup_state
                .listener_config
                .policies
                .transport
                .new_connections_burst,
        );
        loop {
            let accept_result = if let Some(shutdown_signal) = shutdown_signal.as_ref() {
                tokio::select! {
                    accept = listener.accept() => Some(accept),
                    _ = tokio::time::sleep(Duration::from_millis(200)) => {
                        if shutdown_signal.load(Ordering::Relaxed) {
                            None
                        } else {
                            continue;
                        }
                    }
                }
            } else {
                Some(listener.accept().await)
            };
            let Some(accept_result) = accept_result else {
                info!(
                    "Bootstrap TLS listener on {} stopping due to runtime group shutdown",
                    bind
                );
                break;
            };
            let (stream, peer) = match accept_result {
                Ok(v) => v,
                Err(err) => {
                    error!("Bootstrap TLS listener accept failed: {}", err);
                    continue;
                }
            };
            let Some(runtime_state) = super::state::bootstrap_connection_state(
                &listener_label,
                runtime_bundle.as_ref(),
                &startup_state,
            ) else {
                error!(
                    "Bootstrap TLS listener missing live runtime state for listener {}",
                    listener_label
                );
                continue;
            };
            source_rate_limiter.reconfigure(
                runtime_state.new_connections_per_sec,
                runtime_state.new_connections_burst,
            );
            if !source_rate_limiter.try_consume(peer.ip()) {
                runtime_state.metrics.inc_ingress_rate_limited();
                debug!(
                    "Bootstrap TLS per-source connection rate limit exceeded for {}",
                    peer
                );
                continue;
            }
            let active_connections = Arc::clone(&active_connections);
            if !QUICListener::try_claim_runtime_connection_slot(
                &active_connections,
                runtime_state.max_connections,
            ) {
                runtime_state.metrics.inc_connection_cap_reject();
                debug!(
                    "Bootstrap TLS listener dropped connection from {}: max_connections reached",
                    peer
                );
                continue;
            }

            let metrics = Arc::clone(&runtime_state.metrics);
            let runtime_ctx = Arc::new(BootstrapRuntimeCtx::from_connection_state(&runtime_state));
            let timeout = runtime_state.connection_timeout;
            let listener_label = listener_label.clone();
            let listener_tls_store = Arc::clone(&runtime_state.listener_tls_store);

            tokio::spawn(async move {
                let _connection_guard = RuntimeConnectionSlotGuard::new(active_connections);
                let Some(server_config) =
                    listener_tls_store.bootstrap_server_config(&listener_label)
                else {
                    error!(
                        "Bootstrap TLS listener missing live server config for listener {}",
                        listener_label
                    );
                    return;
                };
                let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
                let tls_stream = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(err) => {
                        let err_text = err.to_string();
                        let reason =
                            QUICListener::classify_downstream_tls_failure_reason(&err_text);
                        metrics.record_downstream_tls_handshake_failure(&listener_label, reason);
                        debug!(
                            "Bootstrap TLS handshake failed listener={} peer={} reason={} error={}",
                            listener_label, peer, reason, err_text
                        );
                        return;
                    }
                };

                let Some(listener_tls) = listener_tls_store.inventory(&listener_label) else {
                    error!(
                        "Bootstrap TLS listener missing live inventory for listener {}",
                        listener_label
                    );
                    return;
                };
                let requested_sni = tls_stream.get_ref().1.server_name().map(str::to_string);
                let (selection, identity) = QUICListener::classify_downstream_tls_cert_selection(
                    &listener_tls.listener_tls,
                    requested_sni.as_deref(),
                );
                let negotiated = tls_stream.get_ref().1.alpn_protocol().map(|p| p.to_vec());
                let negotiated_label = negotiated
                    .as_deref()
                    .and_then(|value| std::str::from_utf8(value).ok())
                    .unwrap_or("none");
                let client_cert_present = tls_stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .is_some_and(|certs| !certs.is_empty());
                metrics.inc_downstream_tls_handshake_success();
                metrics.record_downstream_tls_cert_selection(&listener_label, selection);
                metrics.record_downstream_tls_alpn(&listener_label, negotiated_label);
                debug!(
                    "Bootstrap TLS handshake success listener={} peer={} sni={:?} selection={} cert='{}' alpn={} client_cert_present={}",
                    listener_label,
                    peer,
                    requested_sni,
                    selection,
                    identity.cert_path,
                    negotiated_label,
                    client_cert_present
                );
                let use_h2 = negotiated.as_deref() == Some(b"h2");

                let io = TokioIo::new(tls_stream);
                let svc = service_fn(
                    move |mut req: Request<Incoming>| -> BootstrapServiceFuture {
                        let runtime_ctx = Arc::clone(&runtime_ctx);
                        let peer = peer;

                        Box::pin(async move {
                            let request_start = Instant::now();
                            let request_id = REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
                            let terminal_outcome = TerminalOutcomeGuard::default();
                            let request_ctx = BootstrapRequestCtx {
                                runtime: runtime_ctx.as_ref(),
                                peer,
                                request_start,
                                terminal_outcome: &terminal_outcome,
                            };
                            let BootstrapRequestIntake {
                                method,
                                path,
                                authority,
                                content_length,
                                suppress_downstream_body,
                                request_mode,
                                client_upgrade,
                            } = match prepare_bootstrap_request_intake(
                                &mut req,
                                use_h2,
                                runtime_ctx.resilience.as_ref(),
                                runtime_ctx.metrics.as_ref(),
                                &runtime_ctx.alt_svc,
                                request_start,
                            ) {
                                Ok(intake) => intake,
                                Err(terminal) => {
                                    return Ok(terminal
                                        .into_observed_response(request_id, &terminal_outcome));
                                }
                            };

                            let policy_intake = BootstrapRequestIntake {
                                method: method.clone(),
                                path: path.clone(),
                                authority: authority.clone(),
                                content_length,
                                suppress_downstream_body,
                                request_mode,
                                client_upgrade: None,
                            };
                            let prepared_route = match evaluate_bootstrap_request_policy(
                                BootstrapPolicyEvaluationInput {
                                    intake: &policy_intake,
                                    headers: req.headers(),
                                    request_ctx,
                                },
                            ) {
                                Ok(prepared) => prepared,
                                Err(terminal) => {
                                    return Ok(terminal
                                        .into_observed_response(request_id, &terminal_outcome));
                                }
                            };

                            let request_size_decision = checked_request_body_ingress(
                                RequestBodyGuardrailConfig {
                                    idle_timeout: Duration::ZERO,
                                    total_timeout: Duration::ZERO,
                                    max_body_bytes: runtime_ctx.body_limits.max_request_body_bytes,
                                    max_buffered_bytes: usize::MAX,
                                },
                                RequestBodyGuardrailInput {
                                    elapsed: Duration::ZERO,
                                    idle_for: Duration::ZERO,
                                    bytes_received: 0,
                                    buffered_bytes: 0,
                                    next_chunk_bytes: 0,
                                    declared_content_length: content_length,
                                    exempt_from_body_size_cap: request_mode.is_websocket_upgrade(),
                                },
                            );
                            if matches!(
                                request_size_decision,
                                Err(RequestBodyGuardrailDecision::Reject {
                                    kind: BodyLimitKind::BodySize,
                                })
                            ) {
                                observe_bootstrap_request_proxy_error(
                                    runtime_ctx.metrics.as_ref(),
                                    &prepared_route.upstream_name,
                                    &prepared_route.backend_addr,
                                    prepared_route.backend_index,
                                    request_start,
                                    StatusCode::PAYLOAD_TOO_LARGE,
                                    &ProxyError::Transport("request body too large".into()),
                                );
                                return Ok(
                                    super::request::BootstrapTerminalResponse::new(
                                        super::request::BootstrapLifecycleStage::Validate,
                                        BootstrapTerminalOutcome::Rejected(
                                            super::request::BootstrapRejectionReason::RequestBodyTooLarge,
                                        ),
                                        Response::builder()
                                            .status(StatusCode::PAYLOAD_TOO_LARGE)
                                            .header("alt-svc", &runtime_ctx.alt_svc)
                                            .body(boxed_full(Bytes::from_static(
                                                REQUEST_BODY_TOO_LARGE_BODY,
                                            )))
                                            .unwrap_or_else(|_| {
                                                Response::new(boxed_full(Bytes::from_static(
                                                    b"error\n",
                                                )))
                                            }),
                                    )
                                    .into_observed_response(request_id, &terminal_outcome),
                                );
                            }

                            let traceparent = req
                                .headers()
                                .get("traceparent")
                                .and_then(|value| value.to_str().ok())
                                .map(str::to_string);
                            let intake_for_build = BootstrapRequestIntake {
                                method: method.clone(),
                                path: path.clone(),
                                authority: authority.clone(),
                                content_length,
                                suppress_downstream_body,
                                request_mode,
                                client_upgrade: None,
                            };
                            let request_header_mutations = match evaluate_bootstrap_external_auth(
                                &req,
                                &intake_for_build,
                                &prepared_route,
                                request_ctx,
                                request_id,
                                traceparent.as_deref(),
                            )
                            .await
                            {
                                Ok(mutations) => mutations,
                                Err(terminal) => {
                                    return Ok(terminal
                                        .into_observed_response(request_id, &terminal_outcome));
                                }
                            };
                            let upstream_req = match build_bootstrap_upstream_request(
                                BootstrapBuildRequestInput {
                                    request: req,
                                    intake: &intake_for_build,
                                    prepared_route: &prepared_route,
                                    request_ctx,
                                    request_id,
                                    traceparent: traceparent.as_deref(),
                                    request_header_mutations,
                                },
                            ) {
                                Ok(request) => request,
                                Err(err) => {
                                    warn!("Bootstrap request build failed: {}", err);
                                    let (status, body) = if request_mode
                                        == BootstrapRequestMode::WebsocketUpgrade
                                        && matches!(err, impulse_errors::BridgeError::Build(_))
                                    {
                                        (
                                            StatusCode::BAD_GATEWAY,
                                            b"request build error\n".as_slice(),
                                        )
                                    } else {
                                        (StatusCode::BAD_REQUEST, b"invalid request\n".as_slice())
                                    };
                                    let proxy_err = ProxyError::from(err);
                                    observe_bootstrap_request_proxy_error(
                                        runtime_ctx.metrics.as_ref(),
                                        &prepared_route.upstream_name,
                                        &prepared_route.backend_addr,
                                        prepared_route.backend_index,
                                        request_start,
                                        status,
                                        &proxy_err,
                                    );
                                    return Ok(
                                            super::request::BootstrapTerminalResponse::new(
                                                super::request::BootstrapLifecycleStage::Dispatch,
                                                BootstrapTerminalOutcome::BackendFailed(
                                                    super::request::BootstrapBackendFailureReason::RequestBuildFailed,
                                                ),
                                                Response::builder()
                                                    .status(status)
                                                    .header("alt-svc", &runtime_ctx.alt_svc)
                                                    .body(boxed_full(Bytes::copy_from_slice(body)))
                                                    .unwrap_or_else(|_| {
                                                        Response::new(boxed_full(
                                                            Bytes::from_static(b"error\n"),
                                                        ))
                                                    }),
                                            )
                                            .into_observed_response(
                                                request_id,
                                                &terminal_outcome,
                                            ),
                                        );
                                }
                            };
                            let dispatch_ctx = BootstrapDispatchCtx {
                                request: request_ctx,
                                request_id,
                                is_websocket_upgrade: request_mode.is_websocket_upgrade(),
                            };
                            let upstream_resp =
                                match dispatch_bootstrap_upstream(BootstrapDispatchInput {
                                    upstream_req,
                                    prepared_route: &prepared_route,
                                    dispatch_ctx,
                                })
                                .await
                                {
                                    Ok(resp) => resp,
                                    Err(terminal) => {
                                        return Ok(terminal.into_observed_response(
                                            request_id,
                                            &terminal_outcome,
                                        ));
                                    }
                                };

                            let writeback =
                                match write_bootstrap_response(BootstrapWritebackInput {
                                    upstream_resp,
                                    prepared_route: &prepared_route,
                                    dispatch_ctx,
                                    suppress_downstream_body,
                                    request_mode,
                                    client_upgrade,
                                }) {
                                    Ok(writeback) => writeback,
                                    Err(error) => {
                                        terminal_outcome.record();
                                        return Err(error);
                                    }
                                };
                            // Phase 11: observe the writeback terminal outcome so the
                            // success/reject path is traceable, not just the errors.
                            if terminal_outcome.record() && !writeback.terminal.is_accepted() {
                                log::debug!(
                                    "bootstrap request {} write-response terminal outcome={}",
                                    request_id,
                                    writeback.terminal.slug()
                                );
                            }
                            Ok(writeback.response)
                        })
                    },
                );

                if use_h2 {
                    let executor = hyper_util::rt::TokioExecutor::new();
                    let serve = http2::Builder::new(executor).serve_connection(io, svc);
                    match tokio::time::timeout(timeout, serve).await {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => {
                            debug!("Bootstrap h2 connection from {} closed: {}", peer, err);
                        }
                        Err(_) => {
                            debug!("Bootstrap h2 connection from {} timed out", peer);
                        }
                    }
                } else {
                    let serve = http1::Builder::new()
                        .serve_connection(io, svc)
                        .with_upgrades();
                    match tokio::time::timeout(timeout, serve).await {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => {
                            debug!("Bootstrap h1 connection from {} closed: {}", peer, err);
                        }
                        Err(_) => {
                            debug!("Bootstrap h1 connection from {} timed out", peer);
                        }
                    }
                }
            });
        }
    });

    Ok(())
}
