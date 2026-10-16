use std::convert::Infallible;

use bytes::Bytes;
use http::{Request, Response, StatusCode, response::Builder as ResponseBuilder};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{body::Incoming, upgrade, upgrade::OnUpgrade};
use hyper_util::rt::TokioIo;
use impulse_config::backend_endpoint::BackendScheme;
use impulse_errors::ProxyError;
use impulse_transport::{
    UpstreamConnectionReuse, UpstreamExchangeCompletion, UpstreamExchangeOutcome,
    UpstreamExchangeResponse, UpstreamTunnel,
};
use log::debug;

use super::{
    dispatch::{BootstrapDispatchInput, dispatch_bootstrap_http},
    intake::bootstrap_error_response,
    outcome::finish_bootstrap_backend_request_accounting,
    request::{
        BootstrapBackendFailureReason, BootstrapLifecycleStage, BootstrapPreparedRoute,
        BootstrapTerminalOutcome, BootstrapTerminalResponse, BootstrapTerminalResult,
    },
};
use crate::quic_listener::protocol::is_websocket_upgrade_request;

pub(in crate::quic_listener) struct BootstrapWebsocketFlow {
    pub(in crate::quic_listener) is_websocket_upgrade: bool,
    pub(in crate::quic_listener) client_upgrade: Option<OnUpgrade>,
}

fn boxed_full(body: Bytes) -> BoxBody<Bytes, Infallible> {
    Full::new(body).map_err(|never| match never {}).boxed()
}

pub(in crate::quic_listener) fn capture_bootstrap_websocket_flow(
    req: &mut Request<Incoming>,
    use_h2: bool,
) -> BootstrapWebsocketFlow {
    let is_websocket_upgrade = is_websocket_upgrade_request(req, use_h2);
    let client_upgrade = if is_websocket_upgrade {
        Some(upgrade::on(&mut *req))
    } else {
        None
    };

    BootstrapWebsocketFlow {
        is_websocket_upgrade,
        client_upgrade,
    }
}

pub(in crate::quic_listener) async fn dispatch_bootstrap_websocket(
    input: BootstrapDispatchInput<'_>,
) -> BootstrapTerminalResult<UpstreamExchangeResponse> {
    if input.prepared_route.endpoint.scheme() != BackendScheme::Http {
        return Err(BootstrapTerminalResponse::new(
            BootstrapLifecycleStage::Dispatch,
            BootstrapTerminalOutcome::BackendFailed(BootstrapBackendFailureReason::DispatchFailed),
            bootstrap_error_response(
                &input.dispatch_ctx.request.runtime.alt_svc,
                StatusCode::BAD_GATEWAY,
                b"websocket bootstrap requires http upstream\n",
            ),
        ));
    }

    dispatch_bootstrap_http(input).await
}

pub(in crate::quic_listener) fn write_bootstrap_websocket_upgrade(
    resp_builder: ResponseBuilder,
    upstream_resp: UpstreamExchangeResponse,
    prepared_route: &BootstrapPreparedRoute,
    request_start: std::time::Instant,
    alt_svc: &str,
    client_upgrade: Option<OnUpgrade>,
    status: StatusCode,
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
    let client_upgrade = match client_upgrade {
        Some(upgrade) => upgrade,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header("alt-svc", alt_svc)
                .body(boxed_full(Bytes::from_static(b"upgrade setup error\n")))
                .unwrap_or_else(|_| Response::new(boxed_full(Bytes::from_static(b"error\n")))));
        }
    };
    let Some(upstream_upgrade) = upstream_resp.upgrade else {
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header("alt-svc", alt_svc)
            .body(boxed_full(Bytes::from_static(b"upgrade setup error\n")))
            .unwrap_or_else(|_| Response::new(boxed_full(Bytes::from_static(b"error\n")))));
    };
    tokio::spawn(async move {
        let (client, upstream) = tokio::join!(client_upgrade, upstream_upgrade.tunnel);
        let UpstreamTunnel { mut io, lifecycle } = match upstream {
            Ok(Ok(upstream)) => upstream,
            Ok(Err(error)) => {
                debug!("Bootstrap WebSocket upstream upgrade failed: {}", error);
                return;
            }
            Err(_) => {
                debug!("Bootstrap WebSocket upstream upgrade task stopped");
                return;
            }
        };
        let client = match client {
            Ok(client) => client,
            Err(error) => {
                debug!("Bootstrap WebSocket client upgrade failed: {}", error);
                let _ = lifecycle.completion.send(UpstreamExchangeCompletion {
                    outcome: UpstreamExchangeOutcome::Failed(ProxyError::Transport(
                        error.to_string(),
                    )),
                    connection_reuse: UpstreamConnectionReuse::Close,
                });
                return;
            }
        };
        let mut client = TokioIo::new(client);
        let outcome = match tokio::io::copy_bidirectional(&mut client, &mut io).await {
            Ok(_) => UpstreamExchangeOutcome::Completed,
            Err(error) => UpstreamExchangeOutcome::Failed(ProxyError::Transport(error.to_string())),
        };
        let _ = lifecycle.completion.send(UpstreamExchangeCompletion {
            outcome,
            connection_reuse: UpstreamConnectionReuse::Close,
        });
    });
    finish_bootstrap_backend_request_accounting(
        prepared_route,
        request_start,
        Some(status.as_u16()),
    );
    Ok(resp_builder
        .body(boxed_full(Bytes::new()))
        .unwrap_or_else(|_| Response::new(boxed_full(Bytes::new()))))
}
