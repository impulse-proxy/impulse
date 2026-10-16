use std::convert::Infallible;

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::combinators::BoxBody;
use impulse_errors::ProxyError;
use impulse_transport::UpstreamExchangeResponse;

use super::{
    context::BootstrapDispatchCtx,
    intake::bootstrap_error_response,
    outcome::observe_bootstrap_dispatch_failure,
    request::{
        BootstrapBackendFailureReason, BootstrapLifecycleStage, BootstrapPreparedRoute,
        BootstrapTerminalOutcome, BootstrapTerminalResponse, BootstrapTerminalResult,
        BootstrapTimeoutReason,
    },
    websocket::dispatch_bootstrap_websocket,
};
use crate::quic_listener::QUICListener;

pub(in crate::quic_listener) struct BootstrapDispatchInput<'a> {
    pub(in crate::quic_listener) upstream_req: Request<BoxBody<Bytes, Infallible>>,
    pub(in crate::quic_listener) prepared_route: &'a BootstrapPreparedRoute,
    pub(in crate::quic_listener) dispatch_ctx: BootstrapDispatchCtx<'a>,
}

pub(in crate::quic_listener) async fn dispatch_bootstrap_http(
    input: BootstrapDispatchInput<'_>,
) -> BootstrapTerminalResult<UpstreamExchangeResponse> {
    let send_result = match QUICListener::into_upstream_exchange_request(input.upstream_req) {
        Ok((request, _cancellation, _completion)) => {
            input
                .dispatch_ctx
                .request
                .runtime
                .transport_pool
                .send_exchange(&input.prepared_route.backend_addr, request)
                .await
        }
        Err(error) => Err(error),
    };
    match send_result {
        Ok(response) => Ok(response),
        Err(proxy_err) => {
            let status = match proxy_err {
                ProxyError::Timeout => StatusCode::GATEWAY_TIMEOUT,
                _ => StatusCode::BAD_GATEWAY,
            };
            observe_bootstrap_dispatch_failure(
                input.prepared_route,
                input.dispatch_ctx.request.runtime.metrics.as_ref(),
                input.dispatch_ctx.request.request_start,
                input.dispatch_ctx.request_id,
                status,
                &proxy_err,
            );
            Err(BootstrapTerminalResponse::new(
                BootstrapLifecycleStage::Dispatch,
                if matches!(proxy_err, ProxyError::Timeout) {
                    BootstrapTerminalOutcome::TimedOut(BootstrapTimeoutReason::Upstream)
                } else {
                    BootstrapTerminalOutcome::BackendFailed(
                        BootstrapBackendFailureReason::DispatchFailed,
                    )
                },
                bootstrap_error_response(
                    &input.dispatch_ctx.request.runtime.alt_svc,
                    status,
                    if matches!(proxy_err, ProxyError::Timeout) {
                        b"upstream timeout\n"
                    } else {
                        b"upstream error\n"
                    },
                ),
            ))
        }
    }
}

pub(in crate::quic_listener) async fn dispatch_bootstrap_upstream(
    input: BootstrapDispatchInput<'_>,
) -> BootstrapTerminalResult<UpstreamExchangeResponse> {
    if input.dispatch_ctx.is_websocket_upgrade {
        dispatch_bootstrap_websocket(input).await
    } else {
        dispatch_bootstrap_http(input).await
    }
}
