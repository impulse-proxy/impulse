use std::{convert::Infallible, time::Instant};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use hyper::{body::Incoming, upgrade::OnUpgrade};
use impulse_errors::{BridgeError, ProxyError};

use super::{
    super::{protocol::is_head_method, validation::validate_http_request},
    request::{
        BootstrapLifecycleStage, BootstrapRejectionReason, BootstrapRequestMode,
        BootstrapTerminalOutcome, BootstrapTerminalResponse, BootstrapTerminalResult,
    },
    response::boxed_full,
    websocket::capture_bootstrap_websocket_flow,
};
use crate::{
    Metrics,
    resilience::runtime::RuntimeResilience,
    runtime::connection::outcome::{RouteOutcomeTarget, observe_proxy_error_outcome},
};

pub(in crate::quic_listener) struct BootstrapRequestIntake {
    pub(in crate::quic_listener) method: String,
    pub(in crate::quic_listener) path: String,
    pub(in crate::quic_listener) authority: Option<String>,
    pub(in crate::quic_listener) content_length: Option<usize>,
    pub(in crate::quic_listener) suppress_downstream_body: bool,
    pub(in crate::quic_listener) request_mode: BootstrapRequestMode,
    pub(in crate::quic_listener) client_upgrade: Option<OnUpgrade>,
}

pub(in crate::quic_listener) fn bootstrap_error_response(
    alt_svc: &str,
    status: StatusCode,
    body: &'static [u8],
) -> Response<BoxBody<Bytes, Infallible>> {
    Response::builder()
        .status(status)
        .header("alt-svc", alt_svc)
        .body(boxed_full(Bytes::from_static(body)))
        .unwrap_or_else(|_| Response::new(boxed_full(Bytes::from_static(b"error\n"))))
}

pub(in crate::quic_listener) fn prepare_bootstrap_request_intake(
    req: &mut Request<Incoming>,
    use_h2: bool,
    resilience: &RuntimeResilience,
    metrics: &Metrics,
    alt_svc: &str,
    request_start: Instant,
) -> BootstrapTerminalResult<BootstrapRequestIntake> {
    let websocket_flow = capture_bootstrap_websocket_flow(req, use_h2);

    let request = match validate_http_request(req, resilience) {
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
                request_start.elapsed(),
                Some(status),
                &ProxyError::Bridge(BridgeError::InvalidHeader),
                None,
            );
            return Err(BootstrapTerminalResponse::new(
                BootstrapLifecycleStage::Validate,
                BootstrapTerminalOutcome::Rejected(BootstrapRejectionReason::ValidationFailed),
                bootstrap_error_response(alt_svc, status, body),
            ));
        }
    };

    Ok(BootstrapRequestIntake {
        suppress_downstream_body: is_head_method(&request.method),
        method: request.method,
        path: request.path,
        authority: request.authority,
        content_length: request.content_length,
        request_mode: if websocket_flow.is_websocket_upgrade {
            BootstrapRequestMode::WebsocketUpgrade
        } else {
            BootstrapRequestMode::Standard
        },
        client_upgrade: websocket_flow.client_upgrade,
    })
}
