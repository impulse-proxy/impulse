use std::{
    convert::Infallible,
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::{Body, Frame, Incoming};
use impulse_bridge::response::{
    ResponseBodyMode, ResponseBodyPolicy, ResponseNormalizationInput,
    ResponseNormalizationProtocol, ResponseProtocolConstraints, normalize_upstream_response,
};
use impulse_lb::upstream_pool::UpstreamPool;
use impulse_transport::{UpstreamBody, UpstreamBodyFrame, UpstreamExchangeResponse};

use super::{
    context::BootstrapDispatchCtx,
    outcome::{
        finish_bootstrap_backend_request_accounting, observe_bootstrap_response_prebuffer_overflow,
        observe_bootstrap_response_status,
    },
    request::{
        BootstrapPreparedRoute, BootstrapRejectionReason, BootstrapRequestMode,
        BootstrapTerminalOutcome,
    },
    websocket::write_bootstrap_websocket_upgrade,
};
use crate::runtime::connection::guardrails::{
    BodyLimitKind, RESPONSE_BODY_TOO_LARGE_BODY, ResponseBodyGuardrailConfig,
    ResponseBodyGuardrailDecision, ResponseBodyGuardrailInput, checked_response_body_guardrails,
};
pub(in crate::quic_listener) struct BootstrapStreamingBody {
    inner: BootstrapStreamingBodyInner,
    guardrails: Option<ResponseBodyGuardrailConfig>,
    declared_content_length: Option<usize>,
    bytes_seen: usize,
    prebuffered_bytes: usize,
    capped: bool,
    terminal: Option<BootstrapStreamingTerminal>,
    backend_accounting: Option<BootstrapBackendAccounting>,
}

enum BootstrapStreamingBodyInner {
    Hyper(Incoming),
    Exchange(UpstreamBody),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::quic_listener) enum BootstrapResponseMode {
    StandardResponse,
    WebsocketUpgrade,
}

impl BootstrapResponseMode {
    fn from_request_mode(request_mode: BootstrapRequestMode, status: StatusCode) -> Self {
        match request_mode {
            BootstrapRequestMode::WebsocketUpgrade if status == StatusCode::SWITCHING_PROTOCOLS => {
                Self::WebsocketUpgrade
            }
            BootstrapRequestMode::WebsocketUpgrade | BootstrapRequestMode::Standard => {
                Self::StandardResponse
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::quic_listener) enum BootstrapStreamingTerminal {
    Completed,
    CappedRejected,
    UpstreamBodyFailed,
}

pub(in crate::quic_listener) struct BootstrapWritebackOutcome {
    pub(in crate::quic_listener) response: Response<BoxBody<Bytes, Infallible>>,
    pub(in crate::quic_listener) terminal: BootstrapTerminalOutcome,
}

struct BootstrapBackendAccounting {
    upstream_pool: Arc<RwLock<UpstreamPool>>,
    backend_index: usize,
    start: Instant,
    status: Option<u16>,
    finished: bool,
}

impl BootstrapStreamingBody {
    pub(in crate::quic_listener) fn new(inner: Incoming) -> Self {
        Self {
            inner: BootstrapStreamingBodyInner::Hyper(inner),
            guardrails: None,
            declared_content_length: None,
            bytes_seen: 0,
            prebuffered_bytes: 0,
            capped: false,
            terminal: None,
            backend_accounting: None,
        }
    }

    fn with_response_guardrails(
        inner: UpstreamBody,
        max_body_bytes: usize,
        declared_content_length: Option<usize>,
        upstream_pool: Arc<RwLock<UpstreamPool>>,
        backend_index: usize,
        start: Instant,
        status: Option<u16>,
    ) -> Self {
        Self {
            inner: BootstrapStreamingBodyInner::Exchange(inner),
            guardrails: Some(ResponseBodyGuardrailConfig {
                idle_timeout: Duration::MAX,
                total_timeout: Duration::MAX,
                max_body_bytes,
                unknown_length_prebuffer_bytes: max_body_bytes,
                chunk_bytes: usize::MAX,
            }),
            declared_content_length,
            bytes_seen: 0,
            prebuffered_bytes: 0,
            capped: false,
            terminal: None,
            backend_accounting: Some(BootstrapBackendAccounting {
                upstream_pool,
                backend_index,
                start,
                status,
                finished: false,
            }),
        }
    }

    fn finish_backend_accounting(&mut self) {
        if let Some(accounting) = self.backend_accounting.as_mut() {
            if accounting.finished {
                return;
            }
            crate::runtime::connection::outcome::finish_backend_request_accounting(
                crate::runtime::connection::outcome::BackendRequestFinishInput {
                    upstream_pool: Some(&accounting.upstream_pool),
                    backend_index: Some(accounting.backend_index),
                    elapsed: accounting.start.elapsed(),
                    status: accounting.status,
                },
            );
            accounting.finished = true;
        }
    }

    fn terminalize(&mut self, terminal: BootstrapStreamingTerminal) {
        if self.terminal.is_some() {
            return;
        }
        self.terminal = Some(terminal);
        self.finish_backend_accounting();
    }
}

impl Body for BootstrapStreamingBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.capped {
            return Poll::Ready(None);
        }

        let frame = match &mut self.inner {
            BootstrapStreamingBodyInner::Hyper(body) => Pin::new(body)
                .poll_frame(cx)
                .map(|frame| frame.map(|frame| frame.map_err(|_| ()))),
            BootstrapStreamingBodyInner::Exchange(body) => body.poll_recv(cx).map(|frame| {
                frame.map(|frame| {
                    frame
                        .map(|frame| match frame {
                            UpstreamBodyFrame::Data(data) => Frame::data(data),
                            UpstreamBodyFrame::Trailers(trailers) => Frame::trailers(trailers),
                        })
                        .map_err(|_| ())
                })
            }),
        };

        match frame {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(guardrails) = self.guardrails
                    && let Some(data) = frame.data_ref()
                {
                    if let Ok(next_state) = checked_response_body_guardrails(
                        guardrails,
                        ResponseBodyGuardrailInput {
                            elapsed: Duration::ZERO,
                            idle_for: Duration::ZERO,
                            bytes_received: self.bytes_seen,
                            prebuffered_bytes: self.prebuffered_bytes,
                            next_chunk_bytes: data.len(),
                            declared_content_length: self.declared_content_length,
                            headers_emitted: true,
                            progressive_emission_allowed: true,
                            body_forwarding_enabled: true,
                            exempt_from_body_size_cap: false,
                        },
                    ) {
                        self.bytes_seen = next_state.next_state.bytes_received;
                        self.prebuffered_bytes = next_state.next_state.prebuffered_bytes;
                    } else {
                        self.capped = true;
                        self.terminalize(BootstrapStreamingTerminal::CappedRejected);
                        return Poll::Ready(None);
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(_))) => {
                self.terminalize(BootstrapStreamingTerminal::UpstreamBodyFailed);
                Poll::Ready(None)
            }
            Poll::Ready(None) => {
                self.terminalize(BootstrapStreamingTerminal::Completed);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for BootstrapStreamingBody {
    fn drop(&mut self) {
        if self.terminal.is_none() {
            self.terminalize(BootstrapStreamingTerminal::UpstreamBodyFailed);
        }
    }
}

pub(in crate::quic_listener) fn boxed_full(body: Bytes) -> BoxBody<Bytes, Infallible> {
    Full::new(body).map_err(|never| match never {}).boxed()
}

fn bootstrap_response_constraints(
    response_mode: BootstrapResponseMode,
) -> ResponseProtocolConstraints {
    ResponseProtocolConstraints {
        protocol: ResponseNormalizationProtocol::Http1,
        strip_connection_headers: true,
        allow_trailers: false,
        preserve_upgrade: matches!(response_mode, BootstrapResponseMode::WebsocketUpgrade),
    }
}

fn bootstrap_response_body_too_large_response(
    alt_svc: &str,
) -> Response<BoxBody<Bytes, Infallible>> {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("alt-svc", alt_svc)
        .body(boxed_full(Bytes::from_static(RESPONSE_BODY_TOO_LARGE_BODY)))
        .unwrap_or_else(|_| Response::new(boxed_full(Bytes::from_static(b"error\n"))))
}

pub(in crate::quic_listener) struct BootstrapWritebackInput<'a> {
    pub(in crate::quic_listener) upstream_resp: UpstreamExchangeResponse,
    pub(in crate::quic_listener) prepared_route: &'a BootstrapPreparedRoute,
    pub(in crate::quic_listener) dispatch_ctx: BootstrapDispatchCtx<'a>,
    pub(in crate::quic_listener) suppress_downstream_body: bool,
    pub(in crate::quic_listener) request_mode: BootstrapRequestMode,
    pub(in crate::quic_listener) client_upgrade: Option<hyper::upgrade::OnUpgrade>,
}

pub(in crate::quic_listener) fn write_bootstrap_response(
    input: BootstrapWritebackInput<'_>,
) -> Result<BootstrapWritebackOutcome, hyper::Error> {
    let status = input.upstream_resp.head.status;
    let response_mode = BootstrapResponseMode::from_request_mode(input.request_mode, status);
    let normalized_response = normalize_upstream_response(ResponseNormalizationInput {
        upstream: impulse_bridge::response::UpstreamResponseView {
            status,
            headers: &input.upstream_resp.head.headers,
            trailers: None,
        },
        body_mode: if input.suppress_downstream_body {
            ResponseBodyMode::HeadRequest
        } else {
            ResponseBodyMode::Normal
        },
        constraints: bootstrap_response_constraints(response_mode),
    });
    let upstream_content_length = input
        .upstream_resp
        .head
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok());
    let response_size_decision = checked_response_body_guardrails(
        ResponseBodyGuardrailConfig {
            idle_timeout: Duration::ZERO,
            total_timeout: Duration::MAX,
            max_body_bytes: input
                .dispatch_ctx
                .request
                .runtime
                .body_limits
                .max_response_body_bytes,
            unknown_length_prebuffer_bytes: input
                .dispatch_ctx
                .request
                .runtime
                .body_limits
                .max_response_body_bytes,
            chunk_bytes: 1,
        },
        ResponseBodyGuardrailInput {
            elapsed: Duration::ZERO,
            idle_for: Duration::ZERO,
            bytes_received: 0,
            prebuffered_bytes: 0,
            next_chunk_bytes: 0,
            declared_content_length: upstream_content_length,
            headers_emitted: false,
            progressive_emission_allowed: !normalized_response.emission.emit_end_stream_on_headers,
            body_forwarding_enabled: matches!(
                normalized_response.emission.body,
                ResponseBodyPolicy::Forward
            ),
            exempt_from_body_size_cap: matches!(
                response_mode,
                BootstrapResponseMode::WebsocketUpgrade
            ),
        },
    );
    if matches!(
        response_size_decision,
        Err(ResponseBodyGuardrailDecision::Reject {
            kind: BodyLimitKind::BodySize,
        })
    ) {
        observe_bootstrap_response_prebuffer_overflow(
            input.dispatch_ctx.request.runtime.metrics.as_ref(),
            input.prepared_route,
            input.dispatch_ctx.request.request_start,
        );
        return Ok(BootstrapWritebackOutcome {
            terminal: BootstrapTerminalOutcome::Rejected(BootstrapRejectionReason::Overloaded),
            response: bootstrap_response_body_too_large_response(
                &input.dispatch_ctx.request.runtime.alt_svc,
            ),
        });
    }
    observe_bootstrap_response_status(
        input.dispatch_ctx.request.runtime.metrics.as_ref(),
        input.prepared_route,
        input.dispatch_ctx.request.request_start,
        status,
    );

    let mut resp_builder = Response::builder().status(normalized_response.head.status);
    for header in &normalized_response.head.headers {
        resp_builder = resp_builder.header(&header.name, &header.value);
    }
    resp_builder = resp_builder.header("alt-svc", &input.dispatch_ctx.request.runtime.alt_svc);

    if matches!(response_mode, BootstrapResponseMode::WebsocketUpgrade) {
        return Ok(BootstrapWritebackOutcome {
            terminal: BootstrapTerminalOutcome::AcceptedWebsocketUpgrade,
            response: write_bootstrap_websocket_upgrade(
                resp_builder,
                input.upstream_resp,
                input.prepared_route,
                input.dispatch_ctx.request.request_start,
                &input.dispatch_ctx.request.runtime.alt_svc,
                input.client_upgrade,
                status,
            )?,
        });
    }

    let resp_body = if matches!(
        normalized_response.emission.body,
        ResponseBodyPolicy::Suppress
    ) {
        finish_bootstrap_backend_request_accounting(
            input.prepared_route,
            input.dispatch_ctx.request.request_start,
            Some(status.as_u16()),
        );
        boxed_full(Bytes::new())
    } else {
        BootstrapStreamingBody::with_response_guardrails(
            input.upstream_resp.body,
            input
                .dispatch_ctx
                .request
                .runtime
                .body_limits
                .max_response_body_bytes,
            upstream_content_length,
            Arc::clone(&input.prepared_route.upstream_pool),
            input.prepared_route.backend_index,
            input.dispatch_ctx.request.request_start,
            Some(status.as_u16()),
        )
        .map_err(|never| match never {})
        .boxed()
    };

    Ok(BootstrapWritebackOutcome {
        terminal: BootstrapTerminalOutcome::AcceptedStandardResponse,
        response: resp_builder
            .body(resp_body)
            .unwrap_or_else(|_| Response::new(boxed_full(Bytes::new()))),
    })
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue};
    use impulse_bridge::response::{
        ResponseBodyMode, ResponseBodyPolicy, ResponseNormalizationInput,
        ResponseNormalizationProtocol, normalize_upstream_response,
    };

    use super::*;

    fn header_value<'a>(
        headers: &'a [impulse_bridge::response::NormalizedHeader],
        name: &str,
    ) -> Option<&'a str> {
        let name = http::header::HeaderName::from_bytes(name.as_bytes()).ok()?;
        headers
            .iter()
            .find(|header| header.name == name)
            .and_then(|header| header.value.to_str().ok())
    }

    #[test]
    fn bootstrap_overflow_response_has_stable_local_wire_shape() {
        let response = bootstrap_response_body_too_large_response("h3=\":443\"; ma=86400");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response
                .headers()
                .get("alt-svc")
                .and_then(|value| value.to_str().ok()),
            Some("h3=\":443\"; ma=86400")
        );
    }

    #[test]
    fn bootstrap_constraints_strip_hop_headers_and_preserve_upgrade_only_for_websocket() {
        let standard = bootstrap_response_constraints(BootstrapResponseMode::StandardResponse);
        assert_eq!(standard.protocol, ResponseNormalizationProtocol::Http1);
        assert!(standard.strip_connection_headers);
        assert!(!standard.allow_trailers);
        assert!(!standard.preserve_upgrade);

        let websocket = bootstrap_response_constraints(BootstrapResponseMode::WebsocketUpgrade);
        assert!(websocket.preserve_upgrade);
    }

    #[test]
    fn bootstrap_and_quic_normalization_keep_same_end_to_end_response_contract() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("x-hop-token"),
        );
        headers.insert(
            http::header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        headers.insert(
            http::HeaderName::from_static("x-hop-token"),
            HeaderValue::from_static("secret"),
        );
        headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("9"));
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=60"),
        );
        headers.insert(http::header::ETAG, HeaderValue::from_static("\"etag-1\""));

        let quic = normalize_upstream_response(ResponseNormalizationInput {
            upstream: impulse_bridge::response::UpstreamResponseView {
                status: StatusCode::OK,
                headers: &headers,
                trailers: None,
            },
            body_mode: ResponseBodyMode::Normal,
            constraints: ResponseProtocolConstraints {
                protocol: ResponseNormalizationProtocol::Http3,
                strip_connection_headers: true,
                allow_trailers: true,
                preserve_upgrade: false,
            },
        });
        let bootstrap = normalize_upstream_response(ResponseNormalizationInput {
            upstream: impulse_bridge::response::UpstreamResponseView {
                status: StatusCode::OK,
                headers: &headers,
                trailers: None,
            },
            body_mode: ResponseBodyMode::Normal,
            constraints: bootstrap_response_constraints(BootstrapResponseMode::StandardResponse),
        });

        assert_eq!(quic.head.status, bootstrap.head.status);
        assert_eq!(quic.emission.body, ResponseBodyPolicy::Forward);
        assert_eq!(bootstrap.emission.body, ResponseBodyPolicy::Forward);
        assert!(!quic.emission.emit_end_stream_on_headers);
        assert!(!bootstrap.emission.emit_end_stream_on_headers);
        assert_eq!(
            header_value(&quic.head.headers, "cache-control"),
            header_value(&bootstrap.head.headers, "cache-control")
        );
        assert_eq!(
            header_value(&quic.head.headers, "etag"),
            header_value(&bootstrap.head.headers, "etag")
        );
        assert_eq!(header_value(&quic.head.headers, "x-hop-token"), None);
        assert_eq!(header_value(&bootstrap.head.headers, "x-hop-token"), None);
    }

    #[test]
    fn bootstrap_head_and_no_content_responses_stay_terminal_and_bodyless() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("0"));

        let head = normalize_upstream_response(ResponseNormalizationInput {
            upstream: impulse_bridge::response::UpstreamResponseView {
                status: StatusCode::OK,
                headers: &headers,
                trailers: None,
            },
            body_mode: ResponseBodyMode::HeadRequest,
            constraints: bootstrap_response_constraints(BootstrapResponseMode::StandardResponse),
        });
        let no_content = normalize_upstream_response(ResponseNormalizationInput {
            upstream: impulse_bridge::response::UpstreamResponseView {
                status: StatusCode::NO_CONTENT,
                headers: &headers,
                trailers: None,
            },
            body_mode: ResponseBodyMode::Normal,
            constraints: bootstrap_response_constraints(BootstrapResponseMode::StandardResponse),
        });

        assert_eq!(head.emission.body, ResponseBodyPolicy::Suppress);
        assert!(head.emission.emit_end_stream_on_headers);
        assert_eq!(no_content.emission.body, ResponseBodyPolicy::Suppress);
        assert!(no_content.emission.emit_end_stream_on_headers);
    }

    #[test]
    fn bootstrap_websocket_upgrade_switching_protocols_response_survives_header_cleanup() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("upgrade, x-hop-token"),
        );
        headers.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(
            http::HeaderName::from_static("sec-websocket-accept"),
            HeaderValue::from_static("test-accept"),
        );
        headers.insert(
            http::HeaderName::from_static("x-hop-token"),
            HeaderValue::from_static("strip-me"),
        );
        headers.insert(
            http::header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );

        let normalized = normalize_upstream_response(ResponseNormalizationInput {
            upstream: impulse_bridge::response::UpstreamResponseView {
                status: StatusCode::SWITCHING_PROTOCOLS,
                headers: &headers,
                trailers: None,
            },
            body_mode: ResponseBodyMode::Normal,
            constraints: bootstrap_response_constraints(BootstrapResponseMode::WebsocketUpgrade),
        });

        assert_eq!(normalized.head.status, StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(normalized.emission.body, ResponseBodyPolicy::Suppress);
        assert!(normalized.emission.emit_end_stream_on_headers);
        assert_eq!(
            header_value(&normalized.head.headers, "connection"),
            Some("upgrade, x-hop-token")
        );
        assert_eq!(
            header_value(&normalized.head.headers, "upgrade"),
            Some("websocket")
        );
        assert_eq!(
            header_value(&normalized.head.headers, "sec-websocket-accept"),
            Some("test-accept")
        );
        assert_eq!(header_value(&normalized.head.headers, "x-hop-token"), None);
        assert_eq!(
            header_value(&normalized.head.headers, "transfer-encoding"),
            None
        );
    }
}
