use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use pingora_core::{
    Error, InternalError, Result, server::configuration::ServerConf, services::listening::Service,
    upstreams::peer::HttpPeer,
};
use pingora_http::ResponseHeader;
use pingora_proxy::{HttpProxy, ProxyHttp, Session, http_proxy_service_with_name};

use crate::{
    quic_listener::{
        AdmissionPolicyDecision, admission_rejection_response, validate_http_request_parts,
    },
    request_pipeline::{
        PipelineRequest, PipelineRoute, ResolvedRequestPolicy, ResolvedRouteTarget,
        RouteResolutionError, TerminalOutcomeGuard, evaluate_pipeline, resolve_route,
    },
    runtime::bundle::{RuntimeBundle, RuntimeBundleHandle},
};

pub(crate) struct PingoraRequestContext {
    pub(crate) runtime: Arc<RuntimeBundle>,
    pub(crate) route: Option<ResolvedRouteTarget>,
    pub(crate) policy: Option<ResolvedRequestPolicy>,
    pub(crate) terminal_outcome: TerminalOutcomeGuard,
}

pub(crate) struct PingoraIngressService {
    runtime: RuntimeBundleHandle,
}

pub(crate) fn pingora_ingress_service(
    configuration: &Arc<ServerConf>,
    runtime: RuntimeBundleHandle,
) -> Service<HttpProxy<PingoraIngressService>> {
    http_proxy_service_with_name(
        configuration,
        PingoraIngressService { runtime },
        "Impulse Pingora Ingress",
    )
}

#[async_trait]
impl ProxyHttp for PingoraIngressService {
    type CTX = PingoraRequestContext;

    fn new_ctx(&self) -> Self::CTX {
        PingoraRequestContext {
            runtime: self.runtime.current(),
            route: None,
            policy: None,
            terminal_outcome: TerminalOutcomeGuard::default(),
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let runtime = Arc::clone(&ctx.runtime);
        let state = runtime.shared_state.generation_state();
        let shared = runtime.shared_state.shared_services();
        let request = session.req_header();
        let validated = match validate_http_request_parts(
            &request.method,
            &request.uri,
            &request.headers,
            &state.resilience,
        ) {
            Ok(validated) => validated,
            Err((status, body, is_policy)) => {
                ctx.terminal_outcome.record();
                shared.metrics.inc_request_validation_reject();
                if is_policy {
                    shared.metrics.inc_policy_denied();
                }
                write_local_response(session, status, body, None, None).await?;
                return Ok(true);
            }
        };

        let route = match resolve_route(
            &state.routing_index,
            &validated.method,
            &validated.path,
            validated.authority.as_deref(),
        ) {
            Ok(route) => route,
            Err(RouteResolutionError::EmptyMethodOrPath) => {
                ctx.terminal_outcome.record();
                write_local_response(
                    session,
                    http::StatusCode::BAD_REQUEST,
                    b"invalid request\n",
                    None,
                    None,
                )
                .await?;
                return Ok(true);
            }
            Err(RouteResolutionError::NoRoute) => {
                ctx.terminal_outcome.record();
                write_local_response(
                    session,
                    http::StatusCode::BAD_GATEWAY,
                    b"no route\n",
                    None,
                    None,
                )
                .await?;
                return Ok(true);
            }
        };
        let Some(upstream_policy) = state.upstream_policies.get(route.upstream_name.as_ref())
        else {
            ctx.terminal_outcome.record();
            write_local_response(
                session,
                http::StatusCode::BAD_GATEWAY,
                b"no route\n",
                None,
                None,
            )
            .await?;
            return Ok(true);
        };
        let Some(peer_address) = session
            .client_addr()
            .and_then(|address| address.as_inet())
            .copied()
        else {
            ctx.terminal_outcome.record();
            write_local_response(
                session,
                http::StatusCode::INTERNAL_SERVER_ERROR,
                b"internal proxy error\n",
                None,
                None,
            )
            .await?;
            return Ok(true);
        };
        let header_lookup = |name: &str| {
            request
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let pipeline = evaluate_pipeline(
            &state.resilience,
            PipelineRoute::new(route.upstream_name.as_ref(), upstream_policy),
            PipelineRequest {
                method: &validated.method,
                path: &validated.path,
                authority: validated.authority.as_deref(),
                peer_address,
                headers: Some(&header_lookup),
                runtime_generation: runtime.generation,
                terminal_outcome: ctx.terminal_outcome.clone(),
            },
        );
        shared
            .metrics
            .set_brownout_active(state.resilience.brownout.is_active());

        if let Some(response) = admission_rejection_response(&pipeline.admission) {
            ctx.terminal_outcome.record();
            match pipeline.admission {
                AdmissionPolicyDecision::Unauthorized(_) => shared.metrics.inc_policy_denied(),
                AdmissionPolicyDecision::RateLimited(_) => {
                    shared.metrics.inc_request_rate_limited()
                }
                AdmissionPolicyDecision::Overloaded(_) | AdmissionPolicyDecision::AdmitReady => {}
            }
            write_local_response(
                session,
                response.status,
                response.body,
                response.www_authenticate,
                response.retry_after_seconds,
            )
            .await?;
            return Ok(true);
        }

        ctx.route = Some(route);
        ctx.policy = Some(pipeline.policy);
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        Error::e_explain(
            InternalError,
            "Pingora ingress upstream selection is not configured",
        )
    }
}

async fn write_local_response(
    session: &mut Session,
    status: http::StatusCode,
    body: &'static [u8],
    www_authenticate: Option<&'static str>,
    retry_after_seconds: Option<u32>,
) -> Result<()> {
    let mut response = ResponseHeader::build(status, Some(3))?;
    response.insert_header(http::header::CONTENT_LENGTH, body.len().to_string())?;
    if let Some(challenge) = www_authenticate {
        response.insert_header(http::header::WWW_AUTHENTICATE, challenge)?;
    }
    if let Some(seconds) = retry_after_seconds {
        response.insert_header(http::header::RETRY_AFTER, seconds.to_string())?;
    }
    session.write_response_header(Box::new(response)).await?;
    session
        .write_response_body(Bytes::from_static(body), true)
        .await
}
