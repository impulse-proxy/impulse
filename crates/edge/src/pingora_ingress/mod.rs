use std::{
    convert::Infallible,
    sync::{Arc, RwLock, atomic::Ordering},
    time::Instant,
};

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{Full, combinators::BoxBody};
use impulse_config::backend_endpoint::BackendScheme;
use impulse_lb::upstream_pool::UpstreamPool;
use pingora_core::{
    Error, InternalError, Result, server::configuration::ServerConf, services::listening::Service,
    upstreams::peer::HttpPeer,
};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{HttpProxy, ProxyHttp, Session, http_proxy_service_with_name};

use crate::{
    REQUEST_ID_COUNTER,
    quic_listener::{
        AdmissionPolicyDecision, ForwardingSelectionService, TargetResolutionRequest,
        admission_rejection_response, validate_http_request_parts,
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
    method: Option<String>,
    path: Option<String>,
    authority: Option<String>,
    content_length: Option<usize>,
    request_id: u64,
    selected_backend: Option<PingoraSelectedBackend>,
}

struct PingoraSelectedBackend {
    address: String,
    pool: Arc<RwLock<UpstreamPool>>,
    index: usize,
    selected_at: Instant,
}

impl Drop for PingoraSelectedBackend {
    fn drop(&mut self) {
        if let Ok(mut pool) = self.pool.write() {
            pool.finish_request(self.index, self.selected_at.elapsed(), None);
        }
    }
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
            method: None,
            path: None,
            authority: None,
            content_length: None,
            request_id: REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed),
            selected_backend: None,
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
        ctx.method = Some(validated.method);
        ctx.path = Some(validated.path);
        ctx.authority = validated.authority;
        ctx.content_length = validated.content_length;
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let route = ctx.route.as_ref().ok_or_else(|| {
            Error::explain(
                InternalError,
                "Pingora ingress request filter did not resolve a route",
            )
        })?;
        let method = ctx.method.as_deref().ok_or_else(|| {
            Error::explain(
                InternalError,
                "Pingora ingress request filter did not validate a method",
            )
        })?;
        let path = ctx.path.as_deref().ok_or_else(|| {
            Error::explain(
                InternalError,
                "Pingora ingress request filter did not validate a path",
            )
        })?;
        let state = ctx.runtime.shared_state.generation_state();
        let pool = state
            .upstream_pools
            .get(route.upstream_name.as_ref())
            .cloned()
            .ok_or_else(|| {
                Error::explain(
                    InternalError,
                    format!(
                        "Pingora ingress upstream pool is missing: {}",
                        route.upstream_name
                    ),
                )
            })?;
        let request = session.req_header();
        let header_lookup = |name: &str| {
            request
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let selected = ForwardingSelectionService::select_backend(
            &TargetResolutionRequest::new(
                method,
                path,
                ctx.authority.as_deref(),
                None,
                Some(&header_lookup),
            ),
            &pool,
            true,
        )
        .map_err(|error| Error::because(InternalError, "backend selection failed", error))?;
        let selected_backend = PingoraSelectedBackend {
            address: selected.backend_addr.clone(),
            pool,
            index: selected.backend_index,
            selected_at: Instant::now(),
        };
        let peer = ctx
            .runtime
            .shared_state
            .shared_services()
            .transport_pool
            .pingora_peer(&selected.backend_addr, ctx.runtime.generation)
            .map_err(|error| {
                Error::because(InternalError, "backend peer creation failed", error)
            })?;
        ctx.selected_backend = Some(selected_backend);
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let policy = ctx.policy.as_ref().ok_or_else(|| {
            Error::explain(
                InternalError,
                "Pingora ingress request filter did not resolve request policy",
            )
        })?;
        let selected = ctx.selected_backend.as_ref().ok_or_else(|| {
            Error::explain(
                InternalError,
                "Pingora ingress upstream peer did not select a backend",
            )
        })?;
        let method = ctx.method.as_deref().ok_or_else(|| {
            Error::explain(
                InternalError,
                "Pingora ingress request filter did not validate a method",
            )
        })?;
        let path = ctx.path.as_deref().ok_or_else(|| {
            Error::explain(
                InternalError,
                "Pingora ingress request filter did not validate a path",
            )
        })?;
        let endpoint = ctx
            .runtime
            .shared_state
            .generation_state()
            .backend_endpoints
            .get(&selected.address)
            .ok_or_else(|| {
                Error::explain(
                    InternalError,
                    format!(
                        "Pingora ingress backend endpoint is missing: {}",
                        selected.address
                    ),
                )
            })?;
        let client_addr = session
            .client_addr()
            .and_then(|address| address.as_inet())
            .copied()
            .ok_or_else(|| {
                Error::explain(InternalError, "Pingora ingress client address is missing")
            })?;
        let downstream_request = session.req_header();
        let headers = bridge_headers(&downstream_request.headers);
        let traceparent = downstream_request
            .headers
            .get("traceparent")
            .and_then(|value| value.to_str().ok());
        let target = impulse_bridge::request::RequestBuildTarget {
            endpoint,
            policies: impulse_bridge::request::RequestBuildPolicies {
                host_policy: &policy.host_policy,
                forwarded_header_policy: &policy.forwarded_header_policy,
            },
        };
        let input = impulse_bridge::request::RequestBuildInput {
            method,
            path,
            authority: ctx.authority.as_deref(),
            headers: &headers,
            auth_header_mutations: &[],
            body: BoxBody::new(Full::<Bytes>::new(Bytes::new())),
            body_mode: impulse_bridge::request::RequestBuildInput::<
                BoxBody<Bytes, Infallible>,
            >::body_mode_for_length(ctx.content_length),
            trace: impulse_bridge::request::RequestTraceContext {
                request_id: ctx.request_id,
                traceparent,
            },
            forwarded: impulse_bridge::request::RequestForwardedContext { client_addr },
        };
        let normalized = match endpoint.scheme() {
            BackendScheme::Http => impulse_bridge::request::build_h1_request(target, input),
            BackendScheme::Https => {
                impulse_bridge::request::build_h2_request_for_target(target, input)
            }
        }
        .map_err(|error| {
            Error::because(
                InternalError,
                "upstream request normalization failed",
                error,
            )
        })?;

        let existing_headers = upstream_request.headers.keys().cloned().collect::<Vec<_>>();
        for name in existing_headers {
            upstream_request.remove_header(&name);
        }
        for (name, value) in normalized.headers() {
            upstream_request.append_header(name.clone(), value.clone())?;
        }
        Ok(())
    }
}

fn bridge_headers(headers: &http::HeaderMap) -> Vec<quiche::h3::Header> {
    headers
        .iter()
        .map(|(name, value)| quiche::h3::Header::new(name.as_str().as_bytes(), value.as_bytes()))
        .collect()
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
