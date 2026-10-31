use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use pingora_cache::{CacheKey, RespCacheable};
use pingora_core::{Error, Result, upstreams::peer::HttpPeer};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};

#[async_trait]
pub trait PingoraRequestService: Send + Sync + 'static {
    type Context: Send + Sync;

    fn new_context(&self) -> Self::Context;

    async fn request_filter(
        &self,
        session: &mut Session,
        context: &mut Self::Context,
    ) -> Result<bool>;

    fn request_cache_filter(
        &self,
        session: &mut Session,
        context: &mut Self::Context,
    ) -> Result<()>;

    fn cache_key_callback(
        &self,
        session: &Session,
        context: &mut Self::Context,
    ) -> Result<CacheKey>;

    fn response_cache_filter(
        &self,
        session: &Session,
        response: &ResponseHeader,
        context: &mut Self::Context,
    ) -> Result<RespCacheable>;

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        context: &mut Self::Context,
    ) -> Result<()>;

    async fn upstream_peer(
        &self,
        session: &mut Session,
        context: &mut Self::Context,
    ) -> Result<Box<HttpPeer>>;

    fn fail_to_connect(
        &self,
        session: &mut Session,
        peer: &HttpPeer,
        context: &mut Self::Context,
        error: Box<Error>,
    ) -> Box<Error>;

    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        error: Box<Error>,
        context: &mut Self::Context,
        reused: bool,
    ) -> Box<Error>;

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        context: &mut Self::Context,
    ) -> Result<()>;

    async fn adjust_upstream_modules(
        &self,
        session: &mut Session,
        upstream_response: &ResponseHeader,
        end_of_stream: bool,
        context: &mut Self::Context,
    ) -> Result<()>;

    async fn upstream_response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        context: &mut Self::Context,
    ) -> Result<()>;

    fn upstream_response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        context: &mut Self::Context,
    ) -> Result<Option<Duration>>;

    fn upstream_response_trailer_filter(
        &self,
        session: &mut Session,
        upstream_trailers: &mut http::HeaderMap,
        context: &mut Self::Context,
    ) -> Result<()>;

    async fn logging(
        &self,
        session: &mut Session,
        error: Option<&Error>,
        context: &mut Self::Context,
    );
}

pub struct PingoraIngressAdapter<S> {
    request_service: S,
}

impl<S> PingoraIngressAdapter<S> {
    pub fn new(request_service: S) -> Self {
        Self { request_service }
    }
}

#[async_trait]
impl<S: PingoraRequestService> ProxyHttp for PingoraIngressAdapter<S> {
    type CTX = S::Context;

    fn new_ctx(&self) -> Self::CTX {
        self.request_service.new_context()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        self.request_service.request_filter(session, ctx).await
    }

    fn request_cache_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()> {
        self.request_service.request_cache_filter(session, ctx)
    }

    fn cache_key_callback(&self, session: &Session, ctx: &mut Self::CTX) -> Result<CacheKey> {
        self.request_service.cache_key_callback(session, ctx)
    }

    fn response_cache_filter(
        &self,
        session: &Session,
        response: &ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<RespCacheable> {
        self.request_service
            .response_cache_filter(session, response, ctx)
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        self.request_service
            .request_body_filter(session, body, end_of_stream, ctx)
            .await
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        self.request_service.upstream_peer(session, ctx).await
    }

    fn fail_to_connect(
        &self,
        session: &mut Session,
        peer: &HttpPeer,
        ctx: &mut Self::CTX,
        error: Box<Error>,
    ) -> Box<Error> {
        self.request_service
            .fail_to_connect(session, peer, ctx, error)
    }

    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        error: Box<Error>,
        ctx: &mut Self::CTX,
        reused: bool,
    ) -> Box<Error> {
        self.request_service
            .error_while_proxy(peer, session, error, ctx, reused)
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        self.request_service
            .upstream_request_filter(session, upstream_request, ctx)
            .await
    }

    async fn adjust_upstream_modules(
        &self,
        session: &mut Session,
        upstream_response: &ResponseHeader,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        self.request_service
            .adjust_upstream_modules(session, upstream_response, end_of_stream, ctx)
            .await
    }

    async fn upstream_response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        self.request_service
            .upstream_response_filter(session, upstream_response, ctx)
            .await
    }

    fn upstream_response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>> {
        self.request_service
            .upstream_response_body_filter(session, body, end_of_stream, ctx)
    }

    fn upstream_response_trailer_filter(
        &self,
        session: &mut Session,
        upstream_trailers: &mut http::HeaderMap,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        self.request_service
            .upstream_response_trailer_filter(session, upstream_trailers, ctx)
    }

    async fn logging(&self, session: &mut Session, error: Option<&Error>, ctx: &mut Self::CTX) {
        self.request_service.logging(session, error, ctx).await;
    }
}
