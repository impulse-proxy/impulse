use bytes::Bytes;
use hyper::http::{HeaderMap, Method, StatusCode, Uri, Version};
use impulse_errors::ProxyError;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{OwnedSemaphorePermit, mpsc, oneshot},
};

#[derive(Clone, Debug)]
pub struct UpstreamRequestHead {
    pub method: Method,
    pub uri: Uri,
    pub version: Version,
    pub headers: HeaderMap,
}

#[derive(Clone, Debug)]
pub struct UpstreamResponseHead {
    pub status: StatusCode,
    pub version: Version,
    pub headers: HeaderMap,
}

#[derive(Debug)]
pub enum UpstreamBodyFrame {
    Data(Bytes),
    Trailers(HeaderMap),
}

pub type UpstreamBody = mpsc::Receiver<Result<UpstreamBodyFrame, ProxyError>>;

pub(crate) fn upstream_response_body_channel() -> (
    mpsc::Sender<Result<UpstreamBodyFrame, ProxyError>>,
    UpstreamBody,
) {
    mpsc::channel(16)
}

pub(crate) struct UpstreamCancellation {
    pub signal: oneshot::Receiver<()>,
}

#[derive(Debug)]
pub(crate) enum UpstreamExchangeOutcome {
    Completed,
    Cancelled,
    Failed(ProxyError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UpstreamConnectionReuse {
    Reuse,
    Close,
}

#[derive(Debug)]
pub(crate) struct UpstreamExchangeCompletion {
    pub outcome: UpstreamExchangeOutcome,
    pub connection_reuse: UpstreamConnectionReuse,
}

pub(crate) struct UpstreamInflightPermit {
    pub(crate) _permit: OwnedSemaphorePermit,
}

pub(crate) struct UpstreamExchangeLifecycle {
    pub cancellation: UpstreamCancellation,
    pub completion: oneshot::Sender<UpstreamExchangeCompletion>,
    pub inflight_permit: UpstreamInflightPermit,
}

pub trait UpstreamTunnelIo: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> UpstreamTunnelIo for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub struct UpstreamTunnel {
    io: Box<dyn UpstreamTunnelIo>,
    lifecycle: UpstreamExchangeLifecycle,
}

impl UpstreamTunnel {
    pub(crate) fn new(io: Box<dyn UpstreamTunnelIo>, lifecycle: UpstreamExchangeLifecycle) -> Self {
        Self { io, lifecycle }
    }

    pub fn into_parts(self) -> (Box<dyn UpstreamTunnelIo>, UpstreamTunnelCompletion) {
        (
            self.io,
            UpstreamTunnelCompletion {
                lifecycle: self.lifecycle,
            },
        )
    }
}

pub struct UpstreamTunnelCompletion {
    lifecycle: UpstreamExchangeLifecycle,
}

impl UpstreamTunnelCompletion {
    pub fn complete(self) {
        self.finish(UpstreamExchangeOutcome::Completed);
    }

    pub fn fail(self, error: ProxyError) {
        self.finish(UpstreamExchangeOutcome::Failed(error));
    }

    fn finish(self, outcome: UpstreamExchangeOutcome) {
        let _ = self.lifecycle.completion.send(UpstreamExchangeCompletion {
            outcome,
            connection_reuse: UpstreamConnectionReuse::Close,
        });
    }
}

pub struct UpstreamUpgrade {
    pub tunnel: oneshot::Receiver<Result<UpstreamTunnel, ProxyError>>,
}

pub struct UpstreamExchangeRequest {
    pub head: UpstreamRequestHead,
    pub body: UpstreamBody,
}

pub struct UpstreamExchangeResponse {
    pub head: UpstreamResponseHead,
    pub body: UpstreamBody,
    pub upgrade: Option<UpstreamUpgrade>,
}
