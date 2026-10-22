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

pub struct UpstreamCancellation {
    pub signal: oneshot::Receiver<()>,
}

#[derive(Debug)]
pub enum UpstreamExchangeOutcome {
    Completed,
    Cancelled,
    Failed(ProxyError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamConnectionReuse {
    Reuse,
    Close,
}

#[derive(Debug)]
pub struct UpstreamExchangeCompletion {
    pub outcome: UpstreamExchangeOutcome,
    pub connection_reuse: UpstreamConnectionReuse,
}

pub struct UpstreamInflightPermit {
    pub(crate) _permit: OwnedSemaphorePermit,
}

pub struct UpstreamExchangeLifecycle {
    pub cancellation: UpstreamCancellation,
    pub completion: oneshot::Sender<UpstreamExchangeCompletion>,
    pub inflight_permit: UpstreamInflightPermit,
}

pub trait UpstreamTunnelIo: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> UpstreamTunnelIo for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub struct UpstreamTunnel {
    pub io: Box<dyn UpstreamTunnelIo>,
    pub lifecycle: UpstreamExchangeLifecycle,
}

pub struct UpstreamUpgrade {
    pub tunnel: oneshot::Receiver<Result<UpstreamTunnel, ProxyError>>,
}

pub struct UpstreamExchangeRequest {
    pub head: UpstreamRequestHead,
    pub body: UpstreamBody,
    pub cancellation: UpstreamCancellation,
    pub completion: oneshot::Sender<UpstreamExchangeCompletion>,
}

pub struct UpstreamExchangeResponse {
    pub head: UpstreamResponseHead,
    pub body: UpstreamBody,
    pub upgrade: Option<UpstreamUpgrade>,
}
