use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use hyper::{
    body::{Body, Frame},
    http::{HeaderMap, Method, StatusCode, Uri, Version},
};
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

#[derive(Clone, Debug)]
pub struct UpstreamTrailers {
    pub headers: HeaderMap,
}

#[derive(Debug)]
pub enum UpstreamBodyFrame {
    Data(Bytes),
    Trailers(UpstreamTrailers),
}

#[derive(Debug)]
pub struct UpstreamRequestBody {
    pub frames: mpsc::Receiver<Result<UpstreamBodyFrame, ProxyError>>,
}

impl Body for UpstreamRequestBody {
    type Data = Bytes;
    type Error = ProxyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.frames.poll_recv(cx) {
            Poll::Ready(Some(Ok(UpstreamBodyFrame::Data(data)))) => {
                Poll::Ready(Some(Ok(Frame::data(data))))
            }
            Poll::Ready(Some(Ok(UpstreamBodyFrame::Trailers(trailers)))) => {
                Poll::Ready(Some(Ok(Frame::trailers(trailers.headers))))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Debug)]
pub struct UpstreamResponseBody {
    pub frames: mpsc::Receiver<Result<UpstreamBodyFrame, ProxyError>>,
}

pub(crate) fn upstream_response_body_channel() -> (
    mpsc::Sender<Result<UpstreamBodyFrame, ProxyError>>,
    UpstreamResponseBody,
) {
    let (frames, receiver) = mpsc::channel(16);
    (frames, UpstreamResponseBody { frames: receiver })
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
    pub body: UpstreamRequestBody,
    pub cancellation: UpstreamCancellation,
    pub completion: oneshot::Sender<UpstreamExchangeCompletion>,
}

pub struct UpstreamExchangeResponse {
    pub head: UpstreamResponseHead,
    pub body: UpstreamResponseBody,
    pub upgrade: Option<UpstreamUpgrade>,
}
