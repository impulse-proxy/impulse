use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use hyper::http::{HeaderMap, Method, StatusCode, Uri, Version};
use impulse_contracts::TunnelMode;
use impulse_errors::ProxyError;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
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
    /// Move body storage across the transport boundary without materializing a `Vec`.
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

pub(crate) struct UpstreamInflightPermit {
    pub(crate) _permit: OwnedSemaphorePermit,
}

pub(crate) struct UpstreamExchangeLifecycle {
    pub _inflight_permit: UpstreamInflightPermit,
}

pub trait UpstreamTunnelIo: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> UpstreamTunnelIo for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub struct UpstreamTunnel {
    mode: TunnelMode,
    io: Box<dyn UpstreamTunnelIo>,
    lifecycle: UpstreamExchangeLifecycle,
}

impl UpstreamTunnel {
    pub(crate) fn new(
        mode: TunnelMode,
        io: Box<dyn UpstreamTunnelIo>,
        lifecycle: UpstreamExchangeLifecycle,
    ) -> Self {
        Self {
            mode,
            io,
            lifecycle,
        }
    }

    pub fn into_parts(self) -> (TunnelMode, Box<dyn UpstreamTunnelIo>) {
        (
            self.mode,
            Box::new(UpstreamTunnelLease {
                io: self.io,
                _lifecycle: self.lifecycle,
            }),
        )
    }
}

struct UpstreamTunnelLease {
    io: Box<dyn UpstreamTunnelIo>,
    _lifecycle: UpstreamExchangeLifecycle,
}

impl AsyncRead for UpstreamTunnelLease {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(self.io.as_mut()).poll_read(cx, buf)
    }
}

impl AsyncWrite for UpstreamTunnelLease {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(self.io.as_mut()).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(self.io.as_mut()).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(self.io.as_mut()).poll_shutdown(cx)
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
