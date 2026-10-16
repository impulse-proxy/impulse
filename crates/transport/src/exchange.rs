use bytes::Bytes;
use hyper::http::{HeaderMap, Method, StatusCode, Uri, Version};
use impulse_errors::ProxyError;
use tokio::sync::{OwnedSemaphorePermit, mpsc, oneshot};

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

#[derive(Debug)]
pub struct UpstreamResponseBody {
    pub frames: mpsc::Receiver<Result<UpstreamBodyFrame, ProxyError>>,
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
