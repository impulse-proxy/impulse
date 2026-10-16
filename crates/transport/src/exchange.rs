use bytes::Bytes;
use hyper::http::{HeaderMap, Method, StatusCode, Uri, Version};
use impulse_errors::ProxyError;
use tokio::sync::mpsc;

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
