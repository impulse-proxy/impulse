use std::fmt;

/// Stable identifier assigned to one downstream request.
pub type RequestId = u64;

/// Protocol used by a downstream request to enter the runtime.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IngressProtocol {
    Http1,
    Http2,
    Http3,
}

impl IngressProtocol {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http1 => "http1",
            Self::Http2 => "http2",
            Self::Http3 => "http3",
        }
    }
}

impl fmt::Display for IngressProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Canonical identity of one configured or resolved backend.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BackendIdentity {
    pub backend_addr: String,
}

impl BackendIdentity {
    #[must_use]
    pub fn new(backend_addr: impl Into<String>) -> Self {
        Self {
            backend_addr: backend_addr.into(),
        }
    }
}
