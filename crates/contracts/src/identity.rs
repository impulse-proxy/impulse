use std::fmt;

/// Stable identifier assigned to one downstream request.
pub type RequestId = u64;

/// Compact identity of one route in a runtime generation.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RouteId(u32);

impl RouteId {
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Compact identity of one upstream in a runtime generation.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UpstreamId(u32);

impl UpstreamId {
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Compact identity of one backend in a runtime generation.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BackendId(u32);

impl BackendId {
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Compact identity of one listener in a runtime generation.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ListenerId(u32);

impl ListenerId {
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

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
