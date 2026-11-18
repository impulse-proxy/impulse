use std::fmt;

/// Stable identifier assigned to one downstream request.
pub type RequestId = u64;

fn normalize_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    let mut bytes: [u8; N] = value.as_bytes().try_into().ok()?;
    if bytes.iter().all(|byte| *byte == b'0') || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    bytes.make_ascii_lowercase();
    Some(bytes)
}

fn write_hex_u64(value: u64, output: &mut [u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in output.iter_mut().enumerate() {
        let shift = (15 - index) * 4;
        *byte = HEX[((value >> shift) & 0x0f) as usize];
    }
}

/// Fixed-size lowercase hexadecimal trace identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TraceId([u8; 32]);

impl TraceId {
    #[must_use]
    pub fn from_hex(value: &str) -> Option<Self> {
        normalize_hex(value).map(Self)
    }

    #[must_use]
    pub fn from_u64_pair(high: u64, low: u64) -> Self {
        let mut value = [0; 32];
        write_hex_u64(high, &mut value[..16]);
        write_hex_u64(low, &mut value[16..]);
        Self(value)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or("")
    }
}

impl fmt::Display for TraceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Fixed-size lowercase hexadecimal span identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SpanId([u8; 16]);

impl SpanId {
    #[must_use]
    pub fn from_hex(value: &str) -> Option<Self> {
        normalize_hex(value).map(Self)
    }

    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        let mut encoded = [0; 16];
        write_hex_u64(value, &mut encoded);
        Self(encoded)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or("")
    }
}

impl fmt::Display for SpanId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

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
