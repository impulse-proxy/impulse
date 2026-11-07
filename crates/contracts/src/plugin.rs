use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PluginKind {
    ConnectionRateLimit,
    ApiKeyAuth,
    JwtAuth,
    ExternalAuth,
    ScopedRateLimit,
    Quota,
    ResponseCache,
    ResponseCompression,
}

impl PluginKind {
    pub const ALL: [Self; 8] = [
        Self::ConnectionRateLimit,
        Self::ApiKeyAuth,
        Self::JwtAuth,
        Self::ExternalAuth,
        Self::ScopedRateLimit,
        Self::Quota,
        Self::ResponseCache,
        Self::ResponseCompression,
    ];
    pub const COUNT: usize = Self::ALL.len();

    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ConnectionRateLimit => "connection_rate_limit",
            Self::ApiKeyAuth => "api_key_auth",
            Self::JwtAuth => "jwt_auth",
            Self::ExternalAuth => "external_auth",
            Self::ScopedRateLimit => "scoped_rate_limit",
            Self::Quota => "quota",
            Self::ResponseCache => "response_cache",
            Self::ResponseCompression => "response_compression",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PluginPhase {
    ConnectionAdmission,
    RequestGate,
    AsyncRequestGate,
    CacheLookup,
    CacheFill,
    ResponsePolicy,
}

impl PluginPhase {
    pub const ALL: [Self; 6] = [
        Self::ConnectionAdmission,
        Self::RequestGate,
        Self::AsyncRequestGate,
        Self::CacheLookup,
        Self::CacheFill,
        Self::ResponsePolicy,
    ];
    pub const COUNT: usize = Self::ALL.len();

    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ConnectionAdmission => "connection_admission",
            Self::RequestGate => "request_gate",
            Self::AsyncRequestGate => "async_request_gate",
            Self::CacheLookup => "cache_lookup",
            Self::CacheFill => "cache_fill",
            Self::ResponsePolicy => "response_policy",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PluginScope {
    Runtime,
    Listener,
    Upstream,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PluginExecutionOutcome {
    Continue,
    Reject,
    Bypass,
    Fail,
}

impl PluginExecutionOutcome {
    pub const ALL: [Self; 4] = [Self::Continue, Self::Reject, Self::Bypass, Self::Fail];
    pub const COUNT: usize = Self::ALL.len();

    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Continue => "allow",
            Self::Reject => "reject",
            Self::Bypass => "bypass",
            Self::Fail => "failure",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PluginExecutionObservation {
    pub kind: PluginKind,
    pub phase: PluginPhase,
    pub outcome: PluginExecutionOutcome,
    pub async_duration: Option<Duration>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginActivationOutcome {
    Success,
    Failure,
}

impl PluginActivationOutcome {
    pub const ALL: [Self; 2] = [Self::Success, Self::Failure];
    pub const COUNT: usize = Self::ALL.len();

    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PluginRejectionReason {
    ApiKeyMissing,
    ApiKeyInvalid,
    JwtMissing,
    JwtInvalid,
    JwtClaimsRejected,
    JwksUnavailable,
    ExternalAuthDenied,
    ExternalAuthUnavailable,
    RateLimited,
    QuotaDenied,
    QuotaUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PluginStateOwnership {
    Startup,
    Generation,
    SharedService,
    Request,
}
use std::net::SocketAddr;

use http::{HeaderName, HeaderValue, StatusCode};

use crate::{AuthChallengeKind, IngressProtocol, RequestId};

pub type PluginHeaderLookup<'a> = dyn Fn(&str) -> Option<&'a [u8]> + Sync + 'a;

#[derive(Clone, Copy)]
pub struct PluginConnectionView<'a> {
    pub generation: u64,
    pub listener: &'a str,
    pub peer_address: Option<SocketAddr>,
}

#[derive(Clone, Copy)]
pub struct PluginRequestView<'a> {
    pub request_id: RequestId,
    pub generation: u64,
    pub route_id: Option<&'a str>,
    pub upstream_name: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub authority: Option<&'a str>,
    pub peer_address: SocketAddr,
    pub headers: Option<&'a PluginHeaderLookup<'a>>,
    pub has_body: bool,
    pub body_replayable: bool,
    pub ingress_protocol: IngressProtocol,
}

impl PluginRequestView<'_> {
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers.and_then(|lookup| lookup(name))
    }
}

#[derive(Clone, Copy)]
pub struct PluginResponseMetadataView<'a> {
    pub status: StatusCode,
    pub headers: Option<&'a PluginHeaderLookup<'a>>,
    pub declared_content_length: Option<usize>,
    pub body_allowed: bool,
}

impl PluginResponseMetadataView<'_> {
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers.and_then(|lookup| lookup(name))
    }
}

#[derive(Clone, Copy)]
pub struct PluginCacheView<'request, 'response> {
    pub request: PluginRequestView<'request>,
    pub response: Option<PluginResponseMetadataView<'response>>,
    pub representation: Option<&'request str>,
}

#[derive(Clone, Copy)]
pub struct PluginResponseView<'request, 'response> {
    pub request: PluginRequestView<'request>,
    pub response: PluginResponseMetadataView<'response>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginHeaderMutation {
    name: HeaderName,
    value: Option<HeaderValue>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginHeaderMutationError {
    InvalidName,
    InvalidValue,
    ForbiddenName,
}

impl PluginHeaderMutation {
    pub fn upsert(name: &[u8], value: &[u8]) -> Result<Self, PluginHeaderMutationError> {
        let name = validated_plugin_header_name(name)?;
        let value =
            HeaderValue::from_bytes(value).map_err(|_| PluginHeaderMutationError::InvalidValue)?;
        Ok(Self {
            name,
            value: Some(value),
        })
    }

    pub fn remove(name: &[u8]) -> Result<Self, PluginHeaderMutationError> {
        Ok(Self {
            name: validated_plugin_header_name(name)?,
            value: None,
        })
    }

    #[must_use]
    pub const fn name(&self) -> &HeaderName {
        &self.name
    }

    #[must_use]
    pub const fn value(&self) -> Option<&HeaderValue> {
        self.value.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginResponseHeader {
    name: HeaderName,
    value: HeaderValue,
}

impl PluginResponseHeader {
    pub fn new(name: &[u8], value: &[u8]) -> Result<Self, PluginHeaderMutationError> {
        let name = validated_plugin_header_name(name)?;
        let value =
            HeaderValue::from_bytes(value).map_err(|_| PluginHeaderMutationError::InvalidValue)?;
        Ok(Self { name, value })
    }

    #[must_use]
    pub const fn name(&self) -> &HeaderName {
        &self.name
    }

    #[must_use]
    pub const fn value(&self) -> &HeaderValue {
        &self.value
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginRejectionError {
    TooManyHeaders,
    BodyTooLarge,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginRejection {
    reason: PluginRejectionReason,
    status: StatusCode,
    headers: Vec<PluginResponseHeader>,
    body: Vec<u8>,
}

impl PluginRejection {
    pub const MAX_HEADERS: usize = 16;
    pub const MAX_BODY_BYTES: usize = 64 * 1024;

    pub fn new(
        reason: PluginRejectionReason,
        status: StatusCode,
        headers: Vec<PluginResponseHeader>,
        body: Vec<u8>,
    ) -> Result<Self, PluginRejectionError> {
        if headers.len() > Self::MAX_HEADERS {
            return Err(PluginRejectionError::TooManyHeaders);
        }
        if body.len() > Self::MAX_BODY_BYTES {
            return Err(PluginRejectionError::BodyTooLarge);
        }
        Ok(Self {
            reason,
            status,
            headers,
            body,
        })
    }

    #[must_use]
    pub fn unauthorized(reason: PluginRejectionReason, challenge: AuthChallengeKind) -> Self {
        Self {
            reason,
            status: StatusCode::UNAUTHORIZED,
            headers: vec![PluginResponseHeader {
                name: http::header::WWW_AUTHENTICATE,
                value: HeaderValue::from_static(challenge.as_www_authenticate()),
            }],
            body: b"unauthorized\n".to_vec(),
        }
    }

    #[must_use]
    pub fn rate_limited(retry_after_seconds: u32) -> Self {
        Self {
            reason: PluginRejectionReason::RateLimited,
            status: StatusCode::TOO_MANY_REQUESTS,
            headers: vec![PluginResponseHeader {
                name: http::header::RETRY_AFTER,
                value: HeaderValue::from_str(&retry_after_seconds.max(1).to_string())
                    .unwrap_or(HeaderValue::from_static("1")),
            }],
            body: b"request rate limited\n".to_vec(),
        }
    }

    #[must_use]
    pub fn quota_denied(retry_after_seconds: Option<u32>, body: &'static [u8]) -> Self {
        let headers = retry_after_seconds
            .map(|seconds| PluginResponseHeader {
                name: http::header::RETRY_AFTER,
                value: HeaderValue::from_str(&seconds.max(1).to_string())
                    .unwrap_or(HeaderValue::from_static("1")),
            })
            .into_iter()
            .collect();
        Self {
            reason: PluginRejectionReason::QuotaDenied,
            status: StatusCode::TOO_MANY_REQUESTS,
            headers,
            body: body.to_vec(),
        }
    }

    #[must_use]
    pub fn quota_unavailable(body: &'static [u8]) -> Self {
        Self {
            reason: PluginRejectionReason::QuotaUnavailable,
            status: StatusCode::SERVICE_UNAVAILABLE,
            headers: Vec::new(),
            body: body.to_vec(),
        }
    }

    #[must_use]
    pub const fn reason(&self) -> PluginRejectionReason {
        self.reason
    }

    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    #[must_use]
    pub fn headers(&self) -> &[PluginResponseHeader] {
        &self.headers
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

fn validated_plugin_header_name(name: &[u8]) -> Result<HeaderName, PluginHeaderMutationError> {
    let name = HeaderName::from_bytes(name).map_err(|_| PluginHeaderMutationError::InvalidName)?;
    if matches!(
        name.as_str(),
        "connection"
            | "content-length"
            | "host"
            | "keep-alive"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    ) {
        return Err(PluginHeaderMutationError::ForbiddenName);
    }
    Ok(name)
}
