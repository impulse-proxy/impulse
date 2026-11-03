use http::StatusCode;

/// Validated mutation applied to an upstream request header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeaderMutation {
    Upsert { name: Vec<u8>, value: Vec<u8> },
    Remove { name: Vec<u8> },
}

/// Borrowed header mutation consumed by request encoders.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderMutationRef<'a> {
    pub name: &'a [u8],
    pub value: Option<&'a [u8]>,
}

impl HeaderMutation {
    #[must_use]
    pub fn as_ref(&self) -> HeaderMutationRef<'_> {
        match self {
            Self::Upsert { name, value } => HeaderMutationRef {
                name,
                value: Some(value),
            },
            Self::Remove { name } => HeaderMutationRef { name, value: None },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthChallengeKind {
    ApiKey,
    Bearer,
}

impl AuthChallengeKind {
    #[must_use]
    pub const fn as_www_authenticate(self) -> &'static str {
        match self {
            Self::ApiKey => "ApiKey",
            Self::Bearer => "Bearer",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnauthorizedDecision {
    pub challenge: AuthChallengeKind,
    pub status: StatusCode,
    pub body: &'static [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimitedDecision {
    pub rule_name: String,
    pub route: String,
    pub status: StatusCode,
    pub body: &'static [u8],
    pub retry_after_seconds: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OverloadDecisionReason {
    Brownout,
    AdaptiveAdmission,
    RouteCap,
    RouteGlobalCap,
    GlobalInflight,
    UpstreamInflight,
}

impl OverloadDecisionReason {
    #[must_use]
    pub const fn response_body(self) -> &'static [u8] {
        match self {
            Self::Brownout => b"brownout active, non-core route shed\n",
            Self::AdaptiveAdmission => b"adaptive admission overload\n",
            Self::RouteCap => b"route queue cap exceeded\n",
            Self::RouteGlobalCap => b"global queue cap exceeded\n",
            Self::GlobalInflight => b"overloaded, retry later\n",
            Self::UpstreamInflight => b"upstream overloaded, retry later\n",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverloadDecision {
    pub reason: OverloadDecisionReason,
    pub status: StatusCode,
    pub body: &'static [u8],
    pub retry_after_seconds: u32,
}

/// Bounded response that protocol adapters can emit without policy knowledge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedRejectionResponse {
    pub status: StatusCode,
    pub body: &'static [u8],
    pub www_authenticate: Option<&'static str>,
    pub retry_after_seconds: Option<u32>,
}

/// Protocol-neutral request decision produced before upstream execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestDecision {
    AdmitReady,
    Unauthorized(UnauthorizedDecision),
    RateLimited(RateLimitedDecision),
    Overloaded(OverloadDecision),
}

impl RequestDecision {
    #[must_use]
    pub fn rejection_response(&self) -> Option<BoundedRejectionResponse> {
        match self {
            Self::AdmitReady => None,
            Self::Unauthorized(decision) => Some(BoundedRejectionResponse {
                status: decision.status,
                body: decision.body,
                www_authenticate: Some(decision.challenge.as_www_authenticate()),
                retry_after_seconds: None,
            }),
            Self::RateLimited(decision) => Some(BoundedRejectionResponse {
                status: decision.status,
                body: decision.body,
                www_authenticate: None,
                retry_after_seconds: Some(decision.retry_after_seconds.max(1)),
            }),
            Self::Overloaded(decision) => Some(BoundedRejectionResponse {
                status: decision.status,
                body: decision.body,
                www_authenticate: None,
                retry_after_seconds: Some(decision.retry_after_seconds.max(1)),
            }),
        }
    }
}
