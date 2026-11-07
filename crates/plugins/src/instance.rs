use std::fmt;
#[cfg(feature = "connection-rate-limit")]
use std::net::IpAddr;
#[cfg(any(
    feature = "connection-rate-limit",
    feature = "scoped-rate-limit",
    feature = "quota",
    feature = "response-cache"
))]
use std::sync::Arc;

use impulse_contracts::PluginKind;

#[cfg(feature = "api-key-auth")]
use crate::ApiKeyAuthInput;
#[cfg(feature = "quota")]
use crate::CompiledQuota;
#[cfg(feature = "response-cache")]
use crate::CompiledResponseCache;
#[cfg(feature = "response-compression")]
use crate::CompiledResponseCompression;
#[cfg(feature = "external-auth")]
use crate::ExternalAuthInput;
#[cfg(feature = "jwt-auth")]
use crate::JwtAuthInput;
#[cfg(feature = "connection-rate-limit")]
use crate::{
    ConnectionRateLimitInput,
    rate_limit::{ConnectionRateLimitRejection, ConnectionRateLimitRuntime},
};
#[cfg(feature = "scoped-rate-limit")]
use crate::{
    ScopedRateLimitInput,
    rate_limit::{ScopedRateLimitDecision, ScopedRateLimitRuntime},
};

#[derive(Clone)]
pub struct CompiledConnectionPlugin {
    instance: CompiledConnectionPluginInstance,
}

#[derive(Clone)]
enum CompiledConnectionPluginInstance {
    #[cfg(feature = "connection-rate-limit")]
    ConnectionRateLimit(Arc<ConnectionRateLimitRuntime>),
    #[cfg(not(feature = "connection-rate-limit"))]
    Unavailable(std::convert::Infallible),
}

impl CompiledConnectionPlugin {
    #[cfg(feature = "connection-rate-limit")]
    #[must_use]
    pub(crate) fn connection_rate_limit(input: ConnectionRateLimitInput) -> Self {
        Self {
            instance: CompiledConnectionPluginInstance::ConnectionRateLimit(Arc::new(
                ConnectionRateLimitRuntime::new(input),
            )),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> PluginKind {
        match &self.instance {
            #[cfg(feature = "connection-rate-limit")]
            CompiledConnectionPluginInstance::ConnectionRateLimit(_) => {
                PluginKind::ConnectionRateLimit
            }
            #[cfg(not(feature = "connection-rate-limit"))]
            CompiledConnectionPluginInstance::Unavailable(unavailable) => match *unavailable {},
        }
    }

    #[cfg(feature = "connection-rate-limit")]
    pub(crate) fn admit_connection(
        &self,
        source: Option<IpAddr>,
    ) -> Result<(), ConnectionRateLimitRejection> {
        match &self.instance {
            #[cfg(feature = "connection-rate-limit")]
            CompiledConnectionPluginInstance::ConnectionRateLimit(runtime) => runtime.admit(source),
            #[cfg(not(feature = "connection-rate-limit"))]
            CompiledConnectionPluginInstance::Unavailable(unavailable) => match *unavailable {},
        }
    }
}

impl PartialEq for CompiledConnectionPlugin {
    fn eq(&self, other: &Self) -> bool {
        match (&self.instance, &other.instance) {
            #[cfg(feature = "connection-rate-limit")]
            (
                CompiledConnectionPluginInstance::ConnectionRateLimit(left),
                CompiledConnectionPluginInstance::ConnectionRateLimit(right),
            ) => left.input() == right.input(),
            #[cfg(not(feature = "connection-rate-limit"))]
            (CompiledConnectionPluginInstance::Unavailable(unavailable), _) => {
                match *unavailable {}
            }
        }
    }
}

impl Eq for CompiledConnectionPlugin {}

#[cfg(feature = "jwt-auth")]
#[derive(Clone, Eq, PartialEq)]
pub struct CompiledJwtAuth {
    generation: u64,
    input: JwtAuthInput,
}

#[cfg(feature = "jwt-auth")]
impl CompiledJwtAuth {
    #[must_use]
    pub(crate) fn new(generation: u64, input: JwtAuthInput) -> Self {
        Self { generation, input }
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn input(&self) -> &JwtAuthInput {
        &self.input
    }
}

#[cfg(feature = "scoped-rate-limit")]
pub struct CompiledScopedRateLimit {
    runtime: ScopedRateLimitRuntime,
}

#[cfg(feature = "scoped-rate-limit")]
impl CompiledScopedRateLimit {
    pub(crate) fn new(inputs: Arc<[ScopedRateLimitInput]>) -> Self {
        Self {
            runtime: ScopedRateLimitRuntime::new(inputs),
        }
    }

    pub(crate) fn evaluate(
        &self,
        request: impulse_contracts::PluginRequestView<'_>,
    ) -> ScopedRateLimitDecision {
        self.runtime.evaluate(request)
    }
}

#[derive(Clone)]
pub enum CompiledRequestPlugin {
    #[cfg(feature = "api-key-auth")]
    ApiKeyAuth(ApiKeyAuthInput),
    #[cfg(feature = "jwt-auth")]
    JwtAuth(Box<CompiledJwtAuth>),
    #[cfg(feature = "scoped-rate-limit")]
    ScopedRateLimit(Arc<CompiledScopedRateLimit>),
    #[doc(hidden)]
    #[cfg(not(any(
        feature = "api-key-auth",
        feature = "jwt-auth",
        feature = "scoped-rate-limit"
    )))]
    Unavailable(std::convert::Infallible),
}

impl CompiledRequestPlugin {
    #[must_use]
    pub const fn kind(&self) -> PluginKind {
        match self {
            #[cfg(feature = "api-key-auth")]
            Self::ApiKeyAuth(_) => PluginKind::ApiKeyAuth,
            #[cfg(feature = "jwt-auth")]
            Self::JwtAuth(_) => PluginKind::JwtAuth,
            #[cfg(feature = "scoped-rate-limit")]
            Self::ScopedRateLimit(_) => PluginKind::ScopedRateLimit,
            #[cfg(not(any(
                feature = "api-key-auth",
                feature = "jwt-auth",
                feature = "scoped-rate-limit"
            )))]
            Self::Unavailable(unavailable) => match *unavailable {},
        }
    }
}

impl PartialEq for CompiledRequestPlugin {
    #[allow(unreachable_patterns)]
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            #[cfg(feature = "api-key-auth")]
            (Self::ApiKeyAuth(left), Self::ApiKeyAuth(right)) => left == right,
            #[cfg(feature = "jwt-auth")]
            (Self::JwtAuth(left), Self::JwtAuth(right)) => left == right,
            #[cfg(feature = "scoped-rate-limit")]
            (Self::ScopedRateLimit(left), Self::ScopedRateLimit(right)) => {
                left.runtime.inputs() == right.runtime.inputs()
            }
            _ => false,
        }
    }
}

impl Eq for CompiledRequestPlugin {}

#[derive(Clone, Eq, PartialEq)]
pub enum CompiledAsyncRequestPlugin {
    #[cfg(feature = "external-auth")]
    ExternalAuth(ExternalAuthInput),
    #[cfg(feature = "quota")]
    Quota(Arc<CompiledQuota>),
    #[doc(hidden)]
    #[cfg(not(any(feature = "external-auth", feature = "quota")))]
    Unavailable(std::convert::Infallible),
}

impl CompiledAsyncRequestPlugin {
    #[must_use]
    pub const fn kind(&self) -> PluginKind {
        match self {
            #[cfg(feature = "external-auth")]
            Self::ExternalAuth(_) => PluginKind::ExternalAuth,
            #[cfg(feature = "quota")]
            Self::Quota(_) => PluginKind::Quota,
            #[cfg(not(any(feature = "external-auth", feature = "quota")))]
            Self::Unavailable(unavailable) => match *unavailable {},
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum CompiledCachePlugin {
    #[cfg(feature = "response-cache")]
    ResponseCache(Arc<CompiledResponseCache>),
    #[doc(hidden)]
    #[cfg(not(feature = "response-cache"))]
    Unavailable(std::convert::Infallible),
}

impl CompiledCachePlugin {
    #[must_use]
    pub const fn kind(&self) -> PluginKind {
        match self {
            #[cfg(feature = "response-cache")]
            Self::ResponseCache(_) => PluginKind::ResponseCache,
            #[cfg(not(feature = "response-cache"))]
            Self::Unavailable(unavailable) => match *unavailable {},
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum CompiledResponsePlugin {
    #[cfg(feature = "response-compression")]
    ResponseCompression(CompiledResponseCompression),
    #[doc(hidden)]
    #[cfg(not(feature = "response-compression"))]
    Unavailable(std::convert::Infallible),
}

impl CompiledResponsePlugin {
    #[must_use]
    pub const fn kind(&self) -> PluginKind {
        match self {
            #[cfg(feature = "response-compression")]
            Self::ResponseCompression(_) => PluginKind::ResponseCompression,
            #[cfg(not(feature = "response-compression"))]
            Self::Unavailable(unavailable) => match *unavailable {},
        }
    }
}

macro_rules! redacted_debug {
    ($type:ty) => {
        impl fmt::Debug for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple("CompiledPlugin")
                    .field(&self.kind())
                    .finish()
            }
        }
    };
}

redacted_debug!(CompiledConnectionPlugin);
redacted_debug!(CompiledRequestPlugin);
redacted_debug!(CompiledAsyncRequestPlugin);
redacted_debug!(CompiledCachePlugin);
redacted_debug!(CompiledResponsePlugin);
