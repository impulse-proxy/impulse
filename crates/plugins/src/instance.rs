use std::{fmt, net::IpAddr, sync::Arc};

use impulse_contracts::PluginKind;

use crate::{
    ApiKeyAuthInput, CompiledQuota, CompiledResponseCache, CompiledResponseCompression,
    ConnectionRateLimitInput, ExternalAuthInput, JwtAuthInput, ScopedRateLimitInput,
    rate_limit::{
        ConnectionRateLimitRejection, ConnectionRateLimitRuntime, ScopedRateLimitDecision,
        ScopedRateLimitRuntime,
    },
};

#[derive(Clone)]
pub struct CompiledConnectionPlugin {
    instance: CompiledConnectionPluginInstance,
}

#[derive(Clone)]
enum CompiledConnectionPluginInstance {
    ConnectionRateLimit(Arc<ConnectionRateLimitRuntime>),
}

impl CompiledConnectionPlugin {
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
            CompiledConnectionPluginInstance::ConnectionRateLimit(_) => {
                PluginKind::ConnectionRateLimit
            }
        }
    }

    pub(crate) fn admit_connection(
        &self,
        source: Option<IpAddr>,
    ) -> Result<(), ConnectionRateLimitRejection> {
        match &self.instance {
            CompiledConnectionPluginInstance::ConnectionRateLimit(runtime) => runtime.admit(source),
        }
    }
}

impl PartialEq for CompiledConnectionPlugin {
    fn eq(&self, other: &Self) -> bool {
        match (&self.instance, &other.instance) {
            (
                CompiledConnectionPluginInstance::ConnectionRateLimit(left),
                CompiledConnectionPluginInstance::ConnectionRateLimit(right),
            ) => left.input() == right.input(),
        }
    }
}

impl Eq for CompiledConnectionPlugin {}

#[derive(Clone, Eq, PartialEq)]
pub struct CompiledJwtAuth {
    generation: u64,
    input: JwtAuthInput,
}

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

pub struct CompiledScopedRateLimit {
    runtime: ScopedRateLimitRuntime,
}

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
    ApiKeyAuth(ApiKeyAuthInput),
    JwtAuth(Box<CompiledJwtAuth>),
    ScopedRateLimit(Arc<CompiledScopedRateLimit>),
}

impl CompiledRequestPlugin {
    #[must_use]
    pub const fn kind(&self) -> PluginKind {
        match self {
            Self::ApiKeyAuth(_) => PluginKind::ApiKeyAuth,
            Self::JwtAuth(_) => PluginKind::JwtAuth,
            Self::ScopedRateLimit(_) => PluginKind::ScopedRateLimit,
        }
    }
}

impl PartialEq for CompiledRequestPlugin {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::ApiKeyAuth(left), Self::ApiKeyAuth(right)) => left == right,
            (Self::JwtAuth(left), Self::JwtAuth(right)) => left == right,
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
    ExternalAuth(ExternalAuthInput),
    Quota(Arc<CompiledQuota>),
}

impl CompiledAsyncRequestPlugin {
    #[must_use]
    pub const fn kind(&self) -> PluginKind {
        match self {
            Self::ExternalAuth(_) => PluginKind::ExternalAuth,
            Self::Quota(_) => PluginKind::Quota,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum CompiledCachePlugin {
    ResponseCache(Arc<CompiledResponseCache>),
}

impl CompiledCachePlugin {
    #[must_use]
    pub const fn kind(&self) -> PluginKind {
        match self {
            Self::ResponseCache(_) => PluginKind::ResponseCache,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum CompiledResponsePlugin {
    ResponseCompression(CompiledResponseCompression),
}

impl CompiledResponsePlugin {
    #[must_use]
    pub const fn kind(&self) -> PluginKind {
        match self {
            Self::ResponseCompression(_) => PluginKind::ResponseCompression,
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
