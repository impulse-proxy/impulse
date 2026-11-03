use std::{fmt, sync::Arc};

use impulse_contracts::PluginKind;

use crate::{
    ApiKeyAuthInput, ConnectionRateLimitInput, ExternalAuthInput, JwtAuthInput, QuotaInput,
    ResponseCacheInput, ResponseCompressionInput, ScopedRateLimitInput,
};

#[derive(Clone, Eq, PartialEq)]
pub enum CompiledConnectionPlugin {
    ConnectionRateLimit(ConnectionRateLimitInput),
}

impl CompiledConnectionPlugin {
    #[must_use]
    pub const fn kind(&self) -> PluginKind {
        match self {
            Self::ConnectionRateLimit(_) => PluginKind::ConnectionRateLimit,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum CompiledRequestPlugin {
    ApiKeyAuth(ApiKeyAuthInput),
    JwtAuth(JwtAuthInput),
    ScopedRateLimit(Arc<[ScopedRateLimitInput]>),
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

#[derive(Clone, Eq, PartialEq)]
pub enum CompiledAsyncRequestPlugin {
    ExternalAuth(ExternalAuthInput),
    Quota(Arc<QuotaInput>),
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
    ResponseCache(ResponseCacheInput),
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
    ResponseCompression(ResponseCompressionInput),
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
