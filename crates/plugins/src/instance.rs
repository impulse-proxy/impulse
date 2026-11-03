use impulse_contracts::PluginKind;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompiledConnectionPlugin {
    ConnectionRateLimit,
}

impl CompiledConnectionPlugin {
    #[must_use]
    pub const fn kind(self) -> PluginKind {
        match self {
            Self::ConnectionRateLimit => PluginKind::ConnectionRateLimit,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompiledRequestPlugin {
    ApiKeyAuth,
    JwtAuth,
    ScopedRateLimit,
}

impl CompiledRequestPlugin {
    #[must_use]
    pub const fn kind(self) -> PluginKind {
        match self {
            Self::ApiKeyAuth => PluginKind::ApiKeyAuth,
            Self::JwtAuth => PluginKind::JwtAuth,
            Self::ScopedRateLimit => PluginKind::ScopedRateLimit,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompiledAsyncRequestPlugin {
    ExternalAuth,
    Quota,
}

impl CompiledAsyncRequestPlugin {
    #[must_use]
    pub const fn kind(self) -> PluginKind {
        match self {
            Self::ExternalAuth => PluginKind::ExternalAuth,
            Self::Quota => PluginKind::Quota,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompiledCachePlugin {
    ResponseCache,
}

impl CompiledCachePlugin {
    #[must_use]
    pub const fn kind(self) -> PluginKind {
        match self {
            Self::ResponseCache => PluginKind::ResponseCache,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompiledResponsePlugin {
    ResponseCompression,
}

impl CompiledResponsePlugin {
    #[must_use]
    pub const fn kind(self) -> PluginKind {
        match self {
            Self::ResponseCompression => PluginKind::ResponseCompression,
        }
    }
}
