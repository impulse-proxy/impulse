use impulse_contracts::PluginKind;

use super::RuntimeConfig;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimePluginRequirements {
    kinds: Box<[PluginKind]>,
}

impl RuntimePluginRequirements {
    pub(super) fn from_runtime_config(config: &RuntimeConfig) -> Self {
        let mut api_key_auth = false;
        let mut jwt_auth = false;
        let mut external_auth = false;
        let mut response_cache = false;
        let mut response_compression = false;

        for upstream in config.upstreams.values() {
            let auth = &upstream.policy.upstream_auth;
            api_key_auth |= auth.api_key.is_some();
            jwt_auth |= auth.jwt.is_some();
            external_auth |= auth.external_auth.is_some();
            response_cache |= upstream.policy.response_cache.enabled;
            response_compression |= upstream.policy.response_compression.enabled;
        }

        let mut kinds = Vec::with_capacity(PluginKind::COUNT);
        kinds.push(PluginKind::ConnectionRateLimit);
        if api_key_auth {
            kinds.push(PluginKind::ApiKeyAuth);
        }
        if jwt_auth {
            kinds.push(PluginKind::JwtAuth);
        }
        if external_auth {
            kinds.push(PluginKind::ExternalAuth);
        }
        if !config.policies.rate_limits.scoped_limits.is_empty() {
            kinds.push(PluginKind::ScopedRateLimit);
        }
        if config.policies.rate_limits.quota.enabled {
            kinds.push(PluginKind::Quota);
        }
        if response_cache {
            kinds.push(PluginKind::ResponseCache);
        }
        if response_compression {
            kinds.push(PluginKind::ResponseCompression);
        }

        Self {
            kinds: kinds.into_boxed_slice(),
        }
    }

    #[must_use]
    pub fn kinds(&self) -> &[PluginKind] {
        &self.kinds
    }

    #[must_use]
    pub fn requires(&self, kind: PluginKind) -> bool {
        self.kinds.contains(&kind)
    }
}
