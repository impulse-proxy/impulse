use impulse_contracts::PluginKind;

use super::RuntimeConfig;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimePluginRequirements {
    kinds: Box<[PluginKind]>,
    configuration_locations: Box<[String]>,
}

impl RuntimePluginRequirements {
    pub(super) fn from_runtime_config(config: &RuntimeConfig) -> Self {
        let mut api_key_auth = None;
        let mut jwt_auth = None;
        let mut external_auth = None;
        let mut response_cache = None;
        let mut response_compression = None;

        let mut upstreams = config.upstreams.iter().collect::<Vec<_>>();
        upstreams.sort_unstable_by_key(|(name, _)| name.as_str());
        for (name, upstream) in upstreams {
            let auth = &upstream.policy.upstream_auth;
            if auth.api_key.is_some() {
                api_key_auth.get_or_insert_with(|| format!("upstream['{name}'].auth.api_key"));
            }
            if auth.jwt.is_some() {
                jwt_auth.get_or_insert_with(|| format!("upstream['{name}'].auth.jwt"));
            }
            if auth.external_auth.is_some() {
                external_auth
                    .get_or_insert_with(|| format!("upstream['{name}'].auth.external_auth"));
            }
            if upstream.policy.response_cache.enabled {
                response_cache.get_or_insert_with(|| format!("upstream['{name}'].cache.enabled"));
            }
            if upstream.policy.response_compression.enabled {
                response_compression
                    .get_or_insert_with(|| format!("upstream['{name}'].compression.enabled"));
            }
        }

        let mut kinds = Vec::with_capacity(PluginKind::COUNT);
        let mut configuration_locations = Vec::with_capacity(PluginKind::COUNT);
        if config.policies.transport.connection_rate_limit_enabled {
            push_requirement(
                &mut kinds,
                &mut configuration_locations,
                PluginKind::ConnectionRateLimit,
                "performance.connection_rate_limit_enabled".to_string(),
            );
        }
        if let Some(location) = api_key_auth {
            push_requirement(
                &mut kinds,
                &mut configuration_locations,
                PluginKind::ApiKeyAuth,
                location,
            );
        }
        if let Some(location) = jwt_auth {
            push_requirement(
                &mut kinds,
                &mut configuration_locations,
                PluginKind::JwtAuth,
                location,
            );
        }
        if let Some(location) = external_auth {
            push_requirement(
                &mut kinds,
                &mut configuration_locations,
                PluginKind::ExternalAuth,
                location,
            );
        }
        if !config.policies.rate_limits.scoped_limits.is_empty() {
            push_requirement(
                &mut kinds,
                &mut configuration_locations,
                PluginKind::ScopedRateLimit,
                "resilience.scoped_rate_limits".to_string(),
            );
        }
        if config.policies.rate_limits.quota.enabled {
            push_requirement(
                &mut kinds,
                &mut configuration_locations,
                PluginKind::Quota,
                "resilience.quota.enabled".to_string(),
            );
        }
        if let Some(location) = response_cache {
            push_requirement(
                &mut kinds,
                &mut configuration_locations,
                PluginKind::ResponseCache,
                location,
            );
        }
        if let Some(location) = response_compression {
            push_requirement(
                &mut kinds,
                &mut configuration_locations,
                PluginKind::ResponseCompression,
                location,
            );
        }

        Self {
            kinds: kinds.into_boxed_slice(),
            configuration_locations: configuration_locations.into_boxed_slice(),
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

    #[must_use]
    pub fn configuration_location(&self, kind: PluginKind) -> Option<&str> {
        self.kinds
            .iter()
            .position(|required| *required == kind)
            .map(|index| self.configuration_locations[index].as_str())
    }
}

fn push_requirement(
    kinds: &mut Vec<PluginKind>,
    configuration_locations: &mut Vec<String>,
    kind: PluginKind,
    configuration_location: String,
) {
    kinds.push(kind);
    configuration_locations.push(configuration_location);
}
