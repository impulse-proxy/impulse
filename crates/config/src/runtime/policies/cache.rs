use super::config_invalid;
use crate::{config::ResponseCache, runtime::RuntimeConfigError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeResponseCachePolicy {
    pub enabled: bool,
    pub max_bytes: usize,
    pub max_entries: usize,
    pub max_object_bytes: usize,
    pub max_ttl_secs: u64,
}

impl Default for RuntimeResponseCachePolicy {
    fn default() -> Self {
        Self::from_config(&ResponseCache::default())
    }
}

impl RuntimeResponseCachePolicy {
    pub(crate) fn normalize(
        upstream_name: &str,
        cache: &ResponseCache,
    ) -> Result<Self, RuntimeConfigError> {
        cache.validate().map_err(|error| {
            config_invalid(format!("upstream['{upstream_name}'].cache.{error}"))
        })?;
        Ok(Self::from_config(cache))
    }

    fn from_config(cache: &ResponseCache) -> Self {
        Self {
            enabled: cache.enabled,
            max_bytes: cache.max_bytes,
            max_entries: cache.max_entries,
            max_object_bytes: cache.max_object_bytes,
            max_ttl_secs: cache.max_ttl_secs,
        }
    }

    #[cfg(test)]
    pub(crate) fn as_config(&self) -> ResponseCache {
        ResponseCache {
            enabled: self.enabled,
            max_bytes: self.max_bytes,
            max_entries: self.max_entries,
            max_object_bytes: self.max_object_bytes,
            max_ttl_secs: self.max_ttl_secs,
        }
    }
}
