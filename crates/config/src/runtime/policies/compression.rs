use super::config_invalid;
use crate::{config::ResponseCompression, runtime::RuntimeConfigError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeResponseCompressionPolicy {
    pub enabled: bool,
    pub minimum_size_bytes: usize,
}

impl Default for RuntimeResponseCompressionPolicy {
    fn default() -> Self {
        let compression = ResponseCompression::default();
        Self {
            enabled: compression.enabled,
            minimum_size_bytes: compression.minimum_size_bytes,
        }
    }
}

impl RuntimeResponseCompressionPolicy {
    pub(crate) fn normalize(
        upstream_name: &str,
        compression: &ResponseCompression,
    ) -> Result<Self, RuntimeConfigError> {
        if compression.minimum_size_bytes == 0 {
            return Err(config_invalid(format!(
                "upstream['{upstream_name}'].compression.minimum_size_bytes must be greater than 0"
            )));
        }
        Ok(Self {
            enabled: compression.enabled,
            minimum_size_bytes: compression.minimum_size_bytes,
        })
    }

    pub(crate) fn as_config(&self) -> ResponseCompression {
        ResponseCompression {
            enabled: self.enabled,
            minimum_size_bytes: self.minimum_size_bytes,
        }
    }
}
