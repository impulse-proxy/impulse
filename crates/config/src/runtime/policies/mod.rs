//! Runtime policy interpreter façade.
//!
//! This module re-exports the stable normalized policy types that downstream
//! crates consume. Domain-local normalization helpers and intermediate policy
//! set assembly stay crate-private to avoid leaking interpreter structure.

mod admission;
mod auth;
mod backend;
mod cache;
mod compression;
mod lb;
mod quota;
mod resilience;
mod timeouts;
mod transport;
mod watchdog;

pub use self::{
    admission::{
        RuntimeAdmissionPolicy, RuntimeBrownoutPolicy, RuntimeRateLimitPolicy,
        RuntimeRouteQueuePolicy, RuntimeScopedRateLimitPolicy,
    },
    auth::{
        RuntimeApiKeyAuth, RuntimeAuthPolicy, RuntimeExternalAuth, RuntimeExternalAuthFailureMode,
        RuntimeExternalAuthRequestHeader, RuntimeJwtAuth, RuntimeJwtVerificationKey,
    },
    backend::{
        RuntimeBackendAddressKind, RuntimeBackendDnsPolicy, RuntimeBackendEndpoint,
        RuntimeBackendHealthCheck, RuntimeBackendTlsPolicy,
    },
    cache::RuntimeResponseCachePolicy,
    compression::RuntimeResponseCompressionPolicy,
    lb::{
        RuntimeAlternateBackendPolicy, RuntimeBackendWeightPolicy, RuntimeLoadBalancingPolicy,
        RuntimeLoadBalancingStrategy, RuntimeRequestKeySpec,
    },
    quota::{
        RuntimeQuotaBackendFailurePolicy, RuntimeQuotaCounterBackend, RuntimeQuotaEnforcementMode,
        RuntimeQuotaLocalFallback, RuntimeQuotaPolicy, RuntimeQuotaPolicySet,
        RuntimeQuotaSelectorDimension, RuntimeQuotaSelectorMatcher, RuntimeQuotaWindow,
    },
    resilience::{RuntimeCircuitBreakerPolicy, RuntimeHedgingPolicy, RuntimeRetryBudgetPolicy},
    timeouts::RuntimeTimeoutPolicy,
    transport::{RuntimeBackendConnectionPolicy, RuntimeConnectionLimits, RuntimeTransportPolicy},
    watchdog::RuntimeWatchdogPolicy,
};
use super::{Config, RuntimeConfigError, RuntimeListenerTls};
fn config_invalid(message: impl Into<String>) -> RuntimeConfigError {
    RuntimeConfigError::ConfigInvalid(message.into())
}

fn normalize_optional_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn normalize_route_host(raw: &str) -> String {
    let trimmed = raw.trim();
    let host = if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            &rest[..end]
        } else {
            trimmed
        }
    } else if let Some((candidate_host, candidate_port)) = trimmed.rsplit_once(':') {
        if !candidate_host.contains(':') && candidate_port.chars().all(|c| c.is_ascii_digit()) {
            candidate_host
        } else {
            trimmed
        }
    } else {
        trimmed
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn normalized_route_method(method: Option<&str>) -> Option<String> {
    method
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_uppercase())
}

fn parse_runtime_route_host_pattern(raw: &str) -> RuntimeRouteHostPattern {
    let normalized = normalize_route_host(raw);
    let Some(wildcard_suffix) = normalized.strip_prefix("*.") else {
        return RuntimeRouteHostPattern::Exact(normalized);
    };
    if wildcard_suffix.is_empty() || wildcard_suffix.contains('*') {
        return RuntimeRouteHostPattern::Exact(normalized);
    }
    RuntimeRouteHostPattern::WildcardSuffix(wildcard_suffix.to_string())
}

fn valid_runtime_route_host_pattern(normalized: &str) -> bool {
    if normalized.is_empty()
        || normalized.contains('[')
        || normalized.contains(']')
        || normalized.contains('/')
        || normalized.contains('?')
        || normalized.contains('#')
        || normalized.chars().any(char::is_whitespace)
    {
        return false;
    }

    match normalized.strip_prefix("*.") {
        Some(wildcard_suffix) => !wildcard_suffix.is_empty() && !wildcard_suffix.contains('*'),
        None => !normalized.contains('*'),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RuntimeRouteHostPattern {
    Exact(String),
    WildcardSuffix(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuntimeRouteMatchPolicy {
    pub host: Option<String>,
    pub host_pattern: Option<RuntimeRouteHostPattern>,
    pub path_prefix: Option<String>,
    pub method: Option<String>,
    pub path_len: usize,
    pub host_specific: bool,
    pub method_specific: bool,
}

impl RuntimeRouteMatchPolicy {
    pub(crate) fn normalize(
        upstream_name: &str,
        route: &crate::config::RouteMatch,
    ) -> Result<Self, RuntimeConfigError> {
        let path_prefix = normalize_optional_string(route.path_prefix.as_deref());
        if let Some(path_prefix) = path_prefix.as_deref()
            && !path_prefix.starts_with('/')
        {
            return Err(config_invalid(format!(
                "upstream '{upstream_name}' has an invalid route.path_prefix '{}'",
                path_prefix
            )));
        }

        let host = match normalize_optional_string(route.host.as_deref()) {
            Some(host) => {
                let normalized = normalize_route_host(&host);
                if !valid_runtime_route_host_pattern(&normalized) {
                    return Err(config_invalid(format!(
                        "upstream '{upstream_name}' has an invalid route.host '{}'",
                        route.host.as_deref().unwrap_or_default()
                    )));
                }
                Some(normalized)
            }
            None => None,
        };
        if host.is_none() && path_prefix.is_none() {
            return Err(config_invalid(format!(
                "upstream '{upstream_name}' must configure a non-empty route.host or route.path_prefix"
            )));
        }
        let host_pattern = host.as_deref().map(parse_runtime_route_host_pattern);
        let method = normalized_route_method(route.method.as_deref());

        Ok(Self {
            path_len: path_prefix.as_ref().map(|value| value.len()).unwrap_or(0),
            host_specific: host.is_some(),
            method_specific: method.is_some(),
            host,
            host_pattern,
            path_prefix,
            method,
        })
    }

    #[cfg(test)]
    pub(crate) fn as_config(&self) -> crate::config::RouteMatch {
        crate::config::RouteMatch {
            host: self.host.clone(),
            path_prefix: self.path_prefix.clone(),
            method: self.method.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeBackendTransportKind {
    Http1,
    H2,
}

#[derive(Debug, Clone)]
pub struct RuntimePolicySet {
    pub timeouts: RuntimeTimeoutPolicy,
    pub admission: RuntimeAdmissionPolicy,
    pub rate_limits: RuntimeRateLimitPolicy,
    pub transport: RuntimeTransportPolicy,
}

impl RuntimePolicySet {
    pub(crate) fn from_config(config: &Config) -> Result<Self, RuntimeConfigError> {
        let timeouts = RuntimeTimeoutPolicy::normalize(&config.performance)?;
        let transport = RuntimeTransportPolicy::normalize(&config.performance)?;
        let rate_limits = RuntimeRateLimitPolicy::normalize(&config.resilience)?;
        let admission =
            RuntimeAdmissionPolicy::normalize(&config.resilience, transport.global_inflight_limit)?;

        Ok(Self {
            timeouts,
            admission,
            rate_limits,
            transport,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeListenerPolicySet {
    pub timeouts: RuntimeTimeoutPolicy,
    pub transport: RuntimeTransportPolicy,
    pub tls: RuntimeListenerTls,
}
