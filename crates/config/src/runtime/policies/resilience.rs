use std::{collections::HashMap, time::Duration};

use super::config_invalid;
use crate::{config::Resilience, runtime::RuntimeConfigError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeCircuitBreakerPolicy {
    pub enabled: bool,
    pub failure_threshold: u32,
    pub open: Duration,
    pub half_open_max_probes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeRetryBudgetPolicy {
    pub enabled: bool,
    pub ratio_percent: u8,
    pub per_route_ratio_percent: HashMap<String, u8>,
}

pub(crate) fn normalize_circuit_breaker_policy(
    resilience: &Resilience,
) -> Result<RuntimeCircuitBreakerPolicy, RuntimeConfigError> {
    if resilience.circuit_breaker.failure_threshold == 0 {
        return Err(config_invalid(
            "resilience.circuit_breaker.failure_threshold must be greater than 0",
        ));
    }
    if resilience.circuit_breaker.open_ms == 0 {
        return Err(config_invalid(
            "resilience.circuit_breaker.open_ms must be greater than 0",
        ));
    }
    if resilience.circuit_breaker.half_open_max_probes == 0 {
        return Err(config_invalid(
            "resilience.circuit_breaker.half_open_max_probes must be greater than 0",
        ));
    }

    Ok(RuntimeCircuitBreakerPolicy {
        enabled: resilience.circuit_breaker.enabled,
        failure_threshold: resilience.circuit_breaker.failure_threshold,
        open: Duration::from_millis(resilience.circuit_breaker.open_ms.max(1)),
        half_open_max_probes: resilience.circuit_breaker.half_open_max_probes,
    })
}

pub(crate) fn normalize_retry_budget_policy(
    resilience: &Resilience,
) -> Result<RuntimeRetryBudgetPolicy, RuntimeConfigError> {
    if resilience.retry_budget.ratio_percent > 100 {
        return Err(config_invalid(
            "resilience.retry_budget.ratio_percent must be <= 100",
        ));
    }
    if resilience
        .retry_budget
        .per_route_ratio_percent
        .values()
        .any(|ratio| *ratio > 100)
    {
        return Err(config_invalid(
            "resilience.retry_budget.per_route_ratio_percent values must be <= 100",
        ));
    }

    Ok(RuntimeRetryBudgetPolicy {
        enabled: resilience.retry_budget.enabled,
        ratio_percent: resilience.retry_budget.ratio_percent,
        per_route_ratio_percent: resilience.retry_budget.per_route_ratio_percent.clone(),
    })
}
