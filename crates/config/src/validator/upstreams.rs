use std::collections::HashMap;

use super::*;
use crate::validator::{
    auth::validate_upstream_auth,
    helpers::{
        normalize_route_host, normalized_route_method, valid_route_host_pattern,
        valid_static_host_header, validate_upstream_tls,
    },
};

macro_rules! validation_error {
    ($($arg:tt)*) => {{
        let message = format!($($arg)*);
        super::record_validation_error(message.clone());
        log::error!("{}", message);
    }};
}

pub(super) fn validate_upstream_routes(config: &Config) -> bool {
    for (upstream_name, upstream) in &config.upstream {
        let normalized_route_host = upstream
            .route
            .host
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(normalize_route_host);
        let has_host = normalized_route_host.is_some();
        let has_path = upstream.route.path_prefix.is_some();

        if !has_host && !has_path {
            validation_error!(
                "Upstream '{}' must have either 'host' or 'path_prefix' route matcher",
                upstream_name
            );
            return false;
        }

        if let Some(host) = upstream.route.host.as_deref()
            && !valid_route_host_pattern(host)
        {
            validation_error!(
                "Route host matcher must be a valid non-empty host pattern for upstream '{}': {}",
                upstream_name,
                host
            );
            return false;
        }

        if let Some(ref path) = upstream.route.path_prefix {
            if path.is_empty() {
                validation_error!(
                    "Route path_prefix cannot be empty for upstream '{}'",
                    upstream_name
                );
                return false;
            }
            if !path.starts_with('/') {
                validation_error!(
                    "Route path_prefix must start with '/' for upstream '{}': {}",
                    upstream_name,
                    path
                );
                return false;
            }
        }

        match upstream.host_policy.mode {
            UpstreamHostPolicyMode::PassThrough | UpstreamHostPolicyMode::Upstream => {
                if upstream.host_policy.host.is_some() {
                    validation_error!(
                        "upstream {}.host_policy.host is invalid unless mode is rewrite",
                        upstream_name
                    );
                    return false;
                }
            }
            UpstreamHostPolicyMode::Rewrite => match upstream.host_policy.host.as_deref() {
                Some(host) if valid_static_host_header(host) => {}
                _ => {
                    validation_error!(
                        "upstream {}.host_policy.mode=rewrite requires a valid non-empty host_policy.host",
                        upstream_name
                    );
                    return false;
                }
            },
        }
    }

    true
}

pub(super) fn validate_upstreams(config: &Config) -> bool {
    if config.upstream.is_empty() {
        validation_error!("No upstreams configured");
        return false;
    }

    let mut seen_route_matchers: HashMap<RouteMatcherKey, String> = HashMap::new();
    for (upstream_name, upstream) in &config.upstream {
        let route_key = (
            upstream
                .route
                .host
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(normalize_route_host),
            upstream.route.path_prefix.clone(),
            normalized_route_method(upstream.route.method.as_deref()),
        );

        if let Some(existing_upstream) =
            seen_route_matchers.insert(route_key.clone(), upstream_name.clone())
        {
            validation_error!(
                "Ambiguous route matcher detected: upstream '{}' conflicts with upstream '{}' for host={:?} path_prefix={:?} method={:?}",
                upstream_name,
                existing_upstream,
                route_key.0,
                route_key.1,
                route_key.2
            );
            return false;
        }
    }

    let mut seen_backend_origins: HashMap<String, (String, String)> = HashMap::new();
    let mut validate_global_upstream_tls = false;

    for (upstream_name, upstream) in &config.upstream {
        if upstream_name.is_empty() {
            validation_error!("Upstream name is empty");
            return false;
        }

        if !VALID_LB_TYPES
            .iter()
            .any(|lb_type| lb_type.eq_ignore_ascii_case(&upstream.load_balancing.lb_type))
        {
            validation_error!(
                "Invalid load balancing type '{}' for upstream '{}'",
                upstream.load_balancing.lb_type,
                upstream_name
            );
            return false;
        }
        let lb_strategy =
            RuntimeLoadBalancingStrategy::from_lb_type(&upstream.load_balancing.lb_type);

        if !validate_upstream_auth(upstream_name, upstream) {
            return false;
        }
        if upstream.compression.minimum_size_bytes == 0 {
            validation_error!(
                "upstream['{}'].compression.minimum_size_bytes must be greater than 0",
                upstream_name
            );
            return false;
        }
        if let Err(error) = upstream.cache.validate() {
            validation_error!("upstream['{}'].cache.{error}", upstream_name);
            return false;
        }

        if upstream.backends.is_empty() {
            validation_error!("Upstream '{}' has no backends configured", upstream_name);
            return false;
        }

        let mut upstream_uses_https_backends = false;
        for backend in &upstream.backends {
            if backend.id.is_empty() {
                validation_error!("Backend ID is empty in upstream '{}'", upstream_name);
                return false;
            }
            if backend.address.is_empty() {
                validation_error!(
                    "Backend address is empty for backend '{}' in upstream '{}'",
                    backend.id,
                    upstream_name
                );
                return false;
            }

            let endpoint = match BackendEndpoint::parse(&backend.address) {
                Ok(endpoint) => endpoint,
                Err(reason) => {
                    validation_error!(
                        "Backend address '{}' in upstream '{}' is invalid: {}",
                        backend.address,
                        upstream_name,
                        reason
                    );
                    return false;
                }
            };
            if endpoint.scheme() == BackendScheme::Http {
                warn!(
                    "Backend '{}' in upstream '{}' uses explicit insecure cleartext transport ({})",
                    backend.id, upstream_name, backend.address
                );
            } else {
                upstream_uses_https_backends = true;
            }

            let origin = endpoint.origin();
            if let Some((existing_upstream, existing_backend)) = seen_backend_origins
                .insert(origin.clone(), (upstream_name.clone(), backend.id.clone()))
            {
                validation_error!(
                    "Duplicate backend address '{}' detected: upstream '{}' backend '{}' conflicts with upstream '{}' backend '{}'",
                    origin,
                    upstream_name,
                    backend.id,
                    existing_upstream,
                    existing_backend
                );
                return false;
            }

            if backend.weight == 0 || backend.weight > 1000 {
                validation_error!(
                    "Backend '{}' in upstream '{}' has invalid weight {} (must be 1–1000)",
                    backend.id,
                    upstream_name,
                    backend.weight
                );
                return false;
            }

            if lb_strategy.rejects_custom_backend_weight() && backend.weight != 100 {
                validation_error!(
                    "Backend '{}' in upstream '{}' uses weight {} but load balancing type '{}' does not support custom backend weights; use the default weight 100",
                    backend.id,
                    upstream_name,
                    backend.weight,
                    lb_strategy.canonical_name()
                );
                return false;
            }

            if let Some(hc) = &backend.health_check {
                if hc.interval == 0 {
                    validation_error!(
                        "Health check interval is invalid (0) for backend '{}' in upstream '{}'",
                        backend.id,
                        upstream_name
                    );
                    return false;
                }
                if hc.timeout_ms == 0 {
                    validation_error!(
                        "Health check timeout is invalid (0) for backend '{}' in upstream '{}'",
                        backend.id,
                        upstream_name
                    );
                    return false;
                }
                if hc.failure_threshold == 0 {
                    validation_error!(
                        "Health check failure threshold is invalid (0) for backend '{}' in upstream '{}'",
                        backend.id,
                        upstream_name
                    );
                    return false;
                }
                if hc.success_threshold == 0 {
                    validation_error!(
                        "Health check success threshold is invalid (0) for backend '{}' in upstream '{}'",
                        backend.id,
                        upstream_name
                    );
                    return false;
                }
                if hc.cooldown_ms == 0 {
                    validation_error!(
                        "Health check cooldown is invalid (0) for backend '{}' in upstream '{}'",
                        backend.id,
                        upstream_name
                    );
                    return false;
                }
            }
        }

        if upstream_uses_https_backends {
            if let Some(tls) = upstream.tls.as_ref() {
                if !validate_upstream_tls(&format!("upstream['{}'].tls", upstream_name), tls) {
                    return false;
                }
            } else {
                validate_global_upstream_tls = true;
            }
        }
    }

    if validate_global_upstream_tls && !validate_upstream_tls("upstream_tls", &config.upstream_tls)
    {
        return false;
    }

    true
}
