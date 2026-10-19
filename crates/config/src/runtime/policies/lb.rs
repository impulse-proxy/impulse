use super::{config_invalid, normalize_optional_string};
use crate::{config::LoadBalancing, runtime::RuntimeConfigError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeLoadBalancingStrategy {
    RoundRobin,
    ConsistentHash,
    Random,
    LeastConnections,
    LatencyAware,
    StickyCid,
    Other,
}

impl RuntimeLoadBalancingStrategy {
    pub fn from_lb_type(lb_type: &str) -> Self {
        match lb_type.trim().to_ascii_lowercase().as_str() {
            "round-robin" | "round_robin" | "rr" => Self::RoundRobin,
            "consistent-hash" | "consistent_hash" | "ch" => Self::ConsistentHash,
            "random" => Self::Random,
            "least-connections" | "least_connections" | "lc" => Self::LeastConnections,
            "latency-aware" | "latency_aware" | "la" => Self::LatencyAware,
            "sticky-cid" | "sticky_cid" | "cid-sticky" | "cid_sticky" => Self::StickyCid,
            _ => Self::Other,
        }
    }

    pub fn canonical_name(self) -> &'static str {
        match self {
            Self::RoundRobin => "round-robin",
            Self::ConsistentHash => "consistent-hash",
            Self::Random => "random",
            Self::LeastConnections => "least-connections",
            Self::LatencyAware => "latency-aware",
            Self::StickyCid => "sticky-cid",
            Self::Other => "unsupported",
        }
    }

    pub fn supports_readonly_alternate_pick(self) -> bool {
        !matches!(self, Self::ConsistentHash | Self::StickyCid | Self::Other)
    }

    pub fn rejects_custom_backend_weight(self) -> bool {
        matches!(self, Self::LeastConnections | Self::LatencyAware)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RuntimeRequestKeySpec {
    Path,
    Authority,
    Method,
    Cid,
    StickyCid,
    PeerIp,
    ClientIp,
    BearerToken,
    Header(String),
    Cookie(String),
    Query(String),
}

impl RuntimeRequestKeySpec {
    pub(crate) fn normalize(raw: &str) -> Result<Self, RuntimeConfigError> {
        let normalized = raw.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "path" => Ok(Self::Path),
            "authority" => Ok(Self::Authority),
            "method" => Ok(Self::Method),
            "cid" => Ok(Self::Cid),
            "sticky-cid" => Ok(Self::StickyCid),
            "peer_ip" => Ok(Self::PeerIp),
            "client_ip" => Ok(Self::ClientIp),
            "bearer_token" => Ok(Self::BearerToken),
            _ => {
                let Some((source, key_name)) = normalized.split_once(':') else {
                    return Err(config_invalid(format!(
                        "unsupported request key spec '{}'",
                        raw
                    )));
                };
                if key_name.trim().is_empty() {
                    return Err(config_invalid(format!(
                        "unsupported request key spec '{}'",
                        raw
                    )));
                }
                match source {
                    "header" => Ok(Self::Header(key_name.to_string())),
                    "cookie" => Ok(Self::Cookie(key_name.to_string())),
                    "query" => Ok(Self::Query(key_name.to_string())),
                    _ => Err(config_invalid(format!(
                        "unsupported request key spec '{}'",
                        raw
                    ))),
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeAlternateBackendPolicy {
    pub readonly_lb_pick: bool,
    pub healthy_fallback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeLoadBalancingPolicy {
    pub strategy: RuntimeLoadBalancingStrategy,
    pub key: Option<String>,
    pub key_spec: Option<RuntimeRequestKeySpec>,
    pub alternate_backend: RuntimeAlternateBackendPolicy,
}

impl RuntimeLoadBalancingPolicy {
    pub(crate) fn normalize(load_balancing: &LoadBalancing) -> Result<Self, RuntimeConfigError> {
        let strategy = RuntimeLoadBalancingStrategy::from_lb_type(&load_balancing.lb_type);
        if matches!(strategy, RuntimeLoadBalancingStrategy::Other) {
            return Err(config_invalid(format!(
                "unsupported load balancing type '{}'",
                load_balancing.lb_type
            )));
        }

        Ok(Self {
            strategy,
            key: normalize_optional_string(load_balancing.key.as_deref()),
            key_spec: load_balancing
                .key
                .as_deref()
                .map(RuntimeRequestKeySpec::normalize)
                .transpose()?,
            alternate_backend: RuntimeAlternateBackendPolicy {
                readonly_lb_pick: strategy.supports_readonly_alternate_pick(),
                healthy_fallback: true,
            },
        })
    }

    #[cfg(test)]
    pub(crate) fn as_config(&self) -> LoadBalancing {
        LoadBalancing {
            lb_type: self.strategy.canonical_name().to_string(),
            key: self.key.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_config_invalid(err: RuntimeConfigError, expected: impl AsRef<str>) {
        let expected = expected.as_ref();
        assert_eq!(err.category(), "config_invalid");
        assert_eq!(err.to_string(), format!("config_invalid: {expected}"));
    }

    #[test]
    fn load_balancing_strategy_normalizes_supported_aliases_and_canonical_names() {
        let cases = [
            ("round-robin", RuntimeLoadBalancingStrategy::RoundRobin),
            ("round_robin", RuntimeLoadBalancingStrategy::RoundRobin),
            ("rr", RuntimeLoadBalancingStrategy::RoundRobin),
            (
                "consistent-hash",
                RuntimeLoadBalancingStrategy::ConsistentHash,
            ),
            (
                "consistent_hash",
                RuntimeLoadBalancingStrategy::ConsistentHash,
            ),
            ("ch", RuntimeLoadBalancingStrategy::ConsistentHash),
            ("random", RuntimeLoadBalancingStrategy::Random),
            (
                "least-connections",
                RuntimeLoadBalancingStrategy::LeastConnections,
            ),
            (
                "least_connections",
                RuntimeLoadBalancingStrategy::LeastConnections,
            ),
            ("lc", RuntimeLoadBalancingStrategy::LeastConnections),
            ("latency-aware", RuntimeLoadBalancingStrategy::LatencyAware),
            ("latency_aware", RuntimeLoadBalancingStrategy::LatencyAware),
            ("la", RuntimeLoadBalancingStrategy::LatencyAware),
            ("sticky-cid", RuntimeLoadBalancingStrategy::StickyCid),
            ("sticky_cid", RuntimeLoadBalancingStrategy::StickyCid),
            ("cid-sticky", RuntimeLoadBalancingStrategy::StickyCid),
            ("cid_sticky", RuntimeLoadBalancingStrategy::StickyCid),
        ];

        for (raw, expected) in cases {
            assert_eq!(RuntimeLoadBalancingStrategy::from_lb_type(raw), expected);
        }

        assert_eq!(
            RuntimeLoadBalancingStrategy::RoundRobin.canonical_name(),
            "round-robin"
        );
        assert_eq!(
            RuntimeLoadBalancingStrategy::ConsistentHash.canonical_name(),
            "consistent-hash"
        );
        assert_eq!(
            RuntimeLoadBalancingStrategy::LeastConnections.canonical_name(),
            "least-connections"
        );
        assert_eq!(
            RuntimeLoadBalancingStrategy::LatencyAware.canonical_name(),
            "latency-aware"
        );
        assert_eq!(
            RuntimeLoadBalancingStrategy::StickyCid.canonical_name(),
            "sticky-cid"
        );
    }

    #[test]
    fn load_balancing_policy_rejects_unsupported_strategy() {
        let err = RuntimeLoadBalancingPolicy::normalize(&LoadBalancing {
            lb_type: "maglev".to_string(),
            key: None,
        })
        .expect_err("unsupported strategy must fail");

        assert_config_invalid(err, "unsupported load balancing type 'maglev'");
    }

    #[test]
    fn request_key_spec_normalizes_builtin_key_types() {
        let cases = [
            ("path", RuntimeRequestKeySpec::Path),
            ("authority", RuntimeRequestKeySpec::Authority),
            ("method", RuntimeRequestKeySpec::Method),
            ("cid", RuntimeRequestKeySpec::Cid),
            ("sticky-cid", RuntimeRequestKeySpec::StickyCid),
            ("peer_ip", RuntimeRequestKeySpec::PeerIp),
            ("client_ip", RuntimeRequestKeySpec::ClientIp),
            ("bearer_token", RuntimeRequestKeySpec::BearerToken),
        ];

        for (raw, expected) in cases {
            assert_eq!(RuntimeRequestKeySpec::normalize(raw).expect(raw), expected);
        }
    }

    #[test]
    fn request_key_spec_normalizes_header_cookie_and_query_forms() {
        assert_eq!(
            RuntimeRequestKeySpec::normalize(" header:X-Tenant-ID ").expect("header key"),
            RuntimeRequestKeySpec::Header("x-tenant-id".to_string())
        );
        assert_eq!(
            RuntimeRequestKeySpec::normalize("cookie:Session_Id").expect("cookie key"),
            RuntimeRequestKeySpec::Cookie("session_id".to_string())
        );
        assert_eq!(
            RuntimeRequestKeySpec::normalize("query:user_id").expect("query key"),
            RuntimeRequestKeySpec::Query("user_id".to_string())
        );
    }

    #[test]
    fn request_key_spec_rejects_invalid_forms() {
        let cases = [
            "tenant_id",
            "header:",
            "cookie:   ",
            "query:",
            "body:user",
            "header",
        ];

        for raw in cases {
            let err =
                RuntimeRequestKeySpec::normalize(raw).expect_err("invalid key spec must fail");
            assert_config_invalid(err, format!("unsupported request key spec '{}'", raw));
        }
    }

    #[test]
    fn load_balancing_policy_shapes_key_spec_and_alternate_backend_policy() {
        let round_robin = RuntimeLoadBalancingPolicy::normalize(&LoadBalancing {
            lb_type: "rr".to_string(),
            key: Some(" header:x-user-id ".to_string()),
        })
        .expect("round robin policy");

        assert_eq!(
            round_robin.strategy,
            RuntimeLoadBalancingStrategy::RoundRobin
        );
        assert_eq!(round_robin.key.as_deref(), Some("header:x-user-id"));
        assert_eq!(
            round_robin.key_spec,
            Some(RuntimeRequestKeySpec::Header("x-user-id".to_string()))
        );
        assert_eq!(
            round_robin.alternate_backend,
            RuntimeAlternateBackendPolicy {
                readonly_lb_pick: true,
                healthy_fallback: true,
            }
        );

        let consistent_hash = RuntimeLoadBalancingPolicy::normalize(&LoadBalancing {
            lb_type: "consistent_hash".to_string(),
            key: Some("sticky-cid".to_string()),
        })
        .expect("consistent hash policy");

        assert_eq!(
            consistent_hash.strategy,
            RuntimeLoadBalancingStrategy::ConsistentHash
        );
        assert_eq!(
            consistent_hash.key_spec,
            Some(RuntimeRequestKeySpec::StickyCid)
        );
        assert_eq!(
            consistent_hash.alternate_backend,
            RuntimeAlternateBackendPolicy {
                readonly_lb_pick: false,
                healthy_fallback: true,
            }
        );

        let sticky_cid = RuntimeLoadBalancingPolicy::normalize(&LoadBalancing {
            lb_type: "sticky-cid".to_string(),
            key: None,
        })
        .expect("sticky cid policy");

        assert_eq!(sticky_cid.strategy, RuntimeLoadBalancingStrategy::StickyCid);
        assert_eq!(sticky_cid.key_spec, None);
        assert_eq!(
            sticky_cid.alternate_backend,
            RuntimeAlternateBackendPolicy {
                readonly_lb_pick: false,
                healthy_fallback: true,
            }
        );
    }
}
