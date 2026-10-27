use std::{net::SocketAddr, time::SystemTime};

pub use impulse_contracts::BackendIdentity;
use impulse_lb::health::HealthFailureReason;

use super::resolution::{RuntimeBackendAddressKind, RuntimeBackendResolution};

impl From<&RuntimeBackendResolution> for BackendIdentity {
    fn from(value: &RuntimeBackendResolution) -> Self {
        Self::new(value.backend_addr.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendResolutionState {
    pub authority_host: String,
    pub authority_port: u16,
    pub address_kind: RuntimeBackendAddressKind,
    pub resolved_addrs: Vec<SocketAddr>,
    pub last_refresh_success_at: Option<SystemTime>,
    pub refresh_generation: u64,
}

impl BackendResolutionState {
    pub fn is_hostname(&self) -> bool {
        self.address_kind == RuntimeBackendAddressKind::Hostname
    }
}

impl From<&RuntimeBackendResolution> for BackendResolutionState {
    fn from(value: &RuntimeBackendResolution) -> Self {
        Self {
            authority_host: value.authority_host.clone(),
            authority_port: value.authority_port,
            address_kind: value.address_kind,
            resolved_addrs: value.resolved_addrs.clone(),
            last_refresh_success_at: value.last_refresh_success_at,
            refresh_generation: value.refresh_generation,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendHealthState {
    Unknown,
    Healthy,
    Unhealthy { reason: Option<HealthFailureReason> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendMembershipState {
    Active,
    Suppressed,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendLifecycleSnapshot {
    pub identity: BackendIdentity,
    pub resolution: BackendResolutionState,
    pub health: BackendHealthState,
    pub membership: BackendMembershipState,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BackendPoolPlacementSnapshot {
    pub upstream_name: String,
    pub backend_index: usize,
    pub healthy: bool,
    pub active_requests: usize,
    pub ewma_latency_ms: Option<f64>,
    pub membership_epoch: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CanonicalBackendLifecycleSnapshot {
    pub identity: BackendIdentity,
    pub resolution: BackendResolutionState,
    pub health: BackendHealthState,
    pub membership: BackendMembershipState,
    pub placements: Vec<BackendPoolPlacementSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendLifecycleInventorySummary {
    pub healthy_backends: usize,
    pub total_backends: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BackendLifecycleInventorySnapshot {
    pub backends: Vec<CanonicalBackendLifecycleSnapshot>,
}

impl BackendLifecycleInventorySnapshot {
    pub fn summary(&self) -> BackendLifecycleInventorySummary {
        let total_backends = self
            .backends
            .iter()
            .filter(|backend| !backend.placements.is_empty())
            .count();
        let healthy_backends = self
            .backends
            .iter()
            .filter(|backend| {
                !backend.placements.is_empty()
                    && matches!(backend.health, BackendHealthState::Healthy)
            })
            .count();

        BackendLifecycleInventorySummary {
            healthy_backends,
            total_backends,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    #[test]
    fn backend_resolution_state_preserves_runtime_resolution_fields() {
        let resolution = RuntimeBackendResolution::hostname(
            "https://backend.internal:8443".to_string(),
            "backend.internal".to_string(),
            8443,
        );

        let state = BackendResolutionState::from(&resolution);

        assert_eq!(state.authority_host, "backend.internal");
        assert_eq!(state.authority_port, 8443);
        assert!(state.is_hostname());
        assert_eq!(state.refresh_generation, 0);
    }

    #[test]
    fn backend_resolution_state_preserves_ip_literal_addresses() {
        let addrs = vec![
            "10.0.0.10:9443".parse::<SocketAddr>().expect("addr"),
            "10.0.0.11:9443".parse::<SocketAddr>().expect("addr"),
        ];
        let resolution = RuntimeBackendResolution::ip_literal(
            "10.0.0.10:9443".to_string(),
            "10.0.0.10".to_string(),
            9443,
            addrs.clone(),
        );

        let state = BackendResolutionState::from(&resolution);

        assert_eq!(state.resolved_addrs, addrs);
        assert!(!state.is_hostname());
    }

    #[test]
    fn inventory_summary_counts_only_placed_and_healthy_backends() {
        let snapshot = BackendLifecycleInventorySnapshot {
            backends: vec![
                CanonicalBackendLifecycleSnapshot {
                    identity: BackendIdentity::new("backend-a"),
                    resolution: BackendResolutionState {
                        authority_host: "backend-a".into(),
                        authority_port: 443,
                        address_kind: RuntimeBackendAddressKind::IpLiteral,
                        resolved_addrs: vec![],
                        last_refresh_success_at: None,
                        refresh_generation: 0,
                    },
                    health: BackendHealthState::Healthy,
                    membership: BackendMembershipState::Active,
                    placements: vec![BackendPoolPlacementSnapshot {
                        upstream_name: "api".into(),
                        backend_index: 0,
                        healthy: true,
                        active_requests: 0,
                        ewma_latency_ms: None,
                        membership_epoch: 1,
                    }],
                },
                CanonicalBackendLifecycleSnapshot {
                    identity: BackendIdentity::new("backend-b"),
                    resolution: BackendResolutionState {
                        authority_host: "backend-b".into(),
                        authority_port: 443,
                        address_kind: RuntimeBackendAddressKind::IpLiteral,
                        resolved_addrs: vec![],
                        last_refresh_success_at: None,
                        refresh_generation: 0,
                    },
                    health: BackendHealthState::Unhealthy { reason: None },
                    membership: BackendMembershipState::Suppressed,
                    placements: vec![BackendPoolPlacementSnapshot {
                        upstream_name: "api".into(),
                        backend_index: 1,
                        healthy: false,
                        active_requests: 2,
                        ewma_latency_ms: Some(25.0),
                        membership_epoch: 1,
                    }],
                },
                CanonicalBackendLifecycleSnapshot {
                    identity: BackendIdentity::new("backend-c"),
                    resolution: BackendResolutionState {
                        authority_host: "backend-c".into(),
                        authority_port: 443,
                        address_kind: RuntimeBackendAddressKind::IpLiteral,
                        resolved_addrs: vec![],
                        last_refresh_success_at: None,
                        refresh_generation: 0,
                    },
                    health: BackendHealthState::Healthy,
                    membership: BackendMembershipState::Removed,
                    placements: Vec::new(),
                },
            ],
        };

        let summary = snapshot.summary();

        assert_eq!(summary.total_backends, 2);
        assert_eq!(summary.healthy_backends, 1);
    }
}
