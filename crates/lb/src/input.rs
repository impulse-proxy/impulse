use std::time::Duration;

/// Validated backend data required by load-balancing implementations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendInput {
    backend_id: String,
    configured_address: String,
    index: usize,
    weight: BackendWeight,
    health: Option<BackendHealthInput>,
}

impl BackendInput {
    #[must_use]
    pub fn new(
        backend_id: impl Into<String>,
        configured_address: impl Into<String>,
        index: usize,
        weight: BackendWeight,
        health: Option<BackendHealthInput>,
    ) -> Self {
        Self {
            backend_id: backend_id.into(),
            configured_address: configured_address.into(),
            index,
            weight,
            health,
        }
    }

    #[must_use]
    pub fn backend_id(&self) -> &str {
        &self.backend_id
    }

    #[must_use]
    pub fn configured_address(&self) -> &str {
        &self.configured_address
    }

    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    #[must_use]
    pub const fn weight(&self) -> BackendWeight {
        self.weight
    }

    #[must_use]
    pub const fn health(&self) -> Option<&BackendHealthInput> {
        self.health.as_ref()
    }
}

/// Health-state parameters required by load-balancing implementations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendHealthInput {
    failure_threshold: u32,
    success_threshold: u32,
    cooldown: Duration,
    active_checks: bool,
}

impl BackendHealthInput {
    #[must_use]
    pub const fn new(
        failure_threshold: u32,
        success_threshold: u32,
        cooldown: Duration,
        active_checks: bool,
    ) -> Self {
        Self {
            failure_threshold,
            success_threshold,
            cooldown,
            active_checks,
        }
    }

    #[must_use]
    pub const fn failure_threshold(self) -> u32 {
        self.failure_threshold
    }

    #[must_use]
    pub const fn success_threshold(self) -> u32 {
        self.success_threshold
    }

    #[must_use]
    pub const fn cooldown(self) -> Duration {
        self.cooldown
    }

    #[must_use]
    pub const fn active_checks(self) -> bool {
        self.active_checks
    }
}

/// Validated backend weight used by weighted selectors.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BackendWeight(u32);

impl BackendWeight {
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Load-balancing strategies supported by the runtime.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LoadBalancingStrategy {
    RoundRobin,
    ConsistentHash,
    Random,
    LeastConnections,
    LatencyAware,
    StickyCid,
}

impl LoadBalancingStrategy {
    #[must_use]
    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::RoundRobin => "round-robin",
            Self::ConsistentHash => "consistent-hash",
            Self::Random => "random",
            Self::LeastConnections => "least-connections",
            Self::LatencyAware => "latency-aware",
            Self::StickyCid => "sticky-cid",
        }
    }

    #[must_use]
    pub const fn supports_readonly_alternate_pick(self) -> bool {
        !matches!(self, Self::ConsistentHash | Self::StickyCid)
    }
}

/// Validated source used to derive a keyed load-balancing value.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum RequestKeyInput {
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
