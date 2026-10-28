/// Validated backend data required by load-balancing implementations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendInput {
    backend_id: String,
    configured_address: String,
    index: usize,
    weight: BackendWeight,
}

impl BackendInput {
    #[must_use]
    pub fn new(
        backend_id: impl Into<String>,
        configured_address: impl Into<String>,
        index: usize,
        weight: BackendWeight,
    ) -> Self {
        Self {
            backend_id: backend_id.into(),
            configured_address: configured_address.into(),
            index,
            weight,
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

/// Opaque request key supplied to keyed load-balancing strategies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestKeyInput<'a> {
    bytes: &'a [u8],
}

impl<'a> RequestKeyInput<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
}
