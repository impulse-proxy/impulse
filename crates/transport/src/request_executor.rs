use std::sync::Arc;

use impulse_errors::ProxyError;

use crate::{
    exchange::{UpstreamExchangeRequest, UpstreamExchangeResponse},
    transport_pool::UpstreamTransportPool,
};

/// Request-scoped transport boundary used by ingress implementations.
#[derive(Clone)]
pub struct UpstreamRequestExecutor {
    transport_pool: Arc<UpstreamTransportPool>,
}

impl UpstreamRequestExecutor {
    #[must_use]
    pub fn new(transport_pool: Arc<UpstreamTransportPool>) -> Self {
        Self { transport_pool }
    }

    pub async fn execute(
        &self,
        backend: &str,
        request: UpstreamExchangeRequest,
    ) -> Result<UpstreamExchangeResponse, ProxyError> {
        self.transport_pool.send_exchange(backend, request).await
    }
}
