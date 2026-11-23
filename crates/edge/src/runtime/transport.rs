use std::sync::Arc;

use impulse_errors::ProxyError;
use impulse_observability::Metrics;
use impulse_transport::{SharedDnsResolver, UpstreamTransportInput, UpstreamTransportPool};

pub(crate) fn create_transport_pool(
    inputs: impl IntoIterator<Item = UpstreamTransportInput>,
    dns_resolver: SharedDnsResolver,
    generation: u64,
    metrics: Arc<Metrics>,
) -> Result<Arc<UpstreamTransportPool>, ProxyError> {
    UpstreamTransportPool::new(inputs, dns_resolver, generation, metrics)
        .map(Arc::new)
        .map_err(ProxyError::Tls)
}
