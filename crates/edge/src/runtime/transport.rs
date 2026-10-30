use std::sync::Arc;

use impulse_errors::ProxyError;
use impulse_transport::{SharedDnsResolver, UpstreamTransportInput, UpstreamTransportPool};

pub(crate) fn create_transport_pool(
    inputs: impl IntoIterator<Item = UpstreamTransportInput>,
    dns_resolver: SharedDnsResolver,
) -> Result<Arc<UpstreamTransportPool>, ProxyError> {
    UpstreamTransportPool::new(inputs, dns_resolver)
        .map(Arc::new)
        .map_err(ProxyError::Tls)
}

pub(crate) fn activate_transport_pool_generation(
    transport_pool: &UpstreamTransportPool,
    generation: u64,
) {
    transport_pool.rotate_pingora_pool(generation);
}

pub(crate) fn drain_transport_pool_generation(transport_pool: &UpstreamTransportPool) {
    transport_pool.drain_pingora_pool();
}
