use impulse_config::runtime::{
    RuntimeBackend, RuntimeLoadBalancingStrategy, RuntimeRequestKeySpec, RuntimeUpstream,
};
use impulse_lb::{
    BackendHealthInput, BackendInput, BackendWeight, LoadBalancingStrategy, RequestKeyInput,
    upstream_pool::UpstreamPool,
};

pub(crate) fn strategy_input(
    strategy: RuntimeLoadBalancingStrategy,
) -> Result<LoadBalancingStrategy, String> {
    match strategy {
        RuntimeLoadBalancingStrategy::RoundRobin => Ok(LoadBalancingStrategy::RoundRobin),
        RuntimeLoadBalancingStrategy::ConsistentHash => Ok(LoadBalancingStrategy::ConsistentHash),
        RuntimeLoadBalancingStrategy::Random => Ok(LoadBalancingStrategy::Random),
        RuntimeLoadBalancingStrategy::LeastConnections => {
            Ok(LoadBalancingStrategy::LeastConnections)
        }
        RuntimeLoadBalancingStrategy::LatencyAware => Ok(LoadBalancingStrategy::LatencyAware),
        RuntimeLoadBalancingStrategy::StickyCid => Ok(LoadBalancingStrategy::StickyCid),
        RuntimeLoadBalancingStrategy::Other => {
            Err("unsupported load balancing strategy".to_string())
        }
    }
}

fn request_key_input(input: &RuntimeRequestKeySpec) -> RequestKeyInput {
    match input {
        RuntimeRequestKeySpec::Path => RequestKeyInput::Path,
        RuntimeRequestKeySpec::Authority => RequestKeyInput::Authority,
        RuntimeRequestKeySpec::Method => RequestKeyInput::Method,
        RuntimeRequestKeySpec::Cid => RequestKeyInput::Cid,
        RuntimeRequestKeySpec::StickyCid => RequestKeyInput::StickyCid,
        RuntimeRequestKeySpec::PeerIp => RequestKeyInput::PeerIp,
        RuntimeRequestKeySpec::ClientIp => RequestKeyInput::ClientIp,
        RuntimeRequestKeySpec::BearerToken => RequestKeyInput::BearerToken,
        RuntimeRequestKeySpec::Header(name) => RequestKeyInput::Header(name.clone()),
        RuntimeRequestKeySpec::Cookie(name) => RequestKeyInput::Cookie(name.clone()),
        RuntimeRequestKeySpec::Query(name) => RequestKeyInput::Query(name.clone()),
    }
}

fn backend_input(index: usize, backend: &RuntimeBackend) -> BackendInput {
    BackendInput::new(
        backend.backend.id.clone(),
        backend.backend.address.clone(),
        index,
        BackendWeight::new(backend.backend.weight),
        backend.health_check.as_ref().map(|health| {
            BackendHealthInput::new(
                health.failure_threshold,
                health.success_threshold,
                health.cooldown,
                true,
            )
        }),
    )
}

pub(crate) fn backend_inputs(upstream: &RuntimeUpstream) -> Vec<BackendInput> {
    upstream
        .backends
        .iter()
        .enumerate()
        .map(|(index, backend)| backend_input(index, backend))
        .collect()
}

pub(crate) fn upstream_pool(upstream: &RuntimeUpstream) -> Result<UpstreamPool, String> {
    Ok(UpstreamPool::new(
        backend_inputs(upstream),
        strategy_input(upstream.load_balancing.strategy)?,
        upstream
            .load_balancing
            .key_spec
            .as_ref()
            .map(request_key_input),
    ))
}
