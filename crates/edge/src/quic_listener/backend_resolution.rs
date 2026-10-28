use std::{
    net::SocketAddr,
    time::{Duration, SystemTime},
};

use impulse_config::runtime::{RuntimeBackendAddressKind, RuntimeBackendTlsPolicy};
use impulse_lb::pingora_backend::SharedPingoraLoadBalancingRuntimeState;
use log::{debug, error, info, warn};

use super::*;
use crate::metrics::{DiscoveryRefreshUpdate, PingoraDiscoveryRefreshOutcome};

const DNS_REFRESH_CONCURRENCY: usize = 8;

#[derive(Clone)]
struct PingoraDnsRefreshTarget {
    configured_address: String,
    authority_host: String,
    authority_port: u16,
}

impl QUICListener {
    pub(super) fn spawn_pingora_discovery_refresh(
        config: &RuntimeConfig,
        transport_pool: Arc<UpstreamTransportPool>,
        backend_dns_resolver: SharedDnsResolver,
        pingora_load_balancing: SharedPingoraLoadBalancingRuntimeState<RuntimeBackendTlsPolicy>,
        metrics: Arc<Metrics>,
        task_registry: Arc<RuntimeTaskRegistry>,
    ) {
        if !config.policies.transport.backend_dns.refresh_enabled {
            return;
        }

        let backends = config
            .upstreams
            .values()
            .flat_map(|upstream| upstream.backends.iter())
            .filter(|backend| backend.endpoint.address_kind == RuntimeBackendAddressKind::Hostname)
            .map(|backend| PingoraDnsRefreshTarget {
                configured_address: backend.endpoint.configured_address.clone(),
                authority_host: backend.endpoint.authority_host.clone(),
                authority_port: backend.endpoint.authority_port,
            })
            .collect::<Vec<_>>();
        if backends.is_empty() {
            debug!("backend DNS refresh disabled: no hostname-based backends configured");
            return;
        }

        let interval_ms: u64 = config
            .policies
            .transport
            .backend_dns
            .refresh_interval
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
            .max(1);
        let lookup_timeout = config.policies.timeouts.backend_connect;
        let handle = match runtime_handle() {
            Some(handle) => handle,
            None => {
                error!("Backend DNS refresh disabled: no Tokio runtime available");
                return;
            }
        };

        let task_metrics = Arc::clone(&metrics);
        let registration = spawn_supervised_async_task(
            &handle,
            "pingora-service-discovery",
            Some(metrics),
            async move {
                let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                loop {
                    ticker.tick().await;
                    refresh_pingora_backends(
                        &backends,
                        lookup_timeout,
                        Arc::clone(&transport_pool),
                        backend_dns_resolver.clone(),
                        Arc::clone(&pingora_load_balancing),
                        Arc::clone(&task_metrics),
                    )
                    .await;
                }
            },
        );
        task_registry.register(registration);
    }
}

async fn refresh_pingora_backends(
    backends: &[PingoraDnsRefreshTarget],
    lookup_timeout: Duration,
    transport_pool: Arc<UpstreamTransportPool>,
    backend_dns_resolver: SharedDnsResolver,
    pingora_load_balancing: SharedPingoraLoadBalancingRuntimeState<RuntimeBackendTlsPolicy>,
    metrics: Arc<Metrics>,
) {
    let mut backends = backends.iter().cloned();
    let mut refreshes = tokio::task::JoinSet::new();

    loop {
        while refreshes.len() < DNS_REFRESH_CONCURRENCY {
            let Some(backend) = backends.next() else {
                break;
            };
            let transport_pool = Arc::clone(&transport_pool);
            let backend_dns_resolver = backend_dns_resolver.clone();
            let pingora_load_balancing = Arc::clone(&pingora_load_balancing);
            let metrics = Arc::clone(&metrics);
            refreshes.spawn(async move {
                refresh_pingora_backend(
                    &backend,
                    lookup_timeout,
                    transport_pool.as_ref(),
                    &backend_dns_resolver,
                    &pingora_load_balancing,
                    metrics.as_ref(),
                )
                .await;
            });
        }

        let Some(result) = refreshes.join_next().await else {
            break;
        };
        if let Err(error) = result {
            error!("Pingora DNS refresh worker failed: {error}");
        }
    }
}

async fn refresh_pingora_backend(
    backend: &PingoraDnsRefreshTarget,
    lookup_timeout: Duration,
    transport_pool: &UpstreamTransportPool,
    backend_dns_resolver: &SharedDnsResolver,
    pingora_load_balancing: &SharedPingoraLoadBalancingRuntimeState<RuntimeBackendTlsPolicy>,
    metrics: &Metrics,
) {
    let lookup = tokio::time::timeout(
        lookup_timeout,
        tokio::net::lookup_host((backend.authority_host.as_str(), 0)),
    )
    .await;
    let mut resolved_addrs = match lookup {
        Ok(Ok(addrs)) => addrs
            .map(|addr| SocketAddr::new(addr.ip(), backend.authority_port))
            .collect::<Vec<_>>(),
        Ok(Err(error)) => {
            record_pingora_discovery_failure(
                backend,
                error.to_string(),
                pingora_load_balancing,
                metrics,
            )
            .await;
            return;
        }
        Err(_) => {
            record_pingora_discovery_failure(
                backend,
                format!(
                    "DNS resolution timed out after {} ms",
                    lookup_timeout.as_millis()
                ),
                pingora_load_balancing,
                metrics,
            )
            .await;
            return;
        }
    };
    resolved_addrs.sort_unstable();
    resolved_addrs.dedup();
    if resolved_addrs.is_empty() {
        record_pingora_discovery_failure(
            backend,
            "DNS resolution returned no addresses".to_string(),
            pingora_load_balancing,
            metrics,
        )
        .await;
        return;
    }

    let publication = pingora_load_balancing
        .publish_dns_result(&backend.configured_address, Ok(resolved_addrs.clone()))
        .await;
    match publication {
        Ok(update) => {
            let changed = update.membership_changed();
            backend_dns_resolver.set_host_addrs(
                &backend.authority_host,
                resolved_addrs
                    .iter()
                    .map(|address| SocketAddr::new(address.ip(), 0)),
            );
            metrics
                .runtime_observations()
                .record_backend_dns_refresh_success(
                    &backend.configured_address,
                    SystemTime::now(),
                    resolved_addrs.len(),
                    changed,
                );
            if changed {
                metrics
                    .runtime_observations()
                    .record_pingora_lb_selector_rebuild(pingora_load_balancing.generation(), 1);
                match transport_pool.rotate_backend_client(&backend.configured_address) {
                    Ok(rotation) if rotation.rotated() => {
                        metrics
                            .runtime_observations()
                            .inc_backend_client_rotation(&backend.configured_address);
                    }
                    Ok(_) => {}
                    Err(error) => {
                        metrics
                            .runtime_observations()
                            .inc_backend_client_rotation_failure();
                        warn!(
                            "backend client rotation failed for '{}' (backend '{}') after DNS refresh: {}",
                            backend.authority_host, backend.configured_address, error
                        );
                    }
                }
                info!(
                    "Pingora discovery updated '{}' (backend '{}') to {:?} generation={}",
                    backend.authority_host,
                    backend.configured_address,
                    resolved_addrs,
                    update.membership_generation()
                );
            } else {
                debug!(
                    "Pingora discovery unchanged for '{}' (backend '{}') addrs={:?} generation={}",
                    backend.authority_host,
                    backend.configured_address,
                    resolved_addrs,
                    update.membership_generation()
                );
            }
            let refresh_outcome = if changed {
                PingoraDiscoveryRefreshOutcome::Updated
            } else {
                PingoraDiscoveryRefreshOutcome::Unchanged
            };
            metrics
                .runtime_observations()
                .record_pingora_discovery_refresh(
                    refresh_outcome,
                    Some(DiscoveryRefreshUpdate {
                        upstream_name: update.upstream_name(),
                        membership_generation: update.membership_generation(),
                        membership_changed: update.membership_changed(),
                        rebuild_duration: update.rebuild_duration(),
                    }),
                );
        }
        Err(error) => {
            metrics
                .runtime_observations()
                .inc_backend_dns_refresh_failure();
            metrics
                .runtime_observations()
                .inc_pingora_lb_selector_failure();
            metrics
                .runtime_observations()
                .record_pingora_discovery_refresh(
                    PingoraDiscoveryRefreshOutcome::PublishFailed,
                    None,
                );
            error!(
                "failed to publish Pingora DNS membership for backend '{}': {}",
                backend.configured_address, error
            );
        }
    }
}

async fn record_pingora_discovery_failure(
    backend: &PingoraDnsRefreshTarget,
    error: String,
    pingora_load_balancing: &SharedPingoraLoadBalancingRuntimeState<RuntimeBackendTlsPolicy>,
    metrics: &Metrics,
) {
    metrics
        .runtime_observations()
        .inc_backend_dns_refresh_failure();
    let _ = pingora_load_balancing
        .publish_dns_result(&backend.configured_address, Err(error.clone()))
        .await;
    metrics
        .runtime_observations()
        .record_pingora_discovery_refresh(PingoraDiscoveryRefreshOutcome::RetainedFailure, None);
    warn!(
        "Pingora discovery refresh failed for '{}' (backend '{}'): {}; retaining last-known-good membership",
        backend.authority_host, backend.configured_address, error
    );
}
