use std::{net::SocketAddr, time::Duration};

use impulse_config::runtime::RuntimeBackendTlsPolicy;
use impulse_lb::pingora_backend::SharedPingoraLoadBalancingRuntimeState;
use log::{debug, error};

use super::*;
use crate::{
    metrics::PingoraDiscoveryRefreshOutcome,
    runtime::backend::lifecycle::{
        BackendDnsRefreshApplication, BackendLifecycleCoordinator, RuntimeBackendLifecycleState,
        log_backend_dns_refresh, observe_backend_dns_refresh,
    },
};

impl QUICListener {
    pub(super) fn spawn_backend_dns_refresh(
        config: &RuntimeConfig,
        transport_pool: Arc<UpstreamTransportPool>,
        backend_lifecycle: Arc<BackendLifecycleCoordinator>,
        backend_dns_resolver: SharedDnsResolver,
        pingora_load_balancing: SharedPingoraLoadBalancingRuntimeState<RuntimeBackendTlsPolicy>,
        metrics: Arc<Metrics>,
        task_registry: Arc<RuntimeTaskRegistry>,
    ) {
        if !config.policies.transport.backend_dns.refresh_enabled {
            return;
        }

        if backend_lifecycle.hostname_backends().is_empty() {
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
            "backend-dns-refresh",
            Some(metrics),
            async move {
                let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                loop {
                    ticker.tick().await;
                    for backend in backend_lifecycle.hostname_backends() {
                        let outcome = refresh_backend_hostname(
                            &backend,
                            &transport_pool,
                            &backend_lifecycle,
                            &backend_dns_resolver,
                            &pingora_load_balancing,
                            task_metrics.as_ref(),
                        )
                        .await;
                        observe_backend_dns_refresh(task_metrics.as_ref(), &outcome);
                        log_backend_dns_refresh(&outcome);
                    }
                }
            },
        );
        task_registry.register(registration);
    }
}

async fn refresh_backend_hostname(
    backend: &RuntimeBackendLifecycleState,
    transport_pool: &UpstreamTransportPool,
    backend_lifecycle: &BackendLifecycleCoordinator,
    backend_dns_resolver: &SharedDnsResolver,
    pingora_load_balancing: &SharedPingoraLoadBalancingRuntimeState<RuntimeBackendTlsPolicy>,
    metrics: &Metrics,
) -> BackendDnsRefreshApplication {
    let resolved_addrs =
        match tokio::net::lookup_host((backend.resolution.authority_host.as_str(), 0)).await {
            Ok(addrs) => Ok(addrs
                .map(|addr| SocketAddr::new(addr.ip(), backend.resolution.authority_port))
                .collect::<Vec<_>>()),
            Err(err) => Err(err.to_string()),
        };

    let outcome = backend_lifecycle.apply_refresh(
        backend,
        resolved_addrs,
        backend_dns_resolver,
        transport_pool,
    );
    let discovery_result = match &outcome {
        BackendDnsRefreshApplication::Updated { current_addrs, .. }
        | BackendDnsRefreshApplication::Unchanged { current_addrs, .. } => {
            Ok(current_addrs.clone())
        }
        BackendDnsRefreshApplication::EmptyAnswerRetained { .. } => {
            Err("DNS resolution returned no addresses".to_string())
        }
        BackendDnsRefreshApplication::LookupFailed { error, .. } => Err(error.clone()),
    };
    let resolution_succeeded = discovery_result.is_ok();
    let publication = pingora_load_balancing
        .publish_dns_result(&backend.identity.backend_addr, discovery_result)
        .await;
    match publication {
        Ok(update) => {
            let refresh_outcome = if update.membership_changed() {
                metrics.record_pingora_lb_selector_rebuild(pingora_load_balancing.generation(), 1);
                PingoraDiscoveryRefreshOutcome::Updated
            } else {
                PingoraDiscoveryRefreshOutcome::Unchanged
            };
            metrics.record_pingora_discovery_refresh(refresh_outcome, Some(&update));
        }
        Err(error) if resolution_succeeded => {
            metrics.inc_pingora_lb_selector_failure();
            metrics.record_pingora_discovery_refresh(
                PingoraDiscoveryRefreshOutcome::PublishFailed,
                None,
            );
            error!(
                "failed to publish Pingora DNS membership for backend '{}': {}",
                backend.identity.backend_addr, error
            );
        }
        Err(_) => metrics.record_pingora_discovery_refresh(
            PingoraDiscoveryRefreshOutcome::RetainedFailure,
            None,
        ),
    }
    outcome
}
