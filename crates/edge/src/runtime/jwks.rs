use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use impulse_config::{
    config::{JwksStartupBehavior, JwtAlgorithm},
    runtime::{RuntimeConfig, RuntimeJwtAuth},
};
use impulse_errors::ProxyError;
use impulse_plugins::{
    CompiledGenerationPluginPlans, CompiledRequestPlugin, JwksStartupBehaviorInput,
    JwtAlgorithmInput,
};
use impulse_policy::jwks::{
    JwtJwksCacheState, JwtJwksRuntimeSnapshot, JwtJwksSharedCache, JwtJwksSourceConfig,
    fetch_and_normalize_jwks, jwt_jwks_metrics_sink, merge_jwks_source_configs,
    refresh_jwks_source_once, snapshot_jwks_sources,
};

use super::tasks::RuntimeTaskRegistry;

pub(crate) fn runtime_sources(config: &RuntimeConfig) -> Vec<JwtJwksSourceConfig> {
    merge_jwks_source_configs(config.upstreams.values().filter_map(|upstream| {
        upstream
            .policy
            .upstream_auth
            .jwt
            .as_ref()
            .and_then(JwtJwksSourceConfig::from_jwt)
    }))
}

fn compiled_sources(plans: &CompiledGenerationPluginPlans) -> Vec<JwtJwksSourceConfig> {
    let sources = plans.upstreams().values().flat_map(|plan| {
        plan.request_gate().iter().filter_map(|plugin| {
            let CompiledRequestPlugin::JwtAuth(compiled) = plugin else {
                return None;
            };
            let input = compiled.input();
            let jwks_url = input.jwks_url.clone()?;
            let mut allowed_algorithms = input
                .allowed_algorithms
                .iter()
                .filter_map(|algorithm| match algorithm {
                    JwtAlgorithmInput::Hs256 => None,
                    JwtAlgorithmInput::Rs256 => Some(JwtAlgorithm::Rs256),
                    JwtAlgorithmInput::Es256 => Some(JwtAlgorithm::Es256),
                })
                .collect::<Vec<_>>();
            allowed_algorithms.sort_by_key(|algorithm| match algorithm {
                JwtAlgorithm::Hs256 => 0,
                JwtAlgorithm::Rs256 => 1,
                JwtAlgorithm::Es256 => 2,
            });
            allowed_algorithms.dedup();
            Some(JwtJwksSourceConfig {
                generation: compiled.generation(),
                source_identity: impulse_policy::jwks::jwt_jwks_source_identity(
                    &jwks_url,
                    &allowed_algorithms,
                ),
                jwks_url,
                allowed_algorithms,
                refresh_interval: input.jwks_refresh_interval,
                request_timeout: input.jwks_request_timeout,
                cache_ttl: input.jwks_cache_ttl,
                stale_if_error: input.jwks_stale_if_error,
                startup_behavior: match input.jwks_startup_behavior {
                    JwksStartupBehaviorInput::RequireReady => JwksStartupBehavior::RequireReady,
                    JwksStartupBehaviorInput::AllowDegraded => JwksStartupBehavior::AllowDegraded,
                },
            })
        })
    });
    merge_jwks_source_configs(sources)
}

pub(crate) fn register_metrics(metrics: &Arc<crate::Metrics>) {
    if let Ok(mut sink) = jwt_jwks_metrics_sink().write() {
        *sink = Arc::downgrade(metrics);
    }
}

pub(crate) fn snapshot_sources(config: &RuntimeConfig) -> Vec<JwtJwksRuntimeSnapshot> {
    snapshot_jwks_sources(runtime_sources(config))
}

pub(crate) fn source_identity(jwt: &RuntimeJwtAuth) -> Option<String> {
    impulse_policy::jwks::runtime_jwks_source_identity(jwt)
}

pub(crate) fn preflight_require_ready(
    config: &RuntimeConfig,
    trigger: &'static str,
) -> Result<(), ProxyError> {
    let require_ready = runtime_sources(config)
        .into_iter()
        .filter(|source| matches!(source.startup_behavior, JwksStartupBehavior::RequireReady))
        .collect::<Vec<_>>();
    if require_ready.is_empty() {
        return Ok(());
    }

    std::thread::spawn(move || -> Result<(), String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| format!("failed to create JWKS startup runtime: {err}"))?;
        runtime.block_on(async move {
            for source in require_ready {
                let keys = fetch_and_normalize_jwks(
                    &source.jwks_url,
                    &source.allowed_algorithms,
                    source.request_timeout,
                )
                .await
                .map_err(|failure| {
                    format!(
                        "jwks require-ready preflight failed source_id={} endpoint={} trigger={} startup_behavior=require_ready detail={}",
                        source.source_identity,
                        source.public_endpoint(),
                        trigger,
                        failure
                    )
                })?;
                if keys.is_empty() {
                    return Err(format!(
                        "jwks require-ready preflight failed source_id={} endpoint={} trigger={} startup_behavior=require_ready detail=no_usable_keys",
                        source.source_identity,
                        source.public_endpoint(),
                        trigger
                    ));
                }
            }
            Ok(())
        })
    })
    .join()
    .map_err(|_| ProxyError::Transport("jwks startup preflight thread panicked".to_string()))?
    .map_err(ProxyError::Transport)
}

pub(crate) fn spawn_refresh(
    plans: &CompiledGenerationPluginPlans,
    task_registry: Arc<RuntimeTaskRegistry>,
    runtime_handle: Option<tokio::runtime::Handle>,
) {
    let sources = compiled_sources(plans);
    let generation = plans.generation();
    let Some(handle) = runtime_handle else {
        log::error!("JWKS refresh disabled: no Tokio runtime available");
        return;
    };

    task_registry.spawn_supervised(&handle, "jwks-refresh", None, async move {
        JwtJwksSharedCache::shared().reconcile_sources(generation, sources.iter());
        let mut refresh_tasks = tokio::task::JoinSet::new();
        for task_source in sources {
            refresh_tasks.spawn(async move {
                let _ = refresh_jwks_source_once(task_source.clone(), "startup").await;
                if matches!(task_source.startup_behavior, JwksStartupBehavior::RequireReady) {
                    let snapshot = JwtJwksSharedCache::shared()
                        .snapshot(&task_source.source_identity, Instant::now());
                    if !matches!(
                        snapshot.as_ref().map(|entry| entry.state),
                        Some(
                            JwtJwksCacheState::Fresh
                                | JwtJwksCacheState::Stale
                                | JwtJwksCacheState::RefreshFailedRetained
                        )
                    ) {
                        log::warn!(
                            "JWKS source not ready after startup refresh source_id={} endpoint={} startup_behavior=require_ready",
                            task_source.source_identity,
                            task_source.public_endpoint()
                        );
                    }
                }

                let mut ticker = tokio::time::interval(
                    task_source.refresh_interval.max(Duration::from_secs(1)),
                );
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    ticker.tick().await;
                    let _ = refresh_jwks_source_once(task_source.clone(), "periodic").await;
                }
            });
        }
        while let Some(result) = refresh_tasks.join_next().await {
            let Err(error) = result;
            log::error!("JWKS refresh task failed: {error}");
        }
    });
}
