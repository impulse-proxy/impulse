#[cfg(feature = "response-cache")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::{collections::HashMap, fmt, sync::Arc};

use impulse_contracts::PluginKind;

#[cfg(any(feature = "external-auth", feature = "quota"))]
use crate::CompiledAsyncRequestPlugin;
#[cfg(feature = "response-cache")]
use crate::CompiledCachePlugin;
#[cfg(feature = "connection-rate-limit")]
use crate::CompiledConnectionPlugin;
#[cfg(any(
    feature = "api-key-auth",
    feature = "jwt-auth",
    feature = "scoped-rate-limit"
))]
use crate::CompiledRequestPlugin;
#[cfg(feature = "response-compression")]
use crate::CompiledResponsePlugin;
#[cfg(feature = "scoped-rate-limit")]
use crate::CompiledScopedRateLimit;
use crate::{
    CompiledConnectionPlan, CompiledPluginPlan, PluginCatalog, PluginConstructionInputs,
    UpstreamPluginInputs,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginPlanCompileError {
    UnavailableKind(PluginKind),
}

impl fmt::Display for PluginPlanCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnavailableKind(kind) => {
                write!(
                    formatter,
                    "configured plugin kind is not compiled in: {kind:?}"
                )
            }
        }
    }
}

impl std::error::Error for PluginPlanCompileError {}

#[derive(Clone, Debug)]
pub struct CompiledGenerationPluginPlans {
    generation: u64,
    connection: CompiledConnectionPlan,
    upstreams: HashMap<String, Arc<CompiledPluginPlan>>,
    #[cfg(feature = "response-cache")]
    response_cache_namespace: Arc<AtomicU64>,
}

impl CompiledGenerationPluginPlans {
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn connection(&self) -> &CompiledConnectionPlan {
        &self.connection
    }

    #[must_use]
    pub fn upstreams(&self) -> &HashMap<String, Arc<CompiledPluginPlan>> {
        &self.upstreams
    }

    #[must_use]
    pub fn upstream_plan(&self, upstream_name: &str) -> Option<Arc<CompiledPluginPlan>> {
        self.upstreams.get(upstream_name).map(Arc::clone)
    }

    #[must_use]
    #[cfg(feature = "quota")]
    pub fn quota(&self) -> Option<&crate::CompiledQuota> {
        self.upstreams.values().find_map(|plan| {
            plan.async_request_gate()
                .iter()
                .find_map(|plugin| match plugin {
                    CompiledAsyncRequestPlugin::Quota(quota) => Some(quota.as_ref()),
                    #[cfg(feature = "external-auth")]
                    CompiledAsyncRequestPlugin::ExternalAuth(_) => None,
                })
        })
    }

    #[must_use]
    #[cfg(feature = "response-cache")]
    pub fn response_cache_namespace(&self) -> u64 {
        self.response_cache_namespace.load(Ordering::Acquire)
    }

    #[cfg(feature = "response-cache")]
    pub fn inherit_response_cache_namespace(&self, namespace: u64) {
        self.response_cache_namespace
            .store(namespace, Ordering::Release);
    }

    #[must_use]
    pub fn active_count(&self, kind: PluginKind) -> usize {
        if matches!(kind, PluginKind::ScopedRateLimit | PluginKind::Quota) {
            return if self.upstreams.values().any(|plan| {
                plan.request_gate()
                    .iter()
                    .any(|plugin| plugin.kind() == kind)
                    || plan
                        .async_request_gate()
                        .iter()
                        .any(|plugin| plugin.kind() == kind)
            }) {
                1
            } else {
                0
            };
        }

        self.connection
            .connection_admission()
            .iter()
            .filter(|plugin| plugin.kind() == kind)
            .count()
            + self
                .upstreams
                .values()
                .map(|plan| {
                    plan.request_gate()
                        .iter()
                        .filter(|plugin| plugin.kind() == kind)
                        .count()
                        + plan
                            .async_request_gate()
                            .iter()
                            .filter(|plugin| plugin.kind() == kind)
                            .count()
                        + plan
                            .cache_policy()
                            .iter()
                            .filter(|plugin| plugin.kind() == kind)
                            .count()
                        + plan
                            .response_policy()
                            .iter()
                            .filter(|plugin| plugin.kind() == kind)
                            .count()
                })
                .sum::<usize>()
    }
}

#[cfg(any(
    feature = "connection-rate-limit",
    feature = "api-key-auth",
    feature = "jwt-auth",
    feature = "external-auth",
    feature = "scoped-rate-limit",
    feature = "quota",
    feature = "response-cache",
    feature = "response-compression"
))]
fn require_available(
    catalog: &PluginCatalog,
    kind: PluginKind,
) -> Result<(), PluginPlanCompileError> {
    catalog
        .contains(kind)
        .then_some(())
        .ok_or(PluginPlanCompileError::UnavailableKind(kind))
}

pub fn compile_generation_plugin_plans(
    catalog: &PluginCatalog,
    generation: u64,
    inputs: PluginConstructionInputs,
) -> Result<CompiledGenerationPluginPlans, PluginPlanCompileError> {
    #[cfg(feature = "connection-rate-limit")]
    let connection = match inputs.connection_rate_limit {
        Some(input) => {
            require_available(catalog, PluginKind::ConnectionRateLimit)?;
            CompiledConnectionPlan::new(vec![CompiledConnectionPlugin::connection_rate_limit(
                input,
            )])
        }
        None => CompiledConnectionPlan::default(),
    };
    #[cfg(not(feature = "connection-rate-limit"))]
    let connection = CompiledConnectionPlan::default();

    #[cfg(feature = "scoped-rate-limit")]
    let scoped_rate_limits = if inputs.scoped_rate_limits.is_empty() {
        None
    } else {
        require_available(catalog, PluginKind::ScopedRateLimit)?;
        Some(Arc::new(CompiledScopedRateLimit::new(Arc::from(
            inputs.scoped_rate_limits,
        ))))
    };
    #[cfg(feature = "quota")]
    let quota = match inputs.quota {
        Some(quota) => {
            require_available(catalog, PluginKind::Quota)?;
            Some(Arc::new(crate::CompiledQuota::new(quota)))
        }
        None => None,
    };

    #[cfg(feature = "response-cache")]
    let response_cache_namespace = Arc::new(AtomicU64::new(generation));
    let upstreams = inputs
        .upstreams
        .into_vec()
        .into_iter()
        .map(|upstream| {
            compile_upstream_plan(
                catalog,
                generation,
                upstream,
                #[cfg(feature = "scoped-rate-limit")]
                &scoped_rate_limits,
                #[cfg(feature = "quota")]
                &quota,
                #[cfg(feature = "response-cache")]
                &response_cache_namespace,
            )
        })
        .collect::<Result<HashMap<_, _>, _>>()?;

    Ok(CompiledGenerationPluginPlans {
        generation,
        connection,
        upstreams,
        #[cfg(feature = "response-cache")]
        response_cache_namespace,
    })
}

fn compile_upstream_plan(
    _catalog: &PluginCatalog,
    generation: u64,
    inputs: UpstreamPluginInputs,
    #[cfg(feature = "scoped-rate-limit")] scoped_rate_limits: &Option<Arc<CompiledScopedRateLimit>>,
    #[cfg(feature = "quota")] quota: &Option<Arc<crate::CompiledQuota>>,
    #[cfg(feature = "response-cache")] response_cache_namespace: &Arc<AtomicU64>,
) -> Result<(String, Arc<CompiledPluginPlan>), PluginPlanCompileError> {
    #[allow(unused_mut)]
    let mut request_gate = Vec::with_capacity(3);
    #[cfg(feature = "api-key-auth")]
    if let Some(api_key) = inputs.api_key_auth {
        require_available(_catalog, PluginKind::ApiKeyAuth)?;
        request_gate.push(CompiledRequestPlugin::ApiKeyAuth(api_key));
    }
    #[cfg(feature = "jwt-auth")]
    if let Some(jwt) = inputs.jwt_auth {
        require_available(_catalog, PluginKind::JwtAuth)?;
        request_gate.push(CompiledRequestPlugin::JwtAuth(Box::new(
            crate::CompiledJwtAuth::new(generation, jwt),
        )));
    }
    #[cfg(feature = "scoped-rate-limit")]
    if let Some(scoped_rate_limits) = scoped_rate_limits {
        request_gate.push(CompiledRequestPlugin::ScopedRateLimit(Arc::clone(
            scoped_rate_limits,
        )));
    }

    #[allow(unused_mut)]
    let mut async_request_gate = Vec::with_capacity(2);
    #[cfg(feature = "external-auth")]
    if let Some(external_auth) = inputs.external_auth {
        require_available(_catalog, PluginKind::ExternalAuth)?;
        async_request_gate.push(CompiledAsyncRequestPlugin::ExternalAuth(external_auth));
    }
    #[cfg(feature = "quota")]
    if let Some(quota) = quota {
        async_request_gate.push(CompiledAsyncRequestPlugin::Quota(Arc::clone(quota)));
    }

    #[allow(unused_mut)]
    let mut cache_policy = Vec::with_capacity(1);
    #[cfg(feature = "response-cache")]
    if let Some(cache) = inputs.response_cache {
        require_available(_catalog, PluginKind::ResponseCache)?;
        cache_policy.push(CompiledCachePlugin::ResponseCache(Arc::new(
            crate::CompiledResponseCache::new(cache, Arc::clone(response_cache_namespace)),
        )));
    }

    #[allow(unused_mut)]
    let mut response_policy = Vec::with_capacity(1);
    #[cfg(feature = "response-compression")]
    if let Some(compression) = inputs.response_compression {
        require_available(_catalog, PluginKind::ResponseCompression)?;
        response_policy.push(CompiledResponsePlugin::ResponseCompression(
            crate::CompiledResponseCompression::new(compression),
        ));
    }

    Ok((
        inputs.upstream_name,
        Arc::new(
            CompiledPluginPlan::new(
                request_gate,
                async_request_gate,
                cache_policy,
                response_policy,
            )
            .with_generation(generation),
        ),
    ))
}
