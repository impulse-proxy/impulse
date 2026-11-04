use std::{collections::HashMap, fmt, sync::Arc};

use impulse_contracts::PluginKind;

use crate::{
    CompiledAsyncRequestPlugin, CompiledCachePlugin, CompiledConnectionPlan,
    CompiledConnectionPlugin, CompiledPluginPlan, CompiledRequestPlugin, CompiledResponsePlugin,
    CompiledScopedRateLimit, PluginCatalog, PluginConstructionInputs, UpstreamPluginInputs,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledGenerationPluginPlans {
    generation: u64,
    connection: CompiledConnectionPlan,
    upstreams: HashMap<String, Arc<CompiledPluginPlan>>,
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
}

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
    require_available(catalog, PluginKind::ConnectionRateLimit)?;
    let connection =
        CompiledConnectionPlan::new(vec![CompiledConnectionPlugin::connection_rate_limit(
            inputs.connection_rate_limit,
        )]);

    let scoped_rate_limits = if inputs.scoped_rate_limits.is_empty() {
        None
    } else {
        require_available(catalog, PluginKind::ScopedRateLimit)?;
        Some(Arc::new(CompiledScopedRateLimit::new(Arc::from(
            inputs.scoped_rate_limits,
        ))))
    };
    let quota = match inputs.quota {
        Some(quota) => {
            require_available(catalog, PluginKind::Quota)?;
            Some(Arc::new(quota))
        }
        None => None,
    };

    let upstreams = inputs
        .upstreams
        .into_vec()
        .into_iter()
        .map(|upstream| {
            compile_upstream_plan(catalog, generation, upstream, &scoped_rate_limits, &quota)
        })
        .collect::<Result<HashMap<_, _>, _>>()?;

    Ok(CompiledGenerationPluginPlans {
        generation,
        connection,
        upstreams,
    })
}

fn compile_upstream_plan(
    catalog: &PluginCatalog,
    generation: u64,
    inputs: UpstreamPluginInputs,
    scoped_rate_limits: &Option<Arc<CompiledScopedRateLimit>>,
    quota: &Option<Arc<crate::QuotaInput>>,
) -> Result<(String, Arc<CompiledPluginPlan>), PluginPlanCompileError> {
    let mut request_gate = Vec::with_capacity(3);
    if let Some(api_key) = inputs.api_key_auth {
        require_available(catalog, PluginKind::ApiKeyAuth)?;
        request_gate.push(CompiledRequestPlugin::ApiKeyAuth(api_key));
    }
    if let Some(jwt) = inputs.jwt_auth {
        require_available(catalog, PluginKind::JwtAuth)?;
        request_gate.push(CompiledRequestPlugin::JwtAuth(crate::CompiledJwtAuth::new(
            generation, jwt,
        )));
    }
    if let Some(scoped_rate_limits) = scoped_rate_limits {
        request_gate.push(CompiledRequestPlugin::ScopedRateLimit(Arc::clone(
            scoped_rate_limits,
        )));
    }

    let mut async_request_gate = Vec::with_capacity(2);
    if let Some(external_auth) = inputs.external_auth {
        require_available(catalog, PluginKind::ExternalAuth)?;
        async_request_gate.push(CompiledAsyncRequestPlugin::ExternalAuth(external_auth));
    }
    if let Some(quota) = quota {
        async_request_gate.push(CompiledAsyncRequestPlugin::Quota(Arc::clone(quota)));
    }

    let mut cache_policy = Vec::with_capacity(1);
    if let Some(cache) = inputs.response_cache {
        require_available(catalog, PluginKind::ResponseCache)?;
        cache_policy.push(CompiledCachePlugin::ResponseCache(cache));
    }

    let mut response_policy = Vec::with_capacity(1);
    if let Some(compression) = inputs.response_compression {
        require_available(catalog, PluginKind::ResponseCompression)?;
        response_policy.push(CompiledResponsePlugin::ResponseCompression(compression));
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
