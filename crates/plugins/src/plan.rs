use crate::{
    CompiledAsyncRequestPlugin, CompiledCachePlugin, CompiledConnectionPlugin,
    CompiledRequestPlugin, CompiledResponsePlugin,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompiledPluginPlan {
    generation: u64,
    execution_class: RouteExecutionClass,
    request_gate: Box<[CompiledRequestPlugin]>,
    async_request_gate: Box<[CompiledAsyncRequestPlugin]>,
    cache_policy: Box<[CompiledCachePlugin]>,
    response_policy: Box<[CompiledResponsePlugin]>,
}

/// Immutable fast-path classification for one compiled route plan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RouteExecutionClass {
    #[default]
    Passthrough,
    SynchronousPolicy,
    AsynchronousPolicy,
    Cache,
    Compression,
    Full,
}

impl CompiledPluginPlan {
    #[must_use]
    pub fn new(
        request_gate: Vec<CompiledRequestPlugin>,
        async_request_gate: Vec<CompiledAsyncRequestPlugin>,
        cache_policy: Vec<CompiledCachePlugin>,
        response_policy: Vec<CompiledResponsePlugin>,
    ) -> Self {
        let has_sync = !request_gate.is_empty();
        let has_async = !async_request_gate.is_empty();
        let has_cache = !cache_policy.is_empty();
        let has_compression = !response_policy.is_empty();
        let stage_count = [has_sync, has_async, has_cache, has_compression]
            .into_iter()
            .filter(|enabled| *enabled)
            .count();
        let execution_class = match (stage_count, has_sync, has_async, has_cache, has_compression) {
            (0, ..) => RouteExecutionClass::Passthrough,
            (1, true, _, _, _) => RouteExecutionClass::SynchronousPolicy,
            (1, _, true, _, _) => RouteExecutionClass::AsynchronousPolicy,
            (1, _, _, true, _) => RouteExecutionClass::Cache,
            (1, _, _, _, true) => RouteExecutionClass::Compression,
            _ => RouteExecutionClass::Full,
        };
        Self {
            generation: 0,
            execution_class,
            request_gate: request_gate.into_boxed_slice(),
            async_request_gate: async_request_gate.into_boxed_slice(),
            cache_policy: cache_policy.into_boxed_slice(),
            response_policy: response_policy.into_boxed_slice(),
        }
    }

    pub(crate) fn with_generation(mut self, generation: u64) -> Self {
        self.generation = generation;
        self
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn execution_class(&self) -> RouteExecutionClass {
        self.execution_class
    }

    #[must_use]
    pub fn request_gate(&self) -> &[CompiledRequestPlugin] {
        &self.request_gate
    }

    #[must_use]
    pub fn async_request_gate(&self) -> &[CompiledAsyncRequestPlugin] {
        &self.async_request_gate
    }

    #[must_use]
    pub fn cache_policy(&self) -> &[CompiledCachePlugin] {
        &self.cache_policy
    }

    #[must_use]
    #[cfg(feature = "response-cache")]
    pub fn response_cache(&self) -> Option<&crate::CompiledResponseCache> {
        self.cache_policy
            .iter()
            .map(|plugin| match plugin {
                CompiledCachePlugin::ResponseCache(cache) => cache.as_ref(),
            })
            .next()
    }

    #[must_use]
    pub fn response_policy(&self) -> &[CompiledResponsePlugin] {
        &self.response_policy
    }

    #[must_use]
    #[cfg(feature = "response-compression")]
    pub fn response_compression(&self) -> Option<&crate::CompiledResponseCompression> {
        self.response_policy
            .iter()
            .map(|plugin| match plugin {
                CompiledResponsePlugin::ResponseCompression(compression) => compression,
            })
            .next()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.request_gate.is_empty()
            && self.async_request_gate.is_empty()
            && self.cache_policy.is_empty()
            && self.response_policy.is_empty()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompiledConnectionPlan {
    connection_admission: Box<[CompiledConnectionPlugin]>,
}

impl CompiledConnectionPlan {
    #[must_use]
    pub fn new(connection_admission: Vec<CompiledConnectionPlugin>) -> Self {
        Self {
            connection_admission: connection_admission.into_boxed_slice(),
        }
    }

    #[must_use]
    pub fn connection_admission(&self) -> &[CompiledConnectionPlugin] {
        &self.connection_admission
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.connection_admission.is_empty()
    }
}
