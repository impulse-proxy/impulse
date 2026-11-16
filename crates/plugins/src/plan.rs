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
    /// Response compression. This is derived from the response-policy stage
    /// being non-empty, which today can only hold response compression; revisit
    /// this derivation if another response plugin
    /// is added.
    Compression,
    Full,
}

impl RouteExecutionClass {
    /// Classify a route once while preparing its runtime generation.
    pub(crate) const fn compile(
        has_sync: bool,
        has_async: bool,
        has_cache: bool,
        has_compression: bool,
    ) -> RouteExecutionClass {
        match (has_sync, has_async, has_cache, has_compression) {
            (false, false, false, false) => RouteExecutionClass::Passthrough,
            (true, false, false, false) => RouteExecutionClass::SynchronousPolicy,
            (false, true, false, false) => RouteExecutionClass::AsynchronousPolicy,
            (false, false, true, false) => RouteExecutionClass::Cache,
            (false, false, false, true) => RouteExecutionClass::Compression,
            _ => RouteExecutionClass::Full,
        }
    }
}

impl CompiledPluginPlan {
    #[must_use]
    pub(crate) fn new(
        execution_class: RouteExecutionClass,
        request_gate: Vec<CompiledRequestPlugin>,
        async_request_gate: Vec<CompiledAsyncRequestPlugin>,
        cache_policy: Vec<CompiledCachePlugin>,
        response_policy: Vec<CompiledResponsePlugin>,
    ) -> Self {
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

#[cfg(all(
    test,
    feature = "api-key-auth",
    feature = "external-auth",
    feature = "response-cache",
    feature = "response-compression"
))]
mod tests {
    use std::{
        sync::{Arc, atomic::AtomicU64},
        time::Duration,
    };

    use super::*;
    use crate::{
        ApiKeyAuthInput, CompiledResponseCache, CompiledResponseCompression, ExternalAuthInput,
        ResponseCacheInput, ResponseCompressionInput, input::ExternalAuthFailureModeInput,
    };

    fn sync_plugin() -> CompiledRequestPlugin {
        CompiledRequestPlugin::ApiKeyAuth(ApiKeyAuthInput {
            header_name: "x-api-key".to_string(),
            accepted_keys: vec!["key".to_string()].into_boxed_slice(),
        })
    }

    fn async_plugin() -> CompiledAsyncRequestPlugin {
        CompiledAsyncRequestPlugin::ExternalAuth(ExternalAuthInput::Http {
            endpoint: "http://127.0.0.1:1/auth".to_string(),
            request_headers: Box::default(),
            response_header_allowlist: Box::default(),
            timeout: Duration::from_secs(1),
            failure_mode: ExternalAuthFailureModeInput::FailClosed,
        })
    }

    fn cache_plugin() -> CompiledCachePlugin {
        CompiledCachePlugin::ResponseCache(Arc::new(CompiledResponseCache::new(
            ResponseCacheInput {
                max_bytes: 1024,
                max_entries: 8,
                max_object_bytes: 512,
                max_ttl_seconds: 60,
                authenticated_route: false,
            },
            Arc::new(AtomicU64::new(0)),
        )))
    }

    fn compression_plugin() -> CompiledResponsePlugin {
        CompiledResponsePlugin::ResponseCompression(CompiledResponseCompression::new(
            ResponseCompressionInput {
                minimum_size_bytes: 1024,
            },
        ))
    }

    #[test]
    fn empty_plan_is_passthrough() {
        let plan = CompiledPluginPlan::new(
            RouteExecutionClass::Passthrough,
            vec![],
            vec![],
            vec![],
            vec![],
        );
        assert_eq!(plan.execution_class(), RouteExecutionClass::Passthrough);
        assert!(plan.is_empty());
        assert_eq!(
            CompiledPluginPlan::default().execution_class(),
            RouteExecutionClass::Passthrough
        );
    }

    #[test]
    fn single_stage_plans_get_their_own_class() {
        let sync = CompiledPluginPlan::new(
            RouteExecutionClass::SynchronousPolicy,
            vec![sync_plugin()],
            vec![],
            vec![],
            vec![],
        );
        assert_eq!(
            sync.execution_class(),
            RouteExecutionClass::SynchronousPolicy
        );

        let asynchronous = CompiledPluginPlan::new(
            RouteExecutionClass::AsynchronousPolicy,
            vec![],
            vec![async_plugin()],
            vec![],
            vec![],
        );
        assert_eq!(
            asynchronous.execution_class(),
            RouteExecutionClass::AsynchronousPolicy
        );

        let cache = CompiledPluginPlan::new(
            RouteExecutionClass::Cache,
            vec![],
            vec![],
            vec![cache_plugin()],
            vec![],
        );
        assert_eq!(cache.execution_class(), RouteExecutionClass::Cache);

        let compression = CompiledPluginPlan::new(
            RouteExecutionClass::Compression,
            vec![],
            vec![],
            vec![],
            vec![compression_plugin()],
        );
        assert_eq!(
            compression.execution_class(),
            RouteExecutionClass::Compression
        );
    }

    #[test]
    fn several_plugins_in_one_stage_keep_the_single_stage_class() {
        let plan = CompiledPluginPlan::new(
            RouteExecutionClass::SynchronousPolicy,
            vec![sync_plugin(), sync_plugin()],
            vec![],
            vec![],
            vec![],
        );
        assert_eq!(
            plan.execution_class(),
            RouteExecutionClass::SynchronousPolicy
        );
    }

    #[test]
    fn multiple_stages_are_full() {
        let sync_and_async = CompiledPluginPlan::new(
            RouteExecutionClass::Full,
            vec![sync_plugin()],
            vec![async_plugin()],
            vec![],
            vec![],
        );
        assert_eq!(sync_and_async.execution_class(), RouteExecutionClass::Full);

        let cache_and_compression = CompiledPluginPlan::new(
            RouteExecutionClass::Full,
            vec![],
            vec![],
            vec![cache_plugin()],
            vec![compression_plugin()],
        );
        assert_eq!(
            cache_and_compression.execution_class(),
            RouteExecutionClass::Full
        );

        let everything = CompiledPluginPlan::new(
            RouteExecutionClass::Full,
            vec![sync_plugin()],
            vec![async_plugin()],
            vec![cache_plugin()],
            vec![compression_plugin()],
        );
        assert_eq!(everything.execution_class(), RouteExecutionClass::Full);
    }

    #[test]
    fn generation_does_not_change_the_class() {
        let plan = CompiledPluginPlan::new(
            RouteExecutionClass::Cache,
            vec![],
            vec![],
            vec![cache_plugin()],
            vec![],
        )
        .with_generation(7);
        assert_eq!(plan.generation(), 7);
        assert_eq!(plan.execution_class(), RouteExecutionClass::Cache);
    }
}
