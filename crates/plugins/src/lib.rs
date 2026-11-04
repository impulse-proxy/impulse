//! Compiled, protocol-neutral traffic plugin plans.

#![forbid(unsafe_code)]
#![deny(unused_crate_dependencies)]
#![warn(unreachable_pub)]

mod catalog;
mod compile;
mod input;
mod instance;
mod plan;
mod request;

pub use catalog::{
    ALL_COMPILED_PLUGIN_KINDS, PluginCatalog, PluginCatalogBuildError, compiled_plugin_catalog,
};
pub use compile::{
    CompiledGenerationPluginPlans, PluginPlanCompileError, compile_generation_plugin_plans,
};
pub use input::{
    ApiKeyAuthInput, ConnectionRateLimitInput, ExternalAuthFailureModeInput, ExternalAuthInput,
    ExternalAuthRequestHeaderInput, JwksStartupBehaviorInput, JwtAlgorithmInput, JwtAuthInput,
    JwtVerificationKeyInput, PluginConstructionInputs, QuotaBackendFailureInput,
    QuotaCounterBackendInput, QuotaEnforcementInput, QuotaInput, QuotaLocalFallbackInput,
    QuotaPolicyInput, QuotaSelectorInput, QuotaWindowInput, RequestKeyInput, ResponseCacheInput,
    ResponseCompressionInput, ScopedRateLimitInput, ScopedRateLimitScopeInput,
    UpstreamPluginInputs,
};
pub use instance::{
    CompiledAsyncRequestPlugin, CompiledCachePlugin, CompiledConnectionPlugin,
    CompiledRequestPlugin, CompiledResponsePlugin,
};
pub use plan::{CompiledConnectionPlan, CompiledPluginPlan};
pub use request::{
    AsyncRequestPluginDecision, AsyncRequestPluginExecution, AsyncRequestPluginExecutionGuard,
    SynchronousRequestPluginDecision, SynchronousRequestPluginExecution,
    execute_async_request_plugins, execute_synchronous_request_plugins,
};
