//! Compiled, protocol-neutral traffic plugin plans.

#![forbid(unsafe_code)]
#![deny(unused_crate_dependencies)]
#![warn(unreachable_pub)]

mod cache;
mod catalog;
mod compile;
mod compression;
mod connection;
mod input;
mod instance;
mod plan;
mod quota;
mod rate_limit;
mod request;
mod response;

pub use cache::{CachePluginFillDecision, CompiledResponseCache, ResponseCacheKeyParts};
pub use catalog::{
    ALL_COMPILED_PLUGIN_KINDS, PluginCatalog, PluginCatalogBuildError, compiled_plugin_catalog,
};
pub use compile::{
    CompiledGenerationPluginPlans, PluginPlanCompileError, compile_generation_plugin_plans,
};
pub use compression::{CompiledResponseCompression, ResponseCompressionEvaluation};
pub use connection::{
    ConnectionPluginExecution, ConnectionPluginRejection, execute_connection_plugins,
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
    CompiledAsyncRequestPlugin, CompiledCachePlugin, CompiledConnectionPlugin, CompiledJwtAuth,
    CompiledRequestPlugin, CompiledResponsePlugin, CompiledScopedRateLimit,
};
pub use plan::{CompiledConnectionPlan, CompiledPluginPlan};
pub use quota::CompiledQuota;
pub use request::{
    AsyncRequestPluginDecision, AsyncRequestPluginExecution, AsyncRequestPluginExecutionGuard,
    SynchronousRequestPluginDecision, SynchronousRequestPluginExecution,
    execute_async_request_plugins, execute_synchronous_request_plugins,
};
pub use response::{
    CachePluginDecision, CachePluginExecution, ResponsePluginDecision, ResponsePluginExecution,
    execute_cache_plugins, execute_response_plugins,
};
