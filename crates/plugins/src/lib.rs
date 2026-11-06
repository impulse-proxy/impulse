//! Compiled, protocol-neutral traffic plugin plans.

#![forbid(unsafe_code)]
#![deny(unused_crate_dependencies)]
#![warn(unreachable_pub)]

#[cfg(feature = "response-cache")]
mod cache;
mod catalog;
mod compile;
#[cfg(feature = "response-compression")]
mod compression;
#[cfg(feature = "connection-rate-limit")]
mod connection;
mod input;
mod instance;
mod plan;
#[cfg(feature = "quota")]
mod quota;
#[cfg(any(feature = "connection-rate-limit", feature = "scoped-rate-limit"))]
mod rate_limit;
mod request;
mod response;

#[cfg(feature = "response-cache")]
pub use cache::{CompiledResponseCache, ResponseCacheKeyParts};
pub use catalog::{
    ALL_COMPILED_PLUGIN_KINDS, PluginCatalog, PluginCatalogBuildError, compiled_plugin_catalog,
};
pub use compile::{
    CompiledGenerationPluginPlans, PluginPlanCompileError, compile_generation_plugin_plans,
};
#[cfg(feature = "response-compression")]
pub use compression::CompiledResponseCompression;
#[cfg(feature = "connection-rate-limit")]
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
#[cfg(feature = "jwt-auth")]
pub use instance::CompiledJwtAuth;
#[cfg(feature = "scoped-rate-limit")]
pub use instance::CompiledScopedRateLimit;
pub use instance::{
    CompiledAsyncRequestPlugin, CompiledCachePlugin, CompiledConnectionPlugin,
    CompiledRequestPlugin, CompiledResponsePlugin,
};
pub use plan::{CompiledConnectionPlan, CompiledPluginPlan};
#[cfg(feature = "quota")]
pub use quota::CompiledQuota;
pub use request::{
    AsyncRequestPluginDecision, AsyncRequestPluginExecution, AsyncRequestPluginExecutionGuard,
    SynchronousRequestPluginDecision, SynchronousRequestPluginExecution,
    execute_async_request_plugins, execute_synchronous_request_plugins,
};
pub use response::{
    CachePluginDecision, CachePluginExecution, CachePluginFillDecision, ResponsePluginDecision,
    ResponsePluginExecution, execute_cache_plugins, execute_response_plugins,
};
