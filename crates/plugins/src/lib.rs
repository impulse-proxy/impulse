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
#[cfg(any(
    feature = "api-key-auth",
    feature = "jwt-auth",
    feature = "external-auth",
    feature = "scoped-rate-limit",
    feature = "quota"
))]
mod request;
#[cfg(any(feature = "response-cache", feature = "response-compression"))]
mod response;

#[cfg(feature = "response-cache")]
pub use cache::{CachePluginFillDecision, CompiledResponseCache, ResponseCacheKeyParts};
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
#[cfg(any(feature = "external-auth", feature = "quota"))]
pub use request::{
    AsyncRequestPluginDecision, AsyncRequestPluginExecution, AsyncRequestPluginExecutionGuard,
    execute_async_request_plugins,
};
#[cfg(any(
    feature = "api-key-auth",
    feature = "jwt-auth",
    feature = "scoped-rate-limit"
))]
pub use request::{
    SynchronousRequestPluginDecision, SynchronousRequestPluginExecution,
    execute_synchronous_request_plugins,
};
#[cfg(feature = "response-cache")]
pub use response::{CachePluginDecision, CachePluginExecution, execute_cache_plugins};
#[cfg(feature = "response-compression")]
pub use response::{ResponsePluginDecision, ResponsePluginExecution, execute_response_plugins};
