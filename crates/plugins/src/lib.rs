//! Compiled, protocol-neutral traffic plugin plans.

#![forbid(unsafe_code)]
#![deny(unused_crate_dependencies)]
#![warn(unreachable_pub)]

mod catalog;
mod input;
mod instance;
mod plan;

pub use catalog::{PluginCatalog, PluginCatalogBuildError};
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
