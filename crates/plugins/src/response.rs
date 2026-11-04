use impulse_contracts::{PluginCacheView, PluginKind, PluginResponseView};

use crate::{CompiledCachePlugin, CompiledPluginPlan, CompiledResponsePlugin};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CachePluginDecision {
    Continue,
    Bypass,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CachePluginExecution {
    Continue,
    Bypass { kind: PluginKind },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponsePluginDecision {
    Continue,
    Bypass,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponsePluginExecution {
    Continue,
    Bypass { kind: PluginKind },
}

/// Executes cache lookup or fill policy using request and response metadata only.
#[must_use]
pub fn execute_cache_plugins<'a>(
    plan: &CompiledPluginPlan,
    cache: PluginCacheView<'a>,
    mut evaluate: impl FnMut(&CompiledCachePlugin, PluginCacheView<'a>) -> CachePluginDecision,
) -> CachePluginExecution {
    let plugins = plan.cache_policy();
    if plugins.is_empty() {
        return CachePluginExecution::Continue;
    }

    for plugin in plugins {
        if evaluate(plugin, cache) == CachePluginDecision::Bypass {
            return CachePluginExecution::Bypass {
                kind: plugin.kind(),
            };
        }
    }

    CachePluginExecution::Continue
}

/// Executes response policy using metadata only; response bodies and writes stay host-owned.
#[must_use]
pub fn execute_response_plugins<'a>(
    plan: &CompiledPluginPlan,
    response: PluginResponseView<'a>,
    mut evaluate: impl FnMut(&CompiledResponsePlugin, PluginResponseView<'a>) -> ResponsePluginDecision,
) -> ResponsePluginExecution {
    let plugins = plan.response_policy();
    if plugins.is_empty() {
        return ResponsePluginExecution::Continue;
    }

    for plugin in plugins {
        if evaluate(plugin, response) == ResponsePluginDecision::Bypass {
            return ResponsePluginExecution::Bypass {
                kind: plugin.kind(),
            };
        }
    }

    ResponsePluginExecution::Continue
}
