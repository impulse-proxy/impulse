use std::future::Future;

use impulse_contracts::{PluginHeaderMutation, PluginRejection, PluginRequestView};

use crate::{CompiledAsyncRequestPlugin, CompiledPluginPlan, CompiledRequestPlugin};

/// Request-owned guard preventing asynchronous policy work from running again
/// during retries.
#[derive(Debug, Default)]
pub struct AsyncRequestPluginExecutionGuard {
    started: bool,
}

/// One asynchronous plugin's decision for the current request phase.
#[derive(Debug, Eq, PartialEq)]
pub enum AsyncRequestPluginDecision {
    Continue,
    Mutate(Box<[PluginHeaderMutation]>),
    Reject(PluginRejection),
}

/// Host-owned result of executing the asynchronous request phase.
#[derive(Debug, Eq, PartialEq)]
pub enum AsyncRequestPluginExecution {
    Continue {
        mutations: Vec<PluginHeaderMutation>,
    },
    Reject(PluginRejection),
    AlreadyExecuted,
}

/// One synchronous plugin's decision for the current request phase.
#[derive(Debug, Eq, PartialEq)]
pub enum SynchronousRequestPluginDecision {
    Continue,
    Mutate(Box<[PluginHeaderMutation]>),
    Reject(PluginRejection),
}

/// Host-owned result of executing the synchronous request phase.
#[derive(Debug, Eq, PartialEq)]
pub enum SynchronousRequestPluginExecution {
    Continue {
        mutations: Vec<PluginHeaderMutation>,
    },
    Reject(PluginRejection),
}

/// Executes the generation-compiled synchronous request chain in plan order.
///
/// The evaluator is statically dispatched so the hot path does not require a
/// trait object or boxed hook. Headers remain available through the borrowed
/// lookup in `request`; this runner never materializes a header map.
#[must_use]
pub fn execute_synchronous_request_plugins<'a>(
    plan: &CompiledPluginPlan,
    request: PluginRequestView<'a>,
    mut evaluate: impl FnMut(
        &CompiledRequestPlugin,
        PluginRequestView<'a>,
    ) -> SynchronousRequestPluginDecision,
) -> SynchronousRequestPluginExecution {
    let plugins = plan.request_gate();
    if plugins.is_empty() {
        return SynchronousRequestPluginExecution::Continue {
            mutations: Vec::new(),
        };
    }

    let mut mutations = Vec::new();
    for plugin in plugins {
        match evaluate(plugin, request) {
            SynchronousRequestPluginDecision::Continue => {}
            SynchronousRequestPluginDecision::Mutate(plugin_mutations) => {
                mutations.extend(plugin_mutations);
            }
            SynchronousRequestPluginDecision::Reject(rejection) => {
                return SynchronousRequestPluginExecution::Reject(rejection);
            }
        }
    }

    SynchronousRequestPluginExecution::Continue { mutations }
}

/// Executes compiled asynchronous plugins once for the client request.
///
/// The request-owned guard is marked before the first await, so retry attempts
/// cannot repeat authentication, consume quota again, or duplicate mutations.
#[must_use]
pub async fn execute_async_request_plugins<'a, Evaluate, Evaluation>(
    guard: &mut AsyncRequestPluginExecutionGuard,
    plan: &'a CompiledPluginPlan,
    request: PluginRequestView<'a>,
    mut evaluate: Evaluate,
) -> AsyncRequestPluginExecution
where
    Evaluate: FnMut(&'a CompiledAsyncRequestPlugin, PluginRequestView<'a>) -> Evaluation,
    Evaluation: Future<Output = AsyncRequestPluginDecision>,
{
    if guard.started {
        return AsyncRequestPluginExecution::AlreadyExecuted;
    }
    guard.started = true;

    let plugins = plan.async_request_gate();
    if plugins.is_empty() {
        return AsyncRequestPluginExecution::Continue {
            mutations: Vec::new(),
        };
    }

    let mut mutations = Vec::new();
    for plugin in plugins {
        match evaluate(plugin, request).await {
            AsyncRequestPluginDecision::Continue => {}
            AsyncRequestPluginDecision::Mutate(plugin_mutations) => {
                mutations.extend(plugin_mutations);
            }
            AsyncRequestPluginDecision::Reject(rejection) => {
                return AsyncRequestPluginExecution::Reject(rejection);
            }
        }
    }

    AsyncRequestPluginExecution::Continue { mutations }
}
