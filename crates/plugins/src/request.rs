use impulse_contracts::{PluginHeaderMutation, PluginRejection, PluginRequestView};

use crate::{CompiledPluginPlan, CompiledRequestPlugin};

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
