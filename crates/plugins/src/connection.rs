use impulse_contracts::{PluginConnectionView, PluginKind};

use crate::{CompiledConnectionPlan, CompiledConnectionPlugin};

/// One listener-level plugin's connection-admission decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionPluginDecision {
    Continue,
    Reject,
}

/// Host-owned result of executing the compiled connection plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionPluginExecution {
    Continue,
    Reject { kind: PluginKind },
}

/// Executes the listener generation's compiled connection plugins in plan order.
///
/// This phase decides admission only. The host continues to own active-connection
/// permits because their release depends on protocol connection-close events.
#[must_use]
pub fn execute_connection_plugins<'a>(
    plan: &CompiledConnectionPlan,
    connection: PluginConnectionView<'a>,
    mut evaluate: impl FnMut(
        &CompiledConnectionPlugin,
        PluginConnectionView<'a>,
    ) -> ConnectionPluginDecision,
) -> ConnectionPluginExecution {
    let plugins = plan.connection_admission();
    if plugins.is_empty() {
        return ConnectionPluginExecution::Continue;
    }

    for plugin in plugins {
        if evaluate(plugin, connection) == ConnectionPluginDecision::Reject {
            return ConnectionPluginExecution::Reject {
                kind: plugin.kind(),
            };
        }
    }

    ConnectionPluginExecution::Continue
}
