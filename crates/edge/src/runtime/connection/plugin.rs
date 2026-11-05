use impulse_contracts::PluginConnectionView;
use impulse_plugins::{
    CompiledConnectionPlan, ConnectionPluginExecution, ConnectionPluginRejection,
    execute_connection_plugins,
};

pub(crate) fn execute_listener_connection_plan(
    plan: &CompiledConnectionPlan,
    connection: PluginConnectionView<'_>,
    metrics: &crate::Metrics,
) -> Result<(), ConnectionPluginRejection> {
    match execute_connection_plugins(plan, connection, |observation| {
        metrics.plugin_observations().record_execution(observation);
    }) {
        ConnectionPluginExecution::Continue => Ok(()),
        ConnectionPluginExecution::Reject { reason, .. } => Err(reason),
    }
}
