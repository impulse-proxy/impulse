use impulse_plugins::{
    CompiledConnectionPlan, ConnectionPluginExecution, ConnectionPluginRejection,
    execute_connection_plugins,
};

pub(crate) fn execute_listener_connection_plan(
    plan: &CompiledConnectionPlan,
    generation: u64,
    listener: &str,
    peer_address: Option<std::net::SocketAddr>,
    metrics: &crate::Metrics,
) -> Result<(), ConnectionPluginRejection> {
    if plan.is_empty() {
        return Ok(());
    }
    match execute_connection_plugins(
        plan,
        impulse_contracts::PluginConnectionView {
            generation,
            listener,
            peer_address,
        },
        |observation| {
            metrics.plugin_observations().record_execution(observation);
        },
    ) {
        ConnectionPluginExecution::Continue => Ok(()),
        ConnectionPluginExecution::Reject { reason, .. } => Err(reason),
    }
}
