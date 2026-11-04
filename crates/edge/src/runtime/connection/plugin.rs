use std::net::IpAddr;

use impulse_contracts::PluginConnectionView;
use impulse_plugins::{
    CompiledConnectionPlan, CompiledConnectionPlugin, ConnectionPluginDecision,
    ConnectionPluginExecution, ConnectionRateLimitInput, execute_connection_plugins,
};

pub(crate) fn execute_listener_connection_plan(
    plan: &CompiledConnectionPlan,
    connection: PluginConnectionView<'_>,
    mut admit_rate_limited_connection: impl FnMut(&ConnectionRateLimitInput, IpAddr) -> bool,
) -> bool {
    matches!(
        execute_connection_plugins(plan, connection, |plugin, connection| match plugin {
            CompiledConnectionPlugin::ConnectionRateLimit(policy) => {
                if admit_rate_limited_connection(policy, connection.peer_address.ip()) {
                    ConnectionPluginDecision::Continue
                } else {
                    ConnectionPluginDecision::Reject
                }
            }
        }),
        ConnectionPluginExecution::Continue
    )
}
