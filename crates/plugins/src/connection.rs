use impulse_contracts::{
    PluginConnectionView, PluginExecutionObservation, PluginExecutionOutcome, PluginKind,
    PluginPhase,
};

use crate::CompiledConnectionPlan;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionPluginRejection {
    GlobalRateLimit,
    SourceRateLimit,
}

/// Host-owned result of executing the compiled connection plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionPluginExecution {
    Continue,
    Reject {
        kind: PluginKind,
        reason: ConnectionPluginRejection,
    },
}

/// Executes the listener generation's compiled connection plugins in plan order.
///
/// This phase decides admission only. The host continues to own active-connection
/// permits because their release depends on protocol connection-close events.
#[must_use]
pub fn execute_connection_plugins<'a>(
    plan: &CompiledConnectionPlan,
    connection: PluginConnectionView<'a>,
    mut observe: impl FnMut(PluginExecutionObservation),
) -> ConnectionPluginExecution {
    let plugins = plan.connection_admission();
    if plugins.is_empty() {
        return ConnectionPluginExecution::Continue;
    }

    for plugin in plugins {
        if let Err(reason) =
            plugin.admit_connection(connection.peer_address.map(|address| address.ip()))
        {
            observe(PluginExecutionObservation {
                kind: plugin.kind(),
                phase: PluginPhase::ConnectionAdmission,
                outcome: PluginExecutionOutcome::Reject,
                async_duration: None,
            });
            return ConnectionPluginExecution::Reject {
                kind: plugin.kind(),
                reason: match reason {
                    crate::rate_limit::ConnectionRateLimitRejection::Global => {
                        ConnectionPluginRejection::GlobalRateLimit
                    }
                    crate::rate_limit::ConnectionRateLimitRejection::Source => {
                        ConnectionPluginRejection::SourceRateLimit
                    }
                },
            };
        }
        observe(PluginExecutionObservation {
            kind: plugin.kind(),
            phase: PluginPhase::ConnectionAdmission,
            outcome: PluginExecutionOutcome::Continue,
            async_duration: None,
        });
    }

    ConnectionPluginExecution::Continue
}
