use std::{
    collections::HashMap,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Instant,
};

use impulse_config::runtime::RuntimeUpstreamPolicy;
use impulse_contracts::{
    IngressProtocol, PluginExecutionObservation, PluginExecutionOutcome, PluginKind, PluginPhase,
    PluginRequestView,
};
use impulse_plugins::{
    AsyncRequestPluginDecision, AsyncRequestPluginExecution, AsyncRequestPluginExecutionGuard,
    CompiledAsyncRequestPlugin, CompiledGenerationPluginPlans, CompiledRequestPlugin,
    SynchronousRequestPluginDecision, SynchronousRequestPluginExecution,
    execute_async_request_plugins, execute_synchronous_request_plugins,
};
use impulse_policy::quota::QuotaDecision;

use super::{
    PluginRequestExecutionInput, PluginRequestExecutionOutcome, PluginRequestExecutionState,
    PluginTerminalObservation, admission::evaluate_admission, policy::resolve_policy,
    routing::resolve_route,
};
use crate::{Metrics, resilience::runtime::RuntimeResilience, routing::index::RouteIndex};

/// Borrowed protocol-neutral request executor for one runtime generation.
pub(crate) struct EdgeRequestService<'a> {
    routing_index: &'a RouteIndex,
    upstream_policies: &'a HashMap<String, RuntimeUpstreamPolicy>,
    plugin_plans: &'a CompiledGenerationPluginPlans,
    resilience: &'a RuntimeResilience,
    metrics: &'a Metrics,
}
impl<'a> EdgeRequestService<'a> {
    pub(crate) fn new(
        routing_index: &'a RouteIndex,
        upstream_policies: &'a HashMap<String, RuntimeUpstreamPolicy>,
        plugin_plans: &'a CompiledGenerationPluginPlans,
        resilience: &'a RuntimeResilience,
        metrics: &'a Metrics,
    ) -> Self {
        Self {
            routing_index,
            upstream_policies,
            plugin_plans,
            resilience,
            metrics,
        }
    }

    /// Protocol adapters provide only borrowed request data and translate the
    /// returned host-owned decision.
    pub(crate) async fn execute_ingress_plugins(
        &self,
        input: PluginRequestExecutionInput<'_>,
        async_guard: &mut AsyncRequestPluginExecutionGuard,
    ) -> Result<PluginRequestExecutionState<super::ResolvedRouteTarget>, super::RouteResolutionError>
    {
        self.execute_plugins(input, async_guard).await
    }

    /// Runs the currently immediate plugin phase without blocking a protocol
    /// worker. Pending async work remains owned by the ingress state machine.
    pub(crate) fn execute_ingress_plugins_ready(
        &self,
        input: PluginRequestExecutionInput<'_>,
    ) -> Option<
        Result<
            PluginRequestExecutionState<super::ResolvedRouteTarget>,
            super::RouteResolutionError,
        >,
    > {
        let mut guard = AsyncRequestPluginExecutionGuard::default();
        let mut future = std::pin::pin!(self.execute_ingress_plugins(input, &mut guard));
        let mut context = Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut context) {
            Poll::Ready(result) => Some(result),
            Poll::Pending => None,
        }
    }

    /// Resolves a route, executes its compiled request plugins once, then runs
    /// shared request admission for policies not yet migrated into plugins.
    async fn execute_plugins(
        &self,
        input: PluginRequestExecutionInput<'_>,
        async_guard: &mut AsyncRequestPluginExecutionGuard,
    ) -> Result<PluginRequestExecutionState<super::ResolvedRouteTarget>, super::RouteResolutionError>
    {
        let request = input.request;
        let route = resolve_route(
            self.routing_index,
            request.method,
            request.path,
            request.authority,
        )?;
        let upstream_policy = self
            .upstream_policies
            .get(route.upstream_name.as_ref())
            .ok_or(super::RouteResolutionError::MissingUpstreamPolicy)?;
        let plugin_plan = self
            .plugin_plans
            .upstream_plan(route.upstream_name.as_ref())
            .ok_or(super::RouteResolutionError::MissingUpstreamPluginPlan)?;
        let policy = resolve_policy(upstream_policy, Arc::clone(&plugin_plan));
        let source_headers = input.headers;
        let header_lookup = |name: &str| source_headers.and_then(|lookup| lookup(name));
        let plugin_headers =
            source_headers.map(|_| &header_lookup as &impulse_contracts::PluginHeaderLookup<'_>);
        let plugin_request = PluginRequestView {
            request_id: input.request_id,
            generation: input.generation,
            route_id: Some(route.upstream_name.as_ref()),
            upstream_name: route.upstream_name.as_ref(),
            method: request.method,
            path: request.path,
            authority: request.authority,
            peer_address: request.peer_address,
            headers: plugin_headers,
            has_body: input.has_body,
            body_replayable: input.body_replayable,
            ingress_protocol: input.ingress_protocol,
        };
        let external_auth_headers = input.external_auth_headers;
        let external_auth_method = request.method;
        let external_auth_path = request.path;
        let external_auth_authority = request.authority;
        let external_auth_upstream = route.upstream_name.as_ref();

        let mut mutations = match execute_synchronous_request_plugins(
            &plugin_plan,
            plugin_request,
            |observation| {
                self.metrics
                    .plugin_observations()
                    .record_execution(observation);
            },
            |plugin, request| match plugin {
                CompiledRequestPlugin::JwtAuth(jwt) => {
                    crate::quic_listener::evaluate_compiled_jwt_policy(
                        jwt,
                        upstream_policy,
                        request,
                    )
                }
                _ => SynchronousRequestPluginDecision::Continue,
            },
        ) {
            SynchronousRequestPluginExecution::Continue { mutations } => mutations,
            SynchronousRequestPluginExecution::Reject(rejection) => {
                let observation =
                    PluginTerminalObservation::from_rejection_reason(rejection.reason());
                return Ok(PluginRequestExecutionState {
                    route,
                    policy,
                    outcome: PluginRequestExecutionOutcome::Rejected {
                        rejection,
                        observation,
                    },
                });
            }
        };

        match execute_async_request_plugins(
            async_guard,
            &plugin_plan,
            plugin_request,
            |observation| {
                if observation.kind != PluginKind::Quota {
                    self.metrics
                        .plugin_observations()
                        .record_execution(observation);
                }
            },
            |plugin, _| async move {
                match (plugin, external_auth_headers) {
                    (CompiledAsyncRequestPlugin::ExternalAuth(input), Some(headers)) => {
                        let request = crate::runtime::connection::auth::ExternalAuthRequest {
                            method: external_auth_method.to_string(),
                            path: external_auth_path.to_string(),
                            authority: external_auth_authority.map(str::to_string),
                            headers: headers.clone(),
                            upstream_name: external_auth_upstream.to_string(),
                            backend_addr: None,
                        };
                        crate::quic_listener::execute_compiled_external_auth(request, input).await
                    }
                    _ => AsyncRequestPluginDecision::Continue,
                }
            },
        )
        .await
        {
            AsyncRequestPluginExecution::Continue {
                mutations: async_mutations,
            } => {
                mutations.extend(async_mutations);
                if input.ingress_protocol != IngressProtocol::Http3
                    && let Some(quota) =
                        plugin_plan
                            .async_request_gate()
                            .iter()
                            .find_map(|plugin| match plugin {
                                CompiledAsyncRequestPlugin::Quota(quota) => Some(quota),
                                CompiledAsyncRequestPlugin::ExternalAuth(_) => None,
                            })
                {
                    let started_at = Instant::now();
                    let decision = quota.evaluate(plugin_request, &mutations).await;
                    self.metrics.plugin_observations().record_execution(
                        PluginExecutionObservation {
                            kind: PluginKind::Quota,
                            phase: PluginPhase::AsyncRequestGate,
                            outcome: match &decision {
                                QuotaDecision::Denied(_) => PluginExecutionOutcome::Reject,
                                QuotaDecision::FailedClosed(_) => PluginExecutionOutcome::Fail,
                                QuotaDecision::NotApplied
                                | QuotaDecision::Allowed(_)
                                | QuotaDecision::ShadowDenied(_)
                                | QuotaDecision::FailedOpen(_) => PluginExecutionOutcome::Continue,
                            },
                            async_duration: Some(started_at.elapsed()),
                        },
                    );
                    match decision {
                        QuotaDecision::Denied(denial) => {
                            let rejection = super::QuotaRejectedDecision::from_quota_decision(
                                QuotaDecision::Denied(denial),
                            )
                            .map(|decision| decision.as_plugin_rejection());
                            if let Some(rejection) = rejection {
                                return Ok(PluginRequestExecutionState {
                                    route,
                                    policy,
                                    outcome: PluginRequestExecutionOutcome::Rejected {
                                        rejection,
                                        observation: PluginTerminalObservation::QuotaDenied,
                                    },
                                });
                            }
                        }
                        QuotaDecision::FailedClosed(failure) => {
                            let rejection = super::QuotaRejectedDecision::from_quota_decision(
                                QuotaDecision::FailedClosed(failure),
                            )
                            .map(|decision| decision.as_plugin_rejection());
                            if let Some(rejection) = rejection {
                                return Ok(PluginRequestExecutionState {
                                    route,
                                    policy,
                                    outcome: PluginRequestExecutionOutcome::Rejected {
                                        rejection,
                                        observation: PluginTerminalObservation::Failed,
                                    },
                                });
                            }
                        }
                        QuotaDecision::ShadowDenied(denial) => log::debug!(
                            "quota shadow deny observed: policy={} reason={}",
                            denial.policy_name,
                            denial.reason.slug()
                        ),
                        QuotaDecision::NotApplied
                        | QuotaDecision::Allowed(_)
                        | QuotaDecision::FailedOpen(_) => {}
                    }
                }
            }
            AsyncRequestPluginExecution::Reject(rejection) => {
                let observation =
                    PluginTerminalObservation::from_rejection_reason(rejection.reason());
                return Ok(PluginRequestExecutionState {
                    route,
                    policy,
                    outcome: PluginRequestExecutionOutcome::Rejected {
                        rejection,
                        observation,
                    },
                });
            }
            AsyncRequestPluginExecution::AlreadyExecuted => {
                return Ok(PluginRequestExecutionState {
                    route,
                    policy,
                    outcome: PluginRequestExecutionOutcome::AlreadyExecuted,
                });
            }
        }

        let admission = evaluate_admission(self.resilience, route.upstream_name.as_ref());
        Ok(PluginRequestExecutionState {
            route,
            policy,
            outcome: PluginRequestExecutionOutcome::Admitted {
                admission,
                mutations,
            },
        })
    }
}
