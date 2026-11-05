use std::{
    collections::HashMap,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::{Instant, SystemTime},
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
                    evaluate_compiled_jwt_policy(jwt, upstream_policy, request)
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
                let external_auth_deferred =
                    observation.kind == PluginKind::ExternalAuth && external_auth_headers.is_none();
                if observation.kind != PluginKind::Quota && !external_auth_deferred {
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
                        execute_compiled_external_auth(request, input).await
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
                    && plugin_plan
                        .async_request_gate()
                        .iter()
                        .any(|plugin| matches!(plugin, CompiledAsyncRequestPlugin::Quota(_)))
                {
                    let started_at = Instant::now();
                    let decision = super::execute_compiled_quota_plugin(
                        &plugin_plan,
                        plugin_request,
                        &mutations,
                    )
                    .await;
                    self.metrics.plugin_observations().record_execution(
                        PluginExecutionObservation {
                            kind: PluginKind::Quota,
                            phase: PluginPhase::AsyncRequestGate,
                            outcome: decision.as_ref().map_or(
                                PluginExecutionOutcome::Continue,
                                |rejection| {
                                    if rejection.status == http::StatusCode::TOO_MANY_REQUESTS {
                                        PluginExecutionOutcome::Reject
                                    } else {
                                        PluginExecutionOutcome::Fail
                                    }
                                },
                            ),
                            async_duration: Some(started_at.elapsed()),
                        },
                    );
                    if let Some(decision) = decision {
                        let observation = if decision.status == http::StatusCode::TOO_MANY_REQUESTS
                        {
                            PluginTerminalObservation::QuotaDenied
                        } else {
                            PluginTerminalObservation::Failed
                        };
                        return Ok(PluginRequestExecutionState {
                            route,
                            policy,
                            outcome: PluginRequestExecutionOutcome::Rejected {
                                rejection: decision.as_plugin_rejection(),
                                observation,
                            },
                        });
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

fn bearer_token(raw: &str) -> Option<&str> {
    let raw = raw.trim();
    let split = raw.find(char::is_whitespace)?;
    let (scheme, rest) = raw.split_at(split);
    let token = rest.trim_start();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

pub(crate) async fn execute_compiled_external_auth(
    request: crate::runtime::connection::auth::ExternalAuthRequest,
    input: &impulse_plugins::ExternalAuthInput,
) -> AsyncRequestPluginDecision {
    use impulse_contracts::PluginRejectionReason;

    use crate::runtime::connection::auth::{
        ExternalAuthDecision, ExternalAuthExecutionPolicy, ExternalAuthStateTransition,
        resolve_external_auth_state_transition,
    };

    let policy = crate::runtime::connection::auth::external_auth_policy_from_plugin(input);
    let disposition = ExternalAuthExecutionPolicy::from_external_auth(&policy).disposition();
    match resolve_external_auth_state_transition(
        crate::quic_listener::execute_external_auth_request(request, policy).await,
        disposition,
    ) {
        ExternalAuthStateTransition::Admitted {
            request_header_mutations,
        } => external_auth_decision(ExternalAuthDecision::Allow {
            request_header_mutations,
        }),
        ExternalAuthStateTransition::RejectedAuthDenied { decision } => {
            external_auth_decision(decision)
        }
        ExternalAuthStateTransition::RejectedAuthUnavailable { status, body, .. }
        | ExternalAuthStateTransition::TimedOutAuth { status, body } => plugin_rejection(
            PluginRejectionReason::ExternalAuthUnavailable,
            status,
            Vec::new(),
            body.to_vec(),
        ),
    }
}

fn plugin_mutation(
    mutation: impulse_contracts::HeaderMutation,
) -> Option<impulse_contracts::PluginHeaderMutation> {
    use impulse_contracts::{HeaderMutation, PluginHeaderMutation};

    match mutation {
        HeaderMutation::Upsert { name, value } => PluginHeaderMutation::upsert(&name, &value).ok(),
        HeaderMutation::Remove { name } => PluginHeaderMutation::remove(&name).ok(),
    }
}

fn plugin_response_headers(
    headers: &[(String, String)],
    extra: Option<(&str, &str)>,
) -> Vec<impulse_contracts::PluginResponseHeader> {
    use impulse_contracts::{PluginRejection, PluginResponseHeader};

    headers
        .iter()
        .filter_map(|(name, value)| {
            PluginResponseHeader::new(name.as_bytes(), value.as_bytes()).ok()
        })
        .chain(extra.into_iter().filter_map(|(name, value)| {
            PluginResponseHeader::new(name.as_bytes(), value.as_bytes()).ok()
        }))
        .take(PluginRejection::MAX_HEADERS)
        .collect()
}

fn plugin_rejection(
    reason: impulse_contracts::PluginRejectionReason,
    status: http::StatusCode,
    headers: Vec<impulse_contracts::PluginResponseHeader>,
    body: Vec<u8>,
) -> AsyncRequestPluginDecision {
    use impulse_contracts::{PluginRejection, PluginRejectionReason};

    match PluginRejection::new(reason, status, headers, body) {
        Ok(rejection) => AsyncRequestPluginDecision::Reject(rejection),
        Err(_) => AsyncRequestPluginDecision::Reject(
            PluginRejection::new(
                PluginRejectionReason::ExternalAuthUnavailable,
                http::StatusCode::SERVICE_UNAVAILABLE,
                Vec::new(),
                b"external auth unavailable\n".to_vec(),
            )
            .unwrap_or_else(|_| unreachable!("static external-auth rejection is bounded")),
        ),
    }
}

fn external_auth_decision(
    decision: crate::runtime::connection::auth::ExternalAuthDecision,
) -> AsyncRequestPluginDecision {
    use impulse_contracts::PluginRejectionReason;

    use crate::runtime::connection::auth::ExternalAuthDecision;

    match decision {
        ExternalAuthDecision::Allow {
            request_header_mutations,
        } => AsyncRequestPluginDecision::Mutate(
            request_header_mutations
                .into_iter()
                .filter_map(plugin_mutation)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        ),
        ExternalAuthDecision::Deny(response) => plugin_rejection(
            PluginRejectionReason::ExternalAuthDenied,
            response.status,
            plugin_response_headers(&response.headers, None),
            response.body,
        ),
        ExternalAuthDecision::Redirect(response) => plugin_rejection(
            PluginRejectionReason::ExternalAuthDenied,
            response.status,
            plugin_response_headers(
                &response.headers,
                Some((http::header::LOCATION.as_str(), &response.location)),
            ),
            Vec::new(),
        ),
        ExternalAuthDecision::Challenge(response) => plugin_rejection(
            PluginRejectionReason::ExternalAuthDenied,
            response.status,
            plugin_response_headers(
                &response.headers,
                Some((
                    http::header::WWW_AUTHENTICATE.as_str(),
                    &response.www_authenticate,
                )),
            ),
            response.body,
        ),
    }
}

fn evaluate_compiled_jwt_policy(
    compiled: &impulse_plugins::CompiledJwtAuth,
    policy: &RuntimeUpstreamPolicy,
    request: PluginRequestView<'_>,
) -> SynchronousRequestPluginDecision {
    use impulse_contracts::{AuthChallengeKind, PluginRejection, PluginRejectionReason};

    let reject = |reason| {
        SynchronousRequestPluginDecision::Reject(PluginRejection::unauthorized(
            reason,
            AuthChallengeKind::Bearer,
        ))
    };
    let input = compiled.input();
    if compiled.generation() != request.generation {
        return reject(if input.jwks_url.is_some() {
            PluginRejectionReason::JwksUnavailable
        } else {
            PluginRejectionReason::JwtInvalid
        });
    }
    let Some(jwt) = policy.upstream_auth.jwt.as_ref() else {
        return reject(PluginRejectionReason::JwtInvalid);
    };
    let Some(raw) = request.header(http::header::AUTHORIZATION.as_str()) else {
        return reject(PluginRejectionReason::JwtMissing);
    };
    let Ok(raw) = std::str::from_utf8(raw) else {
        return reject(PluginRejectionReason::JwtInvalid);
    };
    let Some(token) = bearer_token(raw) else {
        return reject(PluginRejectionReason::JwtInvalid);
    };
    let claims = match crate::quic_listener::validate_jwt_token_for_generation(
        token,
        jwt,
        compiled.generation(),
        SystemTime::now(),
    ) {
        Ok(validated) => validated.claims,
        Err(failure) => {
            crate::quic_listener::observe_jwt_validation_failure(jwt, token, &failure);
            crate::quic_listener::log_jwt_validation_rejection(jwt, token, &failure);
            let reason = match failure.reason {
                impulse_policy::JwtValidationFailureReason::KeySourceUnavailable => {
                    PluginRejectionReason::JwksUnavailable
                }
                impulse_policy::JwtValidationFailureReason::MissingExpiration
                | impulse_policy::JwtValidationFailureReason::TokenExpired
                | impulse_policy::JwtValidationFailureReason::TokenNotYetValid
                | impulse_policy::JwtValidationFailureReason::TokenIssuedInFuture
                | impulse_policy::JwtValidationFailureReason::IssuerMismatch
                | impulse_policy::JwtValidationFailureReason::AudienceMismatch => {
                    PluginRejectionReason::JwtClaimsRejected
                }
                _ => PluginRejectionReason::JwtInvalid,
            };
            return reject(reason);
        }
    };
    if !impulse_policy::jwt_claims_satisfy_requirements(
        &claims,
        impulse_policy::JwtClaimsRequirements {
            required_scopes: &input.required_scopes,
            required_roles: &input.required_roles,
        },
    ) {
        return reject(PluginRejectionReason::JwtClaimsRejected);
    }
    SynchronousRequestPluginDecision::Continue
}
