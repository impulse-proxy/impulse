use std::{future::Future, time::Instant};

use impulse_contracts::{
    AuthChallengeKind, PluginExecutionObservation, PluginExecutionOutcome, PluginHeaderMutation,
    PluginPhase, PluginRejection, PluginRejectionReason, PluginRequestView,
};
use impulse_policy::{ApiKeyAuthorization, ApiKeyPolicyInput, evaluate_api_key};

use crate::{
    CompiledAsyncRequestPlugin, CompiledPluginPlan, CompiledRequestPlugin,
    rate_limit::ScopedRateLimitDecision,
};

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
    mut observe: impl FnMut(PluginExecutionObservation),
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
        let decision = match plugin {
            CompiledRequestPlugin::ApiKeyAuth(policy) => match evaluate_api_key(
                ApiKeyPolicyInput::new(&policy.header_name, &policy.accepted_keys),
                request.headers,
            ) {
                ApiKeyAuthorization::Authorized => SynchronousRequestPluginDecision::Continue,
                ApiKeyAuthorization::Missing => {
                    SynchronousRequestPluginDecision::Reject(PluginRejection::unauthorized(
                        PluginRejectionReason::ApiKeyMissing,
                        AuthChallengeKind::ApiKey,
                    ))
                }
                ApiKeyAuthorization::Invalid => {
                    SynchronousRequestPluginDecision::Reject(PluginRejection::unauthorized(
                        PluginRejectionReason::ApiKeyInvalid,
                        AuthChallengeKind::ApiKey,
                    ))
                }
            },
            CompiledRequestPlugin::ScopedRateLimit(compiled) => match compiled.evaluate(request) {
                ScopedRateLimitDecision::Deny {
                    retry_after_seconds,
                } => SynchronousRequestPluginDecision::Reject(PluginRejection::rate_limited(
                    retry_after_seconds,
                )),
                ScopedRateLimitDecision::Admit => SynchronousRequestPluginDecision::Continue,
            },
            _ => evaluate(plugin, request),
        };
        observe(PluginExecutionObservation {
            kind: plugin.kind(),
            phase: PluginPhase::RequestGate,
            outcome: request_decision_outcome(&decision),
            async_duration: None,
        });
        match decision {
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
    mut observe: impl FnMut(PluginExecutionObservation),
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
        let started_at = Instant::now();
        let decision = evaluate(plugin, request).await;
        observe(PluginExecutionObservation {
            kind: plugin.kind(),
            phase: PluginPhase::AsyncRequestGate,
            outcome: async_request_decision_outcome(&decision),
            async_duration: Some(started_at.elapsed()),
        });
        match decision {
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

fn rejection_outcome(reason: PluginRejectionReason) -> PluginExecutionOutcome {
    match reason {
        PluginRejectionReason::JwksUnavailable
        | PluginRejectionReason::ExternalAuthUnavailable
        | PluginRejectionReason::QuotaUnavailable => PluginExecutionOutcome::Fail,
        _ => PluginExecutionOutcome::Reject,
    }
}

fn request_decision_outcome(decision: &SynchronousRequestPluginDecision) -> PluginExecutionOutcome {
    match decision {
        SynchronousRequestPluginDecision::Continue
        | SynchronousRequestPluginDecision::Mutate(_) => PluginExecutionOutcome::Continue,
        SynchronousRequestPluginDecision::Reject(rejection) => {
            rejection_outcome(rejection.reason())
        }
    }
}

fn async_request_decision_outcome(decision: &AsyncRequestPluginDecision) -> PluginExecutionOutcome {
    match decision {
        AsyncRequestPluginDecision::Continue | AsyncRequestPluginDecision::Mutate(_) => {
            PluginExecutionOutcome::Continue
        }
        AsyncRequestPluginDecision::Reject(rejection) => rejection_outcome(rejection.reason()),
    }
}
