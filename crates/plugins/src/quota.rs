use std::collections::HashSet;

use impulse_contracts::{PluginHeaderMutation, PluginRequestView};
use impulse_policy::quota::{
    QuotaBackendFailurePolicy, QuotaCounterBackend, QuotaCounterBackendError, QuotaDecision,
    QuotaEnforcementMode, QuotaIdentityContext, QuotaLocalFallbackPolicy, QuotaPolicyRuntime,
    QuotaRuntime, QuotaSelectorKeySpec, QuotaSelectorMatcher, QuotaWindowPolicy,
    SharedDistributedQuotaCounterBackend, evaluate_admission_quota,
};

use crate::{
    QuotaBackendFailureInput, QuotaCounterBackendInput, QuotaEnforcementInput, QuotaInput,
    QuotaPolicyInput, QuotaSelectorInput, QuotaWindowInput, RequestKeyInput,
};

pub struct CompiledQuota {
    input: QuotaInput,
    runtime: QuotaRuntime,
    backend: SharedDistributedQuotaCounterBackend,
    initialization_error: Option<QuotaCounterBackendError>,
}

impl CompiledQuota {
    pub(crate) fn new(input: QuotaInput) -> Self {
        let runtime = quota_runtime(&input);
        let (backend, initialization_error) = runtime.enforcement_backend();
        Self {
            input,
            runtime,
            backend,
            initialization_error,
        }
    }

    pub async fn evaluate(
        &self,
        request: PluginRequestView<'_>,
        mutations: &[PluginHeaderMutation],
    ) -> QuotaDecision {
        let header_lookup = |name: &str| {
            if let Some(mutation) = mutations
                .iter()
                .rev()
                .find(|mutation| mutation.name().as_str().eq_ignore_ascii_case(name))
            {
                return mutation
                    .value()
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
            }
            request
                .header(name)
                .and_then(|value| std::str::from_utf8(value).ok())
                .map(str::to_owned)
        };
        let context = QuotaIdentityContext::new(
            request.route_id,
            request.method,
            request.path,
            request.authority,
            None,
            Some(request.peer_address),
            Some(&header_lookup),
        );
        evaluate_admission_quota(&self.runtime, self.backend.as_ref(), &context).await
    }

    pub fn runtime(&self) -> &QuotaRuntime {
        &self.runtime
    }

    pub fn initialization_error(&self) -> Option<&QuotaCounterBackendError> {
        self.initialization_error.as_ref()
    }
}

fn quota_runtime(input: &QuotaInput) -> QuotaRuntime {
    QuotaRuntime {
        enabled: true,
        enforcement: match input.enforcement {
            QuotaEnforcementInput::Shadow => QuotaEnforcementMode::Shadow,
            QuotaEnforcementInput::Enforce => QuotaEnforcementMode::Enforce,
        },
        backend_failure_policy: match input.backend_failure_policy {
            QuotaBackendFailureInput::FailOpen => QuotaBackendFailurePolicy::FailOpen,
            QuotaBackendFailureInput::FailClosed => QuotaBackendFailurePolicy::FailClosed,
        },
        backend: match &input.backend {
            QuotaCounterBackendInput::InMemory { key_prefix } => QuotaCounterBackend::InMemory {
                key_prefix: key_prefix.clone(),
            },
            QuotaCounterBackendInput::Redis {
                url,
                key_prefix,
                connect_timeout,
                command_timeout,
                max_inflight,
            } => QuotaCounterBackend::Redis {
                url: url.clone(),
                key_prefix: key_prefix.clone(),
                connect_timeout: *connect_timeout,
                command_timeout: *command_timeout,
                max_inflight: *max_inflight,
            },
        },
        local_fallback: input
            .local_fallback
            .as_ref()
            .map(|fallback| QuotaLocalFallbackPolicy {
                key_prefix: fallback.key_prefix.clone(),
                max_entries: fallback.max_entries,
            }),
        policies: input.policies.iter().map(quota_policy).collect(),
    }
}

fn quota_policy(input: &QuotaPolicyInput) -> QuotaPolicyRuntime {
    QuotaPolicyRuntime {
        name: input.name.clone(),
        route_allowlist: input
            .route_allowlist
            .iter()
            .cloned()
            .collect::<HashSet<_>>(),
        selector: quota_selector(&input.selector),
        burst: input.burst.as_ref().map(quota_window),
        sustained: input.sustained.as_ref().map(quota_window),
    }
}

fn quota_selector(input: &QuotaSelectorInput) -> QuotaSelectorMatcher {
    QuotaSelectorMatcher {
        route: input.route,
        tenant: input.tenant.as_ref().map(quota_key),
        token: input.token.as_ref().map(quota_key),
        client: input.client.as_ref().map(quota_key),
    }
}

fn quota_window(input: &QuotaWindowInput) -> QuotaWindowPolicy {
    QuotaWindowPolicy {
        requests: input.requests,
        window: input.window,
    }
}

fn quota_key(input: &RequestKeyInput) -> QuotaSelectorKeySpec {
    match input {
        RequestKeyInput::Path => QuotaSelectorKeySpec::Path,
        RequestKeyInput::Authority => QuotaSelectorKeySpec::Authority,
        RequestKeyInput::Method => QuotaSelectorKeySpec::Method,
        RequestKeyInput::Cid => QuotaSelectorKeySpec::Cid,
        RequestKeyInput::StickyCid => QuotaSelectorKeySpec::StickyCid,
        RequestKeyInput::PeerIp => QuotaSelectorKeySpec::PeerIp,
        RequestKeyInput::ClientIp => QuotaSelectorKeySpec::ClientIp,
        RequestKeyInput::BearerToken => QuotaSelectorKeySpec::BearerToken,
        RequestKeyInput::Header(name) => QuotaSelectorKeySpec::Header(name.clone()),
        RequestKeyInput::Cookie(name) => QuotaSelectorKeySpec::Cookie(name.clone()),
        RequestKeyInput::Query(name) => QuotaSelectorKeySpec::Query(name.clone()),
    }
}

impl PartialEq for CompiledQuota {
    fn eq(&self, other: &Self) -> bool {
        self.input == other.input
    }
}

impl Eq for CompiledQuota {}
