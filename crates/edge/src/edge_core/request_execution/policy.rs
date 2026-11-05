use std::sync::Arc;

use impulse_config::{
    config::{ForwardedHeaderPolicy, UpstreamHostPolicy},
    runtime::RuntimeUpstreamPolicy,
};
use impulse_plugins::CompiledPluginPlan;

/// Resolves the policies selected by route resolution independently of the
/// ingress protocol.
pub(crate) fn resolve_policy(
    upstream_policy: &RuntimeUpstreamPolicy,
    plugin_plan: Arc<CompiledPluginPlan>,
) -> ResolvedRequestPolicy {
    ResolvedRequestPolicy {
        plugin_plan,
        local_auth_policy: upstream_policy.clone(),
        host_policy: upstream_policy.host.0.clone(),
        forwarded_header_policy: upstream_policy.forwarded_headers.0.clone(),
    }
}

/// Protocol-neutral policies applied to a request after its route resolves.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedRequestPolicy {
    /// Generation-pinned plugin plan selected with this upstream policy.
    pub(crate) plugin_plan: Arc<CompiledPluginPlan>,
    /// Local API-key and JWT/JWKS policy evaluated before external auth.
    pub(crate) local_auth_policy: RuntimeUpstreamPolicy,
    pub(crate) host_policy: UpstreamHostPolicy,
    pub(crate) forwarded_header_policy: ForwardedHeaderPolicy,
}

#[cfg(test)]
mod tests {
    use impulse_config::{
        config::{ForwardedHeaderPolicy, ForwardedHeaderPolicyMode, UpstreamHostPolicyMode},
        runtime::{RuntimeForwardedHeaderPolicy, RuntimeHostPolicy},
    };

    use super::*;

    #[test]
    fn shared_policy_preserves_adapter_forwarding_configuration() {
        let upstream_policy = RuntimeUpstreamPolicy {
            host: RuntimeHostPolicy(UpstreamHostPolicy {
                mode: UpstreamHostPolicyMode::Rewrite,
                host: Some("backend.example.com".to_string()),
            }),
            forwarded_headers: RuntimeForwardedHeaderPolicy(ForwardedHeaderPolicy {
                mode: ForwardedHeaderPolicyMode::Append,
            }),
            ..RuntimeUpstreamPolicy::default()
        };

        let resolved = resolve_policy(&upstream_policy, Arc::new(CompiledPluginPlan::default()));

        assert_eq!(
            resolved.host_policy.host.as_deref(),
            Some("backend.example.com")
        );
        assert_eq!(resolved.host_policy.mode, UpstreamHostPolicyMode::Rewrite);
        assert_eq!(
            resolved.forwarded_header_policy.mode,
            ForwardedHeaderPolicyMode::Append
        );
    }
}
