use impulse_config::{
    config::{ForwardedHeaderPolicy, UpstreamHostPolicy},
    runtime::{RuntimeExternalAuth, RuntimeResponseCompressionPolicy, RuntimeUpstreamPolicy},
};

use crate::runtime::connection::auth::{ExternalAuthFailureDisposition, ExternalAuthTaskConfig};

/// Resolves the policies selected by route resolution independently of the
/// ingress protocol.
pub(crate) fn resolve_policy(upstream_policy: &RuntimeUpstreamPolicy) -> ResolvedRequestPolicy {
    ResolvedRequestPolicy {
        local_auth_policy: upstream_policy.clone(),
        host_policy: upstream_policy.host.0.clone(),
        forwarded_header_policy: upstream_policy.forwarded_headers.0.clone(),
        response_compression: upstream_policy.response_compression.clone(),
        external_auth: upstream_policy
            .upstream_auth
            .external_auth
            .clone()
            .map(ExternalAuthPlan::new),
    }
}

/// Protocol-neutral policies applied to a request after its route resolves.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedRequestPolicy {
    /// Local API-key and JWT/JWKS policy evaluated before external auth.
    pub(crate) local_auth_policy: RuntimeUpstreamPolicy,
    pub(crate) host_policy: UpstreamHostPolicy,
    pub(crate) forwarded_header_policy: ForwardedHeaderPolicy,
    pub(crate) response_compression: RuntimeResponseCompressionPolicy,
    pub(crate) external_auth: Option<ExternalAuthPlan>,
}

/// External-auth work selected by the resolved request policy.
#[derive(Clone, Debug)]
pub(crate) struct ExternalAuthPlan {
    pub(crate) policy: RuntimeExternalAuth,
    pub(crate) disposition: ExternalAuthFailureDisposition,
}

impl ExternalAuthPlan {
    fn new(policy: RuntimeExternalAuth) -> Self {
        Self {
            disposition: ExternalAuthTaskConfig::from_external_auth(&policy).disposition,
            policy,
        }
    }
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

        let resolved = resolve_policy(&upstream_policy);

        assert_eq!(
            resolved.host_policy.host.as_deref(),
            Some("backend.example.com")
        );
        assert_eq!(resolved.host_policy.mode, UpstreamHostPolicyMode::Rewrite);
        assert_eq!(
            resolved.forwarded_header_policy.mode,
            ForwardedHeaderPolicyMode::Append
        );
        assert!(resolved.external_auth.is_none());
    }
}
