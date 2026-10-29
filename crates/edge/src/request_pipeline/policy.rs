use impulse_config::{
    config::{ForwardedHeaderPolicy, UpstreamHostPolicy},
    runtime::{
        RuntimeExternalAuth, RuntimeExternalAuthFailureMode, RuntimeExternalAuthRequestHeader,
        RuntimeResponseCompressionPolicy, RuntimeUpstreamPolicy,
    },
};
use impulse_policy::{
    ExternalAuthFailureMode, ExternalAuthPlan, ExternalAuthPolicy, ExternalAuthRequestHeader,
};

fn external_auth_failure_mode(mode: RuntimeExternalAuthFailureMode) -> ExternalAuthFailureMode {
    match mode {
        RuntimeExternalAuthFailureMode::FailOpen => ExternalAuthFailureMode::FailOpen,
        RuntimeExternalAuthFailureMode::FailClosed => ExternalAuthFailureMode::FailClosed,
    }
}

fn external_auth_request_headers(
    headers: &[RuntimeExternalAuthRequestHeader],
) -> Vec<ExternalAuthRequestHeader> {
    headers
        .iter()
        .map(|header| ExternalAuthRequestHeader {
            name: header.name.clone(),
            value: header.value.clone(),
        })
        .collect()
}

fn external_auth_policy(policy: &RuntimeExternalAuth) -> ExternalAuthPolicy {
    match policy {
        RuntimeExternalAuth::Http {
            endpoint,
            request_headers,
            response_header_allowlist,
            timeout,
            failure_mode,
        } => ExternalAuthPolicy::Http {
            endpoint: endpoint.clone(),
            request_headers: external_auth_request_headers(request_headers),
            response_header_allowlist: response_header_allowlist.clone(),
            timeout: *timeout,
            failure_mode: external_auth_failure_mode(*failure_mode),
        },
        RuntimeExternalAuth::Oidc {
            discovery_url,
            issuer_url,
            client_id,
            client_secret,
            audience,
            scopes,
            request_headers,
            response_header_allowlist,
            timeout,
            failure_mode,
        } => ExternalAuthPolicy::Oidc {
            discovery_url: discovery_url.clone(),
            issuer_url: issuer_url.clone(),
            client_id: client_id.clone(),
            client_secret: client_secret.clone(),
            audience: audience.clone(),
            scopes: scopes.clone(),
            request_headers: external_auth_request_headers(request_headers),
            response_header_allowlist: response_header_allowlist.clone(),
            timeout: *timeout,
            failure_mode: external_auth_failure_mode(*failure_mode),
        },
    }
}

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
            .as_ref()
            .map(external_auth_policy)
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
