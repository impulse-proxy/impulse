use impulse_errors::BridgeError;

use crate::{HostPolicyInput, HostPolicyMode, UpstreamTargetInput};

pub fn resolve_upstream_host_value<'a>(
    endpoint: UpstreamTargetInput<'a>,
    host_policy: HostPolicyInput<'a>,
    request_authority: Option<&'a str>,
    host_header: Option<&'a str>,
) -> Result<&'a str, BridgeError> {
    match host_policy.mode {
        HostPolicyMode::PassThrough => Ok(request_authority
            .or(host_header)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(endpoint.authority)),
        HostPolicyMode::Rewrite => host_policy
            .rewrite_host
            .filter(|value| !value.trim().is_empty())
            .ok_or(BridgeError::InvalidHeader),
        HostPolicyMode::Upstream => Ok(endpoint.authority),
    }
}
