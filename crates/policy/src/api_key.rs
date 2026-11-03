use subtle::ConstantTimeEq;

use crate::RequestHeaderLookup;

/// Validated API-key policy required to authenticate one request.
#[derive(Clone, Copy)]
pub struct ApiKeyPolicyInput<'a> {
    header_name: &'a str,
    accepted_keys: &'a [String],
}

impl<'a> ApiKeyPolicyInput<'a> {
    #[must_use]
    pub const fn new(header_name: &'a str, accepted_keys: &'a [String]) -> Self {
        Self {
            header_name,
            accepted_keys,
        }
    }
}

/// Returns whether the request satisfies its optional API-key policy.
#[must_use]
pub fn api_key_is_authorized(
    policy: Option<ApiKeyPolicyInput<'_>>,
    header_lookup: Option<&RequestHeaderLookup<'_>>,
) -> bool {
    let Some(policy) = policy else {
        return true;
    };
    let Some(provided) = resolve_credential(policy.header_name, header_lookup) else {
        return false;
    };
    let provided = provided.trim();

    policy
        .accepted_keys
        .iter()
        .any(|expected| bool::from(provided.as_bytes().ct_eq(expected.as_bytes())))
}

fn resolve_credential(
    header_name: &str,
    header_lookup: Option<&RequestHeaderLookup<'_>>,
) -> Option<String> {
    let credential = header_lookup.and_then(|lookup| lookup(header_name))?;
    (!credential.trim().is_empty()).then_some(credential)
}
