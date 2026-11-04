use impulse_contracts::PluginHeaderLookup;
use subtle::ConstantTimeEq;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiKeyAuthorization {
    Authorized,
    Missing,
    Invalid,
}

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

/// Resolves and verifies the request credential for one API-key policy.
#[must_use]
pub fn evaluate_api_key(
    policy: ApiKeyPolicyInput<'_>,
    header_lookup: Option<&PluginHeaderLookup<'_>>,
) -> ApiKeyAuthorization {
    let Some(raw) = header_lookup.and_then(|lookup| lookup(policy.header_name)) else {
        return ApiKeyAuthorization::Missing;
    };
    let Ok(provided) = std::str::from_utf8(raw) else {
        return ApiKeyAuthorization::Invalid;
    };
    let provided = provided.trim();
    if provided.is_empty() {
        return ApiKeyAuthorization::Invalid;
    }

    if policy
        .accepted_keys
        .iter()
        .any(|expected| bool::from(provided.as_bytes().ct_eq(expected.as_bytes())))
    {
        ApiKeyAuthorization::Authorized
    } else {
        ApiKeyAuthorization::Invalid
    }
}
