use impulse_contracts::IngressProtocol;

/// Host header behavior applied while constructing an upstream request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostPolicyMode {
    PassThrough,
    Rewrite,
    Upstream,
}

/// Validated Host policy required by protocol translation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostPolicyInput<'a> {
    pub mode: HostPolicyMode,
    pub rewrite_host: Option<&'a str>,
}

/// Forwarded-header behavior applied while constructing an upstream request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForwardedHeaderMode {
    Preserve,
    Append,
    Overwrite,
}

/// Validated forwarded-header policy required by protocol translation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForwardingPolicyInput {
    pub mode: ForwardedHeaderMode,
}

/// Request-body framing visible to the upstream protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestFramingInput {
    Empty,
    KnownLength(usize),
    Streaming,
}

/// Trailer behavior required by one protocol translation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrailerPolicyInput {
    pub advertise_upstream_support: bool,
    pub forward_downstream: bool,
}

/// Protocol constraints applied during response normalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalizationInput {
    pub protocol: IngressProtocol,
    pub preserve_upgrade: bool,
}

/// Scheme used when constructing an absolute upstream request URI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamScheme {
    Http,
    Https,
}

impl UpstreamScheme {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// Validated upstream target required by protocol translation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpstreamTargetInput<'a> {
    pub scheme: UpstreamScheme,
    pub authority: &'a str,
}

impl UpstreamTargetInput<'_> {
    pub fn uri_for_path(self, path: &str) -> String {
        let path = if path.is_empty() {
            "/"
        } else if path.starts_with('/') {
            path
        } else {
            return format!("{}://{}/{path}", self.scheme.as_str(), self.authority);
        };
        format!("{}://{}{}", self.scheme.as_str(), self.authority, path)
    }
}
