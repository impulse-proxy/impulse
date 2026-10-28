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
