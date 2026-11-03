use std::net::IpAddr;

use http::HeaderValue;
use impulse_errors::BridgeError;

use crate::{ForwardedHeaderMode, ForwardingPolicyInput};

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ForwardedHeaderChains<'a> {
    pub(crate) forwarded: &'a [&'a [u8]],
    pub(crate) x_forwarded_for: &'a [&'a [u8]],
    pub(crate) x_forwarded_proto: &'a [&'a [u8]],
    pub(crate) x_forwarded_host: &'a [&'a [u8]],
}

#[derive(Debug, Default)]
pub(crate) struct ForwardedHeaderValues {
    pub(crate) forwarded: Option<HeaderValue>,
    pub(crate) x_forwarded_for: Option<HeaderValue>,
    pub(crate) x_forwarded_proto: Option<HeaderValue>,
    pub(crate) x_forwarded_host: Option<HeaderValue>,
}

pub fn build_forwarded_header_values(
    policy: ForwardingPolicyInput,
    inbound: ForwardedHeaderChains<'_>,
    client_ip: IpAddr,
    host_value: &str,
) -> Result<ForwardedHeaderValues, BridgeError> {
    let forwarded_current = format!(
        "for={};proto=https;host=\"{}\"",
        forwarded_for_value(client_ip),
        escape_forwarded_host(host_value),
    );
    let x_forwarded_for_current = client_ip.to_string();
    let x_forwarded_proto_current = "https";
    let x_forwarded_host_current = host_value;

    Ok(ForwardedHeaderValues {
        forwarded: merge_forwarded_chain(
            policy.mode,
            inbound.forwarded,
            Some(forwarded_current.as_bytes()),
        )?,
        x_forwarded_for: merge_forwarded_chain(
            policy.mode,
            inbound.x_forwarded_for,
            Some(x_forwarded_for_current.as_bytes()),
        )?,
        x_forwarded_proto: merge_forwarded_chain(
            policy.mode,
            inbound.x_forwarded_proto,
            Some(x_forwarded_proto_current.as_bytes()),
        )?,
        x_forwarded_host: merge_forwarded_chain(
            policy.mode,
            inbound.x_forwarded_host,
            Some(x_forwarded_host_current.as_bytes()),
        )?,
    })
}

pub fn merge_forwarded_chain(
    mode: ForwardedHeaderMode,
    inbound: &[&[u8]],
    current: Option<&[u8]>,
) -> Result<Option<HeaderValue>, BridgeError> {
    match mode {
        ForwardedHeaderMode::Preserve => join_header_chain(inbound),
        ForwardedHeaderMode::Append => {
            let mut values = smallvec::SmallVec::<[&[u8]; 4]>::with_capacity(inbound.len() + 1);
            values.extend_from_slice(inbound);
            if let Some(current) = current {
                values.push(current);
            }
            join_header_chain(&values)
        }
        ForwardedHeaderMode::Overwrite => current
            .map(HeaderValue::from_bytes)
            .transpose()
            .map_err(|_| BridgeError::InvalidHeader),
    }
}

pub fn join_header_chain(values: &[&[u8]]) -> Result<Option<HeaderValue>, BridgeError> {
    if values.is_empty() {
        return Ok(None);
    }

    let mut joined = Vec::new();
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            joined.extend_from_slice(b", ");
        }
        joined.extend_from_slice(value);
    }

    HeaderValue::from_bytes(&joined)
        .map(Some)
        .map_err(|_| BridgeError::InvalidHeader)
}

pub fn forwarded_for_value(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("\"[{}]\"", v6),
    }
}

pub fn escape_forwarded_host(host: &str) -> String {
    host.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{
        ForwardedHeaderChains, build_forwarded_header_values, escape_forwarded_host,
        forwarded_for_value, merge_forwarded_chain,
    };
    use crate::{ForwardedHeaderMode, ForwardingPolicyInput};

    #[test]
    fn escape_forwarded_host_escapes_backslash_and_quote() {
        assert_eq!(escape_forwarded_host(r#"ex"ample.com"#), r#"ex\"ample.com"#);
        assert_eq!(escape_forwarded_host(r"foo\bar"), r"foo\\bar");
        assert_eq!(escape_forwarded_host(r#"a\"b"#), r#"a\\\"b"#);
        // plain host unchanged
        assert_eq!(escape_forwarded_host("example.com"), "example.com");
    }

    #[test]
    fn forwarded_for_value_ipv4_is_bare() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        assert_eq!(forwarded_for_value(ip), "203.0.113.10");
    }

    #[test]
    fn forwarded_for_value_ipv6_is_quoted_bracket_form() {
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(forwarded_for_value(ip), "\"[::1]\"");
        let ip = IpAddr::V6("2001:db8::1".parse().unwrap());
        assert_eq!(forwarded_for_value(ip), "\"[2001:db8::1]\"");
    }

    #[test]
    fn merge_forwarded_chain_preserve_append_overwrite() {
        let inbound = [b"for=1.1.1.1".as_slice()];
        let current = b"for=2.2.2.2";

        let preserved =
            merge_forwarded_chain(ForwardedHeaderMode::Preserve, &inbound, Some(current))
                .unwrap()
                .unwrap();
        assert_eq!(preserved.as_bytes(), b"for=1.1.1.1");

        let appended = merge_forwarded_chain(ForwardedHeaderMode::Append, &inbound, Some(current))
            .unwrap()
            .unwrap();
        assert_eq!(appended.as_bytes(), b"for=1.1.1.1, for=2.2.2.2");

        let overwritten =
            merge_forwarded_chain(ForwardedHeaderMode::Overwrite, &inbound, Some(current))
                .unwrap()
                .unwrap();
        assert_eq!(overwritten.as_bytes(), b"for=2.2.2.2");
    }

    #[test]
    fn build_forwarded_header_values_overwrite_drops_inbound() {
        let policy = ForwardingPolicyInput {
            mode: ForwardedHeaderMode::Overwrite,
        };
        let inbound_fwd = [b"for=9.9.9.9".as_slice()];
        let inbound_xff = [b"9.9.9.9".as_slice()];
        let inbound_xfp = [b"http".as_slice()];
        let inbound_xfh = [b"old.example".as_slice()];
        let inbound = ForwardedHeaderChains {
            forwarded: &inbound_fwd,
            x_forwarded_for: &inbound_xff,
            x_forwarded_proto: &inbound_xfp,
            x_forwarded_host: &inbound_xfh,
        };
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        let out = build_forwarded_header_values(policy, inbound, ip, "app.example").expect("build");

        assert_eq!(out.x_forwarded_for.unwrap().as_bytes(), b"203.0.113.10");
        assert_eq!(out.x_forwarded_proto.unwrap().as_bytes(), b"https");
        assert_eq!(out.x_forwarded_host.unwrap().as_bytes(), b"app.example");

        // Bind the Bytes so the temporary is not dropped while `s` is borrowed (E0716).
        let forwarded = out.forwarded.unwrap();
        let s = std::str::from_utf8(forwarded.as_bytes()).unwrap();
        assert!(s.contains("for=203.0.113.10"));
        assert!(s.contains("proto=https"));
        assert!(s.contains("host=\"app.example\""));
        assert!(!s.contains("9.9.9.9"), "overwrite must drop inbound: {s}");
    }

    #[test]
    fn build_forwarded_header_values_append_keeps_inbound() {
        let policy = ForwardingPolicyInput {
            mode: ForwardedHeaderMode::Append,
        };
        let inbound_xff = [b"1.1.1.1".as_slice()];
        let inbound = ForwardedHeaderChains {
            forwarded: &[],
            x_forwarded_for: &inbound_xff,
            x_forwarded_proto: &[],
            x_forwarded_host: &[],
        };
        let ip = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
        let out = build_forwarded_header_values(policy, inbound, ip, "h").expect("build");
        assert_eq!(out.x_forwarded_for.unwrap().as_bytes(), b"1.1.1.1, 2.2.2.2");
    }

    #[test]
    fn build_forwarded_header_values_preserve_ignores_current_for_chain() {
        let policy = ForwardingPolicyInput {
            mode: ForwardedHeaderMode::Preserve,
        };
        let inbound_xff = [b"8.8.8.8".as_slice()];
        let inbound = ForwardedHeaderChains {
            forwarded: &[],
            x_forwarded_for: &inbound_xff,
            x_forwarded_proto: &[],
            x_forwarded_host: &[],
        };
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let out = build_forwarded_header_values(policy, inbound, ip, "h").expect("build");
        // Preserve keeps only inbound chain values for XFF
        assert_eq!(out.x_forwarded_for.unwrap().as_bytes(), b"8.8.8.8");
    }
}
