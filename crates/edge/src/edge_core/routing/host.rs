use std::borrow::Cow;

#[inline(always)]
fn parsed_host_for_routing(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let host = if let Some(rest) = trimmed.strip_prefix('[') {
        let end = rest.find(']')?;
        &rest[..end]
    } else if let Some((candidate_host, candidate_port)) = trimmed.rsplit_once(':') {
        if !candidate_host.contains(':') && candidate_port.chars().all(|c| c.is_ascii_digit()) {
            candidate_host
        } else {
            trimmed
        }
    } else {
        trimmed
    };

    let host = host.trim_end_matches('.');
    if host.is_empty() { None } else { Some(host) }
}

pub(crate) fn normalize_host_for_routing(raw: &str) -> Option<Cow<'_, str>> {
    let host = parsed_host_for_routing(raw)?;
    if host_has_uppercase_ascii(host) {
        Some(Cow::Owned(host.to_ascii_lowercase()))
    } else {
        Some(Cow::Borrowed(host))
    }
}

#[inline(always)]
fn host_has_uppercase_ascii(host: &str) -> bool {
    host.bytes().any(|byte| byte.is_ascii_uppercase())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfiguredHostPattern {
    Exact(String),
    WildcardSuffix(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfiguredHostPatternRef<'a> {
    Exact(&'a str),
    WildcardSuffix(&'a str),
}

pub fn parse_configured_host_pattern(raw: &str) -> Option<ConfiguredHostPattern> {
    let normalized = normalize_host_for_routing(raw)?;
    let Some(wildcard_suffix) = normalized.strip_prefix("*.") else {
        return Some(ConfiguredHostPattern::Exact(normalized.into_owned()));
    };
    if wildcard_suffix.is_empty() || wildcard_suffix.contains('*') {
        return Some(ConfiguredHostPattern::Exact(normalized.into_owned()));
    }
    Some(ConfiguredHostPattern::WildcardSuffix(
        wildcard_suffix.to_string(),
    ))
}

pub fn parse_configured_host_pattern_ref(raw: &str) -> Option<ConfiguredHostPatternRef<'_>> {
    let host = parsed_host_for_routing(raw)?;
    let Some(wildcard_suffix) = host.strip_prefix("*.") else {
        return Some(ConfiguredHostPatternRef::Exact(host));
    };
    if wildcard_suffix.is_empty() || wildcard_suffix.contains('*') {
        return Some(ConfiguredHostPatternRef::Exact(host));
    }
    Some(ConfiguredHostPatternRef::WildcardSuffix(wildcard_suffix))
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::{
        ConfiguredHostPattern, ConfiguredHostPatternRef, normalize_host_for_routing,
        parse_configured_host_pattern, parse_configured_host_pattern_ref,
    };

    #[test]
    fn normalize_host_for_routing_lowercases_and_strips_port_and_trailing_dot() {
        assert_eq!(
            normalize_host_for_routing(" Example.COM.:443 "),
            Some(Cow::Owned("example.com".to_string()))
        );
    }

    #[test]
    fn normalize_host_for_routing_preserves_already_normalized_host() {
        assert_eq!(
            normalize_host_for_routing("api.example.com"),
            Some(Cow::Borrowed("api.example.com"))
        );
    }

    #[test]
    fn normalize_host_for_routing_parses_ipv6_authority() {
        assert_eq!(
            normalize_host_for_routing("[2001:db8::1]:443"),
            Some(Cow::Borrowed("2001:db8::1"))
        );
    }

    #[test]
    fn normalize_host_for_routing_rejects_invalid_input() {
        assert_eq!(normalize_host_for_routing(""), None);
        assert_eq!(normalize_host_for_routing("   "), None);
        assert_eq!(normalize_host_for_routing("[missing-end"), None);
    }

    #[test]
    fn parse_configured_host_pattern_distinguishes_exact_and_wildcard_hosts() {
        assert_eq!(
            parse_configured_host_pattern("Api.Example.com."),
            Some(ConfiguredHostPattern::Exact("api.example.com".to_string()))
        );
        assert_eq!(
            parse_configured_host_pattern("*.Example.com"),
            Some(ConfiguredHostPattern::WildcardSuffix(
                "example.com".to_string()
            ))
        );
    }

    #[test]
    fn parse_configured_host_pattern_rejects_invalid_input() {
        assert_eq!(parse_configured_host_pattern(""), None);
        assert_eq!(parse_configured_host_pattern("[missing-end"), None);
    }

    #[test]
    fn parse_configured_host_pattern_ref_distinguishes_exact_and_wildcard_hosts() {
        assert_eq!(
            parse_configured_host_pattern_ref("api.example.com"),
            Some(ConfiguredHostPatternRef::Exact("api.example.com"))
        );
        assert_eq!(
            parse_configured_host_pattern_ref("*.example.com"),
            Some(ConfiguredHostPatternRef::WildcardSuffix("example.com"))
        );
    }

    #[test]
    fn parse_configured_host_pattern_ref_rejects_invalid_input() {
        assert_eq!(parse_configured_host_pattern_ref(""), None);
        assert_eq!(parse_configured_host_pattern_ref("[missing-end"), None);
    }
}
