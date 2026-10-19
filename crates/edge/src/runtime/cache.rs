use http::uri::Authority;
use pingora_cache::key::CacheKey;

use crate::routing::util::canonical_request_target;

const CACHE_KEY_NAMESPACE: &[u8] = b"impulse-response-cache-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCacheRepresentation {
    Get,
    Head,
}

impl ResponseCacheRepresentation {
    fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Get => b"get",
            Self::Head => b"head",
        }
    }
}

pub struct ResponseCacheKeyInput<'a> {
    pub scheme: &'a str,
    pub authority: &'a str,
    pub path_and_query: &'a str,
    pub representation: ResponseCacheRepresentation,
    pub accept_encoding: Option<&'a str>,
    pub generation: u64,
}

pub fn canonical_response_cache_key(input: ResponseCacheKeyInput<'_>) -> Option<CacheKey> {
    let scheme = match input.scheme.trim().to_ascii_lowercase().as_str() {
        "http" => "http",
        "https" => "https",
        _ => return None,
    };
    let authority = canonical_authority(input.authority, scheme)?;
    if !input.path_and_query.starts_with('/') {
        return None;
    }
    let target = canonical_request_target(input.path_and_query);
    let accept_encoding = canonical_accept_encoding(input.accept_encoding);

    let mut primary = Vec::with_capacity(
        CACHE_KEY_NAMESPACE.len()
            + scheme.len()
            + authority.len()
            + target.len()
            + accept_encoding.len()
            + 64,
    );
    push_component(&mut primary, CACHE_KEY_NAMESPACE);
    push_component(&mut primary, &input.generation.to_be_bytes());
    push_component(&mut primary, scheme.as_bytes());
    push_component(&mut primary, authority.as_bytes());
    push_component(&mut primary, target.as_bytes());
    push_component(&mut primary, input.representation.as_bytes());
    push_component(&mut primary, b"accept-encoding");
    push_component(&mut primary, accept_encoding.as_bytes());

    Some(CacheKey::new(primary, ""))
}

fn canonical_authority(raw: &str, scheme: &str) -> Option<String> {
    let authority = raw.trim().parse::<Authority>().ok()?;
    let host = authority.host().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let mut canonical = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    if let Some(port) = authority.port_u16()
        && !matches!((scheme, port), ("http", 80) | ("https", 443))
    {
        canonical.push(':');
        canonical.push_str(&port.to_string());
    }
    Some(canonical)
}

fn canonical_accept_encoding(raw: Option<&str>) -> String {
    let mut encodings = raw
        .unwrap_or_default()
        .split(',')
        .filter_map(|encoding| {
            let normalized = encoding
                .split(';')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(str::to_ascii_lowercase)
                .collect::<Vec<_>>()
                .join(";");
            (!normalized.is_empty()).then_some(normalized)
        })
        .collect::<Vec<_>>();
    encodings.sort_unstable();
    encodings.join(",")
}

fn push_component(key: &mut Vec<u8>, component: &[u8]) {
    key.extend_from_slice(&(component.len() as u64).to_be_bytes());
    key.extend_from_slice(component);
}
