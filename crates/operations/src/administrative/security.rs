use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use impulse_config::config::{
    ControlApi as ControlApiConfig, ControlApiBearerToken, ControlApiClientAuthMode,
    ControlApiIdentitySource, ControlApiRole,
};
use impulse_observability::Metrics;

use super::audit::ControlApiAdminAuditEmitter;

const AUTH_FAILURE_LIMIT: u32 = 5;
const AUTH_FAILURE_WINDOW: Duration = Duration::from_secs(60);
const AUTH_BLOCK_DURATION: Duration = Duration::from_secs(60);
const AUTH_THROTTLE_MAX_PEERS: usize = 4096;

#[derive(Debug)]
struct AuthFailureState {
    first_failure: Instant,
    failures: u32,
    blocked_until: Option<Instant>,
}

#[derive(Debug)]
pub struct ControlApiAuthThrottle {
    peers: Mutex<HashMap<IpAddr, AuthFailureState>>,
}

impl ControlApiAuthThrottle {
    pub fn new() -> Self {
        Self {
            peers: Mutex::new(HashMap::new()),
        }
    }

    pub fn is_blocked(&self, peer: IpAddr) -> bool {
        let now = Instant::now();
        let mut peers = self
            .peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(state) = peers.get_mut(&peer) else {
            return false;
        };
        if state.blocked_until.is_some_and(|until| until > now) {
            return true;
        }
        if state.blocked_until.is_some_and(|until| until <= now)
            || now.duration_since(state.first_failure) >= AUTH_FAILURE_WINDOW
        {
            peers.remove(&peer);
        }
        false
    }

    pub fn record_failure(&self, peer: IpAddr) {
        let now = Instant::now();
        let mut peers = self
            .peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(state) = peers.get_mut(&peer)
            && now.duration_since(state.first_failure) >= AUTH_FAILURE_WINDOW
        {
            *state = AuthFailureState {
                first_failure: now,
                failures: 0,
                blocked_until: None,
            };
        }
        if !peers.contains_key(&peer) {
            if peers.len() >= AUTH_THROTTLE_MAX_PEERS
                && let Some(oldest_peer) = peers
                    .iter()
                    .min_by_key(|(_, state)| state.first_failure)
                    .map(|(peer, _)| *peer)
            {
                peers.remove(&oldest_peer);
            }
            peers.insert(
                peer,
                AuthFailureState {
                    first_failure: now,
                    failures: 0,
                    blocked_until: None,
                },
            );
        }
        let Some(state) = peers.get_mut(&peer) else {
            return;
        };
        state.failures = state.failures.saturating_add(1);
        if state.failures >= AUTH_FAILURE_LIMIT {
            state.blocked_until = Some(now + AUTH_BLOCK_DURATION);
        }
    }

    pub fn record_success(&self, peer: IpAddr) {
        self.peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&peer);
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ControlApiSecurityPolicy {
    pub client_auth: ControlApiClientAuthPolicy,
    pub bearer_tokens: Arc<Vec<ControlApiBearerTokenEntry>>,
    pub identity_source: Option<ControlApiIdentitySourcePolicy>,
    pub authorization: ControlApiAuthorizationPolicy,
    pub ip_allowlist: ControlApiIpAllowlistPolicy,
    pub audit: ControlApiAdminAuditEmitter,
}

impl ControlApiSecurityPolicy {
    pub fn from_config(config: &ControlApiConfig, metrics: Arc<Metrics>) -> Self {
        Self {
            client_auth: ControlApiClientAuthPolicy::from_config(config),
            bearer_tokens: Arc::new(runtime_bearer_tokens(config)),
            identity_source: config
                .auth
                .identity_source
                .as_ref()
                .map(ControlApiIdentitySourcePolicy::from_config),
            authorization: ControlApiAuthorizationPolicy::from_config(config),
            ip_allowlist: ControlApiIpAllowlistPolicy::from_config(config),
            audit: ControlApiAdminAuditEmitter::from_config(config, metrics),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ControlApiClientAuthPolicy {
    pub mode: ControlApiClientAuthMode,
    pub verifier: ControlApiClientVerifierState,
}

impl ControlApiClientAuthPolicy {
    fn from_config(config: &ControlApiConfig) -> Self {
        let client_auth = &config.tls.client_auth;
        Self {
            mode: client_auth.mode,
            verifier: if matches!(client_auth.mode, ControlApiClientAuthMode::Disabled) {
                ControlApiClientVerifierState::Disabled
            } else {
                ControlApiClientVerifierState::Configured(ControlApiClientCaMaterial {
                    ca_file: client_auth.ca_file.clone(),
                    ca_dir: client_auth.ca_dir.clone(),
                })
            },
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ControlApiClientVerifierState {
    Disabled,
    Configured(ControlApiClientCaMaterial),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ControlApiClientCaMaterial {
    pub ca_file: Option<String>,
    pub ca_dir: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ControlApiBearerTokenEntry {
    pub token: String,
    pub role: ControlApiRole,
    pub actor_id: Option<String>,
    pub source: ControlApiBearerTokenSource,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ControlApiBearerTokenSource {
    LegacyAuthToken,
    StaticTokenList,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ControlApiAuthorizationPolicy {
    pub protect_health: bool,
    pub protect_ready: bool,
    pub runtime_read_role: ControlApiRole,
    pub runtime_mutate_role: ControlApiRole,
    pub restart_role: ControlApiRole,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ControlApiIdentitySourcePolicy {
    pub kind: String,
    pub role_attribute: Option<String>,
}

impl ControlApiIdentitySourcePolicy {
    fn from_config(config: &ControlApiIdentitySource) -> Self {
        Self {
            kind: config.kind.clone(),
            role_attribute: config.role_attribute.clone(),
        }
    }
}

impl ControlApiAuthorizationPolicy {
    fn from_config(config: &ControlApiConfig) -> Self {
        let authz = &config.authorization;
        Self {
            protect_health: authz.protect_health,
            protect_ready: authz.protect_ready,
            runtime_read_role: authz.runtime_read_role,
            runtime_mutate_role: authz.runtime_mutate_role,
            restart_role: authz.restart_role,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ControlApiIpAllowlistPolicy {
    pub trust_proxy_headers: bool,
    pub matcher: Option<ControlApiIpAllowlistMatcher>,
    pub trusted_proxy_matcher: Option<ControlApiIpAllowlistMatcher>,
}

impl ControlApiIpAllowlistPolicy {
    fn from_config(config: &ControlApiConfig) -> Self {
        let cidrs = config
            .ip_allowlist
            .cidrs
            .iter()
            .filter_map(|cidr| ControlApiIpNetwork::parse(cidr))
            .collect::<Vec<_>>();
        let trusted_proxy_cidrs = config
            .ip_allowlist
            .trusted_proxy_cidrs
            .iter()
            .filter_map(|cidr| ControlApiIpNetwork::parse(cidr))
            .collect::<Vec<_>>();
        Self {
            trust_proxy_headers: config.ip_allowlist.trust_proxy_headers,
            matcher: (!cidrs.is_empty()).then_some(ControlApiIpAllowlistMatcher { cidrs }),
            trusted_proxy_matcher: (!trusted_proxy_cidrs.is_empty()).then_some(
                ControlApiIpAllowlistMatcher {
                    cidrs: trusted_proxy_cidrs,
                },
            ),
        }
    }

    pub fn allows(&self, ip: IpAddr) -> bool {
        self.matcher
            .as_ref()
            .is_none_or(|matcher| matcher.contains(ip))
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SourceIpExtractionError {
    MalformedForwardingHeaders,
}

pub fn source_ip_from_request<B>(
    request: &::http::Request<B>,
    peer_ip: IpAddr,
    trust_proxy_headers: bool,
    trusted_proxy_matcher: Option<&ControlApiIpAllowlistMatcher>,
) -> Result<IpAddr, SourceIpExtractionError> {
    if !trust_proxy_headers
        || !trusted_proxy_matcher.is_some_and(|matcher| matcher.contains(peer_ip))
    {
        return Ok(peer_ip);
    }

    let forwarded = request.headers().get_all("forwarded");
    let x_forwarded_for = request.headers().get_all("x-forwarded-for");
    let has_forwarded = forwarded.iter().next().is_some();
    let has_x_forwarded_for = x_forwarded_for.iter().next().is_some();

    if has_forwarded == has_x_forwarded_for {
        // No trusted header means the peer is the source. Both families at
        // once are ambiguous: the proxy must select and sanitize one family.
        return if !has_forwarded {
            Ok(peer_ip)
        } else {
            Err(SourceIpExtractionError::MalformedForwardingHeaders)
        };
    }

    if has_forwarded {
        parse_forwarded_for(
            forwarded.iter().map(|value| {
                value
                    .to_str()
                    .map_err(|_| SourceIpExtractionError::MalformedForwardingHeaders)
            }),
            trusted_proxy_matcher,
        )
    } else {
        parse_x_forwarded_for(
            x_forwarded_for.iter().map(|value| {
                value
                    .to_str()
                    .map_err(|_| SourceIpExtractionError::MalformedForwardingHeaders)
            }),
            trusted_proxy_matcher,
        )
    }
}

fn parse_forwarded_for<'a, I>(
    values: I,
    trusted_proxy_matcher: Option<&ControlApiIpAllowlistMatcher>,
) -> Result<IpAddr, SourceIpExtractionError>
where
    I: IntoIterator<Item = Result<&'a str, SourceIpExtractionError>>,
{
    let mut chain = Vec::new();
    for value in values {
        for element in value?.split(',') {
            chain.push(element.split(';').find_map(|parameter| {
                let (name, value) = parameter.trim().split_once('=')?;
                name.trim()
                    .eq_ignore_ascii_case("for")
                    .then(|| parse_proxy_ip(value.trim()))?
            }));
        }
    }
    let chain = chain
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(SourceIpExtractionError::MalformedForwardingHeaders)?;
    chain
        .into_iter()
        .rev()
        .find(|ip| !trusted_proxy_matcher.is_some_and(|matcher| matcher.contains(*ip)))
        .ok_or(SourceIpExtractionError::MalformedForwardingHeaders)
}

fn parse_x_forwarded_for<'a, I>(
    values: I,
    trusted_proxy_matcher: Option<&ControlApiIpAllowlistMatcher>,
) -> Result<IpAddr, SourceIpExtractionError>
where
    I: IntoIterator<Item = Result<&'a str, SourceIpExtractionError>>,
{
    let mut chain = Vec::new();
    for value in values {
        for value in value?.split(',') {
            chain.push(parse_proxy_ip(value.trim()));
        }
    }
    let chain = chain
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(SourceIpExtractionError::MalformedForwardingHeaders)?;
    chain
        .into_iter()
        .rev()
        .find(|ip| !trusted_proxy_matcher.is_some_and(|matcher| matcher.contains(*ip)))
        .ok_or(SourceIpExtractionError::MalformedForwardingHeaders)
}

fn parse_proxy_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim().trim_matches('"');
    if let Some(value) = value.strip_prefix('[') {
        let end = value.find(']')?;
        return value[..end].parse().ok();
    }
    if let Ok(ip) = value.parse() {
        return Some(ip);
    }
    value
        .parse::<std::net::SocketAddr>()
        .ok()
        .map(|addr| addr.ip())
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ControlApiSourcePolicyDecision {
    Allow,
    Deny { reason: &'static str },
}

impl ControlApiSecurityPolicy {
    pub fn has_source_policy(&self) -> bool {
        self.ip_allowlist.matcher.is_some()
    }

    pub fn evaluate_source_policy(&self, source_ip: IpAddr) -> ControlApiSourcePolicyDecision {
        if self.ip_allowlist.allows(source_ip) {
            ControlApiSourcePolicyDecision::Allow
        } else {
            ControlApiSourcePolicyDecision::Deny {
                reason: "source_ip_not_allowed",
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ControlApiIpAllowlistMatcher {
    cidrs: Vec<ControlApiIpNetwork>,
}

impl ControlApiIpAllowlistMatcher {
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.cidrs.iter().any(|cidr| cidr.contains(ip))
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum ControlApiIpNetwork {
    V4 { network: u32, prefix_len: u8 },
    V6 { network: u128, prefix_len: u8 },
}

impl ControlApiIpNetwork {
    fn parse(cidr: &str) -> Option<Self> {
        let (addr, prefix) = cidr.trim().split_once('/')?;
        let prefix = prefix.trim().parse::<u8>().ok()?;
        match addr.trim().parse::<IpAddr>().ok()? {
            IpAddr::V4(ip) if prefix <= 32 => {
                let raw = u32::from(ip);
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                Some(Self::V4 {
                    network: raw & mask,
                    prefix_len: prefix,
                })
            }
            IpAddr::V6(ip) if prefix <= 128 => {
                let raw = u128::from(ip);
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                Some(Self::V6 {
                    network: raw & mask,
                    prefix_len: prefix,
                })
            }
            _ => None,
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (
                Self::V4 {
                    network,
                    prefix_len,
                },
                IpAddr::V4(ip),
            ) => {
                let raw = u32::from(ip);
                let mask = if *prefix_len == 0 {
                    0
                } else {
                    u32::MAX << (32 - *prefix_len)
                };
                (raw & mask) == *network
            }
            (
                Self::V6 {
                    network,
                    prefix_len,
                },
                IpAddr::V6(ip),
            ) => {
                let raw = u128::from(ip);
                let mask = if *prefix_len == 0 {
                    0
                } else {
                    u128::MAX << (128 - *prefix_len)
                };
                (raw & mask) == *network
            }
            _ => false,
        }
    }
}

fn runtime_bearer_tokens(config: &ControlApiConfig) -> Vec<ControlApiBearerTokenEntry> {
    let mut tokens = Vec::new();
    if let Some(token) = config.auth_token.as_ref() {
        tokens.push(ControlApiBearerTokenEntry {
            token: token.clone(),
            role: ControlApiRole::Admin,
            actor_id: Some("legacy_auth_token".to_string()),
            source: ControlApiBearerTokenSource::LegacyAuthToken,
        });
    }
    tokens.extend(
        config
            .auth
            .bearer_tokens
            .iter()
            .map(runtime_bearer_token_from_config),
    );
    tokens
}

fn runtime_bearer_token_from_config(token: &ControlApiBearerToken) -> ControlApiBearerTokenEntry {
    ControlApiBearerTokenEntry {
        token: token.token.clone(),
        role: token.role,
        actor_id: token.actor_id.clone(),
        source: ControlApiBearerTokenSource::StaticTokenList,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_ip_uses_peer_without_trusted_proxy_headers() {
        let request = ::http::Request::builder()
            .header("x-forwarded-for", "203.0.113.10")
            .body(())
            .expect("request");
        let peer = "10.0.0.2".parse().expect("peer ip");

        assert_eq!(
            source_ip_from_request(&request, peer, false, None).unwrap(),
            peer
        );
    }

    #[test]
    fn source_ip_uses_forwarded_header_when_trusted() {
        let request = ::http::Request::builder()
            .header("forwarded", "for=\"[2001:db8::10]:443\";proto=https")
            .body(())
            .expect("request");
        let peer = "10.0.0.2".parse().expect("peer ip");

        assert_eq!(
            source_ip_from_request(
                &request,
                peer,
                true,
                Some(&ControlApiIpAllowlistMatcher {
                    cidrs: vec![ControlApiIpNetwork::parse("10.0.0.0/8").unwrap()],
                }),
            )
            .unwrap(),
            "2001:db8::10".parse::<IpAddr>().expect("forwarded ip")
        );
    }

    #[test]
    fn source_ip_ignores_forwarded_headers_from_untrusted_peer() {
        let request = ::http::Request::builder()
            .header("x-forwarded-for", "203.0.113.10")
            .body(())
            .expect("request");
        let peer = "192.0.2.10".parse().expect("peer ip");
        let trusted_proxy_matcher = ControlApiIpAllowlistMatcher {
            cidrs: vec![ControlApiIpNetwork::parse("10.0.0.0/8").unwrap()],
        };

        assert_eq!(
            source_ip_from_request(&request, peer, true, Some(&trusted_proxy_matcher)).unwrap(),
            peer
        );
    }

    #[test]
    fn source_ip_uses_proxy_adjacent_x_forwarded_for_entry() {
        let request = ::http::Request::builder()
            .header("x-forwarded-for", "203.0.113.10, 10.0.0.2")
            .body(())
            .expect("request");
        let peer = "10.0.0.3".parse().expect("peer ip");

        assert_eq!(
            source_ip_from_request(
                &request,
                peer,
                true,
                Some(&ControlApiIpAllowlistMatcher {
                    cidrs: vec![ControlApiIpNetwork::parse("10.0.0.0/8").unwrap()],
                }),
            )
            .unwrap(),
            "203.0.113.10".parse::<IpAddr>().expect("forwarded ip")
        );
    }

    #[test]
    fn source_ip_combines_repeated_x_forwarded_for_fields_in_wire_order() {
        let request = ::http::Request::builder()
            .header("x-forwarded-for", "203.0.113.10")
            .header("x-forwarded-for", "203.0.113.11, 10.0.0.2")
            .body(())
            .expect("request");
        let peer = "10.0.0.3".parse().expect("peer ip");
        let trusted_proxy_matcher = ControlApiIpAllowlistMatcher {
            cidrs: vec![ControlApiIpNetwork::parse("10.0.0.0/8").unwrap()],
        };

        assert_eq!(
            source_ip_from_request(&request, peer, true, Some(&trusted_proxy_matcher)).unwrap(),
            "203.0.113.11".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn source_ip_rejects_mixed_and_malformed_forwarding_headers() {
        let mixed = ::http::Request::builder()
            .header("forwarded", "for=203.0.113.10")
            .header("x-forwarded-for", "10.0.0.2")
            .body(())
            .expect("request");
        let malformed = ::http::Request::builder()
            .header("x-forwarded-for", "203.0.113.10")
            .header("x-forwarded-for", "not-an-ip")
            .body(())
            .expect("request");
        let peer = "10.0.0.3".parse().expect("peer ip");
        let trusted_proxy_matcher = ControlApiIpAllowlistMatcher {
            cidrs: vec![ControlApiIpNetwork::parse("10.0.0.0/8").unwrap()],
        };

        assert_eq!(
            source_ip_from_request(&mixed, peer, true, Some(&trusted_proxy_matcher)),
            Err(SourceIpExtractionError::MalformedForwardingHeaders)
        );
        assert_eq!(
            source_ip_from_request(&malformed, peer, true, Some(&trusted_proxy_matcher)),
            Err(SourceIpExtractionError::MalformedForwardingHeaders)
        );
    }

    #[test]
    fn auth_throttle_blocks_repeated_failures_and_resets_on_success() {
        let throttle = ControlApiAuthThrottle::new();
        let peer = "192.0.2.10".parse().expect("peer ip");

        for _ in 0..4 {
            throttle.record_failure(peer);
            assert!(!throttle.is_blocked(peer));
        }
        throttle.record_failure(peer);
        assert!(throttle.is_blocked(peer));

        throttle.record_success(peer);
        assert!(!throttle.is_blocked(peer));
    }

    #[test]
    fn trusted_proxy_clients_resolve_to_independent_source_policy_addresses() {
        let proxy = "10.0.0.2".parse().expect("proxy ip");
        let trusted_proxy_matcher = ControlApiIpAllowlistMatcher {
            cidrs: vec![ControlApiIpNetwork::parse("10.0.0.0/8").unwrap()],
        };
        let request_a = ::http::Request::builder()
            .header("x-forwarded-for", "203.0.113.10, 10.0.0.2")
            .body(())
            .expect("request a");
        let request_b = ::http::Request::builder()
            .header("x-forwarded-for", "203.0.113.11, 10.0.0.2")
            .body(())
            .expect("request b");
        let client_a =
            source_ip_from_request(&request_a, proxy, true, Some(&trusted_proxy_matcher)).unwrap();
        let client_b =
            source_ip_from_request(&request_b, proxy, true, Some(&trusted_proxy_matcher)).unwrap();

        assert_ne!(client_a, client_b);
    }
}
