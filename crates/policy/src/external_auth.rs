use std::{collections::HashMap, time::Duration};

use http::{HeaderMap, StatusCode};
use impulse_contracts::HeaderMutation;
use impulse_errors::ProxyError;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ExternalAuthFailureMode {
    FailOpen,
    #[default]
    FailClosed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAuthRequestHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalAuthPolicy {
    Http {
        endpoint: String,
        request_headers: Vec<ExternalAuthRequestHeader>,
        response_header_allowlist: Vec<String>,
        timeout: Duration,
        failure_mode: ExternalAuthFailureMode,
    },
    Oidc {
        discovery_url: Option<String>,
        issuer_url: Option<String>,
        client_id: String,
        client_secret: Option<String>,
        audience: Option<String>,
        scopes: Vec<String>,
        request_headers: Vec<ExternalAuthRequestHeader>,
        response_header_allowlist: Vec<String>,
        timeout: Duration,
        failure_mode: ExternalAuthFailureMode,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalAuthFailureDisposition {
    FailOpen,
    FailClosed,
}

impl ExternalAuthFailureDisposition {
    #[must_use]
    pub fn from_failure_mode(mode: ExternalAuthFailureMode) -> Self {
        match mode {
            ExternalAuthFailureMode::FailOpen => Self::FailOpen,
            ExternalAuthFailureMode::FailClosed => Self::FailClosed,
        }
    }

    #[must_use]
    pub fn fail_open(self) -> bool {
        matches!(self, Self::FailOpen)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalAuthExecutionPolicy {
    pub timeout: Duration,
    pub failure_mode: ExternalAuthFailureMode,
}

impl ExternalAuthExecutionPolicy {
    #[must_use]
    pub fn from_external_auth(value: &ExternalAuthPolicy) -> Self {
        match value {
            ExternalAuthPolicy::Http {
                timeout,
                failure_mode,
                ..
            }
            | ExternalAuthPolicy::Oidc {
                timeout,
                failure_mode,
                ..
            } => Self {
                timeout: *timeout,
                failure_mode: *failure_mode,
            },
        }
    }

    #[must_use]
    pub fn disposition(self) -> ExternalAuthFailureDisposition {
        ExternalAuthFailureDisposition::from_failure_mode(self.failure_mode)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalAuthTaskConfig {
    pub timeout: Duration,
    pub disposition: ExternalAuthFailureDisposition,
}

impl ExternalAuthTaskConfig {
    #[must_use]
    pub fn from_external_auth(value: &ExternalAuthPolicy) -> Self {
        let policy = ExternalAuthExecutionPolicy::from_external_auth(value);
        Self {
            timeout: policy.timeout,
            disposition: policy.disposition(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExternalAuthPlan {
    pub policy: ExternalAuthPolicy,
    pub disposition: ExternalAuthFailureDisposition,
}

impl ExternalAuthPlan {
    #[must_use]
    pub fn new(policy: ExternalAuthPolicy) -> Self {
        Self {
            disposition: ExternalAuthTaskConfig::from_external_auth(&policy).disposition,
            policy,
        }
    }
}

#[derive(Debug)]
pub struct ExternalAuthResponseMetadata<'a> {
    pub status: StatusCode,
    pub headers: &'a HeaderMap,
    pub body: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalAuthDecision {
    Allow {
        request_header_mutations: Vec<HeaderMutation>,
    },
    Deny(ExternalAuthDenyResponse),
    Redirect(ExternalAuthRedirectResponse),
    Challenge(ExternalAuthChallengeResponse),
}

impl ExternalAuthDecision {
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Allow { .. } => StatusCode::OK,
            Self::Deny(response) => response.status,
            Self::Redirect(response) => response.status,
            Self::Challenge(response) => response.status,
        }
    }
}

pub type ExternalAuthResult = Result<ExternalAuthDecision, ProxyError>;

#[derive(Debug)]
pub enum ExternalAuthCompletion {
    Allow {
        request_header_mutations: Vec<HeaderMutation>,
    },
    Respond(ExternalAuthDecision),
    FailOpen {
        timed_out: bool,
        error: Option<ProxyError>,
    },
    Reject {
        status: StatusCode,
        body: &'static [u8],
        timed_out: bool,
        error: Option<ProxyError>,
    },
}

pub enum ExternalAuthStateTransition {
    Admitted {
        request_header_mutations: Vec<HeaderMutation>,
    },
    RejectedAuthDenied {
        decision: ExternalAuthDecision,
    },
    RejectedAuthUnavailable {
        status: StatusCode,
        body: &'static [u8],
        error: Option<ProxyError>,
    },
    TimedOutAuth {
        status: StatusCode,
        body: &'static [u8],
    },
}

pub fn evaluate_external_auth_completion(
    result: ExternalAuthResult,
    disposition: ExternalAuthFailureDisposition,
) -> ExternalAuthCompletion {
    match result {
        Ok(ExternalAuthDecision::Allow {
            request_header_mutations,
        }) => ExternalAuthCompletion::Allow {
            request_header_mutations,
        },
        Ok(
            decision @ (ExternalAuthDecision::Deny(_)
            | ExternalAuthDecision::Redirect(_)
            | ExternalAuthDecision::Challenge(_)),
        ) => ExternalAuthCompletion::Respond(decision),
        Err(ProxyError::Timeout) if disposition.fail_open() => ExternalAuthCompletion::FailOpen {
            timed_out: true,
            error: None,
        },
        Err(ProxyError::Timeout) => ExternalAuthCompletion::Reject {
            status: StatusCode::GATEWAY_TIMEOUT,
            body: b"external auth timeout\n",
            timed_out: true,
            error: None,
        },
        Err(error) if disposition.fail_open() => ExternalAuthCompletion::FailOpen {
            timed_out: false,
            error: Some(error),
        },
        Err(error) => ExternalAuthCompletion::Reject {
            status: StatusCode::SERVICE_UNAVAILABLE,
            body: b"external auth unavailable\n",
            timed_out: false,
            error: Some(error),
        },
    }
}

pub fn resolve_external_auth_state_transition(
    result: ExternalAuthResult,
    disposition: ExternalAuthFailureDisposition,
) -> ExternalAuthStateTransition {
    match evaluate_external_auth_completion(result, disposition) {
        ExternalAuthCompletion::Allow {
            request_header_mutations,
        } => ExternalAuthStateTransition::Admitted {
            request_header_mutations,
        },
        ExternalAuthCompletion::Respond(decision) => {
            ExternalAuthStateTransition::RejectedAuthDenied { decision }
        }
        ExternalAuthCompletion::FailOpen { .. } => ExternalAuthStateTransition::Admitted {
            request_header_mutations: Vec::new(),
        },
        ExternalAuthCompletion::Reject {
            status,
            body,
            timed_out: true,
            ..
        } => ExternalAuthStateTransition::TimedOutAuth { status, body },
        ExternalAuthCompletion::Reject {
            status,
            body,
            timed_out: false,
            error,
        } => ExternalAuthStateTransition::RejectedAuthUnavailable {
            status,
            body,
            error,
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAuthDenyResponse {
    pub status: StatusCode,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAuthRedirectResponse {
    pub status: StatusCode,
    pub headers: Vec<(String, String)>,
    pub location: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAuthChallengeResponse {
    pub status: StatusCode,
    pub headers: Vec<(String, String)>,
    pub www_authenticate: String,
    pub body: Vec<u8>,
}

fn is_safe_request_mutation_header(name: &str) -> bool {
    !name.eq_ignore_ascii_case(http::header::HOST.as_str())
        && !name.eq_ignore_ascii_case(http::header::CONNECTION.as_str())
        && !name.eq_ignore_ascii_case(http::header::CONTENT_LENGTH.as_str())
        && !name.eq_ignore_ascii_case(http::header::TRANSFER_ENCODING.as_str())
        && !name.eq_ignore_ascii_case(http::header::UPGRADE.as_str())
        && !name.eq_ignore_ascii_case(http::header::TE.as_str())
        && !name.eq_ignore_ascii_case(http::header::TRAILER.as_str())
        && !name.eq_ignore_ascii_case(http::header::EXPECT.as_str())
        && !name.eq_ignore_ascii_case(http::header::AUTHORIZATION.as_str())
        && !name.eq_ignore_ascii_case(http::header::LOCATION.as_str())
        && !name.eq_ignore_ascii_case(http::header::WWW_AUTHENTICATE.as_str())
        && !name.eq_ignore_ascii_case(http::header::FORWARDED.as_str())
        && !name.eq_ignore_ascii_case("x-forwarded-for")
        && !name.eq_ignore_ascii_case("x-forwarded-host")
        && !name.eq_ignore_ascii_case("x-forwarded-port")
        && !name.eq_ignore_ascii_case("x-forwarded-proto")
        && !name.eq_ignore_ascii_case("keep-alive")
        && !name.eq_ignore_ascii_case("proxy-connection")
}

fn normalize_request_mutation(mutation: HeaderMutation) -> Option<(String, HeaderMutation)> {
    let (name, value) = match mutation {
        HeaderMutation::Upsert { name, value } => (name, Some(value)),
        HeaderMutation::Remove { name } => (name, None),
    };
    let name = http::header::HeaderName::from_bytes(&name).ok()?;
    if !is_safe_request_mutation_header(name.as_str()) {
        return None;
    }
    let normalized = name.as_str().to_string();
    let mutation = match value {
        Some(value) => HeaderMutation::Upsert {
            name: normalized.as_bytes().to_vec(),
            value,
        },
        None => HeaderMutation::Remove {
            name: normalized.as_bytes().to_vec(),
        },
    };
    Some((normalized, mutation))
}

#[must_use]
pub fn canonicalize_external_auth_mutations<I>(mutations: I) -> Vec<HeaderMutation>
where
    I: IntoIterator<Item = HeaderMutation>,
{
    let normalized = mutations
        .into_iter()
        .enumerate()
        .filter_map(|(index, mutation)| {
            normalize_request_mutation(mutation).map(|(name, mutation)| (index, name, mutation))
        })
        .collect::<Vec<_>>();
    let last_seen = normalized
        .iter()
        .map(|(index, name, _)| (name.clone(), *index))
        .collect::<HashMap<_, _>>();
    normalized
        .into_iter()
        .filter_map(|(index, name, mutation)| {
            (last_seen.get(&name) == Some(&index)).then_some(mutation)
        })
        .collect()
}

pub fn merge_external_auth_mutations<I>(existing: &mut Vec<HeaderMutation>, incoming: I)
where
    I: IntoIterator<Item = HeaderMutation>,
{
    existing.extend(incoming);
    *existing = canonicalize_external_auth_mutations(std::mem::take(existing));
}

#[must_use]
pub fn allowed_external_auth_headers(
    headers: &HeaderMap,
    allowlist: &[String],
) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            allowlist
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(name.as_str()))
                .then(|| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.as_str().to_string(), value.to_string()))
                })
                .flatten()
        })
        .collect()
}

#[must_use]
pub fn external_auth_allow_mutations(
    headers: &HeaderMap,
    allowlist: &[String],
) -> Vec<HeaderMutation> {
    canonicalize_external_auth_mutations(
        allowed_external_auth_headers(headers, allowlist)
            .into_iter()
            .map(|(name, value)| HeaderMutation::Upsert {
                name: name.into_bytes(),
                value: value.into_bytes(),
            }),
    )
}

pub fn map_http_external_auth_response(
    metadata: ExternalAuthResponseMetadata<'_>,
    response_header_allowlist: &[String],
) -> Result<ExternalAuthDecision, ProxyError> {
    let ExternalAuthResponseMetadata {
        status,
        headers,
        body,
    } = metadata;
    let location = headers
        .get(http::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let challenge = headers
        .get(http::header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let allowed_headers = allowed_external_auth_headers(headers, response_header_allowlist);
    if status.is_success() {
        return Ok(ExternalAuthDecision::Allow {
            request_header_mutations: external_auth_allow_mutations(
                headers,
                response_header_allowlist,
            ),
        });
    }
    if status.is_redirection() {
        let Some(location) = location else {
            return Err(ProxyError::Transport(
                "external auth redirect missing location header".into(),
            ));
        };
        return Ok(ExternalAuthDecision::Redirect(
            ExternalAuthRedirectResponse {
                status,
                headers: allowed_headers
                    .into_iter()
                    .filter(|(name, _)| !name.eq_ignore_ascii_case(http::header::LOCATION.as_str()))
                    .collect(),
                location,
            },
        ));
    }
    if status == StatusCode::UNAUTHORIZED
        && let Some(www_authenticate) = challenge
    {
        return Ok(ExternalAuthDecision::Challenge(
            ExternalAuthChallengeResponse {
                status,
                headers: allowed_headers
                    .into_iter()
                    .filter(|(name, _)| {
                        !name.eq_ignore_ascii_case(http::header::WWW_AUTHENTICATE.as_str())
                    })
                    .collect(),
                www_authenticate,
                body: body.to_vec(),
            },
        ));
    }
    if status.is_client_error() {
        return Ok(ExternalAuthDecision::Deny(ExternalAuthDenyResponse {
            status,
            headers: allowed_headers,
            body: body.to_vec(),
        }));
    }
    Err(ProxyError::Transport(format!(
        "external auth endpoint returned {status}"
    )))
}
