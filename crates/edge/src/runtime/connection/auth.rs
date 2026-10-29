pub(crate) use impulse_contracts::HeaderMutation as PendingHeaderMutation;
use impulse_errors::ProxyError;
pub(crate) use impulse_policy::{
    ExternalAuthChallengeResponse, ExternalAuthCompletion, ExternalAuthDecision,
    ExternalAuthDenyResponse, ExternalAuthExecutionPolicy, ExternalAuthFailureDisposition,
    ExternalAuthRedirectResponse, ExternalAuthResponseMetadata, ExternalAuthResult,
    ExternalAuthStateTransition, ExternalAuthTaskConfig,
    allowed_external_auth_headers as allowed_auth_headers,
    canonicalize_external_auth_mutations as canonicalize_auth_request_mutations,
    evaluate_external_auth_completion, external_auth_allow_mutations as auth_allow_mutations,
    map_http_external_auth_response, merge_external_auth_mutations as merge_auth_request_mutations,
    resolve_external_auth_state_transition,
};
use quiche::h3::NameValue;

#[derive(Clone, Debug)]
pub(crate) struct ExternalAuthRequest {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) authority: Option<String>,
    pub(crate) headers: http::HeaderMap,
    pub(crate) upstream_name: String,
    pub(crate) backend_addr: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OidcAuthorizationCheck {
    Token(String),
    Challenge(ExternalAuthChallengeResponse),
}

#[derive(Debug, Clone)]
pub(crate) struct OidcDiscoveryTarget {
    pub url: String,
}

#[derive(Debug, Clone)]
pub(crate) struct OidcProviderMetadata {
    pub introspection_endpoint: String,
}

pub(crate) fn oidc_authorization_check(authorization: Option<&str>) -> OidcAuthorizationCheck {
    let Some(authorization) = authorization else {
        return OidcAuthorizationCheck::Challenge(ExternalAuthChallengeResponse {
            status: http::StatusCode::UNAUTHORIZED,
            headers: Vec::new(),
            www_authenticate: "Bearer".to_string(),
            body: b"missing bearer token\n".to_vec(),
        });
    };
    let Some(token) = bearer_token_from_authorization_value(authorization) else {
        return OidcAuthorizationCheck::Challenge(ExternalAuthChallengeResponse {
            status: http::StatusCode::UNAUTHORIZED,
            headers: Vec::new(),
            www_authenticate: "Bearer".to_string(),
            body: b"invalid bearer token\n".to_vec(),
        });
    };
    OidcAuthorizationCheck::Token(token.to_string())
}

fn bearer_token_from_authorization_value(raw: &str) -> Option<&str> {
    let (scheme, value) = raw.split_once(char::is_whitespace)?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(value.trim())
}

fn auth_uri_scheme_permitted(uri: &http::Uri) -> bool {
    match uri.scheme_str() {
        Some("https") => uri.authority().is_some(),
        Some("http") => uri.host().is_some_and(uri_host_is_loopback),
        _ => false,
    }
}

fn uri_host_is_loopback(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

pub(crate) fn oidc_discovery_target(
    discovery_url: Option<&str>,
    issuer_url: Option<&str>,
) -> Result<OidcDiscoveryTarget, ProxyError> {
    let Some(url) = discovery_url.map(str::to_string).or_else(|| {
        issuer_url.map(|issuer| {
            format!(
                "{}/.well-known/openid-configuration",
                issuer.trim_end_matches('/')
            )
        })
    }) else {
        return Err(ProxyError::Transport(
            "oidc auth missing discovery metadata".into(),
        ));
    };
    let uri = url
        .parse::<http::Uri>()
        .map_err(|err| ProxyError::Transport(err.to_string()))?;
    if !auth_uri_scheme_permitted(&uri) {
        return Err(ProxyError::Transport(
            "oidc discovery endpoint must use https (http allowed only for loopback)".into(),
        ));
    }
    Ok(OidcDiscoveryTarget { url })
}

pub(crate) fn validate_oidc_provider_metadata(
    document: &serde_json::Value,
) -> Result<OidcProviderMetadata, ProxyError> {
    let introspection_endpoint = document
        .get("introspection_endpoint")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ProxyError::Transport("oidc discovery missing introspection_endpoint".into())
        })?
        .to_string();
    let introspection_uri = introspection_endpoint
        .parse::<http::Uri>()
        .map_err(|err| ProxyError::Transport(err.to_string()))?;
    if !auth_uri_scheme_permitted(&introspection_uri) {
        return Err(ProxyError::Transport(
            "oidc introspection endpoint must use https (http allowed only for loopback)".into(),
        ));
    }
    Ok(OidcProviderMetadata {
        introspection_endpoint,
    })
}

pub(crate) fn oidc_scope_satisfied(required_scopes: &[String], granted_scopes: &str) -> bool {
    let granted: std::collections::HashSet<&str> = granted_scopes.split_whitespace().collect();
    required_scopes
        .iter()
        .all(|scope| granted.contains(scope.as_str()))
}

pub(crate) fn oidc_audience_matches(
    expected: Option<&str>,
    value: Option<&serde_json::Value>,
) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    match value {
        Some(serde_json::Value::String(single)) => single == expected,
        Some(serde_json::Value::Array(values)) => {
            values.iter().any(|value| value.as_str() == Some(expected))
        }
        _ => false,
    }
}

pub(crate) fn apply_auth_request_mutations(
    headers: &mut Vec<quiche::h3::Header>,
    mutations: &[PendingHeaderMutation],
) {
    for mutation in canonicalize_auth_request_mutations(mutations.iter().cloned()) {
        match mutation {
            PendingHeaderMutation::Upsert { name, value } => {
                headers.retain(|header| !header.name().eq_ignore_ascii_case(name.as_slice()));
                headers.push(quiche::h3::Header::new(name.as_slice(), value.as_slice()));
            }
            PendingHeaderMutation::Remove { name } => {
                headers.retain(|header| !header.name().eq_ignore_ascii_case(name.as_slice()));
            }
        }
    }
}

/// Result type returned by the in-flight upstream forwarding task.

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use impulse_config::runtime::{RuntimeExternalAuth, RuntimeExternalAuthFailureMode};
    use serde_json::json;

    use super::*;

    mod mutation_contracts {
        use super::*;

        #[test]
        fn canonicalize_auth_request_mutations_drops_protected_and_invalid_names() {
            let mutations = canonicalize_auth_request_mutations(vec![
                PendingHeaderMutation::Upsert {
                    name: b"x-auth-user".to_vec(),
                    value: b"alice".to_vec(),
                },
                PendingHeaderMutation::Upsert {
                    name: b"authorization".to_vec(),
                    value: b"Bearer blocked".to_vec(),
                },
                PendingHeaderMutation::Remove {
                    name: b"bad name".to_vec(),
                },
            ]);

            assert_eq!(
                mutations,
                vec![PendingHeaderMutation::Upsert {
                    name: b"x-auth-user".to_vec(),
                    value: b"alice".to_vec(),
                }]
            );
        }

        #[test]
        fn canonicalize_auth_request_mutations_keeps_last_mutation_per_header() {
            let mutations = canonicalize_auth_request_mutations(vec![
                PendingHeaderMutation::Upsert {
                    name: b"X-User".to_vec(),
                    value: b"one".to_vec(),
                },
                PendingHeaderMutation::Upsert {
                    name: b"x-team".to_vec(),
                    value: b"red".to_vec(),
                },
                PendingHeaderMutation::Remove {
                    name: b"x-user".to_vec(),
                },
                PendingHeaderMutation::Upsert {
                    name: b"X-Team".to_vec(),
                    value: b"blue".to_vec(),
                },
            ]);

            assert_eq!(
                mutations,
                vec![
                    PendingHeaderMutation::Remove {
                        name: b"x-user".to_vec(),
                    },
                    PendingHeaderMutation::Upsert {
                        name: b"x-team".to_vec(),
                        value: b"blue".to_vec(),
                    },
                ]
            );
        }

        #[test]
        fn apply_auth_request_mutations_resolves_conflicts_before_header_rewrite() {
            let mut headers = vec![
                quiche::h3::Header::new(b":method", b"GET"),
                quiche::h3::Header::new(b"x-user", b"stale"),
                quiche::h3::Header::new(b"x-team", b"green"),
            ];
            let mutations = vec![
                PendingHeaderMutation::Upsert {
                    name: b"X-User".to_vec(),
                    value: b"alice".to_vec(),
                },
                PendingHeaderMutation::Remove {
                    name: b"x-team".to_vec(),
                },
                PendingHeaderMutation::Upsert {
                    name: b"x-user".to_vec(),
                    value: b"fresh".to_vec(),
                },
            ];

            apply_auth_request_mutations(&mut headers, &mutations);

            assert!(headers.iter().any(|header| header.name() == b":method"));
            assert!(
                headers
                    .iter()
                    .any(|header| header.name() == b"x-user" && header.value() == b"fresh")
            );
            assert!(
                !headers
                    .iter()
                    .any(|header| header.name() == b"x-user" && header.value() == b"alice")
            );
            assert!(!headers.iter().any(|header| header.name() == b"x-team"));
        }

        #[test]
        fn merge_auth_request_mutations_canonicalizes_existing_and_incoming_values() {
            let mut existing = vec![
                PendingHeaderMutation::Upsert {
                    name: b"x-user".to_vec(),
                    value: b"stale".to_vec(),
                },
                PendingHeaderMutation::Upsert {
                    name: b"authorization".to_vec(),
                    value: b"Bearer blocked".to_vec(),
                },
            ];

            merge_auth_request_mutations(
                &mut existing,
                vec![
                    PendingHeaderMutation::Upsert {
                        name: b"X-User".to_vec(),
                        value: b"fresh".to_vec(),
                    },
                    PendingHeaderMutation::Remove {
                        name: b"x-team".to_vec(),
                    },
                    PendingHeaderMutation::Upsert {
                        name: b"connection".to_vec(),
                        value: b"close".to_vec(),
                    },
                ],
            );

            assert_eq!(
                existing,
                vec![
                    PendingHeaderMutation::Upsert {
                        name: b"x-user".to_vec(),
                        value: b"fresh".to_vec(),
                    },
                    PendingHeaderMutation::Remove {
                        name: b"x-team".to_vec(),
                    },
                ]
            );
        }
    }

    mod external_auth_response_mapping {
        use super::*;

        #[test]
        fn allowed_auth_headers_is_case_insensitive_and_auth_allow_mutations_keep_safe_values() {
            let mut headers = http::HeaderMap::new();
            headers.insert("x-auth-user", http::HeaderValue::from_static("alice"));
            headers.insert("x-auth-group", http::HeaderValue::from_static("admin"));
            headers.insert(
                http::header::AUTHORIZATION,
                http::HeaderValue::from_static("Bearer blocked"),
            );

            assert_eq!(
                allowed_auth_headers(
                    &headers,
                    &[
                        "X-Auth-User".to_string(),
                        "x-auth-group".to_string(),
                        "authorization".to_string(),
                    ],
                ),
                vec![
                    ("x-auth-user".to_string(), "alice".to_string()),
                    ("x-auth-group".to_string(), "admin".to_string()),
                    ("authorization".to_string(), "Bearer blocked".to_string()),
                ]
            );

            assert_eq!(
                auth_allow_mutations(
                    &headers,
                    &[
                        "X-Auth-User".to_string(),
                        "x-auth-group".to_string(),
                        "authorization".to_string(),
                    ],
                ),
                vec![
                    PendingHeaderMutation::Upsert {
                        name: b"x-auth-user".to_vec(),
                        value: b"alice".to_vec(),
                    },
                    PendingHeaderMutation::Upsert {
                        name: b"x-auth-group".to_vec(),
                        value: b"admin".to_vec(),
                    },
                ]
            );
        }

        #[test]
        fn map_http_external_auth_response_covers_allow_deny_redirect_and_challenge() {
            let mut allow_headers = http::HeaderMap::new();
            allow_headers.insert("x-auth-user", http::HeaderValue::from_static("alice"));
            allow_headers.insert(
                http::header::AUTHORIZATION,
                http::HeaderValue::from_static("Bearer blocked"),
            );
            let allow = map_http_external_auth_response(
                ExternalAuthResponseMetadata {
                    status: http::StatusCode::OK,
                    headers: &allow_headers,
                    body: &[],
                },
                &["x-auth-user".to_string(), "authorization".to_string()],
            )
            .expect("allow decision");
            assert_eq!(
                allow,
                ExternalAuthDecision::Allow {
                    request_header_mutations: vec![PendingHeaderMutation::Upsert {
                        name: b"x-auth-user".to_vec(),
                        value: b"alice".to_vec(),
                    }],
                }
            );

            let mut deny_headers = http::HeaderMap::new();
            deny_headers.insert("x-auth-reason", http::HeaderValue::from_static("policy"));
            let deny = map_http_external_auth_response(
                ExternalAuthResponseMetadata {
                    status: http::StatusCode::FORBIDDEN,
                    headers: &deny_headers,
                    body: b"denied\n",
                },
                &["x-auth-reason".to_string()],
            )
            .expect("deny decision");
            assert!(matches!(
                deny,
                ExternalAuthDecision::Deny(ExternalAuthDenyResponse {
                    status: http::StatusCode::FORBIDDEN,
                    ..
                })
            ));

            let mut redirect_headers = http::HeaderMap::new();
            redirect_headers.insert(
                http::header::LOCATION,
                http::HeaderValue::from_static("https://login.example.com/"),
            );
            redirect_headers.insert("x-auth-reason", http::HeaderValue::from_static("login"));
            let redirect = map_http_external_auth_response(
                ExternalAuthResponseMetadata {
                    status: http::StatusCode::FOUND,
                    headers: &redirect_headers,
                    body: &[],
                },
                &["location".to_string(), "x-auth-reason".to_string()],
            )
            .expect("redirect decision");
            assert!(matches!(
                redirect,
                ExternalAuthDecision::Redirect(ExternalAuthRedirectResponse {
                    status: http::StatusCode::FOUND,
                    ..
                })
            ));

            let mut challenge_headers = http::HeaderMap::new();
            challenge_headers.insert(
                http::header::WWW_AUTHENTICATE,
                http::HeaderValue::from_static("Bearer realm=\"impulse\""),
            );
            challenge_headers.insert("x-auth-reason", http::HeaderValue::from_static("expired"));
            let challenge = map_http_external_auth_response(
                ExternalAuthResponseMetadata {
                    status: http::StatusCode::UNAUTHORIZED,
                    headers: &challenge_headers,
                    body: b"challenge\n",
                },
                &["www-authenticate".to_string(), "x-auth-reason".to_string()],
            )
            .expect("challenge decision");
            assert!(matches!(
                challenge,
                ExternalAuthDecision::Challenge(ExternalAuthChallengeResponse {
                    status: http::StatusCode::UNAUTHORIZED,
                    ..
                })
            ));
        }

        #[test]
        fn map_http_external_auth_response_rejects_redirect_without_location_header() {
            let redirect = map_http_external_auth_response(
                ExternalAuthResponseMetadata {
                    status: http::StatusCode::FOUND,
                    headers: &http::HeaderMap::new(),
                    body: &[],
                },
                &["location".to_string()],
            );

            assert!(matches!(redirect, Err(ProxyError::Transport(_))));
        }

        #[test]
        fn response_header_allowlists_are_enforced_exactly_for_each_external_auth_outcome() {
            let mut headers = http::HeaderMap::new();
            headers.insert("x-auth-user", http::HeaderValue::from_static("alice"));
            headers.insert("x-auth-group", http::HeaderValue::from_static("admin"));
            headers.insert(
                http::header::LOCATION,
                http::HeaderValue::from_static("https://login.example.com/"),
            );
            headers.insert(
                http::header::WWW_AUTHENTICATE,
                http::HeaderValue::from_static("Bearer realm=\"impulse\""),
            );

            let allow = map_http_external_auth_response(
                ExternalAuthResponseMetadata {
                    status: http::StatusCode::OK,
                    headers: &headers,
                    body: &[],
                },
                &[
                    "x-auth-user".to_string(),
                    "www-authenticate".to_string(),
                    "location".to_string(),
                ],
            )
            .expect("allow");
            assert_eq!(
                allow,
                ExternalAuthDecision::Allow {
                    request_header_mutations: vec![PendingHeaderMutation::Upsert {
                        name: b"x-auth-user".to_vec(),
                        value: b"alice".to_vec(),
                    }],
                }
            );

            let redirect = map_http_external_auth_response(
                ExternalAuthResponseMetadata {
                    status: http::StatusCode::FOUND,
                    headers: &headers,
                    body: &[],
                },
                &[
                    "x-auth-user".to_string(),
                    "x-auth-group".to_string(),
                    "location".to_string(),
                ],
            )
            .expect("redirect");
            assert_eq!(
                redirect,
                ExternalAuthDecision::Redirect(ExternalAuthRedirectResponse {
                    status: http::StatusCode::FOUND,
                    headers: vec![
                        ("x-auth-user".to_string(), "alice".to_string()),
                        ("x-auth-group".to_string(), "admin".to_string()),
                    ],
                    location: "https://login.example.com/".to_string(),
                })
            );

            let challenge = map_http_external_auth_response(
                ExternalAuthResponseMetadata {
                    status: http::StatusCode::UNAUTHORIZED,
                    headers: &headers,
                    body: b"challenge\n",
                },
                &[
                    "x-auth-group".to_string(),
                    "www-authenticate".to_string(),
                    "location".to_string(),
                ],
            )
            .expect("challenge");
            assert_eq!(
                challenge,
                ExternalAuthDecision::Challenge(ExternalAuthChallengeResponse {
                    status: http::StatusCode::UNAUTHORIZED,
                    headers: vec![
                        ("x-auth-group".to_string(), "admin".to_string()),
                        (
                            "location".to_string(),
                            "https://login.example.com/".to_string(),
                        ),
                    ],
                    www_authenticate: "Bearer realm=\"impulse\"".to_string(),
                    body: b"challenge\n".to_vec(),
                })
            );
        }
    }

    mod oidc_helpers {
        use super::*;

        #[test]
        fn oidc_authorization_check_maps_missing_and_invalid_bearer_tokens_to_challenges() {
            assert!(matches!(
                oidc_authorization_check(None),
                OidcAuthorizationCheck::Challenge(ExternalAuthChallengeResponse {
                    status: http::StatusCode::UNAUTHORIZED,
                    ..
                })
            ));

            let invalid = oidc_authorization_check(Some("Basic abc123"));
            match invalid {
                OidcAuthorizationCheck::Challenge(response) => {
                    assert_eq!(response.www_authenticate, "Bearer");
                    assert_eq!(response.body, b"invalid bearer token\n".to_vec());
                }
                other => panic!("unexpected authorization result: {other:?}"),
            }

            assert_eq!(
                oidc_authorization_check(Some("Bearer token-1")),
                OidcAuthorizationCheck::Token("token-1".to_string())
            );
            assert_eq!(
                oidc_authorization_check(Some("bearer token-2")),
                OidcAuthorizationCheck::Token("token-2".to_string())
            );
        }

        #[test]
        fn oidc_discovery_target_derives_and_validates_provider_metadata_url() {
            let derived = oidc_discovery_target(None, Some("https://issuer.example.com/base/"))
                .expect("derived discovery target");
            assert_eq!(
                derived.url,
                "https://issuer.example.com/base/.well-known/openid-configuration"
            );

            let http_loopback = oidc_discovery_target(Some("http://127.0.0.1:9000/oidc"), None)
                .expect("loopback discovery should be allowed");
            assert!(http_loopback.url.starts_with("http://"));

            let err = oidc_discovery_target(Some("http://example.com/oidc"), None)
                .expect_err("non-loopback http discovery must be rejected");
            assert!(matches!(err, ProxyError::Transport(_)));
        }

        #[test]
        fn validate_oidc_provider_metadata_requires_safe_introspection_endpoint() {
            let valid = validate_oidc_provider_metadata(&json!({
                "introspection_endpoint": "https://issuer.example.com/oauth2/introspect"
            }))
            .expect("valid metadata");
            assert_eq!(
                valid.introspection_endpoint,
                "https://issuer.example.com/oauth2/introspect"
            );

            let missing = validate_oidc_provider_metadata(&json!({}))
                .expect_err("metadata without introspection endpoint must fail");
            assert!(matches!(missing, ProxyError::Transport(_)));

            let invalid = validate_oidc_provider_metadata(&json!({
                "introspection_endpoint": "http://example.com/oauth2/introspect"
            }))
            .expect_err("non-loopback http introspection endpoint must fail");
            assert!(matches!(invalid, ProxyError::Transport(_)));

            let loopback = validate_oidc_provider_metadata(&json!({
                "introspection_endpoint": "http://localhost:9000/oauth2/introspect"
            }))
            .expect("loopback http introspection endpoint should be allowed");
            assert_eq!(
                loopback.introspection_endpoint,
                "http://localhost:9000/oauth2/introspect"
            );
        }

        #[test]
        fn oidc_helper_predicates_match_expected_scope_and_audience_shapes() {
            assert!(oidc_scope_satisfied(
                &["read".to_string(), "write".to_string()],
                "read write admin"
            ));
            assert!(!oidc_scope_satisfied(
                &["read".to_string(), "write".to_string()],
                "read"
            ));

            assert!(oidc_audience_matches(
                Some("api://edge"),
                Some(&json!("api://edge"))
            ));
            assert!(oidc_audience_matches(
                Some("api://edge"),
                Some(&json!(["other", "api://edge"]))
            ));
            assert!(!oidc_audience_matches(
                Some("api://edge"),
                Some(&json!("api://other"))
            ));
            assert!(oidc_audience_matches(None, None));
        }
    }

    mod external_auth_completion {
        use super::*;

        #[test]
        fn external_auth_task_config_tracks_timeout_and_disposition() {
            let auth = RuntimeExternalAuth::Http {
                endpoint: "http://127.0.0.1:9000/auth".to_string(),
                request_headers: Vec::new(),
                response_header_allowlist: Vec::new(),
                timeout: Duration::from_millis(250),
                failure_mode: RuntimeExternalAuthFailureMode::FailOpen,
            };

            let config = ExternalAuthTaskConfig::from_external_auth(&auth);
            assert_eq!(config.timeout, Duration::from_millis(250));
            assert_eq!(config.disposition, ExternalAuthFailureDisposition::FailOpen);
        }

        #[test]
        fn evaluate_external_auth_completion_maps_fail_open_and_fail_closed_outcomes() {
            let fail_open = evaluate_external_auth_completion(
                Err(ProxyError::Transport("unavailable".into())),
                ExternalAuthFailureDisposition::FailOpen,
            );
            assert!(matches!(
                fail_open,
                ExternalAuthCompletion::FailOpen {
                    timed_out: false,
                    error: Some(ProxyError::Transport(_)),
                }
            ));

            let fail_closed = evaluate_external_auth_completion(
                Err(ProxyError::Timeout),
                ExternalAuthFailureDisposition::FailClosed,
            );
            assert!(matches!(
                fail_closed,
                ExternalAuthCompletion::Reject {
                    status: http::StatusCode::GATEWAY_TIMEOUT,
                    timed_out: true,
                    ..
                }
            ));
        }

        #[test]
        fn evaluate_external_auth_completion_distinguishes_fail_open_timeout_from_error() {
            let timeout = evaluate_external_auth_completion(
                Err(ProxyError::Timeout),
                ExternalAuthFailureDisposition::FailOpen,
            );
            assert!(matches!(
                timeout,
                ExternalAuthCompletion::FailOpen {
                    timed_out: true,
                    error: None,
                }
            ));

            let error = evaluate_external_auth_completion(
                Err(ProxyError::Transport("dial failed".into())),
                ExternalAuthFailureDisposition::FailOpen,
            );
            assert!(matches!(
                error,
                ExternalAuthCompletion::FailOpen {
                    timed_out: false,
                    error: Some(ProxyError::Transport(_)),
                }
            ));
        }

        #[test]
        fn evaluate_external_auth_completion_maps_allow_and_response_decisions() {
            let allow = evaluate_external_auth_completion(
                Ok(ExternalAuthDecision::Allow {
                    request_header_mutations: vec![PendingHeaderMutation::Upsert {
                        name: b"x-auth-user".to_vec(),
                        value: b"alice".to_vec(),
                    }],
                }),
                ExternalAuthFailureDisposition::FailClosed,
            );
            assert!(matches!(
                allow,
                ExternalAuthCompletion::Allow {
                    request_header_mutations,
                } if request_header_mutations == vec![PendingHeaderMutation::Upsert {
                    name: b"x-auth-user".to_vec(),
                    value: b"alice".to_vec(),
                }]
            ));

            let deny = evaluate_external_auth_completion(
                Ok(ExternalAuthDecision::Deny(ExternalAuthDenyResponse {
                    status: http::StatusCode::FORBIDDEN,
                    headers: vec![("x-auth-reason".to_string(), "policy".to_string())],
                    body: b"denied\n".to_vec(),
                })),
                ExternalAuthFailureDisposition::FailClosed,
            );
            assert!(matches!(
                deny,
                ExternalAuthCompletion::Respond(ExternalAuthDecision::Deny(
                    ExternalAuthDenyResponse {
                        status: http::StatusCode::FORBIDDEN,
                        ..
                    }
                ))
            ));

            let redirect = evaluate_external_auth_completion(
                Ok(ExternalAuthDecision::Redirect(
                    ExternalAuthRedirectResponse {
                        status: http::StatusCode::FOUND,
                        headers: vec![("x-auth-reason".to_string(), "login".to_string())],
                        location: "https://login.example.com/".to_string(),
                    },
                )),
                ExternalAuthFailureDisposition::FailClosed,
            );
            assert!(matches!(
                redirect,
                ExternalAuthCompletion::Respond(ExternalAuthDecision::Redirect(
                    ExternalAuthRedirectResponse {
                        status: http::StatusCode::FOUND,
                        ..
                    }
                ))
            ));

            let challenge = evaluate_external_auth_completion(
                Ok(ExternalAuthDecision::Challenge(
                    ExternalAuthChallengeResponse {
                        status: http::StatusCode::UNAUTHORIZED,
                        headers: vec![("x-auth-reason".to_string(), "expired".to_string())],
                        www_authenticate: "Bearer realm=\"impulse\"".to_string(),
                        body: b"challenge\n".to_vec(),
                    },
                )),
                ExternalAuthFailureDisposition::FailClosed,
            );
            assert!(matches!(
                challenge,
                ExternalAuthCompletion::Respond(ExternalAuthDecision::Challenge(
                    ExternalAuthChallengeResponse {
                        status: http::StatusCode::UNAUTHORIZED,
                        ..
                    }
                ))
            ));
        }

        #[test]
        fn evaluate_external_auth_completion_fail_closed_transport_error_maps_to_unavailable() {
            let rejected = evaluate_external_auth_completion(
                Err(ProxyError::Transport("connect failed".into())),
                ExternalAuthFailureDisposition::FailClosed,
            );
            assert!(matches!(
                rejected,
                ExternalAuthCompletion::Reject {
                    status: http::StatusCode::SERVICE_UNAVAILABLE,
                    body,
                    timed_out: false,
                    error: Some(ProxyError::Transport(_)),
                } if body == b"external auth unavailable\n"
            ));
        }
    }

    mod external_auth_state_transitions {
        use super::*;

        #[test]
        fn resolve_external_auth_state_transition_maps_all_decision_variants_stably() {
            let allow = resolve_external_auth_state_transition(
                Ok(ExternalAuthDecision::Allow {
                    request_header_mutations: vec![PendingHeaderMutation::Upsert {
                        name: b"x-auth-user".to_vec(),
                        value: b"alice".to_vec(),
                    }],
                }),
                ExternalAuthFailureDisposition::FailClosed,
            );
            assert!(matches!(
                allow,
                ExternalAuthStateTransition::Admitted {
                    request_header_mutations,
                } if request_header_mutations == vec![PendingHeaderMutation::Upsert {
                    name: b"x-auth-user".to_vec(),
                    value: b"alice".to_vec(),
                }]
            ));

            let deny = resolve_external_auth_state_transition(
                Ok(ExternalAuthDecision::Deny(ExternalAuthDenyResponse {
                    status: http::StatusCode::FORBIDDEN,
                    headers: vec![("x-auth-reason".to_string(), "policy".to_string())],
                    body: b"denied\n".to_vec(),
                })),
                ExternalAuthFailureDisposition::FailClosed,
            );
            assert!(matches!(
                deny,
                ExternalAuthStateTransition::RejectedAuthDenied {
                    decision: ExternalAuthDecision::Deny(ExternalAuthDenyResponse {
                        status: http::StatusCode::FORBIDDEN,
                        ..
                    })
                }
            ));

            let redirect = resolve_external_auth_state_transition(
                Ok(ExternalAuthDecision::Redirect(
                    ExternalAuthRedirectResponse {
                        status: http::StatusCode::FOUND,
                        headers: vec![("x-auth-reason".to_string(), "login".to_string())],
                        location: "https://login.example.com/".to_string(),
                    },
                )),
                ExternalAuthFailureDisposition::FailClosed,
            );
            assert!(matches!(
                redirect,
                ExternalAuthStateTransition::RejectedAuthDenied {
                    decision: ExternalAuthDecision::Redirect(ExternalAuthRedirectResponse {
                        status: http::StatusCode::FOUND,
                        ..
                    })
                }
            ));

            let challenge = resolve_external_auth_state_transition(
                Ok(ExternalAuthDecision::Challenge(
                    ExternalAuthChallengeResponse {
                        status: http::StatusCode::UNAUTHORIZED,
                        headers: vec![("x-auth-reason".to_string(), "expired".to_string())],
                        www_authenticate: "Bearer realm=\"impulse\"".to_string(),
                        body: b"challenge\n".to_vec(),
                    },
                )),
                ExternalAuthFailureDisposition::FailClosed,
            );
            assert!(matches!(
                challenge,
                ExternalAuthStateTransition::RejectedAuthDenied {
                    decision: ExternalAuthDecision::Challenge(ExternalAuthChallengeResponse {
                        status: http::StatusCode::UNAUTHORIZED,
                        ..
                    })
                }
            ));
        }

        #[test]
        fn resolve_external_auth_state_transition_maps_timeout_and_execution_errors_stably() {
            let fail_open_timeout = resolve_external_auth_state_transition(
                Err(ProxyError::Timeout),
                ExternalAuthFailureDisposition::FailOpen,
            );
            assert!(matches!(
                fail_open_timeout,
                ExternalAuthStateTransition::Admitted {
                    request_header_mutations,
                } if request_header_mutations.is_empty()
            ));

            let fail_closed_timeout = resolve_external_auth_state_transition(
                Err(ProxyError::Timeout),
                ExternalAuthFailureDisposition::FailClosed,
            );
            assert!(matches!(
                fail_closed_timeout,
                ExternalAuthStateTransition::TimedOutAuth {
                    status: http::StatusCode::GATEWAY_TIMEOUT,
                    body: b"external auth timeout\n",
                }
            ));

            let fail_open_error = resolve_external_auth_state_transition(
                Err(ProxyError::Transport("dial failed".into())),
                ExternalAuthFailureDisposition::FailOpen,
            );
            assert!(matches!(
                fail_open_error,
                ExternalAuthStateTransition::Admitted {
                    request_header_mutations,
                } if request_header_mutations.is_empty()
            ));

            let fail_closed_error = resolve_external_auth_state_transition(
                Err(ProxyError::Transport("dial failed".into())),
                ExternalAuthFailureDisposition::FailClosed,
            );
            assert!(matches!(
                fail_closed_error,
                ExternalAuthStateTransition::RejectedAuthUnavailable {
                    status: http::StatusCode::SERVICE_UNAVAILABLE,
                    body: b"external auth unavailable\n",
                    error: Some(ProxyError::Transport(_)),
                }
            ));
        }

        #[test]
        fn resolve_external_auth_state_transition_fail_open_never_emits_auth_rejection() {
            let timeout = resolve_external_auth_state_transition(
                Err(ProxyError::Timeout),
                ExternalAuthFailureDisposition::FailOpen,
            );
            let error = resolve_external_auth_state_transition(
                Err(ProxyError::Transport("dial failed".into())),
                ExternalAuthFailureDisposition::FailOpen,
            );

            assert!(matches!(
                timeout,
                ExternalAuthStateTransition::Admitted {
                    request_header_mutations,
                } if request_header_mutations.is_empty()
            ));
            assert!(matches!(
                error,
                ExternalAuthStateTransition::Admitted {
                    request_header_mutations,
                } if request_header_mutations.is_empty()
            ));
        }
    }
}
