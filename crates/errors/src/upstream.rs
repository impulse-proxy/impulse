//! Shared upstream error-detail classification and health-mapping contract.

use impulse_lb::health::HealthFailureReason;

pub fn classify_upstream_error_detail(
    detail: &str,
    is_connect: bool,
) -> UpstreamErrorClassification {
    let normalized = detail.to_ascii_lowercase();
    if normalized.contains("timeout") || normalized.contains("timed out") {
        return UpstreamErrorClassification::timeout();
    }

    // TLS alert/certificate vocabulary is unambiguous regardless of whether the
    // underlying HTTP client reports the failure as a connect-phase or
    // send-phase error, so gating this detection on `is_connect` can miss it.
    if normalized.contains("client_certificate_missing") {
        return UpstreamErrorClassification::tls(UpstreamTlsReason::ClientCertificateMissing);
    }
    if normalized.contains("client_key_missing") {
        return UpstreamErrorClassification::tls(UpstreamTlsReason::ClientKeyMissing);
    }
    if normalized.contains("client_identity_invalid") {
        return UpstreamErrorClassification::tls(UpstreamTlsReason::ClientIdentityInvalid);
    }
    if normalized.contains("client_certificate_expired") {
        return UpstreamErrorClassification::tls(UpstreamTlsReason::ClientCertificateExpired);
    }
    if normalized.contains("client_auth_rejected")
        || normalized.contains("certificaterequired")
        || normalized.contains("certificate required")
        || normalized.contains("peer sent no certificates")
        || normalized.contains("bad certificate")
        || normalized.contains("badcertificate")
        || normalized.contains("certificate unknown")
        || normalized.contains("certificateunknown")
        || normalized.contains("unknown ca")
        || normalized.contains("unknownca")
    {
        return UpstreamErrorClassification::tls(UpstreamTlsReason::ClientAuthRejected);
    }
    if normalized.contains("unknownissuer") || normalized.contains("unknown issuer") {
        return UpstreamErrorClassification::tls(UpstreamTlsReason::UnknownIssuer);
    }
    if normalized.contains("alpn") {
        return UpstreamErrorClassification::tls(UpstreamTlsReason::Alpn);
    }

    // These buckets rely on more generic vocabulary ("expired", "hostname",
    // bare "certificate"/"tls") that is more plausible outside of a TLS
    // context (e.g. an application error body), so they stay gated on
    // `is_connect` to avoid misclassifying unrelated protocol/application
    // errors as TLS failures.
    if is_connect {
        if normalized.contains("expired") && normalized.contains("client") {
            return UpstreamErrorClassification::tls(UpstreamTlsReason::ClientCertificateExpired);
        }
        if normalized.contains("expired")
            || normalized.contains("not yet valid")
            || normalized.contains("validity")
        {
            return UpstreamErrorClassification::tls(UpstreamTlsReason::ExpiredCertificate);
        }
        if normalized.contains("hostname")
            || normalized.contains("dns name")
            || normalized.contains("subjectaltname")
            || normalized.contains("not valid for")
        {
            return UpstreamErrorClassification::tls(UpstreamTlsReason::HostnameMismatch);
        }
        if normalized.contains("invalidcertificate")
            || normalized.contains("certificate")
            || normalized.contains("x509")
            || normalized.contains("rustls")
            || normalized.contains("webpki")
            || normalized.contains("tls")
        {
            return UpstreamErrorClassification::tls(UpstreamTlsReason::Handshake);
        }
    }

    UpstreamErrorClassification::transport()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamErrorCategory {
    Timeout,
    Transport,
    Tls,
    Protocol,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamTlsReason {
    UnknownIssuer,
    ExpiredCertificate,
    HostnameMismatch,
    Alpn,
    Handshake,
    ClientCertificateMissing,
    ClientKeyMissing,
    ClientIdentityInvalid,
    ClientAuthRejected,
    ClientCertificateExpired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpstreamErrorClassification {
    pub category: UpstreamErrorCategory,
    pub tls_reason: Option<UpstreamTlsReason>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpstreamHealthFailureMapping {
    pub failure_reason: HealthFailureReason,
    pub metrics_reason: &'static str,
}

impl UpstreamErrorClassification {
    pub const fn timeout() -> Self {
        Self {
            category: UpstreamErrorCategory::Timeout,
            tls_reason: None,
        }
    }

    pub const fn transport() -> Self {
        Self {
            category: UpstreamErrorCategory::Transport,
            tls_reason: None,
        }
    }

    pub const fn tls(reason: UpstreamTlsReason) -> Self {
        Self {
            category: UpstreamErrorCategory::Tls,
            tls_reason: Some(reason),
        }
    }

    pub const fn protocol() -> Self {
        Self {
            category: UpstreamErrorCategory::Protocol,
            tls_reason: None,
        }
    }

    pub const fn internal() -> Self {
        Self {
            category: UpstreamErrorCategory::Internal,
            tls_reason: None,
        }
    }

    pub(crate) fn health_failure_mapping(self) -> UpstreamHealthFailureMapping {
        match self.category {
            UpstreamErrorCategory::Timeout => UpstreamHealthFailureMapping {
                failure_reason: HealthFailureReason::Timeout,
                metrics_reason: "timeout",
            },
            UpstreamErrorCategory::Transport => UpstreamHealthFailureMapping {
                failure_reason: HealthFailureReason::Transport,
                metrics_reason: "transport",
            },
            UpstreamErrorCategory::Tls => UpstreamHealthFailureMapping {
                failure_reason: HealthFailureReason::Tls,
                metrics_reason: match self.tls_reason.unwrap_or(UpstreamTlsReason::Handshake) {
                    UpstreamTlsReason::UnknownIssuer => "unknown_issuer",
                    UpstreamTlsReason::ExpiredCertificate => "expired_certificate",
                    UpstreamTlsReason::HostnameMismatch => "hostname_mismatch",
                    UpstreamTlsReason::Alpn => "alpn",
                    UpstreamTlsReason::Handshake => "handshake",
                    UpstreamTlsReason::ClientCertificateMissing => "client_certificate_missing",
                    UpstreamTlsReason::ClientKeyMissing => "client_key_missing",
                    UpstreamTlsReason::ClientIdentityInvalid => "client_identity_invalid",
                    UpstreamTlsReason::ClientAuthRejected => "client_auth_rejected",
                    UpstreamTlsReason::ClientCertificateExpired => "client_certificate_expired",
                },
            },
            UpstreamErrorCategory::Protocol | UpstreamErrorCategory::Internal => {
                UpstreamHealthFailureMapping {
                    failure_reason: HealthFailureReason::Transport,
                    metrics_reason: "transport",
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use impulse_lb::health::HealthFailureReason;

    use super::{
        UpstreamErrorCategory, UpstreamErrorClassification, UpstreamHealthFailureMapping,
        UpstreamTlsReason, classify_upstream_error_detail,
    };

    mod classification_contracts {
        use super::*;

        #[test]
        fn classify_upstream_error_detail_covers_canonical_tls_and_transport_cases() {
            assert_eq!(
                classify_upstream_error_detail("request timed out", false),
                UpstreamErrorClassification::timeout()
            );
            assert_eq!(
                classify_upstream_error_detail("tls handshake failed: UnknownIssuer", true),
                UpstreamErrorClassification::tls(UpstreamTlsReason::UnknownIssuer)
            );
            assert_eq!(
                classify_upstream_error_detail("certificate expired while verifying backend", true),
                UpstreamErrorClassification::tls(UpstreamTlsReason::ExpiredCertificate)
            );
            assert_eq!(
                classify_upstream_error_detail(
                    "certificate not valid for dns name api.example.com",
                    true,
                ),
                UpstreamErrorClassification::tls(UpstreamTlsReason::HostnameMismatch)
            );
            assert_eq!(
                classify_upstream_error_detail("ALPN negotiation failed", true),
                UpstreamErrorClassification::tls(UpstreamTlsReason::Alpn)
            );
            assert_eq!(
                classify_upstream_error_detail("connection reset by peer", false),
                UpstreamErrorClassification::transport()
            );
            assert_eq!(
                classify_upstream_error_detail("x509 certificate validity error", true),
                UpstreamErrorClassification::tls(UpstreamTlsReason::ExpiredCertificate)
            );
            assert_eq!(
                classify_upstream_error_detail("subjectAltName mismatch for backend", true),
                UpstreamErrorClassification::tls(UpstreamTlsReason::HostnameMismatch)
            );
            assert_eq!(
                classify_upstream_error_detail("rustls alert handshake failure", true),
                UpstreamErrorClassification::tls(UpstreamTlsReason::Handshake)
            );
        }

        #[test]
        fn classify_upstream_error_detail_is_case_insensitive_for_timeout_and_tls_signals() {
            assert_eq!(
                classify_upstream_error_detail("Request TIMED OUT while reading body", false),
                UpstreamErrorClassification::timeout()
            );
            assert_eq!(
                classify_upstream_error_detail("RUSTLS alert HANDSHAKE failure", true),
                UpstreamErrorClassification::tls(UpstreamTlsReason::Handshake)
            );
            assert_eq!(
                classify_upstream_error_detail("UNKNOWN ISSUER from backend cert", true),
                UpstreamErrorClassification::tls(UpstreamTlsReason::UnknownIssuer)
            );
        }
    }

    mod health_mapping_contracts {
        use super::*;

        #[test]
        fn health_failure_mapping_preserves_tls_and_transport_reasoning() {
            assert_eq!(
                UpstreamErrorClassification::timeout().health_failure_mapping(),
                UpstreamHealthFailureMapping {
                    failure_reason: HealthFailureReason::Timeout,
                    metrics_reason: "timeout",
                }
            );
            assert_eq!(
                UpstreamErrorClassification::tls(UpstreamTlsReason::UnknownIssuer)
                    .health_failure_mapping(),
                UpstreamHealthFailureMapping {
                    failure_reason: HealthFailureReason::Tls,
                    metrics_reason: "unknown_issuer",
                }
            );
            assert_eq!(
                UpstreamErrorClassification::tls(UpstreamTlsReason::ExpiredCertificate)
                    .health_failure_mapping(),
                UpstreamHealthFailureMapping {
                    failure_reason: HealthFailureReason::Tls,
                    metrics_reason: "expired_certificate",
                }
            );
            assert_eq!(
                UpstreamErrorClassification::tls(UpstreamTlsReason::HostnameMismatch)
                    .health_failure_mapping(),
                UpstreamHealthFailureMapping {
                    failure_reason: HealthFailureReason::Tls,
                    metrics_reason: "hostname_mismatch",
                }
            );
            assert_eq!(
                UpstreamErrorClassification::tls(UpstreamTlsReason::Alpn).health_failure_mapping(),
                UpstreamHealthFailureMapping {
                    failure_reason: HealthFailureReason::Tls,
                    metrics_reason: "alpn",
                }
            );
            assert_eq!(
                UpstreamErrorClassification::transport().health_failure_mapping(),
                UpstreamHealthFailureMapping {
                    failure_reason: HealthFailureReason::Transport,
                    metrics_reason: "transport",
                }
            );
            assert_eq!(
                UpstreamErrorClassification::protocol().health_failure_mapping(),
                UpstreamHealthFailureMapping {
                    failure_reason: HealthFailureReason::Transport,
                    metrics_reason: "transport",
                }
            );
            assert_eq!(
                UpstreamErrorClassification {
                    category: UpstreamErrorCategory::Tls,
                    tls_reason: None,
                }
                .health_failure_mapping(),
                UpstreamHealthFailureMapping {
                    failure_reason: HealthFailureReason::Tls,
                    metrics_reason: "handshake",
                }
            );
        }

        #[test]
        fn protocol_and_internal_classifications_share_transport_health_mapping_contract() {
            assert_eq!(
                UpstreamErrorClassification::protocol().health_failure_mapping(),
                UpstreamHealthFailureMapping {
                    failure_reason: HealthFailureReason::Transport,
                    metrics_reason: "transport",
                }
            );
            assert_eq!(
                UpstreamErrorClassification::internal().health_failure_mapping(),
                UpstreamHealthFailureMapping {
                    failure_reason: HealthFailureReason::Transport,
                    metrics_reason: "transport",
                }
            );
            assert_eq!(
                UpstreamErrorClassification::protocol().category,
                UpstreamErrorCategory::Protocol
            );
            assert_eq!(
                UpstreamErrorClassification::internal().category,
                UpstreamErrorCategory::Internal
            );
        }
    }
}
