use std::{ffi::OsStr, fs, path::Path, time::Duration};

use rustls_pki_types::{CertificateDer, pem::PemObject};
use sha2::{Digest, Sha256};
use x509_parser::parse_x509_certificate;

use super::config_invalid;
use crate::{
    backend_endpoint::BackendEndpoint,
    bounded_file::{BoundedFileReadError, read_file_with_limit},
    config::{HealthCheck, Performance, UpstreamProtocol, UpstreamTls},
    runtime::{
        RuntimeConfigError, RuntimeResolvedSecretMetadata, RuntimeSecretResolver,
        resolve_file_secret_path,
    },
};

const MAX_CA_PEM_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeBackendAddressKind {
    Hostname,
    IpLiteral,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBackendEndpoint {
    pub configured_address: String,
    pub canonical: BackendEndpoint,
    pub origin: String,
    pub authority_host: String,
    pub authority_port: u16,
    pub address_kind: RuntimeBackendAddressKind,
    pub transport_kind: super::RuntimeBackendTransportKind,
}

impl RuntimeBackendEndpoint {
    pub(crate) fn normalize(
        upstream_name: &str,
        backend_id: &str,
        address: &str,
        protocol: UpstreamProtocol,
    ) -> Result<Self, RuntimeConfigError> {
        let canonical = BackendEndpoint::parse(address).map_err(|reason| {
            RuntimeConfigError::BackendAddressInvalid {
                upstream: upstream_name.to_string(),
                backend: backend_id.to_string(),
                address: address.to_string(),
                reason,
            }
        })?;
        let authority_host = canonical.authority_host().to_string();
        let authority_port = canonical.authority_port();
        let address_kind = if canonical.authority_is_ip_literal() {
            RuntimeBackendAddressKind::IpLiteral
        } else {
            RuntimeBackendAddressKind::Hostname
        };
        let transport_kind = match protocol {
            UpstreamProtocol::Auto => super::RuntimeBackendTransportKind::Auto,
            UpstreamProtocol::Http1 => super::RuntimeBackendTransportKind::Http1,
            UpstreamProtocol::Http2 => super::RuntimeBackendTransportKind::H2,
        };
        let origin = canonical.origin();

        Ok(Self {
            configured_address: address.to_string(),
            canonical,
            origin,
            authority_host,
            authority_port,
            address_kind,
            transport_kind,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBackendHealthCheck {
    pub path: String,
    pub interval: Duration,
    pub timeout: Duration,
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub cooldown: Duration,
}

impl RuntimeBackendHealthCheck {
    pub(crate) fn normalize(
        upstream_name: &str,
        backend_id: &str,
        health_check: &HealthCheck,
    ) -> Result<Self, RuntimeConfigError> {
        if health_check.interval == 0 {
            return Err(config_invalid(format!(
                "health check interval is invalid (0) for backend '{backend_id}' in upstream '{upstream_name}'"
            )));
        }
        if health_check.timeout_ms == 0 {
            return Err(config_invalid(format!(
                "health check timeout is invalid (0) for backend '{backend_id}' in upstream '{upstream_name}'"
            )));
        }
        if health_check.failure_threshold == 0 {
            return Err(config_invalid(format!(
                "health check failure threshold is invalid (0) for backend '{backend_id}' in upstream '{upstream_name}'"
            )));
        }
        if health_check.success_threshold == 0 {
            return Err(config_invalid(format!(
                "health check success threshold is invalid (0) for backend '{backend_id}' in upstream '{upstream_name}'"
            )));
        }

        Ok(Self {
            path: if health_check.path.trim().is_empty() {
                "/".to_string()
            } else {
                health_check.path.clone()
            },
            interval: Duration::from_millis(health_check.interval),
            timeout: Duration::from_millis(health_check.timeout_ms),
            failure_threshold: health_check.failure_threshold,
            success_threshold: health_check.success_threshold,
            cooldown: Duration::from_millis(health_check.cooldown_ms),
        })
    }

    #[cfg(test)]
    pub(crate) fn as_config(&self) -> HealthCheck {
        HealthCheck {
            path: self.path.clone(),
            interval: self.interval.as_millis().try_into().unwrap_or(u64::MAX),
            timeout_ms: self.timeout.as_millis().try_into().unwrap_or(u64::MAX),
            failure_threshold: self.failure_threshold,
            success_threshold: self.success_threshold,
            cooldown_ms: self.cooldown.as_millis().try_into().unwrap_or(u64::MAX),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBackendTlsPolicy {
    pub verify_certificates: bool,
    pub strict_sni: bool,
    pub ca_file: Option<String>,
    pub ca_file_fingerprint_sha256: Option<String>,
    pub ca_dir: Option<String>,
    pub ca_dir_fingerprint_sha256: Option<String>,
    pub client_certificate: Option<RuntimeResolvedSecretMetadata>,
    pub client_certificate_not_after_unix_seconds: Option<i64>,
    pub client_key: Option<RuntimeResolvedSecretMetadata>,
    ca_pem_blobs: Vec<Vec<u8>>,
    client_certificate_pem: Option<Vec<u8>>,
    client_key_pem: Option<Vec<u8>>,
}

impl RuntimeBackendTlsPolicy {
    /// A policy for upstreams that never establish a TLS connection (HTTP-only
    /// backends), where TLS-backed config fields are irrelevant and must not
    /// be resolved.
    pub(crate) fn empty() -> Self {
        Self {
            verify_certificates: false,
            strict_sni: false,
            ca_file: None,
            ca_file_fingerprint_sha256: None,
            ca_dir: None,
            ca_dir_fingerprint_sha256: None,
            client_certificate: None,
            client_certificate_not_after_unix_seconds: None,
            client_key: None,
            ca_pem_blobs: Vec::new(),
            client_certificate_pem: None,
            client_key_pem: None,
        }
    }

    pub(crate) fn from_effective_tls(
        effective_tls: &UpstreamTls,
        field_prefix: &str,
        secret_resolver: &RuntimeSecretResolver,
    ) -> Result<Self, RuntimeConfigError> {
        let client_certificate = resolve_optional_secret_material(
            effective_tls.client_certificate.as_deref(),
            effective_tls.client_certificate_ref.as_ref(),
            &format!("{field_prefix}.client_certificate"),
            true,
            secret_resolver,
        )?;
        let client_key = resolve_optional_secret_material(
            effective_tls.client_key.as_deref(),
            effective_tls.client_key_ref.as_ref(),
            &format!("{field_prefix}.client_key"),
            false,
            secret_resolver,
        )?;
        let (ca_file_fingerprint_sha256, ca_file_pem) = load_optional_ca_file(
            effective_tls.ca_file.as_deref(),
            &format!("{field_prefix}.ca_file"),
        )?;
        let (ca_dir_fingerprint_sha256, ca_dir_pem_blobs) = load_optional_ca_dir(
            effective_tls.ca_dir.as_deref(),
            &format!("{field_prefix}.ca_dir"),
        )?;
        let mut ca_pem_blobs = Vec::new();
        if let Some(ca_file_pem) = ca_file_pem {
            ca_pem_blobs.push(ca_file_pem);
        }
        ca_pem_blobs.extend(ca_dir_pem_blobs);

        Ok(Self {
            verify_certificates: effective_tls.verify_certificates,
            strict_sni: effective_tls.strict_sni,
            ca_file: effective_tls.ca_file.clone(),
            ca_file_fingerprint_sha256,
            ca_dir: effective_tls.ca_dir.clone(),
            ca_dir_fingerprint_sha256,
            client_certificate: client_certificate
                .as_ref()
                .map(|material| material.metadata.clone()),
            client_certificate_not_after_unix_seconds: client_certificate
                .as_ref()
                .and_then(|material| material.not_after_unix_seconds),
            client_key: client_key
                .as_ref()
                .map(|material| material.metadata.clone()),
            ca_pem_blobs,
            client_certificate_pem: client_certificate
                .as_ref()
                .map(|material| material.pem_bytes.clone()),
            client_key_pem: client_key
                .as_ref()
                .map(|material| material.pem_bytes.clone()),
        })
    }

    pub fn ca_pem_blobs(&self) -> &[Vec<u8>] {
        &self.ca_pem_blobs
    }

    pub fn client_certificate_pem(&self) -> Option<&[u8]> {
        self.client_certificate_pem.as_deref()
    }

    pub fn client_key_pem(&self) -> Option<&[u8]> {
        self.client_key_pem.as_deref()
    }
}

struct RuntimeSecretMaterial {
    metadata: RuntimeResolvedSecretMetadata,
    not_after_unix_seconds: Option<i64>,
    pem_bytes: Vec<u8>,
}

fn resolve_optional_secret_material(
    legacy_path: Option<&str>,
    secret_ref: Option<&crate::config::SecretRef>,
    field_name: &str,
    expect_certificate_pem: bool,
    secret_resolver: &RuntimeSecretResolver,
) -> Result<Option<RuntimeSecretMaterial>, RuntimeConfigError> {
    let material = match (
        legacy_path.map(str::trim).filter(|value| !value.is_empty()),
        secret_ref,
    ) {
        (Some(path), None) => Some(
            resolve_file_secret_path(path, field_name)
                .map_err(|err| RuntimeConfigError::SecretResolutionFailed(err.to_string()))?,
        ),
        (None, Some(secret_ref)) => Some(
            secret_resolver
                .resolve(secret_ref, field_name)
                .map_err(|err| RuntimeConfigError::SecretResolutionFailed(err.to_string()))?,
        ),
        (Some(_), Some(_)) => {
            return Err(RuntimeConfigError::SecretResolutionFailed(format!(
                "secret resolution failed for {}: conflicting_sources",
                field_name
            )));
        }
        (None, None) => None,
    };

    if let Some(material) = material {
        let pem_bytes = material.bytes().to_vec();
        let not_after_unix_seconds = if expect_certificate_pem {
            let certificates = material
                .parse_pem_certificates(field_name)
                .map_err(|err| RuntimeConfigError::TlsMaterialInvalid(err.to_string()))?;
            Some(first_certificate_not_after_unix_seconds(
                &certificates,
                field_name,
            )?)
        } else {
            material
                .parse_pem_private_key(field_name)
                .map_err(|err| RuntimeConfigError::TlsMaterialInvalid(err.to_string()))?;
            None
        };
        Ok(Some(RuntimeSecretMaterial {
            metadata: material.metadata().clone(),
            not_after_unix_seconds,
            pem_bytes,
        }))
    } else {
        Ok(None)
    }
}

fn first_certificate_not_after_unix_seconds(
    certificates: &[CertificateDer<'static>],
    field_name: &str,
) -> Result<i64, RuntimeConfigError> {
    let leaf = certificates.first().ok_or_else(|| {
        RuntimeConfigError::TlsMaterialInvalid(format!(
            "{field_name} does not contain any PEM certificates"
        ))
    })?;
    let (_, certificate) = parse_x509_certificate(leaf.as_ref()).map_err(|err| {
        RuntimeConfigError::TlsMaterialInvalid(format!(
            "failed to parse X.509 metadata from {field_name}: {err}"
        ))
    })?;
    Ok(certificate.validity().not_after.timestamp())
}

fn load_optional_ca_file(
    ca_file: Option<&str>,
    field_name: &str,
) -> Result<(Option<String>, Option<Vec<u8>>), RuntimeConfigError> {
    let Some(ca_file) = ca_file.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok((None, None));
    };
    let secret = resolve_file_secret_path(ca_file, field_name)
        .map_err(|err| RuntimeConfigError::SecretResolutionFailed(err.to_string()))?;
    secret
        .parse_pem_certificates(field_name)
        .map_err(|err| RuntimeConfigError::TlsMaterialInvalid(err.to_string()))?;
    Ok((
        Some(secret.metadata().fingerprint_sha256.clone()),
        Some(secret.bytes().to_vec()),
    ))
}

fn load_optional_ca_dir(
    ca_dir: Option<&str>,
    field_name: &str,
) -> Result<(Option<String>, Vec<Vec<u8>>), RuntimeConfigError> {
    let Some(ca_dir) = ca_dir.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok((None, Vec::new()));
    };
    let dir = Path::new(ca_dir);
    let entries = fs::read_dir(dir).map_err(|err| {
        RuntimeConfigError::TlsMaterialInvalid(format!(
            "failed to read {field_name} '{ca_dir}': {err}"
        ))
    })?;

    let mut pem_files = entries
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| {
            RuntimeConfigError::TlsMaterialInvalid(format!(
                "failed to read entry in {field_name} '{ca_dir}': {err}"
            ))
        })?
        .into_iter()
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && is_pem_like_path(path))
        .collect::<Vec<_>>();
    pem_files.sort();

    let mut hasher = Sha256::new();
    let mut loaded = 0usize;
    let mut pem_blobs = Vec::new();
    for path in pem_files {
        let bytes = read_file_with_limit(&path, MAX_CA_PEM_BYTES).map_err(|err| match err {
            BoundedFileReadError::Io(io_err) => RuntimeConfigError::TlsMaterialInvalid(format!(
                "failed to read {field_name} entry '{}': {io_err}",
                path.display()
            )),
            BoundedFileReadError::NotAFile => RuntimeConfigError::TlsMaterialInvalid(format!(
                "{field_name} entry '{}' must be a file",
                path.display()
            )),
            BoundedFileReadError::TooLarge => RuntimeConfigError::TlsMaterialInvalid(format!(
                "{field_name} entry '{}' exceeds the maximum supported PEM size ({} bytes)",
                path.display(),
                MAX_CA_PEM_BYTES
            )),
        })?;
        let certs = CertificateDer::pem_slice_iter(&bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| {
                RuntimeConfigError::TlsMaterialInvalid(format!(
                    "failed to parse PEM certificates from {field_name} entry '{}': {err}",
                    path.display()
                ))
            })?;
        if certs.is_empty() {
            return Err(RuntimeConfigError::TlsMaterialInvalid(format!(
                "{field_name} entry '{}' does not contain any PEM certificates",
                path.display()
            )));
        }
        loaded = loaded.saturating_add(certs.len());
        hasher.update(path.to_string_lossy().as_bytes());
        hasher.update([0u8]);
        hasher.update(&bytes);
        hasher.update([0u8]);
        pem_blobs.push(bytes);
    }

    if loaded == 0 {
        return Err(RuntimeConfigError::TlsMaterialInvalid(format!(
            "{field_name} '{ca_dir}' did not contain any readable PEM certificates"
        )));
    }

    Ok((Some(hex::encode(hasher.finalize())), pem_blobs))
}

fn is_pem_like_path(path: &Path) -> bool {
    matches!(
        path.extension().and_then(OsStr::to_str),
        Some("pem" | "crt" | "cer" | "PEM" | "CRT" | "CER")
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBackendDnsPolicy {
    pub refresh_enabled: bool,
    pub refresh_interval: Duration,
}

impl RuntimeBackendDnsPolicy {
    pub(crate) fn from_performance(performance: &Performance) -> Self {
        Self {
            refresh_enabled: performance.backend_dns_refresh_enabled,
            refresh_interval: Duration::from_millis(performance.backend_dns_refresh_interval_ms),
        }
    }
}

#[cfg(test)]
mod tests {
    use rcgen::{Certificate, CertificateParams, SanType};
    use tempfile::tempdir;

    use super::*;
    use crate::{backend_endpoint::BackendScheme, runtime::RuntimeBackendTransportKind};

    fn assert_config_invalid(err: RuntimeConfigError, expected: impl AsRef<str>) {
        let expected = expected.as_ref();
        assert_eq!(err.category(), "config_invalid");
        assert_eq!(err.to_string(), format!("config_invalid: {expected}"));
    }

    fn write_test_cert(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
        let mut params = CertificateParams::new(vec!["localhost".into()]);
        params
            .subject_alt_names
            .push(SanType::IpAddress("127.0.0.1".parse().expect("ip")));
        let cert = Certificate::from_params(params).expect("cert");
        let path = dir.join(name);
        std::fs::write(&path, cert.serialize_pem().expect("serialize cert")).expect("write cert");
        path
    }

    #[test]
    fn runtime_backend_endpoint_normalizes_hostname_backend_and_canonical_authority() {
        let endpoint = RuntimeBackendEndpoint::normalize(
            "payments",
            "primary",
            "api.example.com",
            UpstreamProtocol::Auto,
        )
        .expect("hostname backend");

        assert_eq!(endpoint.configured_address, "api.example.com");
        assert_eq!(endpoint.origin, "https://api.example.com:443");
        assert_eq!(endpoint.authority_host, "api.example.com");
        assert_eq!(endpoint.authority_port, 443);
        assert_eq!(endpoint.address_kind, RuntimeBackendAddressKind::Hostname);
        assert_eq!(endpoint.transport_kind, RuntimeBackendTransportKind::Auto);
        assert_eq!(endpoint.canonical.scheme(), BackendScheme::Https);
        assert_eq!(endpoint.canonical.authority(), "api.example.com:443");
    }

    #[test]
    fn runtime_backend_endpoint_normalizes_ip_literal_backend_and_canonical_authority() {
        let endpoint = RuntimeBackendEndpoint::normalize(
            "payments",
            "edge-ipv6",
            "https://[2001:db8::10]:9443",
            UpstreamProtocol::Http2,
        )
        .expect("ip literal backend");

        assert_eq!(endpoint.origin, "https://[2001:db8::10]:9443");
        assert_eq!(endpoint.authority_host, "2001:db8::10");
        assert_eq!(endpoint.authority_port, 9443);
        assert_eq!(endpoint.address_kind, RuntimeBackendAddressKind::IpLiteral);
        assert_eq!(endpoint.transport_kind, RuntimeBackendTransportKind::H2);
        assert_eq!(endpoint.canonical.authority(), "[2001:db8::10]:9443");
    }

    #[test]
    fn runtime_backend_endpoint_uses_protocol_independently_of_scheme() {
        let http_endpoint = RuntimeBackendEndpoint::normalize(
            "payments",
            "legacy",
            "http://127.0.0.1:8080",
            UpstreamProtocol::Http2,
        )
        .expect("http backend");
        let https_endpoint = RuntimeBackendEndpoint::normalize(
            "payments",
            "modern",
            "https://api.example.com:8443",
            UpstreamProtocol::Http1,
        )
        .expect("https backend");

        assert_eq!(
            http_endpoint.transport_kind,
            RuntimeBackendTransportKind::H2
        );
        assert_eq!(http_endpoint.authority_host, "127.0.0.1");
        assert_eq!(http_endpoint.authority_port, 8080);
        assert_eq!(
            http_endpoint.address_kind,
            RuntimeBackendAddressKind::IpLiteral
        );
        assert_eq!(http_endpoint.canonical.scheme(), BackendScheme::Http);

        assert_eq!(
            https_endpoint.transport_kind,
            RuntimeBackendTransportKind::Http1
        );
        assert_eq!(https_endpoint.authority_host, "api.example.com");
        assert_eq!(https_endpoint.authority_port, 8443);
        assert_eq!(
            https_endpoint.address_kind,
            RuntimeBackendAddressKind::Hostname
        );
        assert_eq!(https_endpoint.canonical.scheme(), BackendScheme::Https);
    }

    #[test]
    fn runtime_backend_tls_policy_shapes_effective_tls_settings() {
        let dir = tempdir().expect("tempdir");
        let ca_file = write_test_cert(dir.path(), "ca.pem");
        let ca_dir = dir.path().join("ca.d");
        std::fs::create_dir_all(&ca_dir).expect("create ca dir");
        let ca_dir_entry = write_test_cert(&ca_dir, "ca-entry.pem");

        let effective_tls = UpstreamTls {
            verify_certificates: false,
            strict_sni: false,
            ca_file: Some(ca_file.to_string_lossy().to_string()),
            ca_dir: Some(ca_dir.to_string_lossy().to_string()),
            client_certificate: None,
            client_certificate_ref: None,
            client_key: None,
            client_key_ref: None,
        };

        let policy = RuntimeBackendTlsPolicy::from_effective_tls(
            &effective_tls,
            "upstream 'payments' tls",
            &RuntimeSecretResolver::default(),
        )
        .expect("backend tls policy");

        assert_eq!(
            policy,
            RuntimeBackendTlsPolicy {
                verify_certificates: false,
                strict_sni: false,
                ca_file: Some(ca_file.to_string_lossy().to_string()),
                ca_file_fingerprint_sha256: Some(
                    resolve_file_secret_path(
                        &ca_file.to_string_lossy(),
                        "upstream 'payments' tls.ca_file",
                    )
                    .expect("ca file secret")
                    .metadata()
                    .fingerprint_sha256
                    .clone(),
                ),
                ca_dir: Some(ca_dir.to_string_lossy().to_string()),
                ca_dir_fingerprint_sha256: Some({
                    let bytes = std::fs::read(&ca_dir_entry).expect("read ca dir entry");
                    let mut hasher = Sha256::new();
                    hasher.update(ca_dir_entry.to_string_lossy().as_bytes());
                    hasher.update([0u8]);
                    hasher.update(bytes);
                    hasher.update([0u8]);
                    hex::encode(hasher.finalize())
                }),
                client_certificate: None,
                client_certificate_not_after_unix_seconds: None,
                client_key: None,
                ca_pem_blobs: vec![
                    std::fs::read(&ca_file).expect("read ca file"),
                    std::fs::read(&ca_dir_entry).expect("read ca dir entry"),
                ],
                client_certificate_pem: None,
                client_key_pem: None,
            }
        );
    }

    #[test]
    fn runtime_backend_tls_policy_populates_upstream_client_certificate_expiry() {
        let dir = tempdir().expect("tempdir");
        let client_cert = write_test_cert(dir.path(), "client-cert.pem");
        let client_key = dir.path().join("client-key.pem");
        let cert = Certificate::from_params(CertificateParams::new(vec!["localhost".into()]))
            .expect("certificate");
        std::fs::write(&client_key, cert.serialize_private_key_pem()).expect("write key");
        std::fs::write(&client_cert, cert.serialize_pem().expect("serialize cert"))
            .expect("write cert");

        let effective_tls = UpstreamTls {
            verify_certificates: true,
            strict_sni: true,
            ca_file: None,
            ca_dir: None,
            client_certificate: Some(client_cert.to_string_lossy().to_string()),
            client_certificate_ref: None,
            client_key: Some(client_key.to_string_lossy().to_string()),
            client_key_ref: None,
        };

        let policy = RuntimeBackendTlsPolicy::from_effective_tls(
            &effective_tls,
            "upstream 'payments' tls",
            &RuntimeSecretResolver::default(),
        )
        .expect("backend tls policy");

        assert!(
            policy.client_certificate_not_after_unix_seconds.is_some(),
            "expected upstream client certificate expiry to be populated"
        );
    }

    #[test]
    fn runtime_backend_dns_policy_shapes_refresh_settings_from_performance() {
        let performance = Performance {
            backend_dns_refresh_enabled: true,
            backend_dns_refresh_interval_ms: 45_000,
            ..Performance::default()
        };

        let policy = RuntimeBackendDnsPolicy::from_performance(&performance);

        assert!(policy.refresh_enabled);
        assert_eq!(policy.refresh_interval, Duration::from_millis(45_000));
    }

    #[test]
    fn runtime_backend_tls_policy_rejects_oversized_ca_dir_entry() {
        let dir = tempdir().expect("tempdir");
        let ca_dir = dir.path().join("ca.d");
        std::fs::create_dir_all(&ca_dir).expect("create ca dir");
        let huge_entry = ca_dir.join("huge.pem");
        std::fs::write(&huge_entry, vec![b'A'; (MAX_CA_PEM_BYTES as usize) + 1]).expect("write");

        let effective_tls = UpstreamTls {
            verify_certificates: true,
            strict_sni: true,
            ca_file: None,
            ca_dir: Some(ca_dir.to_string_lossy().to_string()),
            client_certificate: None,
            client_certificate_ref: None,
            client_key: None,
            client_key_ref: None,
        };

        let err = RuntimeBackendTlsPolicy::from_effective_tls(
            &effective_tls,
            "upstream 'payments' tls",
            &RuntimeSecretResolver::default(),
        )
        .expect_err("oversized CA dir entry must be rejected");

        assert_eq!(err.category(), "tls_material_invalid");
        assert!(
            err.to_string()
                .contains("exceeds the maximum supported PEM size"),
            "{err}"
        );
    }

    #[test]
    fn runtime_backend_health_check_normalizes_values_and_blank_path() {
        let health_check = HealthCheck {
            path: "   ".to_string(),
            interval: 5_000,
            timeout_ms: 900,
            failure_threshold: 4,
            success_threshold: 2,
            cooldown_ms: 1_500,
        };

        let normalized = RuntimeBackendHealthCheck::normalize("payments", "primary", &health_check)
            .expect("health check");

        assert_eq!(
            normalized,
            RuntimeBackendHealthCheck {
                path: "/".to_string(),
                interval: Duration::from_millis(5_000),
                timeout: Duration::from_millis(900),
                failure_threshold: 4,
                success_threshold: 2,
                cooldown: Duration::from_millis(1_500),
            }
        );
    }

    #[test]
    fn runtime_backend_health_check_rejects_zero_value_fields() {
        let cases = [
            (
                "health check interval is invalid (0) for backend 'primary' in upstream 'payments'",
                HealthCheck {
                    interval: 0,
                    ..valid_health_check()
                },
            ),
            (
                "health check timeout is invalid (0) for backend 'primary' in upstream 'payments'",
                HealthCheck {
                    timeout_ms: 0,
                    ..valid_health_check()
                },
            ),
            (
                "health check failure threshold is invalid (0) for backend 'primary' in upstream 'payments'",
                HealthCheck {
                    failure_threshold: 0,
                    ..valid_health_check()
                },
            ),
            (
                "health check success threshold is invalid (0) for backend 'primary' in upstream 'payments'",
                HealthCheck {
                    success_threshold: 0,
                    ..valid_health_check()
                },
            ),
        ];

        for (expected, health_check) in cases {
            let err = RuntimeBackendHealthCheck::normalize("payments", "primary", &health_check)
                .expect_err(expected);
            assert_config_invalid(err, expected);
        }
    }

    fn valid_health_check() -> HealthCheck {
        HealthCheck {
            path: "/health".to_string(),
            interval: 1_000,
            timeout_ms: 500,
            failure_threshold: 3,
            success_threshold: 2,
            cooldown_ms: 250,
        }
    }
}
