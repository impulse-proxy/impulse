//! Upstream TLS lowering: effective-TLS resolution and validation.

use impulse_config::{
    config::{ForwardedHeaderPolicyMode, SecretRef, UpstreamHostPolicyMode, UpstreamTls},
    runtime::RuntimeBackendTransportKind,
};
use rcgen::{Certificate, CertificateParams, SanType};
use tempfile::tempdir;

use crate::common::{
    api_backend_mut, api_runtime_upstream, api_upstream_mut, assert_config_error_contains,
    sample_runtime_config_err_with, sample_runtime_config_with,
};

fn write_test_certs(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let mut params = CertificateParams::new(vec!["localhost".into()]);
    params
        .subject_alt_names
        .push(SanType::IpAddress("127.0.0.1".parse().expect("ip")));
    let cert = Certificate::from_params(params).expect("build cert");

    let cert_path = dir.join("client-cert.pem");
    let key_path = dir.join("client-key.pem");
    std::fs::write(&cert_path, cert.serialize_pem().expect("serialize cert")).expect("cert");
    std::fs::write(&key_path, cert.serialize_private_key_pem()).expect("key");

    (cert_path, key_path)
}

fn write_test_ca(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let cert = Certificate::from_params(CertificateParams::new(vec!["upstream-ca".into()]))
        .expect("build ca");
    let ca_file = dir.join("upstream-ca.pem");
    let ca_dir = dir.join("ca-dir");
    std::fs::create_dir_all(&ca_dir).expect("create ca dir");
    std::fs::write(&ca_file, cert.serialize_pem().expect("serialize ca")).expect("write ca");
    std::fs::write(
        ca_dir.join("root.pem"),
        cert.serialize_pem().expect("serialize ca dir root"),
    )
    .expect("write ca dir root");
    (ca_file, ca_dir)
}

#[test]
fn runtime_config_lowers_effective_tls_and_upstream_policy_wrappers() {
    let dir = tempdir().expect("tempdir");
    let (global_ca_file, _global_ca_dir) = write_test_ca(dir.path());
    let (upstream_ca_file, upstream_ca_dir) = write_test_ca(dir.path());

    let runtime = sample_runtime_config_with(|config| {
        config.upstream_tls = UpstreamTls {
            verify_certificates: true,
            strict_sni: true,
            ca_file: Some(global_ca_file.to_string_lossy().to_string()),
            ca_dir: None,
            client_certificate: None,
            client_certificate_ref: None,
            client_key: None,
            client_key_ref: None,
        };
        api_upstream_mut(config).tls = Some(UpstreamTls {
            verify_certificates: false,
            strict_sni: false,
            ca_file: Some(upstream_ca_file.to_string_lossy().to_string()),
            ca_dir: Some(upstream_ca_dir.to_string_lossy().to_string()),
            client_certificate: None,
            client_certificate_ref: None,
            client_key: None,
            client_key_ref: None,
        });
    });
    let upstream = api_runtime_upstream(&runtime);

    assert_eq!(upstream.name, "api");
    assert!(!upstream.effective_tls.verify_certificates);
    assert!(!upstream.effective_tls.strict_sni);
    assert_eq!(
        upstream.effective_tls.ca_file.as_deref(),
        Some(upstream_ca_file.to_string_lossy().as_ref())
    );
    assert_eq!(upstream.backends.len(), 1);
    assert_eq!(
        upstream.backends[0].backend.address,
        "https://api.internal:8443"
    );
    assert_eq!(upstream.backends[0].endpoint.authority_host, "api.internal");
    assert_eq!(upstream.backends[0].endpoint.authority_port, 8443);
    assert_eq!(
        upstream.backends[0].endpoint.transport_kind,
        RuntimeBackendTransportKind::Http1
    );
    assert_eq!(
        upstream.backend_tls_policy().ca_file.as_deref(),
        Some(upstream_ca_file.to_string_lossy().as_ref())
    );
    assert_eq!(upstream.policy.host.0.mode, UpstreamHostPolicyMode::Rewrite);
    assert_eq!(
        upstream.policy.forwarded_headers.0.mode,
        ForwardedHeaderPolicyMode::Append
    );
}

#[test]
fn runtime_config_skips_global_tls_validation_for_http_only_upstreams() {
    let runtime = sample_runtime_config_with(|config| {
        api_backend_mut(config).address = "http://127.0.0.1:8080".to_string();
        config.upstream_tls.ca_file = Some("   ".to_string());
        config.upstream_tls.ca_dir = Some("   ".to_string());
    });
    let upstream = api_runtime_upstream(&runtime);

    assert_eq!(
        upstream.backends[0].backend.address,
        "http://127.0.0.1:8080"
    );
}

#[test]
fn runtime_config_skips_per_upstream_tls_validation_for_http_only_upstreams() {
    let runtime = sample_runtime_config_with(|config| {
        api_backend_mut(config).address = "http://127.0.0.1:8080".to_string();
        api_upstream_mut(config).tls = Some(UpstreamTls {
            verify_certificates: true,
            strict_sni: true,
            ca_file: Some("   ".to_string()),
            ca_dir: Some("   ".to_string()),
            client_certificate: None,
            client_certificate_ref: None,
            client_key: None,
            client_key_ref: None,
        });
    });
    let upstream = api_runtime_upstream(&runtime);

    assert_eq!(
        upstream.backends[0].backend.address,
        "http://127.0.0.1:8080"
    );
}

#[test]
fn runtime_config_requires_non_empty_effective_tls_fields_for_https_upstreams() {
    let err = sample_runtime_config_err_with(|config| {
        config.upstream_tls.ca_file = Some("   ".to_string());
    });
    assert_config_error_contains(
        &err,
        "tls_material_invalid",
        "upstream 'api' has an empty effective upstream_tls.ca_file",
    );
}

#[test]
fn runtime_config_lowers_upstream_mtls_metadata_for_https_backends() {
    let dir = tempdir().expect("tempdir");
    let (cert_path, key_path) = write_test_certs(dir.path());
    let (ca_file, ca_dir) = write_test_ca(dir.path());

    let runtime = sample_runtime_config_with(|config| {
        api_upstream_mut(config).tls = Some(UpstreamTls {
            verify_certificates: true,
            strict_sni: false,
            ca_file: Some(ca_file.to_string_lossy().to_string()),
            ca_dir: Some(ca_dir.to_string_lossy().to_string()),
            client_certificate: None,
            client_certificate_ref: Some(SecretRef {
                reference: format!("file://{}", cert_path.display()),
            }),
            client_key: None,
            client_key_ref: Some(SecretRef {
                reference: format!("file://{}", key_path.display()),
            }),
        });
    });
    let upstream = api_runtime_upstream(&runtime);
    let tls_policy = upstream.backend_tls_policy();

    assert_eq!(
        tls_policy.ca_file.as_deref(),
        Some(ca_file.to_string_lossy().as_ref())
    );
    assert_eq!(
        tls_policy.ca_dir.as_deref(),
        Some(ca_dir.to_string_lossy().as_ref())
    );
    assert!(!tls_policy.strict_sni);
    assert_eq!(
        tls_policy
            .client_certificate
            .as_ref()
            .map(|metadata| metadata.source_kind.as_str()),
        Some("file")
    );
    assert_eq!(
        tls_policy
            .client_key
            .as_ref()
            .map(|metadata| metadata.source_kind.as_str()),
        Some("file")
    );
    assert!(
        tls_policy
            .client_certificate
            .as_ref()
            .is_some_and(
                |metadata| !metadata.fingerprint_sha256.is_empty() && metadata.byte_len > 0
            )
    );
    assert!(
        tls_policy
            .client_key
            .as_ref()
            .is_some_and(
                |metadata| !metadata.fingerprint_sha256.is_empty() && metadata.byte_len > 0
            )
    );
}

#[test]
fn runtime_config_rejects_upstream_mtls_without_key() {
    let dir = tempdir().expect("tempdir");
    let (cert_path, _) = write_test_certs(dir.path());

    let err = sample_runtime_config_err_with(|config| {
        api_upstream_mut(config).tls = Some(UpstreamTls {
            verify_certificates: true,
            strict_sni: true,
            ca_file: None,
            ca_dir: None,
            client_certificate: None,
            client_certificate_ref: Some(SecretRef {
                reference: format!("file://{}", cert_path.display()),
            }),
            client_key: None,
            client_key_ref: None,
        });
    });

    assert_config_error_contains(
        &err,
        "unsupported_policy_combination",
        "upstream 'api' tls.client_certificate and tls.client_key must be configured as a complete mTLS pair",
    );
}

#[test]
fn runtime_config_rejects_upstream_mtls_without_certificate() {
    let dir = tempdir().expect("tempdir");
    let (_, key_path) = write_test_certs(dir.path());

    let err = sample_runtime_config_err_with(|config| {
        api_upstream_mut(config).tls = Some(UpstreamTls {
            verify_certificates: true,
            strict_sni: true,
            ca_file: None,
            ca_dir: None,
            client_certificate: None,
            client_certificate_ref: None,
            client_key: None,
            client_key_ref: Some(SecretRef {
                reference: format!("file://{}", key_path.display()),
            }),
        });
    });

    assert_config_error_contains(
        &err,
        "unsupported_policy_combination",
        "upstream 'api' tls.client_certificate and tls.client_key must be configured as a complete mTLS pair",
    );
}

#[test]
fn runtime_config_rejects_upstream_mtls_for_http_backends() {
    let dir = tempdir().expect("tempdir");
    let (cert_path, key_path) = write_test_certs(dir.path());

    let err = sample_runtime_config_err_with(|config| {
        api_backend_mut(config).address = "http://127.0.0.1:8080".to_string();
        api_upstream_mut(config).tls = Some(UpstreamTls {
            verify_certificates: true,
            strict_sni: true,
            ca_file: None,
            ca_dir: None,
            client_certificate: None,
            client_certificate_ref: Some(SecretRef {
                reference: format!("file://{}", cert_path.display()),
            }),
            client_key: None,
            client_key_ref: Some(SecretRef {
                reference: format!("file://{}", key_path.display()),
            }),
        });
    });

    assert_config_error_contains(
        &err,
        "unsupported_policy_combination",
        "upstream 'api' tls.client_certificate/tls.client_key require at least one HTTPS backend",
    );
}
