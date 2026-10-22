//! Reload-boundary contracts for runtime lowering.

use std::time::Duration;

use impulse_config::{
    config::{Listen, LogFormat, SecretRef, Tls, UpstreamTls},
    runtime::RuntimeListenerSource,
};
use rcgen::{Certificate, CertificateParams, SanType};
use tempfile::tempdir;

use crate::common::{
    api_runtime_upstream, api_upstream_mut, primary_listener_runtime_config,
    sample_runtime_config_with,
};

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

fn write_test_key_pair(
    dir: &std::path::Path,
    cert_name: &str,
    key_name: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let mut params = CertificateParams::new(vec!["localhost".into()]);
    params
        .subject_alt_names
        .push(SanType::IpAddress("127.0.0.1".parse().expect("ip")));
    let cert = Certificate::from_params(params).expect("identity");
    let cert_path = dir.join(cert_name);
    let key_path = dir.join(key_name);
    std::fs::write(&cert_path, cert.serialize_pem().expect("serialize cert")).expect("cert");
    std::fs::write(&key_path, cert.serialize_private_key_pem()).expect("key");
    (cert_path, key_path)
}

#[test]
fn runtime_config_keeps_generation_policies_normalized_and_listener_inputs_raw() {
    let runtime = sample_runtime_config_with(|config| {
        config.performance.backend_timeout_ms = 2_400;
        config.performance.backend_connect_timeout_ms = 600;
        config.performance.backend_body_idle_timeout_ms = 3_000;
        config.performance.backend_body_total_timeout_ms = 4_000;
        config.performance.backend_total_request_timeout_ms = 5_000;
        config.performance.worker_threads = 7;
        config.performance.packet_shards_per_worker = 3;
        config.performance.reuseport = true;
        config.performance.quic_initial_max_data = 2_000_000;
        config.observability.tracing.enabled = true;
        config.observability.tracing.service_name = "impulse-edge-prod".to_string();
        config.observability.tracing.sample_ratio = 0.42;
        config.observability.tracing.otlp_endpoint =
            Some("http://otel-collector.internal:4317".to_string());
    });
    let policies = &runtime.policies;
    let listener = primary_listener_runtime_config(&runtime);

    assert_eq!(
        policies.timeouts.backend_request,
        Duration::from_millis(2_400)
    );
    assert_eq!(
        policies.timeouts.backend_connect,
        Duration::from_millis(600)
    );
    assert_eq!(policies.transport.quic_initial_max_data, 2_000_000);
    assert_eq!(listener.policies.timeouts, policies.timeouts);
    assert_eq!(listener.policies.transport, policies.transport);

    assert_eq!(listener.performance.backend_timeout_ms, 2_400);
    assert_eq!(listener.performance.backend_connect_timeout_ms, 600);
    assert_eq!(listener.performance.worker_threads, 7);
    assert_eq!(listener.performance.packet_shards_per_worker, 3);
    assert!(listener.performance.reuseport);

    assert!(listener.observability.tracing.enabled);
    assert_eq!(
        listener.observability.tracing.service_name,
        "impulse-edge-prod"
    );
    assert_eq!(listener.observability.tracing.sample_ratio, 0.42);
    assert_eq!(
        listener.observability.tracing.otlp_endpoint.as_deref(),
        Some("http://otel-collector.internal:4317")
    );
}

#[test]
fn runtime_config_keeps_explicit_listener_topology_and_tls_identities_listener_owned() {
    let runtime = sample_runtime_config_with(|config| {
        config.performance.backend_timeout_ms = 1_750;
        config.performance.backend_connect_timeout_ms = 500;
        config.observability.control_api.enabled = true;
        config.observability.control_api.address = "127.0.0.1".to_string();
        config.observability.control_api.port = 9891;
        config.observability.metrics.enabled = true;
        config.observability.metrics.address = "127.0.0.1".to_string();
        config.observability.metrics.port = 9890;
        config.listeners = vec![
            Listen {
                protocol: "http3".to_string(),
                port: 8443,
                address: "127.0.0.1".to_string(),
                tls: Tls {
                    cert: "/tmp/tls/edge-a.pem".to_string(),
                    key: "/tmp/tls/edge-a.key".to_string(),
                    certificates: Vec::new(),
                    client_auth: Default::default(),
                },
            },
            Listen {
                protocol: "http3".to_string(),
                port: 9443,
                address: "127.0.0.2".to_string(),
                tls: Tls {
                    cert: "/tmp/tls/edge-b.pem".to_string(),
                    key: "/tmp/tls/edge-b.key".to_string(),
                    certificates: Vec::new(),
                    client_auth: Default::default(),
                },
            },
        ];
    });
    let listeners = runtime.listener_runtime_configs();

    assert_eq!(listeners.len(), 2);
    assert_eq!(
        listeners[0].listen.source,
        RuntimeListenerSource::ExplicitListeners
    );
    assert_eq!(
        listeners[1].listen.source,
        RuntimeListenerSource::ExplicitListeners
    );
    assert_eq!(listeners[0].listen.listen.address, "127.0.0.1");
    assert_eq!(listeners[0].listen.listen.port, 8443);
    assert_eq!(listeners[1].listen.listen.address, "127.0.0.2");
    assert_eq!(listeners[1].listen.listen.port, 9443);
    assert_eq!(
        listeners[0].listen.tls.default_identity.cert_path,
        "/tmp/tls/edge-a.pem"
    );
    assert_eq!(
        listeners[1].listen.tls.default_identity.cert_path,
        "/tmp/tls/edge-b.pem"
    );

    assert_eq!(
        listeners[0].policies.timeouts,
        listeners[1].policies.timeouts
    );
    assert_eq!(
        listeners[0].policies.transport,
        listeners[1].policies.transport
    );

    assert!(listeners[0].observability.control_api.enabled);
    assert_eq!(listeners[0].observability.control_api.port, 9891);
    assert!(listeners[1].observability.metrics.enabled);
    assert_eq!(listeners[1].observability.metrics.port, 9890);
}

#[test]
fn runtime_config_excludes_log_sink_shape_from_generation_owned_runtime_state() {
    let plain_runtime = sample_runtime_config_with(|config| {
        config.log.level = "warn".to_string();
        config.log.file.enabled = false;
        config.log.format = LogFormat::Plain;
    });
    let json_runtime = sample_runtime_config_with(|config| {
        config.log.level = "debug".to_string();
        config.log.file.enabled = true;
        config.log.file.path = "/var/log/impulse/edge.json".to_string();
        config.log.format = LogFormat::Json;
    });

    assert_eq!(
        plain_runtime.policies.timeouts,
        json_runtime.policies.timeouts
    );
    assert_eq!(
        plain_runtime.policies.transport,
        json_runtime.policies.transport
    );
    assert_eq!(plain_runtime.listeners.len(), json_runtime.listeners.len());
    assert_eq!(
        plain_runtime.listeners[0].listen.address,
        json_runtime.listeners[0].listen.address
    );
    assert_eq!(
        plain_runtime.listeners[0].listen.port,
        json_runtime.listeners[0].listen.port
    );

    let plain_listener = primary_listener_runtime_config(&plain_runtime);
    let json_listener = primary_listener_runtime_config(&json_runtime);
    assert_eq!(
        plain_listener.policies.timeouts,
        json_listener.policies.timeouts
    );
    assert_eq!(
        plain_listener.policies.transport,
        json_listener.policies.transport
    );
}

#[test]
fn runtime_config_fingerprints_same_path_upstream_client_tls_material_changes() {
    let dir = tempdir().expect("tempdir");
    let ca_path = write_test_cert(dir.path(), "ca.pem");
    let cert_path = dir.path().join("client-cert.pem");
    let key_path = dir.path().join("client-key.pem");

    let _ = write_test_key_pair(dir.path(), "client-cert.pem", "client-key.pem");
    let first_runtime = sample_runtime_config_with(|config| {
        config.upstream_tls = UpstreamTls {
            verify_certificates: true,
            strict_sni: true,
            ca_file: Some(ca_path.to_string_lossy().to_string()),
            ca_dir: None,
            client_certificate: None,
            client_certificate_ref: Some(SecretRef {
                reference: format!("file://{}", cert_path.display()),
            }),
            client_key: None,
            client_key_ref: Some(SecretRef {
                reference: format!("file://{}", key_path.display()),
            }),
        };
    });

    let first_policy = api_runtime_upstream(&first_runtime)
        .backend_tls_policy()
        .clone();

    let _ = write_test_key_pair(dir.path(), "client-cert.pem", "client-key.pem");
    let second_runtime = sample_runtime_config_with(|config| {
        config.upstream_tls = UpstreamTls {
            verify_certificates: true,
            strict_sni: true,
            ca_file: Some(ca_path.to_string_lossy().to_string()),
            ca_dir: None,
            client_certificate: None,
            client_certificate_ref: Some(SecretRef {
                reference: format!("file://{}", cert_path.display()),
            }),
            client_key: None,
            client_key_ref: Some(SecretRef {
                reference: format!("file://{}", key_path.display()),
            }),
        };
    });
    let second_policy = api_runtime_upstream(&second_runtime)
        .backend_tls_policy()
        .clone();

    assert_ne!(
        first_policy
            .client_certificate
            .as_ref()
            .map(|metadata| metadata.fingerprint_sha256.clone()),
        second_policy
            .client_certificate
            .as_ref()
            .map(|metadata| metadata.fingerprint_sha256.clone())
    );
    assert_ne!(
        first_policy
            .client_key
            .as_ref()
            .map(|metadata| metadata.fingerprint_sha256.clone()),
        second_policy
            .client_key
            .as_ref()
            .map(|metadata| metadata.fingerprint_sha256.clone())
    );
}

#[test]
fn runtime_config_fingerprints_same_path_upstream_ca_changes() {
    let dir = tempdir().expect("tempdir");
    let ca_path = dir.path().join("ca.pem");
    std::fs::copy(write_test_cert(dir.path(), "ca-initial.pem"), &ca_path).expect("initial ca");

    let first_runtime = sample_runtime_config_with(|config| {
        api_upstream_mut(config).tls = Some(UpstreamTls {
            verify_certificates: true,
            strict_sni: true,
            ca_file: Some(ca_path.to_string_lossy().to_string()),
            ca_dir: None,
            client_certificate: None,
            client_certificate_ref: None,
            client_key: None,
            client_key_ref: None,
        });
    });
    let first_policy = api_runtime_upstream(&first_runtime)
        .backend_tls_policy()
        .clone();

    let next_ca = write_test_cert(dir.path(), "ca-next.pem");
    std::fs::copy(next_ca, &ca_path).expect("rotated ca");
    let second_runtime = sample_runtime_config_with(|config| {
        api_upstream_mut(config).tls = Some(UpstreamTls {
            verify_certificates: true,
            strict_sni: true,
            ca_file: Some(ca_path.to_string_lossy().to_string()),
            ca_dir: None,
            client_certificate: None,
            client_certificate_ref: None,
            client_key: None,
            client_key_ref: None,
        });
    });
    let second_policy = api_runtime_upstream(&second_runtime)
        .backend_tls_policy()
        .clone();

    assert_ne!(
        first_policy.ca_file_fingerprint_sha256,
        second_policy.ca_file_fingerprint_sha256
    );
}
