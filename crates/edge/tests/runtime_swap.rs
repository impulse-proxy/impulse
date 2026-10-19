use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use bytes::Bytes;
use http_body_util::Full;
use impulse_config::config::{
    Backend, Config, LoadBalancing, RouteMatch, SecretRef, Upstream, UpstreamTls,
};
use impulse_edge::runtime::policy::{LifecycleTransitionResult, RuntimeLifecyclePhase};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose, SanType,
};
use serial_test::serial;
use tempfile::{TempDir, tempdir};

mod support;

use support::{
    net::local_listener_bind_available,
    request_path::{H3RequestSpec, TestTlsMaterial, run_request_to},
    runtime_swap::RuntimeSwapHarness,
    static_full_response,
};

struct MtlsRuntimeMaterial {
    _dir: TempDir,
    ca: Certificate,
    ca_cert_path: String,
    client_cert_path: String,
    client_key_path: String,
    server_cert_path: String,
    server_key_path: String,
}

impl MtlsRuntimeMaterial {
    fn localhost() -> Self {
        let dir = tempdir().expect("tempdir");
        let ca = build_ca("Impulse Runtime Swap CA");
        let (server_cert, server_key) = signed_cert(
            "localhost",
            &ca,
            vec!["localhost".to_string()],
            vec![
                SanType::DnsName("localhost".to_string()),
                SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1])),
            ],
            ExtendedKeyUsagePurpose::ServerAuth,
        );
        let (client_cert, client_key) = signed_cert(
            "runtime-client",
            &ca,
            Vec::new(),
            Vec::new(),
            ExtendedKeyUsagePurpose::ClientAuth,
        );

        let ca_cert_path = dir.path().join("ca.pem");
        let client_cert_path = dir.path().join("client-cert.pem");
        let client_key_path = dir.path().join("client-key.pem");
        let server_cert_path = dir.path().join("server-cert.pem");
        let server_key_path = dir.path().join("server-key.pem");

        std::fs::write(&ca_cert_path, ca.serialize_pem().expect("serialize ca")).expect("write ca");
        std::fs::write(&client_cert_path, client_cert).expect("write client cert");
        std::fs::write(&client_key_path, client_key).expect("write client key");
        std::fs::write(&server_cert_path, server_cert).expect("write server cert");
        std::fs::write(&server_key_path, server_key).expect("write server key");

        Self {
            _dir: dir,
            ca,
            ca_cert_path: ca_cert_path.to_string_lossy().to_string(),
            client_cert_path: client_cert_path.to_string_lossy().to_string(),
            client_key_path: client_key_path.to_string_lossy().to_string(),
            server_cert_path: server_cert_path.to_string_lossy().to_string(),
            server_key_path: server_key_path.to_string_lossy().to_string(),
        }
    }

    fn rotate_client_identity(&self, common_name: &str) {
        let (client_cert, client_key) = signed_cert(
            common_name,
            &self.ca,
            Vec::new(),
            Vec::new(),
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        std::fs::write(&self.client_cert_path, client_cert).expect("rotate client cert");
        std::fs::write(&self.client_key_path, client_key).expect("rotate client key");
    }
}

fn build_ca(common_name: &str) -> Certificate {
    let mut params = CertificateParams::new(Vec::new());
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, common_name);
    params.distinguished_name = distinguished_name;
    Certificate::from_params(params).expect("build ca")
}

fn signed_cert(
    common_name: &str,
    ca: &Certificate,
    dns_names: Vec<String>,
    subject_alt_names: Vec<SanType>,
    usage: ExtendedKeyUsagePurpose,
) -> (String, String) {
    let mut params = CertificateParams::new(dns_names);
    params.extended_key_usages = vec![usage];
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.subject_alt_names = subject_alt_names;
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, common_name);
    params.distinguished_name = distinguished_name;
    let cert = Certificate::from_params(params).expect("build cert");
    (
        cert.serialize_pem_with_signer(ca)
            .expect("serialize signed cert"),
        cert.serialize_private_key_pem(),
    )
}

fn single_backend_upstream(backend_addr: std::net::SocketAddr) -> Upstream {
    single_backend_upstream_with_address(format!("http://{backend_addr}"), None)
}

fn single_backend_upstream_with_address(address: String, tls: Option<UpstreamTls>) -> Upstream {
    Upstream {
        load_balancing: LoadBalancing {
            lb_type: "round-robin".to_string(),
            key: None,
        },
        auth: Default::default(),
        host_policy: Default::default(),
        forwarded_headers: Default::default(),
        compression: Default::default(),
        cache: Default::default(),
        tls,
        route: RouteMatch {
            path_prefix: Some("/".to_string()),
            ..Default::default()
        },
        backends: vec![Backend {
            id: "backend-a".to_string(),
            address,
            weight: 1,
            health_check: None,
        }],
    }
}

fn lifecycle_backend_addresses(snapshot: &serde_json::Value) -> Vec<String> {
    snapshot["backends"]["lifecycle"]
        .as_array()
        .expect("backend lifecycle array")
        .iter()
        .map(|backend| {
            backend["backend"]
                .as_str()
                .expect("backend lifecycle address")
                .to_string()
        })
        .collect()
}

fn start_static_runtime_swap_listener(
    body: &'static [u8],
    configure: impl FnOnce(&mut Config),
) -> Option<RuntimeSwapHarness> {
    if !local_listener_bind_available() {
        return None;
    }

    let mut harness = RuntimeSwapHarness::new();
    let backend_addr = harness.start_h1_static_backend(body);
    let mut config = harness.make_config(HashMap::from([(
        "api".to_string(),
        single_backend_upstream(backend_addr),
    )]));
    configure(&mut config);

    harness
        .start_listener(config)
        .expect("start runtime swap listener");
    Some(harness)
}

/// Like [`start_static_runtime_swap_listener`], but tolerant of the harness's
/// inherent reserve-port/drop/rebind race: the reserved ephemeral port is
/// released just before the real listener binds it, and another process can
/// win that narrow window. Retries with a freshly reserved port on that
/// specific failure instead of treating it as a hard bug.
fn start_static_runtime_swap_listener_retrying_on_port_conflict(
    body: &'static [u8],
    configure: impl Fn(&mut Config),
) -> Option<RuntimeSwapHarness> {
    if !local_listener_bind_available() {
        return None;
    }

    const MAX_ATTEMPTS: u32 = 5;
    let mut last_error = None;
    for attempt in 0..MAX_ATTEMPTS {
        let mut harness = RuntimeSwapHarness::new();
        let backend_addr = harness.start_h1_static_backend(body);
        let mut config = harness.make_config(HashMap::from([(
            "api".to_string(),
            single_backend_upstream(backend_addr),
        )]));
        configure(&mut config);

        match harness.start_listener(config) {
            Ok(_) => return Some(harness),
            Err(err) if err.contains("Address already in use") => {
                last_error = Some(err);
                if attempt + 1 < MAX_ATTEMPTS {
                    thread::sleep(Duration::from_millis(50));
                }
            }
            Err(err) => panic!("start runtime swap listener: {err}"),
        }
    }
    panic!(
        "start runtime swap listener: exhausted retries on port conflict: {}",
        last_error.unwrap_or_default()
    );
}

fn assert_listener_stops_accepting_fresh_quic_connections(harness: &RuntimeSwapHarness) {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut established = true;
    while Instant::now() < deadline {
        established = harness
            .fresh_quic_connection_establishes_within(Duration::from_millis(250))
            .expect("fresh quic connection attempt");
        if !established {
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    assert!(
        !established,
        "fresh QUIC connections must stop establishing once the live listener enters draining"
    );
}

fn assert_watchdog_restart_drains_listener(harness: &RuntimeSwapHarness, reason: &str) {
    assert!(
        harness
            .request_watchdog_restart(reason)
            .expect("request watchdog restart"),
        "watchdog restart request should be accepted"
    );
    assert_listener_stops_accepting_fresh_quic_connections(harness);
}

fn backend_policy_diff_summary(history_generation: &serde_json::Value) -> String {
    history_generation["entries"]
        .as_array()
        .expect("history entries")
        .iter()
        .flat_map(|entry| {
            entry["diff"]["entries"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|diff_entry| diff_entry["domain"] == "backend_policies")
                .filter_map(|diff_entry| diff_entry["summary"].as_str())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .next()
        .expect("backend_policies diff summary")
}

// Domain: reload swap.
#[test]
#[serial]
fn runtime_swap_harness_exposes_reload_control_plane_and_metrics_surfaces() {
    let Some(mut harness) = start_static_runtime_swap_listener(b"ok", |_| {}) else {
        return;
    };

    let startup_snapshot = harness.runtime_snapshot().expect("runtime snapshot");
    assert_eq!(startup_snapshot["runtime"]["generation"], 0);
    assert_eq!(
        startup_snapshot["runtime"]["config_path"],
        harness.config_path().to_string_lossy().to_string()
    );

    let metrics = harness.metrics_text().expect("metrics text");
    assert!(
        metrics.contains("# HELP impulse_requests_total Total requests seen by impulse.\n"),
        "metrics endpoint should expose prometheus request totals"
    );

    harness
        .rewrite_config(|config| {
            config.log.level = "debug".to_string();
            config.performance.new_connections_burst = 2;
        })
        .expect("rewrite config");

    let reload = harness
        .trigger_runtime_reload()
        .expect("trigger runtime reload");
    assert_eq!(reload["reloaded"], true);
    assert_eq!(reload["generation"], 1);

    let reloaded_snapshot = harness
        .runtime_snapshot()
        .expect("reloaded runtime snapshot");
    assert_eq!(reloaded_snapshot["runtime"]["generation"], 1);
    assert_eq!(
        reloaded_snapshot["runtime"]["config_path"],
        harness.config_path().to_string_lossy().to_string()
    );
}

#[test]
#[serial]
fn generation_owned_reload_swaps_backend_targets_without_changing_listener_identity() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = RuntimeSwapHarness::new();
    let old_backend = harness.start_h1_static_backend(b"backend-old");
    let new_backend = harness.start_h1_static_backend(b"backend-new");
    let config = harness.make_config(HashMap::from([(
        "api".to_string(),
        single_backend_upstream(old_backend),
    )]));

    harness
        .start_listener(config)
        .expect("start runtime swap listener");

    let before = harness
        .run_request(H3RequestSpec::get("localhost", "/"))
        .expect("request before reload");
    before.assert_status(200);
    before.assert_body_bytes(b"backend-old");

    let startup_snapshot = harness
        .runtime_snapshot()
        .expect("startup runtime snapshot");
    assert_eq!(startup_snapshot["runtime"]["generation"], 0);
    let startup_tls = startup_snapshot["tls"]["listeners"]
        .as_object()
        .expect("startup tls listener object")
        .clone();
    assert!(
        !startup_tls.is_empty(),
        "startup runtime snapshot should expose listener TLS inventory"
    );

    harness
        .rewrite_config(|config| {
            let upstream = config
                .upstream
                .get_mut("api")
                .expect("runtime swap test upstream");
            upstream.backends[0].address = format!("http://{new_backend}");
        })
        .expect("rewrite backend target");

    let reload = harness
        .trigger_runtime_reload()
        .expect("trigger runtime reload");
    assert_eq!(reload["reloaded"], true);
    assert_eq!(reload["generation"], 1);

    let after = harness
        .run_request(H3RequestSpec::get("localhost", "/"))
        .expect("request after reload");
    after.assert_status(200);
    after.assert_body_bytes(b"backend-new");

    let reloaded_snapshot = harness
        .runtime_snapshot()
        .expect("reloaded runtime snapshot");
    assert_eq!(reloaded_snapshot["runtime"]["generation"], 1);
    assert_eq!(
        startup_snapshot["runtime"]["generation"], 0,
        "stale runtime snapshot values should remain stable after bundle replacement"
    );
    assert_eq!(
        startup_snapshot["tls"]["listeners"]
            .as_object()
            .expect("stale startup tls listeners"),
        &startup_tls,
        "stale runtime snapshot should keep its original listener identity view"
    );
    assert_eq!(
        reloaded_snapshot["tls"]["listeners"]
            .as_object()
            .expect("reloaded tls listener object"),
        &startup_tls,
        "startup-owned listener TLS identity should not change across generation-only reloads"
    );
}

#[test]
#[serial]
fn runtime_activation_and_rollback_restore_the_retained_serving_configuration() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = RuntimeSwapHarness::new();
    let original_backend = harness.start_h1_static_backend(b"generation-zero");
    let activated_backend = harness.start_h1_static_backend(b"generation-one");
    let config = harness.make_config(HashMap::from([(
        "api".to_string(),
        single_backend_upstream(original_backend),
    )]));
    harness
        .start_listener(config)
        .expect("start runtime activation listener");

    harness
        .rewrite_config(|config| {
            config
                .upstream
                .get_mut("api")
                .expect("runtime activation upstream")
                .backends[0]
                .address = format!("http://{activated_backend}");
        })
        .expect("write activation candidate");

    let activation = harness
        .trigger_runtime_activate()
        .expect("activate runtime candidate");
    assert_eq!(activation["active_generation"], 1);
    assert_eq!(activation["activated_generation"], 1);
    let activated = harness
        .run_request(H3RequestSpec::get("localhost", "/"))
        .expect("request after activation");
    activated.assert_status(200);
    activated.assert_body_bytes(b"generation-one");

    let rollback = harness
        .trigger_runtime_rollback(0)
        .expect("rollback to retained generation");
    assert_eq!(rollback["active_generation"], 2);
    assert_eq!(rollback["rolled_back_to"], 0);
    let restored = harness
        .run_request(H3RequestSpec::get("localhost", "/"))
        .expect("request after rollback");
    restored.assert_status(200);
    restored.assert_body_bytes(b"generation-zero");
}

#[test]
#[serial]
fn failed_runtime_activation_keeps_the_active_generation_serving() {
    let Some(mut harness) = start_static_runtime_swap_listener(b"active-generation", |_| {}) else {
        return;
    };

    harness
        .rewrite_config(|config| {
            config.listen.port = config.listen.port.saturating_add(1);
        })
        .expect("write incompatible activation candidate");

    let rejection = harness
        .trigger_runtime_activate_expect(http::StatusCode::CONFLICT)
        .expect("activation rejection");
    assert_eq!(rejection["active_generation"], 0);
    assert_eq!(rejection["activated_generation"], serde_json::Value::Null);
    assert!(
        rejection["rejected_changes"]
            .as_array()
            .is_some_and(|changes| !changes.is_empty()),
        "failed activation should expose its rejected changes"
    );
    assert_eq!(
        harness
            .current_generation()
            .expect("generation after failed activation"),
        0
    );

    let response = harness
        .run_request(H3RequestSpec::get("localhost", "/"))
        .expect("request after failed activation");
    response.assert_status(200);
    response.assert_body_bytes(b"active-generation");
}

#[test]
#[serial]
fn listener_cert_rotation_stays_scoped_to_reload_certs_and_does_not_activate_generation() {
    let Some(harness) = start_static_runtime_swap_listener(b"listener-cert-reload", |_| {}) else {
        return;
    };

    let startup_snapshot = harness
        .runtime_snapshot()
        .expect("startup runtime snapshot");
    let listener_label = format!(
        "{}:{}",
        startup_snapshot["runtime"]["config_path"]
            .as_str()
            .map(|_| "127.0.0.1")
            .unwrap_or("127.0.0.1"),
        harness.listen_addr().expect("listen addr").port()
    );
    let tls_before = startup_snapshot["tls"]["listeners"][&listener_label]["generation"]
        .as_u64()
        .expect("listener tls generation before");
    let generation_before = startup_snapshot["runtime"]["generation"]
        .as_u64()
        .expect("runtime generation before");
    let history_before = harness.runtime_history().expect("startup runtime history");
    let history_entries_before = history_before["entries"]
        .as_array()
        .expect("startup history entries")
        .len();

    let rotated = TestTlsMaterial::localhost();
    let (listener_cert_path, listener_key_path) = harness.listener_tls_paths();
    std::fs::copy(&rotated.cert_path, listener_cert_path).expect("rotate listener cert");
    std::fs::copy(&rotated.key_path, listener_key_path).expect("rotate listener key");

    let reload = harness
        .trigger_runtime_reload_certs()
        .expect("trigger listener cert reload");
    assert_eq!(reload["reloaded"], true);

    let after_snapshot = harness
        .runtime_snapshot()
        .expect("post-reload runtime snapshot");
    assert_eq!(
        after_snapshot["runtime"]["generation"].as_u64(),
        Some(generation_before),
        "listener cert reload must not create a new runtime generation"
    );
    assert!(
        after_snapshot["tls"]["listeners"][&listener_label]["generation"]
            .as_u64()
            .expect("listener tls generation after")
            > tls_before,
        "reload-certs must rotate listener TLS material in place"
    );

    let history_after = harness
        .runtime_history()
        .expect("post-reload runtime history");
    assert_eq!(
        history_after["entries"]
            .as_array()
            .expect("post-reload history entries")
            .len(),
        history_entries_before,
        "reload-certs must not record a generation activation event"
    );
}

#[test]
#[serial]
fn upstream_client_cert_rotation_uses_activation_and_same_path_fingerprint_change() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = RuntimeSwapHarness::new();
    let material = MtlsRuntimeMaterial::localhost();
    let backend_addr =
        harness.start_h2_backend_with_client_auth(
            &material.server_cert_path,
            &material.server_key_path,
            &material.ca_cert_path,
            move |_req| async move {
                Ok::<_, std::convert::Infallible>(static_full_response(b"mtls-ok"))
            },
        );
    let upstream = single_backend_upstream_with_address(
        format!("https://{backend_addr}"),
        Some(UpstreamTls {
            verify_certificates: true,
            strict_sni: false,
            ca_file: Some(material.ca_cert_path.clone()),
            ca_dir: None,
            client_certificate: None,
            client_certificate_ref: Some(SecretRef {
                reference: format!("file://{}", material.client_cert_path),
            }),
            client_key: None,
            client_key_ref: Some(SecretRef {
                reference: format!("file://{}", material.client_key_path),
            }),
        }),
    );
    let config = harness.make_config(HashMap::from([("api".to_string(), upstream)]));
    harness
        .start_listener(config)
        .expect("start runtime swap listener");

    let before = harness
        .run_request(H3RequestSpec::get("localhost", "/"))
        .expect("request before client cert rotation");
    before.assert_status(200);
    before.assert_body_bytes(b"mtls-ok");
    assert_eq!(harness.current_generation().expect("generation before"), 0);

    material.rotate_client_identity("runtime-client-rotated");

    let reload = harness
        .trigger_runtime_reload()
        .expect("trigger activation for upstream client cert rotation");
    assert_eq!(reload["reloaded"], true);
    assert_eq!(reload["generation"], 1);

    let after = harness
        .run_request(H3RequestSpec::get("localhost", "/"))
        .expect("request after client cert rotation");
    after.assert_status(200);
    after.assert_body_bytes(b"mtls-ok");

    let history_generation = harness
        .runtime_history_generation(1)
        .expect("runtime history generation 1");
    let diff_summary = backend_policy_diff_summary(&history_generation);
    assert!(
        diff_summary.contains("client_cert_fp=") && diff_summary.contains("client_key_fp="),
        "activation diff should record upstream client identity fingerprint changes, got: {diff_summary}"
    );
}

#[test]
#[serial]
fn upstream_ca_rotation_uses_activation_even_when_config_path_is_unchanged() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = RuntimeSwapHarness::new();
    let material = MtlsRuntimeMaterial::localhost();
    let backend_addr =
        harness.start_h2_backend_with_client_auth(
            &material.server_cert_path,
            &material.server_key_path,
            &material.ca_cert_path,
            move |_req| async move {
                Ok::<_, std::convert::Infallible>(static_full_response(b"ca-rotate"))
            },
        );
    let upstream = single_backend_upstream_with_address(
        format!("https://{backend_addr}"),
        Some(UpstreamTls {
            verify_certificates: true,
            strict_sni: false,
            ca_file: Some(material.ca_cert_path.clone()),
            ca_dir: None,
            client_certificate: None,
            client_certificate_ref: Some(SecretRef {
                reference: format!("file://{}", material.client_cert_path),
            }),
            client_key: None,
            client_key_ref: Some(SecretRef {
                reference: format!("file://{}", material.client_key_path),
            }),
        }),
    );
    let config = harness.make_config(HashMap::from([("api".to_string(), upstream)]));
    harness
        .start_listener(config)
        .expect("start runtime swap listener");
    assert_eq!(harness.current_generation().expect("generation before"), 0);

    let rotated = MtlsRuntimeMaterial::localhost();
    std::fs::copy(&rotated.ca_cert_path, &material.ca_cert_path).expect("rotate upstream ca file");

    let reload = harness
        .trigger_runtime_reload()
        .expect("trigger activation for upstream ca rotation");
    assert_eq!(reload["reloaded"], true);
    assert_eq!(reload["generation"], 1);

    let history_generation = harness
        .runtime_history_generation(1)
        .expect("runtime history generation 1");
    let diff_summary = backend_policy_diff_summary(&history_generation);
    assert!(
        diff_summary.contains("ca_fp="),
        "activation diff should record upstream ca fingerprint changes, got: {diff_summary}"
    );
}

// Domain: reload rejection.
#[test]
#[serial]
fn startup_owned_listener_bind_change_is_rejected_and_keeps_active_generation_live() {
    let Some(mut harness) = start_static_runtime_swap_listener(b"bind-stable", |_| {}) else {
        return;
    };

    let before = harness
        .run_request(H3RequestSpec::get("localhost", "/"))
        .expect("request before bind-change reload");
    before.assert_status(200);
    before.assert_body_bytes(b"bind-stable");

    let startup_snapshot = harness
        .runtime_snapshot()
        .expect("startup runtime snapshot");
    assert_eq!(startup_snapshot["runtime"]["generation"], 0);

    harness
        .rewrite_config(|config| {
            config.listen.port = config.listen.port.saturating_add(1);
        })
        .expect("rewrite listener bind");

    let rejection = harness
        .trigger_runtime_reload_expect(http::StatusCode::CONFLICT)
        .expect("reload rejection");
    assert_eq!(rejection["reloaded"], false);
    let error = rejection["error"]
        .as_str()
        .expect("reload rejection error string");
    assert!(
        error.contains("restart required"),
        "listener bind change should be restart-required, got: {error}"
    );
    assert!(
        error.contains("listener"),
        "listener bind rejection should mention the listener, got: {error}"
    );

    let after_snapshot = harness
        .runtime_snapshot()
        .expect("post-rejection runtime snapshot");
    assert_eq!(
        after_snapshot["runtime"]["generation"], 0,
        "startup-owned rejection must leave the active generation unchanged"
    );
    assert_eq!(
        after_snapshot["runtime"]["config_path"], startup_snapshot["runtime"]["config_path"],
        "config path should remain the same for a rejected same-path reload attempt"
    );

    let after = harness
        .run_request(H3RequestSpec::get("localhost", "/"))
        .expect("request after bind-change rejection");
    after.assert_status(200);
    after.assert_body_bytes(b"bind-stable");
}

#[test]
#[serial]
fn startup_owned_log_sink_change_is_rejected_and_keeps_request_behavior() {
    let Some(mut harness) = start_static_runtime_swap_listener(b"log-sink-stable", |_| {}) else {
        return;
    };

    let before = harness
        .run_request(H3RequestSpec::get("localhost", "/"))
        .expect("request before log-sink reload");
    before.assert_status(200);
    before.assert_body_bytes(b"log-sink-stable");

    let startup_snapshot = harness
        .runtime_snapshot()
        .expect("startup runtime snapshot");
    assert_eq!(startup_snapshot["runtime"]["generation"], 0);

    harness
        .rewrite_config(|config| {
            config.log.file.enabled = true;
            config.log.file.path = "/tmp/impulse-runtime-swap.log".to_string();
        })
        .expect("rewrite log sink shape");

    let rejection = harness
        .trigger_runtime_reload_expect(http::StatusCode::CONFLICT)
        .expect("reload rejection");
    assert_eq!(rejection["reloaded"], false);
    let error = rejection["error"]
        .as_str()
        .expect("reload rejection error string");
    assert!(
        error.contains("restart required"),
        "log sink shape change should be restart-required, got: {error}"
    );
    assert!(
        error.contains("log.file.enabled") || error.contains("log.file.path"),
        "log sink rejection should point at startup-owned log file fields, got: {error}"
    );

    let after_snapshot = harness
        .runtime_snapshot()
        .expect("post-rejection runtime snapshot");
    assert_eq!(
        after_snapshot["runtime"]["generation"], 0,
        "startup-owned log sink rejection must keep the active generation unchanged"
    );

    let after = harness
        .run_request(H3RequestSpec::get("localhost", "/"))
        .expect("request after log-sink rejection");
    after.assert_status(200);
    after.assert_body_bytes(b"log-sink-stable");
}

#[test]
#[serial]
fn runtime_reload_is_rejected_after_listener_lifecycle_leaves_running() {
    // The harness reserves an ephemeral TCP port, releases it, then rebinds
    // the same port number for the real control API listener. That
    // release-then-rebind window is a genuine OS-level race: another process
    // can grab the port in between. Retry harness construction a few times
    // on that specific failure rather than trying to eliminate an
    // unavoidable TCP race.
    let Some(mut harness) =
        start_static_runtime_swap_listener_retrying_on_port_conflict(b"lifecycle-running", |_| {})
    else {
        return;
    };

    assert_eq!(
        harness.lifecycle_phase().expect("runtime lifecycle phase"),
        RuntimeLifecyclePhase::Running
    );
    assert!(matches!(
        harness
            .begin_lifecycle_drain()
            .expect("begin lifecycle drain"),
        LifecycleTransitionResult::Applied {
            to: RuntimeLifecyclePhase::Draining,
            ..
        } | LifecycleTransitionResult::NoOp {
            phase: RuntimeLifecyclePhase::Draining
        }
    ));
    assert_eq!(
        harness.lifecycle_phase().expect("draining lifecycle phase"),
        RuntimeLifecyclePhase::Draining
    );

    let generation_before = harness.current_generation().expect("generation before");
    harness
        .rewrite_config(|config| {
            config.log.level = "debug".to_string();
        })
        .expect("rewrite live-reloadable config");

    let rejection = harness
        .trigger_runtime_reload_expect(http::StatusCode::CONFLICT)
        .expect("reload rejection after drain");
    assert_eq!(rejection["reloaded"], false);
    let error = rejection["error"]
        .as_str()
        .expect("reload rejection error string");
    assert!(
        error.contains("illegal_transition")
            || error.contains("Draining")
            || error.contains("ReloadCommit"),
        "reload rejection should reflect the non-running lifecycle gate, got: {error}"
    );
    assert_eq!(
        harness
            .current_generation()
            .expect("generation after rejection"),
        generation_before,
        "reload rejection after drain must keep the active generation unchanged"
    );
}

// Domain: control-plane visibility.
#[test]
#[serial]
fn control_api_runtime_snapshot_tracks_active_generation_listener_and_backend_inventory() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = RuntimeSwapHarness::new();
    let old_backend = harness.start_h1_static_backend(b"snapshot-old");
    let new_backend = harness.start_h1_static_backend(b"snapshot-new");
    let config = harness.make_config(HashMap::from([(
        "api".to_string(),
        single_backend_upstream(old_backend),
    )]));
    let listener_label = format!("127.0.0.1:{}", config.listen.port);

    harness
        .start_listener(config)
        .expect("start runtime swap listener");

    let startup_snapshot = harness
        .runtime_snapshot()
        .expect("startup runtime snapshot");
    assert_eq!(startup_snapshot["runtime"]["generation"], 0);
    let startup_listeners = startup_snapshot["tls"]["listeners"]
        .as_object()
        .expect("startup tls listeners");
    assert!(
        startup_listeners.contains_key(&listener_label),
        "runtime snapshot should render the current active listener label"
    );
    assert_eq!(
        lifecycle_backend_addresses(&startup_snapshot),
        vec![format!("http://{old_backend}")],
        "startup runtime snapshot should expose only the active generation backend inventory"
    );

    harness
        .rewrite_config(|config| {
            let upstream = config
                .upstream
                .get_mut("api")
                .expect("runtime swap test upstream");
            upstream.backends[0].address = format!("http://{new_backend}");
            config.observability.control_api.runtime_path = "/runtime-live".to_string();
        })
        .expect("rewrite active generation fields");

    let reload = harness
        .trigger_runtime_reload()
        .expect("trigger runtime reload");
    assert_eq!(reload["reloaded"], true);
    assert_eq!(reload["generation"], 1);

    let live_snapshot = harness.runtime_snapshot().expect("live runtime snapshot");
    assert_eq!(live_snapshot["runtime"]["generation"], 1);
    let live_listeners = live_snapshot["tls"]["listeners"]
        .as_object()
        .expect("live tls listeners");
    assert!(
        live_listeners.contains_key(&listener_label),
        "runtime snapshot should keep rendering the current live listener label after swap"
    );
    assert_eq!(
        live_listeners.len(),
        1,
        "runtime snapshot should render only the active generation listener inventory"
    );

    let live_backends = lifecycle_backend_addresses(&live_snapshot);
    assert_eq!(
        live_backends,
        vec![format!("http://{new_backend}")],
        "runtime snapshot should expose backend lifecycle inventory from the active generation only"
    );
    assert!(
        !live_backends
            .iter()
            .any(|backend| backend == &format!("http://{old_backend}")),
        "runtime snapshot must not leak stale-generation backend inventory"
    );
}

#[test]
#[serial]
fn watchdog_restart_surfaces_not_ready_and_restart_pending_control_plane_state() {
    let Some(harness) = start_static_runtime_swap_listener(b"watchdog-drain-state", |config| {
        config.resilience.watchdog.enabled = true;
    }) else {
        return;
    };

    let ready_before = harness
        .ready_snapshot_expect(http::StatusCode::OK)
        .expect("ready snapshot before watchdog restart");
    assert_eq!(ready_before["ready"], true);
    assert_eq!(ready_before["restart_requested"], false);

    let runtime_before = harness
        .runtime_snapshot()
        .expect("runtime snapshot before restart");
    assert_eq!(runtime_before["watchdog"]["restart_requested"], false);
    assert_eq!(runtime_before["watchdog"]["restart_reason"], "");

    assert!(
        harness
            .request_watchdog_restart("runtime-swap-drain-visible")
            .expect("request watchdog restart"),
        "watchdog restart request should be accepted"
    );

    let ready_after = harness
        .ready_snapshot_expect(http::StatusCode::SERVICE_UNAVAILABLE)
        .expect("ready snapshot after watchdog restart");
    assert_eq!(ready_after["ready"], false);
    assert_eq!(ready_after["restart_requested"], true);

    let runtime_after = harness
        .runtime_snapshot()
        .expect("runtime snapshot after restart");
    assert_eq!(runtime_after["watchdog"]["restart_requested"], true);
    assert_eq!(
        runtime_after["watchdog"]["restart_reason"],
        "runtime-swap-drain-visible"
    );
    assert!(
        runtime_after["watchdog"]["restart_requested_at_ms"]
            .as_u64()
            .expect("watchdog restart timestamp")
            > 0,
        "runtime snapshot should expose the watchdog restart timestamp while drain is pending"
    );

    assert_listener_stops_accepting_fresh_quic_connections(&harness);
}

// Domain: metrics visibility.
#[test]
#[serial]
fn metrics_endpoint_tracks_active_generation_route_label_and_path_after_reload() {
    let Some(mut harness) = start_static_runtime_swap_listener(b"metrics-live", |_| {}) else {
        return;
    };

    let startup_metrics = harness.metrics_text().expect("startup metrics text");
    assert!(
        startup_metrics.contains("impulse_route_requests_total{route=\"api\"} 0\n"),
        "startup metrics should render the startup generation route label"
    );
    let old_path = "/metrics".to_string();

    harness
        .rewrite_config(|config| {
            let upstream = config.upstream.remove("api").expect("startup upstream");
            config.upstream.insert("api-reloaded".to_string(), upstream);
            config.observability.metrics.path = "/metrics-live".to_string();
        })
        .expect("rewrite metrics path and route labels");

    let reload = harness
        .trigger_runtime_reload()
        .expect("trigger runtime reload");
    assert_eq!(reload["reloaded"], true);
    assert_eq!(reload["generation"], 1);

    let live_metrics = harness.metrics_text().expect("live metrics text");
    assert!(
        live_metrics.contains("impulse_route_requests_total{route=\"api-reloaded\"} 0\n"),
        "reloaded metrics should render the active generation route label"
    );
    assert!(
        !live_metrics.contains("impulse_route_requests_total{route=\"api\"}"),
        "reloaded metrics must not fall back to the startup metrics surface after reload"
    );

    let old_path_status = harness
        .metrics_status_at(&old_path)
        .expect("old metrics path status");
    assert_eq!(
        old_path_status,
        http::StatusCode::NOT_FOUND,
        "old metrics path should no longer be treated as the active metrics endpoint after reload"
    );
}

// Domain: drain behavior.
#[test]
#[serial]
fn in_flight_request_completes_while_watchdog_restart_drains_listener() {
    if !local_listener_bind_available() {
        return;
    }

    let mut harness = RuntimeSwapHarness::new();
    let request_started = Arc::new(AtomicBool::new(false));
    let started = Arc::clone(&request_started);
    let backend_addr = harness.start_h1_backend(move |_req| {
        let started = Arc::clone(&started);
        async move {
            started.store(true, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(80)).await;
            Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(Bytes::from_static(
                b"drain-complete",
            ))))
        }
    });
    let mut config = harness.make_config(HashMap::from([(
        "api".to_string(),
        single_backend_upstream(backend_addr),
    )]));
    config.resilience.watchdog.enabled = true;
    config.performance.shutdown_drain_timeout_ms = 500;

    let listen_addr = harness
        .start_listener(config)
        .expect("start runtime swap listener");

    let client =
        thread::spawn(move || run_request_to(listen_addr, H3RequestSpec::get("localhost", "/")));

    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline && !request_started.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        request_started.load(Ordering::Relaxed),
        "backend should observe the in-flight request before drain begins"
    );

    assert!(
        harness
            .request_watchdog_restart("runtime-swap-drain-inflight")
            .expect("request watchdog restart"),
        "watchdog restart request should be accepted"
    );

    let response = client
        .join()
        .expect("client thread join")
        .expect("in-flight response");
    response.assert_status(200);
    response.assert_body_bytes(b"drain-complete");
}

// Domain: watchdog restart path.
#[test]
#[serial]
fn watchdog_restart_blocks_new_quic_connections_once_listener_starts_draining() {
    let Some(harness) = start_static_runtime_swap_listener(b"drain-blocked", |config| {
        config.resilience.watchdog.enabled = true;
    }) else {
        return;
    };

    assert_watchdog_restart_drains_listener(&harness, "runtime-swap-drain-block");
}
