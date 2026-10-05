use std::{collections::HashMap, ffi::OsString, path::Path, sync::Arc};

use ::http::{Method, Request, header};
use bytes::Bytes;
use http_body_util::BodyExt;
use impulse_config::{
    config::{
        ApiKeyAuth, Backend, ClientAuth, Config as ImpulseConfigConfig, ControlApiAuditSink,
        ControlApiBearerToken, ControlApiClientAuthMode, ControlApiRole, DistributedQuotaPolicy,
        DistributedQuotaSelector, DistributedQuotaSelectorSource, DistributedQuotaWindow,
        JwksStartupBehavior, JwtAlgorithm, JwtAuth, Listen, LoadBalancing, Log, LogFormat,
        Observability, Performance, QuotaBackendFailurePolicy, QuotaCounterBackend,
        QuotaEnforcementMode, Resilience, RouteAuth, RouteMatch, SecretProvider, Security, Tls,
        Upstream, UpstreamTls,
    },
    runtime::{RuntimeConfig, RuntimeJwtVerificationKey},
};
use log::LevelFilter;
use tempfile::tempdir;

use super::{state::ControlApiState, *};
use crate::runtime::activation::{
    ActivationRequest, GenerationEventKind, GenerationOperation, GenerationStatus, PlanningPhase,
    PlanningPhaseStatus, RejectedChangeKind, ReloadCompatibilityClassification, ReloadConfigInput,
    ReloadDiffDisposition, RollbackRequest, RuntimeActivationService, RuntimeRejectionReason,
    plan_runtime_reload,
};

/// Render the typed startup-owned compatibility result into the flat list of
/// operator strings the assertions below were written against.
fn startup_owned_issue_strings(current: &RuntimeBundle, next: &RuntimeBundle) -> Vec<String> {
    match QUICListener::validate_startup_owned_reload_compatibility(current, next) {
        Ok(()) => Vec::new(),
        Err(rejections) => rejections.iter().map(|r| r.to_string()).collect(),
    }
}

fn write_test_cert_for_name(dir: &Path, cert_name: &str, dns_name: &str) -> (String, String) {
    use rcgen::{Certificate, CertificateParams, SanType};

    let mut params = CertificateParams::new(vec![dns_name.to_string()]);
    params
        .subject_alt_names
        .push(SanType::DnsName(dns_name.to_string()));
    let cert = Certificate::from_params(params).expect("failed to build cert");

    let cert_path = dir.join(format!("{cert_name}.pem"));
    let key_path = dir.join(format!("{cert_name}.key.pem"));
    std::fs::write(&cert_path, cert.serialize_pem().expect("serialize cert")).expect("write cert");
    std::fs::write(&key_path, cert.serialize_private_key_pem()).expect("write key");
    (
        cert_path.to_string_lossy().to_string(),
        key_path.to_string_lossy().to_string(),
    )
}

fn test_config(cert: String, key: String) -> ImpulseConfigConfig {
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        Upstream {
            load_balancing: LoadBalancing {
                lb_type: "round-robin".to_string(),
                key: None,
            },
            auth: Default::default(),
            host_policy: Default::default(),
            forwarded_headers: Default::default(),
            tls: None,
            route: RouteMatch {
                path_prefix: Some("/".to_string()),
                ..Default::default()
            },
            backends: vec![Backend {
                id: "b1".to_string(),
                address: "http://127.0.0.1:7001".to_string(),
                weight: 1,
                health_check: None,
            }],
        },
    );

    ImpulseConfigConfig {
        version: 1,
        listen: Listen {
            protocol: "http3".to_string(),
            port: 9889,
            address: "127.0.0.1".to_string(),
            tls: Tls {
                cert,
                key,
                certificates: vec![],
                client_auth: ClientAuth::default(),
            },
        },
        listeners: vec![],
        upstream: upstreams,
        load_balancing: Some(LoadBalancing {
            lb_type: "round-robin".to_string(),
            key: None,
        }),
        upstream_tls: UpstreamTls::default(),
        secrets: Default::default(),
        log: Log::default(),
        performance: Performance::default(),
        observability: Observability::default(),
        resilience: Resilience::default(),
        security: Security::default(),
    }
}

fn runtime_bundle_from_config(config_path: &str, config: &ImpulseConfigConfig) -> RuntimeBundle {
    let runtime_config = RuntimeConfig::from_config(config).expect("runtime config");
    QUICListener::build_runtime_bundle(config_path.to_string(), config.log.clone(), &runtime_config)
        .expect("runtime bundle")
}

fn write_config_file(path: &Path, config: &ImpulseConfigConfig) {
    let backend = config
        .upstream
        .get("api")
        .and_then(|upstream| upstream.backends.first())
        .expect("api upstream backend");
    let upstream = config.upstream.get("api").expect("api upstream");
    let yaml = format!(
        r#"version: {version}
listen:
  protocol: "{protocol}"
  address: "{address}"
  port: {port}
  tls:
    cert: "{cert}"
    key: "{key}"
upstream:
  api:
    load_balancing:
      type: "{lb_type}"
    route:
      path_prefix: "{path_prefix}"
{auth}    backends:
      - id: "{backend_id}"
        address: "{backend_address}"
        weight: {backend_weight}
performance:
  control_plane_threads: {control_plane_threads}
log:
  level: "{log_level}"
"#,
        version = config.version,
        protocol = config.listen.protocol,
        address = config.listen.address,
        port = config.listen.port,
        cert = config.listen.tls.cert,
        key = config.listen.tls.key,
        lb_type = upstream.load_balancing.lb_type,
        path_prefix = upstream.route.path_prefix.as_deref().unwrap_or("/"),
        auth = render_test_auth_yaml(&upstream.auth),
        backend_id = backend.id,
        backend_address = backend.address,
        backend_weight = backend.weight,
        control_plane_threads = config.performance.control_plane_threads,
        log_level = config.log.level,
    );
    std::fs::write(path, yaml).expect("write config file");
}

/// Renders only the JWT slice of `auth` that reload tests exercise. The wider
/// config template is hand-written because `Config` is deserialize-only, so
/// anything not emitted here is silently dropped on the round-trip through disk.
fn render_test_auth_yaml(auth: &impulse_config::config::RouteAuth) -> String {
    let Some(jwt) = auth.jwt.as_ref() else {
        return String::new();
    };
    let mut yaml = String::from("    auth:\n      jwt:\n");
    yaml.push_str(&format!("        secret: \"{}\"\n", jwt.secret));
    if let Some(issuer) = jwt.issuer.as_deref() {
        yaml.push_str(&format!("        issuer: \"{issuer}\"\n"));
    }
    if let Some(audience) = jwt.audience.as_deref() {
        yaml.push_str(&format!("        audience: \"{audience}\"\n"));
    }
    let algorithms = jwt
        .allowed_algorithms
        .iter()
        .map(|algorithm| match algorithm {
            JwtAlgorithm::Hs256 => "\"HS256\"",
            JwtAlgorithm::Rs256 => "\"RS256\"",
            JwtAlgorithm::Es256 => "\"ES256\"",
        })
        .collect::<Vec<_>>()
        .join(", ");
    yaml.push_str(&format!("        allowed_algorithms: [{algorithms}]\n"));
    if let Some(jwks_url) = jwt.jwks_url.as_deref() {
        yaml.push_str(&format!("        jwks_url: \"{jwks_url}\"\n"));
        yaml.push_str(&format!(
            "        jwks_refresh_interval_secs: {}\n",
            jwt.jwks_refresh_interval_secs
        ));
        yaml.push_str(&format!(
            "        jwks_request_timeout_ms: {}\n",
            jwt.jwks_request_timeout_ms
        ));
        yaml.push_str(&format!(
            "        jwks_cache_ttl_secs: {}\n",
            jwt.jwks_cache_ttl_secs
        ));
        yaml.push_str(&format!(
            "        jwks_stale_if_error_secs: {}\n",
            jwt.jwks_stale_if_error_secs
        ));
        yaml.push_str(&format!(
            "        jwks_startup_behavior: {}\n",
            match jwt.jwks_startup_behavior {
                JwksStartupBehavior::RequireReady => "require_ready",
                JwksStartupBehavior::AllowDegraded => "allow_degraded",
            }
        ));
    }
    yaml
}

fn control_api_state_with_runtime_bundle(
    startup: &ImpulseConfigConfig,
    reloaded: &ImpulseConfigConfig,
) -> ControlApiState {
    let startup_bundle = runtime_bundle_from_config("startup.yaml", startup);
    let reloaded_bundle = runtime_bundle_from_config("reloaded.yaml", reloaded);
    let runtime_ctx =
        crate::quic_listener::runtime_state::ControlPlaneRuntimeCtx::from_runtime_sources(
            &startup_bundle.runtime_config,
            startup_bundle.shared_state.as_ref(),
            Some(Arc::new(RuntimeBundleHandle::new(reloaded_bundle))),
        );

    ControlApiState::new(runtime_ctx)
}

fn runtime_bundle_control_api_state(
    bundle: RuntimeBundle,
) -> (ControlApiState, Arc<RuntimeBundleHandle>) {
    let runtime_handle = Arc::new(RuntimeBundleHandle::new(bundle.clone()));
    let runtime_ctx =
        crate::quic_listener::runtime_state::ControlPlaneRuntimeCtx::from_runtime_sources(
            &bundle.runtime_config,
            bundle.shared_state.as_ref(),
            Some(Arc::clone(&runtime_handle)),
        );
    let state = ControlApiState::new(runtime_ctx);
    (state, runtime_handle)
}

fn control_api_request(method: Method, path: &str, authorization: Option<&str>) -> Request<()> {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    builder.body(()).expect("control api request")
}

fn attach_control_api_request_context<B>(
    req: &mut Request<B>,
    peer_addr: &str,
    mtls_identity: Option<super::admin_identity::AdminMtlsIdentity>,
) {
    req.extensions_mut()
        .insert(super::admin_identity::ControlApiRequestContext {
            peer_addr: peer_addr.parse().expect("peer socket addr"),
            mtls_identity,
            listener: None,
            request_id: None,
            trace_id: None,
            span_id: None,
        });
}

fn attach_control_api_peer_addr<B>(req: &mut Request<B>, peer_addr: &str) {
    attach_control_api_request_context(req, peer_addr, None);
}

fn read_audit_events(path: &Path) -> Vec<serde_json::Value> {
    for _ in 0..20 {
        if let Ok(contents) = std::fs::read_to_string(path) {
            let events = contents
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| serde_json::from_str(line).expect("parse audit event"))
                .collect::<Vec<_>>();
            if !events.is_empty() {
                return events;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let contents = std::fs::read_to_string(path).expect("read audit file");
    contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("parse audit event"))
        .collect()
}

fn wait_for_audit_event<F>(path: &Path, predicate: F) -> Vec<serde_json::Value>
where
    F: Fn(&serde_json::Value) -> bool,
{
    for _ in 0..40 {
        let events = read_audit_events(path);
        if events.iter().any(&predicate) {
            return events;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    read_audit_events(path)
}

fn audit_enabled_control_api_state(
    config: ImpulseConfigConfig,
    config_path: &Path,
    audit_path: &Path,
) -> ControlApiState {
    let mut config = config;
    config.observability.control_api.enabled = true;
    config.observability.control_api.audit.enabled = true;
    config.observability.control_api.audit.sink = ControlApiAuditSink::File;
    config.observability.control_api.audit.file_path =
        Some(audit_path.to_string_lossy().to_string());
    write_config_file(config_path, &config);
    let bundle = runtime_bundle_from_config(config_path.to_string_lossy().as_ref(), &config);
    runtime_bundle_control_api_state(bundle).0
}

async fn full_body_bytes(response: Response<http_body_util::Full<Bytes>>) -> Bytes {
    response
        .into_body()
        .collect()
        .await
        .expect("collect response body")
        .to_bytes()
}

async fn json_body(response: Response<http_body_util::Full<Bytes>>) -> serde_json::Value {
    serde_json::from_slice(&full_body_bytes(response).await).expect("json response body")
}

fn default_control_api_state() -> ControlApiState {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut startup = test_config(cert.clone(), key.clone());
    startup.observability.control_api.enabled = true;
    startup.observability.control_api.auth_token = Some("secret-token".to_string());
    control_api_state_with_runtime_bundle(&startup, &startup)
}

fn planner_request(expected_generation: u64) -> ActivationRequest {
    ActivationRequest {
        requested_by: Some("test".to_string()),
        trigger_source: Some("unit_test".to_string()),
        reason: Some("planner_contract".to_string()),
        expected_generation: Some(expected_generation),
        requested_at_ms: 1,
    }
}

fn rollback_request(target_generation: u64, expected_active_generation: u64) -> RollbackRequest {
    RollbackRequest {
        target_generation,
        requested_by: Some("test".to_string()),
        trigger_source: Some("unit_test".to_string()),
        reason: Some("rollback_contract".to_string()),
        expected_active_generation: Some(expected_active_generation),
        requested_at_ms: 2,
    }
}

fn assert_structured_resource_preflight_message(
    rejection: &crate::runtime::policy::TransitionRejection,
) {
    let field = rejection
        .field_path
        .as_deref()
        .expect("resource field path");
    let detail = rejection
        .requested_mode
        .as_deref()
        .expect("resource failure detail");
    assert_eq!(
        rejection.to_string(),
        format!(
            "runtime reload rejected: could not prepare {field}: {detail}; active runtime unchanged (no change applied)"
        )
    );
}

#[test]
fn staged_reload_planner_reports_reloadable_candidate_snapshot() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let config = test_config(cert, key);
    let config_path = dir.path().join("runtime.yaml");
    write_config_file(&config_path, &config);

    let bundle = runtime_bundle_from_config(config_path.to_string_lossy().as_ref(), &config);
    let current = RuntimeBundleHandle::new(bundle).current_view();
    let plan = plan_runtime_reload(
        &current,
        planner_request(current.generation()),
        ReloadConfigInput::Path {
            path: config_path.to_string_lossy().to_string(),
        },
    );

    assert!(plan.can_activate());
    assert_eq!(
        plan.plan.compatibility,
        ReloadCompatibilityClassification::LiveReloadable
    );
    assert_eq!(
        plan.plan.phase_status(PlanningPhase::ReadConfig),
        Some(PlanningPhaseStatus::Accepted)
    );
    assert_eq!(
        plan.plan.phase_status(PlanningPhase::ValidateConfig),
        Some(PlanningPhaseStatus::Accepted)
    );
    assert_eq!(
        plan.plan.phase_status(PlanningPhase::NormalizeRuntime),
        Some(PlanningPhaseStatus::Accepted)
    );
    assert_eq!(
        plan.plan.phase_status(PlanningPhase::EvaluateCompatibility),
        Some(PlanningPhaseStatus::Accepted)
    );

    let snapshot = plan
        .plan
        .candidate_snapshot
        .as_ref()
        .expect("candidate snapshot");
    assert_eq!(snapshot.generation, current.generation() + 1);
    assert_eq!(
        snapshot.config_path,
        config_path.to_string_lossy().to_string()
    );
    assert_eq!(snapshot.upstream_count, 1);
    assert_eq!(snapshot.backend_count, 1);
    assert!(
        plan.plan
            .diff
            .entries
            .iter()
            .any(|entry| entry.domain == "observability_control_plane"
                && entry.disposition == ReloadDiffDisposition::NoOp),
        "expected identical config to produce a no-op observability/control-plane diff"
    );
    assert!(plan.plan.diff.reloadable_entries().is_empty());
    assert!(plan.plan.diff.rejected_startup_owned_entries().is_empty());
}

#[test]
fn staged_reload_planner_classifies_restart_required_changes_without_mutation() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let config_path = dir.path().join("runtime.yaml");
    let current_config = test_config(cert.clone(), key.clone());
    write_config_file(&config_path, &current_config);

    let bundle =
        runtime_bundle_from_config(config_path.to_string_lossy().as_ref(), &current_config);
    let current = RuntimeBundleHandle::new(bundle).current_view();

    let mut next_config = test_config(cert, key);
    next_config.performance.control_plane_threads = 4;
    write_config_file(&config_path, &next_config);

    let plan = plan_runtime_reload(
        &current,
        planner_request(current.generation()),
        ReloadConfigInput::Path {
            path: config_path.to_string_lossy().to_string(),
        },
    );

    assert!(!plan.can_activate());
    assert_eq!(
        plan.plan.compatibility,
        ReloadCompatibilityClassification::RestartRequired
    );
    assert_eq!(
        plan.plan.phase_status(PlanningPhase::EvaluateCompatibility),
        Some(PlanningPhaseStatus::Rejected)
    );
    assert!(plan.plan.candidate_snapshot.is_some());
    assert!(plan.plan.rejection_summary.is_some());
    assert!(
        plan.plan.rejected_changes.iter().any(|rejection| {
            rejection.kind == RejectedChangeKind::RestartRequired
                && rejection.field_path.as_deref() == Some("performance.control_plane_threads")
        }),
        "expected a startup-owned restart-required rejection"
    );
    assert!(
        plan.plan
            .diff
            .entries
            .iter()
            .any(|entry| entry.domain == "observability_control_plane"
                && entry.disposition == ReloadDiffDisposition::RejectedStartupOwned
                && matches!(
                    entry.change,
                    crate::runtime::activation::ReloadChangeKind::Modified
                )),
        "expected control-plane startup-owned drift to be separated as rejected startup-owned"
    );
}

#[test]
fn staged_reload_planner_marks_log_level_change_as_reloadable_domain_diff() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let config_path = dir.path().join("runtime.yaml");
    let current_config = test_config(cert.clone(), key.clone());
    write_config_file(&config_path, &current_config);

    let bundle =
        runtime_bundle_from_config(config_path.to_string_lossy().as_ref(), &current_config);
    let current = RuntimeBundleHandle::new(bundle).current_view();

    let mut next_config = test_config(cert, key);
    next_config.log.level = "debug".to_string();
    write_config_file(&config_path, &next_config);

    let plan = plan_runtime_reload(
        &current,
        planner_request(current.generation()),
        ReloadConfigInput::Path {
            path: config_path.to_string_lossy().to_string(),
        },
    );

    assert!(plan.can_activate());
    assert!(
        plan.plan
            .diff
            .entries
            .iter()
            .any(|entry| entry.domain == "observability_control_plane"
                && entry.disposition == ReloadDiffDisposition::Reloadable
                && matches!(
                    entry.change,
                    crate::runtime::activation::ReloadChangeKind::Modified
                )
                && entry.summary.contains("log(level=info")
                && entry.summary.contains("log(level=debug")),
        "expected log.level drift to show up as a reloadable observability/control-plane diff"
    );
    assert_eq!(plan.plan.diff.reloadable_entries().len(), 1);
}

#[test]
fn activation_service_commits_reloadable_candidate_and_advances_generation() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let config_path = dir.path().join("runtime.yaml");
    let current_config = test_config(cert.clone(), key.clone());
    write_config_file(&config_path, &current_config);

    let bundle =
        runtime_bundle_from_config(config_path.to_string_lossy().as_ref(), &current_config);
    let handle = RuntimeBundleHandle::new(bundle);
    let generation_before = handle.current_generation();

    let mut next_config = test_config(cert, key);
    next_config.log.level = "debug".to_string();
    write_config_file(&config_path, &next_config);

    let activation = RuntimeActivationService::activate_reload(
        &handle,
        planner_request(generation_before),
        ReloadConfigInput::Path {
            path: config_path.to_string_lossy().to_string(),
        },
    );

    assert!(
        activation.succeeded(),
        "activation should succeed: {activation:?}"
    );
    assert_eq!(activation.status, GenerationStatus::Active);
    assert_eq!(activation.active_generation, generation_before + 1);
    assert_eq!(activation.activated_generation, Some(generation_before + 1));
    assert_eq!(handle.current_generation(), generation_before + 1);
    assert_eq!(
        activation.history_entry.operation,
        GenerationOperation::Activate
    );
    assert_eq!(activation.history_entry.status, GenerationStatus::Active);
    assert_eq!(
        activation.history_entry.config_source,
        config_path.to_string_lossy()
    );
    assert_eq!(activation.history_entry.config_version, Some(1));
    assert_eq!(
        activation.history_entry.trigger_source.as_deref(),
        Some("unit_test")
    );
    assert!(
        activation
            .history_entry
            .diff
            .reloadable_entries()
            .iter()
            .any(|entry| entry.domain == "observability_control_plane"),
        "expected activation history to preserve the planned reloadable diff"
    );
    assert_eq!(handle.current_view().startup().log_config.level, "debug");

    let history = handle.generation_change_history();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].operation, GenerationOperation::Activate);
    assert_eq!(history[0].config_source, config_path.to_string_lossy());
    assert_eq!(history[0].config_version, Some(1));

    let events = handle.generation_change_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, GenerationEventKind::ActivationSucceeded);
}

#[test]
fn activation_from_alternate_config_path_updates_default_runtime_source() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let primary_path = dir.path().join("primary.yaml");
    let canary_path = dir.path().join("canary.yaml");

    let current_config = test_config(cert.clone(), key.clone());
    write_config_file(&primary_path, &current_config);

    let bundle =
        runtime_bundle_from_config(primary_path.to_string_lossy().as_ref(), &current_config);
    let handle = RuntimeBundleHandle::new(bundle);
    let generation_before = handle.current_generation();

    let mut canary_config = test_config(cert, key);
    canary_config.log.level = "debug".to_string();
    write_config_file(&canary_path, &canary_config);

    let activation = RuntimeActivationService::activate_reload(
        &handle,
        planner_request(generation_before),
        ReloadConfigInput::Path {
            path: canary_path.to_string_lossy().to_string(),
        },
    );

    assert!(activation.succeeded(), "canary activation should succeed");
    assert_eq!(
        handle.current_view().startup().config_path,
        canary_path.to_string_lossy()
    );
    assert_eq!(
        activation.history_entry.config_source,
        canary_path.to_string_lossy()
    );

    let mut followup_config = canary_config.clone();
    followup_config.log.level = "warn".to_string();
    write_config_file(&canary_path, &followup_config);

    let followup = RuntimeActivationService::activate_reload(
        &handle,
        planner_request(handle.current_generation()),
        ReloadConfigInput::Path {
            path: handle.current_view().startup().config_path.clone(),
        },
    );

    assert!(followup.succeeded(), "follow-up activation should succeed");
    assert_eq!(handle.current_view().startup().log_config.level, "warn");
    assert_eq!(
        handle.current_view().startup().config_path,
        canary_path.to_string_lossy()
    );
}

#[test]
fn activation_service_rejects_restart_required_changes_without_mutating_active_generation() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let config_path = dir.path().join("runtime.yaml");
    let current_config = test_config(cert.clone(), key.clone());
    write_config_file(&config_path, &current_config);

    let bundle =
        runtime_bundle_from_config(config_path.to_string_lossy().as_ref(), &current_config);
    let handle = RuntimeBundleHandle::new(bundle);
    let generation_before = handle.current_generation();

    let mut next_config = test_config(cert, key);
    next_config.performance.control_plane_threads = current_config
        .performance
        .control_plane_threads
        .saturating_add(2);
    write_config_file(&config_path, &next_config);

    let activation = RuntimeActivationService::activate_reload(
        &handle,
        planner_request(generation_before),
        ReloadConfigInput::Path {
            path: config_path.to_string_lossy().to_string(),
        },
    );

    assert!(
        !activation.succeeded(),
        "restart-required activation must be rejected"
    );
    assert_eq!(activation.status, GenerationStatus::Rejected);
    assert_eq!(activation.active_generation, generation_before);
    assert_eq!(activation.activated_generation, None);
    assert_eq!(handle.current_generation(), generation_before);
    assert_eq!(
        activation.history_entry.operation,
        GenerationOperation::Activate
    );
    assert_eq!(activation.history_entry.status, GenerationStatus::Rejected);
    assert!(
        activation.rejected_changes.iter().any(|rejection| {
            rejection.kind == RejectedChangeKind::RestartRequired
                && rejection.reason == RuntimeRejectionReason::StartupOwnedChange
                && rejection.field_path.as_deref() == Some("performance.control_plane_threads")
                && !rejection.active_generation_changed
        }),
        "expected a restart-required rejection without live mutation: {:?}",
        activation.rejected_changes
    );

    let events = handle.generation_change_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, GenerationEventKind::ActivationFailed);
    assert_eq!(events[0].entry.status, GenerationStatus::Rejected);
}

#[test]
fn rollback_service_restores_retained_generation_by_id_and_records_rollback_status() {
    impulse_utils::logger::set_log_level("trace").expect("set initial log level");
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");

    let mut generation_one = test_config(cert.clone(), key.clone());
    generation_one
        .upstream
        .get_mut("api")
        .expect("api upstream")
        .backends[0]
        .address = "http://127.0.0.1:7001".to_string();
    let mut generation_two = test_config(cert.clone(), key.clone());
    generation_two.log.level = "debug".to_string();
    generation_two
        .upstream
        .get_mut("api")
        .expect("api upstream")
        .backends[0]
        .address = "http://127.0.0.1:7002".to_string();
    let mut generation_three = test_config(cert, key);
    generation_three.log.level = "trace".to_string();
    generation_three
        .upstream
        .get_mut("api")
        .expect("api upstream")
        .backends[0]
        .address = "http://127.0.0.1:7003".to_string();

    let mut bundle_one = runtime_bundle_from_config("gen-1.yaml", &generation_one);
    bundle_one.generation = 1;
    let mut bundle_two = runtime_bundle_from_config("gen-2.yaml", &generation_two);
    bundle_two.generation = 2;
    let mut bundle_three = runtime_bundle_from_config("gen-3.yaml", &generation_three);
    bundle_three.generation = 3;

    let handle = RuntimeBundleHandle::new(bundle_one);
    handle.replace(bundle_two).expect("install generation 2");
    handle.replace(bundle_three).expect("install generation 3");

    let rollback = RuntimeActivationService::rollback_generation(
        &handle,
        rollback_request(1, handle.current_generation()),
    );

    assert!(
        rollback.succeeded(),
        "rollback should succeed: {rollback:?}"
    );
    assert_eq!(rollback.status, GenerationStatus::RolledBack);
    assert_eq!(rollback.rolled_back_to, Some(1));
    assert_eq!(rollback.active_generation, 4);
    assert_eq!(handle.current_generation(), 4);
    assert_eq!(log::max_level(), LevelFilter::Info);
    assert_eq!(
        rollback.history_entry.operation,
        GenerationOperation::Rollback
    );
    assert_eq!(rollback.history_entry.status, GenerationStatus::RolledBack);
    assert_eq!(
        handle
            .current_view()
            .runtime_config()
            .upstreams
            .get("api")
            .expect("active upstream")
            .backends[0]
            .backend
            .address,
        "http://127.0.0.1:7001"
    );

    let history = handle.generation_history();
    assert_eq!(history[1].generation(), 3);
    assert_eq!(
        history[1].status(),
        crate::runtime::bundle::RuntimeGenerationRecordStatus::RolledBack
    );

    let events = handle.generation_change_events();
    assert_eq!(events[0].kind, GenerationEventKind::RollbackSucceeded);
    assert_eq!(events[0].entry.config_source, "gen-1.yaml");
    assert_eq!(events[0].entry.config_version, Some(1));
    assert_eq!(events[0].entry.trigger_source.as_deref(), Some("unit_test"));
}

#[test]
fn rollback_service_rejects_incomplete_or_failed_prepare_targets_without_mutation() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let handle = RuntimeBundleHandle::new(runtime_bundle_from_config(
        "active.yaml",
        &test_config(cert, key),
    ));
    let active_generation = handle.current_generation();
    handle.record_failed_prepare(9, "candidate generation never prepared");

    let rollback = RuntimeActivationService::rollback_generation(
        &handle,
        rollback_request(9, active_generation),
    );

    assert!(
        !rollback.succeeded(),
        "failed-prepare history entries must not be rollbackable"
    );
    assert_eq!(rollback.status, GenerationStatus::Rejected);
    assert_eq!(rollback.rolled_back_to, None);
    assert_eq!(rollback.active_generation, active_generation);
    assert_eq!(handle.current_generation(), active_generation);
    assert!(
        rollback.rejected_changes.iter().any(|rejection| {
            rejection.kind == RejectedChangeKind::RuntimeStateUnavailable
                && rejection.reason == RuntimeRejectionReason::RollbackNotAllowed
                && rejection.field_path.as_deref() == Some("runtime.rollback.target_generation")
        }),
        "expected rollback rejection for incomplete target: {:?}",
        rollback.rejected_changes
    );

    let events = handle.generation_change_events();
    assert_eq!(events[0].kind, GenerationEventKind::RollbackFailed);
    assert_eq!(events[0].entry.status, GenerationStatus::Rejected);
    assert_eq!(events[0].entry.config_source, "generation:9");
}

#[test]
fn validate_plan_does_not_mutate_the_active_generation() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let config_path = dir.path().join("runtime.yaml");
    let current_config = test_config(cert.clone(), key.clone());
    write_config_file(&config_path, &current_config);

    let bundle =
        runtime_bundle_from_config(config_path.to_string_lossy().as_ref(), &current_config);
    let handle = RuntimeBundleHandle::new(bundle);
    let generation_before = handle.current_generation();
    let log_level_before = handle.current_view().startup().log_config.level.clone();

    let mut restart_required = test_config(cert, key);
    restart_required.performance.control_plane_threads = current_config
        .performance
        .control_plane_threads
        .saturating_add(1);
    write_config_file(&config_path, &restart_required);

    let plan = plan_runtime_reload(
        &handle.current_view(),
        planner_request(generation_before),
        ReloadConfigInput::Path {
            path: config_path.to_string_lossy().to_string(),
        },
    );

    assert!(!plan.can_activate());
    assert_eq!(handle.current_generation(), generation_before);
    assert_eq!(
        handle.current_view().startup().log_config.level,
        log_level_before
    );
    assert_eq!(
        handle
            .current_view()
            .runtime_config()
            .policies
            .transport
            .control_plane_threads,
        current_config.performance.control_plane_threads.max(1)
    );
}

#[test]
fn validate_and_preview_record_only_the_requested_history_operation() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let config_path = dir.path().join("runtime.yaml");
    let current_config = test_config(cert.clone(), key.clone());
    write_config_file(&config_path, &current_config);

    let bundle =
        runtime_bundle_from_config(config_path.to_string_lossy().as_ref(), &current_config);
    let handle = RuntimeBundleHandle::new(bundle);

    let validate_plan = RuntimeActivationService::validate_reload(
        &handle,
        planner_request(handle.current_generation()),
        ReloadConfigInput::Path {
            path: config_path.to_string_lossy().to_string(),
        },
    );
    assert_eq!(validate_plan.candidate_status, GenerationStatus::Staged);

    let validate_history = handle.generation_change_history();
    assert_eq!(validate_history.len(), 1);
    assert_eq!(validate_history[0].operation, GenerationOperation::Validate);
    let validate_events = handle.generation_change_events();
    assert_eq!(validate_events.len(), 1);
    assert_eq!(validate_events[0].kind, GenerationEventKind::Validation);

    let mut next_config = test_config(cert, key);
    next_config.log.level = "debug".to_string();
    write_config_file(&config_path, &next_config);

    let preview_plan = RuntimeActivationService::preview_reload(
        &handle,
        planner_request(handle.current_generation()),
        ReloadConfigInput::Path {
            path: config_path.to_string_lossy().to_string(),
        },
    );
    assert_eq!(preview_plan.candidate_status, GenerationStatus::Staged);

    let preview_history = handle.generation_change_history();
    assert_eq!(preview_history.len(), 2);
    assert_eq!(preview_history[0].operation, GenerationOperation::Preview);
    assert_eq!(preview_history[1].operation, GenerationOperation::Validate);
    let preview_events = handle.generation_change_events();
    assert_eq!(preview_events.len(), 2);
    assert_eq!(preview_events[0].kind, GenerationEventKind::Preview);
    assert_eq!(preview_events[1].kind, GenerationEventKind::Validation);
}

#[test]
fn preview_plan_returns_expected_diff_without_mutating_the_active_generation() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let config_path = dir.path().join("runtime.yaml");
    let current_config = test_config(cert.clone(), key.clone());
    write_config_file(&config_path, &current_config);

    let bundle =
        runtime_bundle_from_config(config_path.to_string_lossy().as_ref(), &current_config);
    let handle = RuntimeBundleHandle::new(bundle);
    let generation_before = handle.current_generation();

    let mut next_config = test_config(cert, key);
    next_config.log.level = "debug".to_string();
    write_config_file(&config_path, &next_config);

    let plan = plan_runtime_reload(
        &handle.current_view(),
        planner_request(generation_before),
        ReloadConfigInput::Path {
            path: config_path.to_string_lossy().to_string(),
        },
    );

    assert!(plan.can_activate());
    assert_eq!(handle.current_generation(), generation_before);
    let reloadable = plan
        .plan
        .diff
        .reloadable_entries()
        .into_iter()
        .find(|entry| entry.domain == "observability_control_plane")
        .expect("reloadable observability diff");
    assert!(reloadable.summary.contains("log(level=info"));
    assert!(reloadable.summary.contains("log(level=debug"));
}

#[test]
fn invalid_activation_leaves_active_generation_unchanged() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let config_path = dir.path().join("runtime.yaml");
    let current_config = test_config(cert, key);
    write_config_file(&config_path, &current_config);

    let bundle =
        runtime_bundle_from_config(config_path.to_string_lossy().as_ref(), &current_config);
    let handle = RuntimeBundleHandle::new(bundle);
    let generation_before = handle.current_generation();

    std::fs::write(&config_path, "version: 1\nlisten:\n  protocol: \"http3\"\n")
        .expect("write invalid config");

    let activation = RuntimeActivationService::activate_reload(
        &handle,
        planner_request(generation_before),
        ReloadConfigInput::Path {
            path: config_path.to_string_lossy().to_string(),
        },
    );

    assert!(!activation.succeeded());
    assert_eq!(activation.activated_generation, None);
    assert_eq!(activation.status, GenerationStatus::Rejected);
    assert_eq!(handle.current_generation(), generation_before);
    assert!(
        activation.rejected_changes.iter().any(|rejection| {
            rejection.kind == RejectedChangeKind::InvalidConfiguration
                && rejection.reason == RuntimeRejectionReason::InvalidConfig
        }),
        "expected invalid config rejection: {:?}",
        activation.rejected_changes
    );
}

#[test]
fn runtime_history_records_activate_fail_and_rollback_flow() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let config_path = dir.path().join("runtime.yaml");

    let generation_one = test_config(cert.clone(), key.clone());
    write_config_file(&config_path, &generation_one);
    let mut bundle_one = runtime_bundle_from_config("gen-1.yaml", &generation_one);
    bundle_one.generation = 1;
    let handle = RuntimeBundleHandle::new(bundle_one);

    let mut generation_two = test_config(cert.clone(), key.clone());
    generation_two.log.level = "debug".to_string();
    write_config_file(&config_path, &generation_two);
    let activation = RuntimeActivationService::activate_reload(
        &handle,
        planner_request(handle.current_generation()),
        ReloadConfigInput::Path {
            path: config_path.to_string_lossy().to_string(),
        },
    );
    assert!(activation.succeeded());

    let mut rejected = test_config(cert, key);
    rejected.performance.control_plane_threads = generation_two
        .performance
        .control_plane_threads
        .saturating_add(1);
    write_config_file(&config_path, &rejected);
    let failed = RuntimeActivationService::activate_reload(
        &handle,
        planner_request(handle.current_generation()),
        ReloadConfigInput::Path {
            path: config_path.to_string_lossy().to_string(),
        },
    );
    assert!(!failed.succeeded());

    let rollback = RuntimeActivationService::rollback_generation(
        &handle,
        rollback_request(1, handle.current_generation()),
    );
    assert!(rollback.succeeded());

    let history = handle.generation_change_history();
    let operations = history
        .iter()
        .map(|entry| (entry.operation, entry.status))
        .take(8)
        .collect::<Vec<_>>();
    assert_eq!(
        operations,
        vec![
            (GenerationOperation::Rollback, GenerationStatus::RolledBack),
            (GenerationOperation::Activate, GenerationStatus::Rejected),
            (GenerationOperation::Activate, GenerationStatus::Active),
        ]
    );
    assert_eq!(handle.current_generation(), 3);
    assert_eq!(
        handle
            .current_view()
            .runtime_config()
            .upstreams
            .get("api")
            .expect("active upstream")
            .backends[0]
            .backend
            .address,
        "http://127.0.0.1:7001"
    );
}

// Domain: watchdog service state transitions and restart environment handling.
#[test]
fn watchdog_restart_env_keeps_path_when_present() {
    let env = crate::watchdog::service::watchdog_restart_env(
        Some(OsString::from("/usr/bin:/bin")),
        "timeout_spike",
    );
    let map: HashMap<OsString, OsString> = env.into_iter().collect();

    assert_eq!(
        map.get(&OsString::from("PATH")),
        Some(&OsString::from("/usr/bin:/bin"))
    );
    assert_eq!(
        map.get(&OsString::from("IMPULSE_WATCHDOG_REASON")),
        Some(&OsString::from("timeout_spike"))
    );
}

#[test]
fn watchdog_restart_env_omits_path_when_missing() {
    let env = crate::watchdog::service::watchdog_restart_env(None, "poll_stall");
    let map: HashMap<OsString, OsString> = env.into_iter().collect();

    assert!(!map.contains_key(&OsString::from("PATH")));
    assert_eq!(
        map.get(&OsString::from("IMPULSE_WATCHDOG_REASON")),
        Some(&OsString::from("poll_stall"))
    );
}

// Domain: control API auth and route gating contracts.
#[test]
fn bearer_authorization_scheme_is_case_insensitive() {
    assert_eq!(
        QUICListener::bearer_token_from_authorization_header("Bearer token-1"),
        Some("token-1")
    );
    assert_eq!(
        QUICListener::bearer_token_from_authorization_header("bearer token-2"),
        Some("token-2")
    );
    assert_eq!(
        QUICListener::bearer_token_from_authorization_header("BEARER token-3"),
        Some("token-3")
    );
}

#[test]
fn bearer_authorization_rejects_malformed_headers() {
    assert_eq!(
        QUICListener::bearer_token_from_authorization_header("Basic abc"),
        None
    );
    assert_eq!(
        QUICListener::bearer_token_from_authorization_header("Bearer"),
        None
    );
    assert_eq!(
        QUICListener::bearer_token_from_authorization_header("Bearer   "),
        None
    );
}

#[test]
fn control_api_route_gating_accepts_only_canonical_method_and_path_pairs() {
    let state = default_control_api_state();
    let paths = state.current_paths();

    let cases = [
        (
            Method::GET,
            paths.health_path.clone(),
            Some(super::admin_auth::ControlApiRoute::Health),
        ),
        (
            Method::GET,
            paths.ready_path.clone(),
            Some(super::admin_auth::ControlApiRoute::Ready),
        ),
        (
            Method::GET,
            paths.runtime_path.clone(),
            Some(super::admin_auth::ControlApiRoute::Runtime),
        ),
        (
            Method::GET,
            paths.runtime_history_path(),
            Some(super::admin_auth::ControlApiRoute::RuntimeHistory),
        ),
        (
            Method::GET,
            format!("{}/2", paths.runtime_history_path()),
            Some(super::admin_auth::ControlApiRoute::RuntimeHistoryGeneration(2)),
        ),
        (
            Method::POST,
            paths.reload_certs_path.clone(),
            Some(super::admin_auth::ControlApiRoute::ReloadCerts),
        ),
        (
            Method::POST,
            paths.runtime_validate_path(),
            Some(super::admin_auth::ControlApiRoute::RuntimeValidate),
        ),
        (
            Method::POST,
            paths.runtime_preview_path(),
            Some(super::admin_auth::ControlApiRoute::RuntimePreview),
        ),
        (
            Method::POST,
            paths.runtime_activate_path(),
            Some(super::admin_auth::ControlApiRoute::RuntimeActivate),
        ),
        (
            Method::POST,
            paths.runtime_rollback_path(),
            Some(super::admin_auth::ControlApiRoute::RuntimeRollback),
        ),
        (
            Method::POST,
            paths.reload_path.clone(),
            Some(super::admin_auth::ControlApiRoute::ReloadRuntime),
        ),
        (
            Method::POST,
            paths.restart_path.clone(),
            Some(super::admin_auth::ControlApiRoute::Restart),
        ),
        (Method::POST, paths.runtime_path.clone(), None),
        (Method::POST, paths.runtime_history_path(), None),
        (Method::GET, paths.reload_path.clone(), None),
        (Method::GET, "/missing".to_string(), None),
    ];

    for (method, path, expected) in cases {
        let req = control_api_request(method, &path, None);
        assert_eq!(
            QUICListener::control_api_request_route_for(&req, &state.current_paths()),
            expected,
            "unexpected route decision for {} {}",
            req.method(),
            req.uri().path()
        );
    }
}

#[test]
fn control_api_route_gating_leaves_health_and_ready_ungated_by_auth() {
    let state = default_control_api_state();
    let paths = state.current_paths();

    for path in [&paths.health_path, &paths.ready_path] {
        let mut req = control_api_request(Method::GET, path, None);
        let route = QUICListener::gate_control_api_request_for(&mut req, &state)
            .expect("health and ready routes should bypass auth");
        assert!(matches!(
            route,
            super::admin_auth::ControlApiRoute::Health | super::admin_auth::ControlApiRoute::Ready
        ));
    }
}

#[test]
fn control_api_authorization_uses_token_matching_independent_of_request_body_type() {
    let state = default_control_api_state();
    let runtime_path = state.current_paths().runtime_path;
    let authorized = control_api_request(Method::GET, &runtime_path, Some("Bearer secret-token"));
    let malformed = control_api_request(Method::GET, &runtime_path, Some("Bearer"));
    let missing = control_api_request(Method::GET, &runtime_path, None);

    let security = state.current_security_policy();

    assert!(QUICListener::control_api_is_authorized_for(
        &authorized,
        &security
    ));
    assert!(!QUICListener::control_api_is_authorized_for(
        &malformed, &security
    ));
    assert!(!QUICListener::control_api_is_authorized_for(
        &missing, &security
    ));
}

#[tokio::test]
async fn control_api_gate_returns_canonical_unauthorized_payloads_per_route() {
    let state = default_control_api_state();
    let paths = state.current_paths();

    let cases = [
        (
            Method::GET,
            paths.runtime_path.clone(),
            serde_json::json!({
                "error": "unauthorized",
                "reason": "missing_authentication",
                "required_role": "viewer"
            }),
        ),
        (
            Method::POST,
            paths.runtime_validate_path(),
            serde_json::json!({
                "error": "unauthorized",
                "reason": "missing_authentication",
                "required_role": "operator"
            }),
        ),
        (
            Method::POST,
            paths.runtime_preview_path(),
            serde_json::json!({
                "error": "unauthorized",
                "reason": "missing_authentication",
                "required_role": "operator"
            }),
        ),
        (
            Method::POST,
            paths.runtime_activate_path(),
            serde_json::json!({
                "error": "unauthorized",
                "reason": "missing_authentication",
                "required_role": "operator"
            }),
        ),
        (
            Method::POST,
            paths.runtime_rollback_path(),
            serde_json::json!({
                "error": "unauthorized",
                "reason": "missing_authentication",
                "required_role": "operator"
            }),
        ),
        (
            Method::GET,
            paths.runtime_history_path(),
            serde_json::json!({
                "error": "unauthorized",
                "reason": "missing_authentication",
                "required_role": "viewer"
            }),
        ),
        (
            Method::POST,
            paths.reload_certs_path.clone(),
            serde_json::json!({
                "reloaded": false,
                "error": "unauthorized",
                "reason": "missing_authentication",
                "required_role": "operator"
            }),
        ),
        (
            Method::POST,
            paths.reload_path.clone(),
            serde_json::json!({
                "reloaded": false,
                "error": "unauthorized",
                "reason": "missing_authentication",
                "required_role": "operator"
            }),
        ),
        (
            Method::POST,
            paths.restart_path.clone(),
            serde_json::json!({
                "accepted": false,
                "error": "unauthorized",
                "reason": "missing_authentication",
                "required_role": "admin"
            }),
        ),
    ];

    for (method, path, expected_body) in cases {
        let mut req = control_api_request(method, &path, None);
        let response = QUICListener::gate_control_api_request_for(&mut req, &state)
            .expect_err("protected route should reject missing auth");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = full_body_bytes(*response).await;
        let payload: serde_json::Value =
            serde_json::from_slice(&body).expect("unauthorized payload");
        assert_eq!(payload, expected_body);
    }
}

#[tokio::test]
async fn control_api_gate_rejects_bearer_only_request_when_mtls_required() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut startup = test_config(cert.clone(), key.clone());
    startup.observability.control_api.enabled = true;
    startup.observability.control_api.auth_token = Some("secret-token".to_string());
    startup.observability.control_api.tls.client_auth.mode = ControlApiClientAuthMode::Required;
    startup.observability.control_api.tls.client_auth.ca_file = Some(cert.clone());
    let state = control_api_state_with_runtime_bundle(&startup, &startup);
    let runtime_path = state.current_paths().runtime_path;

    let mut req = control_api_request(Method::GET, &runtime_path, Some("Bearer secret-token"));
    attach_control_api_peer_addr(&mut req, "127.0.0.1:9443");

    let response = QUICListener::gate_control_api_request_for(&mut req, &state)
        .expect_err("bearer-only request must be rejected once mTLS is required");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = full_body_bytes(*response).await;
    let payload: serde_json::Value = serde_json::from_slice(&body).expect("unauthorized payload");
    assert_eq!(payload["reason"], "missing_authentication");
}

#[test]
fn control_api_auth_policy_generation_changes_after_mtls_mode_reload() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut startup = test_config(cert.clone(), key.clone());
    startup.observability.control_api.enabled = true;
    startup.observability.control_api.auth_token = Some("secret-token".to_string());

    let startup_bundle = runtime_bundle_from_config("startup.yaml", &startup);
    let (state, runtime_handle) = runtime_bundle_control_api_state(startup_bundle);
    let connect_time_generation = state.current_service_state().auth_policy_generation();

    let mut reloaded = startup.clone();
    reloaded.observability.control_api.tls.client_auth.mode = ControlApiClientAuthMode::Required;
    reloaded.observability.control_api.tls.client_auth.ca_file = Some(cert);
    let mut reloaded_bundle = runtime_bundle_from_config("reloaded.yaml", &reloaded);
    reloaded_bundle.generation = 1;
    runtime_handle
        .replace(reloaded_bundle)
        .expect("replace runtime bundle");

    let post_reload_generation = state.current_service_state().auth_policy_generation();
    assert_ne!(
        connect_time_generation, post_reload_generation,
        "a connection that captured the pre-reload generation must observe drift after an mTLS policy change"
    );
}

#[test]
fn control_api_authorization_generation_detects_drift_during_delayed_body_collection() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut startup = test_config(cert.clone(), key.clone());
    startup.observability.control_api.enabled = true;
    startup.observability.control_api.auth_token = Some("operator-token".to_string());

    let startup_bundle = runtime_bundle_from_config("startup.yaml", &startup);
    let (state, runtime_handle) = runtime_bundle_control_api_state(startup_bundle);

    // Captured immediately after the gate authenticates the request headers,
    // before the JSON body (which may take arbitrarily long to arrive) is awaited.
    let (runtime, listener_tls) = state.current_service_state().auth_policy_generation();
    let authorization_generation = super::state::ControlApiAuthorizationGeneration {
        runtime,
        listener_tls,
    };
    assert!(
        authorization_generation.is_current(state.current_service_state().auth_policy_generation())
    );

    // Simulates the token being revoked on another connection while this
    // request's body is still being collected: the active generation changes.
    let mut revoked = startup.clone();
    revoked.observability.control_api.auth_token = Some("new-token-after-revocation".to_string());
    let mut revoked_bundle = runtime_bundle_from_config("revoked.yaml", &revoked);
    revoked_bundle.generation = 1;
    runtime_handle
        .replace(revoked_bundle)
        .expect("replace runtime bundle");

    // The body has now "arrived"; the handler re-checks the generation before
    // committing the mutation and must observe that it is no longer current.
    let current_at_mutation_time = state.current_service_state().auth_policy_generation();
    assert!(
        !authorization_generation.is_current(current_at_mutation_time),
        "a delayed mutation must detect a security-policy change that happened during body collection"
    );
}

#[test]
fn control_api_security_differs_detects_revoked_bearer_token() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut with_admin_token = test_config(cert, key);
    with_admin_token.observability.control_api.enabled = true;
    with_admin_token
        .observability
        .control_api
        .auth
        .bearer_tokens = vec![ControlApiBearerToken {
        token: "old-admin-token".to_string(),
        token_ref: None,
        role: ControlApiRole::Admin,
        actor_id: Some("admin".to_string()),
    }];

    let mut revoked = with_admin_token.clone();
    revoked.observability.control_api.auth.bearer_tokens = vec![ControlApiBearerToken {
        token: "operator-token".to_string(),
        token_ref: None,
        role: ControlApiRole::Operator,
        actor_id: Some("operator".to_string()),
    }];

    assert!(
        super::reload::rollback::control_api_security_differs(
            &revoked.observability.control_api,
            &with_admin_token.observability.control_api
        ),
        "restoring a generation whose bearer tokens include a since-revoked admin \
         credential must be classified as a control-API security change"
    );
}

#[test]
fn control_api_security_differs_ignores_unrelated_application_changes() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut current = test_config(cert, key);
    current.observability.control_api.enabled = true;
    current.observability.control_api.runtime_path = "/runtime-current".to_string();

    let mut target = current.clone();
    target.observability.control_api.runtime_path = "/runtime-target".to_string();

    assert!(
        !super::reload::rollback::control_api_security_differs(
            &current.observability.control_api,
            &target.observability.control_api
        ),
        "a rollback that only changes a non-security field must not be blocked"
    );
}

#[tokio::test]
async fn control_api_gate_returns_forbidden_for_under_scoped_identity() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut startup = test_config(cert, key);
    startup.observability.control_api.enabled = true;
    startup.observability.control_api.auth_token = None;
    startup.observability.control_api.auth.bearer_tokens = vec![ControlApiBearerToken {
        token: "viewer-token".to_string(),
        token_ref: None,
        role: ControlApiRole::Viewer,
        actor_id: Some("viewer".to_string()),
    }];
    let state = control_api_state_with_runtime_bundle(&startup, &startup);

    let mut req = control_api_request(
        Method::POST,
        &state.current_paths().reload_path,
        Some("Bearer viewer-token"),
    );
    let response = QUICListener::gate_control_api_request_for(&mut req, &state)
        .expect_err("viewer should not be allowed to call operator route");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let payload: serde_json::Value =
        serde_json::from_slice(&full_body_bytes(*response).await).expect("forbidden payload");
    assert_eq!(
        payload,
        serde_json::json!({
            "reloaded": false,
            "error": "forbidden",
            "reason": "insufficient_role",
            "required_role": "operator"
        })
    );
}

#[tokio::test]
async fn control_api_gate_rejects_invalid_bearer_token() {
    let state = default_control_api_state();
    let mut req = control_api_request(
        Method::GET,
        &state.current_paths().runtime_path,
        Some("Bearer wrong-token"),
    );

    let response = QUICListener::gate_control_api_request_for(&mut req, &state)
        .expect_err("invalid token should be rejected");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let payload: serde_json::Value =
        serde_json::from_slice(&full_body_bytes(*response).await).expect("unauthorized payload");
    assert_eq!(
        payload,
        serde_json::json!({
            "error": "unauthorized",
            "reason": "invalid_bearer_token",
            "required_role": "viewer"
        })
    );
}

#[tokio::test]
async fn control_api_auth_throttle_ignores_spoofed_forwarding_addresses() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut startup = test_config(cert, key);
    startup.observability.control_api.enabled = true;
    startup.observability.control_api.auth_token = Some("secret-token".to_string());
    startup.observability.control_api.ip_allowlist.cidrs = vec!["0.0.0.0/0".to_string()];
    startup
        .observability
        .control_api
        .ip_allowlist
        .trust_proxy_headers = true;
    startup
        .observability
        .control_api
        .ip_allowlist
        .trusted_proxy_cidrs = vec!["10.0.0.0/8".to_string()];
    let state = control_api_state_with_runtime_bundle(&startup, &startup);
    let runtime_path = state.current_paths().runtime_path;

    for attempt in 0..5 {
        let mut req = control_api_request(
            Method::GET,
            &runtime_path,
            Some("Bearer definitely-not-secret-token"),
        );
        req.headers_mut().insert(
            "x-forwarded-for",
            format!("203.0.113.{attempt}")
                .parse()
                .expect("forwarded ip"),
        );
        attach_control_api_peer_addr(&mut req, "10.0.0.2:9443");

        let response = QUICListener::gate_control_api_request_for(&mut req, &state)
            .expect_err("invalid token should be rejected");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    let mut req = control_api_request(
        Method::GET,
        &runtime_path,
        Some("Bearer definitely-not-secret-token"),
    );
    req.headers_mut().insert(
        "forwarded",
        "for=198.51.100.99".parse().expect("forwarded ip"),
    );
    attach_control_api_peer_addr(&mut req, "10.0.0.2:9443");

    let response = QUICListener::gate_control_api_request_for(&mut req, &state)
        .expect_err("transport peer should remain throttled across spoofed headers");
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    let mut valid_admin =
        control_api_request(Method::GET, &runtime_path, Some("Bearer secret-token"));
    attach_control_api_peer_addr(&mut valid_admin, "10.0.0.2:9443");
    QUICListener::gate_control_api_request_for(&mut valid_admin, &state)
        .expect("valid administrator must not be locked out by shared-peer failures");
}

#[tokio::test]
async fn control_api_gate_returns_forbidden_for_operator_hitting_restart() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut startup = test_config(cert, key);
    startup.observability.control_api.enabled = true;
    startup.observability.control_api.auth_token = None;
    startup.observability.control_api.auth.bearer_tokens = vec![ControlApiBearerToken {
        token: "operator-token".to_string(),
        token_ref: None,
        role: ControlApiRole::Operator,
        actor_id: Some("operator".to_string()),
    }];
    let state = control_api_state_with_runtime_bundle(&startup, &startup);

    let mut req = control_api_request(
        Method::POST,
        &state.current_paths().restart_path,
        Some("Bearer operator-token"),
    );
    let response = QUICListener::gate_control_api_request_for(&mut req, &state)
        .expect_err("operator should not be allowed to restart");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let payload: serde_json::Value =
        serde_json::from_slice(&full_body_bytes(*response).await).expect("forbidden payload");
    assert_eq!(
        payload,
        serde_json::json!({
            "accepted": false,
            "error": "forbidden",
            "reason": "insufficient_role",
            "required_role": "admin"
        })
    );
}

#[test]
fn control_api_builds_mtls_identity_from_subject_role_mapping() {
    use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, SanType};
    use rustls::pki_types::CertificateDer;

    let mut params = CertificateParams::new(vec!["admin.example.com".to_string()]);
    params
        .subject_alt_names
        .push(SanType::DnsName("admin.example.com".to_string()));
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "alice");
    dn.push(DnType::OrganizationalUnitName, "operator");
    params.distinguished_name = dn;
    let cert = Certificate::from_params(params).expect("build cert");
    let cert_der = CertificateDer::from(cert.serialize_der().expect("serialize cert"));

    let identity_source = super::security::ControlApiIdentitySourcePolicy {
        kind: "mtls_subject_cn".to_string(),
        role_attribute: Some("ou".to_string()),
    };
    let request_context = QUICListener::build_control_api_request_context(
        "127.0.0.1:9443".parse().expect("peer addr"),
        Some(std::slice::from_ref(&cert_der)),
        Some(&identity_source),
        Some("edge-primary".to_string()),
    );
    let identity =
        QUICListener::build_admin_identity(Some(request_context), None, Some(&identity_source))
            .expect("mtls identity");

    assert_eq!(identity.actor_id.as_deref(), Some("alice"));
    assert_eq!(
        identity.roles,
        vec![super::admin_identity::AdminRole::Operator]
    );
    assert_eq!(
        identity.authn_mechanisms,
        vec![super::admin_identity::AdminAuthnMechanism::MutualTls]
    );
    assert_eq!(
        identity.peer_addr.expect("peer addr").ip().to_string(),
        "127.0.0.1"
    );
}

#[test]
fn control_api_dual_auth_identity_uses_least_privileged_common_role() {
    let request_context = super::admin_identity::ControlApiRequestContext {
        peer_addr: "127.0.0.1:9443".parse().expect("peer socket addr"),
        mtls_identity: Some(super::admin_identity::AdminMtlsIdentity {
            subject: Some("CN=alice".to_string()),
            common_name: Some("alice".to_string()),
            san_dns: vec!["admin.example.com".to_string()],
            san_uri: Vec::new(),
            roles: vec![super::admin_identity::AdminRole::Admin],
        }),
        listener: Some("edge-primary".to_string()),
        request_id: None,
        trace_id: None,
        span_id: None,
    };
    let token_match = super::admin_identity::AdminTokenMatch {
        actor_id: Some("alice".to_string()),
        role: super::admin_identity::AdminRole::Viewer,
    };

    let identity =
        QUICListener::build_admin_identity(Some(request_context), Some(token_match), None)
            .expect("dual auth identity");

    assert_eq!(
        identity.roles,
        vec![super::admin_identity::AdminRole::Viewer]
    );
    assert_eq!(
        identity.authn_mechanisms,
        vec![
            super::admin_identity::AdminAuthnMechanism::BearerToken,
            super::admin_identity::AdminAuthnMechanism::MutualTls,
        ]
    );
    assert_eq!(identity.actor_id.as_deref(), Some("alice"));
}

#[test]
fn control_api_dual_auth_identity_keeps_token_role_when_mtls_has_no_role_mapping() {
    let request_context = super::admin_identity::ControlApiRequestContext {
        peer_addr: "127.0.0.1:9443".parse().expect("peer socket addr"),
        mtls_identity: Some(super::admin_identity::AdminMtlsIdentity {
            subject: Some("CN=alice".to_string()),
            common_name: Some("alice".to_string()),
            san_dns: vec!["admin.example.com".to_string()],
            san_uri: Vec::new(),
            roles: Vec::new(),
        }),
        listener: Some("edge-primary".to_string()),
        request_id: None,
        trace_id: None,
        span_id: None,
    };
    let token_match = super::admin_identity::AdminTokenMatch {
        actor_id: Some("alice".to_string()),
        role: super::admin_identity::AdminRole::Operator,
    };

    let identity =
        QUICListener::build_admin_identity(Some(request_context), Some(token_match), None)
            .expect("dual auth identity without mtls role");

    assert_eq!(
        identity.roles,
        vec![super::admin_identity::AdminRole::Operator]
    );
    assert_eq!(identity.actor_id.as_deref(), Some("alice"));
}

#[test]
fn control_api_dual_auth_identity_rejects_disagreeing_principals() {
    let request_context = super::admin_identity::ControlApiRequestContext {
        peer_addr: "127.0.0.1:9443".parse().expect("peer socket addr"),
        mtls_identity: Some(super::admin_identity::AdminMtlsIdentity {
            subject: Some("CN=bob".to_string()),
            common_name: Some("bob".to_string()),
            san_dns: vec!["admin.example.com".to_string()],
            san_uri: Vec::new(),
            roles: vec![super::admin_identity::AdminRole::Admin],
        }),
        listener: Some("edge-primary".to_string()),
        request_id: None,
        trace_id: None,
        span_id: None,
    };
    let token_match = super::admin_identity::AdminTokenMatch {
        actor_id: Some("alice".to_string()),
        role: super::admin_identity::AdminRole::Viewer,
    };

    let identity =
        QUICListener::build_admin_identity(Some(request_context), Some(token_match), None);

    assert!(identity.is_none());
}

#[test]
fn control_api_dual_auth_identity_rejects_bearer_actor_from_other_mtls_namespace() {
    let identity_source = super::security::ControlApiIdentitySourcePolicy {
        kind: "mtls_san_uri".to_string(),
        role_attribute: None,
    };
    let request_context = super::admin_identity::ControlApiRequestContext {
        peer_addr: "127.0.0.1:9443".parse().expect("peer socket addr"),
        mtls_identity: Some(super::admin_identity::AdminMtlsIdentity {
            subject: Some("CN=alice".to_string()),
            common_name: Some("alice".to_string()),
            san_dns: vec!["admin.example.com".to_string()],
            san_uri: vec!["spiffe://alice".to_string()],
            roles: Vec::new(),
        }),
        listener: Some("edge-primary".to_string()),
        request_id: None,
        trace_id: None,
        span_id: None,
    };
    let token_match = super::admin_identity::AdminTokenMatch {
        actor_id: Some("admin.example.com".to_string()),
        role: super::admin_identity::AdminRole::Operator,
    };

    let identity = QUICListener::build_admin_identity(
        Some(request_context),
        Some(token_match),
        Some(&identity_source),
    );

    assert!(identity.is_none());
}

#[test]
fn control_api_dual_auth_identity_rejects_when_no_mtls_principal_matches() {
    let identity_source = super::security::ControlApiIdentitySourcePolicy {
        kind: "mtls_san_uri".to_string(),
        role_attribute: None,
    };
    let request_context = super::admin_identity::ControlApiRequestContext {
        peer_addr: "127.0.0.1:9443".parse().expect("peer socket addr"),
        mtls_identity: Some(super::admin_identity::AdminMtlsIdentity {
            subject: Some("CN=alice".to_string()),
            common_name: Some("alice".to_string()),
            san_dns: vec!["admin.example.com".to_string()],
            san_uri: vec!["spiffe://alice".to_string()],
            roles: Vec::new(),
        }),
        listener: Some("edge-primary".to_string()),
        request_id: None,
        trace_id: None,
        span_id: None,
    };
    let token_match = super::admin_identity::AdminTokenMatch {
        actor_id: Some("mallory".to_string()),
        role: super::admin_identity::AdminRole::Operator,
    };

    let identity = QUICListener::build_admin_identity(
        Some(request_context),
        Some(token_match),
        Some(&identity_source),
    );

    assert!(identity.is_none());
}

#[test]
fn control_api_request_context_captures_operator_correlation_headers() {
    let request_context = super::admin_identity::ControlApiRequestContext {
        peer_addr: "127.0.0.1:9443".parse().expect("peer socket addr"),
        mtls_identity: None,
        listener: Some("edge-primary".to_string()),
        request_id: None,
        trace_id: None,
        span_id: None,
    };
    let req = Request::builder()
        .method(Method::GET)
        .uri("/admin/runtime")
        .header(header::HeaderName::from_static("x-request-id"), "req-42")
        .header(
            header::HeaderName::from_static("traceparent"),
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        )
        .body(())
        .expect("control api request");

    let request_context = QUICListener::augment_control_api_request_context(request_context, &req);

    assert_eq!(request_context.listener.as_deref(), Some("edge-primary"));
    assert_eq!(request_context.request_id.as_deref(), Some("req-42"));
    assert_eq!(
        request_context.trace_id.as_deref(),
        Some("4bf92f3577b34da6a3ce929d0e0e4736")
    );
    assert_eq!(request_context.span_id.as_deref(), Some("00f067aa0ba902b7"));
}

#[tokio::test]
async fn control_api_gate_rejects_source_ip_before_authentication() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut startup = test_config(cert, key);
    startup.observability.control_api.enabled = true;
    startup.observability.control_api.auth_token = Some("secret-token".to_string());
    startup.observability.control_api.ip_allowlist.cidrs = vec!["127.0.0.0/8".to_string()];
    let state = control_api_state_with_runtime_bundle(&startup, &startup);

    let mut req = control_api_request(
        Method::POST,
        &state.current_paths().reload_path,
        Some("Bearer definitely-not-secret-token"),
    );
    attach_control_api_peer_addr(&mut req, "10.0.0.10:9443");

    let response = QUICListener::gate_control_api_request_for(&mut req, &state)
        .expect_err("non-allowlisted source should be rejected before auth");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let payload: serde_json::Value =
        serde_json::from_slice(&full_body_bytes(*response).await).expect("forbidden payload");
    assert_eq!(
        payload,
        serde_json::json!({
            "reloaded": false,
            "error": "forbidden",
            "reason": "source_ip_not_allowed",
            "required_role": "operator"
        })
    );
}

#[tokio::test]
async fn control_api_gate_allows_allowlisted_source_and_continues_authentication() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut startup = test_config(cert, key);
    startup.observability.control_api.enabled = true;
    startup.observability.control_api.auth_token = Some("secret-token".to_string());
    startup.observability.control_api.ip_allowlist.cidrs = vec!["127.0.0.0/8".to_string()];
    let state = control_api_state_with_runtime_bundle(&startup, &startup);

    let mut req = control_api_request(
        Method::POST,
        &state.current_paths().reload_path,
        Some("Bearer secret-token"),
    );
    attach_control_api_peer_addr(&mut req, "127.0.0.1:9443");

    let route = QUICListener::gate_control_api_request_for(&mut req, &state)
        .expect("allowlisted source with valid auth should pass");
    assert_eq!(route, super::admin_auth::ControlApiRoute::ReloadRuntime);
}

#[tokio::test]
async fn control_api_gate_returns_not_found_for_invalid_routes_without_transport_coupling() {
    let state = default_control_api_state();
    let mut req = control_api_request(
        Method::DELETE,
        &state.current_paths().runtime_path,
        Some("Bearer secret-token"),
    );

    let response = QUICListener::gate_control_api_request_for(&mut req, &state)
        .expect_err("invalid route should map to not found");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        full_body_bytes(*response).await,
        Bytes::from_static(b"not found\n")
    );
}

#[tokio::test]
async fn control_api_runtime_snapshot_endpoint_allows_viewer() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut startup = test_config(cert, key);
    startup.observability.control_api.enabled = true;
    startup.observability.control_api.auth_token = None;
    startup.observability.control_api.auth.bearer_tokens = vec![ControlApiBearerToken {
        token: "viewer-token".to_string(),
        token_ref: None,
        role: ControlApiRole::Viewer,
        actor_id: Some("viewer".to_string()),
    }];
    let state = control_api_state_with_runtime_bundle(&startup, &startup);

    let mut req = control_api_request(
        Method::GET,
        &state.current_paths().runtime_path,
        Some("Bearer viewer-token"),
    );
    let route = QUICListener::gate_control_api_request_for(&mut req, &state)
        .expect("viewer should be allowed to read runtime snapshot");
    assert_eq!(route, super::admin_auth::ControlApiRoute::Runtime);
    let response = QUICListener::render_control_api_runtime_snapshot(&state);
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn control_api_runtime_snapshot_includes_jwks_cache_visibility() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let jwks_url = "https://issuer.example.com/.well-known/jwks.json";
    let jwks_source_id = crate::quic_listener::admission::jwks_source_identity_for_test(jwks_url);
    let mut startup = test_config(cert, key);
    startup.upstream.get_mut("api").expect("api upstream").auth = RouteAuth {
        api_key: Some(ApiKeyAuth {
            header_name: "x-api-key".to_string(),
            keys: vec!["secret".to_string()],
        }),
        jwt: Some(JwtAuth {
            secret: String::new(),
            allowed_algorithms: vec![JwtAlgorithm::Rs256],
            jwks_url: Some(jwks_url.to_string()),
            jwks_startup_behavior: JwksStartupBehavior::AllowDegraded,
            ..JwtAuth::default()
        }),
        external_auth: None,
        required_scopes: vec!["payments:read".to_string()],
        required_roles: vec!["operator".to_string()],
    };
    crate::quic_listener::admission::prime_jwks_cache_for_test(
        jwks_url,
        false,
        vec![RuntimeJwtVerificationKey::Pem {
            kid: Some("cached-key-1".to_string()),
            alg: Some(JwtAlgorithm::Rs256),
            public_key_pem:
                "-----BEGIN PUBLIC KEY-----\nMIIBCgKCAQEAtest\n-----END PUBLIC KEY-----".to_string(),
        }],
    );
    let state = control_api_state_with_runtime_bundle(&startup, &startup);
    let metrics = state.current_service_state().metrics();
    metrics.record_jwt_validation_failure("issuer_mismatch");
    metrics.record_jwt_algorithm_rejection("RS256");
    metrics.record_jwks_unknown_kid(&jwks_source_id);

    let payload = json_body(QUICListener::render_control_api_runtime_snapshot(&state)).await;
    let providers = payload["auth"]["providers"]
        .as_array()
        .expect("auth providers");
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0]["upstream"], "api");
    assert!(
        providers[0].get("api_key_configured").is_none(),
        "runtime snapshot must not expose api key posture"
    );
    assert!(
        providers[0].get("external_auth_configured").is_none(),
        "runtime snapshot must not expose external auth posture"
    );
    assert!(
        providers[0].get("required_scopes").is_none(),
        "runtime snapshot must not expose required scopes"
    );
    assert!(
        providers[0].get("required_roles").is_none(),
        "runtime snapshot must not expose required roles"
    );
    assert_eq!(providers[0]["jwt"]["provider_mode"], "remote_jwks");
    assert_eq!(providers[0]["jwt"]["jwks_configured"], true);
    assert_eq!(providers[0]["jwt"]["jwks_active"], true);
    assert_eq!(providers[0]["jwt"]["jwks_cache_state"], "fresh");
    assert_eq!(providers[0]["jwt"]["serving_from_stale_cache"], false);
    assert_eq!(providers[0]["jwt"]["usable_key_count"], 1);
    assert_eq!(
        payload["auth"]["jwt_validation_failures"]
            .as_array()
            .expect("jwt failure reasons")[0]["reason"],
        "issuer_mismatch"
    );
    assert_eq!(
        payload["auth"]["jwt_algorithm_rejections"]
            .as_array()
            .expect("jwt algorithm rejections")[0]["reason"],
        "RS256"
    );
    assert_eq!(
        payload["auth"]["unknown_kid_events"]
            .as_array()
            .expect("unknown kid events")[0]["jwks_source_id"],
        jwks_source_id
    );
    let sources = payload["jwks"]["sources"].as_array().expect("jwks sources");
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0]["jwks_source_id"], jwks_source_id);
    assert!(
        sources[0].get("jwks_endpoint").is_none(),
        "runtime snapshot must not expose jwks endpoint"
    );
    assert_eq!(sources[0]["startup_behavior"], "allow_degraded");
    assert_eq!(sources[0]["cache_state"], "fresh");
    assert_eq!(sources[0]["active_key_count"], 1);
    assert!(payload["tls"]["upstreams"]["api"].is_object());
    assert!(payload["secrets"]["providers"].is_array());
    assert!(payload["secrets"]["material"].is_array());
    assert_eq!(
        sources[0]["allowed_algorithms"]
            .as_array()
            .expect("algorithms")[0],
        "RS256"
    );
    crate::quic_listener::admission::clear_jwks_cache_for_test(jwks_url);
}

#[tokio::test]
async fn control_api_runtime_snapshot_omits_jwks_endpoint_details() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let jwks_url = "https://user:secret@issuer.internal.example.com/reload-require-ready.json?token=secret#fragment";
    let mut startup = test_config(cert, key);
    startup
        .upstream
        .get_mut("api")
        .expect("api upstream")
        .auth
        .jwt = Some(JwtAuth {
        secret: String::new(),
        allowed_algorithms: vec![JwtAlgorithm::Rs256],
        jwks_url: Some(jwks_url.to_string()),
        jwks_startup_behavior: JwksStartupBehavior::AllowDegraded,
        ..JwtAuth::default()
    });
    let state = control_api_state_with_runtime_bundle(&startup, &startup);

    let payload = json_body(QUICListener::render_control_api_runtime_snapshot(&state)).await;
    let sources = payload["jwks"]["sources"].as_array().expect("jwks sources");

    assert_eq!(sources.len(), 1);
    assert!(
        sources[0].get("jwks_endpoint").is_none(),
        "viewer payload must not expose jwks endpoint details"
    );
}

#[tokio::test]
async fn control_api_runtime_snapshot_coarsens_sensitive_tls_and_secret_details() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let ca_dir = dir.path().join("ca");
    std::fs::create_dir_all(&ca_dir).expect("create ca dir");
    std::fs::copy(&cert, ca_dir.join("root.pem")).expect("copy ca cert");

    let mut config = test_config(cert.clone(), key.clone());
    config.observability.control_api.enabled = true;
    config
        .upstream
        .get_mut("api")
        .expect("api upstream")
        .backends[0]
        .address = "https://127.0.0.1:7001".to_string();
    config.upstream.get_mut("api").expect("api upstream").tls = Some(UpstreamTls {
        verify_certificates: true,
        strict_sni: true,
        ca_file: Some(cert.clone()),
        ca_dir: Some(ca_dir.to_string_lossy().to_string()),
        client_certificate: Some(cert),
        client_certificate_ref: None,
        client_key: Some(key),
        client_key_ref: None,
    });
    config.secrets.providers.insert(
        "files".to_string(),
        SecretProvider::File {
            base_dir: Some(dir.path().join("secrets").to_string_lossy().to_string()),
        },
    );
    config.secrets.default_provider = Some("files".to_string());

    let state = control_api_state_with_runtime_bundle(&config, &config);
    let payload = json_body(QUICListener::render_control_api_runtime_snapshot(&state)).await;

    let upstream_tls = &payload["tls"]["upstreams"]["api"];
    assert_eq!(upstream_tls["custom_ca_file_configured"], true);
    assert_eq!(upstream_tls["custom_ca_dir_configured"], true);
    assert!(
        upstream_tls.get("ca_file").is_none(),
        "viewer payload must not expose CA file path surrogates"
    );
    assert!(
        upstream_tls.get("ca_dir").is_none(),
        "viewer payload must not expose CA directory path surrogates"
    );
    assert!(
        upstream_tls.get("ca_file_fingerprint").is_none(),
        "viewer payload must not expose CA fingerprint surrogates"
    );
    assert!(
        upstream_tls.get("ca_dir_fingerprint").is_none(),
        "viewer payload must not expose CA fingerprint surrogates"
    );
    assert!(
        upstream_tls["client_certificate"]
            .get("reference")
            .is_none(),
        "viewer payload must not expose secret references"
    );
    assert!(
        upstream_tls["client_certificate"]
            .get("fingerprint")
            .is_none(),
        "viewer payload must not expose secret fingerprints"
    );
    assert_eq!(upstream_tls["client_certificate"]["source_kind"], "file");

    let provider = payload["secrets"]["providers"]
        .as_array()
        .expect("providers array")
        .iter()
        .find(|provider| provider["provider"] == "files")
        .expect("files provider");
    assert_eq!(provider["base_dir_configured"], true);
    assert!(
        provider.get("base_dir").is_none(),
        "viewer payload must not expose secret-provider base_dir"
    );

    let material = payload["secrets"]["material"]
        .as_array()
        .expect("material array");
    assert!(
        material
            .iter()
            .all(|entry| entry.get("reference").is_none()),
        "viewer payload must not expose secret references"
    );
    assert!(
        material
            .iter()
            .all(|entry| entry.get("fingerprint").is_none()),
        "viewer payload must not expose secret fingerprints"
    );
}

#[test]
fn staged_reload_planner_rejects_new_require_ready_jwks_when_preflight_fails() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let config_path = dir.path().join("runtime.yaml");
    let current_config = test_config(cert.clone(), key.clone());
    write_config_file(&config_path, &current_config);

    let bundle =
        runtime_bundle_from_config(config_path.to_string_lossy().as_ref(), &current_config);
    let current = RuntimeBundleHandle::new(bundle).current_view();

    let jwks_url = "https://issuer.example.com/reload-require-ready.json?token=secret";
    crate::quic_listener::admission::clear_jwks_cache_for_test(jwks_url);
    crate::quic_listener::admission::script_jwks_fetches_for_test(
        jwks_url,
        vec![Err(
            crate::quic_listener::admission::JwtJwksFetchFailure::request_failed(
                "scripted reload outage".to_string(),
            ),
        )],
    );

    let mut next_config = test_config(cert, key);
    next_config.upstream.get_mut("api").expect("api").auth.jwt = Some(JwtAuth {
        secret: String::new(),
        allowed_algorithms: vec![JwtAlgorithm::Rs256],
        jwks_url: Some(jwks_url.to_string()),
        jwks_request_timeout_ms: 1000,
        jwks_refresh_interval_secs: 60,
        jwks_cache_ttl_secs: 60,
        jwks_stale_if_error_secs: 60,
        jwks_startup_behavior: JwksStartupBehavior::RequireReady,
        issuer: Some("issuer-1".to_string()),
        audience: Some("aud-1".to_string()),
        ..JwtAuth::default()
    });
    write_config_file(&config_path, &next_config);

    let plan = plan_runtime_reload(
        &current,
        planner_request(current.generation()),
        ReloadConfigInput::Path {
            path: config_path.to_string_lossy().to_string(),
        },
    );

    assert!(!plan.can_activate());
    assert_eq!(
        plan.plan.phase_status(PlanningPhase::NormalizeRuntime),
        Some(PlanningPhaseStatus::Rejected)
    );
    assert!(plan.plan.rejected_changes.iter().any(|rejection| {
        rejection.kind == RejectedChangeKind::ResourcePreparationFailed
            && rejection.field_path.as_deref() == Some("runtime jwks preflight")
    }));
    assert!(
        plan.plan
            .rejection_summary
            .as_deref()
            .is_some_and(|summary| summary.contains("runtime jwks preflight"))
    );

    crate::quic_listener::admission::clear_jwks_cache_for_test(jwks_url);
}

#[tokio::test]
async fn control_api_reload_endpoint_denies_viewer() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut startup = test_config(cert, key);
    startup.observability.control_api.enabled = true;
    startup.observability.control_api.auth_token = None;
    startup.observability.control_api.auth.bearer_tokens = vec![ControlApiBearerToken {
        token: "viewer-token".to_string(),
        token_ref: None,
        role: ControlApiRole::Viewer,
        actor_id: Some("viewer".to_string()),
    }];
    let state = control_api_state_with_runtime_bundle(&startup, &startup);

    let mut req = control_api_request(
        Method::POST,
        &state.current_paths().reload_path,
        Some("Bearer viewer-token"),
    );
    let response = QUICListener::gate_control_api_request_for(&mut req, &state)
        .expect_err("viewer should be denied reload");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn control_api_restart_endpoint_denies_operator() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut startup = test_config(cert, key);
    startup.observability.control_api.enabled = true;
    startup.observability.control_api.auth_token = None;
    startup.observability.control_api.auth.bearer_tokens = vec![ControlApiBearerToken {
        token: "operator-token".to_string(),
        token_ref: None,
        role: ControlApiRole::Operator,
        actor_id: Some("operator".to_string()),
    }];
    startup.resilience.watchdog.enabled = true;
    let state = control_api_state_with_runtime_bundle(&startup, &startup);

    let mut req = control_api_request(
        Method::POST,
        &state.current_paths().restart_path,
        Some("Bearer operator-token"),
    );
    let response = QUICListener::gate_control_api_request_for(&mut req, &state)
        .expect_err("operator should be denied restart");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn control_api_restart_endpoint_allows_admin() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut startup = test_config(cert, key);
    startup.observability.control_api.enabled = true;
    startup.observability.control_api.auth_token = None;
    startup.observability.control_api.auth.bearer_tokens = vec![ControlApiBearerToken {
        token: "admin-token".to_string(),
        token_ref: None,
        role: ControlApiRole::Admin,
        actor_id: Some("admin".to_string()),
    }];
    startup.resilience.watchdog.enabled = true;
    let state = control_api_state_with_runtime_bundle(&startup, &startup);

    let mut req = control_api_request(
        Method::POST,
        &state.current_paths().restart_path,
        Some("Bearer admin-token"),
    );
    let route = QUICListener::gate_control_api_request_for(&mut req, &state)
        .expect("admin should be allowed to hit restart route");
    assert_eq!(route, super::admin_auth::ControlApiRoute::Restart);
    let response = QUICListener::handle_control_api_restart(
        &state,
        req.extensions()
            .get::<super::admin_identity::AdminIdentity>()
            .cloned(),
        req.extensions()
            .get::<super::admin_identity::ControlApiRequestContext>()
            .cloned(),
    );
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn control_api_auth_failure_emits_audit_event() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let config_path = dir.path().join("runtime.yaml");
    let audit_path = dir.path().join("admin-audit.jsonl");
    let mut config = test_config(cert, key);
    config.observability.control_api.auth_token = Some("secret-token".to_string());
    let state = audit_enabled_control_api_state(config, &config_path, &audit_path);

    let mut req = control_api_request(
        Method::GET,
        &state.current_paths().runtime_path,
        Some("Bearer wrong-token"),
    );
    let _ = QUICListener::gate_control_api_request_for(&mut req, &state)
        .expect_err("invalid token should be rejected");

    let events = read_audit_events(&audit_path);
    assert!(events.iter().any(|event| {
        event["event_type"] == "auth"
            && event["action"] == "auth"
            && event["result"] == "denied"
            && event["reason"] == "invalid_bearer_token"
    }));
}

#[tokio::test]
async fn control_api_snapshot_read_emits_audit_event() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let config_path = dir.path().join("runtime.yaml");
    let audit_path = dir.path().join("admin-audit.jsonl");
    let mut config = test_config(cert, key);
    config.observability.control_api.auth_token = None;
    config.observability.control_api.auth.bearer_tokens = vec![ControlApiBearerToken {
        token: "viewer-token".to_string(),
        token_ref: None,
        role: ControlApiRole::Viewer,
        actor_id: Some("viewer".to_string()),
    }];
    let state = audit_enabled_control_api_state(config, &config_path, &audit_path);

    let mut req = control_api_request(
        Method::GET,
        &state.current_paths().runtime_path,
        Some("Bearer viewer-token"),
    );
    let route = QUICListener::gate_control_api_request_for(&mut req, &state)
        .expect("viewer should be authorized");
    let service_state = state.current_service_state();
    let response = QUICListener::render_control_api_runtime_snapshot(&state);
    assert_eq!(response.status(), StatusCode::OK);
    QUICListener::emit_control_api_audit_event(
        &service_state.security,
        req.extensions()
            .get::<super::admin_identity::AdminIdentity>(),
        req.extensions()
            .get::<super::admin_identity::ControlApiRequestContext>(),
        super::audit::AdminAuditEventType::RuntimeSnapshot,
        super::audit::AdminAuditAction::RuntimeSnapshotRead,
        QUICListener::control_api_audit_target_for_route(route, None),
        super::audit::AdminAuditGeneration {
            active_generation: service_state
                .generation
                .as_ref()
                .map(|current| current.generation()),
            ..Default::default()
        },
        super::audit::AdminAuditResult::Success,
        None,
    );

    let events = wait_for_audit_event(&audit_path, |event| {
        event["event_type"] == "runtime_snapshot"
            && event["action"] == "runtime_snapshot.read"
            && event["result"] == "success"
    });
    assert!(events.iter().any(|event| {
        event["event_type"] == "runtime_snapshot"
            && event["action"] == "runtime_snapshot.read"
            && event["result"] == "success"
    }));
}

#[tokio::test]
async fn control_api_reload_emits_attempt_and_result_audit_events() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let config_path = dir.path().join("runtime.yaml");
    let audit_path = dir.path().join("admin-audit.jsonl");
    let mut config = test_config(cert, key);
    config.observability.control_api.auth_token = None;
    config.observability.control_api.auth.bearer_tokens = vec![ControlApiBearerToken {
        token: "operator-token".to_string(),
        token_ref: None,
        role: ControlApiRole::Operator,
        actor_id: Some("operator".to_string()),
    }];
    let state = audit_enabled_control_api_state(config, &config_path, &audit_path);

    let _response = QUICListener::handle_control_api_runtime_reload_without_body_for_tests(
        &state,
        Some(super::admin_identity::AdminIdentity {
            actor_id: Some("operator".to_string()),
            authn_mechanisms: vec![super::admin_identity::AdminAuthnMechanism::BearerToken],
            roles: vec![super::admin_identity::AdminRole::Operator],
            peer_addr: None,
            mtls_subject: None,
            mtls_san: Vec::new(),
        }),
        None,
    )
    .await;

    let events = wait_for_audit_event(&audit_path, |event| {
        event["action"] == "runtime_reload.result"
    });
    assert!(
        events
            .iter()
            .any(|event| event["action"] == "runtime_reload.attempt")
    );
    assert!(
        events
            .iter()
            .any(|event| event["action"] == "runtime_reload.result")
    );
}

#[tokio::test]
async fn control_api_restart_emits_attempt_and_result_audit_events() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let config_path = dir.path().join("runtime.yaml");
    let audit_path = dir.path().join("admin-audit.jsonl");
    let mut config = test_config(cert, key);
    config.observability.control_api.auth_token = None;
    config.observability.control_api.auth.bearer_tokens = vec![ControlApiBearerToken {
        token: "admin-token".to_string(),
        token_ref: None,
        role: ControlApiRole::Admin,
        actor_id: Some("admin".to_string()),
    }];
    config.resilience.watchdog.enabled = true;
    let state = audit_enabled_control_api_state(config, &config_path, &audit_path);

    let response = QUICListener::handle_control_api_restart(
        &state,
        Some(super::admin_identity::AdminIdentity {
            actor_id: Some("admin".to_string()),
            authn_mechanisms: vec![super::admin_identity::AdminAuthnMechanism::BearerToken],
            roles: vec![super::admin_identity::AdminRole::Admin],
            peer_addr: None,
            mtls_subject: None,
            mtls_san: Vec::new(),
        }),
        None,
    );
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let events = wait_for_audit_event(&audit_path, |event| {
        event["action"] == "runtime_restart.result"
    });
    assert!(
        events
            .iter()
            .any(|event| event["action"] == "runtime_restart.attempt")
    );
    assert!(
        events
            .iter()
            .any(|event| event["action"] == "runtime_restart.result")
    );
}

#[tokio::test]
async fn control_api_restart_keeps_admin_action_available_when_audit_sink_fails() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let config_path = dir.path().join("runtime.yaml");
    let audit_sink_path = dir.path().join("audit-sink-dir");
    std::fs::create_dir_all(&audit_sink_path).expect("create audit sink dir");

    let mut config = test_config(cert, key);
    config.observability.control_api.auth_token = None;
    config.observability.control_api.auth.bearer_tokens = vec![ControlApiBearerToken {
        token: "admin-token".to_string(),
        token_ref: None,
        role: ControlApiRole::Admin,
        actor_id: Some("admin".to_string()),
    }];
    config.resilience.watchdog.enabled = true;
    let state = audit_enabled_control_api_state(config, &config_path, &audit_sink_path);

    let metrics = state.current_service_state().metrics();
    let response = QUICListener::handle_control_api_restart(
        &state,
        Some(super::admin_identity::AdminIdentity {
            actor_id: Some("admin".to_string()),
            authn_mechanisms: vec![super::admin_identity::AdminAuthnMechanism::BearerToken],
            roles: vec![super::admin_identity::AdminRole::Admin],
            peer_addr: None,
            mtls_subject: None,
            mtls_san: Vec::new(),
        }),
        None,
    );

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let payload = json_body(response).await;
    assert_eq!(payload["accepted"], true);

    for _ in 0..50 {
        if metrics
            .control_api_audit_write_failures
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    assert!(
        metrics
            .control_api_audit_write_failures
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0,
        "audit sink write/open failures must be observable even when admin actions succeed"
    );
}

// Domain: runtime snapshot rendering and live runtime-view selection.
#[test]
fn control_api_state_prefers_reloaded_paths_and_auth_token() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut startup = test_config(cert.clone(), key.clone());
    startup.observability.control_api.enabled = true;
    startup.observability.control_api.health_path = "/health-old".to_string();
    startup.observability.control_api.runtime_path = "/runtime-old".to_string();
    startup.observability.control_api.auth_token = Some("old-token".to_string());

    let mut reloaded = startup.clone();
    reloaded.observability.control_api.health_path = "/health-new".to_string();
    reloaded.observability.control_api.runtime_path = "/runtime-new".to_string();
    reloaded.observability.control_api.auth_token = Some("new-token".to_string());

    let state = control_api_state_with_runtime_bundle(&startup, &reloaded);
    let paths = state.current_paths();

    assert_eq!(paths.health_path, "/health-new");
    assert_eq!(paths.runtime_path, "/runtime-new");
    assert_eq!(
        state.current_control_api().auth_token.as_deref(),
        Some("new-token")
    );
    assert_eq!(
        state.current_security_policy().bearer_tokens[0].token,
        "new-token"
    );
    assert_eq!(
        state.current_security_policy().bearer_tokens[0].role,
        ControlApiRole::Admin
    );
    assert_eq!(
        state.current_security_policy().bearer_tokens[0]
            .actor_id
            .as_deref(),
        Some("legacy_auth_token")
    );
    assert_eq!(
        state.current_security_policy().bearer_tokens[0].source,
        super::security::ControlApiBearerTokenSource::LegacyAuthToken
    );
}

#[test]
fn control_api_state_builds_runtime_security_policy_from_reloaded_config() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut startup = test_config(cert.clone(), key.clone());
    startup.observability.control_api.enabled = true;
    startup.observability.control_api.auth_token = Some("startup-token".to_string());

    let mut reloaded = startup.clone();
    reloaded.observability.control_api.auth_token = None;
    reloaded.observability.control_api.tls.client_auth.mode = ControlApiClientAuthMode::Required;
    reloaded.observability.control_api.tls.client_auth.ca_file = Some(cert.clone());
    reloaded.observability.control_api.auth.bearer_tokens = vec![ControlApiBearerToken {
        token: "operator-token".to_string(),
        token_ref: None,
        role: ControlApiRole::Operator,
        actor_id: Some("ops".to_string()),
    }];
    reloaded.observability.control_api.ip_allowlist.cidrs =
        vec!["127.0.0.0/8".to_string(), "::1/128".to_string()];
    reloaded.observability.control_api.audit.enabled = true;
    reloaded.observability.control_api.audit.sink = ControlApiAuditSink::File;
    reloaded.observability.control_api.audit.file_path =
        Some("/var/log/impulse-admin-audit.jsonl".to_string());

    let state = control_api_state_with_runtime_bundle(&startup, &reloaded);
    let security = state.current_security_policy();

    assert_eq!(
        security.client_auth.mode,
        ControlApiClientAuthMode::Required
    );
    assert_eq!(
        security.client_auth.verifier,
        super::security::ControlApiClientVerifierState::Configured(
            super::security::ControlApiClientCaMaterial {
                ca_file: Some(cert),
                ca_dir: None,
            }
        )
    );
    assert_eq!(security.bearer_tokens.len(), 1);
    assert_eq!(security.bearer_tokens[0].token, "operator-token");
    assert_eq!(security.bearer_tokens[0].role, ControlApiRole::Operator);
    assert!(
        security
            .ip_allowlist
            .allows("127.0.0.1".parse().expect("ipv4"))
    );
    assert!(security.ip_allowlist.allows("::1".parse().expect("ipv6")));
    assert!(
        !security
            .ip_allowlist
            .allows("10.0.0.1".parse().expect("non-matching ipv4"))
    );
    assert!(security.audit.enabled);
    assert_eq!(
        security.audit.sink,
        super::audit::ControlApiAdminAuditTarget::File(Some(
            "/var/log/impulse-admin-audit.jsonl".to_string()
        ))
    );
}

#[test]
fn control_api_tls_builder_supports_disabled_optional_and_required_client_auth() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut config = test_config(cert.clone(), key.clone());
    config.observability.control_api.enabled = true;
    let runtime_config = RuntimeConfig::from_config(&config).expect("runtime config");
    let listener_config = runtime_config
        .primary_listener_runtime_config()
        .expect("primary listener runtime config");

    let disabled = super::security::ControlApiClientAuthPolicy {
        mode: ControlApiClientAuthMode::Disabled,
        verifier: super::security::ControlApiClientVerifierState::Disabled,
    };
    assert!(QUICListener::build_control_api_server_tls_config(&listener_config, &disabled).is_ok());

    let optional = super::security::ControlApiClientAuthPolicy {
        mode: ControlApiClientAuthMode::Optional,
        verifier: super::security::ControlApiClientVerifierState::Configured(
            super::security::ControlApiClientCaMaterial {
                ca_file: Some(cert.clone()),
                ca_dir: None,
            },
        ),
    };
    assert!(QUICListener::build_control_api_server_tls_config(&listener_config, &optional).is_ok());

    let required = super::security::ControlApiClientAuthPolicy {
        mode: ControlApiClientAuthMode::Required,
        verifier: super::security::ControlApiClientVerifierState::Configured(
            super::security::ControlApiClientCaMaterial {
                ca_file: Some(cert),
                ca_dir: None,
            },
        ),
    };
    assert!(QUICListener::build_control_api_server_tls_config(&listener_config, &required).is_ok());
}

#[test]
fn control_api_state_uses_live_primary_listener_label_after_runtime_swap() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let startup = test_config(cert.clone(), key.clone());

    let mut reloaded = startup.clone();
    reloaded.listeners = vec![
        Listen {
            protocol: "http3".to_string(),
            port: 9890,
            address: "127.0.0.1".to_string(),
            tls: Tls {
                cert: cert.clone(),
                key: key.clone(),
                certificates: vec![],
                client_auth: ClientAuth::default(),
            },
        },
        startup.listen.clone(),
    ];

    let state = control_api_state_with_runtime_bundle(&startup, &reloaded);

    assert_eq!(
        state.current_primary_listener_label().as_deref(),
        Some("127.0.0.1:9890")
    );
}

#[tokio::test]
async fn control_api_runtime_snapshot_uses_live_primary_listener_label_after_bundle_replace() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut startup = test_config(cert.clone(), key.clone());
    startup.observability.control_api.enabled = true;

    let startup_bundle = runtime_bundle_from_config("startup.yaml", &startup);
    let (state, runtime_handle) = runtime_bundle_control_api_state(startup_bundle);

    let startup_payload =
        json_body(QUICListener::render_control_api_runtime_snapshot(&state)).await;
    let startup_listeners = startup_payload["tls"]["listeners"]
        .as_object()
        .expect("startup listeners object");
    assert!(
        startup_listeners.contains_key("127.0.0.1:9889"),
        "startup snapshot should expose the startup primary listener label"
    );

    let mut reloaded = startup.clone();
    reloaded.listeners = vec![
        Listen {
            protocol: "http3".to_string(),
            port: 9890,
            address: "127.0.0.1".to_string(),
            tls: Tls {
                cert: cert.clone(),
                key: key.clone(),
                certificates: vec![],
                client_auth: ClientAuth::default(),
            },
        },
        startup.listen.clone(),
    ];

    let mut reloaded_bundle = runtime_bundle_from_config("reloaded.yaml", &reloaded);
    reloaded_bundle.generation = 1;
    runtime_handle
        .replace(reloaded_bundle)
        .expect("replace runtime bundle");

    assert_eq!(
        state.current_primary_listener_label().as_deref(),
        Some("127.0.0.1:9890"),
        "control api state must prefer the live generation's primary listener label"
    );

    let live_payload = json_body(QUICListener::render_control_api_runtime_snapshot(&state)).await;
    let live_listeners = live_payload["tls"]["listeners"]
        .as_object()
        .expect("live listeners object");

    assert_eq!(live_payload["runtime"]["generation"], 1);
    assert!(
        live_listeners.contains_key("127.0.0.1:9890"),
        "runtime snapshot must render the live generation's primary listener label after bundle replacement"
    );
    assert!(
        live_listeners.contains_key("127.0.0.1:9889"),
        "runtime snapshot should keep the remaining listener inventory from the live generation"
    );
}

#[test]
fn control_api_state_sees_the_active_runtime_generation_after_bundle_replace() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut startup = test_config(cert.clone(), key.clone());
    startup.observability.control_api.enabled = true;
    startup.observability.control_api.runtime_path = "/runtime-startup".to_string();

    let startup_bundle = runtime_bundle_from_config("startup.yaml", &startup);
    let (state, runtime_handle) = runtime_bundle_control_api_state(startup_bundle);

    let current = state.current_generation().expect("current generation");
    assert_eq!(current.generation(), 0);
    assert_eq!(
        state.current_paths().runtime_path,
        "/runtime-startup".to_string()
    );

    let mut reloaded = startup.clone();
    reloaded.observability.control_api.runtime_path = "/runtime-reloaded".to_string();
    reloaded.observability.metrics.path = "/metrics-reloaded".to_string();

    let mut reloaded_bundle = runtime_bundle_from_config("reloaded.yaml", &reloaded);
    reloaded_bundle.generation = 1;
    runtime_handle
        .replace(reloaded_bundle)
        .expect("replace runtime bundle");

    let current = state.current_generation().expect("reloaded generation");
    assert_eq!(current.generation(), 1);
    assert_eq!(
        current.runtime_config().observability.metrics.path,
        "/metrics-reloaded"
    );
    assert_eq!(
        state.current_paths().runtime_path,
        "/runtime-reloaded".to_string()
    );
}

#[test]
fn control_api_gating_uses_live_generation_paths_and_auth_after_bundle_replace() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut startup = test_config(cert.clone(), key.clone());
    startup.observability.control_api.enabled = true;
    startup.observability.control_api.runtime_path = "/runtime-startup".to_string();
    startup.observability.control_api.auth_token = Some("startup-token".to_string());

    let startup_bundle = runtime_bundle_from_config("startup.yaml", &startup);
    let (state, runtime_handle) = runtime_bundle_control_api_state(startup_bundle);

    let mut reloaded = startup.clone();
    reloaded.observability.control_api.runtime_path = "/runtime-reloaded".to_string();
    reloaded.observability.control_api.auth_token = Some("reloaded-token".to_string());
    let mut reloaded_bundle = runtime_bundle_from_config("reloaded.yaml", &reloaded);
    reloaded_bundle.generation = 1;
    runtime_handle
        .replace(reloaded_bundle)
        .expect("replace runtime bundle");

    let mut startup_path = control_api_request(
        Method::GET,
        "/runtime-startup",
        Some("Bearer startup-token"),
    );
    let startup_err = QUICListener::gate_control_api_request_for(&mut startup_path, &state)
        .expect_err("stale runtime path should be rejected after replacement");
    assert_eq!(startup_err.status(), StatusCode::NOT_FOUND);

    let mut stale_token = control_api_request(
        Method::GET,
        "/runtime-reloaded",
        Some("Bearer startup-token"),
    );
    let stale_token_err = QUICListener::gate_control_api_request_for(&mut stale_token, &state)
        .expect_err("stale token should be rejected after replacement");
    assert_eq!(stale_token_err.status(), StatusCode::UNAUTHORIZED);

    let mut live = control_api_request(
        Method::GET,
        "/runtime-reloaded",
        Some("Bearer reloaded-token"),
    );
    let route = QUICListener::gate_control_api_request_for(&mut live, &state)
        .expect("live control api path and auth should be accepted");
    assert!(matches!(route, super::admin_auth::ControlApiRoute::Runtime));
}

#[test]
fn control_api_backend_inventory_and_summary_share_one_canonical_snapshot_contract() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let config = test_config(cert, key);
    let bundle = runtime_bundle_from_config("runtime.yaml", &config);
    let (state, _) = runtime_bundle_control_api_state(bundle);

    let service_state = state.current_service_state();
    let inventory = service_state.snapshot_backend_inventory();
    let summary = service_state.snapshot_backend_health();

    assert_eq!(summary, inventory.summary());
    assert_eq!(inventory.backends.len(), 1);

    let backend = &inventory.backends[0];
    assert_eq!(backend.identity.backend_addr, "http://127.0.0.1:7001");
    assert_eq!(backend.resolution.authority_host, "127.0.0.1");
    assert_eq!(backend.resolution.authority_port, 7001);
    assert_eq!(backend.resolution.refresh_generation, 0);
    assert_eq!(
        backend.membership,
        crate::runtime::backend::state::BackendMembershipState::Active
    );
    assert!(matches!(
        backend.health,
        crate::runtime::backend::state::BackendHealthState::Healthy
    ));
    assert_eq!(backend.placements.len(), 1);
    assert_eq!(backend.placements[0].upstream_name, "api");
    assert!(backend.placements[0].healthy);
    assert_eq!(summary.total_backends, 1);
    assert_eq!(summary.healthy_backends, 1);
}

#[tokio::test]
async fn control_api_runtime_history_renders_recorded_generation_changes() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let config_path = dir.path().join("runtime.yaml");
    let current_config = test_config(cert.clone(), key.clone());
    write_config_file(&config_path, &current_config);

    let bundle =
        runtime_bundle_from_config(config_path.to_string_lossy().as_ref(), &current_config);
    let (state, runtime_handle) = runtime_bundle_control_api_state(bundle);

    let mut next_config = test_config(cert, key);
    next_config.log.level = "debug".to_string();
    write_config_file(&config_path, &next_config);

    let activation = RuntimeActivationService::activate_reload(
        runtime_handle.as_ref(),
        planner_request(runtime_handle.current_generation()),
        ReloadConfigInput::Path {
            path: config_path.to_string_lossy().to_string(),
        },
    );
    assert!(activation.succeeded());
    runtime_handle.record_failed_prepare(9, "candidate generation never prepared");

    let payload = json_body(QUICListener::render_control_api_runtime_history(&state)).await;
    assert_eq!(payload["active_generation"], 1);
    assert_eq!(payload["observability"]["contract_version"], "v1");
    assert_eq!(payload["observability"]["audit_schema_version"], "v1");
    assert_eq!(payload["observability"]["current_generation"], 1);
    assert_eq!(
        payload["retained_generations"].as_array().map(Vec::len),
        Some(3)
    );
    assert_eq!(payload["retained_generations"][0]["generation"], 1);
    assert_eq!(payload["retained_generations"][0]["status"], "active");
    assert_eq!(
        payload["retained_generations"][0]["rollback_candidate"],
        false
    );
    assert_eq!(payload["retained_generations"][0]["has_bundle"], true);
    assert_eq!(payload["retained_generations"][1]["generation"], 9);
    assert_eq!(
        payload["retained_generations"][1]["status"],
        "failed_prepare"
    );
    assert_eq!(
        payload["retained_generations"][1]["rollback_candidate"],
        false
    );
    assert_eq!(payload["retained_generations"][1]["has_bundle"], false);
    assert_eq!(
        payload["retained_generations"][1]["note"],
        "candidate generation never prepared"
    );
    assert_eq!(payload["retained_generations"][2]["generation"], 0);
    assert_eq!(payload["retained_generations"][2]["status"], "previous");
    assert_eq!(
        payload["retained_generations"][2]["rollback_candidate"],
        true
    );
    assert_eq!(payload["retained_generations"][2]["has_bundle"], true);
    assert_eq!(payload["entries"].as_array().map(Vec::len), Some(1));
    assert_eq!(payload["entries"][0]["operation"], "activate");
    assert_eq!(
        payload["observability"]["recent_admin_actions"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(
        payload["observability"]["recent_admin_actions"][0]["kind"],
        "activation_succeeded"
    );
    assert_eq!(
        payload["observability"]["recent_admin_actions"][0]["operation"],
        "activate"
    );
    assert_eq!(
        payload["observability"]["recent_admin_actions"][0]["requested_by"],
        "test"
    );
}

#[tokio::test]
async fn control_api_runtime_history_observability_view_stays_stable_without_admin_actions() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let config_path = dir.path().join("runtime.yaml");
    let mut config = test_config(cert, key);
    config.observability.control_api.enabled = true;
    write_config_file(&config_path, &config);

    let bundle = runtime_bundle_from_config(config_path.to_string_lossy().as_ref(), &config);
    let (state, _) = runtime_bundle_control_api_state(bundle);

    let payload = json_body(QUICListener::render_control_api_runtime_history(&state)).await;

    assert_eq!(
        payload["observability"],
        serde_json::json!({
            "contract_version": "v1",
            "audit_schema_version": "v1",
            "audit_sink": {
                "enabled": false,
                "target": "log",
                "degraded": false
            },
            "current_generation": 0,
            "dashboard_packages": [
                {
                    "dashboard_id": "edge_traffic",
                    "definition_path": "deploy/observability/grafana/edge-traffic.json",
                    "focus": "edge traffic, status mix, and latency"
                },
                {
                    "dashboard_id": "admission_overload",
                    "definition_path": "deploy/observability/grafana/admission-overload.json",
                    "focus": "admission, overload, quota, and auth outcomes"
                },
                {
                    "dashboard_id": "backend_health",
                    "definition_path": "deploy/observability/grafana/backend-health.json",
                    "focus": "backend health, dns refresh, and client rotations"
                },
                {
                    "dashboard_id": "retries_hedges",
                    "definition_path": "deploy/observability/grafana/retries-hedges.json",
                    "focus": "retry amplification and hedge effectiveness"
                },
                {
                    "dashboard_id": "tls_certificates",
                    "definition_path": "deploy/observability/grafana/tls-certificates.json",
                    "focus": "tls handshake failures and certificate expiry"
                },
                {
                    "dashboard_id": "control_plane",
                    "definition_path": "deploy/observability/grafana/control-plane.json",
                    "focus": "runtime activity, watchdog state, and control-plane health"
                }
            ],
            "backend_health_summary": {
                "availability": "healthy",
                "placed_total": 1,
                "healthy": 1,
                "unhealthy": 0,
                "unknown": 0,
                "active_membership": 1,
                "suppressed_membership": 0,
                "removed_membership": 0
            },
            "quota_backend_health_summary": {
                "enabled": false,
                "active_backend": "in_memory",
                "availability": "disabled",
                "degraded": false,
                "recent_error_count": 0
            },
            "recent_admin_actions": []
        })
    );
}

#[tokio::test]
async fn control_api_runtime_history_generation_filters_to_requested_generation() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let config_path = dir.path().join("runtime.yaml");
    let current_config = test_config(cert.clone(), key.clone());
    write_config_file(&config_path, &current_config);

    let bundle =
        runtime_bundle_from_config(config_path.to_string_lossy().as_ref(), &current_config);
    let (state, runtime_handle) = runtime_bundle_control_api_state(bundle);

    let mut next_config = test_config(cert, key);
    next_config.log.level = "debug".to_string();
    write_config_file(&config_path, &next_config);

    let activation = RuntimeActivationService::activate_reload(
        runtime_handle.as_ref(),
        planner_request(runtime_handle.current_generation()),
        ReloadConfigInput::Path {
            path: config_path.to_string_lossy().to_string(),
        },
    );
    assert!(activation.succeeded());

    let payload = json_body(QUICListener::render_control_api_runtime_history_generation(
        &state, 1,
    ))
    .await;
    assert_eq!(payload["generation"], 1);
    assert_eq!(payload["retained_generation"]["generation"], 1);
    assert_eq!(payload["retained_generation"]["status"], "active");
    assert_eq!(payload["retained_generation"]["rollback_candidate"], false);
    assert_eq!(payload["retained_generation"]["has_bundle"], true);
    assert_eq!(payload["entries"].as_array().map(Vec::len), Some(1));

    let missing = QUICListener::render_control_api_runtime_history_generation(&state, 99);
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn control_api_runtime_snapshot_renders_live_generation_listener_and_backend_contract() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut startup = test_config(cert.clone(), key.clone());
    startup.observability.control_api.enabled = true;

    let startup_bundle = runtime_bundle_from_config("startup.yaml", &startup);
    let (state, runtime_handle) = runtime_bundle_control_api_state(startup_bundle);

    let mut reloaded = startup.clone();
    reloaded.listeners = vec![
        Listen {
            protocol: "http3".to_string(),
            port: 9890,
            address: "127.0.0.1".to_string(),
            tls: Tls {
                cert: cert.clone(),
                key: key.clone(),
                certificates: vec![],
                client_auth: ClientAuth {
                    enabled: true,
                    ca_file: Some(cert.clone()),
                    require_client_cert: true,
                },
            },
        },
        startup.listen.clone(),
    ];
    reloaded.observability.metrics.path = "/metrics-live".to_string();

    let mut reloaded_bundle = runtime_bundle_from_config("reloaded.yaml", &reloaded);
    reloaded_bundle.generation = 1;
    runtime_handle
        .replace(reloaded_bundle)
        .expect("replace runtime bundle");

    let live = runtime_handle.current_view();
    live.shared_services()
        .metrics
        .requests_total
        .store(11, std::sync::atomic::Ordering::Relaxed);
    live.shared_services()
        .metrics
        .requests_success
        .store(7, std::sync::atomic::Ordering::Relaxed);
    live.shared_services()
        .metrics
        .requests_failure
        .store(4, std::sync::atomic::Ordering::Relaxed);
    live.shared_services()
        .metrics
        .active_connections
        .store(3, std::sync::atomic::Ordering::Relaxed);

    let payload = json_body(QUICListener::render_control_api_runtime_snapshot(&state)).await;

    assert_eq!(payload["runtime"]["generation"], 1);
    assert_eq!(payload["runtime"]["config_path"], "reloaded.yaml");
    assert_eq!(payload["metrics"]["requests_total"], 11);
    assert_eq!(payload["metrics"]["requests_success"], 7);
    assert_eq!(payload["metrics"]["requests_failure"], 4);
    assert_eq!(payload["metrics"]["active_connections"], 3);

    let listeners = payload["tls"]["listeners"]
        .as_object()
        .expect("listeners object");
    assert!(
        listeners.contains_key("127.0.0.1:9890"),
        "runtime snapshot should render listener inventory from the active generation"
    );
    assert!(
        listeners.contains_key("127.0.0.1:9889"),
        "runtime snapshot should keep the secondary listener visible"
    );
    assert_eq!(
        listeners["127.0.0.1:9890"]["client_auth_enabled"],
        serde_json::Value::Bool(true)
    );
    assert_eq!(
        listeners["127.0.0.1:9890"]["require_client_cert"],
        serde_json::Value::Bool(true)
    );

    assert_eq!(payload["backends"]["healthy"], 1);
    assert_eq!(payload["backends"]["total"], 1);
    let lifecycle = payload["backends"]["lifecycle"]
        .as_array()
        .expect("backend lifecycle array");
    assert_eq!(lifecycle.len(), 1);
    let backend = &lifecycle[0];
    assert_eq!(backend["backend"], "http://127.0.0.1:7001");
    assert_eq!(backend["health"], "healthy");
    assert_eq!(backend["membership"], "active");
    assert_eq!(backend["authority_host"], "127.0.0.1");
    assert_eq!(backend["authority_port"], 7001);
    assert_eq!(backend["resolution_generation"], 0);
    assert!(
        backend.get("health_reason").is_none(),
        "healthy rendered backends must omit optional health_reason"
    );
    assert_eq!(
        backend["placements"]
            .as_array()
            .expect("placement array")
            .len(),
        1
    );
}

#[tokio::test]
async fn control_api_runtime_snapshot_exposes_quota_policy_and_backend_status() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut config = test_config(cert, key);
    config.observability.control_api.enabled = true;
    config.resilience.quota.enabled = true;
    config.resilience.quota.enforcement = QuotaEnforcementMode::Shadow;
    config.resilience.quota.backend_failure_policy = QuotaBackendFailurePolicy::FailOpen;
    config.resilience.quota.backend = QuotaCounterBackend::Redis {
        url: "://bad-redis-url".to_string(),
        key_prefix: "impulse:test:quota".to_string(),
        connect_timeout_ms: 250,
        command_timeout_ms: 100,
        max_inflight: 8,
    };
    config.resilience.quota.policies = vec![DistributedQuotaPolicy {
        name: "tenant-contract".to_string(),
        route_allowlist: vec!["api".to_string()],
        selector: DistributedQuotaSelector {
            route: true,
            tenant: Some(DistributedQuotaSelectorSource {
                key: "header:x-tenant-id".to_string(),
            }),
            token: Some(DistributedQuotaSelectorSource {
                key: "bearer_token".to_string(),
            }),
            client: None,
        },
        burst: Some(DistributedQuotaWindow {
            requests: 50,
            window_secs: 1,
        }),
        sustained: Some(DistributedQuotaWindow {
            requests: 500,
            window_secs: 60,
        }),
    }];

    let bundle = runtime_bundle_from_config("runtime.yaml", &config);
    let (state, _) = runtime_bundle_control_api_state(bundle);

    let payload = json_body(QUICListener::render_control_api_runtime_snapshot(&state)).await;

    assert_eq!(payload["quota"]["enabled"], true);
    assert_eq!(payload["quota"]["enforcement"], "shadow");
    assert_eq!(payload["quota"]["backend_failure_policy"], "fail_open");
    assert_eq!(payload["quota"]["active_backend"], "redis");
    assert_eq!(
        payload["quota"]["backend_status"]["availability"],
        "degraded"
    );
    assert_eq!(payload["quota"]["backend_status"]["degraded"], true);
    assert_eq!(payload["quota"]["backend_status"]["health_reason"], "error");

    let recent_errors = payload["quota"]["backend_status"]["recent_errors"]
        .as_array()
        .expect("quota recent errors");
    assert_eq!(recent_errors.len(), 1);
    assert_eq!(recent_errors[0]["reason"], "backend_error");
    assert!(
        recent_errors[0]["detail"]
            .as_str()
            .map(|value| !value.is_empty())
            .unwrap_or(false),
        "quota backend initialization failure should surface a readable recent error"
    );

    let policies = payload["quota"]["policies"]
        .as_array()
        .expect("quota policies");
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0]["name"], "tenant-contract");
    assert_eq!(policies[0]["route_allowlist"][0], "api");
    assert_eq!(policies[0]["selector"]["route"], true);
    assert_eq!(policies[0]["selector"]["tenant"], "header:x-tenant-id");
    assert_eq!(policies[0]["selector"]["token"], "bearer_token");
    assert_eq!(policies[0]["burst"]["requests"], 50);
    assert_eq!(policies[0]["burst"]["window_secs"], 1);
    assert_eq!(policies[0]["sustained"]["requests"], 500);
    assert_eq!(policies[0]["sustained"]["window_secs"], 60);
    assert_eq!(
        payload["observability"],
        serde_json::json!({
            "contract_version": "v1",
            "audit_schema_version": "v1",
            "audit_sink": {
                "enabled": false,
                "target": "log",
                "degraded": false
            },
            "current_generation": 0,
            "dashboard_packages": [
                {
                    "dashboard_id": "edge_traffic",
                    "definition_path": "deploy/observability/grafana/edge-traffic.json",
                    "focus": "edge traffic, status mix, and latency"
                },
                {
                    "dashboard_id": "admission_overload",
                    "definition_path": "deploy/observability/grafana/admission-overload.json",
                    "focus": "admission, overload, quota, and auth outcomes"
                },
                {
                    "dashboard_id": "backend_health",
                    "definition_path": "deploy/observability/grafana/backend-health.json",
                    "focus": "backend health, dns refresh, and client rotations"
                },
                {
                    "dashboard_id": "retries_hedges",
                    "definition_path": "deploy/observability/grafana/retries-hedges.json",
                    "focus": "retry amplification and hedge effectiveness"
                },
                {
                    "dashboard_id": "tls_certificates",
                    "definition_path": "deploy/observability/grafana/tls-certificates.json",
                    "focus": "tls handshake failures and certificate expiry"
                },
                {
                    "dashboard_id": "control_plane",
                    "definition_path": "deploy/observability/grafana/control-plane.json",
                    "focus": "runtime activity, watchdog state, and control-plane health"
                }
            ],
            "backend_health_summary": {
                "availability": "healthy",
                "placed_total": 1,
                "healthy": 1,
                "unhealthy": 0,
                "unknown": 0,
                "active_membership": 1,
                "suppressed_membership": 0,
                "removed_membership": 0
            },
            "quota_backend_health_summary": {
                "enabled": true,
                "active_backend": "redis",
                "availability": "degraded",
                "degraded": true,
                "health_reason": "error",
                "recent_error_count": 1
            },
            "recent_admin_actions": []
        })
    );
}

#[tokio::test]
async fn control_api_runtime_snapshot_surfaces_degraded_file_audit_sink() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let audit_path = dir.path().join("admin-audit.jsonl");
    let mut config = test_config(cert, key);
    config.observability.control_api.enabled = true;
    config.observability.control_api.audit.enabled = true;
    config.observability.control_api.audit.sink = ControlApiAuditSink::File;
    config.observability.control_api.audit.file_path =
        Some(audit_path.to_string_lossy().to_string());

    super::audit::force_audit_writer_thread_spawn_failure_for_test(true);
    let state = control_api_state_with_runtime_bundle(&config, &config);
    let payload = json_body(QUICListener::render_control_api_runtime_snapshot(&state)).await;
    super::audit::force_audit_writer_thread_spawn_failure_for_test(false);
    assert_eq!(payload["observability"]["audit_sink"]["enabled"], true);
    assert_eq!(payload["observability"]["audit_sink"]["target"], "file");
    assert_eq!(payload["observability"]["audit_sink"]["degraded"], true);
    assert_eq!(
        payload["observability"]["audit_sink"]["reason"],
        "writer_thread_start_failed"
    );
}

#[tokio::test]
async fn control_api_runtime_snapshot_renders_composite_quota_selector_dimensions() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut config = test_config(cert, key);
    config.observability.control_api.enabled = true;
    config.resilience.quota.enabled = true;
    config.resilience.quota.backend = QuotaCounterBackend::InMemory {
        key_prefix: "impulse:test:quota".to_string(),
    };
    config.resilience.quota.policies = vec![DistributedQuotaPolicy {
        name: "tenant-client-contract".to_string(),
        route_allowlist: vec!["api".to_string()],
        selector: DistributedQuotaSelector {
            route: true,
            tenant: Some(DistributedQuotaSelectorSource {
                key: "header:x-tenant-id".to_string(),
            }),
            token: None,
            client: Some(DistributedQuotaSelectorSource {
                key: "client_ip".to_string(),
            }),
        },
        burst: Some(DistributedQuotaWindow {
            requests: 25,
            window_secs: 1,
        }),
        sustained: Some(DistributedQuotaWindow {
            requests: 250,
            window_secs: 60,
        }),
    }];

    let bundle = runtime_bundle_from_config("runtime.yaml", &config);
    let (state, _) = runtime_bundle_control_api_state(bundle);
    let payload = json_body(QUICListener::render_control_api_runtime_snapshot(&state)).await;

    assert_eq!(payload["quota"]["enabled"], true);
    assert_eq!(payload["quota"]["active_backend"], "in_memory");
    let policies = payload["quota"]["policies"]
        .as_array()
        .expect("quota policies");
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0]["name"], "tenant-client-contract");
    assert_eq!(policies[0]["selector"]["route"], true);
    assert_eq!(policies[0]["selector"]["tenant"], "header:x-tenant-id");
    assert_eq!(policies[0]["selector"]["client"], "client_ip");
    assert!(policies[0]["selector"]["token"].is_null());
    assert_eq!(policies[0]["burst"]["requests"], 25);
    assert_eq!(policies[0]["sustained"]["requests"], 250);
}

// Domain: watchdog/runtime ownership alignment across reload boundaries.
#[test]
fn reload_preserves_process_scoped_watchdog_and_dns_resolver() {
    // Regression: process-shared services must be carried across a reload, not
    // rebuilt. Rebuilding the watchdog silently discards an in-flight
    // restart/drain; rebuilding the DNS resolver drops its cache.
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut config = test_config(cert, key);
    // Enable the watchdog so request_restart takes effect.
    config.resilience.watchdog.enabled = true;
    let runtime_config = RuntimeConfig::from_config(&config).expect("runtime config");

    let current = QUICListener::build_shared_state(&runtime_config).expect("current shared state");

    // Simulate an in-flight watchdog restart on the active generation.
    assert!(
        current.shared_services().watchdog.request_restart("test"),
        "watchdog restart should be accepted when enabled"
    );
    assert!(current.shared_services().watchdog.restart_requested());

    // Reload: carry the process-scoped services forward.
    let carried = crate::runtime::generation::CarriedProcessSharedServices::from_active(
        current.shared_services(),
    );
    let next = QUICListener::build_shared_state_with_carried(&runtime_config, Some(carried))
        .expect("reloaded shared state");

    // Same watchdog instance, and its in-flight restart survived the swap.
    assert!(
        Arc::ptr_eq(
            &current.shared_services().watchdog,
            &next.shared_services().watchdog
        ),
        "watchdog must be the same instance across a reload"
    );
    assert!(
        next.shared_services().watchdog.restart_requested(),
        "in-flight watchdog restart must survive a reload"
    );

    // The carried services expose the same DNS resolver handle, so its cache is
    // preserved rather than rebuilt cold on every reload.
    let carried_again = crate::runtime::generation::CarriedProcessSharedServices::from_active(
        current.shared_services(),
    );
    let seeded = carried_again
        .backend_dns_resolver
        .cached_addrs("never-resolved.example");
    assert_eq!(
        seeded,
        next.shared_services()
            .backend_dns_resolver
            .cached_addrs("never-resolved.example"),
        "carried DNS resolver must be the same cache view as the reloaded generation"
    );
}

// Domain: reload compatibility classification and lifecycle gatekeeping.
#[test]
fn live_reloadable_upstream_change_is_accepted() {
    // Phase 9 (#1): a generation-owned change (upstream/route table) must pass
    // reload compatibility — it is live-reloadable, not restart-required.
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let current = test_config(cert, key);

    let mut next = current.clone();
    next.upstream
        .get_mut("api")
        .expect("api upstream")
        .backends
        .push(Backend {
            id: "b2".to_string(),
            address: "http://127.0.0.1:7002".to_string(),
            weight: 1,
            health_check: None,
        });

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);
    let current_active = RuntimeBundleHandle::new(current_bundle).current_view();

    let result = QUICListener::evaluate_runtime_reload_compatibility(&current_active, &next_bundle);
    assert!(
        result.is_ok(),
        "generation-owned upstream change must be live-reloadable, got: {result:?}"
    );
}

#[test]
fn reload_compatibility_classifies_generation_owned_changes_as_live_reloadable() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let current = test_config(cert, key);

    let mut next = current.clone();
    next.upstream
        .get_mut("api")
        .expect("api upstream")
        .route
        .path_prefix = Some("/live".to_string());

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);
    let active = RuntimeBundleHandle::new(current_bundle).current_view();

    assert!(
        QUICListener::evaluate_runtime_reload_compatibility(&active, &next_bundle).is_ok(),
        "generation-owned routing changes should stay reloadable"
    );
}

#[test]
fn restart_required_change_rejects_before_touching_active_generation() {
    // Phase 9 (#4): a failed validation must leave the active generation unchanged.
    // A restart-required change (control_plane_threads) is rejected by the
    // compatibility evaluation, which runs entirely on the candidate bundle and
    // never mutates the live handle.
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let current = test_config(cert, key);

    let mut next = current.clone();
    next.performance.control_plane_threads = current.performance.control_plane_threads + 3;

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);

    let handle = RuntimeBundleHandle::new(current_bundle);
    let generation_before = handle.current_generation();
    let active = handle.current_view();

    let result = QUICListener::evaluate_runtime_reload_compatibility(&active, &next_bundle);
    let rejections = result.expect_err("restart-required change must be rejected");
    assert!(
        rejections.iter().any(
            |r| r.to_string().contains("performance.control_plane_threads") && r.requires_restart()
        ),
        "expected a restart-required rejection, got: {rejections:?}"
    );
    // The active generation is untouched by the rejected evaluation.
    assert_eq!(handle.current_generation(), generation_before);
}

#[test]
fn reload_compatibility_classifies_startup_owned_changes_as_restart_required() {
    use crate::runtime::policy::TransitionRejectionKind;

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let current = test_config(cert, key);

    let mut next = current.clone();
    let current_threads = current.performance.control_plane_threads;
    let next_threads = current_threads.saturating_add(2);
    next.performance.control_plane_threads = next_threads;

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);
    let active = RuntimeBundleHandle::new(current_bundle).current_view();

    let rejections = QUICListener::evaluate_runtime_reload_compatibility(&active, &next_bundle)
        .expect_err("startup-owned change must reject the reload");
    assert_eq!(rejections.len(), 1);
    let rejection = &rejections[0];
    assert_eq!(rejection.kind, TransitionRejectionKind::RestartRequired);
    assert!(rejection.requires_restart());
    assert_eq!(
        rejection.field_path.as_deref(),
        Some("performance.control_plane_threads")
    );
    assert_eq!(
        rejection.to_string(),
        format!(
            "runtime reload rejected: performance.control_plane_threads changed from {current_threads} to {next_threads}; restart required"
        )
    );
}

#[test]
fn accepted_reload_advances_the_active_generation() {
    // Phase 9 (#1/#4 positive path): a valid reload committed through the handle
    // advances the active generation atomically.
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let current = test_config(cert, key);
    let next = current.clone();

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let mut next_bundle = runtime_bundle_from_config("next.yaml", &next);
    next_bundle.generation = current_bundle.generation + 1;

    let handle = RuntimeBundleHandle::new(current_bundle);
    let before = handle.current_generation();

    let committed = handle.replace(next_bundle).expect("valid reload commits");
    assert_eq!(committed, before + 1);
    assert_eq!(handle.current_generation(), before + 1);
}

#[test]
fn handle_drives_full_lifecycle_transition_table() {
    use crate::runtime::policy::{LifecycleTransitionResult, RuntimeLifecyclePhase};

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let config = test_config(cert, key);
    let bundle = runtime_bundle_from_config("current.yaml", &config);
    let handle = RuntimeBundleHandle::new(bundle);

    // The handle publishes into `Running`.
    assert_eq!(handle.lifecycle().phase(), RuntimeLifecyclePhase::Running);

    // Running -> Draining (as the supervisor does on a watchdog restart request).
    assert!(matches!(
        handle.lifecycle().begin_drain(),
        LifecycleTransitionResult::Applied {
            to: RuntimeLifecyclePhase::Draining,
            ..
        }
    ));

    // Draining -> ShuttingDown (as the shutdown-signal handler does).
    assert!(matches!(
        handle.lifecycle().begin_shutdown(),
        LifecycleTransitionResult::Applied {
            to: RuntimeLifecyclePhase::ShuttingDown,
            ..
        }
    ));
    // Idempotent second call (the app calls begin_shutdown again before draining).
    assert!(matches!(
        handle.lifecycle().begin_shutdown(),
        LifecycleTransitionResult::NoOp { .. }
    ));

    // ShuttingDown -> Terminated (after workers are drained and joined).
    assert!(matches!(
        handle.lifecycle().finish_shutdown(),
        LifecycleTransitionResult::Applied {
            to: RuntimeLifecyclePhase::Terminated,
            ..
        }
    ));
    assert!(handle.lifecycle().phase().is_terminal());
}

#[test]
fn reload_commit_is_rejected_after_shutdown_begins() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let config = test_config(cert, key);
    let bundle = runtime_bundle_from_config("current.yaml", &config);
    let next = runtime_bundle_from_config("next.yaml", &config);
    let generation_before = bundle.generation;

    let handle = RuntimeBundleHandle::new(bundle);
    // Phase 6: once shutdown has begun, a reload commit must be rejected and the
    // active generation left untouched.
    handle.lifecycle().begin_shutdown();

    let result = handle.replace(next);
    assert!(result.is_err(), "reload during shutdown must be rejected");
    assert_eq!(
        handle.current_generation(),
        generation_before,
        "active generation must be unchanged after a rejected reload"
    );
}

#[test]
fn current_recovers_from_poisoned_bundle_lock_without_panicking() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let config = test_config(cert, key);
    let bundle = runtime_bundle_from_config("current.yaml", &config);
    let expected_generation = bundle.generation;

    let handle = RuntimeBundleHandle::new(bundle);
    handle.poison_for_test();

    // Phase 5: a poisoned bundle lock must not panic the hot read path; it
    // recovers the last consistently-published generation.
    let recovered = handle.current();
    assert_eq!(recovered.generation, expected_generation);
    // And it keeps working on subsequent reads.
    assert_eq!(handle.current_generation(), expected_generation);
}

#[test]
fn validate_control_api_reload_compatibility_allows_bind_change_when_socket_is_free() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut current = test_config(cert.clone(), key.clone());
    current.observability.control_api.enabled = true;
    current.observability.control_api.address = "127.0.0.1".to_string();
    current.observability.control_api.port = 9443;

    let mut next = current.clone();
    next.observability.control_api.port = 0;

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);
    let result =
        QUICListener::validate_control_api_reload_compatibility(&current_bundle, &next_bundle)
            .map(|rejection| rejection.to_string());
    if result
        .as_deref()
        .is_some_and(|err| err.contains("Operation not permitted"))
    {
        return;
    }
    assert!(
        result.is_none(),
        "expected compatible reload, got: {result:?}"
    );
}

#[test]
fn validate_metrics_reload_compatibility_allows_bind_change_when_socket_is_free() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut current = test_config(cert.clone(), key.clone());
    current.observability.metrics.enabled = true;
    current.observability.metrics.address = "127.0.0.1".to_string();
    current.observability.metrics.port = 9100;

    let mut next = current.clone();
    next.observability.metrics.port = 0;

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);
    let result = QUICListener::validate_metrics_reload_compatibility(&current_bundle, &next_bundle)
        .map(|rejection| rejection.to_string());
    if result
        .as_deref()
        .is_some_and(|err| err.contains("Operation not permitted"))
    {
        return;
    }
    assert!(
        result.is_none(),
        "expected compatible reload, got: {result:?}"
    );
}

#[test]
fn validate_startup_owned_reload_compatibility_allows_log_level_change() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let current = test_config(cert.clone(), key.clone());

    let mut next = current.clone();
    next.log.level = "debug".to_string();

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);
    let issues = startup_owned_issue_strings(&current_bundle, &next_bundle);

    assert!(
        issues.iter().all(|issue| !issue.contains("log.level")),
        "expected log.level to be live-reloadable, got: {issues:?}"
    );
}

#[test]
fn validate_startup_owned_reload_compatibility_rejects_log_format_change() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let current = test_config(cert.clone(), key.clone());

    let mut next = current.clone();
    next.log.format = LogFormat::Json;

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);
    let issues = startup_owned_issue_strings(&current_bundle, &next_bundle);

    assert!(
        issues
            .iter()
            .any(|issue| issue.contains("log.format") && issue.contains("restart required"))
    );
}

#[test]
fn validate_startup_owned_reload_compatibility_allows_worker_topology_change() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let current = test_config(cert.clone(), key.clone());

    let mut next = current.clone();
    next.performance.worker_threads = 4;
    next.performance.packet_shards_per_worker = 2;

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);
    let issues = startup_owned_issue_strings(&current_bundle, &next_bundle);

    assert!(issues.is_empty());
}

#[test]
fn validate_runtime_reload_compatibility_allows_listener_addition_when_binds_are_free() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let current = test_config(cert.clone(), key.clone());

    let mut next = current.clone();
    let mut extra_listener = next.listen.clone();
    extra_listener.port = 0;
    next.listeners = vec![next.listen.clone(), extra_listener];

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);

    let result = QUICListener::validate_runtime_reload_compatibility(&current_bundle, &next_bundle)
        .map(|rejection| rejection.to_string());
    if result
        .as_deref()
        .is_some_and(|err| err.contains("Operation not permitted"))
    {
        return;
    }
    assert!(
        result.is_none(),
        "expected compatible reload, got: {result:?}"
    );
}

#[test]
fn validate_runtime_reload_compatibility_classifies_listener_bind_conflict_as_preflight_failure() {
    use crate::runtime::policy::TransitionRejectionKind;

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let current = test_config(cert.clone(), key.clone());

    let occupied = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind occupied udp");
    let occupied_port = occupied.local_addr().expect("occupied addr").port();

    let mut next = current.clone();
    let mut extra_listener = next.listen.clone();
    extra_listener.port = occupied_port;
    next.listeners = vec![next.listen.clone(), extra_listener];

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);

    let rejection =
        QUICListener::validate_runtime_reload_compatibility(&current_bundle, &next_bundle)
            .expect("listener bind conflict must reject");
    let expected_field = format!("QUIC listener '127.0.0.1:{occupied_port}'");
    assert_eq!(
        rejection.kind,
        TransitionRejectionKind::ResourcePreparationFailed
    );
    assert!(!rejection.requires_restart());
    assert_eq!(
        rejection.field_path.as_deref(),
        Some(expected_field.as_str())
    );
    assert_structured_resource_preflight_message(&rejection);
}

#[test]
fn validate_runtime_reload_compatibility_rejects_listener_removal() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let current = test_config(cert.clone(), key.clone());

    let mut next = current.clone();
    next.listeners = vec![{
        let mut l = next.listen.clone();
        l.port = 9892;
        l
    }];

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);

    let err = QUICListener::validate_runtime_reload_compatibility(&current_bundle, &next_bundle)
        .map(|rejection| rejection.to_string());
    assert!(
        err.as_deref()
            .is_some_and(|e| e.contains("restart required")),
        "expected rejection, got: {:?}",
        err
    );
}

#[test]
fn validate_runtime_reload_compatibility_rejects_listener_bind_change() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let current = test_config(cert.clone(), key.clone());

    let mut next = current.clone();
    next.listen.port = 9893;

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);

    let err = QUICListener::validate_runtime_reload_compatibility(&current_bundle, &next_bundle)
        .map(|rejection| rejection.to_string());
    assert!(
        err.as_deref()
            .is_some_and(|e| e.contains("restart required")),
        "expected rejection, got: {:?}",
        err
    );
}

#[test]
fn validate_control_api_reload_compatibility_classifies_bind_conflict_as_preflight_failure() {
    use crate::runtime::policy::TransitionRejectionKind;

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let current = test_config(cert.clone(), key.clone());

    let occupied = std::net::TcpListener::bind("127.0.0.1:0").expect("bind occupied tcp");
    let occupied_port = occupied.local_addr().expect("occupied addr").port();

    let mut next = current.clone();
    next.observability.control_api.enabled = true;
    next.observability.control_api.address = "127.0.0.1".to_string();
    next.observability.control_api.port = occupied_port;

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);

    let rejection =
        QUICListener::validate_control_api_reload_compatibility(&current_bundle, &next_bundle)
            .expect("control api bind conflict must reject");
    let expected_field = format!("control API endpoint '127.0.0.1:{occupied_port}'");
    assert_eq!(
        rejection.kind,
        TransitionRejectionKind::ResourcePreparationFailed
    );
    assert_eq!(
        rejection.field_path.as_deref(),
        Some(expected_field.as_str())
    );
    assert!(!rejection.requires_restart());
    assert_structured_resource_preflight_message(&rejection);
}

#[test]
fn validate_metrics_reload_compatibility_classifies_bind_conflict_as_preflight_failure() {
    use crate::runtime::policy::TransitionRejectionKind;

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let current = test_config(cert.clone(), key.clone());

    let occupied = std::net::TcpListener::bind("127.0.0.1:0").expect("bind occupied tcp");
    let occupied_port = occupied.local_addr().expect("occupied addr").port();

    let mut next = current.clone();
    next.observability.metrics.enabled = true;
    next.observability.metrics.address = "127.0.0.1".to_string();
    next.observability.metrics.port = occupied_port;

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);

    let rejection =
        QUICListener::validate_metrics_reload_compatibility(&current_bundle, &next_bundle)
            .expect("metrics bind conflict must reject");
    let expected_field = format!("metrics endpoint '127.0.0.1:{occupied_port}'");
    assert_eq!(
        rejection.kind,
        TransitionRejectionKind::ResourcePreparationFailed
    );
    assert_eq!(
        rejection.field_path.as_deref(),
        Some(expected_field.as_str())
    );
    assert!(!rejection.requires_restart());
    assert_structured_resource_preflight_message(&rejection);
}

#[test]
fn validate_control_api_reload_compatibility_rejects_invalid_admin_ca_file() {
    use crate::runtime::policy::TransitionRejectionKind;

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let current = test_config(cert.clone(), key.clone());

    let mut next = current.clone();
    next.observability.control_api.enabled = true;
    next.observability.control_api.tls.client_auth.mode = ControlApiClientAuthMode::Required;
    next.observability.control_api.tls.client_auth.ca_file = Some(
        dir.path()
            .join("missing-admin-ca.pem")
            .display()
            .to_string(),
    );

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);

    let rejection =
        QUICListener::validate_control_api_reload_compatibility(&current_bundle, &next_bundle)
            .expect("invalid admin CA file must reject at preflight");
    assert_eq!(
        rejection.kind,
        TransitionRejectionKind::ResourcePreparationFailed
    );
    assert_eq!(
        rejection.field_path.as_deref(),
        Some("control API TLS '127.0.0.1:9889'")
    );
    assert!(!rejection.requires_restart());
    assert_structured_resource_preflight_message(&rejection);
}

#[test]
fn validate_metrics_reload_compatibility_rejects_invalid_admin_ca_file() {
    use crate::runtime::policy::TransitionRejectionKind;

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let current = test_config(cert.clone(), key.clone());

    let mut next = current.clone();
    next.observability.metrics.enabled = true;
    next.observability.metrics.allow_non_loopback = true;
    next.observability.control_api.tls.client_auth.mode = ControlApiClientAuthMode::Required;
    next.observability.control_api.tls.client_auth.ca_file = Some(
        dir.path()
            .join("missing-admin-ca.pem")
            .display()
            .to_string(),
    );

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);

    let rejection =
        QUICListener::validate_metrics_reload_compatibility(&current_bundle, &next_bundle)
            .expect("invalid admin CA file must reject metrics preflight");
    assert_eq!(
        rejection.kind,
        TransitionRejectionKind::ResourcePreparationFailed
    );
    assert_eq!(
        rejection.field_path.as_deref(),
        Some("metrics TLS '127.0.0.1:9889'")
    );
    assert!(!rejection.requires_restart());
    assert_structured_resource_preflight_message(&rejection);
}

#[test]
fn validate_startup_owned_reload_compatibility_rejects_control_plane_thread_change() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let current = test_config(cert.clone(), key.clone());

    let mut next = current.clone();
    next.performance.control_plane_threads = 7;

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);
    let issues = startup_owned_issue_strings(&current_bundle, &next_bundle);

    assert!(
        issues
            .iter()
            .any(|issue| issue.contains("performance.control_plane_threads"))
    );
}

#[test]
fn set_log_level_updates_global_filter_and_is_idempotent_when_unchanged() {
    impulse_utils::logger::set_log_level("info").expect("set initial level");

    impulse_utils::logger::set_log_level("debug").expect("set live log level");
    assert_eq!(log::max_level(), LevelFilter::Debug);

    impulse_utils::logger::set_log_level("debug").expect("re-applying the same level succeeds");
    assert_eq!(log::max_level(), LevelFilter::Debug);
}

// Domain: control-plane certificate reload and atomic service update behavior.
#[tokio::test]
async fn runtime_bundle_cert_reload_ignores_unrelated_config_drift_and_bundle_swap() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut live = test_config(cert.clone(), key.clone());
    live.observability.metrics.enabled = true;
    live.observability.metrics.path = "/metrics-live".to_string();

    let live_bundle = runtime_bundle_from_config("live.yaml", &live);
    let (state, runtime_handle) = runtime_bundle_control_api_state(live_bundle);

    let mut drifted = live.clone();
    drifted.observability.metrics.path = "/metrics-drifted".to_string();
    drifted.performance.control_plane_threads =
        live.performance.control_plane_threads.saturating_add(1);
    let drifted_bundle = runtime_bundle_from_config("drifted.yaml", &drifted);
    let current_runtime = runtime_handle.current_view();
    let full_reload_issues = startup_owned_issue_strings(current_runtime.bundle(), &drifted_bundle);
    assert!(
        full_reload_issues
            .iter()
            .any(|issue| issue.contains("performance.control_plane_threads")),
        "expected a full reload blocker from on-disk drift, got: {full_reload_issues:?}"
    );

    let generation_before = runtime_handle.current_generation();
    let live_runtime = runtime_handle.current_view();
    let primary_listener_label = state
        .current_primary_listener_label()
        .expect("primary listener label");
    let tls_generation_before = live_runtime
        .shared_services()
        .listener_tls_store
        .generation(&primary_listener_label)
        .unwrap_or(0);

    let response = QUICListener::reload_listener_certs(
        live_runtime.state().listener_runtime_configs.as_ref(),
        live_runtime.shared_services().listener_tls_store.as_ref(),
        live_runtime.shared_services().metrics.as_ref(),
    );
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let body = response
        .into_body()
        .collect()
        .await
        .expect("collect response body")
        .to_bytes();
    let payload: serde_json::Value = serde_json::from_slice(&body).expect("response json");
    assert_eq!(payload["reloaded"], serde_json::Value::Bool(true));
    assert_eq!(payload["reason"], "cert_reload_applied");
    assert_eq!(payload["listener_count"], 1);
    assert_eq!(payload["listeners"][0]["status"], "cert_reload_applied");
    assert!(
        payload["listeners"][0]["loaded_at_unix_ms"]
            .as_u64()
            .expect("loaded at timestamp")
            > 0
    );
    assert!(
        payload["listeners"][0]["default_cert_not_after_unix_seconds"]
            .as_i64()
            .expect("cert expiry")
            > 0
    );

    let current_runtime = runtime_handle.current_view();
    assert_eq!(current_runtime.generation(), generation_before);
    assert_eq!(
        current_runtime.runtime_config().observability.metrics.path,
        "/metrics-live"
    );
    assert!(
        current_runtime
            .shared_services()
            .listener_tls_store
            .generation(&primary_listener_label)
            .unwrap_or(0)
            > tls_generation_before,
        "expected cert reload to rotate the live listener TLS generation"
    );
}

#[tokio::test]
async fn reload_listener_certs_is_atomic_when_any_listener_reload_fails() {
    let dir = tempdir().expect("tempdir");
    let (cert1, key1) = write_test_cert_for_name(dir.path(), "server-one", "api.example.com");
    let (cert2, key2) = write_test_cert_for_name(dir.path(), "server-two", "admin.example.com");
    let mut config = test_config(cert1.clone(), key1.clone());
    config.listeners = vec![
        Listen {
            protocol: "http3".to_string(),
            port: 9889,
            address: "127.0.0.1".to_string(),
            tls: Tls {
                cert: cert1,
                key: key1,
                certificates: vec![],
                client_auth: ClientAuth::default(),
            },
        },
        Listen {
            protocol: "http3".to_string(),
            port: 9890,
            address: "127.0.0.1".to_string(),
            tls: Tls {
                cert: cert2.clone(),
                key: key2,
                certificates: vec![],
                client_auth: ClientAuth::default(),
            },
        },
    ];

    let bundle = runtime_bundle_from_config("current.yaml", &config);
    let generations_before = bundle
        .shared_state
        .shared_services()
        .listener_tls_store
        .generations();

    std::fs::write(&cert2, "not a valid certificate").expect("corrupt cert");

    let response = QUICListener::reload_listener_certs(
        bundle
            .shared_state
            .generation_state()
            .listener_runtime_configs
            .as_ref(),
        bundle
            .shared_state
            .shared_services()
            .listener_tls_store
            .as_ref(),
        bundle.shared_state.shared_services().metrics.as_ref(),
    );
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let body = response
        .into_body()
        .collect()
        .await
        .expect("collect response body")
        .to_bytes();
    let payload: serde_json::Value = serde_json::from_slice(&body).expect("response json");
    assert_eq!(payload["reloaded"], serde_json::Value::Bool(false));

    assert_eq!(
        bundle
            .shared_state
            .shared_services()
            .listener_tls_store
            .generations(),
        generations_before
    );
}

#[test]
fn run_control_api_blocking_does_not_stall_the_async_runtime() {
    // `current_thread` polls every async task (including timers) on exactly
    // one thread. If `run_control_api_blocking` ran its closure inline
    // instead of handing it to Tokio's separate blocking-thread pool, the
    // 200ms `std::thread::sleep` below would occupy that one thread and the
    // concurrently spawned 20ms timer could not fire until it finished,
    // pushing the timer's completion well past 200ms.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("build current-thread runtime");

    let (blocking_result, timer_completed_at, started) = runtime.block_on(async {
        let started = std::time::Instant::now();
        let timer_task = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            std::time::Instant::now()
        });

        let blocking_result = QUICListener::run_control_api_blocking(|| {
            std::thread::sleep(std::time::Duration::from_millis(200));
            42
        })
        .await;

        let timer_completed_at = timer_task.await.expect("concurrent timer task must run");
        (blocking_result, timer_completed_at, started)
    });

    assert_eq!(blocking_result, Some(42));
    assert!(
        timer_completed_at.duration_since(started) < std::time::Duration::from_millis(150),
        "a concurrently spawned 20ms timer must complete well before the 200ms \
         blocking closure finishes, proving the closure ran on Tokio's \
         blocking-thread pool rather than the single current-thread runtime worker"
    );
}

fn authenticated_identity(actor_id: &str) -> super::admin_identity::AdminIdentity {
    super::admin_identity::AdminIdentity {
        actor_id: Some(actor_id.to_string()),
        authn_mechanisms: vec![super::admin_identity::AdminAuthnMechanism::BearerToken],
        roles: vec![super::admin_identity::AdminRole::Operator],
        peer_addr: None,
        mtls_subject: None,
        mtls_san: Vec::new(),
    }
}

#[test]
fn control_api_actor_ignores_caller_supplied_requested_by_for_validate_and_preview() {
    // An attacker-controlled JSON body attempting to attribute the change to
    // "another-admin". The field only ever deserializes into the annotation
    // slot; it must never reach `ActivationRequest.requested_by`.
    let body: super::reload::request_body::ControlApiRuntimePlanRequest =
        serde_json::from_str(r#"{"requested_by": "another-admin"}"#).expect("plan request json");

    let real_identity = authenticated_identity("real-operator");
    let activation_request = QUICListener::control_api_activation_request(
        &body,
        0,
        "runtime_validate",
        Some(&real_identity),
    );

    assert_eq!(
        activation_request.requested_by.as_deref(),
        Some("real-operator"),
        "the authenticated actor must be recorded, not the caller-supplied requested_by"
    );
}

#[test]
fn control_api_actor_falls_back_to_generic_label_without_an_identity() {
    let body: super::reload::request_body::ControlApiRuntimePlanRequest =
        serde_json::from_str(r#"{"requested_by": "another-admin"}"#).expect("plan request json");

    let activation_request =
        QUICListener::control_api_activation_request(&body, 0, "runtime_validate", None);

    assert_eq!(
        activation_request.requested_by.as_deref(),
        Some("control_api"),
        "an unauthenticated/unknown identity must record the generic actor label, \
         never the caller-supplied requested_by"
    );
}

#[test]
fn control_api_actor_ignores_caller_supplied_requested_by_for_rollback() {
    let payload: super::reload::request_body::ControlApiRuntimeRollbackPayload =
        serde_json::from_str(r#"{"target_generation": 1, "requested_by": "another-admin"}"#)
            .expect("rollback payload json");
    assert_eq!(payload.target_generation, 1);

    let real_identity = authenticated_identity("real-admin");
    let requested_by = QUICListener::control_api_actor(Some(&real_identity));

    assert_eq!(
        requested_by.as_deref(),
        Some("real-admin"),
        "rollback must record the authenticated actor, not the caller-supplied requested_by"
    );
}

#[test]
fn activation_requires_expected_generation_but_reload_certs_does_not() {
    let missing = QUICListener::missing_expected_generation_response(
        super::admin_auth::ControlApiRoute::RuntimeActivate,
        None,
    );
    assert!(
        missing.is_some(),
        "activation without expected_generation must be rejected"
    );

    let present = QUICListener::missing_expected_generation_response(
        super::admin_auth::ControlApiRoute::RuntimeActivate,
        Some(3),
    );
    assert!(
        present.is_none(),
        "activation with expected_generation present must not be rejected"
    );

    let unrelated_route = QUICListener::missing_expected_generation_response(
        super::admin_auth::ControlApiRoute::RuntimeValidate,
        None,
    );
    assert!(
        unrelated_route.is_none(),
        "routes other than activate/reload must not require expected_generation"
    );
}

#[tokio::test]
async fn activation_missing_expected_generation_returns_400() {
    let response = QUICListener::missing_expected_generation_response(
        super::admin_auth::ControlApiRoute::RuntimeActivate,
        None,
    )
    .expect("missing expected_generation must produce a response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = full_body_bytes(response).await;
    let payload: serde_json::Value = serde_json::from_slice(&body).expect("error payload");
    assert_eq!(
        payload["error"],
        "expected_generation is required for runtime mutation"
    );
}

#[test]
fn rollback_requires_expected_active_generation() {
    let missing = QUICListener::missing_expected_active_generation_response(None);
    assert!(
        missing.is_some(),
        "rollback without expected_active_generation must be rejected"
    );

    let present = QUICListener::missing_expected_active_generation_response(Some(2));
    assert!(
        present.is_none(),
        "rollback with expected_active_generation present must not be rejected"
    );
}

#[tokio::test]
async fn rollback_missing_expected_active_generation_returns_400() {
    let response = QUICListener::missing_expected_active_generation_response(None)
        .expect("missing expected_active_generation must produce a response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = full_body_bytes(response).await;
    let payload: serde_json::Value = serde_json::from_slice(&body).expect("error payload");
    assert_eq!(
        payload["error"],
        "expected_active_generation is required for runtime rollback"
    );
}

#[test]
fn activation_payload_rejects_misspelled_generation_field() {
    // A caller misspelling `expected_generation` must fail deserialization
    // outright rather than silently proceeding without a concurrency
    // precondition.
    let err = serde_json::from_str::<super::reload::request_body::ControlApiRuntimePlanRequest>(
        r#"{"expected_generatoin": 5}"#,
    )
    .expect_err("misspelled field must be rejected");
    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn activation_payload_rejects_rollback_only_field() {
    // `expected_active_generation` is only meaningful on the rollback
    // endpoint; submitting it to activate/reload must not be silently
    // accepted and ignored.
    let err = serde_json::from_str::<super::reload::request_body::ControlApiRuntimePlanRequest>(
        r#"{"expected_active_generation": 5}"#,
    )
    .expect_err("wrong-endpoint field must be rejected");
    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn rollback_payload_rejects_misspelled_generation_field() {
    let err =
        serde_json::from_str::<super::reload::request_body::ControlApiRuntimeRollbackPayload>(
            r#"{"target_generation": 1, "expected_active_generatoin": 5}"#,
        )
        .expect_err("misspelled field must be rejected");
    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn rollback_payload_rejects_activate_only_field() {
    // `expected_generation` is only meaningful on the activate/reload
    // endpoints; submitting it to rollback must not be silently accepted
    // and ignored, since rollback has its own distinct precondition field.
    let err =
        serde_json::from_str::<super::reload::request_body::ControlApiRuntimeRollbackPayload>(
            r#"{"target_generation": 1, "expected_generation": 5}"#,
        )
        .expect_err("wrong-endpoint field must be rejected");
    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn log_audit_sink_delivers_events_regardless_of_the_application_log_threshold() {
    // A real logger backend writing to a file, so the test can assert on
    // what actually got emitted rather than only on drop counters — an
    // `info!`-gated audit call that application `log.level` suppresses is
    // never dropped (it's never attempted), so a drop-counter-only
    // assertion cannot detect this regression.
    let dir = tempdir().expect("tempdir");
    let log_path = dir.path().join("app.log");
    let init_status = impulse_utils::logger::try_init_logger(
        "info",
        true,
        log_path.to_str().expect("log path utf8"),
        false,
    );
    // `try_init_logger` installs the process-global logger exactly once; if
    // another test already installed it (writing elsewhere, e.g. stderr),
    // this test can't observe file output and would either false-pass or
    // false-fail depending on suite ordering. Skip rather than assert.
    if init_status == impulse_utils::logger::LoggerInitStatus::AlreadyInitialized {
        eprintln!(
            "skipping log_audit_sink_delivers_events_regardless_of_the_application_log_threshold: \
             logger already installed by an earlier test"
        );
        return;
    }

    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut config = test_config(cert, key);
    config.observability.control_api.enabled = true;
    config.observability.control_api.audit.enabled = true;
    config.observability.control_api.audit.sink = ControlApiAuditSink::Log;
    let state = control_api_state_with_runtime_bundle(&config, &config);

    for level in ["off", "error", "warn", "info", "debug", "trace"] {
        impulse_utils::logger::set_log_level(level).expect("set application log level");
        let marker = format!("log-threshold-marker-{level}");

        QUICListener::emit_control_api_audit_event(
            &state.current_security_policy(),
            None,
            None,
            super::audit::AdminAuditEventType::RuntimeSnapshot,
            super::audit::AdminAuditAction::RuntimeSnapshotRead,
            QUICListener::control_api_audit_target_for_route(
                super::admin_auth::ControlApiRoute::Runtime,
                None,
            ),
            super::audit::AdminAuditGeneration::default(),
            super::audit::AdminAuditResult::Success,
            Some(marker.clone()),
        );

        let contents = std::fs::read_to_string(&log_path).expect("read log file");
        assert!(
            contents.contains(&marker),
            "audit event must reach the log sink at application log level '{level}', \
             log file contents: {contents}"
        );
    }
}
