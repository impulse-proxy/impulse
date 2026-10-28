#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{
    fmt,
    fs::{File, OpenOptions},
    io::Write,
    sync::{
        Arc,
        atomic::Ordering,
        mpsc::{self, SyncSender, TrySendError},
    },
    thread,
};

use impulse_config::config::{
    ControlApi as ControlApiConfig, ControlApiAuditFormat, ControlApiAuditSink,
};
use impulse_utils::logger::CONTROL_API_AUDIT_LOG_TARGET;
use log::{Level, Metadata, Record, error, warn};
use serde::Serialize;

use super::{
    admin_auth::ControlApiRoute,
    admin_identity::{AdminAuthnMechanism, AdminIdentity, AdminRole, ControlApiRequestContext},
    security::ControlApiSecurityPolicy,
    *,
};
use crate::{Metrics, REQUEST_ID_COUNTER};

pub(super) const ADMIN_AUDIT_SCHEMA_VERSION: &str = "v1";
const CONTROL_API_AUDIT_BUFFER_CAPACITY: usize = 1024;

pub(in crate::quic_listener) struct ControlApiAdminAuditEmitter {
    pub(in crate::quic_listener) enabled: bool,
    pub(in crate::quic_listener) format: ControlApiAuditFormat,
    pub(in crate::quic_listener) sink: ControlApiAdminAuditTarget,
    delivery: ControlApiAdminAuditDelivery,
    metrics: Arc<Metrics>,
}

impl ControlApiAdminAuditEmitter {
    pub(in crate::quic_listener) fn from_config(
        config: &ControlApiConfig,
        metrics: Arc<Metrics>,
    ) -> Self {
        let sink = match config.audit.sink {
            ControlApiAuditSink::Log => ControlApiAdminAuditTarget::Log,
            ControlApiAuditSink::File => {
                ControlApiAdminAuditTarget::File(config.audit.file_path.clone())
            }
        };
        Self {
            enabled: config.audit.enabled,
            format: config.audit.format,
            delivery: ControlApiAdminAuditDelivery::for_target(&sink, Arc::clone(&metrics)),
            sink,
            metrics,
        }
    }
}

impl Clone for ControlApiAdminAuditEmitter {
    fn clone(&self) -> Self {
        Self {
            enabled: self.enabled,
            format: self.format,
            sink: self.sink.clone(),
            delivery: self.delivery.clone(),
            metrics: Arc::clone(&self.metrics),
        }
    }
}

impl fmt::Debug for ControlApiAdminAuditEmitter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlApiAdminAuditEmitter")
            .field("enabled", &self.enabled)
            .field("format", &self.format)
            .field("sink", &self.sink)
            .finish()
    }
}

impl PartialEq for ControlApiAdminAuditEmitter {
    fn eq(&self, other: &Self) -> bool {
        self.enabled == other.enabled && self.format == other.format && self.sink == other.sink
    }
}

impl Eq for ControlApiAdminAuditEmitter {}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(in crate::quic_listener) enum ControlApiAdminAuditTarget {
    Log,
    File(Option<String>),
}

#[derive(Clone)]
enum ControlApiAdminAuditDelivery {
    Inline,
    BufferedFile(Arc<ControlApiBufferedAuditWriter>),
    UnavailableFile { path: String, reason: &'static str },
}

impl ControlApiAdminAuditDelivery {
    fn for_target(target: &ControlApiAdminAuditTarget, metrics: Arc<Metrics>) -> Self {
        match target {
            ControlApiAdminAuditTarget::Log | ControlApiAdminAuditTarget::File(None) => {
                Self::Inline
            }
            ControlApiAdminAuditTarget::File(Some(path)) => {
                match ControlApiBufferedAuditWriter::try_spawn(path.clone(), Arc::clone(&metrics)) {
                    Some(writer) => Self::BufferedFile(Arc::new(writer)),
                    None => {
                        metrics
                            .ingress_observations()
                            .inc_control_api_audit_write_failure();
                        error!(
                            "failed to start control API admin audit sink thread for {}; file audit sink is degraded and audit events will be dropped until the process is restarted",
                            path
                        );
                        Self::UnavailableFile {
                            path: path.clone(),
                            reason: "writer_thread_start_failed",
                        }
                    }
                }
            }
        }
    }
}

struct ControlApiBufferedAuditWriter {
    sender: Option<SyncSender<String>>,
    path: String,
    metrics: Arc<Metrics>,
    thread: Option<thread::JoinHandle<()>>,
}

impl ControlApiBufferedAuditWriter {
    fn try_spawn(path: String, metrics: Arc<Metrics>) -> Option<Self> {
        #[cfg(test)]
        if FORCE_AUDIT_WRITER_THREAD_SPAWN_FAILURE.with(std::cell::Cell::get) {
            return None;
        }

        let (sender, receiver) = mpsc::sync_channel(CONTROL_API_AUDIT_BUFFER_CAPACITY);
        let thread_path = path.clone();
        let thread_metrics = Arc::clone(&metrics);

        let thread = thread::Builder::new()
            .name("control-api-audit-writer".to_string())
            .spawn(move || {
                let mut file = None;
                while let Ok(serialized) = receiver.recv() {
                    if file.is_none() {
                        file = Self::open_sink(&thread_path, &thread_metrics);
                    }

                    let Some(open_file) = file.as_mut() else {
                        thread_metrics
                            .ingress_observations()
                            .inc_control_api_audit_event_drop();
                        continue;
                    };

                    if let Err(err) =
                        writeln!(open_file, "{}", serialized).and_then(|()| open_file.flush())
                    {
                        thread_metrics
                            .ingress_observations()
                            .inc_control_api_audit_write_failure();
                        thread_metrics
                            .ingress_observations()
                            .inc_control_api_audit_event_drop();
                        error!(
                            "failed to write control API admin audit event to {}: {}",
                            thread_path, err
                        );
                        file = None;
                    }
                }
            })
            .ok()?;

        Some(Self {
            sender: Some(sender),
            path,
            metrics,
            thread: Some(thread),
        })
    }

    fn emit(&self, serialized: String) {
        let Some(sender) = self.sender.as_ref() else {
            self.metrics
                .ingress_observations()
                .inc_control_api_audit_event_drop();
            return;
        };
        match sender.try_send(serialized) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.metrics
                    .ingress_observations()
                    .inc_control_api_audit_event_drop();
                error!(
                    "control API admin audit buffer for {} is full; dropping audit event",
                    self.path
                );
            }
            Err(TrySendError::Disconnected(serialized)) => {
                self.metrics
                    .ingress_observations()
                    .inc_control_api_audit_write_failure();
                error!(
                    "control API admin audit writer thread for {} is unavailable; falling back to synchronous file append",
                    self.path
                );
                if !self.write_synchronously(serialized) {
                    self.metrics
                        .ingress_observations()
                        .inc_control_api_audit_event_drop();
                }
            }
        }
    }

    fn write_synchronously(&self, serialized: String) -> bool {
        let Some(mut file) = Self::open_sink(&self.path, self.metrics.as_ref()) else {
            return false;
        };

        if let Err(err) = writeln!(file, "{}", serialized).and_then(|()| file.flush()) {
            self.metrics
                .ingress_observations()
                .inc_control_api_audit_write_failure();
            error!(
                "failed to synchronously write control API admin audit event to {}: {}",
                self.path, err
            );
            return false;
        }
        true
    }

    fn open_sink(path: &str, metrics: &Metrics) -> Option<File> {
        #[cfg(unix)]
        let options = {
            let mut options = OpenOptions::new();
            options
                .create(true)
                .append(true)
                .mode(0o640)
                .custom_flags(libc::O_NOFOLLOW);
            options
        };

        #[cfg(not(unix))]
        let mut options = {
            let mut options = OpenOptions::new();
            options.create(true).append(true);
            options
        };

        match options.open(path) {
            Ok(file) => {
                #[cfg(unix)]
                if let Err(err) = file.set_permissions(std::fs::Permissions::from_mode(0o640)) {
                    metrics
                        .ingress_observations()
                        .inc_control_api_audit_write_failure();
                    error!(
                        "failed to set restrictive permissions on control API admin audit sink {}: {}",
                        path, err
                    );
                    return None;
                }

                Some(file)
            }
            Err(err) => {
                metrics
                    .ingress_observations()
                    .inc_control_api_audit_write_failure();
                error!(
                    "failed to open control API admin audit sink {}: {}",
                    path, err
                );
                None
            }
        }
    }
}

impl Drop for ControlApiBufferedAuditWriter {
    fn drop(&mut self) {
        // Closing the sender lets the writer drain every queued event before
        // recv() returns Disconnected. Join the thread so process shutdown
        // does not discard events that are still being written.
        self.sender.take();
        if let Some(thread) = self.thread.take()
            && thread.thread().id() != thread::current().id()
        {
            let _ = thread.join();
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub(in crate::quic_listener) struct AdminAuditEvent {
    pub(in crate::quic_listener) schema_version: &'static str,
    pub(in crate::quic_listener) event_id: String,
    pub(in crate::quic_listener) event_type: AdminAuditEventType,
    pub(in crate::quic_listener) time_unix_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::quic_listener) request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::quic_listener) trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::quic_listener) span_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::quic_listener) listener: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::quic_listener) upstream: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::quic_listener) backend: Option<String>,
    pub(in crate::quic_listener) actor: AdminAuditActor,
    pub(in crate::quic_listener) action: AdminAuditAction,
    pub(in crate::quic_listener) target: AdminAuditTarget,
    pub(in crate::quic_listener) generation: AdminAuditGeneration,
    pub(in crate::quic_listener) result: AdminAuditResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::quic_listener) reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::quic_listener) failure_class: Option<AdminAuditFailureClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::quic_listener) peer_addr: Option<String>,
    pub(in crate::quic_listener) authn: AdminAuditAuthn,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::quic_listener) enum AdminAuditFailureClass {
    Authentication,
    Authorization,
    SourcePolicy,
    RequestValidation,
    RuntimeConfig,
    RuntimeState,
    ListenerTls,
    Watchdog,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::quic_listener) enum AdminAuditEventType {
    Auth,
    RuntimeSnapshot,
    RuntimeValidate,
    RuntimePreview,
    RuntimeReload,
    RuntimeActivate,
    RuntimeRollback,
    RuntimeRestart,
    CertReload,
    /// Upstream secret-backed TLS material (client cert/key, CA bundle)
    /// changed and was applied through generation activation.
    UpstreamMtlsMaterial,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub(in crate::quic_listener) struct AdminAuditActor {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::quic_listener) id: Option<String>,
    pub(in crate::quic_listener) roles: Vec<AdminRole>,
    pub(in crate::quic_listener) authn_mechanisms: Vec<AdminAuthnMechanism>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::quic_listener) mtls_subject: Option<String>,
}

impl AdminAuditActor {
    pub(in crate::quic_listener) fn from_identity(identity: Option<&AdminIdentity>) -> Self {
        Self {
            id: identity.and_then(|identity| identity.actor_id.clone()),
            roles: identity
                .map(|identity| identity.roles.clone())
                .unwrap_or_default(),
            authn_mechanisms: identity
                .map(|identity| identity.authn_mechanisms.clone())
                .unwrap_or_default(),
            mtls_subject: identity.and_then(|identity| identity.mtls_subject.clone()),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
pub(in crate::quic_listener) enum AdminAuditAction {
    #[serde(rename = "auth")]
    Auth,
    #[serde(rename = "runtime_snapshot.read")]
    RuntimeSnapshotRead,
    #[serde(rename = "runtime_validate.attempt")]
    RuntimeValidateAttempt,
    #[serde(rename = "runtime_validate.result")]
    RuntimeValidateResult,
    #[serde(rename = "runtime_preview.attempt")]
    RuntimePreviewAttempt,
    #[serde(rename = "runtime_preview.result")]
    RuntimePreviewResult,
    #[serde(rename = "runtime_reload.attempt")]
    RuntimeReloadAttempt,
    #[serde(rename = "runtime_reload.result")]
    RuntimeReloadResult,
    #[serde(rename = "runtime_activate.attempt")]
    RuntimeActivateAttempt,
    #[serde(rename = "runtime_activate.result")]
    RuntimeActivateResult,
    #[serde(rename = "runtime_rollback.attempt")]
    RuntimeRollbackAttempt,
    #[serde(rename = "runtime_rollback.result")]
    RuntimeRollbackResult,
    #[serde(rename = "runtime_restart.attempt")]
    RuntimeRestartAttempt,
    #[serde(rename = "runtime_restart.result")]
    RuntimeRestartResult,
    #[serde(rename = "cert_reload.attempt")]
    CertReloadAttempt,
    #[serde(rename = "cert_reload.result")]
    CertReloadResult,
    #[serde(rename = "cert_reload_applied")]
    CertReloadApplied,
    #[serde(rename = "secret_resolution_failed")]
    SecretResolutionFailed,
    #[serde(rename = "upstream_mtls_material_changed")]
    UpstreamMtlsMaterialChanged,
    #[serde(rename = "upstream_mtls_material_invalid")]
    UpstreamMtlsMaterialInvalid,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub(in crate::quic_listener) struct AdminAuditTarget {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::quic_listener) route: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::quic_listener) resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::quic_listener) config_path: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Default)]
pub(in crate::quic_listener) struct AdminAuditGeneration {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::quic_listener) active_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::quic_listener) candidate_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::quic_listener) target_generation: Option<u64>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::quic_listener) enum AdminAuditResult {
    Success,
    Denied,
    Failed,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub(in crate::quic_listener) struct AdminAuditAuthn {
    pub(in crate::quic_listener) mechanisms: Vec<AdminAuthnMechanism>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::quic_listener) mtls_subject: Option<String>,
}

impl AdminAuditAuthn {
    pub(in crate::quic_listener) fn from_identity(identity: Option<&AdminIdentity>) -> Self {
        Self {
            mechanisms: identity
                .map(|identity| identity.authn_mechanisms.clone())
                .unwrap_or_default(),
            mtls_subject: identity.and_then(|identity| identity.mtls_subject.clone()),
        }
    }
}

impl QUICListener {
    // The audit event is a flat record; passing its fields individually keeps the
    // ~24 emission sites readable rather than forcing a builder at each one.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn emit_control_api_audit_event(
        security: &ControlApiSecurityPolicy,
        identity: Option<&AdminIdentity>,
        request_context: Option<&ControlApiRequestContext>,
        event_type: AdminAuditEventType,
        action: AdminAuditAction,
        target: AdminAuditTarget,
        generation: AdminAuditGeneration,
        result: AdminAuditResult,
        reason: Option<String>,
    ) {
        let emitter = &security.audit;
        if !emitter.enabled {
            return;
        }
        let reason = reason
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);

        let event = AdminAuditEvent {
            schema_version: ADMIN_AUDIT_SCHEMA_VERSION,
            event_id: format!(
                "control-api-audit-{}",
                REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
            ),
            event_type,
            time_unix_ms: crate::watchdog::time::now_millis(),
            request_id: Self::control_api_audit_request_id(request_context),
            trace_id: Self::control_api_audit_trace_id(request_context),
            span_id: Self::control_api_audit_span_id(request_context),
            listener: Self::control_api_audit_listener(request_context),
            upstream: None,
            backend: None,
            actor: AdminAuditActor::from_identity(identity),
            action,
            target,
            generation,
            result,
            failure_class: Self::control_api_audit_failure_class(
                event_type,
                result,
                reason.as_deref(),
            ),
            reason,
            peer_addr: Self::control_api_audit_peer_addr(identity, request_context),
            authn: AdminAuditAuthn::from_identity(identity),
        };

        emitter.emit(&event);
    }

    pub(super) fn emit_control_api_auth_audit_event(
        security: &ControlApiSecurityPolicy,
        identity: Option<&AdminIdentity>,
        request_context: Option<&ControlApiRequestContext>,
        route: ControlApiRoute,
        active_generation: Option<u64>,
        result: AdminAuditResult,
        reason: impl Into<String>,
    ) {
        Self::emit_control_api_audit_event(
            security,
            identity,
            request_context,
            AdminAuditEventType::Auth,
            AdminAuditAction::Auth,
            Self::control_api_audit_target_for_route(route, None),
            AdminAuditGeneration {
                active_generation,
                ..Default::default()
            },
            result,
            Some(reason.into()),
        );
    }

    pub(super) fn emit_control_api_route_denial_audit_event(
        security: &ControlApiSecurityPolicy,
        identity: Option<&AdminIdentity>,
        request_context: Option<&ControlApiRequestContext>,
        route: ControlApiRoute,
        active_generation: Option<u64>,
        reason: impl Into<String>,
    ) {
        let Some((event_type, action)) = Self::control_api_denied_action_for_route(route) else {
            return;
        };

        Self::emit_control_api_audit_event(
            security,
            identity,
            request_context,
            event_type,
            action,
            Self::control_api_audit_target_for_route(route, None),
            AdminAuditGeneration {
                active_generation,
                ..Default::default()
            },
            AdminAuditResult::Denied,
            Some(reason.into()),
        );
    }

    pub(super) fn control_api_audit_target_for_route(
        route: ControlApiRoute,
        config_path: Option<String>,
    ) -> AdminAuditTarget {
        let resource = match route {
            ControlApiRoute::Health | ControlApiRoute::Ready => {
                Some("control_api_status".to_string())
            }
            ControlApiRoute::Runtime
            | ControlApiRoute::RuntimeHistory
            | ControlApiRoute::RuntimeHistoryGeneration(_) => Some("runtime_state".to_string()),
            ControlApiRoute::RuntimeValidate
            | ControlApiRoute::RuntimePreview
            | ControlApiRoute::RuntimeActivate
            | ControlApiRoute::RuntimeRollback
            | ControlApiRoute::ReloadRuntime => Some("runtime_generation".to_string()),
            ControlApiRoute::ReloadCerts => Some("listener_tls".to_string()),
            ControlApiRoute::Restart => Some("watchdog".to_string()),
        };

        AdminAuditTarget {
            route: Some(Self::control_api_route_name(route).to_string()),
            resource,
            config_path,
        }
    }

    pub(super) fn control_api_route_name(route: ControlApiRoute) -> &'static str {
        match route {
            ControlApiRoute::Health => "/health",
            ControlApiRoute::Ready => "/ready",
            ControlApiRoute::Runtime => "/admin/runtime",
            ControlApiRoute::RuntimeValidate => "/admin/runtime/validate",
            ControlApiRoute::RuntimePreview => "/admin/runtime/preview",
            ControlApiRoute::RuntimeActivate => "/admin/runtime/activate",
            ControlApiRoute::RuntimeRollback => "/admin/runtime/rollback",
            ControlApiRoute::RuntimeHistory => "/admin/runtime/history",
            ControlApiRoute::RuntimeHistoryGeneration(_) => "/admin/runtime/history/{generation}",
            ControlApiRoute::ReloadCerts => "/admin/reload-certs",
            ControlApiRoute::ReloadRuntime => "/admin/reload",
            ControlApiRoute::Restart => "/admin/restart",
        }
    }

    fn control_api_denied_action_for_route(
        route: ControlApiRoute,
    ) -> Option<(AdminAuditEventType, AdminAuditAction)> {
        match route {
            ControlApiRoute::Runtime
            | ControlApiRoute::RuntimeHistory
            | ControlApiRoute::RuntimeHistoryGeneration(_) => Some((
                AdminAuditEventType::RuntimeSnapshot,
                AdminAuditAction::RuntimeSnapshotRead,
            )),
            ControlApiRoute::RuntimeValidate => Some((
                AdminAuditEventType::RuntimeValidate,
                AdminAuditAction::RuntimeValidateAttempt,
            )),
            ControlApiRoute::RuntimePreview => Some((
                AdminAuditEventType::RuntimePreview,
                AdminAuditAction::RuntimePreviewAttempt,
            )),
            ControlApiRoute::RuntimeActivate => Some((
                AdminAuditEventType::RuntimeActivate,
                AdminAuditAction::RuntimeActivateAttempt,
            )),
            ControlApiRoute::RuntimeRollback => Some((
                AdminAuditEventType::RuntimeRollback,
                AdminAuditAction::RuntimeRollbackAttempt,
            )),
            ControlApiRoute::ReloadCerts => Some((
                AdminAuditEventType::CertReload,
                AdminAuditAction::CertReloadAttempt,
            )),
            ControlApiRoute::ReloadRuntime => Some((
                AdminAuditEventType::RuntimeReload,
                AdminAuditAction::RuntimeReloadAttempt,
            )),
            ControlApiRoute::Restart => Some((
                AdminAuditEventType::RuntimeRestart,
                AdminAuditAction::RuntimeRestartAttempt,
            )),
            ControlApiRoute::Health | ControlApiRoute::Ready => None,
        }
    }

    fn control_api_audit_peer_addr(
        identity: Option<&AdminIdentity>,
        request_context: Option<&ControlApiRequestContext>,
    ) -> Option<String> {
        identity
            .and_then(|identity| identity.peer_addr)
            .or_else(|| request_context.map(|context| context.peer_addr))
            .map(|addr| addr.to_string())
    }

    fn control_api_audit_request_id(
        request_context: Option<&ControlApiRequestContext>,
    ) -> Option<String> {
        request_context.and_then(|context| context.request_id.clone())
    }

    fn control_api_audit_trace_id(
        request_context: Option<&ControlApiRequestContext>,
    ) -> Option<String> {
        request_context.and_then(|context| context.trace_id.clone())
    }

    fn control_api_audit_span_id(
        request_context: Option<&ControlApiRequestContext>,
    ) -> Option<String> {
        request_context.and_then(|context| context.span_id.clone())
    }

    fn control_api_audit_listener(
        request_context: Option<&ControlApiRequestContext>,
    ) -> Option<String> {
        request_context.and_then(|context| context.listener.clone())
    }

    fn control_api_audit_failure_class(
        event_type: AdminAuditEventType,
        result: AdminAuditResult,
        reason: Option<&str>,
    ) -> Option<AdminAuditFailureClass> {
        if matches!(result, AdminAuditResult::Success) {
            return None;
        }

        match reason {
            Some("missing_authentication")
            | Some("invalid_authorization_header")
            | Some("invalid_bearer_token") => {
                return Some(AdminAuditFailureClass::Authentication);
            }
            Some("insufficient_role") => {
                return Some(AdminAuditFailureClass::Authorization);
            }
            Some("missing_peer_context") | Some("source_ip_not_allowed") => {
                return Some(AdminAuditFailureClass::SourcePolicy);
            }
            Some("invalid_request_body") => {
                return Some(AdminAuditFailureClass::RequestValidation);
            }
            _ => {}
        }

        match event_type {
            AdminAuditEventType::Auth => Some(AdminAuditFailureClass::Authentication),
            AdminAuditEventType::RuntimeSnapshot => Some(AdminAuditFailureClass::RuntimeState),
            AdminAuditEventType::RuntimeValidate
            | AdminAuditEventType::RuntimePreview
            | AdminAuditEventType::RuntimeReload
            | AdminAuditEventType::RuntimeActivate
            | AdminAuditEventType::RuntimeRollback
            | AdminAuditEventType::UpstreamMtlsMaterial => {
                Some(AdminAuditFailureClass::RuntimeConfig)
            }
            AdminAuditEventType::RuntimeRestart => Some(AdminAuditFailureClass::Watchdog),
            AdminAuditEventType::CertReload => Some(AdminAuditFailureClass::ListenerTls),
        }
    }
}

impl ControlApiAdminAuditEmitter {
    fn emit_log_audit(&self, serialized: &str) {
        let metadata = Metadata::builder()
            .level(Level::Info)
            .target(CONTROL_API_AUDIT_LOG_TARGET)
            .build();
        if !log::logger().enabled(&metadata) {
            self.metrics
                .ingress_observations()
                .inc_control_api_audit_event_drop();
            eprintln!(
                "dropping control API admin audit event because the audit logger is unavailable"
            );
            return;
        }

        // Call the configured logger directly instead of using info!, whose
        // macro-level guard consults log::max_level. Application log levels
        // must not disable the independent audit delivery channel.
        let args = format_args!("{}", serialized);
        let record = Record::builder().metadata(metadata).args(args).build();
        log::logger().log(&record);
    }

    fn emit(&self, event: &AdminAuditEvent) {
        let serialized = match self.format {
            ControlApiAuditFormat::Json => match serde_json::to_string(event) {
                Ok(serialized) => serialized,
                Err(err) => {
                    error!("failed to serialize control API admin audit event: {}", err);
                    self.metrics
                        .ingress_observations()
                        .inc_control_api_audit_event_drop();
                    return;
                }
            },
        };

        match &self.sink {
            ControlApiAdminAuditTarget::Log => self.emit_log_audit(&serialized),
            ControlApiAdminAuditTarget::File(Some(_)) => match &self.delivery {
                ControlApiAdminAuditDelivery::BufferedFile(writer) => writer.emit(serialized),
                ControlApiAdminAuditDelivery::UnavailableFile { path, reason } => {
                    self.metrics
                        .ingress_observations()
                        .inc_control_api_audit_event_drop();
                    error!(
                        "dropping control API admin audit event because file sink {} is unavailable: {}",
                        path, reason
                    );
                }
                ControlApiAdminAuditDelivery::Inline => {
                    self.metrics
                        .ingress_observations()
                        .inc_control_api_audit_event_drop();
                    error!(
                        "dropping control API admin audit event because file sink configuration unexpectedly resolved to inline delivery"
                    );
                }
            },
            ControlApiAdminAuditTarget::File(None) => {
                warn!(
                    "control API admin audit sink configured as file without file_path; falling back to log"
                );
                self.emit_log_audit(&serialized);
            }
        }
    }
}

impl ControlApiAdminAuditEmitter {
    pub(super) fn delivery_degraded(&self) -> bool {
        matches!(
            self.delivery,
            ControlApiAdminAuditDelivery::UnavailableFile { .. }
        )
    }

    pub(super) fn delivery_reason(&self) -> Option<&'static str> {
        match &self.delivery {
            ControlApiAdminAuditDelivery::UnavailableFile { reason, .. } => Some(reason),
            _ => None,
        }
    }
}

#[cfg(test)]
thread_local! {
    static FORCE_AUDIT_WRITER_THREAD_SPAWN_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(super) fn force_audit_writer_thread_spawn_failure_for_test(enabled: bool) {
    FORCE_AUDIT_WRITER_THREAD_SPAWN_FAILURE.set(enabled);
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::quic_listener::control_api::admin_identity::{
        AdminAuthnMechanism, AdminIdentity, AdminRole,
    };

    #[test]
    fn admin_audit_event_serialization_stays_stable() {
        let identity = AdminIdentity {
            actor_id: Some("alice".to_string()),
            authn_mechanisms: vec![AdminAuthnMechanism::BearerToken],
            roles: vec![AdminRole::Operator],
            peer_addr: Some("127.0.0.1:9999".parse().expect("socket addr")),
            mtls_subject: Some("CN=alice".to_string()),
            mtls_san: vec!["spiffe://alice".to_string()],
        };
        let event = AdminAuditEvent {
            schema_version: ADMIN_AUDIT_SCHEMA_VERSION,
            event_id: "evt-1".to_string(),
            event_type: AdminAuditEventType::RuntimeReload,
            time_unix_ms: 42,
            request_id: Some("req-7".to_string()),
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
            listener: Some("edge-primary".to_string()),
            upstream: None,
            backend: None,
            actor: AdminAuditActor::from_identity(Some(&identity)),
            action: AdminAuditAction::RuntimeReloadAttempt,
            target: AdminAuditTarget {
                route: Some("/admin/runtime/reload".to_string()),
                resource: Some("control_api".to_string()),
                config_path: Some("/etc/impulse/config.yaml".to_string()),
            },
            generation: AdminAuditGeneration {
                active_generation: Some(7),
                candidate_generation: Some(8),
                target_generation: None,
            },
            result: AdminAuditResult::Success,
            reason: Some("operator_requested".to_string()),
            failure_class: None,
            peer_addr: Some("127.0.0.1:9999".to_string()),
            authn: AdminAuditAuthn::from_identity(Some(&identity)),
        };

        let value = serde_json::to_value(&event).expect("serialize audit event");
        assert_eq!(
            value,
            serde_json::json!({
                "schema_version": "v1",
                "event_id": "evt-1",
                "event_type": "runtime_reload",
                "time_unix_ms": 42,
                "request_id": "req-7",
                "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
                "span_id": "00f067aa0ba902b7",
                "listener": "edge-primary",
                "actor": {
                    "id": "alice",
                    "roles": ["operator"],
                    "authn_mechanisms": ["bearer_token"],
                    "mtls_subject": "CN=alice"
                },
                "action": "runtime_reload.attempt",
                "target": {
                    "route": "/admin/runtime/reload",
                    "resource": "control_api",
                    "config_path": "/etc/impulse/config.yaml"
                },
                "generation": {
                    "active_generation": 7,
                    "candidate_generation": 8
                },
                "result": "success",
                "reason": "operator_requested",
                "peer_addr": "127.0.0.1:9999",
                "authn": {
                    "mechanisms": ["bearer_token"],
                    "mtls_subject": "CN=alice"
                }
            })
        );
    }

    #[test]
    fn admin_audit_failure_class_serializes_low_cardinality_category() {
        assert_eq!(
            QUICListener::control_api_audit_failure_class(
                AdminAuditEventType::RuntimeValidate,
                AdminAuditResult::Failed,
                Some("invalid_request_body"),
            ),
            Some(AdminAuditFailureClass::RequestValidation)
        );
        assert_eq!(
            QUICListener::control_api_audit_failure_class(
                AdminAuditEventType::Auth,
                AdminAuditResult::Denied,
                Some("invalid_bearer_token"),
            ),
            Some(AdminAuditFailureClass::Authentication)
        );
        assert_eq!(
            QUICListener::control_api_audit_failure_class(
                AdminAuditEventType::RuntimeRestart,
                AdminAuditResult::Failed,
                Some("watchdog_disabled"),
            ),
            Some(AdminAuditFailureClass::Watchdog)
        );
    }

    #[cfg(unix)]
    #[test]
    fn control_api_audit_file_sink_uses_restrictive_permissions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("admin-audit.jsonl");
        let metrics = Arc::new(Metrics::default());

        let file = ControlApiBufferedAuditWriter::open_sink(
            path.to_str().expect("utf-8 path"),
            metrics.as_ref(),
        )
        .expect("open audit sink");
        drop(file);

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o640);
    }

    #[cfg(unix)]
    #[test]
    fn control_api_audit_file_sink_corrects_permissions_for_preexisting_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("admin-audit.jsonl");
        let metrics = Arc::new(Metrics::default());
        std::fs::write(&path, b"existing audit data\n").expect("seed file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
            .expect("set permissive mode");

        let file = ControlApiBufferedAuditWriter::open_sink(
            path.to_str().expect("utf-8 path"),
            metrics.as_ref(),
        )
        .expect("open audit sink");
        drop(file);

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o640);
    }

    #[test]
    fn control_api_audit_buffered_writer_drains_queued_events_on_drop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("admin-audit.jsonl");
        let metrics = Arc::new(Metrics::default());
        let writer = ControlApiBufferedAuditWriter::try_spawn(
            path.to_string_lossy().to_string(),
            Arc::clone(&metrics),
        )
        .expect("spawn audit writer");

        writer.emit("{\"event\":\"queued\"}".to_string());
        drop(writer);

        let contents = std::fs::read_to_string(&path).expect("read drained audit file");
        assert_eq!(contents, "{\"event\":\"queued\"}\n");
    }

    #[test]
    fn control_api_audit_buffered_writer_sync_fallback_preserves_event_when_thread_is_gone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("admin-audit.jsonl");
        let metrics = Arc::new(Metrics::default());
        let (sender, receiver) = mpsc::sync_channel(1);
        drop(receiver);
        let writer = ControlApiBufferedAuditWriter {
            sender: Some(sender),
            path: path.to_string_lossy().to_string(),
            metrics: Arc::clone(&metrics),
            thread: None,
        };

        writer.emit("{\"event\":\"audit\"}".to_string());

        let contents = std::fs::read_to_string(&path).expect("read audit file");
        assert_eq!(contents, "{\"event\":\"audit\"}\n");
        assert_eq!(
            metrics
                .control_api_audit_event_drops
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            metrics
                .control_api_audit_write_failures
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn control_api_audit_buffered_writer_drops_without_blocking_when_full() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("admin-audit.jsonl");
        let metrics = Arc::new(Metrics::default());
        let (sender, receiver) = mpsc::sync_channel(1);
        sender
            .send("already-buffered".to_string())
            .expect("fill buffer");
        let writer = ControlApiBufferedAuditWriter {
            sender: Some(sender),
            path: path.to_string_lossy().to_string(),
            metrics: Arc::clone(&metrics),
            thread: None,
        };

        writer.emit("{\"event\":\"audit\"}".to_string());

        assert!(!path.exists());
        assert_eq!(
            metrics
                .control_api_audit_event_drops
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        drop(receiver);
    }
}
