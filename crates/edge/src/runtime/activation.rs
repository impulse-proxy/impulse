//! Canonical activation, preview, and rollback contract for runtime generations.
//!
//! This module owns staged planning, compatibility validation, publication,
//! rollback, and generation history together with their typed contracts.
//! Control-plane handlers translate requests and responses without owning
//! runtime mutation.

pub use impulse_observability::{RuntimeOperationOutcomeReason, RuntimeRejectionReason};
pub use impulse_runtime::GenerationId;
use serde::{Deserialize, Serialize};

use crate::runtime::policy::{TransitionRejection, TransitionRejectionKind};

pub(crate) mod compatibility;
mod diff;
mod history;
mod planning;
mod service;
mod swap;

pub(crate) use self::service::RuntimeActivationService;

/// Milliseconds since the Unix epoch.
///
/// Stored as an integer so the activation contract stays transport-agnostic and
/// trivially serializable for control-plane responses and audit history.
pub type TimestampMillis = u64;

/// Raw configuration source for staged validation/planning.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReloadConfigInput {
    Path { path: String },
}

impl ReloadConfigInput {
    #[must_use]
    pub fn source_label(&self) -> String {
        match self {
            Self::Path { path } => path.clone(),
        }
    }
}

/// Coarse kind of generation operation recorded in history.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum GenerationOperation {
    Validate,
    Preview,
    Activate,
    Rollback,
}

/// Structured runtime generation event kinds.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum GenerationEventKind {
    Validation,
    Preview,
    ActivationSucceeded,
    ActivationFailed,
    RollbackSucceeded,
    RollbackFailed,
}

/// Lifecycle status for a runtime generation or staged candidate.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum GenerationStatus {
    Staged,
    Active,
    Superseded,
    RollbackCandidate,
    RolledBack,
    Rejected,
    Failed,
}

impl GenerationStatus {
    #[must_use]
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    #[must_use]
    pub fn is_rollback_candidate(self) -> bool {
        matches!(self, Self::RollbackCandidate | Self::Superseded)
    }
}

/// Staged validation/planning phase.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PlanningPhase {
    ReadConfig,
    ValidateConfig,
    NormalizeRuntime,
    EvaluateCompatibility,
}

/// Result for an individual staged validation/planning phase.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PlanningPhaseStatus {
    Accepted,
    Rejected,
    Skipped,
}

/// One staged validation/planning outcome.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlanningPhaseResult {
    pub phase: PlanningPhase,
    pub status: PlanningPhaseStatus,
    pub summary: String,
}

/// Coarse classification for the compatibility outcome of a staged reload.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ReloadCompatibilityClassification {
    NotEvaluated,
    LiveReloadable,
    RestartRequired,
    Rejected,
}

/// Operator-visible summary of the next generation the planner would activate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProposedGenerationSnapshot {
    pub generation: GenerationId,
    pub config_path: String,
    pub log_level: String,
    pub listener_labels: Vec<String>,
    pub upstream_count: usize,
    pub backend_count: usize,
}

/// Kind of field/domain diff detected between the active and candidate
/// generations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ReloadChangeKind {
    Added,
    Modified,
    Removed,
    Unchanged,
}

/// Operator-visible disposition for a diff domain.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ReloadDiffDisposition {
    Reloadable,
    RejectedStartupOwned,
    NoOp,
}

/// One operator-visible entry in a reload preview diff.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReloadDiffEntry {
    pub domain: String,
    pub change: ReloadChangeKind,
    pub disposition: ReloadDiffDisposition,
    pub summary: String,
    /// True when this entry's change includes a secret- or certificate-backed
    /// material change (e.g. an upstream client cert/key or CA fingerprint),
    /// even if the referencing config path/ref string is unchanged. Lets
    /// operators spot secret rotations without parsing `summary` text.
    #[serde(default)]
    pub secret_material_changed: bool,
}

/// Canonical preview diff for a staged reload candidate.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReloadDiff {
    pub entries: Vec<ReloadDiffEntry>,
}

impl ReloadDiff {
    #[must_use]
    pub fn is_noop(&self) -> bool {
        self.entries.is_empty()
            || self
                .entries
                .iter()
                .all(|entry| matches!(entry.disposition, ReloadDiffDisposition::NoOp))
    }

    #[must_use]
    pub fn reloadable_entries(&self) -> Vec<&ReloadDiffEntry> {
        self.entries
            .iter()
            .filter(|entry| matches!(entry.disposition, ReloadDiffDisposition::Reloadable))
            .collect()
    }

    #[must_use]
    pub fn rejected_startup_owned_entries(&self) -> Vec<&ReloadDiffEntry> {
        self.entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry.disposition,
                    ReloadDiffDisposition::RejectedStartupOwned
                )
            })
            .collect()
    }

    #[must_use]
    pub fn noop_entries(&self) -> Vec<&ReloadDiffEntry> {
        self.entries
            .iter()
            .filter(|entry| matches!(entry.disposition, ReloadDiffDisposition::NoOp))
            .collect()
    }
}

/// Stable rejection category for preview/activation/rollback flows.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RejectedChangeKind {
    RestartRequired,
    ResourcePreparationFailed,
    InvalidConfiguration,
    IllegalTransition,
    RuntimeStateUnavailable,
}

impl From<TransitionRejectionKind> for RejectedChangeKind {
    fn from(value: TransitionRejectionKind) -> Self {
        match value {
            TransitionRejectionKind::RestartRequired => Self::RestartRequired,
            TransitionRejectionKind::ResourcePreparationFailed => Self::ResourcePreparationFailed,
            TransitionRejectionKind::InvalidConfiguration => Self::InvalidConfiguration,
            TransitionRejectionKind::IllegalTransition => Self::IllegalTransition,
            TransitionRejectionKind::RuntimeStateUnavailable => Self::RuntimeStateUnavailable,
        }
    }
}

/// Canonical operator-visible rejection payload for a planned change.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RejectedChange {
    pub reason: RuntimeRejectionReason,
    pub kind: RejectedChangeKind,
    pub field_path: Option<String>,
    pub current_value: Option<String>,
    pub requested_value: Option<String>,
    pub operator_action: String,
    pub active_generation_changed: bool,
    pub message: String,
}

impl From<TransitionRejection> for RejectedChange {
    fn from(value: TransitionRejection) -> Self {
        Self::from(&value)
    }
}

impl From<&TransitionRejection> for RejectedChange {
    fn from(value: &TransitionRejection) -> Self {
        Self {
            reason: runtime_rejection_reason_for_transition(value),
            kind: value.kind.into(),
            field_path: value.field_path.clone(),
            current_value: value.current_mode.clone(),
            requested_value: value.requested_mode.clone(),
            operator_action: value.operator_action.to_string(),
            active_generation_changed: value.active_runtime_changed,
            message: value.to_string(),
        }
    }
}

impl RejectedChange {
    fn invalid_configuration(message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            reason: RuntimeRejectionReason::InvalidConfig,
            kind: RejectedChangeKind::InvalidConfiguration,
            field_path: None,
            current_value: None,
            requested_value: None,
            operator_action: "fix the configuration and retry the reload".to_string(),
            active_generation_changed: false,
            message,
        }
    }

    fn resource_preparation_failed(
        field_path: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        let field_path = field_path.into();
        let detail = detail.into();
        let message = format!(
            "runtime reload rejected: could not prepare {field_path}: {detail}; active runtime unchanged (no change applied)"
        );
        Self {
            reason: runtime_rejection_reason_for_resource_failure(&field_path, &detail),
            kind: RejectedChangeKind::ResourcePreparationFailed,
            field_path: Some(field_path),
            current_value: None,
            requested_value: Some(detail),
            operator_action:
                "resolve the resource conflict (e.g. free the address/port) and retry the reload"
                    .to_string(),
            active_generation_changed: false,
            message,
        }
    }

    #[must_use]
    pub fn reason_slug(&self) -> &'static str {
        self.reason.slug()
    }
}

fn runtime_rejection_reason_for_transition(
    rejection: &TransitionRejection,
) -> RuntimeRejectionReason {
    match rejection.kind {
        TransitionRejectionKind::RestartRequired => RuntimeRejectionReason::StartupOwnedChange,
        TransitionRejectionKind::InvalidConfiguration => RuntimeRejectionReason::InvalidConfig,
        TransitionRejectionKind::IllegalTransition => RuntimeRejectionReason::IncompatibleReload,
        TransitionRejectionKind::RuntimeStateUnavailable => {
            RuntimeRejectionReason::UnknownGeneration
        }
        TransitionRejectionKind::ResourcePreparationFailed => {
            let field_path = rejection.field_path.as_deref().unwrap_or_default();
            let detail = rejection.requested_mode.as_deref().unwrap_or_default();
            runtime_rejection_reason_for_resource_failure(field_path, detail)
        }
    }
}

fn runtime_rejection_reason_for_resource_failure(
    field_path: &str,
    detail: &str,
) -> RuntimeRejectionReason {
    if field_path.contains("listener")
        || field_path.contains("endpoint")
        || detail.contains("Address already in use")
        || detail.contains("AddrInUse")
    {
        RuntimeRejectionReason::BindConflict
    } else {
        RuntimeRejectionReason::ResourcePrepareFailed
    }
}

/// Activation request metadata.
///
/// This intentionally carries only operator/audit context and concurrency
/// expectations. The actual config source stays outside this step until the
/// activation service is implemented.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActivationRequest {
    pub requested_by: Option<String>,
    pub trigger_source: Option<String>,
    pub reason: Option<String>,
    pub expected_generation: Option<GenerationId>,
    pub requested_at_ms: TimestampMillis,
}

/// Rollback request metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackRequest {
    pub target_generation: GenerationId,
    pub requested_by: Option<String>,
    pub trigger_source: Option<String>,
    pub reason: Option<String>,
    pub expected_active_generation: Option<GenerationId>,
    pub requested_at_ms: TimestampMillis,
}

/// Canonical staged plan returned by validate/preview flows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReloadPlan {
    pub request: ActivationRequest,
    pub config_source: String,
    pub config_version: Option<u32>,
    pub current_generation: Option<GenerationId>,
    pub candidate_generation: GenerationId,
    pub candidate_status: GenerationStatus,
    pub summary: String,
    pub validation: Vec<PlanningPhaseResult>,
    pub compatibility: ReloadCompatibilityClassification,
    pub candidate_snapshot: Option<ProposedGenerationSnapshot>,
    pub rejection_summary: Option<String>,
    pub diff: ReloadDiff,
    pub rejected_changes: Vec<RejectedChange>,
}

impl ReloadPlan {
    #[must_use]
    pub fn can_activate(&self) -> bool {
        self.rejected_changes.is_empty()
            && self.candidate_snapshot.is_some()
            && self.compatibility == ReloadCompatibilityClassification::LiveReloadable
            && !matches!(self.candidate_status, GenerationStatus::Rejected)
    }

    #[must_use]
    pub fn phase_status(&self, phase: PlanningPhase) -> Option<PlanningPhaseStatus> {
        self.validation
            .iter()
            .find(|result| result.phase == phase)
            .map(|result| result.status)
    }

    #[must_use]
    pub fn primary_rejection_reason(&self) -> Option<RuntimeRejectionReason> {
        self.rejected_changes
            .first()
            .map(|rejection| rejection.reason)
    }
}

/// Audit/history record for validation, preview, activation, and rollback.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenerationHistoryEntry {
    pub generation: GenerationId,
    pub operation: GenerationOperation,
    pub status: GenerationStatus,
    pub config_source: String,
    pub config_version: Option<u32>,
    pub requested_by: Option<String>,
    pub trigger_source: Option<String>,
    pub requested_at_ms: TimestampMillis,
    pub completed_at_ms: Option<TimestampMillis>,
    pub summary: String,
    pub diff: ReloadDiff,
    pub rejected_changes: Vec<RejectedChange>,
}

/// Structured change event emitted for runtime generation activity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenerationChangeEvent {
    pub kind: GenerationEventKind,
    pub emitted_at_ms: TimestampMillis,
    pub entry: GenerationHistoryEntry,
}

/// Canonical activation result payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActivationResult {
    pub request: ActivationRequest,
    pub active_generation: GenerationId,
    pub activated_generation: Option<GenerationId>,
    pub status: GenerationStatus,
    pub rejected_changes: Vec<RejectedChange>,
    pub history_entry: GenerationHistoryEntry,
}

impl ActivationResult {
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.activated_generation.is_some() && self.rejected_changes.is_empty()
    }

    #[must_use]
    pub fn primary_rejection_reason(&self) -> Option<RuntimeRejectionReason> {
        self.rejected_changes
            .first()
            .map(|rejection| rejection.reason)
    }

    #[must_use]
    pub fn outcome_reason(&self) -> RuntimeOperationOutcomeReason {
        self.primary_rejection_reason()
            .map(RuntimeOperationOutcomeReason::from_rejection_reason)
            .unwrap_or(RuntimeOperationOutcomeReason::Applied)
    }
}

/// Canonical rollback result payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackResult {
    pub request: RollbackRequest,
    pub active_generation: GenerationId,
    pub rolled_back_to: Option<GenerationId>,
    pub status: GenerationStatus,
    pub rejected_changes: Vec<RejectedChange>,
    pub history_entry: GenerationHistoryEntry,
}

impl RollbackResult {
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.rolled_back_to.is_some() && self.rejected_changes.is_empty()
    }

    #[must_use]
    pub fn primary_rejection_reason(&self) -> Option<RuntimeRejectionReason> {
        self.rejected_changes
            .first()
            .map(|rejection| rejection.reason)
    }

    #[must_use]
    pub fn outcome_reason(&self) -> RuntimeOperationOutcomeReason {
        self.primary_rejection_reason()
            .map(RuntimeOperationOutcomeReason::from_rejection_reason)
            .unwrap_or(RuntimeOperationOutcomeReason::Applied)
    }
}

pub(crate) fn plan_runtime_reload(
    current: &crate::runtime::bundle::ActiveRuntimeGeneration,
    request: ActivationRequest,
    input: ReloadConfigInput,
) -> service::StagedRuntimeReloadPlan {
    planning::plan_runtime_reload(current, request, input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::policy::TransitionRejection;

    #[test]
    fn rejected_change_preserves_transition_rejection_contract() {
        let rejection =
            TransitionRejection::restart_required("performance.worker_threads", "1", "8");
        let rejected = RejectedChange::from(rejection);

        assert_eq!(rejected.kind, RejectedChangeKind::RestartRequired);
        assert_eq!(
            rejected.field_path.as_deref(),
            Some("performance.worker_threads")
        );
        assert_eq!(
            rejected.operator_action,
            "restart the process to apply this change"
        );
        assert!(!rejected.active_generation_changed);
        assert!(rejected.message.contains("restart"));
    }

    #[test]
    fn reload_plan_only_activates_without_rejections() {
        let plan = ReloadPlan {
            request: ActivationRequest {
                requested_by: Some("operator".to_string()),
                trigger_source: Some("unit_test".to_string()),
                reason: Some("rotate routes".to_string()),
                expected_generation: Some(7),
                requested_at_ms: 1_720_000_000_000,
            },
            config_source: "config.yaml".to_string(),
            config_version: Some(1),
            current_generation: Some(7),
            candidate_generation: 8,
            candidate_status: GenerationStatus::Staged,
            summary: "listener policies unchanged".to_string(),
            validation: vec![PlanningPhaseResult {
                phase: PlanningPhase::EvaluateCompatibility,
                status: PlanningPhaseStatus::Accepted,
                summary: "reload candidate is live-reloadable".to_string(),
            }],
            compatibility: ReloadCompatibilityClassification::LiveReloadable,
            candidate_snapshot: Some(ProposedGenerationSnapshot {
                generation: 8,
                config_path: "config.yaml".to_string(),
                log_level: "info".to_string(),
                listener_labels: vec!["edge-primary".to_string()],
                upstream_count: 1,
                backend_count: 2,
            }),
            rejection_summary: None,
            diff: ReloadDiff::default(),
            rejected_changes: Vec::new(),
        };
        assert!(plan.can_activate());

        let mut rejected = plan.clone();
        rejected.rejected_changes.push(RejectedChange {
            reason: RuntimeRejectionReason::InvalidConfig,
            kind: RejectedChangeKind::InvalidConfiguration,
            field_path: Some("resilience.watchdog".to_string()),
            current_value: None,
            requested_value: Some("0".to_string()),
            operator_action: "fix the configuration and retry the reload".to_string(),
            active_generation_changed: false,
            message: "invalid watchdog value".to_string(),
        });
        assert!(!rejected.can_activate());
    }

    #[test]
    fn transition_rejections_map_to_stable_runtime_rejection_reasons() {
        let startup_owned = RejectedChange::from(TransitionRejection::restart_required(
            "performance.worker_threads",
            "1",
            "8",
        ));
        assert_eq!(
            startup_owned.reason,
            RuntimeRejectionReason::StartupOwnedChange
        );

        let bind_conflict = RejectedChange::from(TransitionRejection::resource_preflight_failed(
            "metrics listener",
            "127.0.0.1:9090",
            "bind conflict on 127.0.0.1:9090",
        ));
        assert_eq!(bind_conflict.reason, RuntimeRejectionReason::BindConflict);

        let incompatible = RejectedChange::from(TransitionRejection {
            kind: crate::runtime::policy::TransitionRejectionKind::IllegalTransition,
            field_path: None,
            current_mode: Some("Draining".to_string()),
            requested_mode: Some("Reload".to_string()),
            operator_action: "wait for the current lifecycle phase to complete; the requested transition is not legal now",
            active_runtime_changed: false,
            verbatim: None,
        });
        assert_eq!(
            incompatible.reason,
            RuntimeRejectionReason::IncompatibleReload
        );
    }

    #[test]
    fn activation_and_rollback_results_expose_stable_outcome_reasons() {
        let request = ActivationRequest {
            requested_by: Some("operator".to_string()),
            trigger_source: Some("unit_test".to_string()),
            reason: Some("reload".to_string()),
            expected_generation: Some(3),
            requested_at_ms: 10,
        };
        let rejected = RejectedChange {
            reason: RuntimeRejectionReason::InvalidConfig,
            kind: RejectedChangeKind::InvalidConfiguration,
            field_path: Some("log.level".to_string()),
            current_value: Some("info".to_string()),
            requested_value: Some("".to_string()),
            operator_action: "fix config".to_string(),
            active_generation_changed: false,
            message: "invalid config".to_string(),
        };
        let activation = ActivationResult {
            request: request.clone(),
            active_generation: 3,
            activated_generation: None,
            status: GenerationStatus::Rejected,
            rejected_changes: vec![rejected.clone()],
            history_entry: GenerationHistoryEntry {
                generation: 4,
                operation: GenerationOperation::Activate,
                status: GenerationStatus::Rejected,
                config_source: "runtime.yaml".to_string(),
                config_version: Some(1),
                requested_by: Some("operator".to_string()),
                trigger_source: Some("unit_test".to_string()),
                requested_at_ms: 10,
                completed_at_ms: Some(11),
                summary: "rejected".to_string(),
                diff: ReloadDiff::default(),
                rejected_changes: vec![rejected.clone()],
            },
        };
        assert_eq!(
            activation.outcome_reason(),
            RuntimeOperationOutcomeReason::InvalidConfig
        );

        let rollback = RollbackResult {
            request: RollbackRequest {
                target_generation: 2,
                requested_by: Some("operator".to_string()),
                trigger_source: Some("unit_test".to_string()),
                reason: Some("rollback".to_string()),
                expected_active_generation: Some(4),
                requested_at_ms: 12,
            },
            active_generation: 5,
            rolled_back_to: Some(2),
            status: GenerationStatus::RolledBack,
            rejected_changes: Vec::new(),
            history_entry: GenerationHistoryEntry {
                generation: 5,
                operation: GenerationOperation::Rollback,
                status: GenerationStatus::RolledBack,
                config_source: "generation:2".to_string(),
                config_version: Some(1),
                requested_by: Some("operator".to_string()),
                trigger_source: Some("unit_test".to_string()),
                requested_at_ms: 12,
                completed_at_ms: Some(13),
                summary: "rolled back".to_string(),
                diff: ReloadDiff::default(),
                rejected_changes: Vec::new(),
            },
        };
        assert_eq!(
            rollback.outcome_reason(),
            RuntimeOperationOutcomeReason::Applied
        );
    }
}
