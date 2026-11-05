use super::{
    service::{RejectedActivationResultInput, RejectedRollbackResultInput},
    *,
};
use crate::runtime::bundle::RuntimeBundleHandle;

pub(super) fn record_validation_result(handle: &RuntimeBundleHandle, plan: &ReloadPlan) {
    let validation_entry = validation_history_entry(plan);
    record_history_event(handle, GenerationEventKind::Validation, validation_entry);
}

pub(super) fn record_preview_result(handle: &RuntimeBundleHandle, plan: &ReloadPlan) {
    let preview_entry = preview_history_entry(plan);
    record_history_event(handle, GenerationEventKind::Preview, preview_entry);
}

pub(super) fn record_activation_result(handle: &RuntimeBundleHandle, result: &ActivationResult) {
    handle
        .current_view()
        .shared_services()
        .metrics
        .plugin_observations()
        .record_activation(if result.succeeded() {
            impulse_contracts::PluginActivationOutcome::Success
        } else {
            impulse_contracts::PluginActivationOutcome::Failure
        });
    let kind = if result.succeeded() {
        GenerationEventKind::ActivationSucceeded
    } else {
        GenerationEventKind::ActivationFailed
    };
    record_history_event(handle, kind, result.history_entry.clone());
}

pub(super) fn record_rollback_result(handle: &RuntimeBundleHandle, result: &RollbackResult) {
    let kind = if result.succeeded() {
        GenerationEventKind::RollbackSucceeded
    } else {
        GenerationEventKind::RollbackFailed
    };
    record_history_event(handle, kind, result.history_entry.clone());
}

fn record_history_event(
    handle: &RuntimeBundleHandle,
    kind: GenerationEventKind,
    entry: GenerationHistoryEntry,
) {
    let emitted_at_ms = entry.completed_at_ms.unwrap_or(entry.requested_at_ms);
    handle.record_generation_history_entry(entry.clone());
    handle.record_generation_change_event(GenerationChangeEvent {
        kind,
        emitted_at_ms,
        entry,
    });
}

fn validation_history_entry(plan: &ReloadPlan) -> GenerationHistoryEntry {
    let completed_at_ms = impulse_operations::watchdog::now_millis();
    let status = if plan
        .validation
        .iter()
        .any(|result| matches!(result.status, PlanningPhaseStatus::Rejected))
    {
        GenerationStatus::Rejected
    } else {
        GenerationStatus::Staged
    };
    GenerationHistoryEntry {
        generation: plan.candidate_generation,
        operation: GenerationOperation::Validate,
        status,
        config_source: plan.config_source.clone(),
        config_version: plan.config_version,
        requested_by: plan.request.requested_by.clone(),
        trigger_source: plan.request.trigger_source.clone(),
        requested_at_ms: plan.request.requested_at_ms,
        completed_at_ms: Some(completed_at_ms),
        summary: summarize_validation_results(plan),
        diff: ReloadDiff::default(),
        rejected_changes: plan.rejected_changes.clone(),
    }
}

fn preview_history_entry(plan: &ReloadPlan) -> GenerationHistoryEntry {
    let completed_at_ms = impulse_operations::watchdog::now_millis();
    GenerationHistoryEntry {
        generation: plan.candidate_generation,
        operation: GenerationOperation::Preview,
        status: plan.candidate_status,
        config_source: plan.config_source.clone(),
        config_version: plan.config_version,
        requested_by: plan.request.requested_by.clone(),
        trigger_source: plan.request.trigger_source.clone(),
        requested_at_ms: plan.request.requested_at_ms,
        completed_at_ms: Some(completed_at_ms),
        summary: plan.summary.clone(),
        diff: plan.diff.clone(),
        rejected_changes: plan.rejected_changes.clone(),
    }
}

fn summarize_validation_results(plan: &ReloadPlan) -> String {
    plan.validation
        .iter()
        .map(|result| format!("{:?}: {}", result.phase, result.summary))
        .collect::<Vec<_>>()
        .join("; ")
}

pub(super) fn successful_rollback_result(
    request: RollbackRequest,
    generation: GenerationId,
    target_generation: GenerationId,
    config_source: String,
    config_version: Option<u32>,
    diff: ReloadDiff,
) -> RollbackResult {
    let completed_at_ms = impulse_operations::watchdog::now_millis();
    let history_entry = GenerationHistoryEntry {
        generation,
        operation: GenerationOperation::Rollback,
        status: GenerationStatus::RolledBack,
        config_source,
        config_version,
        requested_by: request.requested_by.clone(),
        trigger_source: request.trigger_source.clone(),
        requested_at_ms: request.requested_at_ms,
        completed_at_ms: Some(completed_at_ms),
        summary: format!(
            "rolled back runtime to retained generation {} as new active generation {}",
            target_generation, generation
        ),
        diff,
        rejected_changes: Vec::new(),
    };

    RollbackResult {
        request,
        active_generation: generation,
        rolled_back_to: Some(target_generation),
        status: GenerationStatus::RolledBack,
        rejected_changes: Vec::new(),
        history_entry,
    }
}

pub(super) fn rejected_rollback_result(input: RejectedRollbackResultInput) -> RollbackResult {
    let completed_at_ms = impulse_operations::watchdog::now_millis();
    let history_entry = GenerationHistoryEntry {
        generation: input
            .target_generation
            .unwrap_or(input.active_generation.saturating_add(1)),
        operation: GenerationOperation::Rollback,
        status: GenerationStatus::Rejected,
        config_source: input.config_source,
        config_version: input.config_version,
        requested_by: input.request.requested_by.clone(),
        trigger_source: input.request.trigger_source.clone(),
        requested_at_ms: input.request.requested_at_ms,
        completed_at_ms: Some(completed_at_ms),
        summary: input.summary,
        diff: input.diff,
        rejected_changes: input.rejected_changes.clone(),
    };

    RollbackResult {
        request: input.request,
        active_generation: input.active_generation,
        rolled_back_to: None,
        status: GenerationStatus::Rejected,
        rejected_changes: input.rejected_changes,
        history_entry,
    }
}

pub(super) fn failed_rollback_result(
    request: RollbackRequest,
    active_generation: GenerationId,
    target_generation: GenerationId,
    config_source: String,
    config_version: Option<u32>,
    diff: ReloadDiff,
    error: String,
) -> RollbackResult {
    let rejected_changes = vec![RejectedChange {
        reason: RuntimeRejectionReason::RollbackNotAllowed,
        kind: RejectedChangeKind::RuntimeStateUnavailable,
        field_path: Some("runtime.rollback".to_string()),
        current_value: Some(active_generation.to_string()),
        requested_value: Some(target_generation.to_string()),
        operator_action: "inspect runtime state and retry the rollback once the runtime is healthy"
            .to_string(),
        active_generation_changed: false,
        message: error.clone(),
    }];
    let completed_at_ms = impulse_operations::watchdog::now_millis();
    let history_entry = GenerationHistoryEntry {
        generation: active_generation.saturating_add(1),
        operation: GenerationOperation::Rollback,
        status: GenerationStatus::Failed,
        config_source,
        config_version,
        requested_by: request.requested_by.clone(),
        trigger_source: request.trigger_source.clone(),
        requested_at_ms: request.requested_at_ms,
        completed_at_ms: Some(completed_at_ms),
        summary: format!(
            "failed to roll back runtime to retained generation {}: {}",
            target_generation, error
        ),
        diff,
        rejected_changes: rejected_changes.clone(),
    };

    RollbackResult {
        request,
        active_generation,
        rolled_back_to: None,
        status: GenerationStatus::Failed,
        rejected_changes,
        history_entry,
    }
}

pub(super) fn successful_activation_result(
    request: ActivationRequest,
    generation: GenerationId,
    config_source: String,
    config_version: Option<u32>,
    diff: ReloadDiff,
    previous_log_level: String,
    active_log_level: String,
) -> ActivationResult {
    let completed_at_ms = impulse_operations::watchdog::now_millis();
    let history_entry = GenerationHistoryEntry {
        generation,
        operation: GenerationOperation::Activate,
        status: GenerationStatus::Active,
        config_source,
        config_version,
        requested_by: request.requested_by.clone(),
        trigger_source: request.trigger_source.clone(),
        requested_at_ms: request.requested_at_ms,
        completed_at_ms: Some(completed_at_ms),
        summary: format!(
            "activated runtime generation {generation} (log.level: {previous_log_level} -> {active_log_level}){}",
            activation_summary_suffix(&diff)
        ),
        diff,
        rejected_changes: Vec::new(),
    };

    ActivationResult {
        request,
        active_generation: generation,
        activated_generation: Some(generation),
        status: GenerationStatus::Active,
        rejected_changes: Vec::new(),
        history_entry,
    }
}

fn activation_summary_suffix(diff: &ReloadDiff) -> &'static str {
    if diff
        .entries
        .iter()
        .any(|entry| entry.secret_material_changed)
    {
        " [upstream_mtls_material_changed]"
    } else {
        ""
    }
}

pub(super) fn rejected_activation_result(input: RejectedActivationResultInput) -> ActivationResult {
    let completed_at_ms = impulse_operations::watchdog::now_millis();
    let history_entry = GenerationHistoryEntry {
        generation: input.candidate_generation,
        operation: GenerationOperation::Activate,
        status: GenerationStatus::Rejected,
        config_source: input.config_source,
        config_version: input.config_version,
        requested_by: input.request.requested_by.clone(),
        trigger_source: input.request.trigger_source.clone(),
        requested_at_ms: input.request.requested_at_ms,
        completed_at_ms: Some(completed_at_ms),
        summary: input.summary,
        diff: input.diff,
        rejected_changes: input.rejected_changes.clone(),
    };

    ActivationResult {
        request: input.request,
        active_generation: input.active_generation,
        activated_generation: None,
        status: GenerationStatus::Rejected,
        rejected_changes: input.rejected_changes,
        history_entry,
    }
}

pub(super) fn failed_activation_result(
    request: ActivationRequest,
    active_generation: GenerationId,
    candidate_generation: GenerationId,
    config_source: String,
    config_version: Option<u32>,
    diff: ReloadDiff,
    error: String,
) -> ActivationResult {
    let rejected_changes = vec![RejectedChange {
        reason: RuntimeRejectionReason::IncompatibleReload,
        kind: RejectedChangeKind::RuntimeStateUnavailable,
        field_path: Some("runtime.activation".to_string()),
        current_value: Some(active_generation.to_string()),
        requested_value: Some(candidate_generation.to_string()),
        operator_action:
            "inspect runtime state and retry the activation once the runtime is healthy".to_string(),
        active_generation_changed: false,
        message: error.clone(),
    }];
    let completed_at_ms = impulse_operations::watchdog::now_millis();
    let history_entry = GenerationHistoryEntry {
        generation: candidate_generation,
        operation: GenerationOperation::Activate,
        status: GenerationStatus::Failed,
        config_source,
        config_version,
        requested_by: request.requested_by.clone(),
        trigger_source: request.trigger_source.clone(),
        requested_at_ms: request.requested_at_ms,
        completed_at_ms: Some(completed_at_ms),
        summary: format!("failed to activate runtime generation {candidate_generation}: {error}"),
        diff,
        rejected_changes: rejected_changes.clone(),
    };

    ActivationResult {
        request,
        active_generation,
        activated_generation: None,
        status: GenerationStatus::Failed,
        rejected_changes,
        history_entry,
    }
}
