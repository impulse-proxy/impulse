use super::{
    diff::{build_reload_diff, rejected_startup_owned_domains},
    history::{
        failed_activation_result, failed_rollback_result, record_activation_result,
        record_preview_result, record_rollback_result, record_validation_result,
        rejected_activation_result, rejected_rollback_result, successful_activation_result,
        successful_rollback_result,
    },
    swap::{commit_runtime_bundle_swap, commit_staged_runtime_reload, prepare_rollback_bundle},
    *,
};
use crate::runtime::{
    activation::compatibility::evaluate_runtime_reload_compatibility,
    bundle::{RuntimeBundle, RuntimeBundleHandle, RuntimeGenerationRecordStatus},
    policy::render_rejections,
};

/// Internal, non-serialized staged runtime reload result.
///
/// This is the pure planning payload that control-plane code can validate and
/// preview before any activation mutates the active bundle.
pub(crate) struct StagedRuntimeReloadPlan {
    pub(crate) plan: ReloadPlan,
    pub(crate) next_runtime: Option<RuntimeBundle>,
}

impl StagedRuntimeReloadPlan {
    #[must_use]
    pub(crate) fn can_activate(&self) -> bool {
        self.plan.can_activate() && self.next_runtime.is_some()
    }
}

/// Canonical runtime activation service.
///
/// This owns the activation transaction for runtime reloads:
/// staged validation/planning, final lifecycle gate, generation swap, and the
/// explicit result object returned to control-plane callers.
pub(crate) struct RuntimeActivationService;

pub(super) struct RejectedRollbackResultInput {
    pub(super) request: RollbackRequest,
    pub(super) active_generation: GenerationId,
    pub(super) target_generation: Option<GenerationId>,
    pub(super) config_source: String,
    pub(super) config_version: Option<u32>,
    pub(super) diff: ReloadDiff,
    pub(super) rejected_changes: Vec<RejectedChange>,
    pub(super) summary: String,
}

pub(super) struct RejectedActivationResultInput {
    pub(super) request: ActivationRequest,
    pub(super) active_generation: GenerationId,
    pub(super) candidate_generation: GenerationId,
    pub(super) config_source: String,
    pub(super) config_version: Option<u32>,
    pub(super) diff: ReloadDiff,
    pub(super) rejected_changes: Vec<RejectedChange>,
    pub(super) summary: String,
}

impl RuntimeActivationService {
    pub(crate) fn validate_reload(
        handle: &RuntimeBundleHandle,
        request: ActivationRequest,
        input: ReloadConfigInput,
    ) -> ReloadPlan {
        let plan = Self::stage_reload(handle, request, input);
        record_validation_result(handle, &plan.plan);
        plan.plan
    }

    pub(crate) fn preview_reload(
        handle: &RuntimeBundleHandle,
        request: ActivationRequest,
        input: ReloadConfigInput,
    ) -> ReloadPlan {
        let plan = Self::stage_reload(handle, request, input);
        record_preview_result(handle, &plan.plan);
        plan.plan
    }

    pub(crate) fn activate_reload(
        handle: &RuntimeBundleHandle,
        request: ActivationRequest,
        input: ReloadConfigInput,
    ) -> ActivationResult {
        let current = handle.current_view();
        let active_generation = current.generation();
        let current_log_level = current.startup().log_config.level.clone();
        let config_source = input.source_label();

        if let Some(expected_generation) = request.expected_generation
            && expected_generation != active_generation
        {
            let result = rejected_activation_result(RejectedActivationResultInput {
                request,
                active_generation,
                candidate_generation: active_generation.saturating_add(1),
                config_source,
                config_version: None,
                diff: ReloadDiff::default(),
                rejected_changes: vec![RejectedChange {
                    reason: RuntimeRejectionReason::UnknownGeneration,
                    kind: RejectedChangeKind::IllegalTransition,
                    field_path: Some("runtime.generation".to_string()),
                    current_value: Some(active_generation.to_string()),
                    requested_value: Some(expected_generation.to_string()),
                    operator_action: "refresh the active generation view and retry the activation"
                        .to_string(),
                    active_generation_changed: false,
                    message: format!(
                        "runtime reload rejected: expected active generation {} but current active generation is {}",
                        expected_generation, active_generation
                    ),
                }],
                summary: "activation request targeted a stale runtime generation".to_string(),
            });
            record_activation_result(handle, &result);
            return result;
        }

        let plan = Self::stage_reload(handle, request.clone(), input);
        if !plan.can_activate() {
            if plan.plan.rejected_changes.iter().any(|rejection| {
                matches!(
                    rejection.kind,
                    RejectedChangeKind::ResourcePreparationFailed
                )
            }) {
                handle.record_failed_prepare(
                    plan.plan.candidate_generation,
                    plan.plan
                        .rejection_summary
                        .clone()
                        .unwrap_or_else(|| plan.plan.summary.clone()),
                );
            }
            let result = rejected_activation_result(RejectedActivationResultInput {
                request,
                active_generation,
                candidate_generation: plan.plan.candidate_generation,
                config_source: plan.plan.config_source.clone(),
                config_version: plan.plan.config_version,
                diff: plan.plan.diff.clone(),
                rejected_changes: plan.plan.rejected_changes.clone(),
                summary: plan
                    .plan
                    .rejection_summary
                    .clone()
                    .unwrap_or_else(|| plan.plan.summary.clone()),
            });
            record_activation_result(handle, &result);
            return result;
        }

        if let Some(rejection) = handle.lifecycle().check_reload_allowed().rejection() {
            let result = rejected_activation_result(RejectedActivationResultInput {
                request,
                active_generation,
                candidate_generation: plan.plan.candidate_generation,
                config_source: plan.plan.config_source.clone(),
                config_version: plan.plan.config_version,
                diff: plan.plan.diff.clone(),
                rejected_changes: vec![RejectedChange::from(rejection)],
                summary: rejection.to_string(),
            });
            record_activation_result(handle, &result);
            return result;
        }

        let config_source = plan.plan.config_source.clone();
        let config_version = plan.plan.config_version;
        let result = match commit_staged_runtime_reload(handle, plan) {
            Ok((generation, diff)) => successful_activation_result(
                request,
                generation,
                config_source,
                config_version,
                diff,
                current_log_level,
                handle.current_view().startup().log_config.level.clone(),
            ),
            Err((candidate_generation, diff, err)) => failed_activation_result(
                request,
                handle.current_generation(),
                candidate_generation,
                config_source,
                config_version,
                diff,
                err,
            ),
        };
        record_activation_result(handle, &result);
        result
    }

    pub(crate) fn rollback_generation(
        handle: &RuntimeBundleHandle,
        request: RollbackRequest,
    ) -> RollbackResult {
        let current = handle.current_view();
        let active_generation = current.generation();
        let target_generation = request.target_generation;
        let fallback_config_source = format!("generation:{target_generation}");

        if let Some(expected_active_generation) = request.expected_active_generation
            && expected_active_generation != active_generation
        {
            let result = rejected_rollback_result(RejectedRollbackResultInput {
                request,
                active_generation,
                target_generation: None,
                config_source: fallback_config_source.clone(),
                config_version: None,
                diff: ReloadDiff::default(),
                rejected_changes: vec![RejectedChange {
                    reason: RuntimeRejectionReason::UnknownGeneration,
                    kind: RejectedChangeKind::IllegalTransition,
                    field_path: Some("runtime.generation".to_string()),
                    current_value: Some(active_generation.to_string()),
                    requested_value: Some(expected_active_generation.to_string()),
                    operator_action: "refresh the active generation view and retry the rollback"
                        .to_string(),
                    active_generation_changed: false,
                    message: format!(
                        "runtime rollback rejected: expected active generation {} but current active generation is {}",
                        expected_active_generation, active_generation
                    ),
                }],
                summary: "rollback request targeted a stale runtime generation".to_string(),
            });
            record_rollback_result(handle, &result);
            return result;
        }

        if request.target_generation == active_generation {
            let result = rejected_rollback_result(RejectedRollbackResultInput {
                request,
                active_generation,
                target_generation: None,
                config_source: fallback_config_source.clone(),
                config_version: None,
                diff: ReloadDiff::default(),
                rejected_changes: vec![RejectedChange {
                    reason: RuntimeRejectionReason::RollbackNotAllowed,
                    kind: RejectedChangeKind::IllegalTransition,
                    field_path: Some("runtime.rollback.target_generation".to_string()),
                    current_value: Some(active_generation.to_string()),
                    requested_value: Some(active_generation.to_string()),
                    operator_action:
                        "choose an older retained generation if rollback is still required"
                            .to_string(),
                    active_generation_changed: false,
                    message: format!(
                        "runtime rollback rejected: generation {} is already active",
                        active_generation
                    ),
                }],
                summary: "rollback target is already the active generation".to_string(),
            });
            record_rollback_result(handle, &result);
            return result;
        }

        let Some(target_record) = handle.generation_record(target_generation) else {
            let result = rejected_rollback_result(RejectedRollbackResultInput {
                request,
                active_generation,
                target_generation: None,
                config_source: fallback_config_source.clone(),
                config_version: None,
                diff: ReloadDiff::default(),
                rejected_changes: vec![RejectedChange {
                    reason: RuntimeRejectionReason::UnknownGeneration,
                    kind: RejectedChangeKind::RuntimeStateUnavailable,
                    field_path: Some("runtime.rollback.target_generation".to_string()),
                    current_value: None,
                    requested_value: Some(target_generation.to_string()),
                    operator_action: "choose a retained known-good generation from runtime history"
                        .to_string(),
                    active_generation_changed: false,
                    message: format!(
                        "runtime rollback rejected: generation {} is not retained as a rollback candidate",
                        target_generation
                    ),
                }],
                summary: "rollback target is not retained in runtime history".to_string(),
            });
            record_rollback_result(handle, &result);
            return result;
        };

        if !target_record.status().is_rollback_candidate() || !target_record.has_bundle() {
            let result = rejected_rollback_result(RejectedRollbackResultInput {
                request,
                active_generation,
                target_generation: Some(target_generation),
                config_source: fallback_config_source.clone(),
                config_version: None,
                diff: ReloadDiff::default(),
                rejected_changes: vec![RejectedChange {
                    reason: RuntimeRejectionReason::RollbackNotAllowed,
                    kind: RejectedChangeKind::RuntimeStateUnavailable,
                    field_path: Some("runtime.rollback.target_generation".to_string()),
                    current_value: Some(target_record.generation().to_string()),
                    requested_value: Some(target_record.status().as_str().to_string()),
                    operator_action:
                        "choose a complete retained generation with a usable runtime bundle"
                            .to_string(),
                    active_generation_changed: false,
                    message: format!(
                        "runtime rollback rejected: generation {} is incomplete or not a usable rollback candidate",
                        target_generation
                    ),
                }],
                summary: "rollback target is incomplete or unusable".to_string(),
            });
            record_rollback_result(handle, &result);
            return result;
        }

        if let Some(rejection) = handle.lifecycle().check_reload_allowed().rejection() {
            let result = rejected_rollback_result(RejectedRollbackResultInput {
                request,
                active_generation,
                target_generation: Some(target_generation),
                config_source: fallback_config_source.clone(),
                config_version: None,
                diff: ReloadDiff::default(),
                rejected_changes: vec![RejectedChange::from(rejection)],
                summary: rejection.to_string(),
            });
            record_rollback_result(handle, &result);
            return result;
        }

        let Some(target_bundle) = target_record.bundle().cloned() else {
            let result = rejected_rollback_result(RejectedRollbackResultInput {
                request,
                active_generation,
                target_generation: Some(target_generation),
                config_source: fallback_config_source.clone(),
                config_version: None,
                diff: ReloadDiff::default(),
                rejected_changes: vec![RejectedChange {
                    reason: RuntimeRejectionReason::RollbackNotAllowed,
                    kind: RejectedChangeKind::RuntimeStateUnavailable,
                    field_path: Some("runtime.rollback.target_generation".to_string()),
                    current_value: Some(target_record.generation().to_string()),
                    requested_value: Some("missing_bundle".to_string()),
                    operator_action:
                        "choose a complete retained generation with a usable runtime bundle"
                            .to_string(),
                    active_generation_changed: false,
                    message: format!(
                        "runtime rollback rejected: generation {} has no retained runtime bundle",
                        target_generation
                    ),
                }],
                summary: "rollback target has no retained runtime bundle".to_string(),
            });
            record_rollback_result(handle, &result);
            return result;
        };
        let rollback_config_source = target_bundle.startup.config_path.clone();
        let rollback_config_version = Some(target_bundle.runtime_config.version);
        let candidate_generation = active_generation.saturating_add(1);
        let prepared = match prepare_rollback_bundle(&current, &target_bundle, candidate_generation)
        {
            Ok(prepared) => prepared,
            Err(rejected) => {
                let rejected = *rejected;
                handle.record_failed_prepare(candidate_generation, rejected.message.clone());
                let result = rejected_rollback_result(RejectedRollbackResultInput {
                    request,
                    active_generation,
                    target_generation: Some(target_generation),
                    config_source: rollback_config_source.clone(),
                    config_version: rollback_config_version,
                    diff: ReloadDiff::default(),
                    rejected_changes: vec![rejected],
                    summary: "rollback preparation failed".to_string(),
                });
                record_rollback_result(handle, &result);
                return result;
            }
        };

        let compatibility_rejections = evaluate_runtime_reload_compatibility(&current, &prepared);
        if let Err(rejections) = compatibility_rejections {
            let rejected_changes = rejections
                .iter()
                .map(RejectedChange::from)
                .collect::<Vec<_>>();
            let diff = build_reload_diff(
                current.bundle(),
                &prepared,
                rejected_startup_owned_domains(&rejected_changes),
            );
            let result = rejected_rollback_result(RejectedRollbackResultInput {
                request,
                active_generation,
                target_generation: Some(target_generation),
                config_source: rollback_config_source.clone(),
                config_version: rollback_config_version,
                diff,
                rejected_changes,
                summary: render_rejections(rejections.as_slice()),
            });
            record_rollback_result(handle, &result);
            return result;
        }

        let diff = build_reload_diff(
            current.bundle(),
            &prepared,
            std::collections::HashSet::new(),
        );
        let result = match commit_runtime_bundle_swap(
            handle,
            prepared,
            RuntimeGenerationRecordStatus::RolledBack,
            Some(active_generation),
        ) {
            Ok(generation) => successful_rollback_result(
                request,
                generation,
                target_generation,
                rollback_config_source,
                rollback_config_version,
                diff,
            ),
            Err(err) => failed_rollback_result(
                request,
                handle.current_generation(),
                target_generation,
                rollback_config_source,
                rollback_config_version,
                diff,
                err.to_string(),
            ),
        };
        record_rollback_result(handle, &result);
        result
    }

    fn stage_reload(
        handle: &RuntimeBundleHandle,
        request: ActivationRequest,
        input: ReloadConfigInput,
    ) -> StagedRuntimeReloadPlan {
        let current = handle.current_view();
        super::plan_runtime_reload(&current, request, input)
    }
}
