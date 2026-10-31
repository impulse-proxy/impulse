use std::sync::Arc;

use impulse_config::{loader::read_config, runtime::RuntimeConfig};

use super::{
    diff::{
        build_reload_diff, classify_compatibility, rejected_startup_owned_domains,
        snapshot_from_bundle,
    },
    service::StagedRuntimeReloadPlan,
    *,
};
use crate::runtime::{
    activation::compatibility::evaluate_runtime_reload_compatibility,
    builder::RuntimeBuilder,
    bundle::{ActiveRuntimeGeneration, RuntimeBundle},
    generation::CarriedProcessSharedServices,
    listener::QUICListener,
    policy::{TransitionRejection, render_rejections},
};

pub(crate) fn plan_runtime_reload(
    current: &ActiveRuntimeGeneration,
    request: ActivationRequest,
    input: ReloadConfigInput,
) -> StagedRuntimeReloadPlan {
    let config_source = input.source_label();
    let current_generation = Some(current.generation());
    let candidate_generation = current.generation().saturating_add(1);
    let mut validation = Vec::with_capacity(4);

    let config = match input {
        ReloadConfigInput::Path { path } => match read_config(&path) {
            Ok(config) => {
                validation.push(PlanningPhaseResult {
                    phase: PlanningPhase::ReadConfig,
                    status: PlanningPhaseStatus::Accepted,
                    summary: format!("read config from '{path}'"),
                });
                config
            }
            Err(err) => {
                validation.push(PlanningPhaseResult {
                    phase: PlanningPhase::ReadConfig,
                    status: PlanningPhaseStatus::Rejected,
                    summary: err.clone(),
                });
                return rejected_reload_plan(
                    request,
                    config_source,
                    None,
                    current_generation,
                    candidate_generation,
                    validation,
                    vec![RejectedChange::invalid_configuration(err)],
                );
            }
        },
    };

    match impulse_config::validator::validate(&config) {
        Ok(()) => validation.push(PlanningPhaseResult {
            phase: PlanningPhase::ValidateConfig,
            status: PlanningPhaseStatus::Accepted,
            summary: "raw config validation passed".to_string(),
        }),
        Err(err) => {
            let message = format!("Configuration validation failed: {err}");
            validation.push(PlanningPhaseResult {
                phase: PlanningPhase::ValidateConfig,
                status: PlanningPhaseStatus::Rejected,
                summary: message.clone(),
            });
            return rejected_reload_plan(
                request,
                config_source,
                Some(config.version),
                current_generation,
                candidate_generation,
                validation,
                vec![RejectedChange::invalid_configuration(message)],
            );
        }
    }

    let runtime_config = match RuntimeConfig::from_config(&config) {
        Ok(runtime_config) => runtime_config,
        Err(err) => {
            let message = format!("Runtime configuration normalization failed: {err}");
            validation.push(PlanningPhaseResult {
                phase: PlanningPhase::NormalizeRuntime,
                status: PlanningPhaseStatus::Rejected,
                summary: message.clone(),
            });
            return rejected_reload_plan(
                request,
                config_source,
                Some(config.version),
                current_generation,
                candidate_generation,
                validation,
                vec![RejectedChange::invalid_configuration(message)],
            );
        }
    };

    if let Err(err) =
        QUICListener::preflight_require_ready_jwks(&runtime_config, "reload_preflight")
    {
        let rejected =
            RejectedChange::resource_preparation_failed("runtime jwks preflight", err.to_string());
        validation.push(PlanningPhaseResult {
            phase: PlanningPhase::NormalizeRuntime,
            status: PlanningPhaseStatus::Rejected,
            summary: rejected.message.clone(),
        });
        return rejected_reload_plan(
            request,
            config_source,
            Some(config.version),
            current_generation,
            candidate_generation,
            validation,
            vec![rejected],
        );
    }

    let carried = CarriedProcessSharedServices::from_active(current.shared_services());
    let next_shared_state =
        match RuntimeBuilder::rebuild_generation(&runtime_config, carried, candidate_generation) {
            Ok(shared_state) => {
                validation.push(PlanningPhaseResult {
                    phase: PlanningPhase::NormalizeRuntime,
                    status: PlanningPhaseStatus::Accepted,
                    summary: "runtime generation assembled successfully".to_string(),
                });
                Arc::new(shared_state)
            }
            Err(err) => {
                let rejected = RejectedChange::resource_preparation_failed(
                    "runtime generation",
                    err.to_string(),
                );
                validation.push(PlanningPhaseResult {
                    phase: PlanningPhase::NormalizeRuntime,
                    status: PlanningPhaseStatus::Rejected,
                    summary: rejected.message.clone(),
                });
                return rejected_reload_plan(
                    request,
                    config_source,
                    Some(config.version),
                    current_generation,
                    candidate_generation,
                    validation,
                    vec![rejected],
                );
            }
        };

    let next_runtime = RuntimeBundle {
        generation: candidate_generation,
        startup: crate::runtime::generation::StartupOwnedRuntimeState {
            config_path: config_source.clone(),
            log_config: config.log.clone(),
        },
        runtime_config,
        shared_state: next_shared_state,
    };
    let candidate_snapshot = Some(snapshot_from_bundle(&next_runtime));

    let compatibility_rejections: Result<(), Vec<TransitionRejection>> =
        evaluate_runtime_reload_compatibility(current, &next_runtime);
    let (compatibility, rejected_changes, compatibility_summary, candidate_status) =
        match compatibility_rejections {
            Ok(()) => (
                ReloadCompatibilityClassification::LiveReloadable,
                Vec::new(),
                "reload candidate is live-reloadable".to_string(),
                GenerationStatus::Staged,
            ),
            Err(rejections) => {
                let classification = classify_compatibility(&rejections);
                let rendered = render_rejections(rejections.as_slice());
                (
                    classification,
                    rejections.into_iter().map(RejectedChange::from).collect(),
                    rendered,
                    GenerationStatus::Rejected,
                )
            }
        };
    validation.push(PlanningPhaseResult {
        phase: PlanningPhase::EvaluateCompatibility,
        status: if rejected_changes.is_empty() {
            PlanningPhaseStatus::Accepted
        } else {
            PlanningPhaseStatus::Rejected
        },
        summary: compatibility_summary.clone(),
    });
    let diff = build_reload_diff(
        current.bundle(),
        &next_runtime,
        rejected_startup_owned_domains(&rejected_changes),
    );

    let rejection_summary = (!rejected_changes.is_empty()).then(|| compatibility_summary.clone());
    let summary = if rejected_changes.is_empty() {
        format!(
            "validated reload candidate for generation {candidate_generation}; ready for activation"
        )
    } else {
        format!(
            "validated reload candidate for generation {candidate_generation}; activation blocked"
        )
    };

    StagedRuntimeReloadPlan {
        plan: ReloadPlan {
            request,
            config_source,
            config_version: Some(config.version),
            current_generation,
            candidate_generation,
            candidate_status,
            summary,
            validation,
            compatibility,
            candidate_snapshot,
            rejection_summary,
            diff,
            rejected_changes,
        },
        next_runtime: Some(next_runtime),
    }
}

fn rejected_reload_plan(
    request: ActivationRequest,
    config_source: String,
    config_version: Option<u32>,
    current_generation: Option<GenerationId>,
    candidate_generation: GenerationId,
    mut validation: Vec<PlanningPhaseResult>,
    rejected_changes: Vec<RejectedChange>,
) -> StagedRuntimeReloadPlan {
    if validation
        .iter()
        .all(|step| step.phase != PlanningPhase::NormalizeRuntime)
    {
        validation.push(PlanningPhaseResult {
            phase: PlanningPhase::NormalizeRuntime,
            status: PlanningPhaseStatus::Skipped,
            summary: "skipped because an earlier validation phase failed".to_string(),
        });
    }
    if validation
        .iter()
        .all(|step| step.phase != PlanningPhase::EvaluateCompatibility)
    {
        validation.push(PlanningPhaseResult {
            phase: PlanningPhase::EvaluateCompatibility,
            status: PlanningPhaseStatus::Skipped,
            summary: "skipped because no valid candidate generation was assembled".to_string(),
        });
    }

    let rejection_summary = Some(render_rejected_changes(&rejected_changes));
    StagedRuntimeReloadPlan {
        plan: ReloadPlan {
            request,
            config_source,
            config_version,
            current_generation,
            candidate_generation,
            candidate_status: GenerationStatus::Rejected,
            summary: format!(
                "reload candidate for generation {candidate_generation} was rejected during staged validation"
            ),
            validation,
            compatibility: ReloadCompatibilityClassification::NotEvaluated,
            candidate_snapshot: None,
            rejection_summary,
            diff: ReloadDiff::default(),
            rejected_changes,
        },
        next_runtime: None,
    }
}

fn render_rejected_changes(rejected_changes: &[RejectedChange]) -> String {
    rejected_changes
        .iter()
        .map(|rejected| rejected.message.as_str())
        .collect::<Vec<_>>()
        .join("; ")
}
