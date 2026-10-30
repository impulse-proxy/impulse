//! Operational policy vocabulary for runtime ownership and reload rules.
//!
//! This module is the **canonical, handler-free description** of the operational
//! contract frozen in Phase 0 (`machine-hardening-phase0.md`). It defines the
//! stable types that later phases build on:
//!
//! - who *owns* a runtime resource ([`OperationalOwnership`]),
//! - whether a config domain can change at runtime ([`ReloadCapability`]),
//! - what kind of runtime transition is being attempted ([`RuntimeTransitionKind`]),
//! - why a transition was rejected ([`TransitionRejectionKind`], [`TransitionRejection`]),
//! - the typed outcome of evaluating a transition ([`RuntimeTransitionDecision`]).
//!
//! It also carries a single source-of-truth table ([`RESOURCE_DOMAINS`]) mapping
//! every config/runtime domain to its ownership class and reload capability, so a
//! reader can answer "what can reload live?" and "who owns this?" from this file
//! alone — the Phase 1 exit criterion.
//!
//! # Phase 1 scope
//!
//! This layer introduces **no semantic change**. Existing validators keep their
//! current behavior; they are given a way to *describe* their outcomes with these
//! types (see [`TransitionRejection::restart_required`]). Wiring the reload flow to
//! *decide* from this table is Phase 2 work and is intentionally not done here.

use std::fmt;

/// Which lifecycle phase owns a runtime resource, i.e. who is allowed to create
/// or replace it and when.
///
/// Derived from the Phase 0 invariants table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationalOwnership {
    /// Constructed once at process startup and never replaced while the process
    /// lives. Changing it requires a full restart (e.g. worker topology,
    /// listener bind, log/tracing sinks).
    StartupOwned,
    /// Rebuilt fresh for each runtime generation and swapped atomically on reload
    /// (e.g. routing index, upstream pools, backend resolution store).
    GenerationOwned,
    /// A single instance shared across all generations for the life of the
    /// process (e.g. the watchdog coordinator, the runtime-bundle handle itself).
    ProcessShared,
}

/// Whether a config domain can change while the process is running, and if so
/// how the change takes effect.
///
/// Derived from the Phase 0 reload-rejection inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReloadCapability {
    /// Change takes effect on the next generation (or immediately, as with
    /// `log.level`) without a restart or a rejection.
    LiveReloadable,
    /// Change is understood but cannot be applied to the running process; the
    /// reload is rejected with a restart-required message and the active
    /// generation is preserved.
    RestartRequired,
    /// The value is fixed for the life of the process and must never differ from
    /// the value the process booted with. Distinct from [`Self::RestartRequired`]
    /// only in intent: these are never expected to change across a restart of the
    /// same deployment (e.g. an identity established at boot).
    ImmutableAtRuntime,
}

pub use impulse_runtime::{
    LifecycleTransitionResult, RuntimeLifecyclePhase, RuntimeLifecycleState,
    RuntimeTransitionDecision, RuntimeTransitionKind, TransitionPlan, TransitionRejection,
    TransitionRejectionKind,
};
/// A single runtime-managed resource or config domain, described by its ownership
/// class and reload capability. One row per operational domain identified in
/// Phase 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceDomain {
    /// Dotted config path or subsystem name this domain covers.
    pub field_path: &'static str,
    /// A one-line human description of the domain.
    pub description: &'static str,
    /// Which lifecycle phase owns the underlying resource.
    pub ownership: OperationalOwnership,
    /// Whether the domain can change at runtime.
    pub reload: ReloadCapability,
}

impl ResourceDomain {
    /// Whether a change to this domain takes effect without a restart.
    pub fn is_live_reloadable(&self) -> bool {
        matches!(self.reload, ReloadCapability::LiveReloadable)
    }

    /// Whether a change to this domain forces a restart (or is fixed for the
    /// life of the process).
    pub fn requires_restart(&self) -> bool {
        matches!(
            self.reload,
            ReloadCapability::RestartRequired | ReloadCapability::ImmutableAtRuntime
        )
    }

    /// Whether the underlying resource is created once at startup and never
    /// replaced while the process runs.
    pub fn is_startup_owned_only(&self) -> bool {
        matches!(self.ownership, OperationalOwnership::StartupOwned)
    }

    /// Whether the underlying resource is rebuilt per generation.
    pub fn is_generation_owned(&self) -> bool {
        matches!(self.ownership, OperationalOwnership::GenerationOwned)
    }
}

/// Marks a runtime state struct with the ownership class that governs its
/// lifetime, making the startup-owned / generation-owned / process-shared
/// distinction a compile-visible property of the type rather than tribal
/// knowledge in the swap code.
///
/// Implemented by the three runtime state structs in
/// [`crate::runtime::generation`]. A reader can answer "may the generation swap
/// replace this?" from `T::OWNERSHIP` alone.
pub trait OwnedRuntimeState {
    /// The ownership class of every resource this struct holds.
    const OWNERSHIP: OperationalOwnership;

    /// Whether the generation swap is allowed to replace an instance of this
    /// struct. Only generation-owned state may be swapped wholesale; startup-owned
    /// and process-shared state must be carried across (or, in the current
    /// implementation, rebuilt identically — see the swap boundary in
    /// `runtime::bundle`).
    fn is_swappable_by_generation() -> bool {
        matches!(Self::OWNERSHIP, OperationalOwnership::GenerationOwned)
    }
}

/// The single source of truth mapping config/runtime domains to their ownership
/// class and reload capability. Phase 2 will make the reload validators *decide*
/// from this table; Phase 1 only records it so the rules are readable in one
/// place.
///
/// Each restart-required entry corresponds to a `note_restart_required_change`
/// call or a bind-compatibility check in `control_api/reload.rs`.
pub static RESOURCE_DOMAINS: &[ResourceDomain] = &[
    // -- listener bind and protocol settings ------------------------------------
    ResourceDomain {
        field_path: "listeners[].listen",
        description: "UDP and Pingora listener bind address/port",
        ownership: OperationalOwnership::GenerationOwned,
        reload: ReloadCapability::LiveReloadable,
    },
    // -- control API settings ---------------------------------------------------
    ResourceDomain {
        field_path: "observability.control_api.address/port",
        description: "control API endpoint bind (preflighted, new bind only)",
        ownership: OperationalOwnership::StartupOwned,
        reload: ReloadCapability::RestartRequired,
    },
    // -- metrics / observability settings ---------------------------------------
    ResourceDomain {
        field_path: "observability.metrics.address/port",
        description: "metrics exporter bind (preflighted, new bind only)",
        ownership: OperationalOwnership::StartupOwned,
        reload: ReloadCapability::RestartRequired,
    },
    ResourceDomain {
        field_path: "observability.tracing.enabled",
        description: "tracing pipeline enablement",
        ownership: OperationalOwnership::StartupOwned,
        reload: ReloadCapability::RestartRequired,
    },
    ResourceDomain {
        field_path: "observability.tracing.service_name",
        description: "tracing service name",
        ownership: OperationalOwnership::StartupOwned,
        reload: ReloadCapability::RestartRequired,
    },
    ResourceDomain {
        field_path: "observability.tracing.otlp_endpoint",
        description: "tracing OTLP exporter endpoint",
        ownership: OperationalOwnership::StartupOwned,
        reload: ReloadCapability::RestartRequired,
    },
    ResourceDomain {
        field_path: "observability.tracing.sample_ratio",
        description: "tracing sample ratio",
        ownership: OperationalOwnership::StartupOwned,
        reload: ReloadCapability::RestartRequired,
    },
    // -- logging sinks ----------------------------------------------------------
    ResourceDomain {
        field_path: "log.file.enabled",
        description: "file log sink enablement",
        ownership: OperationalOwnership::StartupOwned,
        reload: ReloadCapability::RestartRequired,
    },
    ResourceDomain {
        field_path: "log.file.path",
        description: "file log sink path",
        ownership: OperationalOwnership::StartupOwned,
        reload: ReloadCapability::RestartRequired,
    },
    ResourceDomain {
        field_path: "log.format",
        description: "log output format",
        ownership: OperationalOwnership::StartupOwned,
        reload: ReloadCapability::RestartRequired,
    },
    ResourceDomain {
        field_path: "log.level",
        description: "log verbosity (applied live post-commit)",
        ownership: OperationalOwnership::ProcessShared,
        reload: ReloadCapability::LiveReloadable,
    },
    // -- worker topology / runtime threading ------------------------------------
    ResourceDomain {
        field_path: "performance.control_plane_threads",
        description: "control-plane Tokio runtime thread count",
        ownership: OperationalOwnership::StartupOwned,
        reload: ReloadCapability::RestartRequired,
    },
    ResourceDomain {
        field_path: "performance.worker_threads",
        description: "data-plane worker thread count / listener topology",
        ownership: OperationalOwnership::StartupOwned,
        reload: ReloadCapability::RestartRequired,
    },
    // -- route table / upstream definitions -------------------------------------
    ResourceDomain {
        field_path: "routes",
        description: "routing index (rebuilt per generation)",
        ownership: OperationalOwnership::GenerationOwned,
        reload: ReloadCapability::LiveReloadable,
    },
    ResourceDomain {
        field_path: "upstreams",
        description: "upstream pools, inflight semaphores, transport pool",
        ownership: OperationalOwnership::GenerationOwned,
        reload: ReloadCapability::LiveReloadable,
    },
    // -- backend health and load-balancing policy -------------------------------
    ResourceDomain {
        field_path: "upstreams[].backends",
        description: "backend resolution store and DNS refresh (per generation)",
        ownership: OperationalOwnership::GenerationOwned,
        reload: ReloadCapability::LiveReloadable,
    },
    ResourceDomain {
        field_path: "upstreams[].cache.max_bytes",
        description: "process-lifetime response cache byte capacity",
        ownership: OperationalOwnership::StartupOwned,
        reload: ReloadCapability::RestartRequired,
    },
    ResourceDomain {
        field_path: "upstreams[].cache.max_entries",
        description: "process-lifetime response cache entry capacity",
        ownership: OperationalOwnership::StartupOwned,
        reload: ReloadCapability::RestartRequired,
    },
    // -- watchdog ownership and restart semantics -------------------------------
    ResourceDomain {
        field_path: "watchdog",
        description: "watchdog coordinator (shared) + generation-scoped service task",
        ownership: OperationalOwnership::ProcessShared,
        reload: ReloadCapability::LiveReloadable,
    },
];

/// Look up the policy row for a dotted config field path, if one is recorded.
pub fn resource_domain(field_path: &str) -> Option<&'static ResourceDomain> {
    RESOURCE_DOMAINS.iter().find(|d| d.field_path == field_path)
}

/// The single authority that decides reload compatibility.
///
/// It accumulates typed [`TransitionRejection`]s as a validator walks the config
/// domains, so that "what can reload live" and the rejection wording for each
/// class of problem live in exactly one place. Call sites that own runtime types
/// (`RuntimeBundle`, `QUICListener`) feed it the *outcome* of each per-domain
/// comparison or preflight; the authority owns the *rule* (which
/// [`ReloadCapability`] applies) and the *message*.
///
/// This replaces the scattered `Option<String>`/`Vec<String>` checks that
/// previously each formatted their own rejection strings.
#[derive(Debug, Default)]
pub struct ReloadCompatibilityAuthority {
    rejections: Vec<TransitionRejection>,
}

impl ReloadCompatibilityAuthority {
    /// Start with no rejections recorded.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that a restart-required field changed. No-op when the values are
    /// equal, matching the legacy `note_restart_required_change` semantics.
    ///
    /// The `field_path` should exist in [`RESOURCE_DOMAINS`] with
    /// [`ReloadCapability::RestartRequired`]; in debug builds this is asserted so
    /// the table and the call sites cannot silently drift apart.
    pub fn note_restart_required_change<T>(
        &mut self,
        field_path: &'static str,
        current: &T,
        next: &T,
    ) where
        T: PartialEq + fmt::Debug,
    {
        debug_assert!(
            resource_domain(field_path).is_none_or(ResourceDomain::requires_restart),
            "field_path {field_path:?} is recorded as live-reloadable but used as restart-required"
        );
        if current != next {
            self.rejections.push(TransitionRejection::restart_required(
                field_path, current, next,
            ));
        }
    }

    /// Record that a listener was removed or had its bind address changed
    /// (restart-required).
    pub fn note_listener_bind_changed(&mut self, label: impl fmt::Display) {
        self.rejections
            .push(TransitionRejection::listener_bind_changed(label));
    }

    /// Record an already-formed rejection (e.g. a preflight-bind failure whose
    /// message came from an underlying probe).
    pub fn note_rejection(&mut self, rejection: TransitionRejection) {
        self.rejections.push(rejection);
    }

    /// Whether any rejection has been recorded.
    pub fn is_rejected(&self) -> bool {
        !self.rejections.is_empty()
    }

    /// The recorded rejections, in the order they were noted.
    pub fn rejections(&self) -> &[TransitionRejection] {
        &self.rejections
    }

    /// Consume the authority into `Ok(())` when compatible, or `Err(rejections)`
    /// carrying every typed rejection recorded.
    pub fn into_result(self) -> Result<(), Vec<TransitionRejection>> {
        if self.rejections.is_empty() {
            Ok(())
        } else {
            Err(self.rejections)
        }
    }
}

/// Render a slice of rejections into the single legacy operator string:
/// each rejection's `Display`, joined with `"; "`. This is how a typed rejection
/// set is surfaced through the existing string-based handler boundary without
/// changing the bytes an operator sees.
pub fn render_rejections(rejections: &[TransitionRejection]) -> String {
    rejections
        .iter()
        .map(TransitionRejection::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_required_rejection_matches_legacy_wording() {
        // Legacy string: "runtime reload rejected: {field} changed from {current:?} to {next:?}; restart required"
        let rejection = TransitionRejection::restart_required(
            "performance.control_plane_threads",
            2usize,
            4usize,
        );
        assert!(rejection.requires_restart());
        assert_eq!(
            rejection.to_string(),
            "runtime reload rejected: performance.control_plane_threads changed from 2 to 4; restart required"
        );
    }

    #[test]
    fn decision_helpers() {
        let allowed = RuntimeTransitionDecision::Allowed(TransitionPlan {
            kind: RuntimeTransitionKind::ReloadCommit,
        });
        assert!(allowed.is_allowed());
        assert!(allowed.rejection().is_none());

        let rejected = RuntimeTransitionDecision::Rejected(
            TransitionRejection::invalid_configuration("bad yaml"),
        );
        assert!(!rejected.is_allowed());
        assert_eq!(
            rejected.rejection().map(|r| r.kind),
            Some(TransitionRejectionKind::InvalidConfiguration)
        );
    }

    #[test]
    fn domain_helpers_agree_with_table() {
        let threads = resource_domain("performance.control_plane_threads").unwrap();
        assert!(threads.is_startup_owned_only());
        assert!(threads.requires_restart());
        assert!(!threads.is_live_reloadable());

        let routes = resource_domain("routes").unwrap();
        assert!(routes.is_generation_owned());
        assert!(routes.is_live_reloadable());
        assert!(!routes.requires_restart());
    }

    #[test]
    fn authority_collects_and_renders_like_legacy_join() {
        let mut authority = ReloadCompatibilityAuthority::new();
        // Equal values record nothing.
        authority.note_restart_required_change("log.format", &"text", &"text");
        assert!(!authority.is_rejected());
        // Changed values record a restart-required rejection.
        authority.note_restart_required_change("log.format", &"text", &"json");
        authority.note_restart_required_change(
            "performance.control_plane_threads",
            &2usize,
            &4usize,
        );
        assert!(authority.is_rejected());
        assert_eq!(authority.rejections().len(), 2);

        let rendered = render_rejections(authority.rejections());
        // Byte-identical to the pre-Phase-2 `issues.join("; ")` output.
        assert_eq!(
            rendered,
            "runtime reload rejected: log.format changed from \"text\" to \"json\"; restart required; \
             runtime reload rejected: performance.control_plane_threads changed from 2 to 4; restart required"
        );

        let err = authority.into_result().unwrap_err();
        assert!(err.iter().all(TransitionRejection::requires_restart));
    }

    #[test]
    fn listener_bind_changed_matches_legacy_wording() {
        let rejection = TransitionRejection::listener_bind_changed("edge-primary");
        assert_eq!(
            rejection.to_string(),
            "runtime reload rejected: listener 'edge-primary' was removed or its bind address changed; restart required"
        );
        assert!(rejection.requires_restart());
    }

    #[test]
    fn resource_preflight_failure_is_structured_and_states_runtime_unchanged() {
        let rejection = TransitionRejection::resource_preflight_failed(
            "control API endpoint",
            "0.0.0.0:9443",
            "address already in use",
        );
        assert_eq!(
            rejection.kind,
            TransitionRejectionKind::ResourcePreparationFailed
        );
        assert!(!rejection.requires_restart());
        assert!(!rejection.active_runtime_changed);
        // Phase 8: consistent structure — attempted action, the specific resource,
        // the reason, and the explicit runtime-unchanged status.
        assert_eq!(
            rejection.to_string(),
            "runtime reload rejected: could not prepare control API endpoint '0.0.0.0:9443': address already in use; active runtime unchanged (no change applied)"
        );
        // And it carries an actionable next step.
        assert!(rejection.operator_action.contains("retry the reload"));
    }

    #[test]
    fn raw_resource_message_is_emitted_verbatim() {
        let rejection = TransitionRejection::raw_resource_message(
            "failed to bind metrics endpoint 0.0.0.0:9100: in use",
        );
        assert_eq!(
            rejection.to_string(),
            "failed to bind metrics endpoint 0.0.0.0:9100: in use"
        );
        assert!(!rejection.requires_restart());
    }

    #[test]
    fn only_generation_owned_state_is_swappable() {
        use crate::runtime::generation::{
            RuntimeGenerationState, RuntimeSharedServices, StartupOwnedRuntimeState,
        };

        assert_eq!(
            StartupOwnedRuntimeState::OWNERSHIP,
            OperationalOwnership::StartupOwned
        );
        assert_eq!(
            RuntimeSharedServices::OWNERSHIP,
            OperationalOwnership::ProcessShared
        );
        assert_eq!(
            RuntimeGenerationState::OWNERSHIP,
            OperationalOwnership::GenerationOwned
        );

        // The generation swap may replace only generation-owned state.
        assert!(!StartupOwnedRuntimeState::is_swappable_by_generation());
        assert!(!RuntimeSharedServices::is_swappable_by_generation());
        assert!(RuntimeGenerationState::is_swappable_by_generation());
    }

    #[test]
    fn lifecycle_happy_path_startup_to_shutdown() {
        let state = RuntimeLifecycleState::new();
        assert_eq!(state.phase(), RuntimeLifecyclePhase::Starting);

        assert!(matches!(
            state.mark_running(),
            LifecycleTransitionResult::Applied {
                from: RuntimeLifecyclePhase::Starting,
                to: RuntimeLifecyclePhase::Running,
            }
        ));
        assert!(state.check_reload_allowed().is_accepted());

        assert!(matches!(
            state.begin_drain(),
            LifecycleTransitionResult::Applied {
                to: RuntimeLifecyclePhase::Draining,
                ..
            }
        ));
        assert!(matches!(
            state.begin_shutdown(),
            LifecycleTransitionResult::Applied {
                to: RuntimeLifecyclePhase::ShuttingDown,
                ..
            }
        ));
        assert!(matches!(
            state.finish_shutdown(),
            LifecycleTransitionResult::Applied {
                to: RuntimeLifecyclePhase::Terminated,
                ..
            }
        ));
        assert!(state.phase().is_terminal());
    }

    #[test]
    fn lifecycle_repeated_transitions_are_idempotent() {
        let state = RuntimeLifecycleState::new();
        state.mark_running();

        // drain twice -> second is a no-op, not a rejection
        assert!(matches!(
            state.begin_drain(),
            LifecycleTransitionResult::Applied { .. }
        ));
        assert!(matches!(
            state.begin_drain(),
            LifecycleTransitionResult::NoOp {
                phase: RuntimeLifecyclePhase::Draining
            }
        ));

        // shutdown twice -> second is a no-op
        assert!(matches!(
            state.begin_shutdown(),
            LifecycleTransitionResult::Applied { .. }
        ));
        assert!(matches!(
            state.begin_shutdown(),
            LifecycleTransitionResult::NoOp { .. }
        ));
        // finishing twice is idempotent
        assert!(matches!(
            state.finish_shutdown(),
            LifecycleTransitionResult::Applied { .. }
        ));
        assert!(matches!(
            state.finish_shutdown(),
            LifecycleTransitionResult::NoOp { .. }
        ));
    }

    #[test]
    fn lifecycle_rejects_illegal_transitions() {
        // reload while shutting down is rejected
        let state = RuntimeLifecycleState::new();
        state.mark_running();
        state.begin_shutdown();
        let rejected = state.check_reload_allowed();
        assert!(!rejected.is_accepted());
        assert_eq!(
            rejected.rejection().map(|r| r.kind),
            Some(TransitionRejectionKind::IllegalTransition)
        );

        // drain-start after shutdown is rejected
        assert!(!state.begin_drain().is_accepted());

        // shutdown from Starting (no active generation) is rejected
        let fresh = RuntimeLifecycleState::new();
        assert!(!fresh.begin_shutdown().is_accepted());
        // and reload before running is rejected too
        assert!(!fresh.check_reload_allowed().is_accepted());
    }

    #[test]
    fn lifecycle_shutdown_directly_from_running() {
        let state = RuntimeLifecycleState::new();
        state.mark_running();
        // Skipping drain is legal: Running -> ShuttingDown.
        assert!(matches!(
            state.begin_shutdown(),
            LifecycleTransitionResult::Applied {
                from: RuntimeLifecyclePhase::Running,
                to: RuntimeLifecyclePhase::ShuttingDown,
            }
        ));
    }

    #[test]
    fn every_domain_path_is_unique() {
        let mut paths: Vec<_> = RESOURCE_DOMAINS.iter().map(|d| d.field_path).collect();
        paths.sort_unstable();
        let before = paths.len();
        paths.dedup();
        assert_eq!(
            before,
            paths.len(),
            "duplicate field_path in RESOURCE_DOMAINS"
        );
    }
}
