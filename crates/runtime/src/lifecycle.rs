use std::{
    fmt,
    sync::atomic::{AtomicU8, Ordering},
};

/// Stable identifier for a published or staged runtime generation.
pub type GenerationId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeTransitionKind {
    Startup,
    ReloadValidate,
    ReloadCommit,
    DrainStart,
    DrainFinish,
    ShutdownStart,
    ShutdownFinish,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransitionRejectionKind {
    RestartRequired,
    ResourcePreparationFailed,
    InvalidConfiguration,
    IllegalTransition,
    RuntimeStateUnavailable,
}

impl TransitionRejectionKind {
    pub fn requires_restart(self) -> bool {
        matches!(self, Self::RestartRequired)
    }

    pub fn slug(self) -> &'static str {
        match self {
            Self::RestartRequired => "restart_required",
            Self::ResourcePreparationFailed => "resource_preparation_failed",
            Self::InvalidConfiguration => "invalid_configuration",
            Self::IllegalTransition => "illegal_transition",
            Self::RuntimeStateUnavailable => "runtime_state_unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionRejection {
    pub kind: TransitionRejectionKind,
    pub field_path: Option<String>,
    pub current_mode: Option<String>,
    pub requested_mode: Option<String>,
    pub operator_action: &'static str,
    pub active_runtime_changed: bool,
    pub verbatim: Option<String>,
}

impl TransitionRejection {
    fn new(kind: TransitionRejectionKind, operator_action: &'static str) -> Self {
        Self {
            kind,
            field_path: None,
            current_mode: None,
            requested_mode: None,
            operator_action,
            active_runtime_changed: false,
            verbatim: None,
        }
    }

    pub fn restart_required(
        field_path: impl Into<String>,
        current_mode: impl fmt::Debug,
        requested_mode: impl fmt::Debug,
    ) -> Self {
        Self {
            field_path: Some(field_path.into()),
            current_mode: Some(format!("{current_mode:?}")),
            requested_mode: Some(format!("{requested_mode:?}")),
            ..Self::new(
                TransitionRejectionKind::RestartRequired,
                "restart the process to apply this change",
            )
        }
    }

    pub fn listener_bind_changed(label: impl fmt::Display) -> Self {
        Self {
            field_path: Some(format!("listeners['{label}']")),
            verbatim: Some(format!(
                "runtime reload rejected: listener '{label}' was removed or its bind address changed; restart required"
            )),
            ..Self::new(
                TransitionRejectionKind::RestartRequired,
                "restart the process to apply this change",
            )
        }
    }

    pub fn raw_resource_message(message: impl Into<String>) -> Self {
        Self {
            verbatim: Some(message.into()),
            ..Self::new(
                TransitionRejectionKind::ResourcePreparationFailed,
                "fix the reported resource conflict and retry the reload",
            )
        }
    }

    pub fn resource_preflight_failed(
        resource_kind: &'static str,
        resource_id: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            field_path: Some(format!("{resource_kind} '{}'", resource_id.into())),
            requested_mode: Some(reason.into()),
            ..Self::new(
                TransitionRejectionKind::ResourcePreparationFailed,
                "resolve the resource conflict (e.g. free the address/port) and retry the reload",
            )
        }
    }

    pub fn invalid_configuration(reason: impl Into<String>) -> Self {
        Self {
            requested_mode: Some(reason.into()),
            ..Self::new(
                TransitionRejectionKind::InvalidConfiguration,
                "fix the configuration and retry the reload",
            )
        }
    }

    pub fn runtime_state_unavailable(reason: impl Into<String>) -> Self {
        Self {
            requested_mode: Some(reason.into()),
            ..Self::new(
                TransitionRejectionKind::RuntimeStateUnavailable,
                "inspect process state; the reload could not be evaluated",
            )
        }
    }

    pub fn requires_restart(&self) -> bool {
        self.kind.requires_restart()
    }
}

impl fmt::Display for TransitionRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(verbatim) = &self.verbatim {
            return formatter.write_str(verbatim);
        }
        if self.kind == TransitionRejectionKind::ResourcePreparationFailed
            && let (Some(field), Some(detail)) = (&self.field_path, &self.requested_mode)
        {
            return write!(
                formatter,
                "runtime reload rejected: could not prepare {field}: {detail}; active runtime unchanged ({})",
                if self.active_runtime_changed {
                    "state may be partially applied"
                } else {
                    "no change applied"
                }
            );
        }
        match (&self.field_path, &self.current_mode, &self.requested_mode) {
            (Some(field), Some(current), Some(requested))
                if self.kind == TransitionRejectionKind::RestartRequired =>
            {
                write!(
                    formatter,
                    "runtime reload rejected: {field} changed from {current} to {requested}; restart required"
                )
            }
            (Some(field), _, Some(detail)) => {
                write!(formatter, "runtime reload rejected: {field}: {detail}")
            }
            (_, _, Some(detail)) => write!(formatter, "runtime reload rejected: {detail}"),
            _ => write!(formatter, "runtime reload rejected: {}", self.kind.slug()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionPlan {
    pub kind: RuntimeTransitionKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeTransitionDecision {
    Allowed(TransitionPlan),
    Rejected(TransitionRejection),
}

impl RuntimeTransitionDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed(_))
    }

    pub fn rejection(&self) -> Option<&TransitionRejection> {
        match self {
            Self::Rejected(rejection) => Some(rejection),
            Self::Allowed(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeLifecyclePhase {
    Starting,
    Running,
    Draining,
    ShuttingDown,
    Terminated,
}

impl RuntimeLifecyclePhase {
    pub fn allows_reload(self) -> bool {
        matches!(self, Self::Running)
    }

    pub fn allows_drain_start(self) -> bool {
        matches!(self, Self::Running | Self::Draining)
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Terminated)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleTransitionResult {
    Applied {
        from: RuntimeLifecyclePhase,
        to: RuntimeLifecyclePhase,
    },
    NoOp {
        phase: RuntimeLifecyclePhase,
    },
    Rejected(TransitionRejection),
}

impl LifecycleTransitionResult {
    pub fn is_accepted(&self) -> bool {
        !matches!(self, Self::Rejected(_))
    }

    pub fn rejection(&self) -> Option<&TransitionRejection> {
        match self {
            Self::Rejected(rejection) => Some(rejection),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct RuntimeLifecycleState {
    phase: AtomicU8,
}

impl Default for RuntimeLifecycleState {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeLifecycleState {
    const STARTING: u8 = 0;
    const RUNNING: u8 = 1;
    const DRAINING: u8 = 2;
    const SHUTTING_DOWN: u8 = 3;
    const TERMINATED: u8 = 4;

    pub fn new() -> Self {
        Self {
            phase: AtomicU8::new(Self::STARTING),
        }
    }

    fn decode(raw: u8) -> RuntimeLifecyclePhase {
        match raw {
            Self::STARTING => RuntimeLifecyclePhase::Starting,
            Self::RUNNING => RuntimeLifecyclePhase::Running,
            Self::DRAINING => RuntimeLifecyclePhase::Draining,
            Self::SHUTTING_DOWN => RuntimeLifecyclePhase::ShuttingDown,
            _ => RuntimeLifecyclePhase::Terminated,
        }
    }

    const fn encode(phase: RuntimeLifecyclePhase) -> u8 {
        match phase {
            RuntimeLifecyclePhase::Starting => Self::STARTING,
            RuntimeLifecyclePhase::Running => Self::RUNNING,
            RuntimeLifecyclePhase::Draining => Self::DRAINING,
            RuntimeLifecyclePhase::ShuttingDown => Self::SHUTTING_DOWN,
            RuntimeLifecyclePhase::Terminated => Self::TERMINATED,
        }
    }

    pub fn phase(&self) -> RuntimeLifecyclePhase {
        Self::decode(self.phase.load(Ordering::Acquire))
    }

    fn reject(&self, attempted: RuntimeTransitionKind) -> LifecycleTransitionResult {
        let phase = self.phase();
        LifecycleTransitionResult::Rejected(TransitionRejection {
            kind: TransitionRejectionKind::IllegalTransition,
            field_path: None,
            current_mode: Some(format!("{phase:?}")),
            requested_mode: Some(format!("{attempted:?}")),
            operator_action: "wait for the current lifecycle phase to complete; the requested transition is not legal now",
            active_runtime_changed: false,
            verbatim: None,
        })
    }

    fn transition(
        &self,
        expected: RuntimeLifecyclePhase,
        target: RuntimeLifecyclePhase,
        attempted: RuntimeTransitionKind,
    ) -> LifecycleTransitionResult {
        let current = self.phase();
        if current == target {
            return LifecycleTransitionResult::NoOp { phase: current };
        }
        if current != expected {
            return self.reject(attempted);
        }
        match self.phase.compare_exchange(
            Self::encode(expected),
            Self::encode(target),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                Self::log_transition(expected, target);
                LifecycleTransitionResult::Applied {
                    from: expected,
                    to: target,
                }
            }
            Err(actual) if Self::decode(actual) == target => {
                LifecycleTransitionResult::NoOp { phase: target }
            }
            Err(_) => self.reject(attempted),
        }
    }

    fn log_transition(from: RuntimeLifecyclePhase, to: RuntimeLifecyclePhase) {
        log::info!("runtime lifecycle transition {from:?} -> {to:?}");
    }

    pub fn mark_running(&self) -> LifecycleTransitionResult {
        self.transition(
            RuntimeLifecyclePhase::Starting,
            RuntimeLifecyclePhase::Running,
            RuntimeTransitionKind::Startup,
        )
    }

    pub fn check_reload_allowed(&self) -> LifecycleTransitionResult {
        let phase = self.phase();
        if phase.allows_reload() {
            LifecycleTransitionResult::NoOp { phase }
        } else {
            self.reject(RuntimeTransitionKind::ReloadCommit)
        }
    }

    pub fn begin_drain(&self) -> LifecycleTransitionResult {
        self.transition(
            RuntimeLifecyclePhase::Running,
            RuntimeLifecyclePhase::Draining,
            RuntimeTransitionKind::DrainStart,
        )
    }

    pub fn begin_shutdown(&self) -> LifecycleTransitionResult {
        let current = self.phase();
        match current {
            RuntimeLifecyclePhase::ShuttingDown | RuntimeLifecyclePhase::Terminated => {
                LifecycleTransitionResult::NoOp { phase: current }
            }
            RuntimeLifecyclePhase::Running | RuntimeLifecyclePhase::Draining => {
                match self.phase.compare_exchange(
                    Self::encode(current),
                    Self::SHUTTING_DOWN,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        Self::log_transition(current, RuntimeLifecyclePhase::ShuttingDown);
                        LifecycleTransitionResult::Applied {
                            from: current,
                            to: RuntimeLifecyclePhase::ShuttingDown,
                        }
                    }
                    Err(_) => LifecycleTransitionResult::NoOp {
                        phase: self.phase(),
                    },
                }
            }
            RuntimeLifecyclePhase::Starting => self.reject(RuntimeTransitionKind::ShutdownStart),
        }
    }

    pub fn finish_shutdown(&self) -> LifecycleTransitionResult {
        self.transition(
            RuntimeLifecyclePhase::ShuttingDown,
            RuntimeLifecyclePhase::Terminated,
            RuntimeTransitionKind::ShutdownFinish,
        )
    }
}
