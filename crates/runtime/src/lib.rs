//! Shared runtime identity and lifecycle state.
//!
//! This crate owns process lifecycle transitions and generation identity. It
//! deliberately contains no configuration loading, protocol I/O, or runtime
//! resource implementations.

#![forbid(unsafe_code)]
#![deny(unused_crate_dependencies)]
#![warn(unreachable_pub)]

mod lifecycle;

pub use lifecycle::{
    GenerationId, LifecycleTransitionResult, RuntimeLifecyclePhase, RuntimeLifecycleState,
    RuntimeTransitionDecision, RuntimeTransitionKind, TransitionPlan, TransitionRejection,
    TransitionRejectionKind,
};
