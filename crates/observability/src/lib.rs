//! Bounded observability vocabulary shared by Impulse runtime crates.

#![forbid(unsafe_code)]
#![deny(unused_crate_dependencies)]
#![warn(unreachable_pub)]

mod event;
mod labels;

pub use event::{MetricReasonLabels, OperationalEventContext};
pub use labels::{
    AdmissionDecisionReason, AdmissionOverloadCause, BackendHealthReason, HedgeDecisionReason,
    QuotaBackendHealthReason, QuotaPolicyDecision, QuotaPolicyReason, RequestOutcomeReason,
    RetryDecisionReason,
};
