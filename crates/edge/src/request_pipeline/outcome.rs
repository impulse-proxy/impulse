use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use http::StatusCode;

use crate::AdmissionOverloadCause;

/// Shared request-scoped ownership for terminal outcome recording.
#[derive(Clone, Debug, Default)]
pub(crate) struct TerminalOutcomeGuard {
    recorded: Arc<AtomicBool>,
}

impl TerminalOutcomeGuard {
    /// Claims the request's terminal outcome. Only the first caller succeeds.
    pub(crate) fn record(&self) -> bool {
        !self.recorded.swap(true, Ordering::AcqRel)
    }

    #[cfg(test)]
    pub(crate) fn is_recorded(&self) -> bool {
        self.recorded.load(Ordering::Acquire)
    }
}

/// Protocol-neutral result of request admission.
///
/// Adapters translate a rejection into their existing HTTP or H3 response only
/// after shared admission has completed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionOutcome {
    Admitted,
    Rejected {
        reason: AdmissionRejectionReason,
        overload_cause: Option<AdmissionOverloadCause>,
    },
}

/// Semantic reason a request was not admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionRejectionReason {
    AuthDenied,
    AuthUnavailable,
    RateLimited,
    QuotaDenied,
    Overloaded,
    ValidationRejected,
    PolicyRejected,
    RequestBodyNotAllowed,
    RequestBodyTooLarge,
}

/// Protocol-neutral result of forwarding an admitted request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ForwardingOutcome {
    Completed { status: StatusCode },
    Failed { reason: ForwardingFailureReason },
}

/// Semantic class of a failed upstream forwarding attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ForwardingFailureReason {
    DispatchUnavailable,
    UpstreamResultDropped,
    Timeout,
    Transport,
    Protocol,
    Tls,
    Bridge,
}

/// Protocol-neutral state of the downstream response lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseOutcome {
    Pending,
    Completed { status: StatusCode },
    Aborted { reason: ResponseAbortReason },
}

/// Semantic reason a downstream response could not complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseAbortReason {
    ClientDisconnected,
    WriteFailed,
    StreamAborted,
    TimedOut,
}
