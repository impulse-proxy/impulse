use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

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
