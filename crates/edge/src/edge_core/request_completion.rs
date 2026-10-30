use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// Request-scoped ownership for exactly-once completion recording.
#[derive(Clone, Debug, Default)]
pub(crate) struct RequestCompletion {
    completed: Arc<AtomicBool>,
}

impl RequestCompletion {
    pub(crate) fn complete(&self) -> bool {
        self.complete_with(|| ()).is_some()
    }

    pub(crate) fn complete_with<T>(&self, record: impl FnOnce() -> T) -> Option<T> {
        self.completed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| record())
    }

    #[cfg(test)]
    pub(crate) fn is_complete(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }
}
