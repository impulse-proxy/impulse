use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};

use log::{error, warn};
use tokio::{runtime::Handle, sync::oneshot, task::AbortHandle};

use crate::Metrics;

pub struct RuntimeTaskRegistry {
    state: Mutex<RuntimeTaskRegistryState>,
}

impl RuntimeTaskRegistry {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(RuntimeTaskRegistryState {
                retired: false,
                tasks: Vec::new(),
            }),
        }
    }

    pub(crate) fn register(&self, task: RuntimeTaskRegistration) {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.retired {
            task.abort.abort();
        } else {
            state.tasks.push(task);
        }
    }

    pub(crate) fn spawn_supervised<F>(
        &self,
        handle: &Handle,
        task_name: &'static str,
        metrics: Option<Arc<Metrics>>,
        future: F,
    ) where
        F: Future<Output = ()> + Send + 'static,
    {
        let task_name = task_name.to_string();
        let (completion_tx, completion_rx) = oneshot::channel();
        let join = handle.spawn(future);
        let abort = join.abort_handle();
        handle.spawn(async move {
            match join.await {
                Ok(()) => {}
                Err(task_error) => {
                    if let Some(metrics) = metrics {
                        metrics.runtime_observations().inc_runtime_panic();
                    }
                    if task_error.is_panic() {
                        error!("Background task '{}' panicked", task_name);
                    } else {
                        warn!("Background task '{}' cancelled", task_name);
                    }
                }
            }
            let _ = completion_tx.send(());
        });
        self.register(RuntimeTaskRegistration::new(abort, completion_rx));
    }

    fn begin_generation_retirement(&self) -> Vec<oneshot::Receiver<()>> {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.retired {
            return Vec::new();
        }
        state.retired = true;
        state
            .tasks
            .drain(..)
            .map(|task| {
                task.abort.abort();
                task.completion
            })
            .collect()
    }

    pub(crate) fn abort_generation(&self) {
        let _ = self.begin_generation_retirement();
    }

    async fn wait_for_generation_retirement(
        completions: Vec<oneshot::Receiver<()>>,
        timeout: Duration,
    ) {
        if completions.is_empty() {
            return;
        }

        let wait_for_completion = async {
            for completion in completions {
                let _ = completion.await;
            }
        };

        if tokio::time::timeout(timeout, wait_for_completion)
            .await
            .is_err()
        {
            warn!(
                "generation background tasks did not stop within {:?}; continuing reload",
                timeout
            );
        }
    }

    pub(crate) fn retire_generation(&self, timeout: Duration) {
        let completions = self.begin_generation_retirement();
        if completions.is_empty() {
            return;
        }

        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    Self::wait_for_generation_retirement(completions, timeout).await;
                });
            }
            Err(_) => {
                warn!(
                    "generation background tasks retired without an active Tokio runtime; completion wait skipped"
                );
            }
        }
    }
}

impl Drop for RuntimeTaskRegistry {
    fn drop(&mut self) {
        self.abort_generation();
    }
}

struct RuntimeTaskRegistryState {
    retired: bool,
    tasks: Vec<RuntimeTaskRegistration>,
}

pub(crate) struct RuntimeTaskRegistration {
    abort: AbortHandle,
    completion: oneshot::Receiver<()>,
}

impl RuntimeTaskRegistration {
    pub(crate) fn new(abort: AbortHandle, completion: oneshot::Receiver<()>) -> Self {
        Self { abort, completion }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };

    use super::*;

    struct CompletionSignal(Option<oneshot::Sender<()>>);

    impl Drop for CompletionSignal {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    fn spawn_registered_task(
        registry: &RuntimeTaskRegistry,
        completed: Arc<AtomicBool>,
    ) -> AbortHandle {
        let (completion_tx, completion_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _completion = CompletionSignal(Some(completion_tx));
            future::pending::<()>().await;
        });
        let task_handle = task.abort_handle();
        let task_join = task;
        let completed_flag = Arc::clone(&completed);
        tokio::spawn(async move {
            let _ = task_join.await;
            completed_flag.store(true, Ordering::Release);
        });
        registry.register(RuntimeTaskRegistration::new(
            task_handle.clone(),
            completion_rx,
        ));
        task_handle
    }

    mod runtime_generation_task_ownership {
        use super::*;

        #[tokio::test]
        async fn task_retirement_is_generation_scoped() {
            let retired_generation = RuntimeTaskRegistry::new();
            let active_generation = RuntimeTaskRegistry::new();

            let retired_completed = Arc::new(AtomicBool::new(false));
            let active_completed = Arc::new(AtomicBool::new(false));

            let _retired_task =
                spawn_registered_task(&retired_generation, Arc::clone(&retired_completed));
            let active_task =
                spawn_registered_task(&active_generation, Arc::clone(&active_completed));

            retired_generation.retire_generation(Duration::from_millis(50));
            tokio::time::sleep(Duration::from_millis(20)).await;

            assert!(
                retired_completed.load(Ordering::Acquire),
                "retired generation tasks should be aborted during retirement"
            );
            assert!(
                !active_completed.load(Ordering::Acquire),
                "active generation tasks should remain alive"
            );

            active_task.abort();
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert!(active_completed.load(Ordering::Acquire));
        }
    }
}
