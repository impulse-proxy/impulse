use std::{
    future::Future,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use log::{error, warn};
use tokio::{runtime::Handle, sync::oneshot};

use crate::{Metrics, runtime::tasks::RuntimeTaskRegistration};

pub fn configure_async_runtime(worker_threads: usize) {
    let threads = worker_threads.max(1);
    if FALLBACK_RT.get().is_some() {
        warn!(
            "async runtime already initialized; ignoring new worker_threads={}",
            threads
        );
        return;
    }
    FALLBACK_RT_THREADS.store(threads, Ordering::Relaxed);
}

pub(in crate::quic_listener) fn runtime_handle() -> Option<Handle> {
    if let Ok(handle) = Handle::try_current() {
        return Some(handle);
    }
    fallback_runtime().map(|rt| rt.handle().clone())
}

pub(in crate::quic_listener) fn spawn_async_task<F>(fut: F, _task_name: &str) -> bool
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    if let Some(handle) = runtime_handle() {
        handle.spawn(fut);
        true
    } else {
        false
    }
}

pub(in crate::quic_listener) fn spawn_supervised_async_task<F>(
    handle: &Handle,
    task_name: &'static str,
    metrics: Option<Arc<Metrics>>,
    fut: F,
) -> RuntimeTaskRegistration
where
    F: Future<Output = ()> + Send + 'static,
{
    let task_name = task_name.to_string();
    let (completion_tx, completion_rx) = oneshot::channel();
    let join = handle.spawn(fut);
    let abort = join.abort_handle();
    let monitor_handle = handle.clone();
    monitor_handle.spawn(async move {
        match join.await {
            Ok(()) => {}
            Err(err) => {
                if let Some(metrics) = metrics {
                    metrics.runtime_observations().inc_runtime_panic();
                }
                if err.is_panic() {
                    error!("Background task '{}' panicked", task_name);
                } else {
                    warn!("Background task '{}' cancelled", task_name);
                }
            }
        }
        let _ = completion_tx.send(());
    });
    RuntimeTaskRegistration::new(abort, completion_rx)
}

fn fallback_runtime() -> Option<&'static tokio::runtime::Runtime> {
    FALLBACK_RT
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(FALLBACK_RT_THREADS.load(Ordering::Relaxed))
                .thread_name("impulse-edge-fallback-rt")
                .build()
                .ok()
        })
        .as_ref()
}

static FALLBACK_RT: OnceLock<Option<tokio::runtime::Runtime>> = OnceLock::new();
static FALLBACK_RT_THREADS: AtomicUsize = AtomicUsize::new(2);
