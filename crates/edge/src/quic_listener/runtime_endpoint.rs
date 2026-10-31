use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use tokio::runtime::Handle;

use super::QUICListener;

pub(super) struct RuntimeConnectionSlotGuard {
    active_connections: Arc<AtomicUsize>,
}

impl RuntimeConnectionSlotGuard {
    pub(super) fn new(active_connections: Arc<AtomicUsize>) -> Self {
        Self { active_connections }
    }
}

impl Drop for RuntimeConnectionSlotGuard {
    fn drop(&mut self) {
        self.active_connections.fetch_sub(1, Ordering::AcqRel);
    }
}

impl QUICListener {
    pub(super) fn bind_tcp_listener(
        bind: &str,
        handle: Option<&Handle>,
        context: &str,
    ) -> Result<tokio::net::TcpListener, String> {
        let std_listener = std::net::TcpListener::bind(bind)
            .map_err(|err| format!("failed to bind {context} {bind}: {err}"))?;
        std_listener.set_nonblocking(true).map_err(|err| {
            format!(
                "failed to set {context} listener nonblocking ({}): {}",
                bind, err
            )
        })?;
        let from_std_result = if let Some(handle) = handle {
            let _guard = handle.enter();
            tokio::net::TcpListener::from_std(std_listener)
        } else {
            tokio::net::TcpListener::from_std(std_listener)
        };
        from_std_result
            .map_err(|err| format!("failed to register {context} listener {}: {}", bind, err))
    }

    pub(crate) fn probe_tcp_bind(bind: &str, context: &str) -> Result<(), String> {
        std::net::TcpListener::bind(bind)
            .map(|_| ())
            .map_err(|err| format!("failed to bind {context} {bind}: {err}"))
    }

    pub(super) fn try_claim_runtime_connection_slot(
        active_connections: &Arc<AtomicUsize>,
        max_connections: usize,
    ) -> bool {
        loop {
            let current = active_connections.load(Ordering::Relaxed);
            if current >= max_connections {
                return false;
            }
            if active_connections
                .compare_exchange(
                    current,
                    current.saturating_add(1),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return true;
            }
        }
    }
}
