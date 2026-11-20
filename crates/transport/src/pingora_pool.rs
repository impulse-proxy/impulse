use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use pingora_core::connectors::http::Connector;

pub(crate) struct PingoraPoolGeneration {
    generation: u64,
    connector: Connector,
    draining: AtomicBool,
}

impl PingoraPoolGeneration {
    pub fn new(generation: u64) -> Arc<Self> {
        Arc::new(Self {
            generation,
            connector: Connector::new(None),
            draining: AtomicBool::new(false),
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn connector(&self) -> &Connector {
        &self.connector
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    pub fn acquire(self: &Arc<Self>) -> Option<Arc<Self>> {
        if self.is_draining() {
            None
        } else {
            Some(Arc::clone(self))
        }
    }

    pub fn drain(&self) {
        self.draining.store(true, Ordering::Release);
    }
}
