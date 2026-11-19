use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use pingora_core::connectors::http::Connector;

struct PingoraPoolGeneration {
    generation: u64,
    connector: Arc<Connector>,
    draining: AtomicBool,
}

#[derive(Clone)]
pub(crate) struct PingoraPoolLease {
    generation: Arc<PingoraPoolGeneration>,
}

impl PingoraPoolLease {
    pub fn generation(&self) -> u64 {
        self.generation.generation
    }

    pub fn connector(&self) -> &Connector {
        &self.generation.connector
    }

    pub fn is_draining(&self) -> bool {
        self.generation.draining.load(Ordering::Acquire)
    }
}

pub(crate) struct PingoraPool {
    generation: Arc<PingoraPoolGeneration>,
}

impl PingoraPool {
    pub fn new(generation: u64) -> Self {
        Self {
            generation: Self::generation(generation),
        }
    }

    pub fn acquire(&self) -> Option<PingoraPoolLease> {
        if self.generation.draining.load(Ordering::Acquire) {
            None
        } else {
            Some(PingoraPoolLease {
                generation: Arc::clone(&self.generation),
            })
        }
    }

    pub fn drain(&self) {
        self.generation.draining.store(true, Ordering::Release);
    }

    fn generation(generation: u64) -> Arc<PingoraPoolGeneration> {
        Arc::new(PingoraPoolGeneration {
            generation,
            connector: Arc::new(Connector::new(None)),
            draining: AtomicBool::new(false),
        })
    }
}
