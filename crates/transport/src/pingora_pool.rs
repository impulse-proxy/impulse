use std::sync::{Arc, RwLock};

use pingora_core::connectors::http::Connector;

struct PingoraPoolGeneration {
    generation: u64,
    connector: Arc<Connector>,
}

#[derive(Clone)]
pub struct PingoraPoolLease {
    generation: Arc<PingoraPoolGeneration>,
}

impl PingoraPoolLease {
    pub fn generation(&self) -> u64 {
        self.generation.generation
    }

    pub fn connector(&self) -> &Connector {
        &self.generation.connector
    }
}

pub struct PingoraPool {
    active: RwLock<Option<Arc<PingoraPoolGeneration>>>,
}

impl PingoraPool {
    pub fn new(generation: u64) -> Self {
        Self {
            active: RwLock::new(Some(Self::generation(generation))),
        }
    }

    pub fn acquire(&self) -> Option<PingoraPoolLease> {
        self.active
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|generation| PingoraPoolLease {
                generation: Arc::clone(generation),
            })
    }

    pub fn rotate(&self, generation: u64) {
        let mut active = self
            .active
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if active
            .as_ref()
            .is_some_and(|active| active.generation == generation)
        {
            return;
        }
        *active = Some(Self::generation(generation));
    }

    pub fn drain(&self) {
        self.active
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }

    fn generation(generation: u64) -> Arc<PingoraPoolGeneration> {
        Arc::new(PingoraPoolGeneration {
            generation,
            connector: Arc::new(Connector::new(None)),
        })
    }
}
