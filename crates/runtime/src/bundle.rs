use std::sync::Arc;

use crate::GenerationId;

/// Read-only access to the shared and generation-owned portions of a bundle.
pub trait RuntimeStateView {
    type SharedServices;
    type GenerationState;
    type ListenerConfig: Clone;

    fn shared_services(&self) -> &Self::SharedServices;
    fn generation_state(&self) -> &Self::GenerationState;
    fn listener_runtime_config(&self, label: &str) -> Option<Self::ListenerConfig>;
}

/// One immutable runtime generation published to request workers.
pub struct RuntimeBundle<Startup, Config, State> {
    pub generation: GenerationId,
    pub startup: Startup,
    pub runtime_config: Config,
    pub shared_state: Arc<State>,
}

impl<Startup: Clone, Config: Clone, State> Clone for RuntimeBundle<Startup, Config, State> {
    fn clone(&self) -> Self {
        Self {
            generation: self.generation,
            startup: self.startup.clone(),
            runtime_config: self.runtime_config.clone(),
            shared_state: Arc::clone(&self.shared_state),
        }
    }
}

impl<Startup, Config, State> RuntimeBundle<Startup, Config, State>
where
    State: RuntimeStateView,
{
    pub fn startup(&self) -> &Startup {
        &self.startup
    }

    pub fn generation_view(&self) -> RuntimeGenerationView<'_, Startup, Config, State> {
        RuntimeGenerationView {
            generation: self.generation,
            startup: &self.startup,
            runtime_config: &self.runtime_config,
            shared: self.shared_state.shared_services(),
            state: self.shared_state.generation_state(),
            runtime_state: self.shared_state.as_ref(),
        }
    }

    pub fn listener_runtime_config(&self, label: &str) -> Option<State::ListenerConfig> {
        self.shared_state.listener_runtime_config(label)
    }
}

/// Generation-pinned references used while executing one request.
pub struct RuntimeGenerationView<'a, Startup, Config, State>
where
    State: RuntimeStateView,
{
    pub generation: GenerationId,
    pub startup: &'a Startup,
    pub runtime_config: &'a Config,
    pub shared: &'a State::SharedServices,
    pub state: &'a State::GenerationState,
    runtime_state: &'a State,
}

impl<Startup, Config, State> Copy for RuntimeGenerationView<'_, Startup, Config, State> where
    State: RuntimeStateView
{
}

impl<Startup, Config, State> Clone for RuntimeGenerationView<'_, Startup, Config, State>
where
    State: RuntimeStateView,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<Startup, Config, State> RuntimeGenerationView<'_, Startup, Config, State>
where
    State: RuntimeStateView,
{
    pub fn listener_runtime_config(&self, label: &str) -> Option<State::ListenerConfig> {
        self.runtime_state.listener_runtime_config(label)
    }
}

/// Owned pin to one published generation.
pub struct ActiveRuntimeGeneration<Startup, Config, State> {
    bundle: Arc<RuntimeBundle<Startup, Config, State>>,
}

impl<Startup, Config, State> Clone for ActiveRuntimeGeneration<Startup, Config, State> {
    fn clone(&self) -> Self {
        Self {
            bundle: Arc::clone(&self.bundle),
        }
    }
}

impl<Startup, Config, State> ActiveRuntimeGeneration<Startup, Config, State>
where
    State: RuntimeStateView,
{
    pub fn new(bundle: Arc<RuntimeBundle<Startup, Config, State>>) -> Self {
        Self { bundle }
    }

    pub fn bundle(&self) -> &RuntimeBundle<Startup, Config, State> {
        self.bundle.as_ref()
    }

    pub fn generation(&self) -> GenerationId {
        self.bundle.generation
    }

    pub fn startup(&self) -> &Startup {
        &self.bundle.startup
    }

    pub fn runtime_config(&self) -> &Config {
        &self.bundle.runtime_config
    }

    pub fn shared_services(&self) -> &State::SharedServices {
        self.bundle.shared_state.shared_services()
    }

    pub fn state(&self) -> &State::GenerationState {
        self.bundle.shared_state.generation_state()
    }

    pub fn view(&self) -> RuntimeGenerationView<'_, Startup, Config, State> {
        self.bundle.generation_view()
    }

    pub fn listener_runtime_config(&self, label: &str) -> Option<State::ListenerConfig> {
        self.bundle.listener_runtime_config(label)
    }
}
