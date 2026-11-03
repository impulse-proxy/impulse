//! Compiled, protocol-neutral traffic plugin plans.

#![forbid(unsafe_code)]
#![deny(unused_crate_dependencies)]
#![warn(unreachable_pub)]

mod instance;
mod plan;

pub use instance::{
    CompiledAsyncRequestPlugin, CompiledCachePlugin, CompiledConnectionPlugin,
    CompiledRequestPlugin, CompiledResponsePlugin,
};
pub use plan::{CompiledConnectionPlan, CompiledPluginPlan};
