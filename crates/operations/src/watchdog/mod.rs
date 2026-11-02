mod config;
mod coordinator;
mod time;

pub use config::WatchdogRuntimeConfig;
pub use coordinator::WatchdogCoordinator;
pub use time::now_millis;
