pub use impulse_contracts::HealthFailureReason;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthTransition {
    BecameHealthy,
    BecameUnhealthy,
}
