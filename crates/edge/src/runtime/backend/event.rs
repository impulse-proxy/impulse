use std::time::Duration;

use http::StatusCode;
use impulse_lb::health::HealthFailureReason;

use super::state::{
    BackendHealthState, BackendIdentity, BackendLifecycleSnapshot, BackendMembershipState,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendLifecycleEvent {
    HealthObservation(BackendHealthObservation),
    RequestFeedback(BackendRequestFeedback),
    Mutation(BackendLifecycleMutation),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendLifecycleMutation {
    HealthUpdated {
        identity: BackendIdentity,
        state: BackendHealthState,
    },
    MembershipUpdated {
        identity: BackendIdentity,
        state: BackendMembershipState,
    },
    SnapshotPublished(BackendLifecycleSnapshot),
    Noop {
        identity: BackendIdentity,
        reason: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendHealthObservation {
    pub identity: BackendIdentity,
    pub source: BackendHealthObservationSource,
    pub outcome: BackendHealthObservationOutcome,
    pub reason: Option<HealthFailureReason>,
}

impl BackendHealthObservation {
    pub fn active_check(
        identity: BackendIdentity,
        outcome: BackendHealthObservationOutcome,
        reason: Option<HealthFailureReason>,
    ) -> Self {
        Self {
            identity,
            source: BackendHealthObservationSource::ActiveCheck,
            outcome,
            reason,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendHealthObservationSource {
    ActiveCheck,
    PassiveRequest,
    RequestCompletion,
    ControlPlane,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendHealthObservationOutcome {
    Success,
    Failure,
    Neutral,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendRequestFeedback {
    pub identity: BackendIdentity,
    pub elapsed: Duration,
    pub status: Option<u16>,
    pub outcome: BackendRequestFeedbackOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendRequestFeedbackOutcome {
    Success,
    Neutral,
    Failure { reason: Option<HealthFailureReason> },
}

impl BackendRequestFeedback {
    pub fn from_status(identity: BackendIdentity, elapsed: Duration, status: StatusCode) -> Self {
        let outcome = if status.is_server_error() {
            BackendRequestFeedbackOutcome::Failure {
                reason: Some(HealthFailureReason::HttpStatus5xx),
            }
        } else if status.is_client_error() {
            BackendRequestFeedbackOutcome::Neutral
        } else {
            BackendRequestFeedbackOutcome::Success
        };

        Self {
            identity,
            elapsed,
            status: Some(status.as_u16()),
            outcome,
        }
    }

    pub fn failure(
        identity: BackendIdentity,
        elapsed: Duration,
        status: Option<u16>,
        reason: Option<HealthFailureReason>,
    ) -> Self {
        Self {
            identity,
            elapsed,
            status,
            outcome: BackendRequestFeedbackOutcome::Failure { reason },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_feedback_from_status_maps_success_client_error_and_server_error() {
        let identity = BackendIdentity::new("https://backend.internal:8443");

        let success = BackendRequestFeedback::from_status(
            identity.clone(),
            Duration::from_millis(5),
            StatusCode::OK,
        );
        assert!(matches!(
            success.outcome,
            BackendRequestFeedbackOutcome::Success
        ));
        assert_eq!(success.status, Some(200));

        let client_error = BackendRequestFeedback::from_status(
            identity.clone(),
            Duration::from_millis(5),
            StatusCode::TOO_MANY_REQUESTS,
        );
        assert!(matches!(
            client_error.outcome,
            BackendRequestFeedbackOutcome::Neutral
        ));
        assert_eq!(client_error.status, Some(429));

        let server_error = BackendRequestFeedback::from_status(
            identity,
            Duration::from_millis(5),
            StatusCode::BAD_GATEWAY,
        );
        assert!(matches!(
            server_error.outcome,
            BackendRequestFeedbackOutcome::Failure {
                reason: Some(HealthFailureReason::HttpStatus5xx)
            }
        ));
        assert_eq!(server_error.status, Some(502));
    }

    #[test]
    fn explicit_request_feedback_failure_preserves_reason_mapping() {
        let timeout = BackendRequestFeedback::failure(
            BackendIdentity::new("https://backend.internal:8443"),
            Duration::from_millis(50),
            None,
            Some(HealthFailureReason::Timeout),
        );
        assert!(matches!(
            timeout.outcome,
            BackendRequestFeedbackOutcome::Failure {
                reason: Some(HealthFailureReason::Timeout)
            }
        ));
        assert_eq!(timeout.status, None);

        let transport = BackendRequestFeedback::failure(
            BackendIdentity::new("https://backend.internal:8443"),
            Duration::from_millis(50),
            Some(0),
            Some(HealthFailureReason::Transport),
        );
        assert!(matches!(
            transport.outcome,
            BackendRequestFeedbackOutcome::Failure {
                reason: Some(HealthFailureReason::Transport)
            }
        ));
        assert_eq!(transport.status, Some(0));
    }
}
