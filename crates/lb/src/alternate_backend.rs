//! Alternate-backend selection façade.
//!
//! This module owns retry/hedge follow-up backend choice on top of
//! [`UpstreamPool`]. It consumes pool-level read APIs and does not mutate pool
//! internals directly.

use crate::upstream_pool::UpstreamPool;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlternateBackendSelectionMode {
    LoadBalancerReadonly,
    HealthyFallback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlternateBackendChoice {
    pub index: usize,
    pub mode: AlternateBackendSelectionMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlternateBackendFailureReason {
    NoHealthyBackends,
    OnlyExcludedBackendsHealthy,
    PoolUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlternateBackendDecision {
    Select(AlternateBackendChoice),
    DoNotSelect {
        denial: AlternateBackendFailureReason,
    },
}

fn is_excluded(index: usize, excluded_indices: &[usize]) -> bool {
    excluded_indices.contains(&index)
}

pub fn choose_alternate_backend(
    pool: &UpstreamPool,
    excluded_indices: &[usize],
    lb_key: Option<&str>,
) -> AlternateBackendDecision {
    let policy = pool.alternate_backend_policy();

    if policy.readonly_lb_pick {
        let readonly_candidate = pool
            .pick_readonly(lb_key.unwrap_or_default())
            .filter(|index| !is_excluded(*index, excluded_indices));
        if let Some(index) = readonly_candidate {
            return AlternateBackendDecision::Select(AlternateBackendChoice {
                index,
                mode: AlternateBackendSelectionMode::LoadBalancerReadonly,
            });
        }
    }

    if policy.healthy_fallback {
        let fallback_candidate = pool
            .healthy_backend_indices_iter()
            .find(|index| !is_excluded(*index, excluded_indices));
        if let Some(index) = fallback_candidate {
            return AlternateBackendDecision::Select(AlternateBackendChoice {
                index,
                mode: AlternateBackendSelectionMode::HealthyFallback,
            });
        }
    }

    if pool.membership_summary().healthy_backends == 0 {
        AlternateBackendDecision::DoNotSelect {
            denial: AlternateBackendFailureReason::NoHealthyBackends,
        }
    } else {
        AlternateBackendDecision::DoNotSelect {
            denial: AlternateBackendFailureReason::OnlyExcludedBackendsHealthy,
        }
    }
}

#[cfg(test)]
mod tests {
    use impulse_config::runtime::RuntimeAlternateBackendPolicy;

    use super::*;
    use crate::test_support::runtime_upstream_from_addresses;

    fn pool_for(lb_type: &str, backends: &[&str]) -> UpstreamPool {
        UpstreamPool::from_runtime_upstream(&runtime_upstream_from_addresses(
            lb_type, None, backends,
        ))
        .expect("alternate-backend fixture pool should build")
    }

    #[test]
    fn readonly_lb_pick_wins_when_candidate_is_not_excluded() {
        let pool = pool_for("least-connections", &["http://a", "http://b", "http://c"]);

        let decision = choose_alternate_backend(&pool, &[2], None);
        assert_eq!(
            decision,
            AlternateBackendDecision::Select(AlternateBackendChoice {
                index: 0,
                mode: AlternateBackendSelectionMode::LoadBalancerReadonly,
            })
        );
    }

    #[test]
    fn healthy_fallback_runs_when_readonly_pick_hits_excluded_backend() {
        let pool = pool_for("least-connections", &["http://a", "http://b", "http://c"]);

        let decision = choose_alternate_backend(&pool, &[0], None);
        assert_eq!(
            decision,
            AlternateBackendDecision::Select(AlternateBackendChoice {
                index: 1,
                mode: AlternateBackendSelectionMode::HealthyFallback,
            })
        );
    }

    #[test]
    fn alternate_selection_respects_multiple_excluded_backends() {
        let pool = pool_for(
            "least-connections",
            &["http://a", "http://b", "http://c", "http://d"],
        );

        let decision = choose_alternate_backend(&pool, &[0, 1, 2], None);
        assert_eq!(
            decision,
            AlternateBackendDecision::Select(AlternateBackendChoice {
                index: 3,
                mode: AlternateBackendSelectionMode::HealthyFallback,
            })
        );
    }

    #[test]
    fn healthy_fallback_skips_unhealthy_backends() {
        let mut pool = pool_for("least-connections", &["http://a", "http://b", "http://c"]);

        let _ = pool.mark_backend_failure_from_active_check(1);

        let decision = choose_alternate_backend(&pool, &[0], None);
        assert_eq!(
            decision,
            AlternateBackendDecision::Select(AlternateBackendChoice {
                index: 2,
                mode: AlternateBackendSelectionMode::HealthyFallback,
            })
        );
    }

    #[test]
    fn alternate_selection_reports_only_excluded_backends_when_no_candidate_remains() {
        let pool = pool_for("least-connections", &["http://a"]);

        let decision = choose_alternate_backend(&pool, &[0], None);
        assert_eq!(
            decision,
            AlternateBackendDecision::DoNotSelect {
                denial: AlternateBackendFailureReason::OnlyExcludedBackendsHealthy,
            }
        );
    }

    #[test]
    fn readonly_strategy_interaction_uses_load_balancer_mode_for_alternates() {
        let pool = pool_for("least-connections", &["http://a", "http://b", "http://c"]);

        let first = choose_alternate_backend(&pool, &[], Some("tenant-a"));
        let second = choose_alternate_backend(&pool, &[], Some("tenant-b"));

        assert!(matches!(
            first,
            AlternateBackendDecision::Select(AlternateBackendChoice {
                mode: AlternateBackendSelectionMode::LoadBalancerReadonly,
                ..
            })
        ));
        assert!(matches!(
            second,
            AlternateBackendDecision::Select(AlternateBackendChoice {
                mode: AlternateBackendSelectionMode::LoadBalancerReadonly,
                ..
            })
        ));
    }

    #[test]
    fn readonly_lb_pick_respects_lb_key_input_when_returning_typed_selection_mode() {
        let pool = pool_for("least-connections", &["http://a", "http://b", "http://c"]);

        let decision = choose_alternate_backend(&pool, &[1, 2], Some("tenant-a"));

        assert_eq!(
            decision,
            AlternateBackendDecision::Select(AlternateBackendChoice {
                index: 0,
                mode: AlternateBackendSelectionMode::LoadBalancerReadonly,
            })
        );
    }

    #[test]
    fn alternate_selection_reports_no_healthy_backends_when_pool_is_drained() {
        let mut pool = pool_for("least-connections", &["http://a", "http://b"]);

        let _ = pool.mark_backend_failure_from_active_check(0);
        let _ = pool.mark_backend_failure_from_active_check(1);

        let decision = choose_alternate_backend(&pool, &[], None);
        assert_eq!(
            decision,
            AlternateBackendDecision::DoNotSelect {
                denial: AlternateBackendFailureReason::NoHealthyBackends,
            }
        );
    }

    #[test]
    fn alternate_selection_denials_remain_distinct_between_no_healthy_and_only_excluded() {
        let mut no_healthy = pool_for("least-connections", &["http://a", "http://b"]);
        let _ = no_healthy.mark_backend_failure_from_active_check(0);
        let _ = no_healthy.mark_backend_failure_from_active_check(1);
        assert_eq!(
            choose_alternate_backend(&no_healthy, &[], None),
            AlternateBackendDecision::DoNotSelect {
                denial: AlternateBackendFailureReason::NoHealthyBackends,
            }
        );

        let only_excluded = pool_for("least-connections", &["http://a", "http://b"]);
        assert_eq!(
            choose_alternate_backend(&only_excluded, &[0, 1], None),
            AlternateBackendDecision::DoNotSelect {
                denial: AlternateBackendFailureReason::OnlyExcludedBackendsHealthy,
            }
        );
    }

    #[test]
    fn no_healthy_backend_denial_survives_policy_disablement() {
        let mut pool = pool_for("least-connections", &["http://a", "http://b"]);
        pool.set_alternate_backend_policy(RuntimeAlternateBackendPolicy {
            readonly_lb_pick: false,
            healthy_fallback: false,
        });
        let _ = pool.mark_backend_failure_from_active_check(0);
        let _ = pool.mark_backend_failure_from_active_check(1);

        let decision = choose_alternate_backend(&pool, &[0], None);
        assert_eq!(
            decision,
            AlternateBackendDecision::DoNotSelect {
                denial: AlternateBackendFailureReason::NoHealthyBackends,
            }
        );
    }

    #[test]
    fn alternate_selection_respects_disabled_readonly_pick_policy() {
        let mut pool = pool_for("least-connections", &["http://a", "http://b", "http://c"]);
        pool.set_alternate_backend_policy(RuntimeAlternateBackendPolicy {
            readonly_lb_pick: false,
            healthy_fallback: true,
        });

        let decision = choose_alternate_backend(&pool, &[0], None);
        assert_eq!(
            decision,
            AlternateBackendDecision::Select(AlternateBackendChoice {
                index: 1,
                mode: AlternateBackendSelectionMode::HealthyFallback,
            })
        );
    }

    #[test]
    fn only_excluded_backend_denial_survives_when_failover_modes_are_disabled() {
        let mut pool = pool_for("least-connections", &["http://a", "http://b"]);
        pool.set_alternate_backend_policy(RuntimeAlternateBackendPolicy {
            readonly_lb_pick: false,
            healthy_fallback: false,
        });

        let decision = choose_alternate_backend(&pool, &[0], None);
        assert_eq!(
            decision,
            AlternateBackendDecision::DoNotSelect {
                denial: AlternateBackendFailureReason::OnlyExcludedBackendsHealthy,
            }
        );
    }
}
