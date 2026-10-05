use std::{
    collections::HashMap,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
};

use impulse_errors::RetryPolicyDenialReason;

pub struct RetryBudget {
    enabled: bool,
    global_ratio_percent: u8,
    per_route_ratio_percent: HashMap<String, u8>,
    global_primary: AtomicU64,
    global_retries: AtomicU64,
    route_stats: Mutex<HashMap<String, (u64, u64)>>,
}

impl RetryBudget {
    pub fn new(
        enabled: bool,
        global_ratio_percent: u8,
        per_route_ratio_percent: HashMap<String, u8>,
    ) -> Self {
        Self {
            enabled,
            global_ratio_percent,
            per_route_ratio_percent,
            global_primary: AtomicU64::new(0),
            global_retries: AtomicU64::new(0),
            route_stats: Mutex::new(HashMap::new()),
        }
    }

    pub fn mark_primary(&self, route: &str) {
        self.global_primary.fetch_add(1, Ordering::Relaxed);
        let mut stats = self.lock_route_stats();
        let entry = stats.entry(route.to_string()).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(1);
    }

    pub fn allow_retry(&self, route: &str) -> Result<(), RetryPolicyDenialReason> {
        if !self.enabled {
            return Ok(());
        }

        let route_ratio = self
            .per_route_ratio_percent
            .get(route)
            .copied()
            .unwrap_or(self.global_ratio_percent);

        let primary = self.global_primary.load(Ordering::Relaxed);
        let global_limit = ((primary * self.global_ratio_percent as u64) / 100).saturating_add(1);
        if self
            .global_retries
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |retries| {
                (retries < global_limit).then_some(retries + 1)
            })
            .is_err()
        {
            return Err(RetryPolicyDenialReason::BudgetDenied);
        }

        let mut route_allowed = true;
        let mut stats = self.lock_route_stats();
        let entry = stats.entry(route.to_string()).or_insert((0, 0));
        let route_limit = ((entry.0 * route_ratio as u64) / 100).saturating_add(1);
        if entry.1 >= route_limit {
            route_allowed = false;
        } else {
            entry.1 = entry.1.saturating_add(1);
        }
        drop(stats);
        if !route_allowed {
            self.global_retries.fetch_sub(1, Ordering::Relaxed);
            return Err(RetryPolicyDenialReason::BudgetDenied);
        }

        Ok(())
    }

    fn lock_route_stats(&self) -> MutexGuard<'_, HashMap<String, (u64, u64)>> {
        match self.route_stats.lock() {
            Ok(stats) => stats,
            Err(poisoned) => {
                self.route_stats.clear_poison();
                poisoned.into_inner()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Barrier, atomic::Ordering},
        thread,
    };

    use impulse_errors::RetryPolicyDenialReason;

    use super::RetryBudget;

    #[test]
    fn allow_retry_denial_does_not_consume_retry_budget_counters() {
        let budget = RetryBudget::new(true, 100, HashMap::new());

        assert_eq!(budget.allow_retry("api"), Ok(()));
        assert_eq!(
            budget.allow_retry("api"),
            Err(RetryPolicyDenialReason::BudgetDenied)
        );
        assert_eq!(
            budget
                .global_primary
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            budget
                .global_retries
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            budget.route_stats.lock().expect("route stats").get("api"),
            Some(&(0, 1))
        );

        budget.mark_primary("api");
        assert_eq!(budget.allow_retry("api"), Ok(()));
        assert_eq!(
            budget.allow_retry("api"),
            Err(RetryPolicyDenialReason::BudgetDenied)
        );
        assert_eq!(
            budget
                .global_primary
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            budget
                .global_retries
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        assert_eq!(
            budget.route_stats.lock().expect("route stats").get("api"),
            Some(&(1, 2))
        );
    }

    #[test]
    fn route_specific_budget_denial_leaves_other_routes_retryable() {
        let budget = RetryBudget::new(
            true,
            100,
            HashMap::from([(String::from("api"), 0), (String::from("other"), 100)]),
        );
        budget.mark_primary("api");
        budget.mark_primary("other");

        assert_eq!(budget.allow_retry("api"), Ok(()));
        assert_eq!(
            budget.allow_retry("api"),
            Err(RetryPolicyDenialReason::BudgetDenied)
        );
        assert_eq!(budget.allow_retry("other"), Ok(()));
        assert_eq!(
            budget
                .global_retries
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        assert_eq!(
            budget.route_stats.lock().expect("route stats").get("api"),
            Some(&(1, 1))
        );
        assert_eq!(
            budget.route_stats.lock().expect("route stats").get("other"),
            Some(&(1, 1))
        );
    }

    #[test]
    fn route_override_does_not_reduce_global_retry_budget() {
        let budget = RetryBudget::new(true, 100, HashMap::from([(String::from("strict"), 0)]));
        budget.mark_primary("strict");
        budget.mark_primary("other");

        assert_eq!(budget.allow_retry("other"), Ok(()));
        assert_eq!(budget.allow_retry("strict"), Ok(()));
        assert_eq!(
            budget.allow_retry("strict"),
            Err(RetryPolicyDenialReason::BudgetDenied)
        );
    }

    #[test]
    fn concurrent_attempts_do_not_overshoot_global_retry_budget() {
        const ATTEMPTS: usize = 64;

        let budget = Arc::new(RetryBudget::new(true, 0, HashMap::new()));
        let barrier = Arc::new(Barrier::new(ATTEMPTS));
        let handles = (0..ATTEMPTS)
            .map(|attempt| {
                let budget = Arc::clone(&budget);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    budget.allow_retry(&format!("route-{attempt}"))
                })
            })
            .collect::<Vec<_>>();

        let admitted = handles
            .into_iter()
            .map(|handle| handle.join().expect("retry attempt thread").is_ok())
            .filter(|admitted| *admitted)
            .count();

        assert_eq!(admitted, 1);
        assert_eq!(budget.global_retries.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn poisoned_route_stats_lock_does_not_disable_route_budget() {
        let budget = Arc::new(RetryBudget::new(
            true,
            100,
            HashMap::from([(String::from("strict"), 0)]),
        ));
        let poisoner = Arc::clone(&budget);

        assert!(
            thread::spawn(move || {
                let _stats = poisoner.route_stats.lock().expect("route stats");
                panic!("poison route stats");
            })
            .join()
            .is_err()
        );

        budget.mark_primary("strict");
        assert_eq!(budget.allow_retry("strict"), Ok(()));
        assert_eq!(
            budget.allow_retry("strict"),
            Err(RetryPolicyDenialReason::BudgetDenied)
        );
        assert_eq!(
            budget
                .route_stats
                .lock()
                .expect("route stats poison should be cleared")
                .get("strict"),
            Some(&(1, 1))
        );
    }
}
