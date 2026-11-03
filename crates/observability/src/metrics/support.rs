use super::*;

pub(super) fn normalize_metric_label(raw: &str, fallback: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

pub(super) fn status_class_label(status: Option<u16>) -> &'static str {
    match status {
        Some(100..=199) => "1xx",
        Some(200..=299) => "2xx",
        Some(300..=399) => "3xx",
        Some(400..=499) => "4xx",
        Some(500..=599) => "5xx",
        Some(_) => "other",
        None => "unknown",
    }
}

pub(super) fn route_outcome_label(outcome: RouteOutcome) -> &'static str {
    match outcome {
        RouteOutcome::Success => "success",
        RouteOutcome::Failure => "failure",
        RouteOutcome::RateLimited => "rate_limited",
        RouteOutcome::Timeout => "timeout",
        RouteOutcome::BackendError => "backend_error",
        RouteOutcome::OverloadShed => "overload_shed",
    }
}

pub(super) fn increment_label_counter(counter: &RwLock<HashMap<String, u64>>, label: &str) -> bool {
    if let Ok(mut guard) = counter.write() {
        if let Some(value) = guard.get_mut(label) {
            *value = value.saturating_add(1);
        } else {
            guard.insert(label.to_string(), 1);
        }
        true
    } else {
        false
    }
}

pub(super) fn jwks_source_state_entry_mut<'a>(
    states: &'a mut HashMap<String, JwksSourceState>,
    jwks_source_id: &str,
) -> &'a mut JwksSourceState {
    states
        .entry(jwks_source_id.to_string())
        .or_insert_with(|| JwksSourceState {
            jwks_source_id: jwks_source_id.to_string(),
            ..JwksSourceState::default()
        })
}
