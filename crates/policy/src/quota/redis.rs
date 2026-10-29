use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use redis::{ErrorKind as RedisErrorKind, RedisError, aio::MultiplexedConnection};
use sha2::{Digest, Sha256};
use tokio::{
    sync::{OnceCell, OwnedSemaphorePermit, Semaphore},
    time::timeout,
};

use super::{
    DistributedQuotaCounterBackend, QuotaCounterBackendError, QuotaCounterBackendErrorKind,
    QuotaCounterBackendMetadata, QuotaCounterEvalFuture, QuotaCounterEvaluationDecision,
    QuotaCounterEvaluationOutcome, QuotaCounterEvaluationRequest, QuotaCounterResult,
    QuotaDenyReason, QuotaWindowPolicy, QuotaWindowUsage,
};

pub const REDIS_QUOTA_PROTOCOL_VERSION: &str = "redis-fixed-window/v1";

const REDIS_BACKEND_KIND: &str = "redis";
const REDIS_KEY_PROTOCOL_TAG: &str = "qv1";
const REDIS_KEY_TTL_GRACE_MS: u64 = 1_000;
const REDIS_WINDOW_RESPONSE_FIELD_COUNT: usize = 9;
const REDIS_WINDOW_KIND_BURST: &str = "burst";
const REDIS_WINDOW_KIND_SUSTAINED: &str = "sustained";
const REDIS_QUOTA_EVAL_LUA: &str = r#"
local expected_protocol = "redis-fixed-window/v1"
if ARGV[1] ~= expected_protocol then
    return redis.error_reply("quota protocol mismatch: " .. tostring(ARGV[1]))
end

local now_ms = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])
local window_count = tonumber(ARGV[4])
local first_window_offset = 5
local window_argv_width = 6
local decision = "allow"
local deny_reason = ""
local windows = {}

for index = 1, window_count do
    local arg_index = first_window_offset + ((index - 1) * window_argv_width)
    local kind = ARGV[arg_index]
    local limit = tonumber(ARGV[arg_index + 1])
    local window_ms = tonumber(ARGV[arg_index + 2])
    local bucket_started_at_ms = tonumber(ARGV[arg_index + 3])
    local reset_at_ms = tonumber(ARGV[arg_index + 4])
    local ttl_ms = tonumber(ARGV[arg_index + 5])
    local key = KEYS[index]
    local current = tonumber(redis.call("GET", key) or "0")
    local projected = current + cost
    local remaining = limit - current

    if remaining < 0 then
        remaining = 0
    end

    if projected > limit and deny_reason == "" then
        decision = "deny"
        if kind == "burst" then
            deny_reason = "burst_quota_exhausted"
        else
            deny_reason = "sustained_quota_exhausted"
        end
    end

    windows[index] = {
        kind,
        limit,
        current,
        remaining,
        window_ms,
        math.max(reset_at_ms - now_ms, 0),
        bucket_started_at_ms,
        reset_at_ms,
        key,
        projected,
        ttl_ms,
    }
end

if decision == "allow" then
    for index = 1, window_count do
        local window = windows[index]
        local key = window[9]
        local current = tonumber(window[3])
        local projected = tonumber(window[10])
        local ttl_ms = tonumber(window[11])

        if current == 0 then
            redis.call("PSETEX", key, ttl_ms, projected)
        else
            redis.call("INCRBY", key, cost)
            local existing_ttl_ms = redis.call("PTTL", key)
            if existing_ttl_ms < ttl_ms then
                redis.call("PEXPIRE", key, ttl_ms)
            end
        end

        window[3] = projected
        window[4] = math.max(tonumber(window[2]) - projected, 0)
    end
end

local response = {
    expected_protocol,
    decision,
    deny_reason,
    tostring(now_ms),
    tostring(window_count),
}

for index = 1, window_count do
    local window = windows[index]
    for field = 1, 9 do
        table.insert(response, tostring(window[field]))
    end
end

return response
"#;

struct RedisQuotaWindowSpec {
    kind: &'static str,
    limit: u64,
    window_ms: u64,
    bucket_started_at_unix_ms: u64,
    reset_at_unix_ms: u64,
    storage_key: String,
    ttl_ms: u64,
}

pub struct RedisDistributedQuotaCounterStore {
    client: redis::Client,
    key_prefix: String,
    connect_timeout: Duration,
    command_timeout: Duration,
    max_inflight: Arc<Semaphore>,
    connection: OnceCell<MultiplexedConnection>,
}

impl RedisDistributedQuotaCounterStore {
    pub fn new(
        url: &str,
        key_prefix: &str,
        connect_timeout: Duration,
        command_timeout: Duration,
        max_inflight: usize,
    ) -> Result<Self, QuotaCounterBackendError> {
        let client = redis::Client::open(url).map_err(|error| QuotaCounterBackendError {
            policy_name: None,
            composite_key: None,
            kind: classify_redis_error(&error),
            detail: Some(error.to_string()),
        })?;

        Ok(Self {
            client,
            key_prefix: key_prefix.trim().to_string(),
            connect_timeout,
            command_timeout,
            max_inflight: Arc::new(Semaphore::new(max_inflight.max(1))),
            connection: OnceCell::new(),
        })
    }

    pub fn protocol_version(&self) -> &'static str {
        REDIS_QUOTA_PROTOCOL_VERSION
    }

    pub fn key_prefix(&self) -> &str {
        &self.key_prefix
    }

    async fn evaluate_request(
        &self,
        request: QuotaCounterEvaluationRequest,
    ) -> Result<QuotaCounterEvaluationOutcome, QuotaCounterBackendError> {
        let policy_name = request.policy_name.clone();
        let composite_key = request.composite_key.key.clone();
        let _permit = self
            .acquire_inflight_permit(&policy_name, &composite_key)
            .await?;
        let now_ms = unix_now_ms();
        let windows = build_window_specs(&self.key_prefix, &request, now_ms);

        if windows.is_empty() {
            return Err(QuotaCounterBackendError {
                policy_name: Some(policy_name),
                composite_key: Some(composite_key),
                kind: QuotaCounterBackendErrorKind::Error,
                detail: Some(
                    "distributed quota evaluation requires at least one configured window"
                        .to_string(),
                ),
            });
        }

        let mut connection = self.connection(&policy_name, &composite_key).await?;
        let mut command = redis::cmd("EVAL");
        command.arg(REDIS_QUOTA_EVAL_LUA);
        command.arg(windows.len());

        for window in &windows {
            command.arg(&window.storage_key);
        }

        command.arg(REDIS_QUOTA_PROTOCOL_VERSION);
        command.arg(now_ms as i64);
        command.arg(request.cost as i64);
        command.arg(windows.len() as i64);

        for window in &windows {
            command.arg(window.kind);
            command.arg(window.limit as i64);
            command.arg(window.window_ms as i64);
            command.arg(window.bucket_started_at_unix_ms as i64);
            command.arg(window.reset_at_unix_ms as i64);
            command.arg(window.ttl_ms as i64);
        }

        let response: Vec<String> =
            timeout(self.command_timeout, command.query_async(&mut connection))
                .await
                .map_err(|_| QuotaCounterBackendError {
                    policy_name: Some(policy_name.clone()),
                    composite_key: Some(composite_key.clone()),
                    kind: QuotaCounterBackendErrorKind::Timeout,
                    detail: Some("redis quota evaluation timed out".to_string()),
                })?
                .map_err(|error| QuotaCounterBackendError {
                    policy_name: Some(policy_name.clone()),
                    composite_key: Some(composite_key.clone()),
                    kind: classify_redis_error(&error),
                    detail: Some(error.to_string()),
                })?;

        parse_eval_response(request, &response)
    }

    async fn acquire_inflight_permit(
        &self,
        policy_name: &str,
        composite_key: &str,
    ) -> Result<OwnedSemaphorePermit, QuotaCounterBackendError> {
        self.max_inflight
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| QuotaCounterBackendError {
                policy_name: Some(policy_name.to_string()),
                composite_key: Some(composite_key.to_string()),
                kind: QuotaCounterBackendErrorKind::Unavailable,
                detail: Some("redis quota inflight limiter is closed".to_string()),
            })
    }

    async fn connection(
        &self,
        policy_name: &str,
        composite_key: &str,
    ) -> Result<MultiplexedConnection, QuotaCounterBackendError> {
        let connection = self
            .connection
            .get_or_try_init(|| async {
                timeout(
                    self.connect_timeout,
                    self.client.get_multiplexed_async_connection(),
                )
                .await
                .map_err(|_| QuotaCounterBackendError {
                    policy_name: Some(policy_name.to_string()),
                    composite_key: Some(composite_key.to_string()),
                    kind: QuotaCounterBackendErrorKind::Timeout,
                    detail: Some("redis quota connection timed out".to_string()),
                })?
                .map_err(|error| QuotaCounterBackendError {
                    policy_name: Some(policy_name.to_string()),
                    composite_key: Some(composite_key.to_string()),
                    kind: classify_redis_error(&error),
                    detail: Some(error.to_string()),
                })
            })
            .await?;

        Ok(connection.clone())
    }
}

impl DistributedQuotaCounterBackend for RedisDistributedQuotaCounterStore {
    fn evaluate<'a>(
        &'a self,
        request: QuotaCounterEvaluationRequest,
    ) -> QuotaCounterEvalFuture<'a> {
        Box::pin(async move { self.evaluate_request(request).await })
    }
}

fn build_window_specs(
    key_prefix: &str,
    request: &QuotaCounterEvaluationRequest,
    now_ms: u64,
) -> Vec<RedisQuotaWindowSpec> {
    let mut windows = Vec::new();

    if let Some(window) = request.burst.as_ref() {
        windows.push(build_window_spec(
            key_prefix,
            request,
            REDIS_WINDOW_KIND_BURST,
            window,
            now_ms,
        ));
    }
    if let Some(window) = request.sustained.as_ref() {
        windows.push(build_window_spec(
            key_prefix,
            request,
            REDIS_WINDOW_KIND_SUSTAINED,
            window,
            now_ms,
        ));
    }

    windows
}

fn build_window_spec(
    key_prefix: &str,
    request: &QuotaCounterEvaluationRequest,
    kind: &'static str,
    window: &QuotaWindowPolicy,
    now_ms: u64,
) -> RedisQuotaWindowSpec {
    let window_ms = window.window.as_millis().max(1) as u64;
    let bucket_started_at_unix_ms = now_ms - (now_ms % window_ms);
    let reset_at_unix_ms = bucket_started_at_unix_ms.saturating_add(window_ms);
    let reset_after_ms = reset_at_unix_ms.saturating_sub(now_ms);
    let ttl_ms = reset_after_ms.max(1).saturating_add(REDIS_KEY_TTL_GRACE_MS);
    let digest = composite_key_digest(&request.composite_key.key);
    let storage_key = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        key_prefix,
        REDIS_KEY_PROTOCOL_TAG,
        encode_key_component(&request.policy_name),
        kind,
        window_ms,
        bucket_started_at_unix_ms,
        digest
    );

    RedisQuotaWindowSpec {
        kind,
        limit: window.requests,
        window_ms,
        bucket_started_at_unix_ms,
        reset_at_unix_ms,
        storage_key,
        ttl_ms,
    }
}

fn parse_eval_response(
    request: QuotaCounterEvaluationRequest,
    response: &[String],
) -> Result<QuotaCounterEvaluationOutcome, QuotaCounterBackendError> {
    let policy_name = request.policy_name.clone();
    let composite_key = request.composite_key.key.clone();

    if response.len() < 5 {
        return Err(QuotaCounterBackendError {
            policy_name: Some(policy_name),
            composite_key: Some(composite_key),
            kind: QuotaCounterBackendErrorKind::Error,
            detail: Some("redis quota response was truncated".to_string()),
        });
    }

    let protocol_version = response[0].clone();
    if protocol_version != REDIS_QUOTA_PROTOCOL_VERSION {
        return Err(QuotaCounterBackendError {
            policy_name: Some(request.policy_name),
            composite_key: Some(request.composite_key.key),
            kind: QuotaCounterBackendErrorKind::Error,
            detail: Some(format!(
                "redis quota protocol mismatch: expected {}, got {}",
                REDIS_QUOTA_PROTOCOL_VERSION, protocol_version
            )),
        });
    }

    let decision_raw = response[1].as_str();
    let deny_reason_raw = response[2].as_str();
    let evaluated_at_unix_ms = parse_u64_field(&response[3], "evaluated_at_unix_ms", &request)?;
    let window_count = parse_u64_field(&response[4], "window_count", &request)? as usize;
    let expected_len = 5 + (window_count * REDIS_WINDOW_RESPONSE_FIELD_COUNT);

    if response.len() != expected_len {
        return Err(QuotaCounterBackendError {
            policy_name: Some(request.policy_name),
            composite_key: Some(request.composite_key.key),
            kind: QuotaCounterBackendErrorKind::Error,
            detail: Some(format!(
                "redis quota response field mismatch: expected {}, got {}",
                expected_len,
                response.len()
            )),
        });
    }

    let mut burst = None;
    let mut sustained = None;

    for index in 0..window_count {
        let offset = 5 + (index * REDIS_WINDOW_RESPONSE_FIELD_COUNT);
        let kind = response[offset].as_str();
        let usage = QuotaWindowUsage {
            limit: parse_u64_field(&response[offset + 1], "limit", &request)?,
            consumed: parse_u64_field(&response[offset + 2], "consumed", &request)?,
            remaining: parse_u64_field(&response[offset + 3], "remaining", &request)?,
            window: Duration::from_millis(parse_u64_field(
                &response[offset + 4],
                "window_ms",
                &request,
            )?),
            reset_after: Some(Duration::from_millis(parse_u64_field(
                &response[offset + 5],
                "reset_after_ms",
                &request,
            )?)),
            bucket_started_at_unix_ms: Some(parse_u64_field(
                &response[offset + 6],
                "bucket_started_at_unix_ms",
                &request,
            )?),
            reset_at_unix_ms: Some(parse_u64_field(
                &response[offset + 7],
                "reset_at_unix_ms",
                &request,
            )?),
            storage_key: Some(response[offset + 8].clone()),
        };

        match kind {
            REDIS_WINDOW_KIND_BURST => burst = Some(usage),
            REDIS_WINDOW_KIND_SUSTAINED => sustained = Some(usage),
            _ => {
                return Err(QuotaCounterBackendError {
                    policy_name: Some(request.policy_name),
                    composite_key: Some(request.composite_key.key),
                    kind: QuotaCounterBackendErrorKind::Error,
                    detail: Some(format!("unknown redis quota window kind: {kind}")),
                });
            }
        }
    }

    let decision = match decision_raw {
        "allow" => QuotaCounterEvaluationDecision::Allowed,
        "deny" => QuotaCounterEvaluationDecision::Denied(
            QuotaDenyReason::from_slug(deny_reason_raw).ok_or_else(|| {
                QuotaCounterBackendError {
                    policy_name: Some(request.policy_name.clone()),
                    composite_key: Some(request.composite_key.key.clone()),
                    kind: QuotaCounterBackendErrorKind::Error,
                    detail: Some(format!(
                        "unknown redis quota deny reason: {deny_reason_raw}"
                    )),
                }
            })?,
        ),
        _ => {
            return Err(QuotaCounterBackendError {
                policy_name: Some(request.policy_name),
                composite_key: Some(request.composite_key.key),
                kind: QuotaCounterBackendErrorKind::Error,
                detail: Some(format!("unknown redis quota decision: {decision_raw}")),
            });
        }
    };

    Ok(QuotaCounterEvaluationOutcome {
        matched_policy: request.policy_name,
        composite_key: request.composite_key,
        decision,
        counter: QuotaCounterResult { burst, sustained },
        backend_metadata: QuotaCounterBackendMetadata {
            backend_kind: REDIS_BACKEND_KIND.to_string(),
            protocol_version,
            evaluated_at_unix_ms: Some(evaluated_at_unix_ms),
        },
    })
}

fn parse_u64_field(
    value: &str,
    field: &str,
    request: &QuotaCounterEvaluationRequest,
) -> Result<u64, QuotaCounterBackendError> {
    value
        .parse::<u64>()
        .map_err(|error| QuotaCounterBackendError {
            policy_name: Some(request.policy_name.clone()),
            composite_key: Some(request.composite_key.key.clone()),
            kind: QuotaCounterBackendErrorKind::Error,
            detail: Some(format!("invalid redis quota field {field}: {error}")),
        })
}

fn composite_key_digest(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn encode_key_component(value: &str) -> String {
    format!("{}:{}", value.len(), value)
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

fn classify_redis_error(error: &RedisError) -> QuotaCounterBackendErrorKind {
    if error.is_timeout() {
        return QuotaCounterBackendErrorKind::Timeout;
    }
    if error.is_connection_dropped() {
        return QuotaCounterBackendErrorKind::Unavailable;
    }

    match error.kind() {
        RedisErrorKind::BusyLoadingError
        | RedisErrorKind::MasterDown
        | RedisErrorKind::ClusterDown
        | RedisErrorKind::TryAgain
        | RedisErrorKind::IoError => QuotaCounterBackendErrorKind::Unavailable,
        _ => QuotaCounterBackendErrorKind::Error,
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, time::Duration};

    use super::*;
    use crate::quota::{
        QuotaCompositeKey, QuotaIdentityLabels, QuotaPolicyRuntime, QuotaSelectorDimensions,
        QuotaSelectorMatcher,
    };

    fn sample_request() -> QuotaCounterEvaluationRequest {
        let policy = QuotaPolicyRuntime {
            name: "tenant-quota".to_string(),
            route_allowlist: HashSet::from(["api".to_string()]),
            selector: QuotaSelectorMatcher {
                route: true,
                tenant: None,
                token: None,
                client: None,
            },
            burst: Some(QuotaWindowPolicy {
                requests: 50,
                window: Duration::from_secs(1),
            }),
            sustained: Some(QuotaWindowPolicy {
                requests: 500,
                window: Duration::from_secs(60),
            }),
        };
        let composite_key = QuotaCompositeKey {
            policy_name: "tenant-quota".to_string(),
            key: "policy=12:tenant-quota|route=3:api|tenant=4:acme|".to_string(),
            labels: QuotaIdentityLabels {
                route: Some("api".to_string()),
                tenant: Some("acme".to_string()),
                token: None,
                client: None,
            },
            dimensions: QuotaSelectorDimensions {
                route: true,
                tenant: true,
                token: false,
                client: false,
            },
        };

        policy.counter_request(composite_key)
    }

    #[test]
    fn redis_window_specs_encode_protocol_and_bucket_identity() {
        let request = sample_request();
        let windows = build_window_specs("impulse:quota", &request, 1_700_000_000_125);

        assert_eq!(windows.len(), 2);
        assert!(windows[0].storage_key.starts_with("impulse:quota:qv1:"));
        assert!(
            windows[0]
                .storage_key
                .contains(":burst:1000:1700000000000:")
        );
        assert!(
            windows[1]
                .storage_key
                .contains(":sustained:60000:1699999980000:")
        );
        assert_eq!(windows[0].ttl_ms, 1_875);
    }

    #[test]
    fn redis_eval_response_parses_operator_metadata() {
        let request = sample_request();
        let response = vec![
            REDIS_QUOTA_PROTOCOL_VERSION.to_string(),
            "deny".to_string(),
            "burst_quota_exhausted".to_string(),
            "1700000000125".to_string(),
            "2".to_string(),
            "burst".to_string(),
            "50".to_string(),
            "50".to_string(),
            "0".to_string(),
            "1000".to_string(),
            "875".to_string(),
            "1700000000000".to_string(),
            "1700000001000".to_string(),
            "impulse:quota:qv1:12:tenant-quota:burst:1000:1700000000000:abc".to_string(),
            "sustained".to_string(),
            "500".to_string(),
            "320".to_string(),
            "180".to_string(),
            "60000".to_string(),
            "59875".to_string(),
            "1699999980000".to_string(),
            "1700000040000".to_string(),
            "impulse:quota:qv1:12:tenant-quota:sustained:60000:1699999980000:def".to_string(),
        ];

        let outcome = parse_eval_response(request, &response).expect("response should parse");

        assert_eq!(outcome.matched_policy, "tenant-quota");
        assert_eq!(
            outcome.decision,
            QuotaCounterEvaluationDecision::Denied(QuotaDenyReason::BurstQuotaExhausted)
        );
        assert_eq!(outcome.backend_metadata.backend_kind, "redis");
        assert_eq!(
            outcome.backend_metadata.protocol_version,
            REDIS_QUOTA_PROTOCOL_VERSION
        );
        assert_eq!(
            outcome.backend_metadata.evaluated_at_unix_ms,
            Some(1_700_000_000_125)
        );
        assert_eq!(
            outcome
                .counter
                .burst
                .as_ref()
                .and_then(|window| window.storage_key.as_deref()),
            Some("impulse:quota:qv1:12:tenant-quota:burst:1000:1700000000000:abc")
        );
        assert_eq!(
            outcome
                .counter
                .sustained
                .as_ref()
                .and_then(|window| window.reset_at_unix_ms),
            Some(1_700_000_040_000)
        );
    }

    #[test]
    fn redis_eval_response_parses_allowed_atomic_multi_window_updates() {
        let request = sample_request();
        let response = vec![
            REDIS_QUOTA_PROTOCOL_VERSION.to_string(),
            "allow".to_string(),
            String::new(),
            "1700000000125".to_string(),
            "2".to_string(),
            "burst".to_string(),
            "50".to_string(),
            "7".to_string(),
            "43".to_string(),
            "1000".to_string(),
            "875".to_string(),
            "1700000000000".to_string(),
            "1700000001000".to_string(),
            "impulse:quota:qv1:12:tenant-quota:burst:1000:1700000000000:abc".to_string(),
            "sustained".to_string(),
            "500".to_string(),
            "129".to_string(),
            "371".to_string(),
            "60000".to_string(),
            "59875".to_string(),
            "1699999980000".to_string(),
            "1700000040000".to_string(),
            "impulse:quota:qv1:12:tenant-quota:sustained:60000:1699999980000:def".to_string(),
        ];

        let outcome = parse_eval_response(request, &response).expect("response should parse");

        assert_eq!(outcome.decision, QuotaCounterEvaluationDecision::Allowed);
        assert_eq!(
            outcome.counter.burst.as_ref().map(|window| window.consumed),
            Some(7)
        );
        assert_eq!(
            outcome
                .counter
                .sustained
                .as_ref()
                .map(|window| window.consumed),
            Some(129)
        );
    }

    #[test]
    fn redis_eval_response_rejects_protocol_and_reason_contract_violations() {
        let request = sample_request();

        let protocol_mismatch = parse_eval_response(
            request.clone(),
            &[
                "redis-fixed-window/v999".to_string(),
                "allow".to_string(),
                String::new(),
                "1700000000125".to_string(),
                "0".to_string(),
            ],
        )
        .expect_err("protocol mismatch must fail");
        assert_eq!(protocol_mismatch.kind, QuotaCounterBackendErrorKind::Error);
        assert!(
            protocol_mismatch
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("protocol mismatch"))
        );

        let unknown_reason = parse_eval_response(
            request,
            &[
                REDIS_QUOTA_PROTOCOL_VERSION.to_string(),
                "deny".to_string(),
                "mystery_reason".to_string(),
                "1700000000125".to_string(),
                "0".to_string(),
            ],
        )
        .expect_err("unknown deny reason must fail");
        assert_eq!(unknown_reason.kind, QuotaCounterBackendErrorKind::Error);
        assert!(
            unknown_reason
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("unknown redis quota deny reason"))
        );
    }

    #[test]
    fn redis_error_classification_distinguishes_retryable_and_fatal_failures() {
        let retryable = RedisError::from((RedisErrorKind::TryAgain, "retry later"));
        assert_eq!(
            classify_redis_error(&retryable),
            QuotaCounterBackendErrorKind::Unavailable
        );

        let fatal = RedisError::from((RedisErrorKind::ResponseError, "bad lua response"));
        assert_eq!(
            classify_redis_error(&fatal),
            QuotaCounterBackendErrorKind::Error
        );
    }
}
