use super::*;

impl UnavailableDistributedQuotaCounterStore {
    pub fn new(error: QuotaCounterBackendError) -> Self {
        Self { error }
    }
}

impl DistributedQuotaCounterBackend for UnavailableDistributedQuotaCounterStore {
    fn evaluate<'a>(
        &'a self,
        request: QuotaCounterEvaluationRequest,
    ) -> QuotaCounterEvalFuture<'a> {
        let mut error = self.error.clone();
        if error.policy_name.is_none() {
            error.policy_name = Some(request.policy_name);
        }
        if error.composite_key.is_none() {
            error.composite_key = Some(request.composite_key.key);
        }
        Box::pin(async move { Err(error) })
    }
}

impl DegradedQuotaCounterBackend {
    pub fn new(
        primary: SharedDistributedQuotaCounterBackend,
        primary_backend_kind: &str,
        local_fallback: Arc<InMemoryDistributedQuotaCounterStore>,
    ) -> Self {
        Self {
            primary,
            primary_backend_kind: primary_backend_kind.to_string(),
            local_fallback,
        }
    }
}

impl DistributedQuotaCounterBackend for DegradedQuotaCounterBackend {
    fn evaluate<'a>(
        &'a self,
        request: QuotaCounterEvaluationRequest,
    ) -> QuotaCounterEvalFuture<'a> {
        Box::pin(async move {
            match self.primary.evaluate(request.clone()).await {
                Ok(outcome) => Ok(outcome),
                Err(primary_error) if should_attempt_local_fallback(&primary_error) => {
                    match self.local_fallback.evaluate(request).await {
                        Ok(mut fallback_outcome) => {
                            fallback_outcome.backend_metadata.backend_kind =
                                local_fallback_backend_mode(
                                    &self.primary_backend_kind,
                                    primary_error.deny_reason(),
                                );
                            fallback_outcome.backend_metadata.protocol_version = format!(
                                "{}+{}",
                                LOCAL_FALLBACK_PROTOCOL_VERSION,
                                fallback_outcome.backend_metadata.protocol_version
                            );
                            Ok(fallback_outcome)
                        }
                        Err(fallback_error) => Err(combine_primary_and_fallback_error(
                            primary_error,
                            fallback_error,
                        )),
                    }
                }
                Err(primary_error) => Err(primary_error),
            }
        })
    }
}

impl QuotaCounterBackend {
    pub fn backend_kind(&self) -> &'static str {
        match self {
            Self::InMemory { .. } => "in_memory",
            Self::Redis { .. } => "redis",
        }
    }

    fn from_runtime(value: &ConfigRuntimeQuotaCounterBackend) -> Self {
        match value {
            ConfigRuntimeQuotaCounterBackend::InMemory { key_prefix } => Self::InMemory {
                key_prefix: key_prefix.clone(),
            },
            ConfigRuntimeQuotaCounterBackend::Redis {
                url,
                key_prefix,
                connect_timeout,
                command_timeout,
                max_inflight,
            } => Self::Redis {
                url: url.clone(),
                key_prefix: key_prefix.clone(),
                connect_timeout: *connect_timeout,
                command_timeout: *command_timeout,
                max_inflight: *max_inflight,
            },
        }
    }

    fn from_raw(value: &RawQuotaCounterBackend) -> Self {
        match value {
            RawQuotaCounterBackend::InMemory { key_prefix } => Self::InMemory {
                key_prefix: key_prefix.trim().to_string(),
            },
            RawQuotaCounterBackend::Redis {
                url,
                key_prefix,
                connect_timeout_ms,
                command_timeout_ms,
                max_inflight,
            } => Self::Redis {
                url: url.trim().to_string(),
                key_prefix: key_prefix.trim().to_string(),
                connect_timeout: Duration::from_millis(*connect_timeout_ms),
                command_timeout: Duration::from_millis(*command_timeout_ms),
                max_inflight: *max_inflight,
            },
        }
    }

    pub fn redis_store(
        &self,
    ) -> Result<Option<Arc<RedisDistributedQuotaCounterStore>>, QuotaCounterBackendError> {
        match self {
            Self::InMemory { .. } => Ok(None),
            Self::Redis {
                url,
                key_prefix,
                connect_timeout,
                command_timeout,
                max_inflight,
            } => RedisDistributedQuotaCounterStore::new(
                url,
                key_prefix,
                *connect_timeout,
                *command_timeout,
                *max_inflight,
            )
            .map(|store| Some(Arc::new(store))),
        }
    }

    pub fn in_memory_store(
        &self,
    ) -> Result<Option<Arc<InMemoryDistributedQuotaCounterStore>>, QuotaCounterBackendError> {
        match self {
            Self::InMemory { key_prefix } => Ok(Some(Arc::new(
                InMemoryDistributedQuotaCounterStore::bounded(
                    key_prefix,
                    memory::DEFAULT_IN_MEMORY_QUOTA_MAX_ENTRIES,
                ),
            ))),
            Self::Redis { .. } => Ok(None),
        }
    }

    pub fn distributed_store(
        &self,
    ) -> Result<SharedDistributedQuotaCounterBackend, QuotaCounterBackendError> {
        match self {
            Self::InMemory { key_prefix } => {
                Ok(Arc::new(InMemoryDistributedQuotaCounterStore::bounded(
                    key_prefix,
                    memory::DEFAULT_IN_MEMORY_QUOTA_MAX_ENTRIES,
                )))
            }
            Self::Redis {
                url,
                key_prefix,
                connect_timeout,
                command_timeout,
                max_inflight,
            } => Ok(Arc::new(RedisDistributedQuotaCounterStore::new(
                url,
                key_prefix,
                *connect_timeout,
                *command_timeout,
                *max_inflight,
            )?)),
        }
    }
}

impl QuotaRuntime {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            enforcement: QuotaEnforcementMode::Enforce,
            backend_failure_policy: QuotaBackendFailurePolicy::FailClosed,
            backend: QuotaCounterBackend::InMemory {
                key_prefix: "impulse:quota".to_string(),
            },
            local_fallback: None,
            policies: Vec::new(),
        }
    }

    pub fn from_resilience_config(config: &ResilienceConfig) -> Self {
        Self::from_raw_config(&config.quota)
    }

    pub fn from_rate_limit_policies(
        rate_limit_policy: &impulse_config::runtime::RuntimeRateLimitPolicy,
    ) -> Self {
        Self::from_runtime_policy_set(&rate_limit_policy.quota)
    }

    pub fn from_runtime_policy_set(config: &ConfigRuntimeQuotaPolicySet) -> Self {
        Self {
            enabled: config.enabled,
            enforcement: match config.enforcement {
                ConfigRuntimeQuotaEnforcementMode::Shadow => QuotaEnforcementMode::Shadow,
                ConfigRuntimeQuotaEnforcementMode::Enforce => QuotaEnforcementMode::Enforce,
            },
            backend_failure_policy: match config.backend_failure_policy {
                ConfigRuntimeQuotaBackendFailurePolicy::FailOpen => {
                    QuotaBackendFailurePolicy::FailOpen
                }
                ConfigRuntimeQuotaBackendFailurePolicy::FailClosed => {
                    QuotaBackendFailurePolicy::FailClosed
                }
            },
            backend: QuotaCounterBackend::from_runtime(&config.backend),
            local_fallback: config
                .local_fallback
                .as_ref()
                .map(QuotaLocalFallbackPolicy::from_runtime),
            policies: config
                .policies
                .iter()
                .map(QuotaPolicyRuntime::from_runtime)
                .collect(),
        }
    }

    fn from_raw_config(config: &RawQuotaPolicyConfig) -> Self {
        Self {
            enabled: config.enabled,
            enforcement: match config.enforcement {
                RawQuotaEnforcementMode::Shadow => QuotaEnforcementMode::Shadow,
                RawQuotaEnforcementMode::Enforce => QuotaEnforcementMode::Enforce,
            },
            backend_failure_policy: match config.backend_failure_policy {
                RawQuotaBackendFailurePolicy::FailOpen => QuotaBackendFailurePolicy::FailOpen,
                RawQuotaBackendFailurePolicy::FailClosed => QuotaBackendFailurePolicy::FailClosed,
            },
            backend: QuotaCounterBackend::from_raw(&config.backend),
            local_fallback: config
                .local_fallback
                .as_ref()
                .map(QuotaLocalFallbackPolicy::from_raw),
            policies: config
                .policies
                .iter()
                .map(QuotaPolicyRuntime::from_raw)
                .collect(),
        }
    }

    pub fn redis_store(
        &self,
    ) -> Result<Option<Arc<RedisDistributedQuotaCounterStore>>, QuotaCounterBackendError> {
        self.backend.redis_store()
    }

    pub fn in_memory_store(
        &self,
    ) -> Result<Option<Arc<InMemoryDistributedQuotaCounterStore>>, QuotaCounterBackendError> {
        self.backend.in_memory_store()
    }

    pub fn distributed_store(
        &self,
    ) -> Result<SharedDistributedQuotaCounterBackend, QuotaCounterBackendError> {
        self.backend.distributed_store()
    }

    pub fn enforcement_backend(
        &self,
    ) -> (
        SharedDistributedQuotaCounterBackend,
        Option<QuotaCounterBackendError>,
    ) {
        let mut initialization_error = None;
        let primary = match self.distributed_store() {
            Ok(backend) => backend,
            Err(error) => {
                initialization_error = Some(error.clone());
                Arc::new(UnavailableDistributedQuotaCounterStore::new(error))
                    as SharedDistributedQuotaCounterBackend
            }
        };

        let backend = self
            .local_fallback
            .as_ref()
            .map(|fallback| {
                Arc::new(DegradedQuotaCounterBackend::new(
                    Arc::clone(&primary),
                    self.backend.backend_kind(),
                    fallback.build_store(),
                )) as SharedDistributedQuotaCounterBackend
            })
            .unwrap_or(primary);

        (backend, initialization_error)
    }
}
