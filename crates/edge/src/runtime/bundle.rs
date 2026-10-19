use std::{
    collections::VecDeque,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use impulse_config::runtime::{ListenerRuntimeConfig, RuntimeConfig};
use impulse_errors::ProxyError;
use log::{info, warn};

use crate::runtime::{
    activation::{GenerationChangeEvent, GenerationHistoryEntry},
    cache::BoundedPingoraMemoryCache,
    generation::{
        RuntimeGenerationState, RuntimeGenerationView, RuntimeSharedServices,
        StartupOwnedRuntimeState,
    },
    policy::RuntimeLifecycleState,
    shared_state::SharedRuntimeState,
};

/// The fully assembled runtime generation published to listener workers.
///
/// A bundle is the canonical boundary between configuration/build time and live
/// worker execution: startup-owned state, generation-owned state, and shared
/// services are packaged together and swapped as one unit.
#[derive(Clone)]
pub struct RuntimeBundle {
    pub generation: u64,
    pub startup: StartupOwnedRuntimeState,
    pub runtime_config: RuntimeConfig,
    pub shared_state: Arc<SharedRuntimeState>,
}

impl RuntimeBundle {
    pub fn startup(&self) -> &StartupOwnedRuntimeState {
        &self.startup
    }

    pub fn generation_view(&self) -> RuntimeGenerationView<'_> {
        RuntimeGenerationView {
            generation: self.generation,
            startup: &self.startup,
            runtime_config: &self.runtime_config,
            shared: self.shared_state.shared_services(),
            state: self.shared_state.generation_state(),
        }
    }

    pub fn listener_runtime_config(&self, label: &str) -> Option<ListenerRuntimeConfig> {
        self.generation_view().listener_runtime_config(label)
    }
}

fn bounded_response_cache(runtime: &RuntimeBundle) -> Option<&'static BoundedPingoraMemoryCache> {
    let state = runtime.shared_state.generation_state();
    let mut policies = state
        .upstream_policies
        .values()
        .map(|policy| policy.response_cache.clone());
    let mut storage_policy = policies.next()?;
    for policy in policies {
        storage_policy.max_bytes = storage_policy.max_bytes.max(policy.max_bytes);
        storage_policy.max_entries = storage_policy.max_entries.max(policy.max_entries);
        storage_policy.max_object_bytes =
            storage_policy.max_object_bytes.max(policy.max_object_bytes);
    }
    Some(Box::leak(Box::new(BoundedPingoraMemoryCache::new(
        &storage_policy,
        Arc::clone(&runtime.shared_state.shared_services().metrics),
    ))))
}

fn response_cache_namespaces_compatible(current: &RuntimeBundle, next: &RuntimeBundle) -> bool {
    let current = current
        .runtime_config
        .upstreams
        .iter()
        .filter(|(_, upstream)| upstream.policy.response_cache.enabled)
        .collect::<Vec<_>>();
    let next_count = next
        .runtime_config
        .upstreams
        .values()
        .filter(|upstream| upstream.policy.response_cache.enabled)
        .count();

    current.len() == next_count
        && current.into_iter().all(|(name, upstream)| {
            next.runtime_config
                .upstreams
                .get(name)
                .filter(|candidate| candidate.policy.response_cache.enabled)
                .is_some_and(|candidate| {
                    upstream.route == candidate.route && upstream.policy == candidate.policy
                })
        })
}

/// Read-only view of the generation currently installed in the process.
///
/// This wrapper gives callers stable access to the active bundle without
/// exposing the swap mechanism itself.
#[derive(Clone)]
pub struct ActiveRuntimeGeneration {
    bundle: Arc<RuntimeBundle>,
}

impl ActiveRuntimeGeneration {
    pub fn bundle(&self) -> &RuntimeBundle {
        self.bundle.as_ref()
    }

    pub fn generation(&self) -> u64 {
        self.bundle.generation
    }

    pub fn startup(&self) -> &StartupOwnedRuntimeState {
        &self.bundle.startup
    }

    pub fn runtime_config(&self) -> &RuntimeConfig {
        &self.bundle.runtime_config
    }

    pub fn shared_services(&self) -> &RuntimeSharedServices {
        self.bundle.shared_state.shared_services()
    }

    pub fn state(&self) -> &RuntimeGenerationState {
        self.bundle.shared_state.generation_state()
    }

    pub fn view(&self) -> RuntimeGenerationView<'_> {
        self.bundle.generation_view()
    }

    pub fn listener_runtime_config(&self, label: &str) -> Option<ListenerRuntimeConfig> {
        self.bundle.listener_runtime_config(label)
    }
}

const MAX_ARCHIVED_RUNTIME_GENERATIONS: usize = 8;
const MAX_GENERATION_HISTORY_ENTRIES: usize = 32;
const MAX_GENERATION_CHANGE_EVENTS: usize = 64;

/// Runtime-owned lifecycle status for retained generations.
///
/// This is intentionally narrower than the control-plane activation contract.
/// It answers one ownership question only: how the runtime handle currently
/// classifies a retained generation for rollback/history purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeGenerationRecordStatus {
    Active,
    Previous,
    FailedPrepare,
    RolledBack,
    Superseded,
}

impl RuntimeGenerationRecordStatus {
    #[must_use]
    pub fn is_rollback_candidate(self) -> bool {
        matches!(self, Self::Previous | Self::RolledBack | Self::Superseded)
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Previous => "previous",
            Self::FailedPrepare => "failed_prepare",
            Self::RolledBack => "rolled_back",
            Self::Superseded => "superseded",
        }
    }
}

/// Retained runtime generation metadata owned by [`RuntimeBundleHandle`].
#[derive(Clone)]
pub struct RuntimeGenerationRecord {
    generation: u64,
    status: RuntimeGenerationRecordStatus,
    bundle: Option<Arc<RuntimeBundle>>,
    note: Option<String>,
}

impl RuntimeGenerationRecord {
    fn active(bundle: Arc<RuntimeBundle>) -> Self {
        Self {
            generation: bundle.generation,
            status: RuntimeGenerationRecordStatus::Active,
            bundle: Some(bundle),
            note: None,
        }
    }

    fn archived(
        generation: u64,
        status: RuntimeGenerationRecordStatus,
        bundle: Option<Arc<RuntimeBundle>>,
        note: Option<String>,
    ) -> Self {
        Self {
            generation,
            status,
            bundle,
            note,
        }
    }

    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn status(&self) -> RuntimeGenerationRecordStatus {
        self.status
    }

    #[must_use]
    pub fn bundle(&self) -> Option<&Arc<RuntimeBundle>> {
        self.bundle.as_ref()
    }

    #[must_use]
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }

    #[must_use]
    pub fn has_bundle(&self) -> bool {
        self.bundle.is_some()
    }
}

/// Atomic handle for publishing and reading the active runtime generation.
///
/// Ownership of reload lifecycle transitions stays here. Callers that only need
/// runtime data should prefer [`Self::current_view`] or [`Self::with_current_view`].
#[derive(Clone)]
pub struct RuntimeBundleHandle {
    inner: Arc<RwLock<Arc<RuntimeBundle>>>,
    response_cache: Option<&'static BoundedPingoraMemoryCache>,
    response_cache_namespace: Arc<AtomicU64>,
    history: Arc<RwLock<VecDeque<RuntimeGenerationRecord>>>,
    generation_history: Arc<RwLock<VecDeque<GenerationHistoryEntry>>>,
    generation_events: Arc<RwLock<VecDeque<GenerationChangeEvent>>>,
    lifecycle: Arc<RuntimeLifecycleState>,
}

impl RuntimeBundleHandle {
    pub fn new(bundle: RuntimeBundle) -> Self {
        // The handle is constructed only once the first generation has been built
        // and is about to be published, so the process is `Running` from the
        // handle's perspective. Drain/shutdown transitions move it forward from
        // here (see `begin_drain`/`begin_shutdown`).
        let lifecycle = RuntimeLifecycleState::new();
        let _ = lifecycle.mark_running();
        let response_cache = bounded_response_cache(&bundle);
        let response_cache_namespace = bundle.generation;
        let handle = Self {
            inner: Arc::new(RwLock::new(Arc::new(bundle))),
            response_cache,
            response_cache_namespace: Arc::new(AtomicU64::new(response_cache_namespace)),
            history: Arc::new(RwLock::new(VecDeque::new())),
            generation_history: Arc::new(RwLock::new(VecDeque::new())),
            generation_events: Arc::new(RwLock::new(VecDeque::new())),
            lifecycle: Arc::new(lifecycle),
        };
        handle.sync_runtime_observability_metrics();
        info!(
            "runtime generation initialized: generation={} upstream_lb_policies={}",
            handle.current_generation(),
            summarize_upstream_lb_policies(handle.current().as_ref())
        );
        handle
    }

    pub(crate) fn response_cache(&self) -> Option<&'static BoundedPingoraMemoryCache> {
        self.response_cache
    }

    pub(crate) fn current_with_response_cache_namespace(&self) -> (Arc<RuntimeBundle>, u64) {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (
            Arc::clone(&guard),
            self.response_cache_namespace.load(Ordering::Acquire),
        )
    }

    pub(crate) fn current_view_with_response_cache_namespace(
        &self,
    ) -> (ActiveRuntimeGeneration, u64) {
        let (bundle, namespace) = self.current_with_response_cache_namespace();
        (ActiveRuntimeGeneration { bundle }, namespace)
    }

    /// The shared process lifecycle state machine (Phase 6). All clones of this
    /// handle observe the same phase.
    pub fn lifecycle(&self) -> &RuntimeLifecycleState {
        &self.lifecycle
    }

    /// Return the active generation's bundle.
    ///
    /// # Poisoning policy (Phase 5)
    ///
    /// This is on the hot poll path and cannot return an error to its callers, so
    /// it must not panic on a poisoned lock. Read-lock poisoning is recovered from
    /// rather than propagated, which is safe here by construction:
    ///
    /// - The only writer is [`Self::replace`], whose critical section is a single
    ///   `mem::replace` of an `Arc<RuntimeBundle>` — it runs no fallible or
    ///   panic-prone code while holding the write guard, so a panic *inside* the
    ///   critical section cannot occur.
    /// - A poisoned guard still references a fully-constructed, immutable
    ///   `Arc<RuntimeBundle>`; recovering it yields the last consistently-published
    ///   generation. There is no torn or partially-written state to observe.
    ///
    /// Recovering therefore preserves liveness (the data plane keeps serving the
    /// active generation) without masking a real corruption risk.
    pub fn current(&self) -> Arc<RuntimeBundle> {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(&guard)
    }

    /// Test-only: deliberately poison the internal lock so poison-recovery paths
    /// can be exercised. Poisoning leaves the stored `Arc<RuntimeBundle>` intact.
    #[cfg(test)]
    pub fn poison_for_test(&self) {
        let inner = Arc::clone(&self.inner);
        // Panic while holding the write guard, in a thread whose unwind we catch,
        // so the process survives but the lock is marked poisoned.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = inner.write().expect("lock not yet poisoned");
            panic!("intentional poison for test");
        }));
    }

    pub fn current_view(&self) -> ActiveRuntimeGeneration {
        ActiveRuntimeGeneration {
            bundle: self.current(),
        }
    }

    pub fn current_generation(&self) -> u64 {
        self.current_view().generation()
    }

    pub fn with_current_generation<R>(&self, f: impl FnOnce(ActiveRuntimeGeneration) -> R) -> R {
        f(self.current_view())
    }

    pub fn with_current_view<R>(&self, f: impl FnOnce(RuntimeGenerationView<'_>) -> R) -> R {
        self.with_current_generation(|current| f(current.view()))
    }

    /// Snapshot the active and retained generations known to the runtime.
    ///
    /// The first entry is always the live active generation. Archived entries are
    /// ordered newest-first behind it and capped in memory.
    pub fn generation_history(&self) -> Vec<RuntimeGenerationRecord> {
        let active = RuntimeGenerationRecord::active(self.current());
        let archived = self
            .history
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let mut history = Vec::with_capacity(archived.len() + 1);
        history.push(active);
        history.extend(archived);
        history
    }

    /// Return a retained rollback candidate by generation, if still available.
    pub fn rollback_candidate(&self, generation: u64) -> Option<Arc<RuntimeBundle>> {
        let current = self.current();
        if current.generation == generation {
            return Some(current);
        }

        self.history
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find(|entry| entry.generation == generation && entry.status.is_rollback_candidate())
            .and_then(|entry| entry.bundle.clone())
    }

    pub fn generation_record(&self, generation: u64) -> Option<RuntimeGenerationRecord> {
        let current = self.current();
        if current.generation == generation {
            return Some(RuntimeGenerationRecord::active(current));
        }

        self.history
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find(|entry| entry.generation == generation)
            .cloned()
    }

    pub fn generation_change_history(&self) -> Vec<GenerationHistoryEntry> {
        self.generation_history
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    pub fn generation_change_events(&self) -> Vec<GenerationChangeEvent> {
        self.generation_events
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    pub(crate) fn record_generation_history_entry(&self, entry: GenerationHistoryEntry) {
        {
            let mut history = self
                .generation_history
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            history.push_front(entry);
            trim_bounded_history(&mut history, MAX_GENERATION_HISTORY_ENTRIES);
        }
        self.sync_runtime_observability_metrics();
    }

    pub(crate) fn record_generation_change_event(&self, event: GenerationChangeEvent) {
        let mut events = self
            .generation_events
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        events.push_front(event);
        trim_bounded_history(&mut events, MAX_GENERATION_CHANGE_EVENTS);
    }

    pub(crate) fn record_failed_prepare(&self, generation: u64, note: impl Into<String>) {
        let mut history = self
            .history
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        history.retain(|entry| entry.generation != generation);
        history.push_front(RuntimeGenerationRecord::archived(
            generation,
            RuntimeGenerationRecordStatus::FailedPrepare,
            None,
            Some(note.into()),
        ));
        trim_runtime_generation_history(&mut history);
    }

    /// Atomically install `bundle` as the active generation, returning its
    /// generation number.
    ///
    /// # Ownership boundary (Phase 3)
    ///
    /// The swap replaces the whole [`RuntimeBundle`] pointer. By ownership class
    /// (see [`crate::runtime::policy::OwnedRuntimeState`]):
    ///
    /// - **Generation-owned** ([`RuntimeGenerationState`]): fully replaced. The
    ///   old generation's state is retired below.
    /// - **Startup-owned** ([`StartupOwnedRuntimeState`]): the caller
    ///   (`build_runtime_reload_plan`) carries the current values forward, and the
    ///   reload validator has already rejected any startup-owned change as
    ///   restart-required, so the swap must not observe a change here.
    /// - **Process-shared** ([`RuntimeSharedServices`]): logically one instance
    ///   per process; in the current implementation the reload rebuilds it (see
    ///   the note on `RuntimeSharedServices`).
    ///
    /// The active generation is only mutated at the single `mem::replace`; every
    /// failure path before it leaves the running generation intact.
    ///
    /// # Lifecycle gate (Phase 6)
    ///
    /// A reload commit is only legal while the process is `Running`. If a drain or
    /// shutdown has begun, the swap is rejected before touching the active
    /// generation, so a reload cannot race a shutdown into ambiguous state.
    #[cfg(test)]
    pub(crate) fn replace(&self, bundle: RuntimeBundle) -> Result<u64, ProxyError> {
        self.replace_with_archive_status(bundle, RuntimeGenerationRecordStatus::Previous, None)
    }

    pub(crate) fn replace_with_archive_status(
        &self,
        bundle: RuntimeBundle,
        previous_status: RuntimeGenerationRecordStatus,
        expected_generation: Option<u64>,
    ) -> Result<u64, ProxyError> {
        let generation = bundle.generation;
        let next_tasks = Arc::clone(&bundle.shared_state.generation_state().generation_tasks);

        if let Some(rejection) = self.lifecycle.check_reload_allowed().rejection() {
            next_tasks.abort_generation();
            warn!(
                "runtime reload commit rejected in lifecycle phase {:?}: refusing to install generation {}",
                self.lifecycle.phase(),
                generation
            );
            return Err(ProxyError::Transport(rejection.to_string()));
        }

        let previous = {
            // Poisoning cannot actually occur (the critical section runs no
            // panic-prone code — see `current()`), but the reload path can safely
            // return an error, so fail closed here rather than recover: abort the
            // staged generation's tasks and leave the active generation intact.
            let mut guard = match self.inner.write() {
                Ok(guard) => guard,
                Err(_) => {
                    next_tasks.abort_generation();
                    return Err(ProxyError::Transport(
                        "runtime bundle lock poisoned".to_string(),
                    ));
                }
            };
            let previous_generation = guard.generation;
            if let Some(expected_generation) = expected_generation
                && previous_generation != expected_generation
            {
                next_tasks.abort_generation();
                return Err(ProxyError::Transport(format!(
                    "runtime generation conflict: expected active generation {}, found {}",
                    expected_generation, previous_generation
                )));
            }
            let rotate_response_cache_namespace =
                !response_cache_namespaces_compatible(guard.as_ref(), &bundle);
            bundle
                .shared_state
                .shared_services()
                .transport_pool
                .rotate_pingora_pool(generation);
            // --- old-generation teardown boundary: BEGIN ---
            // The previous bundle's generation-owned state is now unreachable to
            // new readers; existing readers keep their clone until it drains.
            let previous = std::mem::replace(&mut *guard, Arc::new(bundle));
            if rotate_response_cache_namespace {
                self.response_cache_namespace
                    .store(generation, Ordering::Release);
            }
            previous
        };
        // Retire only the previous generation's generation-owned background tasks.
        // Startup-owned and process-shared resources are not torn down here.
        self.archive_previous_generation(previous.clone(), previous_status);
        previous
            .shared_state
            .generation_state()
            .generation_tasks
            .retire_generation(Duration::from_secs(5));
        previous
            .shared_state
            .shared_services()
            .transport_pool
            .drain_pingora_pool();
        // --- old-generation teardown boundary: END ---
        info!(
            "runtime generation swap committed: {} -> {} (lifecycle phase {:?})",
            previous.generation,
            generation,
            self.lifecycle.phase()
        );
        info!(
            "runtime generation {} upstream_lb_policies={}",
            generation,
            summarize_upstream_lb_policies(self.current().as_ref())
        );
        self.sync_runtime_observability_metrics();
        Ok(generation)
    }

    fn sync_runtime_observability_metrics(&self) {
        let current = self.current();
        let history_depth = self
            .generation_history
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        let metrics = &current.shared_state.shared_services().metrics;
        let generation_state = current.shared_state.generation_state();
        metrics.reconcile_runtime_metric_labels(
            generation_state
                .upstream_policies
                .keys()
                .map(String::as_str),
            generation_state
                .backend_endpoints
                .keys()
                .map(String::as_str),
            generation_state
                .listener_runtime_configs
                .keys()
                .map(String::as_str),
            generation_state
                .resilience
                .quota
                .policies
                .iter()
                .map(|policy| policy.name.as_str()),
        );
        metrics.set_runtime_active_generation(current.generation);
        metrics.set_runtime_history_depth(history_depth);
    }

    fn archive_previous_generation(
        &self,
        previous: Arc<RuntimeBundle>,
        status: RuntimeGenerationRecordStatus,
    ) {
        let mut history = self
            .history
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for entry in history.iter_mut() {
            if entry.status == RuntimeGenerationRecordStatus::Previous {
                entry.status = RuntimeGenerationRecordStatus::Superseded;
            }
        }
        history.retain(|entry| entry.generation != previous.generation);
        history.push_front(RuntimeGenerationRecord::archived(
            previous.generation,
            status,
            Some(previous),
            None,
        ));
        trim_runtime_generation_history(&mut history);
    }
}

fn summarize_upstream_lb_policies(bundle: &RuntimeBundle) -> String {
    let mut upstreams = bundle
        .runtime_config
        .upstreams
        .iter()
        .map(|(name, upstream)| {
            let weight_policy = upstream.load_balancing.strategy.backend_weight_policy();
            format!(
                "{}:{}:{}:{}",
                name,
                upstream.load_balancing.strategy.canonical_name(),
                weight_policy.weighting_label(),
                weight_policy.canonical_label()
            )
        })
        .collect::<Vec<_>>();
    upstreams.sort_unstable();
    upstreams.join(" | ")
}

fn trim_runtime_generation_history(history: &mut VecDeque<RuntimeGenerationRecord>) {
    while history.len() > MAX_ARCHIVED_RUNTIME_GENERATIONS {
        history.pop_back();
    }
}

fn trim_bounded_history<T>(history: &mut VecDeque<T>, max_len: usize) {
    while history.len() > max_len {
        history.pop_back();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        future,
        path::Path,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use impulse_config::{
        config::{
            Backend, ClientAuth, Config as ImpulseConfigConfig, Listen, LoadBalancing, Log,
            LogFile, LogFormat, Observability, Performance, Resilience, RouteMatch, Security, Tls,
            Upstream, UpstreamTls,
        },
        runtime::RuntimeConfig,
    };
    use rcgen::{Certificate, CertificateParams, SanType};
    use tempfile::tempdir;
    use tokio::sync::oneshot;

    use super::*;
    use crate::runtime::{listener::QUICListener, tasks::RuntimeTaskRegistration};

    fn write_test_cert_for_name(dir: &Path, cert_name: &str, dns_name: &str) -> (String, String) {
        let mut params = CertificateParams::new(vec![dns_name.to_string()]);
        params
            .subject_alt_names
            .push(SanType::DnsName(dns_name.to_string()));
        let cert = Certificate::from_params(params).expect("failed to build cert");

        let cert_path = dir.join(format!("{cert_name}.pem"));
        let key_path = dir.join(format!("{cert_name}.key.pem"));
        std::fs::write(&cert_path, cert.serialize_pem().expect("serialize cert"))
            .expect("write cert");
        std::fs::write(&key_path, cert.serialize_private_key_pem()).expect("write key");
        (
            cert_path.to_string_lossy().to_string(),
            key_path.to_string_lossy().to_string(),
        )
    }

    fn test_config(cert: String, key: String, backend_addr: &str) -> ImpulseConfigConfig {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "api".to_string(),
            Upstream {
                load_balancing: LoadBalancing {
                    lb_type: "round-robin".to_string(),
                    key: None,
                },
                auth: Default::default(),
                host_policy: Default::default(),
                forwarded_headers: Default::default(),
                compression: Default::default(),
                cache: Default::default(),
                tls: None,
                route: RouteMatch {
                    path_prefix: Some("/".to_string()),
                    ..Default::default()
                },
                backends: vec![Backend {
                    id: "b1".to_string(),
                    address: backend_addr.to_string(),
                    weight: 1,
                    health_check: None,
                }],
            },
        );

        ImpulseConfigConfig {
            version: 1,
            listen: Listen {
                protocol: "http3".to_string(),
                port: 9889,
                address: "127.0.0.1".to_string(),
                tls: Tls {
                    cert,
                    key,
                    certificates: vec![],
                    client_auth: ClientAuth::default(),
                },
            },
            listeners: vec![],
            upstream: upstreams,
            load_balancing: Some(LoadBalancing {
                lb_type: "round-robin".to_string(),
                key: None,
            }),
            upstream_tls: UpstreamTls::default(),
            secrets: Default::default(),
            log: Log {
                level: "info".to_string(),
                file: LogFile {
                    enabled: false,
                    path: String::new(),
                },
                format: LogFormat::Plain,
            },
            performance: Performance::default(),
            observability: Observability::default(),
            resilience: Resilience::default(),
            security: Security::default(),
        }
    }

    fn runtime_bundle_from_config(
        generation: u64,
        config_path: &str,
        config: &ImpulseConfigConfig,
    ) -> RuntimeBundle {
        let runtime_config = RuntimeConfig::from_config(config).expect("runtime config");
        let mut bundle = QUICListener::build_runtime_bundle(
            config_path.to_string(),
            config.log.clone(),
            &runtime_config,
        )
        .expect("runtime bundle");
        bundle.generation = generation;
        bundle
    }

    fn runtime_bundle_pair(
        dir: &Path,
        startup_path: &str,
        startup_backend_addr: &str,
        next_generation: u64,
        next_path: &str,
        next_backend_addr: &str,
    ) -> (RuntimeBundle, RuntimeBundle) {
        let (cert, key) = write_test_cert_for_name(dir, "server", "api.example.com");
        let startup = test_config(cert.clone(), key.clone(), startup_backend_addr);
        let reloaded = test_config(cert, key, next_backend_addr);
        (
            runtime_bundle_from_config(1, startup_path, &startup),
            runtime_bundle_from_config(next_generation, next_path, &reloaded),
        )
    }

    #[test]
    fn upstream_lb_policy_summary_exposes_canonical_weighting_contract() {
        let dir = tempdir().expect("tempdir");
        let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");

        let mut weighted = test_config(cert.clone(), key.clone(), "127.0.0.1:7001");
        weighted
            .upstream
            .get_mut("api")
            .expect("api upstream")
            .load_balancing
            .lb_type = "random".to_string();
        let weighted_bundle = runtime_bundle_from_config(1, "weighted.yaml", &weighted);
        assert_eq!(
            summarize_upstream_lb_policies(&weighted_bundle),
            "api:random:weighted:honored"
        );

        let mut adaptive = test_config(cert, key, "127.0.0.1:7002");
        adaptive
            .upstream
            .get_mut("api")
            .expect("api upstream")
            .load_balancing
            .lb_type = "least-connections".to_string();
        let adaptive_bundle = runtime_bundle_from_config(2, "adaptive.yaml", &adaptive);
        assert_eq!(
            summarize_upstream_lb_policies(&adaptive_bundle),
            "api:least-connections:unweighted:rejected-as-invalid"
        );
    }

    #[test]
    fn stale_generation_swap_is_rejected_under_the_write_lock() {
        let dir = tempdir().expect("tempdir");
        let (current_bundle, next_bundle) = runtime_bundle_pair(
            dir.path(),
            "startup.yaml",
            "http://127.0.0.1:7001",
            2,
            "reloaded.yaml",
            "http://127.0.0.1:7002",
        );
        let handle = RuntimeBundleHandle::new(current_bundle);

        let error = handle
            .replace_with_archive_status(
                next_bundle,
                RuntimeGenerationRecordStatus::Previous,
                Some(99),
            )
            .expect_err("a stale expected generation must reject the swap");

        assert!(error.to_string().contains("runtime generation conflict"));
        assert_eq!(handle.current_generation(), 1);
    }

    struct CompletionSignal(Option<oneshot::Sender<()>>);

    impl Drop for CompletionSignal {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    fn spawn_generation_task(
        bundle: &RuntimeBundle,
        completed: Arc<AtomicBool>,
    ) -> tokio::task::AbortHandle {
        let (completion_tx, completion_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _completion = CompletionSignal(Some(completion_tx));
            future::pending::<()>().await;
        });
        let abort = task.abort_handle();
        let join = task;
        tokio::spawn(async move {
            let _ = join.await;
            completed.store(true, Ordering::Release);
        });
        bundle
            .shared_state
            .generation_state()
            .generation_tasks
            .register(RuntimeTaskRegistration::new(abort.clone(), completion_rx));
        abort
    }

    mod runtime_generation_view_ownership {
        use super::*;

        #[test]
        fn current_generation_helpers_share_one_canonical_active_view() {
            let dir = tempdir().expect("tempdir");
            let (startup_bundle, _) = runtime_bundle_pair(
                dir.path(),
                "runtime.yaml",
                "http://127.0.0.1:7001",
                8,
                "unused.yaml",
                "http://127.0.0.1:7002",
            );
            let mut bundle = startup_bundle;
            bundle.generation = 7;
            let handle = RuntimeBundleHandle::new(bundle);

            let current = handle.current_view();
            let via_generation = handle.with_current_generation(|active| {
                (
                    active.generation(),
                    active.startup().config_path.clone(),
                    active
                        .runtime_config()
                        .upstreams
                        .get("api")
                        .expect("upstream")
                        .backends[0]
                        .backend
                        .address
                        .clone(),
                )
            });
            let via_view = handle.with_current_view(|view| {
                (
                    view.generation,
                    view.startup.config_path.clone(),
                    view.runtime_config
                        .upstreams
                        .get("api")
                        .expect("upstream")
                        .backends[0]
                        .backend
                        .address
                        .clone(),
                )
            });

            assert_eq!(handle.current_generation(), 7);
            assert_eq!(current.generation(), 7);
            assert_eq!(
                via_generation,
                (
                    7,
                    "runtime.yaml".to_string(),
                    "http://127.0.0.1:7001".to_string()
                )
            );
            assert_eq!(via_generation, via_view);
        }

        #[test]
        fn startup_owned_state_stays_stable_while_generation_owned_runtime_changes() {
            let dir = tempdir().expect("tempdir");
            let (current_bundle, next_bundle) = runtime_bundle_pair(
                dir.path(),
                "impulse.yaml",
                "http://127.0.0.1:7001",
                2,
                "impulse.yaml",
                "http://127.0.0.1:7002",
            );
            let handle = RuntimeBundleHandle::new(current_bundle);

            handle.replace(next_bundle).expect("replace");

            let active = handle.current_view();
            assert_eq!(active.generation(), 2);
            assert_eq!(active.startup().config_path, "impulse.yaml");
            assert_eq!(
                active
                    .runtime_config()
                    .upstreams
                    .get("api")
                    .expect("active upstream")
                    .backends[0]
                    .backend
                    .address,
                "http://127.0.0.1:7002"
            );
        }

        #[test]
        fn current_view_helpers_follow_the_live_generation_after_replacement() {
            let dir = tempdir().expect("tempdir");
            let (current_bundle, next_bundle) = runtime_bundle_pair(
                dir.path(),
                "startup.yaml",
                "http://127.0.0.1:7001",
                2,
                "reloaded.yaml",
                "http://127.0.0.1:7002",
            );
            let handle = RuntimeBundleHandle::new(current_bundle);

            handle.replace(next_bundle).expect("replace");

            let via_generation = handle.with_current_generation(|active| {
                (
                    active.generation(),
                    active.startup().config_path.clone(),
                    active
                        .runtime_config()
                        .upstreams
                        .get("api")
                        .expect("active upstream")
                        .backends[0]
                        .backend
                        .address
                        .clone(),
                )
            });
            let via_view = handle.with_current_view(|view| {
                (
                    view.generation,
                    view.startup.config_path.clone(),
                    view.runtime_config
                        .upstreams
                        .get("api")
                        .expect("active upstream")
                        .backends[0]
                        .backend
                        .address
                        .clone(),
                )
            });

            assert_eq!(handle.current_generation(), 2);
            assert_eq!(
                via_generation,
                (
                    2,
                    "reloaded.yaml".to_string(),
                    "http://127.0.0.1:7002".to_string()
                )
            );
            assert_eq!(via_generation, via_view);
        }

        #[test]
        fn stale_generation_views_keep_the_original_runtime_snapshot_after_replacement() {
            let dir = tempdir().expect("tempdir");
            let (current_bundle, next_bundle) = runtime_bundle_pair(
                dir.path(),
                "startup.yaml",
                "http://127.0.0.1:7001",
                2,
                "reloaded.yaml",
                "http://127.0.0.1:7002",
            );
            let handle = RuntimeBundleHandle::new(current_bundle.clone());

            let stale = handle.current_view();
            let installed = handle.replace(next_bundle).expect("replace");

            assert_eq!(installed, 2);
            assert_eq!(handle.current_generation(), 2);
            assert_eq!(stale.generation(), 1);
            assert_eq!(stale.startup().config_path, "startup.yaml");
            assert_eq!(
                stale
                    .runtime_config()
                    .upstreams
                    .get("api")
                    .expect("stale upstream")
                    .backends[0]
                    .backend
                    .address,
                "http://127.0.0.1:7001"
            );
            assert_eq!(
                handle
                    .current()
                    .runtime_config
                    .upstreams
                    .get("api")
                    .expect("current upstream")
                    .backends[0]
                    .backend
                    .address,
                "http://127.0.0.1:7002"
            );
        }

        #[tokio::test]
        async fn bundle_replacement_retires_only_previous_generation_tasks() {
            let dir = tempdir().expect("tempdir");
            let (current_bundle, next_bundle) = runtime_bundle_pair(
                dir.path(),
                "impulse.yaml",
                "http://127.0.0.1:7001",
                2,
                "impulse.yaml",
                "http://127.0.0.1:7002",
            );

            let retired_completed = Arc::new(AtomicBool::new(false));
            let active_completed = Arc::new(AtomicBool::new(false));
            let _retired_task =
                spawn_generation_task(&current_bundle, Arc::clone(&retired_completed));
            let active_task = spawn_generation_task(&next_bundle, Arc::clone(&active_completed));

            let handle = RuntimeBundleHandle::new(current_bundle);
            handle.replace(next_bundle).expect("replace");
            tokio::time::sleep(Duration::from_millis(20)).await;

            assert!(
                retired_completed.load(Ordering::Acquire),
                "previous generation tasks should retire when the bundle is replaced"
            );
            assert!(
                !active_completed.load(Ordering::Acquire),
                "new generation tasks should remain active after replacement"
            );

            active_task.abort();
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert!(active_completed.load(Ordering::Acquire));
        }
    }

    mod runtime_generation_history {
        use super::*;

        #[test]
        fn replacement_retains_previous_generation_as_rollback_candidate() {
            let dir = tempdir().expect("tempdir");
            let (current_bundle, next_bundle) = runtime_bundle_pair(
                dir.path(),
                "startup.yaml",
                "http://127.0.0.1:7001",
                2,
                "reloaded.yaml",
                "http://127.0.0.1:7002",
            );
            let previous_generation = current_bundle.generation;
            let handle = RuntimeBundleHandle::new(current_bundle);

            handle.replace(next_bundle).expect("replace");

            let history = handle.generation_history();
            assert_eq!(history[0].generation(), 2);
            assert_eq!(history[0].status(), RuntimeGenerationRecordStatus::Active);
            assert_eq!(history[1].generation(), previous_generation);
            assert_eq!(history[1].status(), RuntimeGenerationRecordStatus::Previous);
            let rollback = handle
                .rollback_candidate(previous_generation)
                .expect("previous generation should be retained");
            assert_eq!(rollback.generation, previous_generation);
        }

        #[test]
        fn replacement_marks_older_retained_generations_as_superseded() {
            let dir = tempdir().expect("tempdir");
            let (bundle_one, bundle_two) = runtime_bundle_pair(
                dir.path(),
                "one.yaml",
                "http://127.0.0.1:7001",
                2,
                "two.yaml",
                "http://127.0.0.1:7002",
            );
            let (_, mut bundle_three) = runtime_bundle_pair(
                dir.path(),
                "unused.yaml",
                "http://127.0.0.1:7003",
                3,
                "three.yaml",
                "http://127.0.0.1:7004",
            );
            bundle_three.generation = 3;
            let handle = RuntimeBundleHandle::new(bundle_one);

            handle.replace(bundle_two).expect("first replace");
            handle.replace(bundle_three).expect("second replace");

            let history = handle.generation_history();
            assert_eq!(history[0].generation(), 3);
            assert_eq!(history[0].status(), RuntimeGenerationRecordStatus::Active);
            assert_eq!(history[1].generation(), 2);
            assert_eq!(history[1].status(), RuntimeGenerationRecordStatus::Previous);
            assert_eq!(history[2].generation(), 1);
            assert_eq!(
                history[2].status(),
                RuntimeGenerationRecordStatus::Superseded
            );
            assert!(
                handle.rollback_candidate(1).is_some(),
                "superseded known-good generations should remain rollback candidates"
            );
        }

        #[test]
        fn failed_prepare_history_is_retained_without_mutating_active_generation() {
            let dir = tempdir().expect("tempdir");
            let (current_bundle, _) = runtime_bundle_pair(
                dir.path(),
                "runtime.yaml",
                "http://127.0.0.1:7001",
                2,
                "unused.yaml",
                "http://127.0.0.1:7002",
            );
            let handle = RuntimeBundleHandle::new(current_bundle);

            handle.record_failed_prepare(2, "could not prepare runtime generation");

            let history = handle.generation_history();
            assert_eq!(history[0].generation(), 1);
            assert_eq!(history[0].status(), RuntimeGenerationRecordStatus::Active);
            assert_eq!(history[1].generation(), 2);
            assert_eq!(
                history[1].status(),
                RuntimeGenerationRecordStatus::FailedPrepare
            );
            assert_eq!(
                history[1].note(),
                Some("could not prepare runtime generation")
            );
            assert!(history[1].bundle().is_none());
            assert_eq!(handle.current_generation(), 1);
            assert!(handle.rollback_candidate(2).is_none());
        }

        #[test]
        fn rollback_candidate_selection_prefers_active_and_excludes_failed_prepare_entries() {
            let dir = tempdir().expect("tempdir");
            let (current_bundle, next_bundle) = runtime_bundle_pair(
                dir.path(),
                "startup.yaml",
                "http://127.0.0.1:7001",
                2,
                "reloaded.yaml",
                "http://127.0.0.1:7002",
            );
            let handle = RuntimeBundleHandle::new(current_bundle);

            let active = handle
                .rollback_candidate(1)
                .expect("active generation should be addressable as a rollback target");
            assert_eq!(active.generation, 1);

            handle.record_failed_prepare(9, "candidate not fully prepared");
            assert!(
                handle.rollback_candidate(9).is_none(),
                "failed-prepare entries must not be exposed as rollback candidates"
            );

            handle.replace(next_bundle).expect("replace");
            let previous = handle
                .rollback_candidate(1)
                .expect("previous known-good generation should stay rollbackable");
            assert_eq!(previous.generation, 1);
        }

        #[test]
        fn runtime_observability_metrics_follow_active_generation_and_history_depth() {
            let dir = tempdir().expect("tempdir");
            let (current_bundle, next_bundle) = runtime_bundle_pair(
                dir.path(),
                "startup.yaml",
                "http://127.0.0.1:7001",
                2,
                "reloaded.yaml",
                "http://127.0.0.1:7002",
            );
            let handle = RuntimeBundleHandle::new(current_bundle);

            let initial_metrics = Arc::clone(&handle.current_view().shared_services().metrics);
            assert_eq!(
                initial_metrics
                    .runtime_active_generation
                    .load(Ordering::Relaxed),
                1
            );
            assert_eq!(
                initial_metrics
                    .runtime_history_depth
                    .load(Ordering::Relaxed),
                0
            );

            handle.record_generation_history_entry(GenerationHistoryEntry {
                generation: 2,
                operation: crate::runtime::activation::GenerationOperation::Validate,
                status: crate::runtime::activation::GenerationStatus::Staged,
                config_source: "startup.yaml".to_string(),
                config_version: Some(1),
                requested_by: Some("test".to_string()),
                trigger_source: Some("test".to_string()),
                requested_at_ms: 1,
                completed_at_ms: Some(2),
                summary: "validated".to_string(),
                diff: crate::runtime::activation::ReloadDiff::default(),
                rejected_changes: Vec::new(),
            });

            assert_eq!(
                initial_metrics
                    .runtime_history_depth
                    .load(Ordering::Relaxed),
                1
            );

            handle.replace(next_bundle).expect("replace");

            let next_metrics = Arc::clone(&handle.current_view().shared_services().metrics);
            assert_eq!(
                next_metrics
                    .runtime_active_generation
                    .load(Ordering::Relaxed),
                2
            );
            assert_eq!(
                next_metrics.runtime_history_depth.load(Ordering::Relaxed),
                1
            );
        }
    }
}
