#![allow(dead_code)]

use std::{
    collections::HashMap,
    convert::Infallible,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use bytes::Bytes;
use http::{StatusCode, Uri};
use http_body_util::Full;
use hyper::{Request, Response, body::Incoming};
use impulse_config::config::{Config, Upstream};
use impulse_edge::runtime::{
    backend::state::{BackendLifecycleInventorySnapshot, BackendLifecycleSnapshot},
    bundle::RuntimeBundleHandle,
};
use impulse_lb::{
    HealthTransition,
    health::HealthFailureReason,
    upstream_pool::{UpstreamBackendRuntimeState, UpstreamPoolMembershipSummary},
};

use super::{
    request_path::{H3RequestSpec, H3Response},
    runtime_swap::RuntimeSwapHarness,
};

#[derive(Clone)]
pub(crate) struct ToggleBackendFixture {
    failing: Arc<AtomicBool>,
}

impl ToggleBackendFixture {
    pub(crate) fn set_failing(&self, failing: bool) {
        self.failing.store(failing, Ordering::Relaxed);
    }

    pub(crate) fn is_failing(&self) -> bool {
        self.failing.load(Ordering::Relaxed)
    }
}

pub(crate) struct BackendLifecycleHarness {
    runtime: RuntimeSwapHarness,
}

impl BackendLifecycleHarness {
    pub(crate) fn new() -> Self {
        Self {
            runtime: RuntimeSwapHarness::new(),
        }
    }

    pub(crate) fn make_config(&self, upstreams: HashMap<String, Upstream>) -> Config {
        self.runtime.make_config(upstreams)
    }

    pub(crate) fn start_listener(&mut self, config: Config) -> Result<SocketAddr, String> {
        self.runtime.start_listener(config)
    }

    pub(crate) fn start_h1_static_backend(&mut self, body: &'static [u8]) -> SocketAddr {
        self.runtime.start_h1_static_backend(body)
    }

    pub(crate) fn start_h1_backend<F, Fut>(&mut self, handler: F) -> SocketAddr
    where
        F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send + 'static,
    {
        self.runtime.start_h1_backend(handler)
    }

    pub(crate) fn try_start_h1_backend_at<F, Fut>(
        &mut self,
        bind_addr: SocketAddr,
        handler: F,
    ) -> Result<SocketAddr, String>
    where
        F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send + 'static,
    {
        self.runtime.try_start_h1_backend_at(bind_addr, handler)
    }

    pub(crate) fn start_h1_fail_then_recover_backend(
        &mut self,
        success_body: &'static [u8],
        failure_status: StatusCode,
        failure_body: &'static [u8],
    ) -> (SocketAddr, ToggleBackendFixture) {
        let failing = Arc::new(AtomicBool::new(false));
        let failing_flag = Arc::clone(&failing);
        let addr = self.runtime.start_h1_backend(move |_req| {
            let failing_flag = Arc::clone(&failing_flag);
            async move {
                if failing_flag.load(Ordering::Relaxed) {
                    let response = Response::builder()
                        .status(failure_status)
                        .body(Full::new(Bytes::from_static(failure_body)))
                        .expect("failure response");
                    Ok::<_, Infallible>(response)
                } else {
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(success_body))))
                }
            }
        });
        (addr, ToggleBackendFixture { failing })
    }

    pub(crate) fn run_request(&self, request: H3RequestSpec<'_>) -> Result<H3Response, String> {
        self.runtime.run_request(request)
    }

    pub(crate) fn runtime_snapshot(&self) -> Result<serde_json::Value, String> {
        self.runtime.runtime_snapshot()
    }

    pub(crate) fn ready_snapshot_expect(
        &self,
        expected_status: StatusCode,
    ) -> Result<serde_json::Value, String> {
        self.runtime.ready_snapshot_expect(expected_status)
    }

    pub(crate) fn metrics_text(&self) -> Result<String, String> {
        self.runtime.metrics_text()
    }

    pub(crate) fn metrics_status_at(&self, path: &str) -> Result<StatusCode, String> {
        self.runtime.metrics_status_at(path)
    }

    pub(crate) fn runtime_bundle_handle(&self) -> Result<Arc<RuntimeBundleHandle>, String> {
        self.runtime.runtime_bundle_handle()
    }

    pub(crate) fn backend_inventory(&self) -> Result<BackendLifecycleInventorySnapshot, String> {
        let handle = self.runtime_bundle_handle()?;
        let current = handle.current_view();
        Ok(current
            .shared_services()
            .backend_lifecycle
            .snapshot_inventory(&current.state().upstream_pools))
    }

    pub(crate) fn backend_snapshot(
        &self,
        backend_addr: &str,
    ) -> Result<Option<BackendLifecycleSnapshot>, String> {
        let handle = self.runtime_bundle_handle()?;
        Ok(handle
            .current_view()
            .shared_services()
            .backend_lifecycle
            .snapshot_backend(backend_addr))
    }

    pub(crate) fn upstream_membership_summary(
        &self,
        upstream_name: &str,
    ) -> Result<UpstreamPoolMembershipSummary, String> {
        let handle = self.runtime_bundle_handle()?;
        let current = handle.current_view();
        let pool = current
            .state()
            .upstream_pools
            .get(upstream_name)
            .ok_or_else(|| format!("missing upstream pool '{upstream_name}'"))?;
        let guard = pool
            .read()
            .map_err(|_| format!("upstream pool '{upstream_name}' poisoned"))?;
        Ok(guard.membership_summary())
    }

    pub(crate) fn upstream_backend_runtime_state(
        &self,
        upstream_name: &str,
        backend_addr: &str,
    ) -> Result<Option<UpstreamBackendRuntimeState>, String> {
        let (pool, backend_index) = self.resolve_pool_backend_index(upstream_name, backend_addr)?;
        let guard = pool
            .read()
            .map_err(|_| format!("upstream pool '{upstream_name}' poisoned"))?;
        Ok(backend_index.and_then(|index| guard.backend_runtime_state(index)))
    }

    pub(crate) fn mark_backend_passive_failure(
        &self,
        upstream_name: &str,
        backend_addr: &str,
        reason: HealthFailureReason,
    ) -> Result<Option<HealthTransition>, String> {
        let (pool, backend_index) = self.resolve_pool_backend_index(upstream_name, backend_addr)?;
        let Some(index) = backend_index else {
            return Ok(None);
        };
        let mut guard = pool
            .write()
            .map_err(|_| format!("upstream pool '{upstream_name}' poisoned"))?;
        Ok(guard.mark_backend_request_failure(index, reason))
    }

    pub(crate) fn mark_backend_active_recovery(
        &self,
        upstream_name: &str,
        backend_addr: &str,
    ) -> Result<Option<HealthTransition>, String> {
        let (pool, backend_index) = self.resolve_pool_backend_index(upstream_name, backend_addr)?;
        let Some(index) = backend_index else {
            return Ok(None);
        };
        let mut guard = pool
            .write()
            .map_err(|_| format!("upstream pool '{upstream_name}' poisoned"))?;
        Ok(guard.mark_backend_healthy(index))
    }

    fn resolve_pool_backend_index(
        &self,
        upstream_name: &str,
        backend_addr: &str,
    ) -> Result<
        (
            Arc<std::sync::RwLock<impulse_lb::upstream_pool::UpstreamPool>>,
            Option<usize>,
        ),
        String,
    > {
        let handle = self.runtime_bundle_handle()?;
        let current = handle.current_view();
        let pool = current
            .state()
            .upstream_pools
            .get(upstream_name)
            .cloned()
            .ok_or_else(|| format!("missing upstream pool '{upstream_name}'"))?;
        let guard = pool
            .read()
            .map_err(|_| format!("upstream pool '{upstream_name}' poisoned"))?;
        let backend_index = guard
            .backend_indices()
            .into_iter()
            .find(|index| guard.backend_address(*index) == Some(backend_addr));
        drop(guard);
        Ok((pool, backend_index))
    }
}

impl Default for BackendLifecycleHarness {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn alternate_loopback_backend_addrs(port: u16) -> (SocketAddr, SocketAddr) {
    (
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), port),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), port),
    )
}

pub(crate) fn hostname_backend_uri(authority_host: &str, authority_port: u16) -> Uri {
    format!("http://{authority_host}:{authority_port}")
        .parse()
        .expect("hostname backend uri")
}
