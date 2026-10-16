use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, RwLock},
    time::Duration,
};

use http_body_util::{BodyExt, combinators::BoxBody};
use hyper::{
    Request,
    body::{Bytes, Incoming},
};
use impulse_errors::{PoolError, ProxyError};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::{
    client_rotation::BackendClientRotation,
    h2_client::{ConnectObserver, H2Client, SharedDnsResolver, TlsClientConfig},
};

struct BackendClientState {
    client: Arc<H2Client>,
    generation: u64,
    tls: TlsClientConfig,
}

struct BackendHandle {
    state: RwLock<BackendClientState>,
    inflight: Arc<Semaphore>,
}

// Connection pools are keyed by configured backend identity, not by resolved IP.
// When DNS refresh updates a hostname's address set, new connects pick up the
// refreshed resolver results, while already-pooled H2 connections may continue
// using older addresses until Hyper retires them via the normal idle timeout.
pub(crate) struct H2Pool {
    backends: HashMap<String, BackendHandle>,
    max_idle_per_backend: usize,
    pool_idle_timeout: Duration,
    connect_timeout: Duration,
    dns_resolver: SharedDnsResolver,
    connect_observer: Option<ConnectObserver>,
}

impl H2Pool {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_observer<I>(
        backends: I,
        backend_tls: HashMap<String, TlsClientConfig>,
        max_inflight: usize,
        max_idle_per_backend: usize,
        pool_idle_timeout: Duration,
        connect_timeout: Duration,
        dns_resolver: SharedDnsResolver,
        connect_observer: Option<ConnectObserver>,
    ) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let inflight = max_inflight.max(1);
        let max_idle_per_backend = max_idle_per_backend.max(1);
        let mut map = HashMap::new();
        for backend in backends {
            let tls = backend_tls.get(&backend).cloned().unwrap_or_default();
            let client = Arc::new(H2Client::new_with_observer(
                max_idle_per_backend,
                pool_idle_timeout,
                connect_timeout,
                tls.clone(),
                dns_resolver.clone(),
                connect_observer.clone(),
            )?);
            map.insert(
                backend,
                BackendHandle {
                    state: RwLock::new(BackendClientState {
                        client,
                        generation: 0,
                        tls,
                    }),
                    inflight: Arc::new(Semaphore::new(inflight)),
                },
            );
        }
        Ok(Self {
            backends: map,
            max_idle_per_backend,
            pool_idle_timeout,
            connect_timeout,
            dns_resolver,
            connect_observer,
        })
    }

    pub(crate) fn rotate_backend_client(
        &self,
        backend: &str,
    ) -> Result<BackendClientRotation, String> {
        let Some(handle) = self.backends.get(backend) else {
            return Ok(BackendClientRotation::missing_backend());
        };

        let tls = handle
            .state
            .read()
            .map(|state| state.tls.clone())
            .map_err(|_| format!("backend client state poisoned for '{backend}'"))?;

        let client = Arc::new(H2Client::new_with_observer(
            self.max_idle_per_backend,
            self.pool_idle_timeout,
            self.connect_timeout,
            tls,
            self.dns_resolver.clone(),
            self.connect_observer.clone(),
        )?);

        let mut state = handle
            .state
            .write()
            .map_err(|_| format!("backend client state poisoned for '{backend}'"))?;
        let previous_generation = state.generation;
        state.client = client;
        state.generation = state.generation.saturating_add(1);
        Ok(BackendClientRotation::rotated(
            previous_generation,
            state.generation,
        ))
    }

    pub(crate) fn rotate_backend_client_with_tls(
        &self,
        backend: &str,
        tls: TlsClientConfig,
    ) -> Result<BackendClientRotation, String> {
        let Some(handle) = self.backends.get(backend) else {
            return Ok(BackendClientRotation::missing_backend());
        };

        {
            let state = handle
                .state
                .read()
                .map_err(|_| format!("backend client state poisoned for '{backend}'"))?;
            if state.tls == tls {
                return Ok(BackendClientRotation::unchanged(state.generation));
            }
        }

        let client = Arc::new(H2Client::new_with_observer(
            self.max_idle_per_backend,
            self.pool_idle_timeout,
            self.connect_timeout,
            tls.clone(),
            self.dns_resolver.clone(),
            self.connect_observer.clone(),
        )?);

        let mut state = handle
            .state
            .write()
            .map_err(|_| format!("backend client state poisoned for '{backend}'"))?;
        if state.tls == tls {
            return Ok(BackendClientRotation::unchanged(state.generation));
        }
        let previous_generation = state.generation;
        state.client = client;
        state.tls = tls;
        state.generation = state.generation.saturating_add(1);
        Ok(BackendClientRotation::rotated(
            previous_generation,
            state.generation,
        ))
    }

    pub(crate) async fn send(
        &self,
        backend: &str,
        req: Request<BoxBody<Bytes, Infallible>>,
    ) -> Result<hyper::Response<Incoming>, PoolError> {
        let handle = self.backend_handle(backend)?;
        let _permit = Self::acquire_inflight_permit(handle, backend)?;
        let client = Self::current_client(handle)?;
        client
            .send(Self::map_legacy_request(req))
            .await
            .map_err(PoolError::Send)
    }

    pub(crate) async fn send_exchange(
        &self,
        backend: &str,
        req: Request<BoxBody<Bytes, ProxyError>>,
    ) -> Result<(hyper::Response<Incoming>, OwnedSemaphorePermit), PoolError> {
        let handle = self.backend_handle(backend)?;
        let permit = Self::acquire_inflight_permit(handle, backend)?;
        let client = Self::current_client(handle)?;
        let response = client.send(req).await.map_err(PoolError::Send)?;
        Ok((response, permit))
    }

    pub(crate) fn acquire_exchange_permit(
        &self,
        backend: &str,
    ) -> Result<OwnedSemaphorePermit, PoolError> {
        Self::acquire_inflight_permit(self.backend_handle(backend)?, backend)
    }

    fn backend_handle(&self, backend: &str) -> Result<&BackendHandle, PoolError> {
        self.backends
            .get(backend)
            .ok_or_else(|| PoolError::UnknownBackend(backend.to_string()))
    }

    fn acquire_inflight_permit(
        handle: &BackendHandle,
        backend: &str,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, PoolError> {
        match Arc::clone(&handle.inflight).try_acquire_owned() {
            Ok(permit) => Ok(permit),
            Err(TryAcquireError::NoPermits) => {
                Err(PoolError::BackendOverloaded(backend.to_string()))
            }
            Err(TryAcquireError::Closed) => Err(PoolError::InflightLimiterClosed),
        }
    }

    fn current_client(handle: &BackendHandle) -> Result<Arc<H2Client>, PoolError> {
        handle
            .state
            .read()
            .map(|state| Arc::clone(&state.client))
            .map_err(|_| PoolError::InflightLimiterClosed)
    }

    fn map_legacy_request(
        req: Request<BoxBody<Bytes, Infallible>>,
    ) -> Request<BoxBody<Bytes, ProxyError>> {
        let (parts, body) = req.into_parts();
        Request::from_parts(
            parts,
            body.map_err(|never| -> ProxyError { match never {} })
                .boxed(),
        )
    }
}
