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
    h1_client::H1Client,
    h2_client::{ConnectObserver, SharedDnsResolver},
};

struct BackendClientState {
    client: Arc<H1Client>,
}

struct BackendHandle {
    state: RwLock<BackendClientState>,
    inflight: Arc<Semaphore>,
}

pub(crate) struct H1Pool {
    backends: HashMap<String, BackendHandle>,
    max_idle_per_backend: usize,
    pool_idle_timeout: Duration,
    connect_timeout: Duration,
    dns_resolver: SharedDnsResolver,
    connect_observer: Option<ConnectObserver>,
}

impl H1Pool {
    pub(crate) fn new_with_observer<I>(
        backends: I,
        max_inflight: usize,
        max_idle_per_backend: usize,
        pool_idle_timeout: Duration,
        connect_timeout: Duration,
        dns_resolver: SharedDnsResolver,
        connect_observer: Option<ConnectObserver>,
    ) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        let inflight = max_inflight.max(1);
        let max_idle_per_backend = max_idle_per_backend.max(1);
        let mut map = HashMap::new();
        for backend in backends {
            let client = Arc::new(H1Client::new_with_observer(
                max_idle_per_backend,
                pool_idle_timeout,
                connect_timeout,
                dns_resolver.clone(),
                connect_observer.clone(),
            ));
            map.insert(
                backend,
                BackendHandle {
                    state: RwLock::new(BackendClientState { client }),
                    inflight: Arc::new(Semaphore::new(inflight)),
                },
            );
        }

        Self {
            backends: map,
            max_idle_per_backend,
            pool_idle_timeout,
            connect_timeout,
            dns_resolver,
            connect_observer,
        }
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

    pub(crate) async fn send_upgrade(
        &self,
        backend: &str,
        req: Request<BoxBody<Bytes, Infallible>>,
    ) -> Result<(hyper::Response<Incoming>, OwnedSemaphorePermit), PoolError> {
        let handle = self.backend_handle(backend)?;
        let permit = Self::acquire_inflight_permit(handle, backend)?;
        let client = Self::current_client(handle)?;
        let response = client
            .send(Self::map_legacy_request(req))
            .await
            .map_err(PoolError::Send)?;
        Ok((response, permit))
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

    pub(crate) fn rotate_backend_client(
        &self,
        backend: &str,
    ) -> Result<BackendClientRotation, String> {
        let Some(handle) = self.backends.get(backend) else {
            return Ok(BackendClientRotation::missing_backend());
        };

        let client = Arc::new(H1Client::new_with_observer(
            self.max_idle_per_backend,
            self.pool_idle_timeout,
            self.connect_timeout,
            self.dns_resolver.clone(),
            self.connect_observer.clone(),
        ));

        let mut state = handle
            .state
            .write()
            .map_err(|_| format!("backend client state poisoned for '{backend}'"))?;
        state.client = client;
        Ok(BackendClientRotation::recreated())
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

    fn current_client(handle: &BackendHandle) -> Result<Arc<H1Client>, PoolError> {
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
