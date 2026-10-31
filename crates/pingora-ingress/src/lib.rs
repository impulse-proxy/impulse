//! Pingora HTTP/1.1 and HTTP/2 listener runtime for Impulse.
//!
//! Protocol-neutral request execution remains owned by `impulse-edge`.

#![forbid(unsafe_code)]
#![deny(unused_crate_dependencies)]
#![warn(unreachable_pub)]

use std::{
    fmt,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
#[cfg(unix)]
use pingora_core::server::{Fds, ListenFds};
use pingora_core::{
    Result,
    apps::ServerApp,
    listeners::{ConnectionFilter, TcpSocketOptions, tls::TlsSettings},
    services::{Service as PingoraServiceLifecycle, listening::Service},
};
use rustls::server::{ResolvesServerCert, danger::ClientCertVerifier};

#[async_trait]
pub trait ConnectionAdmission: fmt::Debug + Send + Sync {
    async fn should_accept(&self, address: Option<&SocketAddr>) -> bool;
}

#[derive(Debug)]
struct PingoraConnectionFilter {
    admission: Arc<dyn ConnectionAdmission>,
}

#[async_trait]
impl ConnectionFilter for PingoraConnectionFilter {
    async fn should_accept(&self, address: Option<&SocketAddr>) -> bool {
        self.admission.should_accept(address).await
    }
}

pub struct PingoraListenerConfig {
    pub address: String,
    pub certificate_path: String,
    pub private_key_path: String,
    pub reuse_port: bool,
    pub certificate_resolver: Arc<dyn ResolvesServerCert>,
    pub client_certificate_verifier: Option<Arc<dyn ClientCertVerifier>>,
}

#[derive(Default)]
pub struct PingoraDrainState {
    active_requests: AtomicUsize,
    active_connections: AtomicUsize,
}

impl PingoraDrainState {
    pub fn request_started(&self) {
        self.active_requests.fetch_add(1, Ordering::AcqRel);
    }

    pub fn request_finished(&self) {
        self.active_requests.fetch_sub(1, Ordering::AcqRel);
    }

    pub fn active_requests(&self) -> usize {
        self.active_requests.load(Ordering::Acquire)
    }

    pub fn try_acquire_connection(self: &Arc<Self>, limit: usize) -> Option<ConnectionPermit> {
        self.active_connections
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < limit).then_some(active + 1)
            })
            .ok()?;
        Some(ConnectionPermit {
            drain: Arc::clone(self),
        })
    }
}

pub struct ConnectionPermit {
    drain: Arc<PingoraDrainState>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.drain.active_connections.fetch_sub(1, Ordering::AcqRel);
    }
}

pub fn create_listener_service<A>(
    app: A,
    config: PingoraListenerConfig,
    admission: Arc<dyn ConnectionAdmission>,
) -> Result<Service<A>> {
    let mut tls = TlsSettings::intermediate(&config.certificate_path, &config.private_key_path)?;
    tls.set_cert_resolver(config.certificate_resolver);
    if let Some(verifier) = config.client_certificate_verifier {
        tls.set_client_cert_verifier(verifier);
    }
    tls.enable_h2();

    let mut service = Service::new(format!("Impulse Pingora Ingress {}", config.address), app);
    service.set_connection_filter(Arc::new(PingoraConnectionFilter { admission }));
    let socket_options = config.reuse_port.then(|| {
        let mut options = TcpSocketOptions::default();
        options.so_reuseport = Some(true);
        options
    });
    service.add_tls_with_settings(&config.address, socket_options, tls);
    Ok(service)
}

pub struct PingoraListenerTask {
    address: String,
    #[cfg(unix)]
    listen_fds: ListenFds,
    shutdown: tokio::sync::watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<()>>,
    drain: Arc<PingoraDrainState>,
    forced_drained: bool,
}

impl PingoraListenerTask {
    pub async fn wait_until_ready(&mut self) -> std::result::Result<(), String> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if self
                .task
                .as_ref()
                .is_some_and(tokio::task::JoinHandle::is_finished)
            {
                return match self.collect_finished().await {
                    Some(Err(error)) => Err(error),
                    _ => Err(format!(
                        "Pingora listener {} stopped during startup",
                        self.address
                    )),
                };
            }
            #[cfg(unix)]
            if self.listen_fds.lock().get(&self.address).is_some() {
                return Ok(());
            }
            #[cfg(not(unix))]
            if tokio::time::timeout(
                Duration::from_millis(50),
                tokio::net::TcpStream::connect(&self.address),
            )
            .await
            .is_ok_and(|result| result.is_ok())
            {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "Timed out waiting for Pingora listener {}",
                    self.address
                ));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub fn request_shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    pub fn active_requests(&self) -> usize {
        self.drain.active_requests()
    }

    pub async fn collect_finished(&mut self) -> Option<std::result::Result<(), String>> {
        if !self
            .task
            .as_ref()
            .is_some_and(tokio::task::JoinHandle::is_finished)
        {
            return None;
        }
        let task = self.task.take()?;
        Some(
            task.await
                .map_err(|error| format!("Pingora listener {} failed: {error}", self.address)),
        )
    }

    pub fn stopped(&self) -> bool {
        self.forced_drained || (self.task.is_none() && self.active_requests() == 0)
    }

    pub fn force_drain(&mut self) -> usize {
        self.forced_drained = true;
        self.active_requests()
    }

    pub async fn drain(mut self, timeout: Duration) -> std::result::Result<usize, String> {
        self.request_shutdown();
        let deadline = tokio::time::Instant::now() + timeout;
        if let Some(mut task) = self.task.take() {
            match tokio::time::timeout_at(deadline, &mut task).await {
                Ok(result) => result.map_err(|error| {
                    format!("Pingora listener {} failed: {error}", self.address)
                })?,
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    return Ok(self.active_requests());
                }
            }
        }
        loop {
            let active = self.active_requests();
            if active == 0 {
                return Ok(0);
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(active);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

impl Drop for PingoraListenerTask {
    fn drop(&mut self) {
        self.request_shutdown();
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
    }
}

pub fn spawn_listener<A>(
    address: String,
    mut service: Service<A>,
    drain: Arc<PingoraDrainState>,
) -> PingoraListenerTask
where
    A: ServerApp + Send + Sync + 'static,
{
    let (shutdown, shutdown_watch) = tokio::sync::watch::channel(false);
    #[cfg(unix)]
    let listen_fds: ListenFds = Arc::new(Fds::new().into());
    #[cfg(unix)]
    let service_listen_fds = Arc::clone(&listen_fds);
    let task = tokio::spawn(async move {
        #[cfg(unix)]
        service
            .start_service(Some(service_listen_fds), shutdown_watch, 1)
            .await;
        #[cfg(not(unix))]
        service.start_service(shutdown_watch, 1).await;
    });
    PingoraListenerTask {
        address,
        #[cfg(unix)]
        listen_fds,
        shutdown,
        task: Some(task),
        drain,
        forced_drained: false,
    }
}
