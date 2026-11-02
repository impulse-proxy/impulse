use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use log::error;
use rustls::{ServerConfig, pki_types::CertificateDer};
use tokio_rustls::TlsAcceptor;

pub type ControlApiResponse = Response<Full<Bytes>>;

#[async_trait]
pub trait ControlApiRequestService: Clone + Send + Sync + 'static {
    type ConnectionContext: Clone + Send + Sync + 'static;

    fn connection_context(
        &self,
        peer: SocketAddr,
        peer_certificates: Option<&[CertificateDer<'static>]>,
    ) -> Self::ConnectionContext;

    async fn handle_request(
        &self,
        request: Request<Incoming>,
        context: Self::ConnectionContext,
    ) -> ControlApiResponse;
}

#[derive(Debug)]
pub enum ControlApiConnectionError {
    TlsHandshake(std::io::Error),
    TlsHandshakeTimeout,
    Http(hyper::Error),
    ConnectionTimeout,
}

pub struct ControlApiConnectionService<S> {
    request_service: S,
}

impl<S> ControlApiConnectionService<S> {
    pub fn new(request_service: S) -> Self {
        Self { request_service }
    }
}

impl<S: ControlApiRequestService> ControlApiConnectionService<S> {
    pub async fn serve(
        self,
        stream: tokio::net::TcpStream,
        peer: SocketAddr,
        server_config: Arc<ServerConfig>,
        timeout: Duration,
    ) -> Result<(), ControlApiConnectionError> {
        let tls_stream = accept_control_api_tls(stream, server_config, timeout).await?;
        let context = self
            .request_service
            .connection_context(peer, tls_stream.get_ref().1.peer_certificates());
        let request_service = self.request_service;
        let service = service_fn(move |request| {
            let request_service = request_service.clone();
            let context = context.clone();
            async move { Ok::<_, hyper::Error>(request_service.handle_request(request, context).await) }
        });
        let connection = http1::Builder::new().serve_connection(TokioIo::new(tls_stream), service);
        match tokio::time::timeout(timeout, connection).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(ControlApiConnectionError::Http(error)),
            Err(_) => Err(ControlApiConnectionError::ConnectionTimeout),
        }
    }
}

pub async fn accept_control_api_tls(
    stream: tokio::net::TcpStream,
    server_config: Arc<ServerConfig>,
    timeout: Duration,
) -> Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, ControlApiConnectionError> {
    let accept = TlsAcceptor::from(server_config).accept(stream);
    match tokio::time::timeout(timeout, accept).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(error)) => Err(ControlApiConnectionError::TlsHandshake(error)),
        Err(_) => Err(ControlApiConnectionError::TlsHandshakeTimeout),
    }
}

pub async fn run_control_api_blocking<F, T>(work: F) -> Option<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(value) => Some(value),
        Err(error) => {
            error!("control API blocking task panicked: {}", error);
            None
        }
    }
}

pub fn control_api_internal_error_response() -> ControlApiResponse {
    Response::builder()
        .status(http::StatusCode::INTERNAL_SERVER_ERROR)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from_static(
            b"{\"error\":\"internal_error\"}",
        )))
        .unwrap_or_else(|_| {
            Response::new(Full::new(Bytes::from_static(b"{\"error\":\"response\"}")))
        })
}

pub fn stale_control_api_connection_response() -> ControlApiResponse {
    Response::builder()
        .status(http::StatusCode::UNAUTHORIZED)
        .header(http::header::CONNECTION, "close")
        .body(Full::new(Bytes::from_static(
            b"control API authentication policy changed\n",
        )))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"unauthorized\n"))))
}

pub fn try_claim_control_api_connection_slot(
    active_connections: &Arc<AtomicUsize>,
    max_connections: usize,
) -> bool {
    loop {
        let current = active_connections.load(Ordering::Relaxed);
        if current >= max_connections {
            return false;
        }
        if active_connections
            .compare_exchange(
                current,
                current.saturating_add(1),
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            return true;
        }
    }
}

pub struct ConnectionSlotGuard {
    active_connections: Arc<AtomicUsize>,
}

impl ConnectionSlotGuard {
    pub fn new(active_connections: Arc<AtomicUsize>) -> Self {
        Self { active_connections }
    }
}

impl Drop for ConnectionSlotGuard {
    fn drop(&mut self) {
        self.active_connections.fetch_sub(1, Ordering::AcqRel);
    }
}
