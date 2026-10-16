//! Local support helpers for transport facade contract tests.

use std::{collections::HashMap, time::Duration};

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode, body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use impulse_config::runtime::{RuntimeBackendConnectionPolicy, RuntimeBackendTransportKind};
use impulse_transport::{SharedDnsResolver, UpstreamTransportPool};
use tokio::{io::AsyncReadExt, net::TcpListener};

#[derive(Clone, Copy)]
pub(crate) enum TransportTestProtocol {
    Http1,
    H2,
}

impl TransportTestProtocol {
    pub(crate) fn runtime_kind(self) -> RuntimeBackendTransportKind {
        match self {
            Self::Http1 => RuntimeBackendTransportKind::Http1,
            Self::H2 => RuntimeBackendTransportKind::H2,
        }
    }
}

pub(crate) fn loopback_bind_restricted(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::PermissionDenied
        || matches!(err.raw_os_error(), Some(1) | Some(13))
}

pub(crate) fn build_pool(
    backends: impl IntoIterator<Item = (String, RuntimeBackendTransportKind)>,
    max_inflight: usize,
    resolver: SharedDnsResolver,
) -> UpstreamTransportPool {
    UpstreamTransportPool::new_from_runtime_backends(
        backends,
        HashMap::new(),
        RuntimeBackendConnectionPolicy {
            max_inflight,
            max_idle_per_backend: 64,
            pool_idle_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(2),
            execution_timeout: Duration::from_secs(5),
        },
        resolver,
    )
    .expect("transport pool")
}

pub(crate) fn build_single_backend_pool(
    backend: String,
    transport_kind: RuntimeBackendTransportKind,
    max_inflight: usize,
    resolver: SharedDnsResolver,
) -> UpstreamTransportPool {
    build_pool([(backend, transport_kind)], max_inflight, resolver)
}

pub(crate) fn backend_address(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

pub(crate) async fn start_h1_upgrade_server() -> std::io::Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let backend = backend_address(listener.local_addr()?.port());

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            let service = service_fn(move |mut req: Request<Incoming>| async move {
                let upgrade_requested = req
                    .headers()
                    .get("upgrade")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
                if upgrade_requested {
                    let on_upgrade = hyper::upgrade::on(&mut req);
                    tokio::spawn(async move {
                        if let Ok(upgraded) = on_upgrade.await {
                            let mut upgraded = TokioIo::new(upgraded);
                            let mut buf = [0u8; 16];
                            let _ = upgraded.read(&mut buf).await;
                        }
                    });
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::SWITCHING_PROTOCOLS)
                            .header("connection", "upgrade")
                            .header("upgrade", "websocket")
                            .body(Full::new(Bytes::new()))
                            .expect("upgrade response"),
                    )
                } else {
                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(
                        b"ok",
                    ))))
                }
            });

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .with_upgrades()
                    .await;
            });
        }
    });

    Ok(backend)
}
