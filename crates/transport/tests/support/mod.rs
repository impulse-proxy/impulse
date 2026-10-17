//! Local support helpers for transport facade contract tests.

use std::collections::HashMap;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode, body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use impulse_config::{
    config::{
        Backend, ClientAuth, Config, Listen, LoadBalancing, Log, Observability, Performance,
        Resilience, RouteMatch, Security, Tls, Upstream, UpstreamTls,
    },
    runtime::RuntimeConfig,
};
use impulse_transport::{SharedDnsResolver, UpstreamTransportPool};
use tokio::{io::AsyncReadExt, net::TcpListener};

pub(crate) fn loopback_bind_restricted(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::PermissionDenied
        || matches!(err.raw_os_error(), Some(1) | Some(13))
}

pub(crate) fn build_pool(
    backends: impl IntoIterator<Item = String>,
    max_inflight: usize,
    resolver: SharedDnsResolver,
) -> UpstreamTransportPool {
    let mut config = Config {
        version: 1,
        listen: Listen {
            protocol: "http3".to_string(),
            port: 443,
            address: "0.0.0.0".to_string(),
            tls: Tls {
                cert: "/tmp/tls/default.pem".to_string(),
                key: "/tmp/tls/default.key".to_string(),
                certificates: Vec::new(),
                client_auth: ClientAuth::default(),
            },
        },
        listeners: Vec::new(),
        upstream: HashMap::new(),
        load_balancing: None,
        upstream_tls: UpstreamTls::default(),
        secrets: Default::default(),
        log: Log::default(),
        performance: Performance {
            worker_threads: 1,
            per_backend_inflight_limit: max_inflight,
            ..Performance::default()
        },
        observability: Observability::default(),
        resilience: Resilience::default(),
        security: Security::default(),
    };
    for (index, backend) in backends.into_iter().enumerate() {
        config.upstream.insert(
            format!("backend-{index}"),
            Upstream {
                load_balancing: LoadBalancing::default(),
                auth: Default::default(),
                host_policy: Default::default(),
                forwarded_headers: Default::default(),
                tls: None,
                route: RouteMatch {
                    host: Some(format!("backend-{index}.example.com")),
                    path_prefix: Some("/".to_string()),
                    method: None,
                },
                backends: vec![Backend {
                    id: format!("backend-{index}"),
                    address: backend,
                    weight: 100,
                    health_check: None,
                }],
            },
        );
    }
    let runtime = RuntimeConfig::from_config(&config).expect("runtime config");
    UpstreamTransportPool::from_runtime_upstreams(
        runtime.upstreams.values(),
        &runtime.policies.transport.backend_connections,
        resolver,
    )
    .expect("transport pool")
}

pub(crate) fn build_single_backend_pool(
    backend: String,
    max_inflight: usize,
    resolver: SharedDnsResolver,
) -> UpstreamTransportPool {
    build_pool([backend], max_inflight, resolver)
}

pub(crate) fn backend_address(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
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
