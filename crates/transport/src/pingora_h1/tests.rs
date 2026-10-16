use std::{collections::HashMap, convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    http::{HeaderMap, HeaderValue, Uri, Version},
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use impulse_config::runtime::{RuntimeBackendConnectionPolicy, RuntimeBackendTransportKind};
use pingora_core::upstreams::peer::HttpPeer;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{Semaphore, mpsc, oneshot},
};

use super::*;
use crate::{
    SharedDnsResolver, UpstreamExchangeRequest, UpstreamInflightPermit, UpstreamTransportPool,
};

#[derive(Debug, Eq, PartialEq)]
struct ResponseSnapshot {
    status: StatusCode,
    version: Version,
    marker: Option<HeaderValue>,
    body: Vec<u8>,
    connection_reuse: UpstreamConnectionReuse,
}

async fn start_parity_server() -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let service = service_fn(|mut request: Request<Incoming>| async move {
                let tunnel = request.method() == Method::CONNECT
                    || request.headers().contains_key(hyper::header::UPGRADE);
                if tunnel {
                    let connect = request.method() == Method::CONNECT;
                    let upgrade = hyper::upgrade::on(&mut request);
                    tokio::spawn(async move {
                        if let Ok(upgraded) = upgrade.await {
                            let mut upgraded = TokioIo::new(upgraded);
                            let mut payload = [0; 4];
                            if upgraded.read_exact(&mut payload).await.is_ok() {
                                let _ = upgraded.write_all(&payload).await;
                            }
                        }
                    });
                    let mut response = Response::builder().status(if connect {
                        StatusCode::OK
                    } else {
                        StatusCode::SWITCHING_PROTOCOLS
                    });
                    if !connect {
                        response = response
                            .header(hyper::header::CONNECTION, "upgrade")
                            .header(hyper::header::UPGRADE, "websocket");
                    }
                    return Ok::<_, Infallible>(
                        response
                            .body(Full::new(Bytes::new()))
                            .expect("tunnel response"),
                    );
                }

                let method = request.method().clone();
                let path = request.uri().path().to_string();
                let marker = request
                    .headers()
                    .get("x-parity-request")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                let body = request
                    .into_body()
                    .collect()
                    .await
                    .expect("request body")
                    .to_bytes();
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::CREATED)
                        .header("x-parity-response", "matched")
                        .body(Full::new(Bytes::from(format!(
                            "{method} {path} {marker} {}",
                            String::from_utf8_lossy(&body)
                        ))))
                        .expect("parity response"),
                )
            });
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades()
                    .await;
            });
        }
    });
    Ok(address)
}

fn transport_pool(address: SocketAddr) -> UpstreamTransportPool {
    UpstreamTransportPool::new_from_runtime_backends(
        [(address.to_string(), RuntimeBackendTransportKind::Http1)],
        HashMap::new(),
        RuntimeBackendConnectionPolicy {
            max_inflight: 4,
            max_idle_per_backend: 4,
            pool_idle_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(2),
            execution_timeout: Duration::from_secs(2),
        },
        SharedDnsResolver::new(),
    )
    .expect("transport pool")
}

fn request_parts(
    address: SocketAddr,
    method: Method,
) -> (UpstreamRequestHead, UpstreamRequestBody) {
    let mut headers = HeaderMap::new();
    headers.insert(
        hyper::header::HOST,
        HeaderValue::from_str(&address.to_string()).expect("host header"),
    );
    let payload = if method == Method::POST {
        headers.insert("x-parity-request", HeaderValue::from_static("canonical"));
        headers.insert(hyper::header::CONTENT_LENGTH, HeaderValue::from_static("7"));
        [
            Some(Bytes::from_static(b"pay")),
            Some(Bytes::from_static(b"load")),
        ]
    } else {
        if method != Method::CONNECT {
            headers.insert(
                hyper::header::CONNECTION,
                HeaderValue::from_static("upgrade"),
            );
            headers.insert(
                hyper::header::UPGRADE,
                HeaderValue::from_static("websocket"),
            );
        }
        [None, None]
    };
    let uri = if method == Method::CONNECT {
        Uri::try_from(address.to_string()).expect("CONNECT URI")
    } else {
        Uri::try_from(format!("http://{address}/parity?case=h1")).expect("request URI")
    };
    let (frames, body) = mpsc::channel(2);
    for payload in payload.into_iter().flatten() {
        frames
            .try_send(Ok(UpstreamBodyFrame::Data(payload)))
            .expect("request body");
    }
    drop(frames);
    (
        UpstreamRequestHead {
            method,
            uri,
            version: Version::HTTP_11,
            headers,
        },
        UpstreamRequestBody { frames: body },
    )
}

fn exchange_request(
    head: UpstreamRequestHead,
    body: UpstreamRequestBody,
) -> (
    UpstreamExchangeRequest,
    oneshot::Receiver<UpstreamExchangeCompletion>,
) {
    let (_cancel, cancellation) = oneshot::channel();
    let (completed, completion) = oneshot::channel();
    (
        UpstreamExchangeRequest {
            head,
            body,
            cancellation: UpstreamCancellation {
                signal: cancellation,
            },
            completion: completed,
        },
        completion,
    )
}

async fn pingora_lifecycle() -> (
    UpstreamExchangeLifecycle,
    oneshot::Receiver<UpstreamExchangeCompletion>,
) {
    let (_cancel, cancellation) = oneshot::channel();
    let (completed, completion) = oneshot::channel();
    let permit = Arc::new(Semaphore::new(1))
        .acquire_owned()
        .await
        .expect("inflight permit");
    (
        UpstreamExchangeLifecycle {
            cancellation: UpstreamCancellation {
                signal: cancellation,
            },
            completion: completed,
            inflight_permit: UpstreamInflightPermit { _permit: permit },
        },
        completion,
    )
}

async fn pingora_response(
    pool: &UpstreamTransportPool,
    address: SocketAddr,
    head: UpstreamRequestHead,
    body: UpstreamRequestBody,
) -> (
    UpstreamExchangeResponse,
    oneshot::Receiver<UpstreamExchangeCompletion>,
) {
    let identity = PingoraUpstreamConnectionIdentity::new(
        address,
        RuntimeBackendTransportKind::Http1,
        String::new(),
        None,
        None,
        0,
    );
    let mut session = pool
        .acquire_pingora_h1_session(HttpPeer::new(address, false, String::new()), &identity)
        .await
        .expect("Pingora H1 session");
    session
        .write_request(&head, body)
        .await
        .expect("Pingora H1 request");
    let (lifecycle, completion) = pingora_lifecycle().await;
    (
        session
            .read_response(lifecycle)
            .await
            .expect("Pingora H1 response"),
        completion,
    )
}

async fn response_snapshot(
    mut response: UpstreamExchangeResponse,
    completion: oneshot::Receiver<UpstreamExchangeCompletion>,
) -> ResponseSnapshot {
    let mut body = Vec::new();
    while let Some(frame) = response.body.frames.recv().await {
        if let UpstreamBodyFrame::Data(data) = frame.expect("response frame") {
            body.extend_from_slice(&data);
        }
    }
    let completion = completion.await.expect("exchange completion");
    assert!(matches!(
        completion.outcome,
        UpstreamExchangeOutcome::Completed
    ));
    ResponseSnapshot {
        status: response.head.status,
        version: response.head.version,
        marker: response.head.headers.get("x-parity-response").cloned(),
        body,
        connection_reuse: completion.connection_reuse,
    }
}

async fn tunnel_snapshot(
    response: UpstreamExchangeResponse,
    completion: oneshot::Receiver<UpstreamExchangeCompletion>,
) -> (StatusCode, [u8; 4]) {
    let mut tunnel = response
        .upgrade
        .expect("upgrade response")
        .tunnel
        .await
        .expect("tunnel channel")
        .expect("tunnel");
    tunnel.io.write_all(b"ping").await.expect("write tunnel");
    let mut echoed = [0; 4];
    tunnel
        .io
        .read_exact(&mut echoed)
        .await
        .expect("read tunnel");
    tunnel
        .lifecycle
        .completion
        .send(UpstreamExchangeCompletion {
            outcome: UpstreamExchangeOutcome::Completed,
            connection_reuse: UpstreamConnectionReuse::Close,
        })
        .expect("complete tunnel");
    let completed = completion.await.expect("tunnel completion");
    assert!(matches!(
        completed.outcome,
        UpstreamExchangeOutcome::Completed
    ));
    assert_eq!(completed.connection_reuse, UpstreamConnectionReuse::Close);
    (response.head.status, echoed)
}

#[tokio::test]
async fn hyper_and_pingora_h1_request_response_snapshots_match() {
    let address = match start_parity_server().await {
        Ok(address) => address,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("start parity server: {error}"),
    };
    let pool = transport_pool(address);

    let (head, body) = request_parts(address, Method::POST);
    let (request, hyper_completion) = exchange_request(head, body);
    let hyper = pool
        .send_h1_exchange(&address.to_string(), request)
        .await
        .expect("Hyper H1 response");

    let (head, body) = request_parts(address, Method::POST);
    let (pingora, pingora_completion) = pingora_response(&pool, address, head, body).await;

    assert_eq!(
        response_snapshot(hyper, hyper_completion).await,
        response_snapshot(pingora, pingora_completion).await
    );
}

#[tokio::test]
async fn hyper_and_pingora_h1_websocket_and_connect_tunnels_match() {
    let address = match start_parity_server().await {
        Ok(address) => address,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("start parity server: {error}"),
    };
    let pool = transport_pool(address);

    for method in [Method::GET, Method::CONNECT] {
        let (head, body) = request_parts(address, method.clone());
        let (request, hyper_completion) = exchange_request(head, body);
        let hyper = pool
            .send_h1_exchange(&address.to_string(), request)
            .await
            .expect("Hyper H1 tunnel response");

        let (head, body) = request_parts(address, method);
        let (pingora, pingora_completion) = pingora_response(&pool, address, head, body).await;

        assert_eq!(
            tunnel_snapshot(hyper, hyper_completion).await,
            tunnel_snapshot(pingora, pingora_completion).await
        );
    }
}
