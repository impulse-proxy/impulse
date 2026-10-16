use std::{collections::HashMap, convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    http::{HeaderMap, HeaderValue, Uri, Version},
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use impulse_config::runtime::{RuntimeBackendConnectionPolicy, RuntimeBackendTransportKind};
use pingora_core::upstreams::peer::HttpPeer;
use tokio::{
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
    trailer: Option<HeaderValue>,
    connection_reuse: UpstreamConnectionReuse,
}

async fn start_parity_server() -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let service = service_fn(|request: Request<Incoming>| async move {
                let method = request.method().clone();
                let path = request.uri().path().to_string();
                let marker = request
                    .headers()
                    .get("x-parity-request")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                let collected = request.into_body().collect().await.expect("request body");
                let trailer = collected
                    .trailers()
                    .and_then(|trailers| trailers.get("x-request-end"))
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                let body = collected.to_bytes();
                let mut trailers = HeaderMap::new();
                trailers.insert("x-response-end", HeaderValue::from_static("done"));
                let response_body = Full::new(Bytes::from(format!(
                    "{method} {path} {marker} {} {trailer}",
                    String::from_utf8_lossy(&body)
                )))
                .with_trailers(async move { Some(Ok::<_, Infallible>(trailers)) });
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::CREATED)
                        .header("x-parity-response", "matched")
                        .body(response_body)
                        .expect("parity response"),
                )
            });
            tokio::spawn(async move {
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Ok(address)
}

fn transport_pool(address: SocketAddr) -> UpstreamTransportPool {
    UpstreamTransportPool::new_from_runtime_backends(
        [(address.to_string(), RuntimeBackendTransportKind::H2)],
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

fn request_parts(address: SocketAddr) -> (UpstreamRequestHead, UpstreamRequestBody) {
    let mut headers = HeaderMap::new();
    headers.insert("x-parity-request", HeaderValue::from_static("canonical"));
    headers.insert(hyper::header::CONTENT_LENGTH, HeaderValue::from_static("7"));
    let (frames, body) = mpsc::channel(3);
    frames
        .try_send(Ok(UpstreamBodyFrame::Data(Bytes::from_static(b"pay"))))
        .expect("first request body frame");
    frames
        .try_send(Ok(UpstreamBodyFrame::Data(Bytes::from_static(b"load"))))
        .expect("second request body frame");
    let mut trailers = HeaderMap::new();
    trailers.insert("x-request-end", HeaderValue::from_static("done"));
    frames
        .try_send(Ok(UpstreamBodyFrame::Trailers(UpstreamTrailers {
            headers: trailers,
        })))
        .expect("request trailers");
    drop(frames);

    (
        UpstreamRequestHead {
            method: Method::POST,
            uri: Uri::try_from(format!("http://{address}/parity?case=h2")).expect("request URI"),
            version: Version::HTTP_2,
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
    bool,
) {
    let identity = PingoraUpstreamConnectionIdentity::new(
        address,
        RuntimeBackendTransportKind::H2,
        String::new(),
        None,
        None,
        0,
    );
    let mut session = pool
        .acquire_pingora_h2_session(HttpPeer::new(address, false, String::new()), &identity)
        .await
        .expect("Pingora H2 session");
    let reused = session.reused();
    session
        .write_request(&head, body)
        .await
        .expect("Pingora H2 request");
    let (lifecycle, completion) = pingora_lifecycle().await;
    (
        session
            .read_response(lifecycle)
            .await
            .expect("Pingora H2 response"),
        completion,
        reused,
    )
}

async fn response_snapshot(
    mut response: UpstreamExchangeResponse,
    completion: oneshot::Receiver<UpstreamExchangeCompletion>,
) -> ResponseSnapshot {
    let mut body = Vec::new();
    let mut trailer = None;
    while let Some(frame) = response.body.frames.recv().await {
        match frame.expect("response frame") {
            UpstreamBodyFrame::Data(data) => body.extend_from_slice(&data),
            UpstreamBodyFrame::Trailers(trailers) => {
                trailer = trailers.headers.get("x-response-end").cloned();
            }
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
        trailer,
        connection_reuse: completion.connection_reuse,
    }
}

#[tokio::test]
async fn hyper_and_pingora_h2_streaming_snapshots_match() {
    let address = match start_parity_server().await {
        Ok(address) => address,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("start parity server: {error}"),
    };
    let pool = transport_pool(address);

    for expected_reused in [false, true] {
        let (head, body) = request_parts(address);
        let (request, hyper_completion) = exchange_request(head, body);
        let hyper = pool
            .send_h2_exchange(&address.to_string(), request)
            .await
            .expect("Hyper H2 response");

        let (head, body) = request_parts(address);
        let (pingora, pingora_completion, reused) =
            pingora_response(&pool, address, head, body).await;

        assert_eq!(reused, expected_reused);
        assert_eq!(
            response_snapshot(hyper, hyper_completion).await,
            response_snapshot(pingora, pingora_completion).await
        );
    }
}
