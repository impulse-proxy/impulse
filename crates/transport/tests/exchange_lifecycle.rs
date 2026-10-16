//! Upstream exchange streaming and lifecycle contract tests.

mod support;

use std::{
    collections::VecDeque,
    convert::Infallible,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::{
    Request, Response, StatusCode,
    body::{Body, Frame, Incoming},
    http::{HeaderMap, HeaderValue, Method, Uri, Version},
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use impulse_errors::{PoolError, ProxyError};
use impulse_transport::{
    SharedDnsResolver, UpstreamBody, UpstreamBodyFrame, UpstreamCancellation,
    UpstreamConnectionReuse, UpstreamExchangeCompletion, UpstreamExchangeLifecycle,
    UpstreamExchangeOutcome, UpstreamExchangeRequest, UpstreamRequestHead, UpstreamTunnel,
};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::{mpsc, oneshot},
};

use crate::support::{
    TransportTestProtocol, backend_address, build_single_backend_pool, loopback_bind_restricted,
    start_h1_upgrade_server,
};

enum TestBody {
    Scripted(VecDeque<Frame<Bytes>>),
    Pending(mpsc::Receiver<Result<Frame<Bytes>, Infallible>>),
}

impl TestBody {
    fn scripted(frames: impl IntoIterator<Item = Frame<Bytes>>) -> Self {
        Self::Scripted(frames.into_iter().collect())
    }
}

impl Body for TestBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match &mut *self {
            Self::Scripted(frames) => Poll::Ready(frames.pop_front().map(Ok)),
            Self::Pending(frames) => frames.poll_recv(cx),
        }
    }
}

struct CapturedRequest {
    data: Vec<Bytes>,
    trailers: HeaderMap,
}

fn exchange_request(
    backend: &str,
    path: &str,
    method: Method,
    headers: HeaderMap,
    frames: impl IntoIterator<Item = UpstreamBodyFrame>,
) -> (
    UpstreamExchangeRequest,
    oneshot::Sender<()>,
    oneshot::Receiver<UpstreamExchangeCompletion>,
) {
    let frames = frames.into_iter().collect::<Vec<_>>();
    let (frame_tx, frame_rx) = mpsc::channel(frames.len().max(1));
    for frame in frames {
        frame_tx.try_send(Ok(frame)).expect("queue request frame");
    }
    drop(frame_tx);

    let (cancellation, cancellation_signal) = oneshot::channel();
    let (completion_signal, completion) = oneshot::channel();
    (
        UpstreamExchangeRequest {
            head: UpstreamRequestHead {
                method,
                uri: Uri::try_from(format!("http://{backend}{path}"))
                    .expect("exchange request URI"),
                version: Version::HTTP_11,
                headers,
            },
            body: frame_rx,
            cancellation: UpstreamCancellation {
                signal: cancellation_signal,
            },
            completion: completion_signal,
        },
        cancellation,
        completion,
    )
}

async fn collect_exchange_body(mut body: UpstreamBody) -> Vec<UpstreamBodyFrame> {
    let mut frames = Vec::new();
    while let Some(frame) = body.recv().await {
        frames.push(frame.expect("upstream response frame"));
    }
    frames
}

async fn start_streaming_server() -> std::io::Result<(String, oneshot::Receiver<CapturedRequest>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let backend = backend_address(listener.local_addr()?.port());
    let (captured_tx, captured_rx) = oneshot::channel();
    let captured_tx = Arc::new(Mutex::new(Some(captured_tx)));

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(connection) => connection,
                Err(_) => return,
            };
            let captured_tx = Arc::clone(&captured_tx);
            let service = service_fn(move |mut request: Request<Incoming>| {
                let captured_tx = Arc::clone(&captured_tx);
                async move {
                    let mut data = Vec::new();
                    let mut trailers = HeaderMap::new();
                    while let Some(frame) = request.body_mut().frame().await {
                        let frame = frame.expect("request body frame");
                        match frame.into_data() {
                            Ok(chunk) => data.push(chunk),
                            Err(frame) => {
                                if let Ok(request_trailers) = frame.into_trailers() {
                                    trailers = request_trailers;
                                }
                            }
                        }
                    }
                    if let Some(captured_tx) = captured_tx.lock().expect("capture lock").take() {
                        let _ = captured_tx.send(CapturedRequest { data, trailers });
                    }

                    let mut response_trailers = HeaderMap::new();
                    response_trailers.insert("x-response-end", HeaderValue::from_static("done"));
                    Ok::<_, Infallible>(
                        Response::builder()
                            .header("trailer", "x-response-end")
                            .body(TestBody::scripted([
                                Frame::data(Bytes::from_static(b"first")),
                                Frame::data(Bytes::from_static(b"second")),
                                Frame::trailers(response_trailers),
                            ]))
                            .expect("streaming response"),
                    )
                }
            });
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    Ok((backend, captured_rx))
}

async fn start_pending_body_server() -> std::io::Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let backend = backend_address(listener.local_addr()?.port());
    let request_count = Arc::new(AtomicUsize::new(0));
    let held_bodies = Arc::new(Mutex::new(Vec::new()));

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(connection) => connection,
                Err(_) => return,
            };
            let request_count = Arc::clone(&request_count);
            let held_bodies = Arc::clone(&held_bodies);
            let service = service_fn(move |_request: Request<Incoming>| {
                let request_number = request_count.fetch_add(1, Ordering::SeqCst);
                let held_bodies = Arc::clone(&held_bodies);
                async move {
                    let body = if request_number == 0 {
                        let (frames, body) = mpsc::channel(1);
                        held_bodies.lock().expect("held body lock").push(frames);
                        TestBody::Pending(body)
                    } else {
                        TestBody::scripted([Frame::data(Bytes::from_static(b"released"))])
                    };
                    Ok::<_, Infallible>(Response::new(body))
                }
            });
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    Ok(backend)
}

fn assert_completed(completion: UpstreamExchangeCompletion) {
    assert!(matches!(
        completion.outcome,
        UpstreamExchangeOutcome::Completed
    ));
    assert_eq!(completion.connection_reuse, UpstreamConnectionReuse::Reuse);
}

#[tokio::test]
async fn exchange_streams_data_and_trailers_in_both_directions() {
    let (backend, captured) = match start_streaming_server().await {
        Ok(server) => server,
        Err(error) if loopback_bind_restricted(&error) => return,
        Err(error) => panic!("start streaming exchange server: {error}"),
    };
    let pool = build_single_backend_pool(
        backend.clone(),
        TransportTestProtocol::Http1.runtime_kind(),
        1,
        SharedDnsResolver::new(),
    );
    let mut request_trailers = HeaderMap::new();
    request_trailers.insert("x-request-end", HeaderValue::from_static("done"));
    let mut request_headers = HeaderMap::new();
    request_headers.insert("trailer", HeaderValue::from_static("x-request-end"));
    request_headers.insert("te", HeaderValue::from_static("trailers"));
    let (request, _cancellation, completion) = exchange_request(
        &backend,
        "/stream",
        Method::POST,
        request_headers,
        [
            UpstreamBodyFrame::Data(Bytes::from_static(b"one")),
            UpstreamBodyFrame::Data(Bytes::from_static(b"two")),
            UpstreamBodyFrame::Trailers(request_trailers),
        ],
    );

    let response = pool
        .send_exchange(&backend, request)
        .await
        .expect("streaming exchange response");
    assert_eq!(response.head.status, StatusCode::OK);
    let response_frames = collect_exchange_body(response.body).await;
    let mut response_data = Vec::new();
    let mut response_trailers = None;
    for frame in response_frames {
        match frame {
            UpstreamBodyFrame::Data(data) => response_data.extend_from_slice(&data),
            UpstreamBodyFrame::Trailers(trailers) => response_trailers = Some(trailers),
        }
    }
    assert_eq!(response_data, b"firstsecond");
    assert_eq!(
        response_trailers
            .as_ref()
            .and_then(|trailers| trailers.get("x-response-end")),
        Some(&HeaderValue::from_static("done"))
    );

    let captured = captured.await.expect("captured request");
    assert_eq!(
        captured
            .data
            .iter()
            .flat_map(|chunk| chunk.iter().copied())
            .collect::<Vec<_>>(),
        b"onetwo"
    );
    assert_eq!(
        captured.trailers.get("x-request-end"),
        Some(&HeaderValue::from_static("done"))
    );
    assert_completed(completion.await.expect("streaming completion"));
}

#[tokio::test]
async fn cancellation_closes_the_exchange_and_releases_its_inflight_permit() {
    let backend = match start_pending_body_server().await {
        Ok(backend) => backend,
        Err(error) if loopback_bind_restricted(&error) => return,
        Err(error) => panic!("start pending exchange server: {error}"),
    };
    let pool = build_single_backend_pool(
        backend.clone(),
        TransportTestProtocol::Http1.runtime_kind(),
        1,
        SharedDnsResolver::new(),
    );
    let (request, cancellation, completion) =
        exchange_request(&backend, "/hold", Method::GET, HeaderMap::new(), []);
    let response = pool
        .send_exchange(&backend, request)
        .await
        .expect("held exchange response");

    let (blocked, _blocked_cancellation, _blocked_completion) =
        exchange_request(&backend, "/blocked", Method::GET, HeaderMap::new(), []);
    assert!(matches!(
        pool.send_exchange(&backend, blocked).await,
        Err(ProxyError::Pool(PoolError::BackendOverloaded(_)))
    ));

    cancellation.send(()).expect("cancel exchange");
    let completion = completion.await.expect("cancellation completion");
    assert!(matches!(
        completion.outcome,
        UpstreamExchangeOutcome::Cancelled
    ));
    assert_eq!(completion.connection_reuse, UpstreamConnectionReuse::Close);
    drop(response);

    let (released, _released_cancellation, released_completion) =
        exchange_request(&backend, "/released", Method::GET, HeaderMap::new(), []);
    let released = pool
        .send_exchange(&backend, released)
        .await
        .expect("exchange after cancellation");
    let frames = collect_exchange_body(released.body).await;
    assert!(matches!(
        frames.as_slice(),
        [UpstreamBodyFrame::Data(body)] if body.as_ref() == b"released"
    ));
    assert_completed(released_completion.await.expect("released completion"));
}

#[tokio::test]
async fn tunnel_completion_releases_its_inflight_permit() {
    let backend = match start_h1_upgrade_server().await {
        Ok(backend) => backend,
        Err(error) if loopback_bind_restricted(&error) => return,
        Err(error) => panic!("start tunnel exchange server: {error}"),
    };
    let pool = build_single_backend_pool(
        backend.clone(),
        TransportTestProtocol::Http1.runtime_kind(),
        1,
        SharedDnsResolver::new(),
    );
    let mut headers = HeaderMap::new();
    headers.insert("connection", HeaderValue::from_static("upgrade"));
    headers.insert("upgrade", HeaderValue::from_static("websocket"));
    let (request, _cancellation, completion) =
        exchange_request(&backend, "/", Method::GET, headers, []);
    let response = pool
        .send_exchange(&backend, request)
        .await
        .expect("tunnel exchange response");
    assert_eq!(response.head.status, StatusCode::SWITCHING_PROTOCOLS);
    let upgrade = response.upgrade.expect("exchange upgrade");
    let UpstreamTunnel { mut io, lifecycle } =
        tokio::time::timeout(Duration::from_secs(1), upgrade.tunnel)
            .await
            .expect("tunnel timeout")
            .expect("tunnel task")
            .expect("upstream tunnel");

    let (blocked, _blocked_cancellation, _blocked_completion) =
        exchange_request(&backend, "/blocked", Method::GET, HeaderMap::new(), []);
    assert!(matches!(
        pool.send_exchange(&backend, blocked).await,
        Err(ProxyError::Pool(PoolError::BackendOverloaded(_)))
    ));

    io.write_all(b"ping").await.expect("write tunnel payload");
    drop(io);
    let UpstreamExchangeLifecycle {
        cancellation,
        completion: done,
        inflight_permit,
    } = lifecycle;
    done.send(UpstreamExchangeCompletion {
        outcome: UpstreamExchangeOutcome::Completed,
        connection_reuse: UpstreamConnectionReuse::Close,
    })
    .expect("complete tunnel exchange");
    drop(cancellation);
    drop(inflight_permit);
    let completion = completion.await.expect("tunnel completion");
    assert!(matches!(
        completion.outcome,
        UpstreamExchangeOutcome::Completed
    ));
    assert_eq!(completion.connection_reuse, UpstreamConnectionReuse::Close);

    let (released, _released_cancellation, released_completion) =
        exchange_request(&backend, "/released", Method::GET, HeaderMap::new(), []);
    let released = pool
        .send_exchange(&backend, released)
        .await
        .expect("exchange after tunnel cleanup");
    let frames = collect_exchange_body(released.body).await;
    assert!(matches!(
        frames.as_slice(),
        [UpstreamBodyFrame::Data(body)] if body.as_ref() == b"ok"
    ));
    assert_completed(released_completion.await.expect("released completion"));
}
