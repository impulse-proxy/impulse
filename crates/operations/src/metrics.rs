use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::Full;
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;

pub type MetricsResponse = Response<Full<Bytes>>;

pub trait MetricsSource: Clone + Send + Sync + 'static {
    fn render_prometheus(&self) -> String;
}

#[derive(Debug)]
pub enum MetricsConnectionError {
    TlsHandshake(std::io::Error),
    TlsHandshakeTimeout,
    Http(hyper::Error),
    ConnectionTimeout,
}

#[derive(Clone)]
pub struct MetricsHttpService<S> {
    path: String,
    source: S,
}

impl<S: MetricsSource> MetricsHttpService<S> {
    pub fn new(path: String, source: S) -> Self {
        Self { path, source }
    }

    pub fn handle_request<B>(&self, request: &Request<B>) -> MetricsResponse {
        if *request.method() != Method::GET {
            return response(
                StatusCode::METHOD_NOT_ALLOWED,
                &[
                    (header::ALLOW, "GET"),
                    (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                ],
                Bytes::from_static(b"method not allowed\n"),
                b"method not allowed\n",
            );
        }
        if request.uri().path() != self.path {
            return response(
                StatusCode::NOT_FOUND,
                &[(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                Bytes::from_static(b"not found\n"),
                b"not found\n",
            );
        }
        response(
            StatusCode::OK,
            &[(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
            Bytes::from(self.source.render_prometheus()),
            b"failed to render metrics\n",
        )
    }

    pub async fn serve(
        self,
        stream: tokio::net::TcpStream,
        server_config: Option<Arc<ServerConfig>>,
        timeout: Duration,
    ) -> Result<(), MetricsConnectionError> {
        if let Some(server_config) = server_config {
            let accept = TlsAcceptor::from(server_config).accept(stream);
            let stream = match tokio::time::timeout(timeout, accept).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => return Err(MetricsConnectionError::TlsHandshake(error)),
                Err(_) => return Err(MetricsConnectionError::TlsHandshakeTimeout),
            };
            self.serve_io(stream, timeout).await
        } else {
            self.serve_io(stream, timeout).await
        }
    }

    async fn serve_io<I>(self, stream: I, timeout: Duration) -> Result<(), MetricsConnectionError>
    where
        I: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let service = service_fn(move |request: Request<Incoming>| {
            let response = self.handle_request(&request);
            async move { Ok::<_, hyper::Error>(response) }
        });
        let connection = http1::Builder::new().serve_connection(TokioIo::new(stream), service);
        match tokio::time::timeout(timeout, connection).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(MetricsConnectionError::Http(error)),
            Err(_) => Err(MetricsConnectionError::ConnectionTimeout),
        }
    }
}

fn response(
    status: StatusCode,
    headers: &[(header::HeaderName, &'static str)],
    body: Bytes,
    fallback: &'static [u8],
) -> MetricsResponse {
    let mut builder = Response::builder().status(status);
    for (name, value) in headers {
        builder = builder.header(name, *value);
    }
    builder
        .body(Full::new(body))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(fallback))))
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt;

    use super::*;

    #[derive(Clone)]
    struct TestMetricsSource;

    impl MetricsSource for TestMetricsSource {
        fn render_prometheus(&self) -> String {
            "impulse_requests_total 0\n".to_string()
        }
    }

    fn service() -> MetricsHttpService<TestMetricsSource> {
        MetricsHttpService::new("/metrics".to_string(), TestMetricsSource)
    }

    fn request(method: Method, path: &str) -> Request<()> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(())
            .expect("metrics request")
    }

    async fn body(response: MetricsResponse) -> Bytes {
        response
            .into_body()
            .collect()
            .await
            .expect("collect metrics body")
            .to_bytes()
    }

    #[tokio::test]
    async fn serves_prometheus_metrics_on_the_configured_path() {
        let response = service().handle_request(&request(Method::GET, "/metrics"));

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static(
                "text/plain; version=0.0.4"
            ))
        );
        assert_eq!(
            body(response).await,
            Bytes::from_static(b"impulse_requests_total 0\n")
        );
    }

    #[tokio::test]
    async fn rejects_unknown_metrics_paths() {
        let response = service().handle_request(&request(Method::GET, "/missing"));

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(body(response).await, Bytes::from_static(b"not found\n"));
    }

    #[tokio::test]
    async fn rejects_unsupported_metrics_methods() {
        let response = service().handle_request(&request(Method::POST, "/metrics"));

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            response.headers().get(header::ALLOW),
            Some(&header::HeaderValue::from_static("GET"))
        );
        assert_eq!(
            body(response).await,
            Bytes::from_static(b"method not allowed\n")
        );
    }
}
