use super::*;

impl Http3Service {
    pub(super) fn handle_metrics_request_for<B>(
        req: &::http::Request<B>,
        metrics_path: &str,
        metrics: Arc<Metrics>,
    ) -> Response<Full<Bytes>> {
        if *req.method() != ::http::Method::GET {
            return Self::metrics_method_not_allowed_response();
        }

        if req.uri().path() != metrics_path {
            return Self::metrics_not_found_response();
        }

        Self::metrics_ok_response(metrics.render_prometheus())
    }

    pub(super) fn handle_metrics_request(
        req: Request<Incoming>,
        metrics_path: &str,
        metrics: Arc<Metrics>,
    ) -> Response<Full<Bytes>> {
        Self::handle_metrics_request_for(&req, metrics_path, metrics)
    }

    fn metrics_not_found_response() -> Response<Full<Bytes>> {
        match Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("content-type", "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from_static(b"not found\n")))
        {
            Ok(resp) => resp,
            Err(_) => Response::new(Full::new(Bytes::from_static(b"not found\n"))),
        }
    }

    fn metrics_method_not_allowed_response() -> Response<Full<Bytes>> {
        match Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header("allow", "GET")
            .header("content-type", "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from_static(b"method not allowed\n")))
        {
            Ok(resp) => resp,
            Err(_) => Response::new(Full::new(Bytes::from_static(b"method not allowed\n"))),
        }
    }

    fn metrics_ok_response(body: String) -> Response<Full<Bytes>> {
        match Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; version=0.0.4")
            .body(Full::new(Bytes::from(body)))
        {
            Ok(resp) => resp,
            Err(_) => Response::new(Full::new(Bytes::from_static(b"failed to render metrics\n"))),
        }
    }
}

#[cfg(test)]
mod tests {
    // Domain anchor: metrics endpoint path and response handling contract tests
    // live here so they stay local to the HTTP handling surface rather than
    // drifting into listener/control-plane integration coverage.
    use ::http::{Method, Request, header};
    use http_body_util::BodyExt;

    use super::*;

    fn metrics_request(method: Method, path: &str) -> Request<()> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(())
            .expect("metrics request")
    }

    async fn full_body_bytes(response: Response<Full<Bytes>>) -> Bytes {
        response
            .into_body()
            .collect()
            .await
            .expect("collect metrics body")
            .to_bytes()
    }

    #[tokio::test]
    async fn metrics_endpoint_accepts_configured_metrics_path_with_stable_prometheus_response() {
        let response = Http3Service::handle_metrics_request_for(
            &metrics_request(Method::GET, "/metrics"),
            "/metrics",
            Arc::new(Metrics::default()),
        );

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static(
                "text/plain; version=0.0.4"
            ))
        );

        let body = String::from_utf8(full_body_bytes(response).await.to_vec())
            .expect("metrics response utf-8");
        assert!(
            body.contains("# HELP impulse_requests_total Total requests seen by impulse.\n"),
            "metrics body should expose prometheus text for impulse_requests_total"
        );
        assert!(
            body.contains("impulse_requests_total 0\n"),
            "metrics body should include the requests counter sample"
        );
    }

    #[tokio::test]
    async fn metrics_endpoint_rejects_unsupported_paths_with_stable_not_found_shape() {
        let response = Http3Service::handle_metrics_request_for(
            &metrics_request(Method::GET, "/metrics-missing"),
            "/metrics",
            Arc::new(Metrics::default()),
        );

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static(
                "text/plain; charset=utf-8"
            ))
        );
        assert_eq!(
            full_body_bytes(response).await,
            Bytes::from_static(b"not found\n")
        );
    }

    #[tokio::test]
    async fn metrics_endpoint_rejects_unsupported_methods_without_service_loop_coupling() {
        let response = Http3Service::handle_metrics_request_for(
            &metrics_request(Method::POST, "/metrics"),
            "/metrics",
            Arc::new(Metrics::default()),
        );

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            response.headers().get(header::ALLOW),
            Some(&header::HeaderValue::from_static("GET"))
        );
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static(
                "text/plain; charset=utf-8"
            ))
        );
        assert_eq!(
            full_body_bytes(response).await,
            Bytes::from_static(b"method not allowed\n")
        );
    }
}
