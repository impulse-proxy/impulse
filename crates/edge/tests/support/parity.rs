#![allow(dead_code)]

use std::{collections::HashMap, convert::Infallible, net::SocketAddr};

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, body::Incoming};
use impulse_config::config::{Backend, Config, Upstream, UpstreamTls};

use super::request_path::{H3RequestSpec, H3Response, QuicRequestPathHarness};

#[derive(Clone, Copy)]
pub struct ParityRequestSpec<'a> {
    pub method: &'a str,
    pub authority: &'a str,
    pub path: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: Option<&'a [u8]>,
    pub user_agent: &'a str,
    pub selected_response_headers: &'a [&'a str],
}

impl<'a> ParityRequestSpec<'a> {
    pub fn get(authority: &'a str, path: &'a str) -> Self {
        Self {
            method: "GET",
            authority,
            path,
            headers: &[],
            body: None,
            user_agent: "impulse-protocol-parity-test",
            selected_response_headers: &[],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParityResponseSnapshot {
    pub status: u16,
    pub body: Vec<u8>,
    pub selected_headers: Vec<(String, String)>,
    pub trailers: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParityObservation {
    pub response: ParityResponseSnapshot,
}

pub struct ProtocolParityHarness {
    inner: QuicRequestPathHarness,
}

impl ProtocolParityHarness {
    pub fn new() -> Self {
        Self {
            inner: QuicRequestPathHarness::new(),
        }
    }

    pub fn make_config(&self, upstreams: HashMap<String, Upstream>) -> Config {
        self.inner.make_config(upstreams)
    }

    pub fn start_listener(&mut self, config: Config) -> Result<SocketAddr, String> {
        self.inner.start_listener(config)
    }

    pub fn start_h1_backend<F, Fut>(&mut self, handler: F) -> SocketAddr
    where
        F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<Response<Full<Bytes>>, Infallible>>
            + Send
            + 'static,
    {
        self.inner.start_h1_backend(handler)
    }

    pub fn start_h1_static_backend(&mut self, body: &'static [u8]) -> SocketAddr {
        self.inner.start_h1_static_backend(body)
    }

    pub fn run_quic(&self, request: ParityRequestSpec<'_>) -> Result<ParityObservation, String> {
        let response = self.inner.run_request(H3RequestSpec {
            method: request.method,
            authority: request.authority,
            path: request.path,
            headers: request.headers,
            body: request.body,
            user_agent: request.user_agent,
        })?;
        Ok(ParityObservation {
            response: snapshot_h3_response(response, request.selected_response_headers),
        })
    }

    pub fn cert_path(&self) -> &str {
        &self.inner.tls.cert_path
    }

    pub fn metrics_text(&self) -> Option<String> {
        self.inner.metrics_text()
    }
}

impl Default for ProtocolParityHarness {
    fn default() -> Self {
        Self::new()
    }
}

fn snapshot_h3_response(
    response: H3Response,
    selected_response_headers: &[&str],
) -> ParityResponseSnapshot {
    ParityResponseSnapshot {
        status: response.status,
        body: response.body,
        selected_headers: select_headers(response.headers, selected_response_headers),
        trailers: sorted_headers(response.trailers),
    }
}

fn select_headers(
    headers: Vec<(String, String)>,
    selected_response_headers: &[&str],
) -> Vec<(String, String)> {
    let mut selected = headers
        .into_iter()
        .filter(|(name, _)| {
            selected_response_headers
                .iter()
                .any(|selected| name.eq_ignore_ascii_case(selected))
        })
        .collect::<Vec<_>>();
    selected.sort_by(|left, right| {
        left.0
            .to_ascii_lowercase()
            .cmp(&right.0.to_ascii_lowercase())
            .then_with(|| left.1.cmp(&right.1))
    });
    selected
}

fn sorted_headers(mut headers: Vec<(String, String)>) -> Vec<(String, String)> {
    headers.sort_by(|left, right| {
        left.0
            .to_ascii_lowercase()
            .cmp(&right.0.to_ascii_lowercase())
            .then_with(|| left.1.cmp(&right.1))
    });
    headers
}

pub fn make_upstream(
    path_prefix: &str,
    backends: Vec<Backend>,
    tls: Option<UpstreamTls>,
    lb_type: &str,
) -> Upstream {
    super::request_path::make_upstream(path_prefix, backends, tls, lb_type)
}

pub fn make_backend(id: &str, address: impl Into<String>) -> Backend {
    super::request_path::make_backend(id, address)
}
