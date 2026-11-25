use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use hyper::{Method, http::Version};
use impulse_contracts::TunnelMode;
use impulse_errors::{ProxyError, RequestFailure};
use pingora_core::{
    Error, InternalError, Result,
    connectors::http::Connector,
    protocols::{
        Stream,
        http::{client::HttpSession as PingoraHttpSession, v1::client::HttpSession},
    },
    upstreams::peer::HttpPeer,
};
use pingora_http::RequestHeader;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, oneshot},
};

use crate::{
    PingoraUpstreamConnectionIdentity, UpstreamProtocol,
    exchange::{UpstreamExchangeLifecycle, upstream_response_body_channel},
    http3::{
        UpstreamBody, UpstreamBodyFrame, UpstreamExchangeResponse, UpstreamRequestHead,
        UpstreamResponseHead, UpstreamTunnel, UpstreamUpgrade,
    },
    pingora_failure::classify_pingora_h1_error,
};

pub(crate) fn translate_pingora_h1_request_header(
    head: &UpstreamRequestHead,
) -> Result<Box<RequestHeader>> {
    let target = if head.method == Method::CONNECT {
        head.uri
            .authority()
            .map(|authority| authority.as_str())
            .or_else(|| head.uri.path_and_query().map(|target| target.as_str()))
            .unwrap_or_default()
    } else {
        head.uri
            .path_and_query()
            .map(|target| target.as_str())
            .unwrap_or("/")
    };
    let mut translated = RequestHeader::build(
        head.method.clone(),
        target.as_bytes(),
        Some(head.headers.len()),
    )?;
    translated.set_version(Version::HTTP_11);
    for (name, value) in &head.headers {
        translated.append_header(name.clone(), value.clone())?;
    }
    Ok(Box::new(translated))
}
pub(crate) struct PingoraH1UpstreamSession {
    connector: Arc<Connector>,
    peer: HttpPeer,
    session: Option<HttpSession>,
    state: PingoraH1ExchangeState,
    connect_request: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PingoraH1ExchangeState {
    Acquired,
    RequestComplete,
    ResponseComplete,
    Closed,
}

impl PingoraH1UpstreamSession {
    pub(crate) fn from_negotiated(
        connector: Arc<Connector>,
        peer: HttpPeer,
        session: HttpSession,
    ) -> Self {
        Self {
            connector,
            peer,
            session: Some(session),
            state: PingoraH1ExchangeState::Acquired,
            connect_request: false,
        }
    }

    pub async fn acquire(
        connector: Arc<Connector>,
        mut peer: HttpPeer,
        identity: &PingoraUpstreamConnectionIdentity,
    ) -> Result<Self> {
        if identity.protocol != UpstreamProtocol::Http1 {
            return Err(Error::explain(
                InternalError,
                "HTTP/1 session acquisition requires an HTTP/1 connection identity",
            ));
        }
        peer.options.alpn = pingora_core::upstreams::peer::ALPN::H1;
        peer.group_key = identity.pool_key();
        let (mut session, _) = connector.get_http_session(&peer).await?;
        session.set_read_timeout(peer.options.read_timeout);
        session.set_write_timeout(peer.options.write_timeout);
        let session = match session {
            PingoraHttpSession::H1(session) => session,
            mut session => {
                session.shutdown().await;
                return Err(Error::explain(
                    InternalError,
                    "Pingora returned a non-HTTP/1 upstream session",
                ));
            }
        };

        Ok(Self::from_negotiated(connector, peer, session))
    }

    pub fn session(&self) -> &HttpSession {
        let Some(session) = self.session.as_ref() else {
            unreachable!("Pingora H1 session ownership already released");
        };
        session
    }

    pub fn session_mut(&mut self) -> &mut HttpSession {
        let Some(session) = self.session.as_mut() else {
            unreachable!("Pingora H1 session ownership already released");
        };
        session
    }

    pub async fn write_request(
        &mut self,
        head: &UpstreamRequestHead,
        mut body: UpstreamBody,
    ) -> Result<(), ProxyError> {
        if self.state != PingoraH1ExchangeState::Acquired {
            self.close().await;
            return Err(ProxyError::RequestProtocol(
                RequestFailure::Http1RequestAlreadyWritten,
            ));
        }
        let header = match translate_pingora_h1_request_header(head) {
            Ok(header) => header,
            Err(error) => {
                self.close().await;
                return Err(classify_pingora_h1_error(&error));
            }
        };
        if let Err(error) = self.session_mut().write_request_header(header).await {
            self.close().await;
            return Err(classify_pingora_h1_error(&error));
        }

        while let Some(frame) = body.recv().await {
            match frame {
                Ok(UpstreamBodyFrame::Data(data)) if data.is_empty() => {}
                Ok(UpstreamBodyFrame::Data(data)) => {
                    match self.session_mut().write_body(&data).await {
                        Ok(Some(written)) if written == data.len() => {}
                        Ok(Some(written)) => {
                            self.close().await;
                            return Err(ProxyError::Transport(format!(
                                "Pingora wrote {written} of {} request body bytes",
                                data.len()
                            )));
                        }
                        Ok(None) => {
                            self.close().await;
                            return Err(ProxyError::RequestProtocol(
                                RequestFailure::RequestBodyExceedsDeclaredFraming,
                            ));
                        }
                        Err(error) => {
                            self.close().await;
                            return Err(classify_pingora_h1_error(&error));
                        }
                    }
                }
                Ok(UpstreamBodyFrame::Trailers(_)) => {
                    self.close().await;
                    return Err(ProxyError::RequestProtocol(
                        RequestFailure::Http1RequestTrailersUnsupported,
                    ));
                }
                Err(error) => {
                    self.close().await;
                    return Err(error);
                }
            }
        }

        if let Err(error) = self.session_mut().finish_body().await {
            self.close().await;
            return Err(classify_pingora_h1_error(&error));
        }
        self.connect_request = head.method == Method::CONNECT;
        self.state = PingoraH1ExchangeState::RequestComplete;
        Ok(())
    }

    pub async fn read_response(
        mut self,
        lifecycle: UpstreamExchangeLifecycle,
    ) -> Result<UpstreamExchangeResponse, ProxyError> {
        if self.state != PingoraH1ExchangeState::RequestComplete {
            self.close().await;
            let detail = "Pingora HTTP/1 response read before request completion".to_string();
            return Err(ProxyError::Protocol(detail));
        }
        loop {
            if let Err(error) = self.session_mut().read_response().await {
                let error = classify_pingora_h1_error(&error);
                self.shutdown().await;
                return Err(error);
            }
            let Some(status) = self.session().get_status() else {
                let detail =
                    "Pingora HTTP/1 response status is unavailable after reading its header"
                        .to_string();
                self.shutdown().await;
                return Err(ProxyError::Protocol(detail));
            };
            if !status.is_informational() || status == hyper::StatusCode::SWITCHING_PROTOCOLS {
                break;
            }
        }

        let Some(response) = self.session().resp_header() else {
            let detail =
                "Pingora HTTP/1 response header is unavailable after reading it".to_string();
            self.shutdown().await;
            return Err(ProxyError::Protocol(detail));
        };
        let head = UpstreamResponseHead {
            status: response.status,
            version: response.version,
            headers: response.headers.clone(),
        };
        let tunnel_response =
            self.session().was_upgraded() || (self.connect_request && head.status.is_success());
        if tunnel_response {
            let tunnel_mode = if self.connect_request {
                TunnelMode::Connect
            } else {
                TunnelMode::Websocket
            };
            let (frames, body) = upstream_response_body_channel();
            drop(frames);
            let (tunnel_sender, tunnel) = oneshot::channel();
            let _ = tunnel_sender.send(Ok(UpstreamTunnel::new(
                tunnel_mode,
                Box::new(self.into_tunnel()),
                lifecycle,
            )));
            return Ok(UpstreamExchangeResponse {
                head,
                body,
                upgrade: Some(UpstreamUpgrade { tunnel }),
            });
        }
        if head.headers.contains_key(hyper::header::TRAILER) {
            self.shutdown().await;
            let detail = "Pingora 0.9 cannot expose HTTP/1 response trailers".to_string();
            return Err(ProxyError::Protocol(detail));
        }
        let (frames, body) = upstream_response_body_channel();
        tokio::spawn(pump_pingora_h1_response(self, frames, lifecycle));
        Ok(UpstreamExchangeResponse {
            head,
            body,
            upgrade: None,
        })
    }

    pub async fn release(mut self) {
        if self.state != PingoraH1ExchangeState::ResponseComplete {
            self.close().await;
            return;
        }
        let Some(mut session) = self.session.take() else {
            return;
        };
        if !session.is_body_done() {
            session.shutdown().await;
            return;
        }
        session.respect_keepalive();
        self.connector
            .release_http_session(
                PingoraHttpSession::H1(session),
                &self.peer,
                self.peer.options.idle_timeout,
            )
            .await;
    }

    pub async fn shutdown(mut self) {
        self.close().await;
    }

    async fn close(&mut self) {
        self.state = PingoraH1ExchangeState::Closed;
        if let Some(mut session) = self.session.take() {
            session.shutdown().await;
        }
    }

    fn into_tunnel(mut self) -> PingoraH1TunnelLease {
        let Some(session) = self.session.take() else {
            unreachable!("Pingora H1 session ownership already released");
        };
        let stream = session.into_inner();
        PingoraH1TunnelLease {
            stream,
            _connector: self.connector,
        }
    }
}
struct PingoraH1TunnelLease {
    stream: Stream,
    _connector: Arc<Connector>,
}

impl AsyncRead for PingoraH1TunnelLease {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(self.stream.as_mut()).poll_read(cx, buf)
    }
}

impl AsyncWrite for PingoraH1TunnelLease {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(self.stream.as_mut()).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(self.stream.as_mut()).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(self.stream.as_mut()).poll_shutdown(cx)
    }
}

async fn pump_pingora_h1_response(
    mut session: PingoraH1UpstreamSession,
    frames: mpsc::Sender<Result<UpstreamBodyFrame, ProxyError>>,
    _lifecycle: UpstreamExchangeLifecycle,
) {
    loop {
        match session.session_mut().read_body_bytes().await {
            Ok(Some(data)) => {
                if frames
                    .send(Ok(UpstreamBodyFrame::Data(data)))
                    .await
                    .is_err()
                {
                    session.shutdown().await;
                    return;
                }
            }
            Ok(None) => {
                session.state = PingoraH1ExchangeState::ResponseComplete;
                session.release().await;
                return;
            }
            Err(error) => {
                let frame_error = classify_pingora_h1_error(&error);
                let _ = frames.send(Err(frame_error)).await;
                session.shutdown().await;
                return;
            }
        }
    }
}
