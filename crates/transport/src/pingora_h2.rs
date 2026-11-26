use std::sync::Arc;

use hyper::http::Version;
use impulse_errors::{ProxyError, RequestFailure};
use impulse_observability::Metrics;
use pingora_core::{
    Error, InternalError, Result,
    connectors::http::{Connector as HttpConnector, v2::Connector},
    protocols::http::{client::HttpSession as PingoraHttpSession, v2::client::Http2Session},
    upstreams::peer::{ALPN, HttpPeer},
};
use pingora_http::RequestHeader;
use tokio::sync::{RwLock, mpsc};

use crate::{
    PingoraUpstreamConnectionIdentity, UpstreamProtocol,
    exchange::{UpstreamExchangeLifecycle, upstream_response_body_channel},
    http3::{
        UpstreamBody, UpstreamBodyFrame, UpstreamExchangeResponse, UpstreamRequestHead,
        UpstreamResponseHead,
    },
    pingora_failure::classify_pingora_h2_error,
};

pub(crate) fn translate_pingora_h2_request_header(
    head: &UpstreamRequestHead,
) -> Result<Box<RequestHeader>> {
    let target = head.uri.to_string();
    let mut translated = RequestHeader::build_no_case(
        head.method.clone(),
        target.as_bytes(),
        Some(head.headers.len()),
    )?;
    translated.set_version(Version::HTTP_2);
    for (name, value) in &head.headers {
        translated.append_header(name.clone(), value.clone())?;
    }
    Ok(Box::new(translated))
}

pub(crate) struct PingoraH2UpstreamSession {
    connector: PingoraH2Connector,
    peer: HttpPeer,
    session: Option<Http2Session>,
    reused: bool,
    state: PingoraH2ExchangeState,
}

enum PingoraH2Connector {
    Dedicated(Arc<Connector>),
    Negotiated(Arc<HttpConnector>),
}

impl PingoraH2Connector {
    async fn release(
        &self,
        session: Http2Session,
        peer: &HttpPeer,
        idle_timeout: Option<std::time::Duration>,
    ) {
        match self {
            Self::Dedicated(connector) => {
                connector.release_http_session(session, peer, idle_timeout);
            }
            Self::Negotiated(connector) => {
                connector
                    .release_http_session(PingoraHttpSession::H2(session), peer, idle_timeout)
                    .await;
            }
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PingoraH2ExchangeState {
    Acquired,
    RequestComplete,
    ResponseComplete,
    Closed,
}

impl PingoraH2UpstreamSession {
    pub(crate) fn from_negotiated(
        connector: Arc<HttpConnector>,
        peer: HttpPeer,
        session: Http2Session,
        reused: bool,
        metrics: &Metrics,
    ) -> Self {
        metrics
            .ingress_observations()
            .record_pingora_h2_stream_capacity(session.conn.free_stream_slots());
        Self {
            connector: PingoraH2Connector::Negotiated(connector),
            peer,
            session: Some(session),
            reused,
            state: PingoraH2ExchangeState::Acquired,
        }
    }

    pub async fn acquire(
        connector: Arc<Connector>,
        mut peer: HttpPeer,
        identity: &PingoraUpstreamConnectionIdentity,
        acquire_lock: Arc<RwLock<()>>,
        metrics: &Metrics,
    ) -> Result<Self> {
        if identity.protocol != UpstreamProtocol::Http2 {
            return Err(Error::explain(
                InternalError,
                "HTTP/2 session acquisition requires an HTTP/2 connection identity",
            ));
        }
        peer.options.alpn = ALPN::H2;
        peer.group_key = identity.pool_key();
        let reused_session = {
            let _reuse_guard = acquire_lock.read().await;
            connector.reused_http_session(&peer).await?
        };
        let (mut session, reused) = if let Some(session) = reused_session {
            (PingoraHttpSession::H2(session), true)
        } else {
            let _connect_guard = acquire_lock.write().await;
            if let Some(session) = connector.reused_http_session(&peer).await? {
                (PingoraHttpSession::H2(session), true)
            } else {
                metrics.ingress_observations().inc_pingora_pool_saturation();
                (connector.new_http_session::<_, ()>(&peer).await?, false)
            }
        };
        session.set_read_timeout(peer.options.read_timeout);
        session.set_write_timeout(peer.options.write_timeout);
        let session = match session {
            PingoraHttpSession::H2(session) => session,
            mut session => {
                session.shutdown().await;
                return Err(Error::explain(
                    InternalError,
                    "Pingora returned a non-HTTP/2 upstream session",
                ));
            }
        };
        metrics
            .ingress_observations()
            .record_pingora_h2_stream_capacity(session.conn.free_stream_slots());
        Ok(Self {
            connector: PingoraH2Connector::Dedicated(connector),
            peer,
            session: Some(session),
            reused,
            state: PingoraH2ExchangeState::Acquired,
        })
    }

    pub fn session(&self) -> &Http2Session {
        let Some(session) = self.session.as_ref() else {
            unreachable!("Pingora H2 session ownership already released");
        };
        session
    }

    pub fn session_mut(&mut self) -> &mut Http2Session {
        let Some(session) = self.session.as_mut() else {
            unreachable!("Pingora H2 session ownership already released");
        };
        session
    }

    pub async fn write_request(
        &mut self,
        head: &UpstreamRequestHead,
        mut body: UpstreamBody,
    ) -> Result<(), ProxyError> {
        if self.state != PingoraH2ExchangeState::Acquired {
            self.close().await;
            return Err(ProxyError::RequestProtocol(
                RequestFailure::Http2RequestAlreadyWritten,
            ));
        }
        let header = match translate_pingora_h2_request_header(head) {
            Ok(header) => header,
            Err(error) => {
                self.mark_connection_draining_on_goaway(&error);
                self.close().await;
                return Err(classify_pingora_h2_error(&error, self.reused));
            }
        };
        if let Err(error) = self.session_mut().write_request_header(header, false) {
            self.mark_connection_draining_on_goaway(&error);
            self.close().await;
            return Err(classify_pingora_h2_error(&error, self.reused));
        }

        let mut ended = false;
        while let Some(frame) = body.recv().await {
            if ended {
                self.close().await;
                return Err(ProxyError::RequestProtocol(
                    RequestFailure::Http2FramesAfterTrailers,
                ));
            }
            match frame {
                Ok(UpstreamBodyFrame::Data(data)) if data.is_empty() => {}
                Ok(UpstreamBodyFrame::Data(data)) => {
                    if let Err(error) = self.session_mut().write_request_body(data, false).await {
                        self.mark_connection_draining_on_goaway(&error);
                        self.close().await;
                        return Err(classify_pingora_h2_error(&error, self.reused));
                    }
                }
                Ok(UpstreamBodyFrame::Trailers(trailers)) => {
                    let Some(mut writer) = self.session_mut().take_request_body_writer() else {
                        self.close().await;
                        return Err(ProxyError::RequestProtocol(
                            RequestFailure::Http2RequestBodyAlreadyComplete,
                        ));
                    };
                    if let Err(error) = writer.send_trailers(trailers) {
                        if error.is_go_away() {
                            self.session().conn.mark_shutdown();
                        }
                        self.close().await;
                        return Err(ProxyError::Protocol(error.to_string()));
                    }
                    ended = true;
                }
                Err(error) => {
                    self.close().await;
                    return Err(error);
                }
            }
        }

        if !ended && let Err(error) = self.session_mut().finish_request_body() {
            self.mark_connection_draining_on_goaway(&error);
            self.close().await;
            return Err(classify_pingora_h2_error(&error, self.reused));
        }
        self.state = PingoraH2ExchangeState::RequestComplete;
        Ok(())
    }

    pub async fn read_response(
        mut self,
        lifecycle: UpstreamExchangeLifecycle,
    ) -> Result<UpstreamExchangeResponse, ProxyError> {
        if self.state != PingoraH2ExchangeState::RequestComplete {
            self.close().await;
            let detail = "Pingora HTTP/2 response read before request completion".to_string();
            return Err(ProxyError::Protocol(detail));
        }
        let response_header = self.session_mut().read_response_header().await;
        if let Err(error) = response_header {
            let classified = classify_pingora_h2_error(&error, self.reused);
            self.mark_connection_draining_on_goaway(&error);
            self.close().await;
            return Err(classified);
        }

        let Some(response) = self.session().response_header() else {
            let detail =
                "Pingora HTTP/2 response header is unavailable after reading it".to_string();
            self.close().await;
            return Err(ProxyError::Protocol(detail));
        };
        let head = UpstreamResponseHead {
            status: response.status,
            version: response.version,
            headers: response.headers.clone(),
        };
        let (frames, body) = upstream_response_body_channel();
        tokio::spawn(pump_pingora_h2_response(self, frames, lifecycle));
        Ok(UpstreamExchangeResponse {
            head,
            body,
            upgrade: None,
        })
    }

    pub async fn release(mut self) {
        if self.state != PingoraH2ExchangeState::ResponseComplete {
            self.close().await;
            return;
        }
        let Some(session) = self.session.take() else {
            return;
        };
        let reusable = !session.conn.is_closed() && !session.conn.is_shutting_down();
        if !reusable {
            session.conn.mark_shutdown();
        }
        self.connector
            .release(session, &self.peer, self.peer.options.idle_timeout)
            .await;
    }

    pub async fn shutdown(mut self) {
        self.close().await;
    }

    fn mark_connection_draining_on_goaway(&self, error: &Error) {
        if error
            .root_cause()
            .downcast_ref::<h2::Error>()
            .is_some_and(h2::Error::is_go_away)
        {
            self.session().conn.mark_shutdown();
        }
    }

    async fn close(&mut self) {
        self.state = PingoraH2ExchangeState::Closed;
        if let Some(mut session) = self.session.take() {
            session.shutdown();
            self.connector
                .release(session, &self.peer, self.peer.options.idle_timeout)
                .await;
        }
    }
}

async fn fail_pingora_h2_response(
    session: PingoraH2UpstreamSession,
    frames: &mpsc::Sender<Result<UpstreamBodyFrame, ProxyError>>,
    _lifecycle: UpstreamExchangeLifecycle,
    error: Box<Error>,
) {
    let frame_error = classify_pingora_h2_error(&error, session.reused);
    session.mark_connection_draining_on_goaway(&error);
    let _ = frames.send(Err(frame_error)).await;
    session.shutdown().await;
}

async fn pump_pingora_h2_response(
    mut session: PingoraH2UpstreamSession,
    frames: mpsc::Sender<Result<UpstreamBodyFrame, ProxyError>>,
    lifecycle: UpstreamExchangeLifecycle,
) {
    loop {
        match session.session_mut().read_response_body().await {
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
            Ok(None) => break,
            Err(error) => {
                fail_pingora_h2_response(session, &frames, lifecycle, error).await;
                return;
            }
        }
    }

    let trailers = session.session_mut().read_trailers().await;
    match trailers {
        Ok(Some(headers)) => {
            if frames
                .send(Ok(UpstreamBodyFrame::Trailers(headers)))
                .await
                .is_err()
            {
                session.shutdown().await;
                return;
            }
        }
        Ok(None) => {}
        Err(error) => {
            fail_pingora_h2_response(session, &frames, lifecycle, error).await;
            return;
        }
    }

    match session.session_mut().check_response_end_or_error() {
        Ok(true) => {}
        Ok(false) => {
            session.shutdown().await;
            return;
        }
        Err(error) => {
            fail_pingora_h2_response(session, &frames, lifecycle, error).await;
            return;
        }
    }

    session.state = PingoraH2ExchangeState::ResponseComplete;
    session.release().await;
}
