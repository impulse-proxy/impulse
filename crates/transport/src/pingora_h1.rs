use hyper::{Method, http::Version};
use impulse_config::runtime::RuntimeBackendTransportKind;
use impulse_errors::ProxyError;
use pingora_core::{
    Error, InternalError, Result,
    protocols::http::{client::HttpSession as PingoraHttpSession, v1::client::HttpSession},
    upstreams::peer::HttpPeer,
};
use pingora_http::RequestHeader;
use tokio::sync::mpsc;

use crate::{
    PingoraPoolLease, PingoraUpstreamConnectionIdentity, UpstreamBodyFrame, UpstreamCancellation,
    UpstreamConnectionReuse, UpstreamExchangeCompletion, UpstreamExchangeLifecycle,
    UpstreamExchangeOutcome, UpstreamExchangeResponse, UpstreamRequestBody, UpstreamRequestHead,
    UpstreamResponseHead, classify_pingora_h1_error, exchange::upstream_response_body_channel,
};

pub fn translate_pingora_h1_request_header(
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

pub struct PingoraH1UpstreamSession {
    pool: PingoraPoolLease,
    peer: HttpPeer,
    session: Option<HttpSession>,
    reused: bool,
    state: PingoraH1ExchangeState,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PingoraH1ExchangeState {
    Acquired,
    RequestComplete,
    ResponseComplete,
    Closed,
}

impl PingoraH1UpstreamSession {
    pub async fn acquire(
        pool: PingoraPoolLease,
        mut peer: HttpPeer,
        identity: &PingoraUpstreamConnectionIdentity,
    ) -> Result<Self> {
        if identity.protocol != RuntimeBackendTransportKind::Http1 {
            return Err(Error::explain(
                InternalError,
                "HTTP/1 session acquisition requires an HTTP/1 connection identity",
            ));
        }
        if pool.generation() != identity.generation {
            return Err(Error::explain(
                InternalError,
                "Pingora pool generation does not match the upstream connection identity",
            ));
        }

        peer.options.alpn = pingora_core::upstreams::peer::ALPN::H1;
        peer.group_key = identity.pool_key();
        let (session, reused) = pool.connector().get_http_session(&peer).await?;
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

        Ok(Self {
            pool,
            peer,
            session: Some(session),
            reused,
            state: PingoraH1ExchangeState::Acquired,
        })
    }

    pub fn generation(&self) -> u64 {
        self.pool.generation()
    }

    pub fn reused(&self) -> bool {
        self.reused
    }

    pub fn session(&self) -> &HttpSession {
        self.session
            .as_ref()
            .expect("Pingora H1 session ownership already released")
    }

    pub fn session_mut(&mut self) -> &mut HttpSession {
        self.session
            .as_mut()
            .expect("Pingora H1 session ownership already released")
    }

    pub async fn write_request(
        &mut self,
        head: &UpstreamRequestHead,
        mut body: UpstreamRequestBody,
    ) -> Result<(), ProxyError> {
        if self.state != PingoraH1ExchangeState::Acquired {
            self.close().await;
            return Err(ProxyError::Protocol(
                "Pingora HTTP/1 request has already been written".to_string(),
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

        while let Some(frame) = body.frames.recv().await {
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
                            return Err(ProxyError::Protocol(
                                "request body exceeds its declared framing".to_string(),
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
                    return Err(ProxyError::Protocol(
                        "Pingora 0.9 cannot forward HTTP/1 request trailers".to_string(),
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
            finish_pingora_h1_exchange(
                lifecycle,
                UpstreamExchangeOutcome::Failed(ProxyError::Protocol(detail.clone())),
                UpstreamConnectionReuse::Close,
            );
            return Err(ProxyError::Protocol(detail));
        }
        loop {
            if let Err(error) = self.session_mut().read_response().await {
                let outcome_error = classify_pingora_h1_error(&error);
                let return_error = classify_pingora_h1_error(&error);
                self.shutdown().await;
                finish_pingora_h1_exchange(
                    lifecycle,
                    UpstreamExchangeOutcome::Failed(outcome_error),
                    UpstreamConnectionReuse::Close,
                );
                return Err(return_error);
            }
            let status = self
                .session()
                .get_status()
                .expect("Pingora response status is available after reading its header");
            if !status.is_informational() || status == hyper::StatusCode::SWITCHING_PROTOCOLS {
                break;
            }
        }

        let response = self
            .session()
            .resp_header()
            .expect("Pingora response header is available after reading it");
        if response.headers.contains_key(hyper::header::TRAILER) {
            self.shutdown().await;
            let detail = "Pingora 0.9 cannot expose HTTP/1 response trailers".to_string();
            finish_pingora_h1_exchange(
                lifecycle,
                UpstreamExchangeOutcome::Failed(ProxyError::Protocol(detail.clone())),
                UpstreamConnectionReuse::Close,
            );
            return Err(ProxyError::Protocol(detail));
        }
        let head = UpstreamResponseHead {
            status: response.status,
            version: response.version,
            headers: response.headers.clone(),
        };
        let (frames, body) = upstream_response_body_channel();
        tokio::spawn(pump_pingora_h1_response(self, frames, lifecycle));
        Ok(UpstreamExchangeResponse {
            head,
            body,
            upgrade: None,
        })
    }

    pub async fn release(mut self) -> UpstreamConnectionReuse {
        if self.state != PingoraH1ExchangeState::ResponseComplete {
            self.close().await;
            return UpstreamConnectionReuse::Close;
        }
        let connection_reuse = if self.session().will_keepalive() {
            UpstreamConnectionReuse::Reuse
        } else {
            UpstreamConnectionReuse::Close
        };
        let session = self
            .session
            .take()
            .expect("Pingora H1 session ownership already released");
        self.pool
            .connector()
            .release_http_session(
                PingoraHttpSession::H1(session),
                &self.peer,
                self.peer.options.idle_timeout,
            )
            .await;
        connection_reuse
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
}

fn finish_pingora_h1_exchange(
    lifecycle: UpstreamExchangeLifecycle,
    outcome: UpstreamExchangeOutcome,
    connection_reuse: UpstreamConnectionReuse,
) {
    let _ = lifecycle.completion.send(UpstreamExchangeCompletion {
        outcome,
        connection_reuse,
    });
}

async fn send_pingora_h1_response_frame(
    frames: &mpsc::Sender<Result<UpstreamBodyFrame, ProxyError>>,
    frame: Result<UpstreamBodyFrame, ProxyError>,
    cancellation: &mut UpstreamCancellation,
    cancellation_open: &mut bool,
) -> bool {
    if !*cancellation_open {
        return frames.send(frame).await.is_ok();
    }
    tokio::select! {
        cancellation_result = &mut cancellation.signal => {
            if cancellation_result.is_ok() {
                false
            } else {
                *cancellation_open = false;
                frames.send(frame).await.is_ok()
            }
        }
        permit = frames.reserve() => match permit {
            Ok(permit) => {
                permit.send(frame);
                true
            }
            Err(_) => false,
        },
    }
}

async fn pump_pingora_h1_response(
    mut session: PingoraH1UpstreamSession,
    frames: mpsc::Sender<Result<UpstreamBodyFrame, ProxyError>>,
    mut lifecycle: UpstreamExchangeLifecycle,
) {
    let mut cancellation_open = true;
    loop {
        let next = if cancellation_open {
            tokio::select! {
                cancellation_result = &mut lifecycle.cancellation.signal => {
                    if cancellation_result.is_ok() {
                        session.shutdown().await;
                        finish_pingora_h1_exchange(
                            lifecycle,
                            UpstreamExchangeOutcome::Cancelled,
                            UpstreamConnectionReuse::Close,
                        );
                        return;
                    }
                    cancellation_open = false;
                    continue;
                }
                body = session.session_mut().read_body_bytes() => body,
            }
        } else {
            session.session_mut().read_body_bytes().await
        };

        match next {
            Ok(Some(data)) => {
                if !send_pingora_h1_response_frame(
                    &frames,
                    Ok(UpstreamBodyFrame::Data(data)),
                    &mut lifecycle.cancellation,
                    &mut cancellation_open,
                )
                .await
                {
                    session.shutdown().await;
                    finish_pingora_h1_exchange(
                        lifecycle,
                        UpstreamExchangeOutcome::Cancelled,
                        UpstreamConnectionReuse::Close,
                    );
                    return;
                }
            }
            Ok(None) => {
                session.state = PingoraH1ExchangeState::ResponseComplete;
                let connection_reuse = session.release().await;
                finish_pingora_h1_exchange(
                    lifecycle,
                    UpstreamExchangeOutcome::Completed,
                    connection_reuse,
                );
                return;
            }
            Err(error) => {
                let frame_error = classify_pingora_h1_error(&error);
                let outcome_error = classify_pingora_h1_error(&error);
                let delivered = send_pingora_h1_response_frame(
                    &frames,
                    Err(frame_error),
                    &mut lifecycle.cancellation,
                    &mut cancellation_open,
                )
                .await;
                session.shutdown().await;
                finish_pingora_h1_exchange(
                    lifecycle,
                    if delivered {
                        UpstreamExchangeOutcome::Failed(outcome_error)
                    } else {
                        UpstreamExchangeOutcome::Cancelled
                    },
                    UpstreamConnectionReuse::Close,
                );
                return;
            }
        }
    }
}
