use hyper::http::Version;
use impulse_errors::ProxyError;
use pingora_core::{
    Error, ErrorType, InternalError, Result,
    protocols::http::{client::HttpSession as PingoraHttpSession, v2::client::Http2Session},
    upstreams::peer::{ALPN, HttpPeer},
};
use pingora_http::RequestHeader;
use tokio::sync::mpsc;

use crate::{
    PingoraUpstreamConnectionIdentity, UpstreamBody, UpstreamBodyFrame, UpstreamCancellation,
    UpstreamConnectionReuse, UpstreamExchangeCompletion, UpstreamExchangeLifecycle,
    UpstreamExchangeOutcome, UpstreamExchangeResponse, UpstreamProtocol, UpstreamRequestHead,
    UpstreamResponseHead, exchange::upstream_response_body_channel,
    pingora_failure::classify_pingora_h2_error, pingora_pool::PingoraPoolLease,
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
    pool: PingoraPoolLease,
    peer: HttpPeer,
    session: Option<Http2Session>,
    reused: bool,
    state: PingoraH2ExchangeState,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PingoraH2ExchangeState {
    Acquired,
    RequestComplete,
    ResponseComplete,
    Closed,
}

impl PingoraH2UpstreamSession {
    pub async fn acquire(
        pool: PingoraPoolLease,
        mut peer: HttpPeer,
        identity: &PingoraUpstreamConnectionIdentity,
    ) -> Result<Self> {
        if identity.protocol != UpstreamProtocol::Http2 {
            return Err(Error::explain(
                InternalError,
                "HTTP/2 session acquisition requires an HTTP/2 connection identity",
            ));
        }
        if pool.generation() != identity.generation {
            return Err(Error::explain(
                InternalError,
                "Pingora pool generation does not match the upstream connection identity",
            ));
        }
        if pool.is_draining() {
            return Err(Error::explain(
                InternalError,
                "Pingora pool generation is draining",
            ));
        }

        peer.options.alpn = ALPN::H2;
        peer.group_key = identity.pool_key();
        let (mut session, reused) = pool.connector().get_http_session(&peer).await?;
        session.set_read_timeout(peer.options.read_timeout);
        session.set_write_timeout(peer.options.write_timeout);
        let mut session = match session {
            PingoraHttpSession::H2(session) => session,
            mut session => {
                session.shutdown().await;
                return Err(Error::explain(
                    InternalError,
                    "Pingora returned a non-HTTP/2 upstream session",
                ));
            }
        };
        if pool.is_draining() {
            session.shutdown();
            session.conn.mark_shutdown();
            pool.connector()
                .release_http_session(
                    PingoraHttpSession::H2(session),
                    &peer,
                    peer.options.idle_timeout,
                )
                .await;
            return Err(Error::explain(
                InternalError,
                "Pingora pool generation began draining during HTTP/2 session acquisition",
            ));
        }

        Ok(Self {
            pool,
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
            return Err(ProxyError::Protocol(
                "Pingora HTTP/2 request has already been written".to_string(),
            ));
        }
        let header = match translate_pingora_h2_request_header(head) {
            Ok(header) => header,
            Err(error) => {
                self.close().await;
                return Err(classify_pingora_h2_error(&error, self.reused));
            }
        };
        if let Err(error) = self.session_mut().write_request_header(header, false) {
            self.close().await;
            return Err(classify_pingora_h2_error(&error, self.reused));
        }

        let mut ended = false;
        while let Some(frame) = body.recv().await {
            if ended {
                self.close().await;
                return Err(ProxyError::Protocol(
                    "request body contains frames after HTTP/2 trailers".to_string(),
                ));
            }
            match frame {
                Ok(UpstreamBodyFrame::Data(data)) if data.is_empty() => {}
                Ok(UpstreamBodyFrame::Data(data)) => {
                    if let Err(error) = self.session_mut().write_request_body(data, false).await {
                        self.close().await;
                        return Err(classify_pingora_h2_error(&error, self.reused));
                    }
                }
                Ok(UpstreamBodyFrame::Trailers(trailers)) => {
                    let Some(mut writer) = self.session_mut().take_request_body_writer() else {
                        self.close().await;
                        return Err(ProxyError::Protocol(
                            "Pingora HTTP/2 request body is already complete".to_string(),
                        ));
                    };
                    if let Err(error) = writer.send_trailers(trailers) {
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
            self.close().await;
            return Err(classify_pingora_h2_error(&error, self.reused));
        }
        self.state = PingoraH2ExchangeState::RequestComplete;
        Ok(())
    }

    pub async fn read_response(
        mut self,
        mut lifecycle: UpstreamExchangeLifecycle,
    ) -> Result<UpstreamExchangeResponse, ProxyError> {
        if self.state != PingoraH2ExchangeState::RequestComplete {
            self.close().await;
            let detail = "Pingora HTTP/2 response read before request completion".to_string();
            finish_pingora_h2_exchange(
                lifecycle,
                UpstreamExchangeOutcome::Failed(ProxyError::Protocol(detail.clone())),
                UpstreamConnectionReuse::Close,
            );
            return Err(ProxyError::Protocol(detail));
        }
        let response_header = tokio::select! {
            cancellation_result = &mut lifecycle.cancellation.signal => {
                if cancellation_result.is_ok() {
                    self.close().await;
                    finish_pingora_h2_exchange(
                        lifecycle,
                        UpstreamExchangeOutcome::Cancelled,
                        UpstreamConnectionReuse::Reuse,
                    );
                    return Err(ProxyError::Transport(
                        "upstream exchange cancelled".to_string(),
                    ));
                }
                self.session_mut().read_response_header().await
            }
            response_header = self.session_mut().read_response_header() => response_header,
        };
        if let Err(error) = response_header {
            let outcome_error = classify_pingora_h2_error(&error, self.reused);
            let return_error = classify_pingora_h2_error(&error, self.reused);
            let connection_reuse = pingora_h2_error_reuse(&error);
            self.close().await;
            finish_pingora_h2_exchange(
                lifecycle,
                UpstreamExchangeOutcome::Failed(outcome_error),
                connection_reuse,
            );
            return Err(return_error);
        }

        let Some(response) = self.session().response_header() else {
            let detail =
                "Pingora HTTP/2 response header is unavailable after reading it".to_string();
            self.close().await;
            finish_pingora_h2_exchange(
                lifecycle,
                UpstreamExchangeOutcome::Failed(ProxyError::Protocol(detail.clone())),
                UpstreamConnectionReuse::Close,
            );
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

    pub async fn release(mut self) -> UpstreamConnectionReuse {
        if self.state != PingoraH2ExchangeState::ResponseComplete {
            self.close().await;
            return UpstreamConnectionReuse::Close;
        }
        let Some(session) = self.session.take() else {
            return UpstreamConnectionReuse::Close;
        };
        let reusable = !self.pool.is_draining()
            && !session.conn.is_closed()
            && !session.conn.is_shutting_down();
        if !reusable {
            session.conn.mark_shutdown();
        }
        self.pool
            .connector()
            .release_http_session(
                PingoraHttpSession::H2(session),
                &self.peer,
                self.peer.options.idle_timeout,
            )
            .await;
        if reusable {
            UpstreamConnectionReuse::Reuse
        } else {
            UpstreamConnectionReuse::Close
        }
    }

    pub async fn shutdown(mut self) {
        self.close().await;
    }

    async fn close(&mut self) {
        self.state = PingoraH2ExchangeState::Closed;
        if let Some(mut session) = self.session.take() {
            session.shutdown();
            if self.pool.is_draining() {
                session.conn.mark_shutdown();
            }
            self.pool
                .connector()
                .release_http_session(
                    PingoraHttpSession::H2(session),
                    &self.peer,
                    self.peer.options.idle_timeout,
                )
                .await;
        }
    }
}

fn pingora_h2_error_reuse(error: &Error) -> UpstreamConnectionReuse {
    if let Some(error) = error.root_cause().downcast_ref::<h2::Error>() {
        return if error.is_reset() {
            UpstreamConnectionReuse::Reuse
        } else {
            UpstreamConnectionReuse::Close
        };
    }
    match &error.etype {
        ErrorType::ReadTimedout | ErrorType::WriteTimedout | ErrorType::InvalidHTTPHeader => {
            UpstreamConnectionReuse::Reuse
        }
        _ => UpstreamConnectionReuse::Close,
    }
}

fn finish_pingora_h2_exchange(
    lifecycle: UpstreamExchangeLifecycle,
    outcome: UpstreamExchangeOutcome,
    connection_reuse: UpstreamConnectionReuse,
) {
    let _ = lifecycle.completion.send(UpstreamExchangeCompletion {
        outcome,
        connection_reuse,
    });
}

async fn send_pingora_h2_response_frame(
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

async fn fail_pingora_h2_response(
    session: PingoraH2UpstreamSession,
    frames: &mpsc::Sender<Result<UpstreamBodyFrame, ProxyError>>,
    lifecycle: UpstreamExchangeLifecycle,
    error: Box<Error>,
    cancellation_open: &mut bool,
) {
    let frame_error = classify_pingora_h2_error(&error, session.reused);
    let outcome_error = classify_pingora_h2_error(&error, session.reused);
    let connection_reuse = pingora_h2_error_reuse(&error);
    let mut lifecycle = lifecycle;
    let delivered = send_pingora_h2_response_frame(
        frames,
        Err(frame_error),
        &mut lifecycle.cancellation,
        cancellation_open,
    )
    .await;
    session.shutdown().await;
    finish_pingora_h2_exchange(
        lifecycle,
        if delivered {
            UpstreamExchangeOutcome::Failed(outcome_error)
        } else {
            UpstreamExchangeOutcome::Cancelled
        },
        connection_reuse,
    );
}

async fn pump_pingora_h2_response(
    mut session: PingoraH2UpstreamSession,
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
                        finish_pingora_h2_exchange(
                            lifecycle,
                            UpstreamExchangeOutcome::Cancelled,
                            UpstreamConnectionReuse::Reuse,
                        );
                        return;
                    }
                    cancellation_open = false;
                    continue;
                }
                body = session.session_mut().read_response_body() => body,
            }
        } else {
            session.session_mut().read_response_body().await
        };

        match next {
            Ok(Some(data)) => {
                if !send_pingora_h2_response_frame(
                    &frames,
                    Ok(UpstreamBodyFrame::Data(data)),
                    &mut lifecycle.cancellation,
                    &mut cancellation_open,
                )
                .await
                {
                    session.shutdown().await;
                    finish_pingora_h2_exchange(
                        lifecycle,
                        UpstreamExchangeOutcome::Cancelled,
                        UpstreamConnectionReuse::Reuse,
                    );
                    return;
                }
            }
            Ok(None) => break,
            Err(error) => {
                fail_pingora_h2_response(
                    session,
                    &frames,
                    lifecycle,
                    error,
                    &mut cancellation_open,
                )
                .await;
                return;
            }
        }
    }

    let trailers = if cancellation_open {
        tokio::select! {
            cancellation_result = &mut lifecycle.cancellation.signal => {
                if cancellation_result.is_ok() {
                    session.shutdown().await;
                    finish_pingora_h2_exchange(
                        lifecycle,
                        UpstreamExchangeOutcome::Cancelled,
                        UpstreamConnectionReuse::Reuse,
                    );
                    return;
                }
                cancellation_open = false;
                session.session_mut().read_trailers().await
            }
            trailers = session.session_mut().read_trailers() => trailers,
        }
    } else {
        session.session_mut().read_trailers().await
    };
    match trailers {
        Ok(Some(headers)) => {
            if !send_pingora_h2_response_frame(
                &frames,
                Ok(UpstreamBodyFrame::Trailers(headers)),
                &mut lifecycle.cancellation,
                &mut cancellation_open,
            )
            .await
            {
                session.shutdown().await;
                finish_pingora_h2_exchange(
                    lifecycle,
                    UpstreamExchangeOutcome::Cancelled,
                    UpstreamConnectionReuse::Reuse,
                );
                return;
            }
        }
        Ok(None) => {}
        Err(error) => {
            fail_pingora_h2_response(session, &frames, lifecycle, error, &mut cancellation_open)
                .await;
            return;
        }
    }

    match session.session_mut().check_response_end_or_error() {
        Ok(true) => {}
        Ok(false) => {
            session.shutdown().await;
            finish_pingora_h2_exchange(
                lifecycle,
                UpstreamExchangeOutcome::Failed(ProxyError::Protocol(
                    "Pingora HTTP/2 response ended without closing its stream".to_string(),
                )),
                UpstreamConnectionReuse::Reuse,
            );
            return;
        }
        Err(error) => {
            fail_pingora_h2_response(session, &frames, lifecycle, error, &mut cancellation_open)
                .await;
            return;
        }
    }

    session.state = PingoraH2ExchangeState::ResponseComplete;
    let connection_reuse = session.release().await;
    finish_pingora_h2_exchange(
        lifecycle,
        UpstreamExchangeOutcome::Completed,
        connection_reuse,
    );
}
