use impulse_config::runtime::RuntimeBackendTransportKind;
use pingora_core::{
    Error, InternalError, Result,
    protocols::http::{client::HttpSession as PingoraHttpSession, v2::client::Http2Session},
    upstreams::peer::{ALPN, HttpPeer},
};

use crate::{PingoraPoolLease, PingoraUpstreamConnectionIdentity};

pub struct PingoraH2UpstreamSession {
    pool: PingoraPoolLease,
    peer: HttpPeer,
    session: Option<Http2Session>,
    reused: bool,
}

impl PingoraH2UpstreamSession {
    pub async fn acquire(
        pool: PingoraPoolLease,
        mut peer: HttpPeer,
        identity: &PingoraUpstreamConnectionIdentity,
    ) -> Result<Self> {
        if identity.protocol != RuntimeBackendTransportKind::H2 {
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

        peer.options.alpn = ALPN::H2;
        peer.group_key = identity.pool_key();
        let (session, reused) = pool.connector().get_http_session(&peer).await?;
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

        Ok(Self {
            pool,
            peer,
            session: Some(session),
            reused,
        })
    }

    pub fn generation(&self) -> u64 {
        self.pool.generation()
    }

    pub fn reused(&self) -> bool {
        self.reused
    }

    pub fn session(&self) -> &Http2Session {
        self.session
            .as_ref()
            .expect("Pingora H2 session ownership already released")
    }

    pub fn session_mut(&mut self) -> &mut Http2Session {
        self.session
            .as_mut()
            .expect("Pingora H2 session ownership already released")
    }

    pub async fn release(mut self) {
        let session = self
            .session
            .take()
            .expect("Pingora H2 session ownership already released");
        self.pool
            .connector()
            .release_http_session(
                PingoraHttpSession::H2(session),
                &self.peer,
                self.peer.options.idle_timeout,
            )
            .await;
    }

    pub fn shutdown(mut self) {
        if let Some(mut session) = self.session.take() {
            session.shutdown();
        }
    }
}
