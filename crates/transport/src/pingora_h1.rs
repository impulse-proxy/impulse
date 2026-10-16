use impulse_config::runtime::RuntimeBackendTransportKind;
use pingora_core::{
    Error, InternalError, Result,
    protocols::http::{client::HttpSession as PingoraHttpSession, v1::client::HttpSession},
    upstreams::peer::HttpPeer,
};

use crate::{PingoraPoolLease, PingoraUpstreamConnectionIdentity};

pub struct PingoraH1UpstreamSession {
    pool: PingoraPoolLease,
    peer: HttpPeer,
    session: Option<HttpSession>,
    reused: bool,
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

    pub async fn release(mut self) {
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
    }

    pub async fn shutdown(mut self) {
        if let Some(mut session) = self.session.take() {
            session.shutdown().await;
        }
    }
}
