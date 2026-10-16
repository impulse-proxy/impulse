use hyper::{Method, http::Version};
use impulse_config::runtime::RuntimeBackendTransportKind;
use pingora_core::{
    Error, InternalError, Result,
    protocols::http::{client::HttpSession as PingoraHttpSession, v1::client::HttpSession},
    upstreams::peer::HttpPeer,
};
use pingora_http::RequestHeader;

use crate::{PingoraPoolLease, PingoraUpstreamConnectionIdentity, UpstreamRequestHead};

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
