use std::sync::Arc;

use async_trait::async_trait;
use pingora_core::{
    Error, InternalError, Result, server::configuration::ServerConf, services::listening::Service,
    upstreams::peer::HttpPeer,
};
use pingora_proxy::{HttpProxy, ProxyHttp, Session, http_proxy_service_with_name};

use crate::runtime::bundle::{RuntimeBundle, RuntimeBundleHandle};

pub(crate) struct PingoraRequestContext {
    pub(crate) runtime: Arc<RuntimeBundle>,
}

pub(crate) struct PingoraIngressService {
    runtime: RuntimeBundleHandle,
}

pub(crate) fn pingora_ingress_service(
    configuration: &Arc<ServerConf>,
    runtime: RuntimeBundleHandle,
) -> Service<HttpProxy<PingoraIngressService>> {
    http_proxy_service_with_name(
        configuration,
        PingoraIngressService { runtime },
        "Impulse Pingora Ingress",
    )
}

#[async_trait]
impl ProxyHttp for PingoraIngressService {
    type CTX = PingoraRequestContext;

    fn new_ctx(&self) -> Self::CTX {
        PingoraRequestContext {
            runtime: self.runtime.current(),
        }
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        Error::e_explain(
            InternalError,
            "Pingora ingress upstream selection is not configured",
        )
    }
}
