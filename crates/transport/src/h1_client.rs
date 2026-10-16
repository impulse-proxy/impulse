use http_body_util::combinators::BoxBody;
use hyper::{Request, body::Bytes};
use hyper_util::client::legacy::Client;
use impulse_errors::ProxyError;

use crate::h2_client::{
    ConnectObserver, DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_IDLE_PER_HOST, DEFAULT_POOL_IDLE_TIMEOUT,
    ObservedHttpConnector, SharedDnsResolver, TokioExecutor, build_observed_http_connector,
};

pub(crate) struct H1Client {
    client: Client<ObservedHttpConnector, BoxBody<Bytes, ProxyError>>,
}

impl Default for H1Client {
    fn default() -> Self {
        Self::new(
            DEFAULT_MAX_IDLE_PER_HOST,
            DEFAULT_POOL_IDLE_TIMEOUT,
            DEFAULT_CONNECT_TIMEOUT,
            SharedDnsResolver::new(),
        )
    }
}

impl H1Client {
    pub(crate) fn new(
        max_idle_per_host: usize,
        pool_idle_timeout: std::time::Duration,
        connect_timeout: std::time::Duration,
        dns_resolver: SharedDnsResolver,
    ) -> Self {
        Self::new_with_observer(
            max_idle_per_host,
            pool_idle_timeout,
            connect_timeout,
            dns_resolver,
            None,
        )
    }

    pub(crate) fn new_with_observer(
        max_idle_per_host: usize,
        pool_idle_timeout: std::time::Duration,
        connect_timeout: std::time::Duration,
        dns_resolver: SharedDnsResolver,
        connect_observer: Option<ConnectObserver>,
    ) -> Self {
        let http =
            build_observed_http_connector(dns_resolver, true, connect_timeout, connect_observer);

        let client = Client::builder(TokioExecutor)
            .pool_max_idle_per_host(max_idle_per_host)
            .pool_idle_timeout(pool_idle_timeout)
            .build(http);

        Self { client }
    }

    pub(crate) async fn send(
        &self,
        req: Request<BoxBody<Bytes, ProxyError>>,
    ) -> Result<hyper::Response<hyper::body::Incoming>, hyper_util::client::legacy::Error> {
        self.client.request(req).await
    }

    #[cfg(test)]
    fn try_default() -> Self {
        Self::new(
            DEFAULT_MAX_IDLE_PER_HOST,
            DEFAULT_POOL_IDLE_TIMEOUT,
            DEFAULT_CONNECT_TIMEOUT,
            SharedDnsResolver::new(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::H1Client;

    #[test]
    fn default_h1_client_does_not_panic() {
        let _client = H1Client::default();
    }

    #[test]
    fn default_h1_client_builds() {
        let _client = H1Client::try_default();
    }
}
