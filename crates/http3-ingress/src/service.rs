use std::net::SocketAddr;

pub type Http3HeaderLookup<'a> = dyn Fn(&str) -> Option<String> + Sync + 'a;

pub struct Http3RequestExecutionInput<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub authority: Option<&'a str>,
    pub peer_address: SocketAddr,
    pub headers: Option<&'a Http3HeaderLookup<'a>>,
}

pub trait Http3RequestService {
    type Output;
    type Error;

    fn execute_http3(
        &self,
        request: Http3RequestExecutionInput<'_>,
    ) -> Result<Self::Output, Self::Error>;
}

pub struct Http3IngressAdapter<S> {
    request_service: S,
}

impl<S> Http3IngressAdapter<S> {
    pub fn new(request_service: S) -> Self {
        Self { request_service }
    }
}

impl<S: Http3RequestService> Http3IngressAdapter<S> {
    pub fn execute(&self, request: Http3RequestExecutionInput<'_>) -> Result<S::Output, S::Error> {
        self.request_service.execute_http3(request)
    }
}
