use std::net::SocketAddr;

pub type RequestHeaderLookup<'a> = dyn Fn(&str) -> Option<String> + Sync + 'a;

/// Borrowed request data shared by every traffic-policy implementation.
#[derive(Clone, Copy)]
pub struct RequestView<'a> {
    method: &'a str,
    path: &'a str,
    authority: Option<&'a str>,
    peer_address: SocketAddr,
    headers: Option<&'a RequestHeaderLookup<'a>>,
}

impl<'a> RequestView<'a> {
    #[must_use]
    pub const fn new(
        method: &'a str,
        path: &'a str,
        authority: Option<&'a str>,
        peer_address: SocketAddr,
        headers: Option<&'a RequestHeaderLookup<'a>>,
    ) -> Self {
        Self {
            method,
            path,
            authority,
            peer_address,
            headers,
        }
    }

    #[must_use]
    pub const fn method(&self) -> &'a str {
        self.method
    }

    #[must_use]
    pub const fn path(&self) -> &'a str {
        self.path
    }

    #[must_use]
    pub const fn authority(&self) -> Option<&'a str> {
        self.authority
    }

    #[must_use]
    pub const fn peer_address(&self) -> SocketAddr {
        self.peer_address
    }

    #[must_use]
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers.and_then(|lookup| lookup(name))
    }
}
