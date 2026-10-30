use http::StatusCode;

/// Request-scoped ownership mode for upgraded byte streams.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TunnelMode {
    #[default]
    None,
    Connect,
    Websocket,
}

impl TunnelMode {
    pub fn is_tunnel(self) -> bool {
        self != Self::None
    }

    pub fn established_by(self, method: &str, status: StatusCode) -> bool {
        match self {
            Self::None => false,
            Self::Connect => method.eq_ignore_ascii_case("CONNECT") && status.is_success(),
            Self::Websocket if method.eq_ignore_ascii_case("CONNECT") => status.is_success(),
            Self::Websocket => status == StatusCode::SWITCHING_PROTOCOLS,
        }
    }
}
