use impulse_contracts::TunnelMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamPhase {
    ReceivingRequest,
    AwaitingUpstream,
    SendingResponse,
    Completed,
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamAdmissionState {
    WaitingForAuth,
    ReadyToForward,
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestMode {
    Normal,
    Bodyless,
    HeadLike,
    ConnectTunnel,
    WebsocketTunnel,
}

impl RequestMode {
    pub fn from_intake(
        tunnel_mode: TunnelMode,
        method: &str,
        content_length: Option<usize>,
    ) -> Self {
        match tunnel_mode {
            TunnelMode::Connect => Self::ConnectTunnel,
            TunnelMode::Websocket => Self::WebsocketTunnel,
            TunnelMode::None
                if content_length.unwrap_or(0) == 0 && method.eq_ignore_ascii_case("HEAD") =>
            {
                Self::HeadLike
            }
            TunnelMode::None
                if content_length.unwrap_or(0) == 0 && method.eq_ignore_ascii_case("GET") =>
            {
                Self::Bodyless
            }
            TunnelMode::None => Self::Normal,
        }
    }

    pub fn is_tunnel(self) -> bool {
        matches!(self, Self::ConnectTunnel | Self::WebsocketTunnel)
    }

    pub fn suppresses_response_body(self) -> bool {
        matches!(self, Self::HeadLike)
    }

    pub fn bodyless_mode(self) -> bool {
        matches!(self, Self::Bodyless | Self::HeadLike)
    }

    pub fn tunnel_mode(self) -> TunnelMode {
        match self {
            Self::Normal | Self::Bodyless | Self::HeadLike => TunnelMode::None,
            Self::ConnectTunnel => TunnelMode::Connect,
            Self::WebsocketTunnel => TunnelMode::Websocket,
        }
    }

    pub fn initial_body_state(self) -> RequestBodyState {
        if self.bodyless_mode() {
            RequestBodyState::FinReceived
        } else {
            RequestBodyState::Open
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestBodyState {
    Open,
    Buffered,
    FinReceived,
    ClosedToUpstream,
}

impl RequestBodyState {
    pub fn from_runtime(
        request_fin_received: bool,
        has_buffered_body: bool,
        forward_open: bool,
    ) -> Self {
        if forward_open {
            if has_buffered_body {
                Self::Buffered
            } else if request_fin_received {
                Self::FinReceived
            } else {
                Self::Open
            }
        } else if request_fin_received {
            Self::ClosedToUpstream
        } else if has_buffered_body {
            Self::Buffered
        } else {
            Self::Open
        }
    }

    pub fn on_buffered(self) -> Self {
        match self {
            Self::ClosedToUpstream => Self::ClosedToUpstream,
            _ => Self::Buffered,
        }
    }

    pub fn on_downstream_finished(self) -> Self {
        match self {
            Self::ClosedToUpstream => Self::ClosedToUpstream,
            _ => Self::FinReceived,
        }
    }

    pub fn on_forward_closed(self) -> Self {
        Self::ClosedToUpstream
    }

    pub fn request_fin_received(self) -> bool {
        matches!(self, Self::FinReceived | Self::ClosedToUpstream)
    }

    pub fn can_accept_downstream_body(self) -> bool {
        matches!(self, Self::Open | Self::Buffered)
    }

    pub fn forwarding_complete(self) -> bool {
        matches!(self, Self::ClosedToUpstream)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseEmissionState {
    DeferredHeaders,
    HeadersSent,
    StreamingBody,
    TrailersPending,
    EndPending,
}
