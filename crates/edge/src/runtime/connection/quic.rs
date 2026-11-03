use crate::runtime::connection::request::RequestEnvelope;

pub(crate) type QuicConnection = impulse_http3_ingress::QuicConnection<RequestEnvelope>;
pub(crate) use impulse_http3_ingress::QuicConnectionErrorSnapshot;
