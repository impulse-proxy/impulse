use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionAdmissionRejection {
    Draining,
    Unroutable,
    GlobalRateLimit,
    SourceRateLimit,
    ConnectionCapacity,
}

pub trait ConnectionAdmissionAdapter {
    fn draining(&self) -> bool;
    fn admit_connection_plugins(
        &mut self,
        peer: SocketAddr,
    ) -> Result<(), ConnectionAdmissionRejection>;
    fn active_connections(&self) -> usize;
    fn max_active_connections(&self) -> usize;
    fn record_rejection(&self, reason: ConnectionAdmissionRejection);
}

pub fn admit_initial_connection(
    admission: &mut impl ConnectionAdmissionAdapter,
    peer: SocketAddr,
    packet_type: quiche::Type,
) -> Result<(), ConnectionAdmissionRejection> {
    let rejection = if admission.draining() {
        Some(ConnectionAdmissionRejection::Draining)
    } else if packet_type != quiche::Type::Initial {
        Some(ConnectionAdmissionRejection::Unroutable)
    } else if let Err(reason) = admission.admit_connection_plugins(peer) {
        Some(reason)
    } else if admission.active_connections() >= admission.max_active_connections() {
        Some(ConnectionAdmissionRejection::ConnectionCapacity)
    } else {
        None
    };

    if let Some(reason) = rejection {
        admission.record_rejection(reason);
        Err(reason)
    } else {
        Ok(())
    }
}
