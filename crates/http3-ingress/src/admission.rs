use std::net::IpAddr;

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
    fn try_consume_global_token(&mut self) -> bool;
    fn try_consume_source_token(&self, source: IpAddr) -> bool;
    fn active_connections(&self) -> usize;
    fn max_active_connections(&self) -> usize;
    fn record_rejection(&self, reason: ConnectionAdmissionRejection);
}

pub fn admit_initial_connection(
    admission: &mut impl ConnectionAdmissionAdapter,
    source: IpAddr,
    packet_type: quiche::Type,
) -> Result<(), ConnectionAdmissionRejection> {
    let rejection = if admission.draining() {
        Some(ConnectionAdmissionRejection::Draining)
    } else if packet_type != quiche::Type::Initial {
        Some(ConnectionAdmissionRejection::Unroutable)
    } else if !admission.try_consume_global_token() {
        Some(ConnectionAdmissionRejection::GlobalRateLimit)
    } else if !admission.try_consume_source_token(source) {
        Some(ConnectionAdmissionRejection::SourceRateLimit)
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
