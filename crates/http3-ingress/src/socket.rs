use std::{
    io,
    net::{SocketAddr, UdpSocket},
    time::Duration,
};

use socket2::{Domain, Protocol, Socket, Type};

#[derive(Clone, Copy, Debug)]
pub struct UdpSocketConfig {
    pub bind_address: SocketAddr,
    pub reuse_port: bool,
    pub receive_buffer_bytes: usize,
    pub send_buffer_bytes: usize,
    pub read_timeout: Duration,
}

pub fn bind_udp_socket(config: UdpSocketConfig) -> io::Result<UdpSocket> {
    let domain = if config.bind_address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_recv_buffer_size(config.receive_buffer_bytes)?;
    socket.set_send_buffer_size(config.send_buffer_bytes)?;

    #[cfg(all(
        unix,
        not(target_os = "solaris"),
        not(target_os = "illumos"),
        not(target_os = "cygwin")
    ))]
    socket.set_reuse_port(config.reuse_port)?;

    socket.bind(&config.bind_address.into())?;
    let socket: UdpSocket = socket.into();
    socket.set_read_timeout(Some(config.read_timeout))?;
    Ok(socket)
}
