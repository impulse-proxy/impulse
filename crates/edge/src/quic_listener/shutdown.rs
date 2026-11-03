use std::{net::UdpSocket, sync::atomic::Ordering, time::Instant};

use log::{error, info, warn};

use crate::{
    constants::MAX_DATAGRAM_SIZE_BYTES,
    runtime::{connection::quic::QuicConnection, listener::Http3Service},
};

impl Http3Service {
    pub fn start_draining(&mut self) {
        if self.draining {
            return;
        }
        self.draining = true;
        self.drain_start = Some(Instant::now());
        info!("Draining connections");
    }

    pub fn drain_complete(&mut self) -> bool {
        if !self.draining {
            return self.connections.is_empty();
        }

        if self.connections.is_empty() {
            return true;
        }

        if !self.has_active_streams() {
            self.close_all_connections();
            return true;
        }

        if let Some(start) = self.drain_start
            && start.elapsed() >= self.drain_timeout
        {
            self.close_all_connections();
            return true;
        }

        false
    }

    pub fn drain_with_active_polls(&mut self) {
        self.start_draining();
        while !self.drain_complete() {
            self.poll();
        }
    }

    pub fn drain_with_idle_polls(&mut self) {
        self.start_draining();
        while !self.drain_complete() {
            self.poll_idle();
        }
    }

    pub(super) fn poll_preamble(&mut self) -> bool {
        self.sync_runtime_before_poll();
        self.watchdog.mark_poll_progress();

        if self.watchdog_restart_cleared() {
            self.watchdog_worker_drained = false;
        }
        if self.should_enter_draining() {
            if self.watchdog.restart_requested() {
                warn!("Watchdog requested restart; entering draining mode");
            } else {
                info!("Shutdown requested; entering draining mode");
            }
            self.start_draining();
        }
        if self.draining && self.drain_complete() {
            self.finish_watchdog_drain();
            return false;
        }
        true
    }

    fn sync_runtime_before_poll(&mut self) {
        if let Err(err) = self.sync_runtime_bundle_if_needed() {
            error!(
                "Failed to refresh runtime configuration for listener {}: {}",
                self.listener_label, err
            );
        }
    }

    fn watchdog_restart_cleared(&self) -> bool {
        !self.watchdog.restart_requested()
    }

    fn should_enter_draining(&self) -> bool {
        (self.watchdog.restart_requested() || self.shutdown.load(Ordering::Relaxed))
            && !self.draining
    }

    fn finish_watchdog_drain(&mut self) {
        if self.watchdog.restart_requested() && !self.watchdog_worker_drained {
            self.watchdog.mark_worker_drained();
            self.watchdog_worker_drained = true;
        }
    }

    fn has_active_streams(&self) -> bool {
        self.connections
            .values()
            .any(|conn| !conn.streams.is_empty())
    }

    fn close_all_connections(&mut self) {
        let mut send_buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];
        for connection in self.connections.values_mut() {
            Self::close_and_flush_connection(&self.socket, &mut send_buf, connection);
        }
        self.clear_connection_registry();
    }

    fn close_and_flush_connection(
        socket: &UdpSocket,
        send_buf: &mut [u8],
        connection: &mut QuicConnection,
    ) {
        let _ = connection.quic.close(true, 0x0, b"draining");
        Self::flush_send(socket, send_buf, connection);
    }
}
