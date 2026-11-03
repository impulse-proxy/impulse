use tokio::runtime::Handle;

use super::Http3Service;

impl Http3Service {
    pub(super) fn bind_tcp_listener(
        bind: &str,
        handle: Option<&Handle>,
        context: &str,
    ) -> Result<tokio::net::TcpListener, String> {
        let std_listener = std::net::TcpListener::bind(bind)
            .map_err(|err| format!("failed to bind {context} {bind}: {err}"))?;
        std_listener.set_nonblocking(true).map_err(|err| {
            format!(
                "failed to set {context} listener nonblocking ({}): {}",
                bind, err
            )
        })?;
        let from_std_result = if let Some(handle) = handle {
            let _guard = handle.enter();
            tokio::net::TcpListener::from_std(std_listener)
        } else {
            tokio::net::TcpListener::from_std(std_listener)
        };
        from_std_result
            .map_err(|err| format!("failed to register {context} listener {}: {}", bind, err))
    }

    pub(crate) fn probe_tcp_bind(bind: &str, context: &str) -> Result<(), String> {
        std::net::TcpListener::bind(bind)
            .map(|_| ())
            .map_err(|err| format!("failed to bind {context} {bind}: {err}"))
    }
}
