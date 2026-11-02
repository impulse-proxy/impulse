use boring::ssl::SslContextBuilder;

#[derive(Clone, Copy, Debug)]
pub struct Http3TlsSettings {
    pub max_idle_timeout_millis: u64,
    pub max_udp_payload_bytes: usize,
    pub initial_max_data: u64,
    pub initial_max_stream_data: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub client_auth_enabled: bool,
}

pub fn build_http3_tls_config(
    tls_context: SslContextBuilder,
    settings: Http3TlsSettings,
) -> Result<quiche::Config, String> {
    let mut config =
        quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, tls_context)
            .map_err(|error| format!("failed to create QUIC config: {error}"))?;
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|error| format!("failed to set HTTP/3 ALPN protocols: {error}"))?;
    config.set_max_idle_timeout(settings.max_idle_timeout_millis);
    config.set_max_recv_udp_payload_size(settings.max_udp_payload_bytes);
    config.set_max_send_udp_payload_size(settings.max_udp_payload_bytes);
    config.set_initial_max_data(settings.initial_max_data);
    config.set_initial_max_stream_data_bidi_local(settings.initial_max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(settings.initial_max_stream_data);
    config.set_initial_max_stream_data_uni(settings.initial_max_stream_data);
    config.set_initial_max_streams_bidi(settings.initial_max_streams_bidi);
    config.set_initial_max_streams_uni(settings.initial_max_streams_uni);
    config.set_disable_active_migration(true);
    if !settings.client_auth_enabled {
        config.verify_peer(false);
    }
    Ok(config)
}
