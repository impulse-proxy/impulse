use impulse_config::{
    backend_endpoint::BackendScheme,
    runtime::{RuntimeBackendTransportKind, RuntimeConfig, RuntimeUpstream},
};
use impulse_transport::{
    UpstreamConnectionLimitsInput, UpstreamEndpointInput, UpstreamProtocol, UpstreamTimeoutInput,
    UpstreamTlsInput, UpstreamTransportInput,
};

fn tls_input(upstream: &RuntimeUpstream) -> UpstreamTlsInput {
    let tls = upstream.backend_tls_policy();
    UpstreamTlsInput {
        verify_certificates: tls.verify_certificates,
        verify_hostname: tls.strict_sni,
        ca_file_fingerprint_sha256: tls.ca_file_fingerprint_sha256.clone(),
        ca_dir_fingerprint_sha256: tls.ca_dir_fingerprint_sha256.clone(),
        ca_pem_blobs: tls.ca_pem_blobs().to_vec(),
        client_certificate_pem: tls.client_certificate_pem().map(|pem| pem.to_vec()),
        client_key_pem: tls.client_key_pem().map(|pem| pem.to_vec()),
        client_certificate_fingerprint_sha256: tls
            .client_certificate
            .as_ref()
            .map(|metadata| metadata.fingerprint_sha256.clone()),
        client_key_fingerprint_sha256: tls
            .client_key
            .as_ref()
            .map(|metadata| metadata.fingerprint_sha256.clone()),
    }
}

pub(crate) fn upstream_transport_inputs(config: &RuntimeConfig) -> Vec<UpstreamTransportInput> {
    let connection = &config.policies.transport.backend_connections;
    let timeouts = UpstreamTimeoutInput {
        connect: connection.connect_timeout,
        execution: connection.execution_timeout,
        pool_idle: connection.pool_idle_timeout,
    };
    let connection_limits = UpstreamConnectionLimitsInput {
        max_inflight: connection.max_inflight,
        max_idle: connection.max_idle_per_backend,
    };

    config
        .upstreams
        .values()
        .flat_map(|upstream| {
            let tls = tls_input(upstream);
            upstream.backends.iter().map(move |backend| {
                let uses_tls = backend.endpoint.canonical.scheme() == BackendScheme::Https;
                UpstreamTransportInput {
                    endpoint: UpstreamEndpointInput {
                        configured_address: backend.backend.address.clone(),
                        authority_host: backend.endpoint.authority_host.clone(),
                        authority_port: backend.endpoint.authority_port,
                        protocol: match backend.endpoint.transport_kind {
                            RuntimeBackendTransportKind::Http1 => UpstreamProtocol::Http1,
                            RuntimeBackendTransportKind::H2 => UpstreamProtocol::Http2,
                        },
                        tls: uses_tls,
                    },
                    tls: uses_tls.then(|| tls.clone()),
                    timeouts,
                    proxy: None,
                    connection_limits,
                }
            })
        })
        .collect()
}
