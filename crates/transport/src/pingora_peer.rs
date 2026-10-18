use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use impulse_config::{
    backend_endpoint::BackendScheme,
    runtime::{
        RuntimeBackendConnectionPolicy, RuntimeBackendEndpoint, RuntimeBackendTransportKind,
    },
};
use pingora_core::{
    upstreams::peer::{ALPN, HttpPeer},
    utils::tls::{CertKey, WrappedX509, parse_x509},
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

use crate::TlsClientConfig;

pub(crate) fn build_pingora_http_peer(
    endpoint: &RuntimeBackendEndpoint,
    connection_policy: &RuntimeBackendConnectionPolicy,
    tls_config: &TlsClientConfig,
) -> Result<(HttpPeer, SocketAddr), String> {
    let address = SocketAddr::new(
        endpoint
            .authority_host
            .parse()
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        endpoint.authority_port,
    );
    let tls = endpoint.canonical.scheme() == BackendScheme::Https;
    let mut peer = HttpPeer::new(
        address,
        tls,
        tls.then(|| endpoint.authority_host.clone())
            .unwrap_or_default(),
    );
    peer.options.connection_timeout = Some(connection_policy.connect_timeout);
    peer.options.total_connection_timeout = Some(connection_policy.connect_timeout);
    peer.options.read_timeout = Some(connection_policy.execution_timeout);
    peer.options.write_timeout = Some(connection_policy.execution_timeout);
    peer.options.idle_timeout = Some(connection_policy.pool_idle_timeout);
    peer.options.alpn = match endpoint.transport_kind {
        RuntimeBackendTransportKind::Http1 => ALPN::H1,
        RuntimeBackendTransportKind::H2 => ALPN::H2,
    };
    peer.options.max_h2_streams = connection_policy.max_inflight;
    if tls {
        peer.options.verify_cert = tls_config.verify_certificates;
        peer.options.verify_hostname = tls_config.strict_sni;
        let ca_certificates = tls_config
            .ca_pem_blobs
            .iter()
            .flat_map(|pem| CertificateDer::pem_slice_iter(pem))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("failed to parse upstream CA certificates: {error}"))?;
        if !ca_certificates.is_empty() {
            let certificates = ca_certificates
                .into_iter()
                .map(|certificate| WrappedX509::new(certificate.as_ref().to_vec(), parse_x509))
                .collect::<Vec<_>>();
            peer.options.ca = Some(Arc::from(certificates.into_boxed_slice()));
        }
        match (
            tls_config.client_certificate_pem.as_deref(),
            tls_config.client_key_pem.as_deref(),
        ) {
            (Some(certificate_pem), Some(key_pem)) => {
                let certificates = CertificateDer::pem_slice_iter(certificate_pem)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| {
                        format!("failed to parse upstream client certificate: {error}")
                    })?
                    .into_iter()
                    .map(|certificate| certificate.as_ref().to_vec())
                    .collect::<Vec<_>>();
                if certificates.is_empty() {
                    return Err("upstream client certificate chain is empty".to_string());
                }
                let key = PrivateKeyDer::from_pem_slice(key_pem)
                    .map_err(|error| format!("failed to parse upstream client key: {error}"))?;
                peer.client_cert_key = Some(Arc::new(CertKey::new(
                    certificates,
                    key.secret_der().to_vec(),
                )));
            }
            (None, None) => {}
            _ => {
                return Err(
                    "upstream client certificate and key must be configured together".to_string(),
                );
            }
        }
    }
    Ok((peer, address))
}
