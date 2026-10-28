use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use pingora_core::{
    upstreams::peer::{ALPN, HttpPeer, Proxy},
    utils::tls::{CertKey, WrappedX509, parse_x509},
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

use crate::{UpstreamProtocol, UpstreamTransportInput};

pub(crate) fn build_pingora_http_peer(
    input: &UpstreamTransportInput,
) -> Result<(HttpPeer, SocketAddr), String> {
    let endpoint = &input.endpoint;
    let address = SocketAddr::new(
        endpoint
            .authority_host
            .parse()
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        endpoint.authority_port,
    );
    let tls = endpoint.tls;
    let mut peer = HttpPeer::new(
        address,
        tls,
        if tls {
            endpoint.authority_host.clone()
        } else {
            String::new()
        },
    );
    peer.options.connection_timeout = Some(input.timeouts.connect);
    peer.options.total_connection_timeout = Some(input.timeouts.connect);
    peer.options.read_timeout = Some(input.timeouts.execution);
    peer.options.write_timeout = Some(input.timeouts.execution);
    peer.options.idle_timeout = Some(input.timeouts.pool_idle);
    peer.options.alpn = match endpoint.protocol {
        UpstreamProtocol::Http1 => ALPN::H1,
        UpstreamProtocol::Http2 => ALPN::H2,
    };
    peer.options.max_h2_streams = input.connection_limits.max_inflight;
    peer.proxy = input.proxy.as_ref().map(|proxy| Proxy {
        next_hop: proxy.next_hop.clone().into_boxed_path(),
        host: proxy.host.clone(),
        port: proxy.port,
        headers: proxy.headers.clone(),
    });
    if tls {
        let tls_config = input.tls.as_ref();
        peer.options.verify_cert = tls_config.is_none_or(|tls| tls.verify_certificates);
        peer.options.verify_hostname = tls_config.is_none_or(|tls| tls.verify_hostname);
        let ca_certificates = tls_config
            .map(|tls| tls.ca_pem_blobs.as_slice())
            .unwrap_or_default()
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
            tls_config.and_then(|tls| tls.client_certificate_pem.as_deref()),
            tls_config.and_then(|tls| tls.client_key_pem.as_deref()),
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
