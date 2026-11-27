use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use pingora_core::{
    upstreams::peer::{ALPN, HttpPeer, HttpUpstreamRequestPolicy},
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
    peer.options.http_upstream_request_policy = HttpUpstreamRequestPolicy::standard();
    peer.options.alpn = match endpoint.protocol {
        UpstreamProtocol::Auto => ALPN::H2H1,
        UpstreamProtocol::Http1 => ALPN::H1,
        UpstreamProtocol::Http2 => ALPN::H2,
    };
    if matches!(
        endpoint.protocol,
        UpstreamProtocol::Auto | UpstreamProtocol::Http2
    ) {
        peer.options.max_h2_streams = input.connection_limits.max_inflight;
        peer.options.h2_stream_window_size = Some(input.h2_flow_control.stream_window_bytes);
        peer.options.h2_connection_window_size =
            Some(input.h2_flow_control.connection_window_bytes);
    }
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::{
        UpstreamConnectionLimitsInput, UpstreamEndpointInput, UpstreamH2FlowControlInput,
        UpstreamTimeoutInput,
    };

    fn transport_input(protocol: UpstreamProtocol, tls: bool) -> UpstreamTransportInput {
        UpstreamTransportInput {
            endpoint: UpstreamEndpointInput {
                configured_address: "127.0.0.1:8443".to_string(),
                authority_host: "127.0.0.1".to_string(),
                authority_port: 8443,
                protocol,
                tls,
            },
            tls: None,
            timeouts: UpstreamTimeoutInput {
                connect: Duration::from_secs(1),
                execution: Duration::from_secs(2),
                pool_idle: Duration::from_secs(3),
            },
            connection_limits: UpstreamConnectionLimitsInput { max_inflight: 23 },
            h2_flow_control: UpstreamH2FlowControlInput {
                stream_window_bytes: 65_535,
                connection_window_bytes: 131_070,
            },
        }
    }

    #[test]
    fn tls_protocol_policy_maps_to_expected_alpn() {
        for (protocol, expected) in [
            (UpstreamProtocol::Auto, ALPN::H2H1),
            (UpstreamProtocol::Http1, ALPN::H1),
            (UpstreamProtocol::Http2, ALPN::H2),
        ] {
            let (peer, _) =
                build_pingora_http_peer(&transport_input(protocol, true)).expect("TLS peer");
            assert_eq!(peer.options.alpn, expected);
        }
    }

    #[test]
    fn h2_settings_apply_only_to_h2_capable_protocols() {
        let (http1, _) = build_pingora_http_peer(&transport_input(UpstreamProtocol::Http1, true))
            .expect("HTTP/1 peer");
        assert_eq!(http1.options.max_h2_streams, 1);
        assert_eq!(http1.options.h2_stream_window_size, None);
        assert_eq!(http1.options.h2_connection_window_size, None);

        for protocol in [UpstreamProtocol::Auto, UpstreamProtocol::Http2] {
            let (peer, _) =
                build_pingora_http_peer(&transport_input(protocol, true)).expect("H2-capable peer");
            assert_eq!(peer.options.max_h2_streams, 23);
            assert_eq!(peer.options.h2_stream_window_size, Some(65_535));
            assert_eq!(peer.options.h2_connection_window_size, Some(131_070));
        }
    }
}
