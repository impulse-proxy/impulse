use std::{
    ffi::OsStr,
    fs::File,
    io::Read,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use super::*;
use crate::quic_listener::control_api::security::{
    ControlApiClientAuthPolicy, ControlApiClientVerifierState,
};

const MAX_TLS_PEM_BYTES: u64 = 1024 * 1024;

#[derive(Debug)]
struct FallbackServerCertResolver {
    sni_resolver: ResolvesServerCertUsingSni,
    fallback: Arc<CertifiedKey>,
}

#[derive(Clone)]
pub(super) struct LoadedListenerIdentity {
    identity: RuntimeTlsIdentity,
    certified_key: Arc<CertifiedKey>,
    metadata: RuntimeTlsCertificateMetadata,
}

impl LoadedListenerIdentity {
    /// The only way to build this type: certificate validity is checked
    /// before construction, so a `LoadedListenerIdentity` can never carry an
    /// expired or not-yet-valid certificate.
    fn new(
        identity: RuntimeTlsIdentity,
        certified_key: Arc<CertifiedKey>,
        metadata: RuntimeTlsCertificateMetadata,
        cert_field: &str,
        cert_path: &str,
    ) -> Result<Self, ProxyError> {
        QUICListener::validate_tls_certificate_validity(&metadata, cert_field, cert_path)?;
        Ok(Self {
            identity,
            certified_key,
            metadata,
        })
    }

    pub(super) fn identity(&self) -> &RuntimeTlsIdentity {
        &self.identity
    }

    pub(super) fn certified_key(&self) -> &Arc<CertifiedKey> {
        &self.certified_key
    }

    pub(super) fn metadata(&self) -> &RuntimeTlsCertificateMetadata {
        &self.metadata
    }
}

#[derive(Clone)]
pub(super) struct LoadedClientAuthCa {
    pub(super) ca_file: String,
    pub(super) certificate_count: usize,
    pub(super) roots: Arc<RootCertStore>,
}

#[derive(Clone)]
pub(super) struct LoadedListenerTlsMaterial {
    pub(super) default_identity: LoadedListenerIdentity,
    pub(super) sni_identities: HashMap<String, LoadedListenerIdentity>,
    pub(super) client_auth: ClientAuth,
    pub(super) client_auth_ca: Option<LoadedClientAuthCa>,
}

struct QuicSniCertMaterial {
    leaf: X509,
    chain: Vec<X509>,
    key: PKey<Private>,
}

impl QuicSniCertMaterial {
    /// The only way to build this type: cert/key match is checked before
    /// construction, so a `QuicSniCertMaterial` can never pair a leaf
    /// certificate with a private key that doesn't match it.
    fn new(
        leaf: X509,
        chain: Vec<X509>,
        key: PKey<Private>,
        cert_path: &str,
        key_path: &str,
    ) -> Result<Self, ProxyError> {
        QUICListener::validate_boring_certificate_key(&leaf, &key, cert_path, key_path)?;
        Ok(Self { leaf, chain, key })
    }
}

impl ResolvesServerCert for FallbackServerCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.sni_resolver
            .resolve(client_hello)
            .or_else(|| Some(Arc::clone(&self.fallback)))
    }
}

impl QUICListener {
    fn read_tls_pem_file_with_limit(path: &str, field_name: &str) -> Result<Vec<u8>, ProxyError> {
        let file = File::open(path).map_err(|err| {
            ProxyError::Tls(format!("failed to read {field_name} '{path}': {err}"))
        })?;
        let metadata = file.metadata().map_err(|err| {
            ProxyError::Tls(format!("failed to read {field_name} '{path}': {err}"))
        })?;
        if !metadata.is_file() {
            return Err(ProxyError::Tls(format!(
                "{field_name} '{path}' must be a file"
            )));
        }
        if metadata.len() > MAX_TLS_PEM_BYTES {
            return Err(ProxyError::Tls(format!(
                "{field_name} '{path}' exceeds the maximum supported PEM size ({} bytes)",
                MAX_TLS_PEM_BYTES
            )));
        }

        let mut bytes = Vec::with_capacity(
            usize::try_from(metadata.len())
                .unwrap_or(usize::MAX)
                .min(usize::try_from(MAX_TLS_PEM_BYTES).unwrap_or(usize::MAX)),
        );
        file.take(MAX_TLS_PEM_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|err| {
                ProxyError::Tls(format!("failed to read {field_name} '{path}': {err}"))
            })?;
        if bytes.len() > usize::try_from(MAX_TLS_PEM_BYTES).unwrap_or(usize::MAX) {
            return Err(ProxyError::Tls(format!(
                "{field_name} '{path}' exceeds the maximum supported PEM size ({} bytes)",
                MAX_TLS_PEM_BYTES
            )));
        }

        Ok(bytes)
    }

    pub(super) fn runtime_listener_tls(
        config: &ListenerRuntimeConfig,
    ) -> Result<RuntimeListenerTls, ProxyError> {
        Ok(config.listen.tls.clone())
    }

    pub(super) fn build_quic_config(config: &ListenerRuntimeConfig) -> Result<Config, ProxyError> {
        let loaded_tls = Self::load_listener_tls_material(config)?;
        let transport_policy = &config.policies.transport;
        let timeout_policy = &config.policies.timeouts;
        debug!(
            "Loaded downstream default TLS identity cert='{}' serial={} san_dns={:?} sni_identities={}",
            loaded_tls.default_identity.identity().cert_path,
            loaded_tls.default_identity.metadata().serial_hex,
            loaded_tls.default_identity.metadata().dns_names,
            loaded_tls.sni_identities.len()
        );
        if let Some(client_auth_ca) = loaded_tls.client_auth_ca.as_ref() {
            debug!(
                "Loaded downstream client-auth CA bundle '{}' with {} certificates",
                client_auth_ca.ca_file, client_auth_ca.certificate_count
            );
        }
        let mut quic_config = Self::build_quic_config_from_loaded(&loaded_tls)?;

        quic_config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .map_err(|err| {
                ProxyError::Transport(format!("failed to set ALPN protocols: {:?}", err))
            })?;
        quic_config.set_max_idle_timeout(
            timeout_policy
                .quic_max_idle
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
        );
        quic_config.set_max_recv_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
        quic_config.set_max_send_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
        quic_config.set_initial_max_data(transport_policy.quic_initial_max_data);
        quic_config
            .set_initial_max_stream_data_bidi_local(transport_policy.quic_initial_max_stream_data);
        quic_config
            .set_initial_max_stream_data_bidi_remote(transport_policy.quic_initial_max_stream_data);
        quic_config.set_initial_max_stream_data_uni(transport_policy.quic_initial_max_stream_data);
        quic_config.set_initial_max_streams_bidi(transport_policy.quic_initial_max_streams_bidi);
        quic_config.set_initial_max_streams_uni(transport_policy.quic_initial_max_streams_uni);
        quic_config.set_disable_active_migration(true);

        if loaded_tls.client_auth.enabled {
            info!(
                "Downstream mTLS enabled (require_client_cert={})",
                loaded_tls.client_auth.require_client_cert
            );
        } else {
            quic_config.verify_peer(false);
        }

        Ok(quic_config)
    }

    fn build_quic_config_from_loaded(
        loaded_tls: &LoadedListenerTlsMaterial,
    ) -> Result<Config, ProxyError> {
        let tls_ctx_builder = Self::build_quic_ssl_context_builder(loaded_tls)?;
        Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, tls_ctx_builder)
            .map_err(|err| ProxyError::Transport(format!("failed to create QUIC config: {err}")))
    }

    fn build_quic_ssl_context_builder(
        loaded_tls: &LoadedListenerTlsMaterial,
    ) -> Result<SslContextBuilder, ProxyError> {
        let mut default_builder = Self::build_quic_ssl_context_builder_for_identity(
            loaded_tls.default_identity.identity(),
            &loaded_tls.client_auth,
            loaded_tls.client_auth_ca.as_ref(),
        )?;

        if loaded_tls.sni_identities.is_empty() {
            return Ok(default_builder);
        }

        let mut sni_certs: HashMap<String, QuicSniCertMaterial> =
            HashMap::with_capacity(loaded_tls.sni_identities.len());
        for (server_name, identity) in &loaded_tls.sni_identities {
            Self::validate_loaded_sni_identity(server_name, identity)?;
            let cert_pem =
                Self::read_tls_pem_file_with_limit(&identity.identity().cert_path, "SNI cert")?;
            let mut certs = X509::stack_from_pem(&cert_pem).map_err(|err| {
                ProxyError::Tls(format!(
                    "failed to parse SNI cert '{}': {}",
                    identity.identity().cert_path,
                    err
                ))
            })?;
            if certs.is_empty() {
                return Err(ProxyError::Tls(format!(
                    "SNI cert '{}' contains no certificates",
                    identity.identity().cert_path
                )));
            }
            let leaf = certs.remove(0);
            let chain = certs;
            let key_pem =
                Self::read_tls_pem_file_with_limit(&identity.identity().key_path, "SNI key")?;
            let key = PKey::private_key_from_pem(&key_pem).map_err(|err| {
                ProxyError::Tls(format!(
                    "failed to parse SNI key '{}': {}",
                    identity.identity().key_path,
                    err
                ))
            })?;
            let sni_material = QuicSniCertMaterial::new(
                leaf,
                chain,
                key,
                &identity.identity().cert_path,
                &identity.identity().key_path,
            )?;
            sni_certs.insert(server_name.clone(), sni_material);
        }

        let sni_certs = Arc::new(sni_certs);
        default_builder.set_select_certificate_callback(move |mut hello| {
            let Some(server_name) = hello.servername(NameType::HOST_NAME) else {
                return Ok(());
            };
            let normalized_server_name = server_name.to_ascii_lowercase();
            let Some(data) = sni_certs.get(&normalized_server_name) else {
                return Ok(());
            };
            let ssl = hello.ssl_mut();
            ssl.set_certificate(&data.leaf).map_err(|err| {
                error!(
                    "failed to set QUIC SNI certificate for server_name='{}': {}",
                    normalized_server_name, err
                );
                SelectCertError::ERROR
            })?;
            for cert in &data.chain {
                ssl.add_chain_cert(cert).map_err(|err| {
                    error!(
                        "failed to add QUIC SNI chain cert for server_name='{}': {}",
                        normalized_server_name, err
                    );
                    SelectCertError::ERROR
                })?;
            }
            ssl.set_private_key(&data.key).map_err(|err| {
                error!(
                    "failed to set QUIC SNI key for server_name='{}': {}",
                    normalized_server_name, err
                );
                SelectCertError::ERROR
            })?;
            Ok(())
        });
        Ok(default_builder)
    }

    fn build_quic_ssl_context_builder_for_identity(
        identity: &RuntimeTlsIdentity,
        client_auth: &ClientAuth,
        client_auth_ca: Option<&LoadedClientAuthCa>,
    ) -> Result<SslContextBuilder, ProxyError> {
        let mut builder = SslContextBuilder::new(SslMethod::tls()).map_err(|err| {
            ProxyError::Tls(format!(
                "failed to build downstream QUIC TLS context for '{}': {}",
                identity.cert_path, err
            ))
        })?;

        let cert_pem = Self::read_tls_pem_file_with_limit(
            &identity.cert_path,
            "listen.tls.default_identity.cert",
        )?;
        let mut certs = X509::stack_from_pem(&cert_pem).map_err(|err| {
            ProxyError::Tls(format!(
                "failed to parse certificate '{}': {}",
                identity.cert_path, err
            ))
        })?;
        if certs.is_empty() {
            return Err(ProxyError::Tls(format!(
                "certificate '{}' contains no certificates",
                identity.cert_path
            )));
        }
        let leaf = certs.remove(0);
        builder.set_certificate(&leaf).map_err(|err| {
            ProxyError::Tls(format!(
                "failed to load certificate '{}': {}",
                identity.cert_path, err
            ))
        })?;
        for cert in certs {
            builder.add_extra_chain_cert(cert).map_err(|err| {
                ProxyError::Tls(format!(
                    "failed to load certificate chain '{}': {}",
                    identity.cert_path, err
                ))
            })?;
        }

        let key_pem = Self::read_tls_pem_file_with_limit(
            &identity.key_path,
            "listen.tls.default_identity.key",
        )?;
        let key = PKey::private_key_from_pem(&key_pem).map_err(|err| {
            ProxyError::Tls(format!(
                "failed to parse key '{}': {}",
                identity.key_path, err
            ))
        })?;
        Self::validate_boring_certificate_key(
            &leaf,
            &key,
            &identity.cert_path,
            &identity.key_path,
        )?;
        builder.set_private_key(&key).map_err(|err| {
            ProxyError::Tls(format!(
                "failed to load key '{}': {}",
                identity.key_path, err
            ))
        })?;

        if client_auth.enabled {
            let client_auth_ca = client_auth_ca.ok_or_else(|| {
                ProxyError::Tls(
                    "listen.tls.client_auth.ca_file is required when mTLS is enabled".to_string(),
                )
            })?;
            let ca_pem = Self::read_tls_pem_file_with_limit(
                &client_auth_ca.ca_file,
                "listen.tls.client_auth.ca_file",
            )?;
            let ca_certs = X509::stack_from_pem(&ca_pem).map_err(|err| {
                ProxyError::Tls(format!(
                    "failed to parse listen.tls.client_auth.ca_file '{}': {}",
                    client_auth_ca.ca_file, err
                ))
            })?;
            let mut verify_store = boring::x509::store::X509StoreBuilder::new().map_err(|err| {
                ProxyError::Tls(format!(
                    "failed to initialize listen.tls.client_auth.ca_file '{}': {}",
                    client_auth_ca.ca_file, err
                ))
            })?;
            for cert in ca_certs {
                verify_store.add_cert(cert.clone()).map_err(|err| {
                    ProxyError::Tls(format!(
                        "failed to load listen.tls.client_auth.ca_file '{}': {}",
                        client_auth_ca.ca_file, err
                    ))
                })?;
                builder.add_client_ca(&cert).map_err(|err| {
                    ProxyError::Tls(format!(
                        "failed to advertise client CA from listen.tls.client_auth.ca_file '{}': {}",
                        client_auth_ca.ca_file, err
                    ))
                })?;
            }
            builder
                .set_verify_cert_store(verify_store.build())
                .map_err(|err| {
                    ProxyError::Tls(format!(
                        "failed to load listen.tls.client_auth.ca_file '{}': {}",
                        client_auth_ca.ca_file, err
                    ))
                })?;
            let verify_mode = if client_auth.require_client_cert {
                SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT
            } else {
                SslVerifyMode::PEER
            };
            builder.set_verify(verify_mode);
        } else {
            builder.set_verify(SslVerifyMode::NONE);
        }

        Ok(builder)
    }

    fn validate_boring_certificate_key(
        certificate: &X509,
        key: &PKey<boring::pkey::Private>,
        cert_path: &str,
        key_path: &str,
    ) -> Result<(), ProxyError> {
        let certificate_key = certificate.public_key().map_err(|err| {
            ProxyError::Tls(format!(
                "failed to read public key from certificate '{}': {}",
                cert_path, err
            ))
        })?;
        if !certificate_key.public_eq(key) {
            return Err(ProxyError::Tls(format!(
                "certificate/key mismatch for '{}' and '{}'",
                cert_path, key_path
            )));
        }
        Ok(())
    }

    pub(super) fn tls_reload_generation_if_needed(
        listener_label: &str,
        current_generation: u64,
        listener_tls_store: &ListenerTlsReloadStore,
    ) -> Result<Option<u64>, ProxyError> {
        let next_generation = listener_tls_store
            .generation(listener_label)
            .ok_or_else(|| {
                ProxyError::Transport(format!(
                    "missing TLS reload state for listener '{}'",
                    listener_label
                ))
            })?;
        if next_generation == current_generation {
            return Ok(None);
        }
        Ok(Some(next_generation))
    }

    fn sync_tls_reload_state_if_needed(&mut self) -> Result<(), ProxyError> {
        let Some(current_generation) = Self::tls_reload_generation_if_needed(
            &self.listener_label,
            self.tls_reload_generation,
            &self.listener_tls_store,
        )?
        else {
            return Ok(());
        };

        self.quic_config = Self::build_quic_config(&self.config)?;
        self.tls_reload_generation = current_generation;
        info!(
            "Reloaded QUIC TLS configuration for listener {} at generation {}",
            self.listener_label, self.tls_reload_generation
        );
        Ok(())
    }

    pub(super) fn sync_runtime_bundle_if_needed(&mut self) -> Result<(), ProxyError> {
        let Some(runtime_bundle) = self.runtime_bundle.as_ref() else {
            return self.sync_tls_reload_state_if_needed();
        };

        let runtime = runtime_bundle.current_view();
        let current_tls_generation = runtime
            .shared_services()
            .listener_tls_store
            .generation(&self.listener_label)
            .ok_or_else(|| {
                ProxyError::Transport(format!(
                    "missing TLS reload state for listener '{}'",
                    self.listener_label
                ))
            })?;
        if runtime.generation() == self.runtime_generation
            && current_tls_generation == self.tls_reload_generation
        {
            return Ok(());
        }

        let Some(listener_config) = runtime.listener_runtime_config(&self.listener_label) else {
            return Err(ProxyError::Transport(format!(
                "runtime reload dropped listener '{}'",
                self.listener_label
            )));
        };

        let shared = runtime.shared_services();
        let generation = runtime.state();
        self.config = listener_config;
        self.listener_tls_store = Arc::clone(&shared.listener_tls_store);
        self.transport_pool = Arc::clone(&shared.transport_pool);
        self.backend_endpoints = Arc::clone(&generation.backend_endpoints);
        self.backend_dns_resolver = shared.backend_dns_resolver.clone();
        self.upstream_policies = Arc::clone(&generation.upstream_policies);
        self.upstream_pools = generation.upstream_pools.clone();
        self.upstream_inflight = generation.upstream_inflight.clone();
        self.global_inflight = Arc::clone(&generation.global_inflight);
        self.routing_index = Arc::clone(&generation.routing_index);
        self.metrics = Arc::clone(&shared.metrics);
        self.resilience = Arc::clone(&generation.resilience);
        self.watchdog = Arc::clone(&shared.watchdog);
        let settings = Self::listener_runtime_settings(&self.config);
        self.backend_timeout = settings.backend_timeout;
        self.backend_body_idle_timeout = settings.backend_body_idle_timeout;
        self.backend_body_total_timeout = settings.backend_body_total_timeout;
        self.client_body_idle_timeout = settings.client_body_idle_timeout;
        self.backend_total_request_timeout = settings.backend_total_request_timeout;
        self.inflight_acquire_wait = settings.inflight_acquire_wait;
        self.drain_timeout = settings.drain_timeout;
        self.max_active_connections = settings.max_active_connections;
        self.max_streams_per_connection = settings.max_streams_per_connection;
        self.max_request_body_bytes = settings.max_request_body_bytes;
        self.max_response_body_bytes = settings.max_response_body_bytes;
        self.request_buffer_global_cap_bytes = settings.request_buffer_global_cap_bytes;
        self.unknown_length_response_prebuffer_bytes =
            settings.unknown_length_response_prebuffer_bytes;
        self.require_client_cert = Self::runtime_listener_tls(&self.config)?
            .client_auth
            .require_client_cert;
        self.conn_rate_limiter.reconfigure(
            settings.new_connections_per_sec,
            settings.new_connections_burst,
        );
        self.source_conn_rate_limiter.reconfigure(
            settings.new_connections_per_sec,
            settings.new_connections_burst,
        );
        self.quic_config = Self::build_quic_config(&self.config)?;
        self.runtime_generation = runtime.generation();
        self.tls_reload_generation = current_tls_generation;
        info!(
            "Reloaded runtime configuration for listener {} at generation {}",
            self.listener_label, self.runtime_generation
        );
        Ok(())
    }
    fn load_tls_cert_chain_from_pem_file(
        path: &str,
        field_name: &str,
    ) -> Result<Vec<CertificateDer<'static>>, ProxyError> {
        let pem = Self::read_tls_pem_file_with_limit(path, field_name)?;
        CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<_, _>>()
            .map_err(|err| ProxyError::Tls(format!("failed to parse {field_name} PEM: {err}")))
    }

    fn load_tls_private_key_from_pem_file(
        path: &str,
        field_name: &str,
    ) -> Result<PrivateKeyDer<'static>, ProxyError> {
        let pem = Self::read_tls_pem_file_with_limit(path, field_name)?;
        PrivateKeyDer::from_pem_slice(&pem).map_err(|err| {
            ProxyError::Tls(format!(
                "failed to parse {field_name} PEM from '{}': {err}",
                path
            ))
        })
    }

    fn load_certified_key(
        cert_path: &str,
        key_path: &str,
        cert_field: &str,
        key_field: &str,
    ) -> Result<CertifiedKey, ProxyError> {
        let certs = Self::load_tls_cert_chain_from_pem_file(cert_path, cert_field)?;
        let key = Self::load_tls_private_key_from_pem_file(key_path, key_field)?;
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|err| {
            ProxyError::Tls(format!(
                "failed to parse private key from {} '{}': {}",
                key_field, key_path, err
            ))
        })?;
        let certified = CertifiedKey::new(certs, signing_key);
        certified.keys_match().map_err(|err| {
            ProxyError::Tls(format!(
                "certificate/key mismatch for {} '{}' and {} '{}': {}",
                cert_field, cert_path, key_field, key_path, err
            ))
        })?;
        Ok(certified)
    }

    fn load_tls_certificate_metadata(
        cert: &CertificateDer<'static>,
        cert_field: &str,
        cert_path: &str,
    ) -> Result<RuntimeTlsCertificateMetadata, ProxyError> {
        let (_, certificate) = parse_x509_certificate(cert.as_ref()).map_err(|err| {
            ProxyError::Tls(format!(
                "failed to parse X.509 metadata from {cert_field} '{}': {}",
                cert_path, err
            ))
        })?;

        let validity = certificate.validity();
        let mut dns_names = Vec::new();
        if let Ok(Some(san)) = certificate.tbs_certificate.subject_alternative_name() {
            for general_name in &san.value.general_names {
                if let GeneralName::DNSName(name) = general_name {
                    dns_names.push(name.to_string());
                }
            }
        }
        for common_name in certificate.subject().iter_common_name() {
            if let Ok(name) = common_name.as_str() {
                dns_names.push(name.to_string());
            }
        }
        dns_names.sort();
        dns_names.dedup();

        Ok(RuntimeTlsCertificateMetadata {
            serial_hex: certificate.tbs_certificate.raw_serial_as_string(),
            not_before_unix_seconds: validity.not_before.timestamp(),
            not_after_unix_seconds: validity.not_after.timestamp(),
            dns_names,
        })
    }

    fn load_listener_identity(
        identity: &RuntimeTlsIdentity,
        cert_field: &str,
        key_field: &str,
    ) -> Result<LoadedListenerIdentity, ProxyError> {
        let certified_key = Arc::new(Self::load_certified_key(
            &identity.cert_path,
            &identity.key_path,
            cert_field,
            key_field,
        )?);
        let leaf = certified_key.cert.first().ok_or_else(|| {
            ProxyError::Tls(format!(
                "{cert_field} '{}' did not produce a leaf certificate",
                identity.cert_path
            ))
        })?;
        let metadata = Self::load_tls_certificate_metadata(leaf, cert_field, &identity.cert_path)?;

        LoadedListenerIdentity::new(
            identity.clone(),
            certified_key,
            metadata,
            cert_field,
            &identity.cert_path,
        )
    }

    fn validate_tls_certificate_validity(
        metadata: &RuntimeTlsCertificateMetadata,
        cert_field: &str,
        cert_path: &str,
    ) -> Result<(), ProxyError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| ProxyError::Tls(format!("system clock is before Unix epoch: {err}")))?
            .as_secs();
        let now = i64::try_from(now).unwrap_or(i64::MAX);
        if metadata.not_before_unix_seconds > now {
            return Err(ProxyError::Tls(format!(
                "{cert_field} '{cert_path}' is not yet valid (not_before={}, now={now})",
                metadata.not_before_unix_seconds
            )));
        }
        if metadata.not_after_unix_seconds < now {
            return Err(ProxyError::Tls(format!(
                "{cert_field} '{cert_path}' is expired (not_after={}, now={now})",
                metadata.not_after_unix_seconds
            )));
        }
        Ok(())
    }

    fn load_client_auth_ca(
        client_auth: &ClientAuth,
    ) -> Result<Option<LoadedClientAuthCa>, ProxyError> {
        if !client_auth.enabled {
            return Ok(None);
        }

        let ca_file = client_auth.ca_file.as_ref().ok_or_else(|| {
            ProxyError::Tls(
                "listen.tls.client_auth.ca_file is required when mTLS is enabled".to_string(),
            )
        })?;
        let certs =
            Self::load_tls_cert_chain_from_pem_file(ca_file, "listen.tls.client_auth.ca_file")?;
        let mut roots = RootCertStore::empty();
        for cert in certs {
            roots.add(cert).map_err(|err| {
                ProxyError::Tls(format!(
                    "failed to add certificate from listen.tls.client_auth.ca_file '{}': {}",
                    ca_file, err
                ))
            })?;
        }

        Ok(Some(LoadedClientAuthCa {
            ca_file: ca_file.clone(),
            certificate_count: roots.len(),
            roots: Arc::new(roots),
        }))
    }

    fn load_root_store_from_pem_file(
        path: &str,
        field_name: &str,
        roots: &mut RootCertStore,
    ) -> Result<usize, ProxyError> {
        let certs = Self::load_tls_cert_chain_from_pem_file(path, field_name)?;
        let mut count = 0usize;
        for cert in certs {
            roots.add(cert).map_err(|err| {
                ProxyError::Tls(format!(
                    "failed to add certificate from {field_name} '{path}': {err}"
                ))
            })?;
            count = count.saturating_add(1);
        }
        Ok(count)
    }

    fn load_control_api_client_auth_roots(
        client_auth: &ControlApiClientAuthPolicy,
    ) -> Result<Option<Arc<RootCertStore>>, ProxyError> {
        let ControlApiClientVerifierState::Configured(material) = &client_auth.verifier else {
            return Ok(None);
        };

        let mut roots = RootCertStore::empty();
        let mut loaded_any = false;
        if let Some(ca_file) = material.ca_file.as_deref() {
            Self::load_root_store_from_pem_file(
                ca_file,
                "observability.control_api.tls.client_auth.ca_file",
                &mut roots,
            )?;
            loaded_any = true;
        }

        if let Some(ca_dir) = material.ca_dir.as_deref() {
            let entries = std::fs::read_dir(ca_dir).map_err(|err| {
                ProxyError::Tls(format!(
                    "failed to read observability.control_api.tls.client_auth.ca_dir '{}': {}",
                    ca_dir, err
                ))
            })?;
            let mut pem_files = entries
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| {
                    ProxyError::Tls(format!(
                        "failed to read entry in observability.control_api.tls.client_auth.ca_dir '{}': {}",
                        ca_dir, err
                    ))
                })?
                .into_iter()
                .map(|entry| entry.path())
                .filter(|path| path.is_file() && Self::is_pem_like_path(path))
                .collect::<Vec<_>>();
            pem_files.sort();

            for path in pem_files {
                let path_str = path.to_string_lossy().into_owned();
                Self::load_root_store_from_pem_file(
                    &path_str,
                    "observability.control_api.tls.client_auth.ca_dir",
                    &mut roots,
                )?;
                loaded_any = true;
            }
        }

        if !loaded_any {
            return Err(ProxyError::Tls(
                "control API client-auth is enabled but no CA certificates were loaded".to_string(),
            ));
        }

        Ok(Some(Arc::new(roots)))
    }

    fn is_pem_like_path(path: &Path) -> bool {
        matches!(
            path.extension().and_then(OsStr::to_str),
            Some("pem" | "crt" | "cer" | "PEM" | "CRT" | "CER")
        )
    }

    pub(super) fn load_listener_tls_material(
        config: &ListenerRuntimeConfig,
    ) -> Result<LoadedListenerTlsMaterial, ProxyError> {
        let listener_tls = Self::runtime_listener_tls(config)?;
        let default_identity = Self::load_listener_identity(
            &listener_tls.default_identity,
            "listen.tls.default_identity.cert",
            "listen.tls.default_identity.key",
        )?;

        let mut sni_identities = HashMap::new();
        for (server_name, identity) in &listener_tls.sni_identities {
            let cert_field = format!("listen.tls.certificates['{server_name}'].cert");
            let key_field = format!("listen.tls.certificates['{server_name}'].key");
            let loaded_identity = Self::load_listener_identity(identity, &cert_field, &key_field)?;
            Self::validate_loaded_sni_identity(server_name, &loaded_identity)?;
            sni_identities.insert(server_name.clone(), loaded_identity);
        }

        Ok(LoadedListenerTlsMaterial {
            default_identity,
            sni_identities,
            client_auth_ca: Self::load_client_auth_ca(&listener_tls.client_auth)?,
            client_auth: listener_tls.client_auth,
        })
    }

    fn listener_tls_inventory(loaded_tls: &LoadedListenerTlsMaterial) -> ListenerTlsInventory {
        ListenerTlsInventory {
            listener_tls: RuntimeListenerTls {
                default_identity: loaded_tls.default_identity.identity().clone(),
                sni_identities: loaded_tls
                    .sni_identities
                    .iter()
                    .map(|(server_name, identity)| {
                        (server_name.clone(), identity.identity().clone())
                    })
                    .collect(),
                client_auth: loaded_tls.client_auth.clone(),
            },
            default_identity: RuntimeLoadedTlsIdentity {
                identity: loaded_tls.default_identity.identity().clone(),
                metadata: loaded_tls.default_identity.metadata().clone(),
            },
            sni_identities: loaded_tls
                .sni_identities
                .iter()
                .map(|(server_name, identity)| {
                    (
                        server_name.clone(),
                        RuntimeLoadedTlsIdentity {
                            identity: identity.identity().clone(),
                            metadata: identity.metadata().clone(),
                        },
                    )
                })
                .collect(),
            client_auth_ca: loaded_tls.client_auth_ca.as_ref().map(|client_auth_ca| {
                RuntimeLoadedClientAuthCa {
                    ca_file: client_auth_ca.ca_file.clone(),
                    certificate_count: client_auth_ca.certificate_count,
                }
            }),
        }
    }

    fn build_server_tls_config_from_loaded(
        loaded_tls: &LoadedListenerTlsMaterial,
        enforce_client_auth: bool,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Result<RustlsServerConfig, ProxyError> {
        let verifier = Self::build_client_cert_verifier(
            &loaded_tls.client_auth,
            loaded_tls.client_auth_ca.as_ref(),
            enforce_client_auth,
        )?;
        let builder = if let Some(verifier) = verifier {
            RustlsServerConfig::builder().with_client_cert_verifier(verifier)
        } else {
            RustlsServerConfig::builder().with_no_client_auth()
        };

        let mut sni_resolver = ResolvesServerCertUsingSni::new();
        for (server_name, identity) in &loaded_tls.sni_identities {
            Self::validate_loaded_sni_identity(server_name, identity)?;
            sni_resolver
                .add(
                    server_name.as_str(),
                    identity.certified_key().as_ref().clone(),
                )
                .map_err(|err| {
                    ProxyError::Tls(format!(
                        "failed to add SNI certificate mapping for '{server_name}': {}",
                        err
                    ))
                })?;
        }
        let resolver = Arc::new(FallbackServerCertResolver {
            sni_resolver,
            fallback: loaded_tls.default_identity.certified_key().clone(),
        });
        let mut tls_config = builder.with_cert_resolver(resolver);
        tls_config.alpn_protocols = alpn_protocols;
        Ok(tls_config)
    }

    fn build_client_cert_verifier(
        client_auth: &ClientAuth,
        client_auth_ca: Option<&LoadedClientAuthCa>,
        enforce_client_auth: bool,
    ) -> Result<Option<Arc<dyn ClientCertVerifier>>, ProxyError> {
        if !enforce_client_auth || !client_auth.enabled {
            return Ok(None);
        }
        let client_auth_ca = client_auth_ca.ok_or_else(|| {
            ProxyError::Tls(
                "listen.tls.client_auth.ca_file is required when mTLS is enabled".to_string(),
            )
        })?;
        let verifier_builder = WebPkiClientVerifier::builder(client_auth_ca.roots.clone());
        let verifier = if client_auth.require_client_cert {
            verifier_builder.build()
        } else {
            verifier_builder.allow_unauthenticated().build()
        }
        .map_err(|err| {
            ProxyError::Tls(format!(
                "failed to build downstream client certificate verifier: {}",
                err
            ))
        })?;
        Ok(Some(verifier))
    }

    pub(crate) fn build_listener_client_cert_verifier(
        listener_tls: &RuntimeListenerTls,
    ) -> Result<Option<Arc<dyn ClientCertVerifier>>, ProxyError> {
        let client_auth_ca = Self::load_client_auth_ca(&listener_tls.client_auth)?;
        Self::build_client_cert_verifier(&listener_tls.client_auth, client_auth_ca.as_ref(), true)
    }

    pub(in crate::quic_listener) fn build_control_api_server_tls_config(
        config: &ListenerRuntimeConfig,
        client_auth: &ControlApiClientAuthPolicy,
    ) -> Result<Arc<RustlsServerConfig>, ProxyError> {
        let loaded_tls = Self::load_listener_tls_material(config)?;

        let builder = match client_auth.mode {
            impulse_config::config::ControlApiClientAuthMode::Disabled => {
                RustlsServerConfig::builder().with_no_client_auth()
            }
            impulse_config::config::ControlApiClientAuthMode::Optional
            | impulse_config::config::ControlApiClientAuthMode::Required => {
                let roots =
                    Self::load_control_api_client_auth_roots(client_auth)?.ok_or_else(|| {
                        ProxyError::Tls(
                            "control API client-auth roots unavailable while mTLS is enabled"
                                .to_string(),
                        )
                    })?;
                let verifier_builder = WebPkiClientVerifier::builder(roots);
                let verifier = if matches!(
                    client_auth.mode,
                    impulse_config::config::ControlApiClientAuthMode::Required
                ) {
                    verifier_builder.build()
                } else {
                    verifier_builder.allow_unauthenticated().build()
                }
                .map_err(|err| {
                    ProxyError::Tls(format!(
                        "failed to build control API client certificate verifier: {}",
                        err
                    ))
                })?;
                RustlsServerConfig::builder().with_client_cert_verifier(verifier)
            }
        };

        let mut sni_resolver = ResolvesServerCertUsingSni::new();
        for (server_name, identity) in &loaded_tls.sni_identities {
            Self::validate_loaded_sni_identity(server_name, identity)?;
            sni_resolver
                .add(
                    server_name.as_str(),
                    identity.certified_key().as_ref().clone(),
                )
                .map_err(|err| {
                    ProxyError::Tls(format!(
                        "failed to add control API SNI certificate mapping for '{server_name}': {}",
                        err
                    ))
                })?;
        }
        let resolver = Arc::new(FallbackServerCertResolver {
            sni_resolver,
            fallback: loaded_tls.default_identity.certified_key().clone(),
        });
        let mut tls_config = builder.with_cert_resolver(resolver);
        tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(tls_config))
    }

    fn validate_loaded_sni_identity(
        server_name: &str,
        identity: &LoadedListenerIdentity,
    ) -> Result<(), ProxyError> {
        if Self::certificate_covers_server_name(identity.metadata(), server_name) {
            return Ok(());
        }

        Err(ProxyError::Tls(format!(
            "failed to add SNI certificate mapping for '{server_name}': certificate SANs {:?} do not cover server name",
            identity.metadata().dns_names
        )))
    }

    fn certificate_covers_server_name(
        metadata: &RuntimeTlsCertificateMetadata,
        server_name: &str,
    ) -> bool {
        metadata
            .dns_names
            .iter()
            .any(|dns_name| Self::certificate_name_matches(dns_name, server_name))
    }

    pub(super) fn certificate_name_matches(pattern: &str, server_name: &str) -> bool {
        if pattern.eq_ignore_ascii_case(server_name) {
            return true;
        }

        let Some(suffix) = pattern.strip_prefix("*.") else {
            return false;
        };
        let suffix = suffix.to_ascii_lowercase();
        let server_name = server_name.to_ascii_lowercase();
        let Some(prefix) = server_name.strip_suffix(&suffix) else {
            return false;
        };
        let Some(label) = prefix.strip_suffix('.') else {
            return false;
        };
        !label.is_empty() && !label.contains('.')
    }

    pub(super) fn build_listener_tls_reload_state(
        config: &ListenerRuntimeConfig,
    ) -> Result<ListenerTlsReloadState, ProxyError> {
        let loaded_tls = Self::load_listener_tls_material(config)?;
        let inventory = Self::listener_tls_inventory(&loaded_tls);
        let bootstrap_server_config = Arc::new(Self::build_server_tls_config_from_loaded(
            &loaded_tls,
            true,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        )?);
        Ok(ListenerTlsReloadState {
            generation: 0,
            loaded_at_unix_ms: crate::watchdog::time::now_millis(),
            last_reload_status: "loaded".to_string(),
            inventory,
            bootstrap_server_config,
        })
    }

    pub(super) fn build_listener_tls_reload_store(
        config: &RuntimeConfig,
    ) -> Result<ListenerTlsReloadStore, ProxyError> {
        let mut listeners = HashMap::new();
        for listener_config in config.listener_runtime_configs() {
            let listener_label = Self::listener_label(&listener_config);
            let state = Self::build_listener_tls_reload_state(&listener_config)?;
            listeners.insert(listener_label, state);
        }
        Ok(ListenerTlsReloadStore::new(listeners))
    }

    #[cfg(test)]
    pub(super) fn build_server_tls_acceptor(
        config: &ListenerRuntimeConfig,
        enforce_client_auth: bool,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Result<TlsAcceptor, ProxyError> {
        let loaded_tls = Self::load_listener_tls_material(config)?;
        debug!(
            "Building rustls downstream acceptor with default cert='{}' serial={} and {} explicit SNI identities",
            loaded_tls.default_identity.identity().cert_path,
            loaded_tls.default_identity.metadata().serial_hex,
            loaded_tls.sni_identities.len()
        );
        Ok(TlsAcceptor::from(Arc::new(
            Self::build_server_tls_config_from_loaded(
                &loaded_tls,
                enforce_client_auth,
                alpn_protocols,
            )?,
        )))
    }

    pub(super) fn listener_label(config: &ListenerRuntimeConfig) -> String {
        format!(
            "{}:{}",
            config.listen.listen.address, config.listen.listen.port
        )
    }

    pub(super) fn update_listener_tls_expiry_metrics(
        metrics: &Metrics,
        listener_label: &str,
        inventory: &ListenerTlsInventory,
    ) {
        let mut certs = Vec::with_capacity(inventory.sni_identities.len() + 1);
        certs.push((
            "__default__".to_string(),
            inventory.default_identity.metadata.not_after_unix_seconds,
        ));
        certs.extend(
            inventory
                .sni_identities
                .iter()
                .map(|(server_name, identity)| {
                    (
                        server_name.clone(),
                        identity.metadata.not_after_unix_seconds,
                    )
                }),
        );
        metrics.replace_downstream_tls_cert_expiry(listener_label, certs);
    }

    pub(super) fn classify_downstream_tls_cert_selection<'a>(
        listener_tls: &'a RuntimeListenerTls,
        requested_sni: Option<&str>,
    ) -> (&'static str, &'a RuntimeTlsIdentity) {
        let normalized_sni =
            requested_sni.map(|value| value.trim().trim_end_matches('.').to_ascii_lowercase());
        if let Some(sni) = normalized_sni.as_deref()
            && let Some(identity) = listener_tls.sni_identities.get(sni)
        {
            return ("exact_sni", identity);
        }

        if requested_sni.is_none() {
            if listener_tls.sni_identities.is_empty() {
                ("default_only", &listener_tls.default_identity)
            } else {
                ("fallback_no_sni", &listener_tls.default_identity)
            }
        } else if listener_tls.sni_identities.is_empty() {
            ("default_only", &listener_tls.default_identity)
        } else {
            ("fallback_unmatched_sni", &listener_tls.default_identity)
        }
    }

    pub(in crate::quic_listener) fn classify_downstream_tls_failure_reason(
        error: &str,
    ) -> &'static str {
        let lower = error.to_ascii_lowercase();
        if lower.contains("peer sent no certificates")
            || lower.contains("peer sent no certificate")
            || lower.contains("certificate required")
        {
            "missing_client_cert"
        } else if lower.contains("unknownissuer") || lower.contains("unknown issuer") {
            "unknown_issuer"
        } else if lower.contains("expired") || lower.contains("not yet valid") {
            "expired_client_cert"
        } else if lower.contains("certificate") || lower.contains("cert") {
            "invalid_client_cert"
        } else if lower.contains("alpn")
            || lower.contains("application protocol")
            || lower.contains("no application protocol")
        {
            "alpn"
        } else {
            "handshake"
        }
    }

    pub(super) fn maybe_record_quic_tls_observation(&self, connection: &mut QuicConnection) {
        if connection.tls_observed || !connection.quic.is_established() {
            return;
        }

        let listener_label = Self::listener_label(&self.config);
        let listener_tls = match Self::runtime_listener_tls(&self.config) {
            Ok(listener_tls) => listener_tls,
            Err(err) => {
                debug!(
                    "Skipping QUIC TLS observation for listener {}: {}",
                    listener_label, err
                );
                return;
            }
        };
        let requested_sni = connection.quic.server_name();
        let (selection, identity) =
            Self::classify_downstream_tls_cert_selection(&listener_tls, requested_sni);
        let alpn = std::str::from_utf8(connection.quic.application_proto())
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or("none");
        let client_cert_present = connection.quic.peer_cert().is_some();

        self.metrics.inc_downstream_tls_handshake_success();
        self.metrics
            .record_downstream_tls_cert_selection(&listener_label, selection);
        self.metrics
            .record_downstream_tls_alpn(&listener_label, alpn);
        debug!(
            "QUIC TLS established listener={} peer={} sni={:?} selection={} cert='{}' alpn={} client_cert_present={}",
            listener_label,
            connection.peer_address,
            requested_sni,
            selection,
            identity.cert_path,
            alpn,
            client_cert_present
        );
        connection.tls_observed = true;
    }

    pub(super) fn maybe_record_quic_tls_handshake_failure(&self, connection: &mut QuicConnection) {
        if connection.tls_observed
            || connection.tls_handshake_failure_recorded
            || connection.quic.is_established()
        {
            return;
        }

        // Record as soon as a connection error is present, not just when fully closed.
        // local_error() is set the moment quiche sends CONNECTION_CLOSE, which happens
        // during the draining period before is_closed() becomes true.
        let Some(err) = connection
            .quic
            .local_error()
            .or_else(|| connection.quic.peer_error())
        else {
            return;
        };

        let reason_text = if err.reason.is_empty() {
            // QUIC CRYPTO_ERRORs (0x100–0x1ff) encode a TLS alert in the low byte (RFC 9001 §4.8).
            // Map the alert to a description that classify_downstream_tls_failure_reason can match.
            if !err.is_app && (0x100..=0x1ff).contains(&err.error_code) {
                let tls_alert = err.error_code - 0x100;
                match tls_alert {
                    120 => "no application protocol".to_string(), // ALPN mismatch
                    42 => "bad certificate".to_string(),
                    45 => "certificate expired".to_string(),
                    48 => "unknown certificate authority".to_string(),
                    _ => format!("quic tls alert={}", tls_alert),
                }
            } else {
                format!(
                    "quic handshake error code={} is_app={}",
                    err.error_code, err.is_app
                )
            }
        } else {
            String::from_utf8_lossy(&err.reason).into_owned()
        };
        let reason = Self::classify_downstream_tls_failure_reason(&reason_text);
        self.metrics
            .record_downstream_tls_handshake_failure(&Self::listener_label(&self.config), reason);
        connection.tls_handshake_failure_recorded = true;
        debug!(
            "Recorded QUIC TLS handshake failure listener={} peer={} reason={} detail={}",
            Self::listener_label(&self.config),
            connection.peer_address,
            reason,
            reason_text
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use boring::{pkey::PKey, x509::X509};
    use impulse_config::{
        config::{ClientAuth, ControlApiClientAuthMode},
        runtime::RuntimeTlsIdentity,
    };
    use rcgen::{Certificate, CertificateParams, SanType};
    use rustls::RootCertStore;
    use tempfile::tempdir;

    use super::{
        LoadedClientAuthCa, MAX_TLS_PEM_BYTES, QUICListener, RuntimeTlsCertificateMetadata,
    };
    use crate::quic_listener::control_api::security::{
        ControlApiClientAuthPolicy, ControlApiClientCaMaterial, ControlApiClientVerifierState,
    };

    fn write_test_identity_files(dir: &std::path::Path) -> RuntimeTlsIdentity {
        let mut params = CertificateParams::new(vec!["example.com".to_string()]);
        params
            .subject_alt_names
            .push(SanType::DnsName("example.com".to_string()));
        let cert = Certificate::from_params(params).expect("certificate");
        let cert_path = dir.join("listener.pem");
        let key_path = dir.join("listener.key.pem");
        std::fs::write(&cert_path, cert.serialize_pem().expect("serialize cert")).expect("cert");
        std::fs::write(&key_path, cert.serialize_private_key_pem()).expect("key");
        RuntimeTlsIdentity {
            cert_path: cert_path.to_string_lossy().to_string(),
            key_path: key_path.to_string_lossy().to_string(),
        }
    }

    fn control_api_client_auth_policy(
        ca_file: Option<String>,
        ca_dir: Option<String>,
    ) -> ControlApiClientAuthPolicy {
        ControlApiClientAuthPolicy {
            mode: ControlApiClientAuthMode::Required,
            verifier: ControlApiClientVerifierState::Configured(ControlApiClientCaMaterial {
                ca_file,
                ca_dir,
            }),
        }
    }

    #[test]
    fn read_tls_pem_file_with_limit_rejects_oversized_file() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("oversized.pem");
        std::fs::write(&path, vec![b'A'; (MAX_TLS_PEM_BYTES as usize) + 1]).expect("write");

        let err = QUICListener::read_tls_pem_file_with_limit(
            path.to_str().expect("utf-8 path"),
            "SNI cert",
        )
        .expect_err("oversized PEM must be rejected");

        let message = err.to_string();
        assert!(message.contains("exceeds the maximum supported PEM size"));
    }

    #[test]
    fn default_quic_identity_rejects_oversized_cert_file() {
        let dir = tempdir().expect("tempdir");
        let identity = write_test_identity_files(dir.path());
        std::fs::write(
            &identity.cert_path,
            vec![b'A'; (MAX_TLS_PEM_BYTES as usize) + 1],
        )
        .expect("oversized cert");

        let err = match QUICListener::build_quic_ssl_context_builder_for_identity(
            &identity,
            &ClientAuth::default(),
            None,
        ) {
            Ok(_) => panic!("oversized default cert must be rejected"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("exceeds the maximum supported PEM size")
        );
    }

    #[test]
    fn boring_quic_identity_rejects_mismatched_certificate_and_key() {
        let dir = tempdir().expect("tempdir");
        let first = write_test_identity_files(dir.path());
        let second_dir = tempdir().expect("second tempdir");
        let second = write_test_identity_files(second_dir.path());
        let certificate_pem = std::fs::read(&first.cert_path).expect("certificate");
        let key_pem = std::fs::read(&second.key_path).expect("key");
        let certificate = X509::stack_from_pem(&certificate_pem)
            .expect("parse certificate")
            .remove(0);
        let key = PKey::private_key_from_pem(&key_pem).expect("parse key");

        let error = QUICListener::validate_boring_certificate_key(
            &certificate,
            &key,
            &first.cert_path,
            &second.key_path,
        )
        .expect_err("mismatched certificate and key must be rejected");

        assert!(error.to_string().contains("certificate/key mismatch"));
    }

    #[test]
    fn tls_certificate_validity_rejects_expired_and_future_certificates() {
        let expired = RuntimeTlsCertificateMetadata {
            serial_hex: "01".to_string(),
            not_before_unix_seconds: 100,
            not_after_unix_seconds: 200,
            dns_names: vec!["example.com".to_string()],
        };
        let future = RuntimeTlsCertificateMetadata {
            serial_hex: "02".to_string(),
            not_before_unix_seconds: i64::MAX,
            not_after_unix_seconds: i64::MAX,
            dns_names: vec!["example.com".to_string()],
        };

        assert!(
            QUICListener::validate_tls_certificate_validity(
                &expired,
                "listen.tls.default_identity.cert",
                "/tmp/expired.pem",
            )
            .is_err()
        );
        assert!(
            QUICListener::validate_tls_certificate_validity(
                &future,
                "listen.tls.default_identity.cert",
                "/tmp/future.pem",
            )
            .is_err()
        );
    }

    #[test]
    fn default_quic_identity_rejects_oversized_key_file() {
        let dir = tempdir().expect("tempdir");
        let identity = write_test_identity_files(dir.path());
        std::fs::write(
            &identity.key_path,
            vec![b'A'; (MAX_TLS_PEM_BYTES as usize) + 1],
        )
        .expect("oversized key");

        let err = match QUICListener::build_quic_ssl_context_builder_for_identity(
            &identity,
            &ClientAuth::default(),
            None,
        ) {
            Ok(_) => panic!("oversized default key must be rejected"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("exceeds the maximum supported PEM size")
        );
    }

    #[test]
    fn default_quic_identity_rejects_oversized_client_auth_ca_file() {
        let dir = tempdir().expect("tempdir");
        let identity = write_test_identity_files(dir.path());
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, vec![b'A'; (MAX_TLS_PEM_BYTES as usize) + 1])
            .expect("oversized ca");
        let client_auth = ClientAuth {
            enabled: true,
            require_client_cert: true,
            ca_file: Some(ca_path.to_string_lossy().to_string()),
        };
        let loaded_ca = LoadedClientAuthCa {
            ca_file: ca_path.to_string_lossy().to_string(),
            certificate_count: 0,
            roots: Arc::new(RootCertStore::empty()),
        };

        let err = match QUICListener::build_quic_ssl_context_builder_for_identity(
            &identity,
            &client_auth,
            Some(&loaded_ca),
        ) {
            Ok(_) => panic!("oversized client-auth ca must be rejected"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("exceeds the maximum supported PEM size")
        );
    }

    #[test]
    fn control_api_client_auth_ca_dir_rejects_oversized_pem_entry() {
        let dir = tempdir().expect("tempdir");
        let ca_dir = dir.path().join("ca.d");
        std::fs::create_dir_all(&ca_dir).expect("create ca dir");
        std::fs::write(
            ca_dir.join("huge.pem"),
            vec![b'A'; (MAX_TLS_PEM_BYTES as usize) + 1],
        )
        .expect("write huge pem");

        let err = QUICListener::load_control_api_client_auth_roots(
            &control_api_client_auth_policy(None, Some(ca_dir.to_string_lossy().to_string())),
        )
        .expect_err("oversized ca_dir entry must be rejected");

        assert!(
            err.to_string()
                .contains("exceeds the maximum supported PEM size")
        );
    }

    #[test]
    fn control_api_client_auth_ca_dir_ignores_non_pem_entries() {
        let dir = tempdir().expect("tempdir");
        let ca_dir = dir.path().join("ca.d");
        std::fs::create_dir_all(&ca_dir).expect("create ca dir");
        std::fs::write(ca_dir.join("notes.txt"), b"not a pem").expect("write txt");
        let identity = write_test_identity_files(&ca_dir);
        std::fs::rename(&identity.cert_path, ca_dir.join("root.pem")).expect("rename cert");

        let roots = QUICListener::load_control_api_client_auth_roots(
            &control_api_client_auth_policy(None, Some(ca_dir.to_string_lossy().to_string())),
        )
        .expect("load roots")
        .expect("configured roots");

        assert_eq!(roots.len(), 1);
    }
}
