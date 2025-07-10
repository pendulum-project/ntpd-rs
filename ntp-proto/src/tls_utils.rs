mod rustls23_shim {
    /// The intent of this AnonymousOrCertificateForDomainVerifier is that it accepts any client connections that are either
    /// a.) not presenting a client certificate
    /// b.) are presenting a well-formed, valid certificate for one of the domains specified as acceptable.
    #[cfg(feature = "nts-pool")]
    #[derive(Debug)]
    pub struct AnonymousOrCertificateForDomainVerifier {
        domains: Vec<ServerName<'static>>,
        inner: rustls_platform_verifier::Verifier,
    }

    #[cfg(feature = "nts-pool")]
    impl AnonymousOrCertificateForDomainVerifier {
        pub fn new(
            provider: std::sync::Arc<rustls23::crypto::CryptoProvider>,
            extra_roots: impl IntoIterator<Item = Certificate>,
            domains: Vec<ServerName<'static>>,
        ) -> Result<Self, rustls23::Error> {
            Ok(Self {
                domains,
                inner: rustls_platform_verifier::Verifier::new_with_extra_roots(extra_roots)?
                    .with_provider(provider),
            })
        }
    }

    #[cfg(feature = "nts-pool")]
    impl rustls23::server::danger::ClientCertVerifier for AnonymousOrCertificateForDomainVerifier {
        fn root_hint_subjects(&self) -> &[rustls23::DistinguishedName] {
            &[]
        }

        fn verify_client_cert(
            &self,
            end_entity: &rustls23::pki_types::CertificateDer<'_>,
            intermediates: &[rustls23::pki_types::CertificateDer<'_>],
            now: rustls23::pki_types::UnixTime,
        ) -> Result<rustls23::server::danger::ClientCertVerified, Error> {
            use rustls23::client::danger::ServerCertVerifier;
            for server in &self.domains {
                if self
                    .inner
                    .verify_server_cert(end_entity, intermediates, server, &[], now)
                    .is_ok()
                {
                    return Ok(rustls23::server::danger::ClientCertVerified::assertion());
                }
            }

            Err(Error::InvalidCertificate(
                rustls23::CertificateError::NotValidForName,
            ))
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls23::pki_types::CertificateDer<'_>,
            dss: &rustls23::DigitallySignedStruct,
        ) -> Result<rustls23::client::danger::HandshakeSignatureValid, Error> {
            use rustls23::client::danger::ServerCertVerifier;
            self.inner.verify_tls12_signature(message, cert, dss)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls23::pki_types::CertificateDer<'_>,
            dss: &rustls23::DigitallySignedStruct,
        ) -> Result<rustls23::client::danger::HandshakeSignatureValid, Error> {
            use rustls23::client::danger::ServerCertVerifier;
            self.inner.verify_tls13_signature(message, cert, dss)
        }

        fn supported_verify_schemes(&self) -> Vec<rustls23::SignatureScheme> {
            use rustls23::client::danger::ServerCertVerifier;
            self.inner.supported_verify_schemes()
        }

        fn client_auth_mandatory(&self) -> bool {
            false
        }
    }

    pub use rustls23::ClientConfig;
    pub use rustls23::ClientConnection;
    pub use rustls23::ConnectionCommon;
    pub use rustls23::Error;
    pub use rustls23::RootCertStore;
    pub use rustls23::ServerConfig;
    pub use rustls23::ServerConnection;
    pub use rustls23::pki_types::InvalidDnsNameError;
    pub use rustls23::pki_types::ServerName;
    pub use rustls23::server::NoClientAuth;
    pub use rustls23::version::TLS13;

    pub type Certificate = rustls23::pki_types::CertificateDer<'static>;
    pub type PrivateKey = rustls23::pki_types::PrivateKeyDer<'static>;

    pub use rustls_platform_verifier::Verifier as PlatformVerifier;

    pub mod pemfile {
        use rustls23::pki_types::{
            CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject,
        };

        pub fn certs(
            rd: &mut dyn std::io::BufRead,
        ) -> impl Iterator<Item = Result<CertificateDer<'static>, std::io::Error>> + '_ {
            CertificateDer::pem_reader_iter(rd).map(|item| {
                item.map_err(|err| match err {
                    rustls23::pki_types::pem::Error::Io(error) => error,
                    _ => std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string()),
                })
            })
        }

        pub fn private_key(
            rd: &mut dyn std::io::BufRead,
        ) -> Result<PrivateKeyDer<'static>, std::io::Error> {
            PrivateKeyDer::from_pem_reader(rd).map_err(|err| match err {
                rustls23::pki_types::pem::Error::Io(error) => error,
                _ => std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string()),
            })
        }

        pub fn pkcs8_private_keys(
            rd: &mut dyn std::io::BufRead,
        ) -> impl Iterator<Item = Result<PrivatePkcs8KeyDer<'static>, std::io::Error>> + '_
        {
            PrivatePkcs8KeyDer::pem_reader_iter(rd).map(|item| {
                item.map_err(|err| match err {
                    rustls23::pki_types::pem::Error::Io(error) => error,
                    _ => std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string()),
                })
            })
        }
    }

    pub trait CloneKeyShim {}

    pub fn client_config_builder()
    -> rustls23::ConfigBuilder<rustls23::ClientConfig, rustls23::WantsVerifier> {
        ClientConfig::builder()
    }

    pub fn client_config_builder_with_protocol_versions(
        versions: &[&'static rustls23::SupportedProtocolVersion],
    ) -> rustls23::ConfigBuilder<rustls23::ClientConfig, rustls23::WantsVerifier> {
        ClientConfig::builder_with_protocol_versions(versions)
    }

    pub fn server_config_builder()
    -> rustls23::ConfigBuilder<rustls23::ServerConfig, rustls23::WantsVerifier> {
        ServerConfig::builder()
    }

    pub fn server_config_builder_with_protocol_versions(
        versions: &[&'static rustls23::SupportedProtocolVersion],
    ) -> rustls23::ConfigBuilder<rustls23::ServerConfig, rustls23::WantsVerifier> {
        ServerConfig::builder_with_protocol_versions(versions)
    }
}

pub use rustls23_shim::*;
