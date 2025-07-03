mod rustls23_shim {
    /// The intent of this ClientCertVerifier is that it accepts any connections that are either
    /// a.) not presenting a client certificate
    /// b.) are presenting a well-formed, but otherwise not checked (against a trust root) client certificate
    ///
    /// This is because RusTLS apparently doesn't accept every kind of self-signed certificate.
    ///
    /// The only goal of this ClientCertVerifier is to achieve that, if a client presents a TLS certificate,
    /// this certificate shows up in the .peer_certificates() for that connection.
    #[cfg(feature = "nts-pool")]
    #[derive(Debug)]
    pub struct AllowAnyAnonymousOrCertificateBearingClient {
        supported_algs: WebPkiSupportedAlgorithms,
    }

    #[cfg(feature = "nts-pool")]
    use rustls23::{
        crypto::{CryptoProvider, WebPkiSupportedAlgorithms},
        pki_types::CertificateDer,
        server::danger::ClientCertVerified,
    };

    #[cfg(feature = "nts-pool")]
    impl AllowAnyAnonymousOrCertificateBearingClient {
        pub fn new(provider: &CryptoProvider) -> Self {
            AllowAnyAnonymousOrCertificateBearingClient {
                supported_algs: provider.signature_verification_algorithms,
            }
        }
    }

    #[cfg(feature = "nts-pool")]
    impl rustls23::server::danger::ClientCertVerifier for AllowAnyAnonymousOrCertificateBearingClient {
        fn verify_client_cert(
            &self,
            _end_entity: &CertificateDer,
            _intermediates: &[CertificateDer],
            _now: rustls23::pki_types::UnixTime,
        ) -> Result<ClientCertVerified, rustls23::Error> {
            Ok(ClientCertVerified::assertion())
        }

        fn client_auth_mandatory(&self) -> bool {
            false
        }

        fn root_hint_subjects(&self) -> &[rustls23::DistinguishedName] {
            &[]
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls23::pki_types::CertificateDer<'_>,
            dss: &rustls23::DigitallySignedStruct,
        ) -> Result<rustls23::client::danger::HandshakeSignatureValid, rustls23::Error> {
            rustls23::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls23::pki_types::CertificateDer<'_>,
            dss: &rustls23::DigitallySignedStruct,
        ) -> Result<rustls23::client::danger::HandshakeSignatureValid, rustls23::Error> {
            rustls23::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
        }

        fn supported_verify_schemes(&self) -> Vec<rustls23::SignatureScheme> {
            self.supported_algs.supported_schemes()
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
