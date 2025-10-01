mod rustls23_shim {
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
