#[cfg(feature = "rustls23")]
mod rustls23_shim {
    /// The intent of this `ClientCertVerifier` is that it accepts any connections that are either
    /// a.) not presenting a client certificate
    /// b.) are presenting a well-formed, but otherwise not checked (against a trust root) client certificate
    ///
    /// This is because `RusTLS` apparently doesn't accept every kind of self-signed certificate.
    ///
    /// The only goal of this `ClientCertVerifier` is to achieve that, if a client presents a TLS certificate,
    /// this certificate shows up in the `.peer_certificates()` for that connection.
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
        #[must_use]
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

    pub use rustls23::pki_types::InvalidDnsNameError;
    pub use rustls23::pki_types::ServerName;
    pub use rustls23::server::NoClientAuth;
    pub use rustls23::version::TLS13;
    pub use rustls23::ClientConfig;
    pub use rustls23::ClientConnection;
    pub use rustls23::ConnectionCommon;
    pub use rustls23::Error;
    pub use rustls23::RootCertStore;
    pub use rustls23::ServerConfig;
    pub use rustls23::ServerConnection;

    pub type Certificate = rustls23::pki_types::CertificateDer<'static>;
    pub type PrivateKey = rustls23::pki_types::PrivateKeyDer<'static>;

    pub mod pemfile {
        pub use rustls_native_certs7::load_native_certs;
        pub use rustls_pemfile2::certs;
        pub use rustls_pemfile2::pkcs8_private_keys;
        pub use rustls_pemfile2::private_key;

        #[must_use]
        pub fn rootstore_ref_shim(cert: &super::Certificate) -> super::Certificate {
            cert.clone()
        }
    }

    pub trait CloneKeyShim {}

    #[must_use]
    pub fn client_config_builder(
    ) -> rustls23::ConfigBuilder<rustls23::ClientConfig, rustls23::WantsVerifier> {
        ClientConfig::builder()
    }

    #[must_use]
    pub fn client_config_builder_with_protocol_versions(
        versions: &[&'static rustls23::SupportedProtocolVersion],
    ) -> rustls23::ConfigBuilder<rustls23::ClientConfig, rustls23::WantsVerifier> {
        ClientConfig::builder_with_protocol_versions(versions)
    }

    #[must_use]
    pub fn server_config_builder(
    ) -> rustls23::ConfigBuilder<rustls23::ServerConfig, rustls23::WantsVerifier> {
        ServerConfig::builder()
    }

    #[must_use]
    pub fn server_config_builder_with_protocol_versions(
        versions: &[&'static rustls23::SupportedProtocolVersion],
    ) -> rustls23::ConfigBuilder<rustls23::ServerConfig, rustls23::WantsVerifier> {
        ServerConfig::builder_with_protocol_versions(versions)
    }
}

#[cfg(feature = "rustls22")]
mod rustls22_shim {
    pub use rustls22::server::NoClientAuth;
    pub use rustls22::version::TLS13;
    pub use rustls22::ClientConfig;
    pub use rustls22::ClientConnection;
    pub use rustls22::ConnectionCommon;
    pub use rustls22::Error;
    pub use rustls22::RootCertStore;
    pub use rustls22::ServerConfig;
    pub use rustls22::ServerConnection;
    pub use rustls_pki_types::InvalidDnsNameError;
    pub use rustls_pki_types::ServerName;

    pub type Certificate = rustls_pki_types::CertificateDer<'static>;
    pub type PrivateKey = rustls_pki_types::PrivateKeyDer<'static>;

    pub mod pemfile {
        pub use rustls_native_certs7::load_native_certs;
        pub use rustls_pemfile2::certs;
        pub use rustls_pemfile2::pkcs8_private_keys;
        pub use rustls_pemfile2::private_key;

        pub fn rootstore_ref_shim(cert: &super::Certificate) -> super::Certificate {
            cert.clone()
        }
    }

    pub trait CloneKeyShim {}

    pub fn client_config_builder(
    ) -> rustls22::ConfigBuilder<rustls22::ClientConfig, rustls22::WantsVerifier> {
        ClientConfig::builder()
    }

    pub fn client_config_builder_with_protocol_versions(
        versions: &[&'static rustls22::SupportedProtocolVersion],
    ) -> rustls22::ConfigBuilder<rustls22::ClientConfig, rustls22::WantsVerifier> {
        ClientConfig::builder_with_protocol_versions(versions)
    }

    pub fn server_config_builder(
    ) -> rustls22::ConfigBuilder<rustls22::ServerConfig, rustls22::WantsVerifier> {
        ServerConfig::builder()
    }

    pub fn server_config_builder_with_protocol_versions(
        versions: &[&'static rustls22::SupportedProtocolVersion],
    ) -> rustls22::ConfigBuilder<rustls22::ServerConfig, rustls22::WantsVerifier> {
        ServerConfig::builder_with_protocol_versions(versions)
    }
}

#[cfg(feature = "rustls21")]
mod rustls21_shim {
    pub use rustls21::client::InvalidDnsNameError;
    pub use rustls21::client::ServerName;
    pub use rustls21::server::NoClientAuth;
    pub use rustls21::version::TLS13;
    pub use rustls21::Certificate;
    pub use rustls21::ClientConfig;
    pub use rustls21::ClientConnection;
    pub use rustls21::ConnectionCommon;
    pub use rustls21::Error;
    pub use rustls21::PrivateKey;
    pub use rustls21::RootCertStore;
    pub use rustls21::ServerConfig;
    pub use rustls21::ServerConnection;

    pub fn client_config_builder(
    ) -> rustls21::ConfigBuilder<rustls21::ClientConfig, rustls21::WantsVerifier> {
        ClientConfig::builder().with_safe_defaults()
    }

    pub fn server_config_builder(
    ) -> rustls21::ConfigBuilder<rustls21::ServerConfig, rustls21::WantsVerifier> {
        ServerConfig::builder().with_safe_defaults()
    }

    pub fn client_config_builder_with_protocol_versions(
        versions: &[&'static rustls21::SupportedProtocolVersion],
    ) -> rustls21::ConfigBuilder<rustls21::ClientConfig, rustls21::WantsVerifier> {
        // Expect is ok here as this should never fail (not user controlled)
        ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(versions)
            .expect("Could not set protocol versions")
    }
    pub fn server_config_builder_with_protocol_versions(
        versions: &[&'static rustls21::SupportedProtocolVersion],
    ) -> rustls21::ConfigBuilder<rustls21::ServerConfig, rustls21::WantsVerifier> {
        // Expect is ok here as this should never fail (not user controlled)
        ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(versions)
            .expect("Could not set protocol versions")
    }

    pub trait CloneKeyShim {
        fn clone_key(&self) -> Self;
    }

    impl CloneKeyShim for PrivateKey {
        fn clone_key(&self) -> Self {
            self.clone()
        }
    }

    pub mod pemfile {
        enum Either<T, U> {
            L(T),
            R(U),
        }
        impl<T, U, V> Iterator for Either<T, U>
        where
            T: Iterator<Item = V>,
            U: Iterator<Item = V>,
        {
            type Item = V;

            fn next(&mut self) -> Option<Self::Item> {
                match self {
                    Self::L(l) => l.next(),
                    Self::R(r) => r.next(),
                }
            }
        }

        pub fn certs(
            rd: &mut dyn std::io::BufRead,
        ) -> impl Iterator<Item = Result<super::Certificate, std::io::Error>> {
            match rustls_pemfile1::certs(rd) {
                Ok(v) => Either::L(v.into_iter().map(super::Certificate).map(Ok)),
                Err(e) => Either::R(core::iter::once(Err(e))),
            }
        }

        pub fn pkcs8_private_keys(
            rd: &mut dyn std::io::BufRead,
        ) -> impl Iterator<Item = Result<super::PrivateKey, std::io::Error>> {
            match rustls_pemfile1::pkcs8_private_keys(rd) {
                Ok(v) => Either::L(v.into_iter().map(super::PrivateKey).map(Ok)),
                Err(e) => Either::R(core::iter::once(Err(e))),
            }
        }

        pub fn private_key(
            rd: &mut dyn std::io::BufRead,
        ) -> Result<Option<super::PrivateKey>, std::io::Error> {
            for item in std::iter::from_fn(|| rustls_pemfile1::read_one(rd).transpose()) {
                match item {
                    Ok(
                        rustls_pemfile1::Item::RSAKey(key)
                        | rustls_pemfile1::Item::PKCS8Key(key)
                        | rustls_pemfile1::Item::ECKey(key),
                    ) => return Ok(Some(super::PrivateKey(key))),
                    Err(e) => return Err(e),
                    _ => {}
                }
            }

            Ok(None)
        }

        pub fn load_native_certs() -> Result<Vec<super::Certificate>, std::io::Error> {
            Ok(rustls_native_certs6::load_native_certs()?
                .into_iter()
                .map(|v| super::Certificate(v.0))
                .collect())
        }

        pub fn rootstore_ref_shim(cert: &super::Certificate) -> &super::Certificate {
            cert
        }
    }
}

#[cfg(feature = "rustls23")]
pub use rustls23_shim::*;

#[cfg(all(feature = "rustls22", not(feature = "rustls23")))]
pub use rustls22_shim::*;

#[cfg(all(
    feature = "rustls21",
    not(any(feature = "rustls23", feature = "rustls22"))
))]
pub use rustls21_shim::*;
