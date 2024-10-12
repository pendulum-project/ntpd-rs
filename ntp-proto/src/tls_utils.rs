/// The intent of this `ClientCertVerifier` is that it accepts any connections that are either
/// a.) not presenting a client certificate
/// b.) are presenting a well-formed, but otherwise not checked (against a trust root) client certificate
///
/// This is because `RusTLS` apparently doesn't accept every kind of self-signed certificate.
///
/// The only goal of this `ClientCertVerifier` is to achieve that, if a client presents a TLS certificate,
/// this certificate shows up in the .`peer_certificates()` for that connection.

#[derive(Debug)]
pub struct AllowAnyAnonymousOrCertificateBearingClient {
    supported_algs: WebPkiSupportedAlgorithms,
}

use rustls::pki_types::CertificateDer;
use rustls::{
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms},
    server::danger::ClientCertVerified,
};

impl AllowAnyAnonymousOrCertificateBearingClient {
    #[must_use] pub fn new(provider: &CryptoProvider) -> Self {
        AllowAnyAnonymousOrCertificateBearingClient {
            supported_algs: provider.signature_verification_algorithms,
        }
    }
}

impl rustls::server::danger::ClientCertVerifier for AllowAnyAnonymousOrCertificateBearingClient {
    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}
