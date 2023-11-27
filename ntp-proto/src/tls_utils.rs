/// The intent of this ClientCertVerifier is that it accepts any connections that are either
/// a.) not presenting a client certificicate
/// b.) are presenting a well-formed, but otherwise not checked (against a trust root) client certificate
///
/// This is because RusTLS apparently doesn't accept every kind of self-signed certificate.
///
/// The only goal of this ClientCertVerifier is to achieve that, if a client presents a TLS certificate,
/// this certificate shows up in the .peer_certificates() for that connection.

pub struct AllowAnyAnonymousOrCertificateBearingClient;

use rustls::{server::ClientCertVerified, Certificate};

impl rustls::server::ClientCertVerifier for AllowAnyAnonymousOrCertificateBearingClient {
    fn client_auth_root_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _now: std::time::SystemTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }
}
