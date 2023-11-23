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
