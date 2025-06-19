use std::{borrow::Cow, sync::Arc};

use rustls23::{
    pki_types::{CertificateDer, ServerName},
    version::TLS13,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;

use crate::{
    cookiestash::CookieStash,
    nts::messages::{KeyExchangeResponse, Request},
    packet::{AesSivCmac256, AesSivCmac512, Cipher},
    source::{ProtocolVersion, SourceNtsData},
    tls_utils, NTP_DEFAULT_PORT,
};

mod messages;
mod record;

/// From https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
enum AeadAlgorithm {
    AeadAesSivCmac256,
    AeadAesSivCmac512,
    Unknown(u16),
}

impl From<u16> for AeadAlgorithm {
    fn from(value: u16) -> Self {
        match value {
            15 => Self::AeadAesSivCmac256,
            17 => Self::AeadAesSivCmac512,
            v => Self::Unknown(v),
        }
    }
}

impl From<AeadAlgorithm> for u16 {
    fn from(value: AeadAlgorithm) -> Self {
        match value {
            AeadAlgorithm::AeadAesSivCmac256 => 15,
            AeadAlgorithm::AeadAesSivCmac512 => 17,
            AeadAlgorithm::Unknown(v) => v,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
enum NextProtocol {
    NTPv4,
    DraftNTPv5,
    Unknown(u16),
}

impl From<u16> for NextProtocol {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::NTPv4,
            0x8001 => Self::DraftNTPv5,
            v => Self::Unknown(v),
        }
    }
}

impl From<NextProtocol> for u16 {
    fn from(value: NextProtocol) -> Self {
        match value {
            NextProtocol::NTPv4 => 0,
            NextProtocol::DraftNTPv5 => 0x8001,
            NextProtocol::Unknown(v) => v,
        }
    }
}

fn extract_key_bytes<T: Default + AsMut<[u8]>, ConnectionData>(
    tls_connection: &tls_utils::ConnectionCommon<ConnectionData>,
    context: &[u8],
) -> Result<T, tls_utils::Error> {
    let mut key = T::default();
    tls_connection.export_keying_material(
        &mut key,
        b"EXPORTER-network-time-security",
        Some(context),
    )?;

    Ok(key)
}

struct NtsKeys {
    c2s: Box<dyn Cipher>,
    s2c: Box<dyn Cipher>,
}

impl NtsKeys {
    fn extract_from_connection<T>(
        tls_connection: &tls_utils::ConnectionCommon<T>,
        protocol: NextProtocol,
        algorithm: AeadAlgorithm,
    ) -> Result<Self, NtsError> {
        let protocol_id: u16 = protocol.into();
        let algorithm_id: u16 = algorithm.into();

        let c2s_context = &[
            (protocol_id >> 8) as u8,
            protocol_id as u8,
            (algorithm_id >> 8) as u8,
            algorithm_id as u8,
            0,
        ];
        let s2c_context = &[
            (protocol_id >> 8) as u8,
            protocol_id as u8,
            (algorithm_id >> 8) as u8,
            algorithm_id as u8,
            1,
        ];

        match algorithm {
            AeadAlgorithm::AeadAesSivCmac256 => Ok(NtsKeys {
                c2s: Box::new(AesSivCmac256::new(extract_key_bytes(
                    tls_connection,
                    c2s_context,
                )?)),
                s2c: Box::new(AesSivCmac256::new(extract_key_bytes(
                    tls_connection,
                    s2c_context,
                )?)),
            }),
            AeadAlgorithm::AeadAesSivCmac512 => Ok(NtsKeys {
                c2s: Box::new(AesSivCmac512::new(extract_key_bytes(
                    tls_connection,
                    c2s_context,
                )?)),
                s2c: Box::new(AesSivCmac512::new(extract_key_bytes(
                    tls_connection,
                    s2c_context,
                )?)),
            }),
            AeadAlgorithm::Unknown(_) => Err(NtsError::Invalid),
        }
    }
}

#[cfg(feature = "nts-pool")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AlgorithmDescription {
    id: AeadAlgorithm,
    keysize: u16,
}

#[cfg(feature = "nts-pool")]
impl AeadAlgorithm {
    #[allow(unused)]
    fn description(self) -> Option<AlgorithmDescription> {
        use crate::packet::{AesSivCmac256, AesSivCmac512};

        match self {
            AeadAlgorithm::AeadAesSivCmac256 => Some(AlgorithmDescription {
                id: self,
                keysize: AesSivCmac256::key_size()
                    .try_into()
                    .expect("Aead algorithm has oversized keys"),
            }),
            AeadAlgorithm::AeadAesSivCmac512 => Some(AlgorithmDescription {
                id: self,
                keysize: AesSivCmac512::key_size()
                    .try_into()
                    .expect("Aead algorithm has oversized keys"),
            }),
            AeadAlgorithm::Unknown(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    UnrecognizedCriticalRecord,
    BadRequest,
    InternalServerError,
    Unknown(u16),
}

impl From<u16> for ErrorCode {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::UnrecognizedCriticalRecord,
            1 => Self::BadRequest,
            2 => Self::InternalServerError,
            v => Self::Unknown(v),
        }
    }
}

impl From<ErrorCode> for u16 {
    fn from(value: ErrorCode) -> Self {
        match value {
            ErrorCode::UnrecognizedCriticalRecord => 0,
            ErrorCode::BadRequest => 1,
            ErrorCode::InternalServerError => 2,
            ErrorCode::Unknown(v) => v,
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorCode::UnrecognizedCriticalRecord => f.write_str("Unrecognized critical record"),
            ErrorCode::BadRequest => f.write_str("Bad request"),
            ErrorCode::InternalServerError => f.write_str("Internal server error"),
            ErrorCode::Unknown(id) => write!(f, "Unknown({})", id),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WarningCode {
    Unknown(u16),
}

impl From<u16> for WarningCode {
    fn from(value: u16) -> Self {
        Self::Unknown(value)
    }
}

impl From<WarningCode> for u16 {
    fn from(value: WarningCode) -> Self {
        match value {
            WarningCode::Unknown(v) => v,
        }
    }
}

/// Error generated during the parsing of NTS messages.
#[derive(Debug)]
pub enum NtsError {
    IO(std::io::Error),
    Tls(tls_utils::Error),
    Dns(tls_utils::InvalidDnsNameError),
    UnrecognizedCriticalRecord,
    Invalid,
    NoOverlappingProtocol,
    NoOverlappingAlgorithm,
    UnknownWarning(u16),
    Error(ErrorCode),
    #[cfg(feature = "nts-pool")]
    AeadNotSupported(u16),
    #[cfg(feature = "nts-pool")]
    IncorrectSizedKey,
}

impl From<std::io::Error> for NtsError {
    fn from(value: std::io::Error) -> Self {
        Self::IO(value)
    }
}

impl From<tls_utils::Error> for NtsError {
    fn from(value: tls_utils::Error) -> Self {
        Self::Tls(value)
    }
}

impl From<tls_utils::InvalidDnsNameError> for NtsError {
    fn from(value: tls_utils::InvalidDnsNameError) -> Self {
        Self::Dns(value)
    }
}

impl std::fmt::Display for NtsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NtsError::IO(error) => error.fmt(f),
            NtsError::Tls(error) => error.fmt(f),
            NtsError::Dns(error) => error.fmt(f),
            NtsError::UnrecognizedCriticalRecord => f.write_str("Unrecognized critical record"),
            NtsError::Invalid => f.write_str("Invalid request or response"),
            NtsError::NoOverlappingProtocol => f.write_str("No overlap in supported protocols"),
            NtsError::NoOverlappingAlgorithm => {
                f.write_str("No overlap in supported AEAD algorithms")
            }
            NtsError::UnknownWarning(code) => {
                write!(f, "Received unknown warning from remote: {}", code)
            }
            NtsError::Error(error) => write!(f, "Received error from remote: {}", error),
            #[cfg(feature = "nts-pool")]
            NtsError::AeadNotSupported(v) => {
                write!(f, "Received fixed key request using unknown AEAD({})", v)
            }
            #[cfg(feature = "nts-pool")]
            NtsError::IncorrectSizedKey => {
                write!(f, "Received fix key request with incorrectly sized key(s)")
            }
        }
    }
}

impl std::error::Error for NtsError {}

#[derive(Debug)]
#[allow(unused)]
pub struct KeyExchangeResult {
    pub remote: String,
    pub port: u16,
    pub nts: Box<SourceNtsData>,
    pub protocol_version: ProtocolVersion,
}

#[derive(Debug, Clone)]
pub struct NtsClientConfig {
    pub certificates: Arc<[CertificateDer<'static>]>,
    pub protocol_version: ProtocolVersion,
}

struct KeyExchangeClient {
    connector: TlsConnector,
    protocols: Box<[NextProtocol]>,
    algorithms: Box<[AeadAlgorithm]>,
}

impl KeyExchangeClient {
    #[allow(unused)]
    pub fn new(config: NtsClientConfig) -> Result<Self, NtsError> {
        let builder = tls_utils::ClientConfig::builder_with_protocol_versions(&[&TLS13]);
        let verifier =
            tls_utils::PlatformVerifier::new_with_extra_roots(config.certificates.iter().cloned())?
                .with_provider(builder.crypto_provider().clone());
        let mut tls_config = builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        tls_config.alpn_protocols = vec![b"ntske/1".to_vec()];

        Ok(KeyExchangeClient {
            connector: TlsConnector::from(Arc::new(tls_config)),
            protocols: match config.protocol_version {
                ProtocolVersion::V4 => [NextProtocol::NTPv4].into(),
                ProtocolVersion::V5 => [NextProtocol::DraftNTPv5].into(),
                _ => [NextProtocol::DraftNTPv5, NextProtocol::NTPv4].into(),
            },
            algorithms: [
                AeadAlgorithm::AeadAesSivCmac512,
                AeadAlgorithm::AeadAesSivCmac256,
            ]
            .into(),
        })
    }

    #[allow(unused)]
    pub async fn exchange_keys(
        &self,
        io: impl AsyncRead + AsyncWrite + Unpin,
        server_name: String,
    ) -> Result<KeyExchangeResult, NtsError> {
        let request = Request::KeyExchange {
            algorithms: self.algorithms.as_ref().into(),
            protocols: self.protocols.as_ref().into(),
        };

        let mut io = self
            .connector
            .connect(ServerName::try_from(server_name.clone())?, io)
            .await?;

        request.serialize(&mut io).await?;

        let response = KeyExchangeResponse::parse(&mut io).await?;

        let keys = NtsKeys::extract_from_connection(
            io.get_ref().1,
            response.protocol,
            response.algorithm,
        )?;

        let mut cookies = CookieStash::default();
        for cookie in response.cookies.into_owned().into_iter() {
            cookies.store(cookie.into_owned());
        }

        Ok(KeyExchangeResult {
            remote: response
                .server
                .unwrap_or(Cow::Owned(server_name))
                .into_owned(),
            port: response.port.unwrap_or(NTP_DEFAULT_PORT),
            nts: Box::new(SourceNtsData {
                cookies,
                c2s: keys.c2s,
                s2c: keys.s2c,
            }),
            protocol_version: match response.protocol {
                NextProtocol::NTPv4 => ProtocolVersion::V4,
                NextProtocol::DraftNTPv5 => ProtocolVersion::V5,
                NextProtocol::Unknown(_) => return Err(NtsError::Invalid),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_algorithm_encoding() {
        for i in 0..=u16::MAX {
            assert_eq!(i, u16::from(AeadAlgorithm::from(i)));
        }
    }

    #[test]
    fn test_next_protocol_encoding() {
        for i in 0..=u16::MAX {
            assert_eq!(i, u16::from(NextProtocol::from(i)));
        }
    }

    #[test]
    fn test_error_code_encoding() {
        for i in 0..=u16::MAX {
            assert_eq!(i, u16::from(ErrorCode::from(i)));
        }
    }

    #[test]
    fn test_warning_code_encoding() {
        for i in 0..=u16::MAX {
            assert_eq!(i, u16::from(WarningCode::from(i)));
        }
    }
}
