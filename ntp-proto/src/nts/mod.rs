use std::{borrow::Cow, sync::Arc};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::{
    DecodedServerCookie, NTP_DEFAULT_PORT,
    cookiestash::CookieStash,
    generic::NtpVersion,
    keyset::KeySet,
    nts::messages::{ErrorResponse, NoOverlapResponse},
    packet::{AesSivCmac256, AesSivCmac512, Cipher},
    source::{ProtocolVersion, SourceNtsData},
    tls_utils::{self, Certificate, PrivateKey, ServerName, TLS13},
};

#[cfg(feature = "__internal-fuzz")]
pub use messages::{KeyExchangeResponse, Request};
#[cfg(not(feature = "__internal-fuzz"))]
use messages::{KeyExchangeResponse, Request};
#[cfg(feature = "__internal-fuzz")]
pub use record::NtsRecord;

mod messages;
mod record;

const DEFAULT_NUMBER_OF_COOKIES: usize = 8;

/// From https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum AeadAlgorithm {
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
            ErrorCode::Unknown(id) => write!(f, "Unknown({id})"),
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
    NoCookie,
    NoOverlappingProtocol,
    NoOverlappingAlgorithm,
    UnknownWarning(u16),
    Error(ErrorCode),
    #[cfg(feature = "nts-pool")]
    AeadNotSupported(u16),
    #[cfg(feature = "nts-pool")]
    IncorrectSizedKey,
    #[cfg(feature = "nts-pool")]
    NotPermitted,
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
            NtsError::NoCookie => f.write_str("Remote provided no cookies"),
            NtsError::NoOverlappingProtocol => f.write_str("No overlap in supported protocols"),
            NtsError::NoOverlappingAlgorithm => {
                f.write_str("No overlap in supported AEAD algorithms")
            }
            NtsError::UnknownWarning(code) => {
                write!(f, "Received unknown warning from remote: {code}")
            }
            NtsError::Error(error) => write!(f, "Received error from remote: {error}"),
            #[cfg(feature = "nts-pool")]
            NtsError::AeadNotSupported(v) => {
                write!(f, "Received fixed key request using unknown AEAD({v})")
            }
            #[cfg(feature = "nts-pool")]
            NtsError::IncorrectSizedKey => {
                write!(f, "Received fix key request with incorrectly sized key(s)")
            }
            #[cfg(feature = "nts-pool")]
            NtsError::NotPermitted => write!(f, "Request not permitted without authentication"),
        }
    }
}

impl std::error::Error for NtsError {}

#[derive(Debug)]
pub struct KeyExchangeResult {
    pub remote: String,
    pub port: u16,
    pub nts: Box<SourceNtsData>,
    pub protocol_version: ProtocolVersion,
}

#[derive(Debug, Clone)]
pub struct NtsClientConfig {
    pub certificates: Arc<[Certificate]>,
    pub protocol_version: ProtocolVersion,
}

impl Default for NtsClientConfig {
    fn default() -> Self {
        Self {
            certificates: Default::default(),
            protocol_version: ProtocolVersion::V4,
        }
    }
}

pub struct KeyExchangeClient {
    connector: TlsConnector,
    protocols: Box<[NextProtocol]>,
    algorithms: Box<[AeadAlgorithm]>,
}

impl KeyExchangeClient {
    pub fn new(config: NtsClientConfig) -> Result<Self, NtsError> {
        let builder = tls_utils::client_config_builder_with_protocol_versions(&[&TLS13]);
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

    pub async fn exchange_keys(
        &self,
        io: impl AsyncRead + AsyncWrite + Unpin,
        server_name: String,
        #[cfg_attr(not(feature = "nts-pool"), allow(unused))] denied_servers: impl IntoIterator<
            Item = Cow<'_, str>,
        >,
    ) -> Result<KeyExchangeResult, NtsError> {
        let request = Request::KeyExchange {
            algorithms: self.algorithms.as_ref().into(),
            protocols: self.protocols.as_ref().into(),
            #[cfg(feature = "nts-pool")]
            denied_servers: denied_servers.into_iter().collect::<Vec<_>>().into(),
        };

        let mut io = self
            .connector
            .connect(ServerName::try_from(server_name.clone())?, io)
            .await?;

        // Serialize request first to a buffer to ensure it is most likely to be sent as a
        // single packet, which ntpsec needs.
        let mut req_buf = vec![];
        request.serialize(&mut req_buf).await?;
        io.write_all(req_buf.as_slice()).await?;

        io.flush().await?;

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

        if cookies.is_empty() {
            return Err(NtsError::NoCookie);
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

#[derive(Debug)]
pub struct NtsServerConfig {
    pub certificate_chain: Vec<Certificate>,
    pub private_key: PrivateKey,
    pub accepted_versions: Vec<NtpVersion>,
    pub server: Option<String>,
    pub port: Option<u16>,
    #[cfg(feature = "nts-pool")]
    pub pool_authentication_tokens: Vec<String>,
}

pub struct KeyExchangeServer {
    acceptor: TlsAcceptor,
    protocols: Box<[NextProtocol]>,
    #[cfg(feature = "nts-pool")]
    algorithms: Box<[AlgorithmDescription]>,
    #[cfg(feature = "nts-pool")]
    pool_authentication_tokens: Box<[String]>,
    server: Option<String>,
    port: Option<u16>,
}

impl KeyExchangeServer {
    pub fn new(config: NtsServerConfig) -> Result<Self, NtsError> {
        let mut server_config = tls_utils::server_config_builder_with_protocol_versions(&[&TLS13])
            .with_no_client_auth()
            .with_single_cert(config.certificate_chain, config.private_key)?;
        server_config.alpn_protocols = vec![b"ntske/1".to_vec()];

        let protocols = config
            .accepted_versions
            .into_iter()
            .filter_map(|v| match v {
                NtpVersion::V3 => None,
                NtpVersion::V4 => Some(NextProtocol::NTPv4),
                NtpVersion::V5 => Some(NextProtocol::DraftNTPv5),
            })
            .collect();

        Ok(KeyExchangeServer {
            acceptor: TlsAcceptor::from(Arc::new(server_config)),
            protocols,
            #[cfg(feature = "nts-pool")]
            algorithms: Box::new([
                AeadAlgorithm::AeadAesSivCmac256
                    .description()
                    .expect("Missing description for AEAD algorithm"),
                AeadAlgorithm::AeadAesSivCmac512
                    .description()
                    .expect("Missing description for AEAD algorithm"),
            ]),
            #[cfg(feature = "nts-pool")]
            pool_authentication_tokens: config.pool_authentication_tokens.into(),
            server: config.server,
            port: config.port,
        })
    }

    pub async fn handle_connection(
        &self,
        io: impl AsyncRead + AsyncWrite + Unpin,
        keyset: &KeySet,
    ) -> Result<(), NtsError> {
        let mut io = self.acceptor.accept(io).await?;

        let request = match Request::parse(&mut io).await {
            Ok(request) => request,
            Err(NtsError::Invalid) => {
                ErrorResponse {
                    errorcode: ErrorCode::BadRequest,
                }
                .serialize(&mut io)
                .await?;
                io.shutdown().await?;
                return Err(NtsError::Invalid);
            }
            #[cfg(feature = "nts-pool")]
            Err(NtsError::NotPermitted) => {
                ErrorResponse {
                    errorcode: ErrorCode::BadRequest,
                }
                .serialize(&mut io)
                .await?;
                io.shutdown().await?;
                return Err(NtsError::NotPermitted);
            }
            Err(NtsError::UnrecognizedCriticalRecord) => {
                ErrorResponse {
                    errorcode: ErrorCode::UnrecognizedCriticalRecord,
                }
                .serialize(&mut io)
                .await?;
                io.shutdown().await?;
                return Err(NtsError::Invalid);
            }
            Err(v) => return Err(v),
        };

        match request {
            Request::KeyExchange {
                algorithms,
                protocols,
                ..
            } => {
                let protocol = protocols
                    .iter()
                    .find(|v| self.protocols.contains(v))
                    .cloned();
                let algorithm = algorithms
                    .iter()
                    .find(|v| !matches!(v, AeadAlgorithm::Unknown(_)))
                    .cloned();

                let result = match (protocol, algorithm) {
                    (None, _) => {
                        NoOverlapResponse::NoOverlappingProtocol
                            .serialize(&mut io)
                            .await?;

                        Err(NtsError::NoOverlappingProtocol)
                    }
                    (Some(protocol), None) => {
                        NoOverlapResponse::NoOverlappingAlgorithm { protocol }
                            .serialize(&mut io)
                            .await?;

                        Err(NtsError::NoOverlappingAlgorithm)
                    }
                    (Some(protocol), Some(algorithm)) => {
                        let keys = match NtsKeys::extract_from_connection(
                            io.get_ref().1,
                            protocol,
                            algorithm,
                        ) {
                            Ok(keys) => keys,
                            Err(e) => {
                                ErrorResponse {
                                    errorcode: ErrorCode::InternalServerError,
                                }
                                .serialize(&mut io)
                                .await?;
                                return Err(e);
                            }
                        };

                        let cookie = DecodedServerCookie {
                            algorithm,
                            s2c: keys.s2c,
                            c2s: keys.c2s,
                        };

                        let mut cookies = Vec::with_capacity(DEFAULT_NUMBER_OF_COOKIES);

                        for _ in 0..DEFAULT_NUMBER_OF_COOKIES {
                            cookies.push(keyset.encode_cookie(&cookie).into());
                        }

                        let response = KeyExchangeResponse {
                            protocol,
                            algorithm,
                            cookies: cookies.into(),
                            server: self.server.as_deref().map(|v| v.into()),
                            port: self.port,
                        };

                        // Serialize response first to a buffer to ensure it is most likely to be sent as a
                        // single packet, which ntpsec needs.
                        let mut req_buf = vec![];
                        response.serialize(&mut req_buf).await?;
                        io.write_all(&req_buf).await?;

                        Ok(())
                    }
                };
                io.shutdown().await?;

                result
            }
            #[cfg(feature = "nts-pool")]
            Request::FixedKey {
                authentication,
                c2s_key,
                s2c_key,
                algorithm,
                protocol,
            } if self
                .pool_authentication_tokens
                .iter()
                .any(|v| v == authentication.as_ref()) =>
            {
                let cookie = DecodedServerCookie {
                    algorithm,
                    s2c: s2c_key,
                    c2s: c2s_key,
                };

                let mut cookies = Vec::with_capacity(DEFAULT_NUMBER_OF_COOKIES);

                for _ in 0..DEFAULT_NUMBER_OF_COOKIES {
                    cookies.push(keyset.encode_cookie(&cookie).into());
                }

                let response = KeyExchangeResponse {
                    protocol,
                    algorithm,
                    cookies: cookies.into(),
                    server: self.server.as_deref().map(|v| v.into()),
                    port: self.port,
                };

                response.serialize(&mut io).await?;
                io.shutdown().await?;

                Ok(())
            }
            #[cfg(feature = "nts-pool")]
            Request::Support {
                authentication,
                wants_protocols,
                wants_algorithms,
            } if self
                .pool_authentication_tokens
                .iter()
                .any(|v| v == authentication.as_ref()) =>
            {
                use crate::nts::messages::SupportsResponse;
                use std::ops::Deref;

                SupportsResponse {
                    algorithms: if wants_algorithms {
                        Some(self.algorithms.deref().into())
                    } else {
                        None
                    },
                    protocols: if wants_protocols {
                        Some(self.protocols.deref().into())
                    } else {
                        None
                    },
                }
                .serialize(&mut io)
                .await?;
                io.shutdown().await?;

                Ok(())
            }
            #[cfg(feature = "nts-pool")]
            Request::FixedKey { .. } | Request::Support { .. } => {
                ErrorResponse {
                    errorcode: ErrorCode::BadRequest,
                }
                .serialize(&mut io)
                .await?;
                io.shutdown().await?;
                Err(NtsError::NotPermitted)
            }
        }
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

    #[tokio::test]
    async fn test_keyexchange_roundtrip_v4() {
        let (client, server) = tokio::io::duplex(2048);

        let client = async move {
            let certificates = tls_utils::pemfile::certs(
                &mut include_bytes!("../../test-keys/testca.pem").as_slice(),
            )
            .collect::<Result<Arc<_>, _>>()
            .unwrap();
            let kex = KeyExchangeClient::new(NtsClientConfig {
                certificates,
                protocol_version: ProtocolVersion::V4,
            })
            .unwrap();
            kex.exchange_keys(client, "localhost".into(), [])
                .await
                .unwrap()
        };

        let server = async move {
            let certificate_chain = tls_utils::pemfile::certs(
                &mut include_bytes!("../../test-keys/end.fullchain.pem").as_slice(),
            )
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
            let private_key = tls_utils::pemfile::private_key(
                &mut include_bytes!("../../test-keys/end.key").as_slice(),
            )
            .unwrap();
            let kex = KeyExchangeServer::new(NtsServerConfig {
                certificate_chain,
                private_key,
                accepted_versions: vec![NtpVersion::V4],
                server: None,
                port: None,
                #[cfg(feature = "nts-pool")]
                pool_authentication_tokens: vec![],
            })
            .unwrap();
            let keyset = KeySet::new();
            assert!(kex.handle_connection(server, &keyset).await.is_ok());
            keyset
        };

        let (mut kexresult, keyset) = tokio::join!(client, server);
        assert_eq!(kexresult.protocol_version, ProtocolVersion::V4);

        let mut count = 0;
        while let Some(cookie) = kexresult.nts.get_cookie() {
            let decoded = keyset.decode_cookie(&cookie).unwrap();

            assert_eq!(decoded.c2s.key_bytes(), kexresult.nts.c2s.key_bytes());
            assert_eq!(decoded.s2c.key_bytes(), kexresult.nts.s2c.key_bytes());
            count += 1;
        }
        assert_eq!(count, 8);
    }

    #[tokio::test]
    async fn test_keyexchange_roundtrip_v5() {
        let (client, server) = tokio::io::duplex(2048);

        let client = async move {
            let certificates = tls_utils::pemfile::certs(
                &mut include_bytes!("../../test-keys/testca.pem").as_slice(),
            )
            .collect::<Result<Arc<_>, _>>()
            .unwrap();
            let kex = KeyExchangeClient::new(NtsClientConfig {
                certificates,
                protocol_version: ProtocolVersion::V5,
            })
            .unwrap();
            kex.exchange_keys(client, "localhost".into(), [])
                .await
                .unwrap()
        };

        let server = async move {
            let certificate_chain = tls_utils::pemfile::certs(
                &mut include_bytes!("../../test-keys/end.fullchain.pem").as_slice(),
            )
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
            let private_key = tls_utils::pemfile::private_key(
                &mut include_bytes!("../../test-keys/end.key").as_slice(),
            )
            .unwrap();
            let kex = KeyExchangeServer::new(NtsServerConfig {
                certificate_chain,
                private_key,
                accepted_versions: vec![NtpVersion::V5],
                server: None,
                port: None,
                #[cfg(feature = "nts-pool")]
                pool_authentication_tokens: vec![],
            })
            .unwrap();
            let keyset = KeySet::new();
            assert!(kex.handle_connection(server, &keyset).await.is_ok());
            keyset
        };

        let (mut kexresult, keyset) = tokio::join!(client, server);
        assert_eq!(kexresult.protocol_version, ProtocolVersion::V5);

        let mut count = 0;
        while let Some(cookie) = kexresult.nts.get_cookie() {
            let decoded = keyset.decode_cookie(&cookie).unwrap();

            assert_eq!(decoded.c2s.key_bytes(), kexresult.nts.c2s.key_bytes());
            assert_eq!(decoded.s2c.key_bytes(), kexresult.nts.s2c.key_bytes());
            count += 1;
        }
        assert_eq!(count, 8);
    }

    #[tokio::test]
    async fn test_keyexchange_roundtrip_upgrading() {
        let (client, server) = tokio::io::duplex(2048);

        let client = async move {
            let certificates = tls_utils::pemfile::certs(
                &mut include_bytes!("../../test-keys/testca.pem").as_slice(),
            )
            .collect::<Result<Arc<_>, _>>()
            .unwrap();
            let kex = KeyExchangeClient::new(NtsClientConfig {
                certificates,
                protocol_version: ProtocolVersion::V4UpgradingToV5 { tries_left: 8 },
            })
            .unwrap();
            kex.exchange_keys(client, "localhost".into(), [])
                .await
                .unwrap()
        };

        let server = async move {
            let certificate_chain = tls_utils::pemfile::certs(
                &mut include_bytes!("../../test-keys/end.fullchain.pem").as_slice(),
            )
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
            let private_key = tls_utils::pemfile::private_key(
                &mut include_bytes!("../../test-keys/end.key").as_slice(),
            )
            .unwrap();
            let kex = KeyExchangeServer::new(NtsServerConfig {
                certificate_chain,
                private_key,
                accepted_versions: vec![NtpVersion::V4, NtpVersion::V5],
                server: None,
                port: None,
                #[cfg(feature = "nts-pool")]
                pool_authentication_tokens: vec![],
            })
            .unwrap();
            let keyset = KeySet::new();
            assert!(kex.handle_connection(server, &keyset).await.is_ok());
            keyset
        };

        let (mut kexresult, keyset) = tokio::join!(client, server);
        assert_eq!(kexresult.protocol_version, ProtocolVersion::V5);

        let mut count = 0;
        while let Some(cookie) = kexresult.nts.get_cookie() {
            let decoded = keyset.decode_cookie(&cookie).unwrap();

            assert_eq!(decoded.c2s.key_bytes(), kexresult.nts.c2s.key_bytes());
            assert_eq!(decoded.s2c.key_bytes(), kexresult.nts.s2c.key_bytes());
            count += 1;
        }
        assert_eq!(count, 8);
    }

    #[tokio::test]
    async fn test_keyexchange_roundtrip_no_upgrade_possible() {
        let (client, server) = tokio::io::duplex(2048);

        let client = async move {
            let certificates = tls_utils::pemfile::certs(
                &mut include_bytes!("../../test-keys/testca.pem").as_slice(),
            )
            .collect::<Result<Arc<_>, _>>()
            .unwrap();
            let kex = KeyExchangeClient::new(NtsClientConfig {
                certificates,
                protocol_version: ProtocolVersion::V4UpgradingToV5 { tries_left: 8 },
            })
            .unwrap();
            kex.exchange_keys(client, "localhost".into(), [])
                .await
                .unwrap()
        };

        let server = async move {
            let certificate_chain = tls_utils::pemfile::certs(
                &mut include_bytes!("../../test-keys/end.fullchain.pem").as_slice(),
            )
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
            let private_key = tls_utils::pemfile::private_key(
                &mut include_bytes!("../../test-keys/end.key").as_slice(),
            )
            .unwrap();
            let kex = KeyExchangeServer::new(NtsServerConfig {
                certificate_chain,
                private_key,
                accepted_versions: vec![NtpVersion::V4],
                server: None,
                port: None,
                #[cfg(feature = "nts-pool")]
                pool_authentication_tokens: vec![],
            })
            .unwrap();
            let keyset = KeySet::new();
            assert!(kex.handle_connection(server, &keyset).await.is_ok());
            keyset
        };

        let (mut kexresult, keyset) = tokio::join!(client, server);
        assert_eq!(kexresult.protocol_version, ProtocolVersion::V4);

        let mut count = 0;
        while let Some(cookie) = kexresult.nts.get_cookie() {
            let decoded = keyset.decode_cookie(&cookie).unwrap();

            assert_eq!(decoded.c2s.key_bytes(), kexresult.nts.c2s.key_bytes());
            assert_eq!(decoded.s2c.key_bytes(), kexresult.nts.s2c.key_bytes());
            count += 1;
        }
        assert_eq!(count, 8);
    }

    #[tokio::test]
    async fn test_keyexchange_roundtrip_no_proto_overlap() {
        let (client, server) = tokio::io::duplex(2048);

        let client = async move {
            let certificates = tls_utils::pemfile::certs(
                &mut include_bytes!("../../test-keys/testca.pem").as_slice(),
            )
            .collect::<Result<Arc<_>, _>>()
            .unwrap();
            let kex = KeyExchangeClient::new(NtsClientConfig {
                certificates,
                protocol_version: ProtocolVersion::V5,
            })
            .unwrap();
            kex.exchange_keys(client, "localhost".into(), []).await
        };

        let server = async move {
            let certificate_chain = tls_utils::pemfile::certs(
                &mut include_bytes!("../../test-keys/end.fullchain.pem").as_slice(),
            )
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
            let private_key = tls_utils::pemfile::private_key(
                &mut include_bytes!("../../test-keys/end.key").as_slice(),
            )
            .unwrap();
            let kex = KeyExchangeServer::new(NtsServerConfig {
                certificate_chain,
                private_key,
                accepted_versions: vec![NtpVersion::V4],
                server: None,
                port: None,
                #[cfg(feature = "nts-pool")]
                pool_authentication_tokens: vec![],
            })
            .unwrap();
            let keyset = KeySet::new();
            kex.handle_connection(server, &keyset).await
        };

        let (kexresult, serverresult) = tokio::join!(client, server);
        assert!(matches!(kexresult, Err(NtsError::NoOverlappingProtocol)));
        assert!(matches!(serverresult, Err(NtsError::NoOverlappingProtocol)));
    }

    #[tokio::test]
    async fn test_key_exchange_roundtrip_no_cookies() {
        let (client, server) = tokio::io::duplex(2048);

        let client = async move {
            let certificates = tls_utils::pemfile::certs(
                &mut include_bytes!("../../test-keys/testca.pem").as_slice(),
            )
            .collect::<Result<Arc<_>, _>>()
            .unwrap();
            let kex = KeyExchangeClient::new(NtsClientConfig {
                certificates,
                protocol_version: ProtocolVersion::V4,
            })
            .unwrap();
            kex.exchange_keys(client, "localhost".into(), []).await
        };

        let server = async move {
            let certificate_chain = tls_utils::pemfile::certs(
                &mut include_bytes!("../../test-keys/end.fullchain.pem").as_slice(),
            )
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
            let private_key = tls_utils::pemfile::private_key(
                &mut include_bytes!("../../test-keys/end.key").as_slice(),
            )
            .unwrap();
            let kex = KeyExchangeServer::new(NtsServerConfig {
                certificate_chain,
                private_key,
                accepted_versions: vec![NtpVersion::V4],
                server: None,
                port: None,
                #[cfg(feature = "nts-pool")]
                pool_authentication_tokens: vec![],
            })
            .unwrap();
            let mut server = kex.acceptor.accept(server).await.unwrap();
            Request::parse(&mut server).await.unwrap();
            KeyExchangeResponse {
                protocol: NextProtocol::NTPv4,
                algorithm: AeadAlgorithm::AeadAesSivCmac256,
                cookies: [].as_slice().into(),
                server: None,
                port: None,
            }
            .serialize(&mut server)
            .await
            .unwrap();
            server.shutdown().await.unwrap();
        };

        let (kexresult, _) = tokio::join!(client, server);
        assert!(matches!(kexresult, Err(NtsError::NoCookie)));
    }

    #[cfg(feature = "nts-pool")]
    #[tokio::test]
    async fn test_keyexchange_roundtrip_fixed_key() {
        let (client, server) = tokio::io::duplex(2048);

        let client = async move {
            let certificates = tls_utils::pemfile::certs(
                &mut include_bytes!("../../test-keys/testca.pem").as_slice(),
            )
            .collect::<Result<Arc<_>, _>>()
            .unwrap();
            let certificate_chain = tls_utils::pemfile::certs(
                &mut include_bytes!("../../test-keys/end.fullchain.pem").as_slice(),
            )
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
            let private_key = tls_utils::pemfile::private_key(
                &mut include_bytes!("../../test-keys/end.key").as_slice(),
            )
            .unwrap();

            let builder = tls_utils::client_config_builder_with_protocol_versions(&[&TLS13]);
            let verifier =
                tls_utils::PlatformVerifier::new_with_extra_roots(certificates.iter().cloned())
                    .unwrap()
                    .with_provider(builder.crypto_provider().clone());
            let mut tls_config = builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_client_auth_cert(certificate_chain, private_key)
                .unwrap();
            tls_config.alpn_protocols = vec![b"ntske/1".into()];
            let connector = TlsConnector::from(Arc::new(tls_config));

            let mut client = connector
                .connect(ServerName::try_from("localhost").unwrap(), client)
                .await
                .unwrap();

            client
                .write_all(&[
                    0x40, 5, 0, 2, b'h', b'i', 0xC0, 2, 0, 64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                    11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
                    31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
                    51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 0x80, 1, 0, 2, 0, 0, 0x80,
                    4, 0, 2, 0, 15, 0x80, 0, 0, 0,
                ])
                .await
                .unwrap();

            KeyExchangeResponse::parse(&mut client).await.unwrap()
        };

        let server = async move {
            let certificate_chain = tls_utils::pemfile::certs(
                &mut include_bytes!("../../test-keys/end.fullchain.pem").as_slice(),
            )
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
            let private_key = tls_utils::pemfile::private_key(
                &mut include_bytes!("../../test-keys/end.key").as_slice(),
            )
            .unwrap();
            let kex = KeyExchangeServer::new(NtsServerConfig {
                certificate_chain,
                private_key,
                accepted_versions: vec![NtpVersion::V4],
                server: None,
                port: None,
                pool_authentication_tokens: vec!["hi".into()],
            })
            .unwrap();
            let keyset = KeySet::new();
            kex.handle_connection(server, &keyset).await.unwrap();
            keyset
        };

        let (response, keyset) = tokio::join!(client, server);

        assert_eq!(response.algorithm, AeadAlgorithm::AeadAesSivCmac256);
        assert_eq!(response.protocol, NextProtocol::NTPv4);

        for cookie in response.cookies.iter() {
            let decoded = keyset.decode_cookie(cookie).unwrap();
            assert_eq!(
                decoded.c2s.key_bytes(),
                [
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31
                ]
            );
            assert_eq!(
                decoded.s2c.key_bytes(),
                [
                    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
                    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63
                ]
            );
        }
    }

    #[cfg(feature = "nts-pool")]
    #[tokio::test]
    async fn test_keyexchange_fixed_key_no_permission() {
        let (client, server) = tokio::io::duplex(2048);

        let client = async move {
            let certificates = tls_utils::pemfile::certs(
                &mut include_bytes!("../../test-keys/testca.pem").as_slice(),
            )
            .collect::<Result<Arc<_>, _>>()
            .unwrap();

            let builder = tls_utils::client_config_builder_with_protocol_versions(&[&TLS13]);
            let verifier =
                tls_utils::PlatformVerifier::new_with_extra_roots(certificates.iter().cloned())
                    .unwrap()
                    .with_provider(builder.crypto_provider().clone());
            let mut tls_config = builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth();
            tls_config.alpn_protocols = vec![b"ntske/1".into()];
            let connector = TlsConnector::from(Arc::new(tls_config));

            let mut client = connector
                .connect(ServerName::try_from("localhost").unwrap(), client)
                .await
                .unwrap();

            client
                .write_all(&[
                    0x40, 5, 0, 2, b'n', b'o', 0xC0, 2, 0, 64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                    11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
                    31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
                    51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 0x80, 1, 0, 2, 0, 0, 0x80,
                    4, 0, 2, 0, 15, 0x80, 0, 0, 0,
                ])
                .await
                .unwrap();

            KeyExchangeResponse::parse(&mut client).await
        };

        let server = async move {
            let certificate_chain = tls_utils::pemfile::certs(
                &mut include_bytes!("../../test-keys/end.fullchain.pem").as_slice(),
            )
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
            let private_key = tls_utils::pemfile::private_key(
                &mut include_bytes!("../../test-keys/end.key").as_slice(),
            )
            .unwrap();
            let kex = KeyExchangeServer::new(NtsServerConfig {
                certificate_chain,
                private_key,
                accepted_versions: vec![NtpVersion::V4],
                server: None,
                port: None,
                pool_authentication_tokens: vec!["hi".into()],
            })
            .unwrap();
            let keyset = KeySet::new();
            kex.handle_connection(server, &keyset).await
        };

        let (response, kexerror) = tokio::join!(client, server);

        assert!(response.is_err());
        assert!(kexerror.is_err());
    }

    #[cfg(feature = "nts-pool")]
    #[tokio::test]
    async fn test_keyexchange_roundtrip_supports() {
        let (client, server) = tokio::io::duplex(2048);

        let client = async move {
            use tokio::io::AsyncReadExt;

            let certificates = tls_utils::pemfile::certs(
                &mut include_bytes!("../../test-keys/testca.pem").as_slice(),
            )
            .collect::<Result<Arc<_>, _>>()
            .unwrap();
            let certificate_chain = tls_utils::pemfile::certs(
                &mut include_bytes!("../../test-keys/end.fullchain.pem").as_slice(),
            )
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
            let private_key = tls_utils::pemfile::private_key(
                &mut include_bytes!("../../test-keys/end.key").as_slice(),
            )
            .unwrap();

            let builder = tls_utils::client_config_builder_with_protocol_versions(&[&TLS13]);
            let verifier =
                tls_utils::PlatformVerifier::new_with_extra_roots(certificates.iter().cloned())
                    .unwrap()
                    .with_provider(builder.crypto_provider().clone());
            let mut tls_config = builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_client_auth_cert(certificate_chain, private_key)
                .unwrap();
            tls_config.alpn_protocols = vec![b"ntske/1".into()];
            let connector = TlsConnector::from(Arc::new(tls_config));

            let mut client = connector
                .connect(ServerName::try_from("localhost").unwrap(), client)
                .await
                .unwrap();

            client
                .write_all(&[
                    0x40, 5, 0, 2, b'h', b'i', 0xC0, 4, 0, 0, 0xC0, 1, 0, 0, 0x80, 0, 0, 0,
                ])
                .await
                .unwrap();

            let mut data = vec![];
            client.read_to_end(&mut data).await.unwrap();
            data
        };

        let server = async move {
            let certificate_chain = tls_utils::pemfile::certs(
                &mut include_bytes!("../../test-keys/end.fullchain.pem").as_slice(),
            )
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
            let private_key = tls_utils::pemfile::private_key(
                &mut include_bytes!("../../test-keys/end.key").as_slice(),
            )
            .unwrap();
            let kex = KeyExchangeServer::new(NtsServerConfig {
                certificate_chain,
                private_key,
                accepted_versions: vec![NtpVersion::V4],
                server: None,
                port: None,
                pool_authentication_tokens: vec!["hi".into()],
            })
            .unwrap();
            let keyset = KeySet::new();
            kex.handle_connection(server, &keyset).await.unwrap();
        };

        let (response, _) = tokio::join!(client, server);

        assert_eq!(
            response,
            [
                0xC0, 1, 0, 8, 0, 15, 0, 32, 0, 17, 0, 64, 0xC0, 4, 0, 2, 0, 0, 0x80, 0, 0, 0
            ]
        );
    }

    #[cfg(feature = "nts-pool")]
    #[tokio::test]
    async fn test_keyexchange_supports_no_permission() {
        let (client, server) = tokio::io::duplex(2048);

        let client = async move {
            use tokio::io::AsyncReadExt;

            let certificates = tls_utils::pemfile::certs(
                &mut include_bytes!("../../test-keys/testca.pem").as_slice(),
            )
            .collect::<Result<Arc<_>, _>>()
            .unwrap();

            let builder = tls_utils::client_config_builder_with_protocol_versions(&[&TLS13]);
            let verifier =
                tls_utils::PlatformVerifier::new_with_extra_roots(certificates.iter().cloned())
                    .unwrap()
                    .with_provider(builder.crypto_provider().clone());
            let mut tls_config = builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth();
            tls_config.alpn_protocols = vec![b"ntske/1".into()];
            let connector = TlsConnector::from(Arc::new(tls_config));

            let mut client = connector
                .connect(ServerName::try_from("localhost").unwrap(), client)
                .await
                .unwrap();

            client
                .write_all(&[
                    0x40, 5, 0, 2, b'n', b'o', 0xC0, 4, 0, 0, 0xC0, 1, 0, 0, 0x80, 0, 0, 0,
                ])
                .await
                .unwrap();

            let mut data = vec![];
            client.read_to_end(&mut data).await.unwrap();
            data
        };

        let server = async move {
            let certificate_chain = tls_utils::pemfile::certs(
                &mut include_bytes!("../../test-keys/end.fullchain.pem").as_slice(),
            )
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
            let private_key = tls_utils::pemfile::private_key(
                &mut include_bytes!("../../test-keys/end.key").as_slice(),
            )
            .unwrap();
            let kex = KeyExchangeServer::new(NtsServerConfig {
                certificate_chain,
                private_key,
                accepted_versions: vec![NtpVersion::V4],
                server: None,
                port: None,
                pool_authentication_tokens: vec!["hi".into()],
            })
            .unwrap();
            let keyset = KeySet::new();
            kex.handle_connection(server, &keyset).await
        };

        let (response, server_res) = tokio::join!(client, server);

        assert_eq!(response, [0x80, 2, 0, 2, 0, 1, 0x80, 0, 0, 0]);
        assert!(server_res.is_err());
    }
}
