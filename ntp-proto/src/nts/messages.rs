use std::borrow::Cow;

use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(feature = "nts-pool")]
use crate::nts::AlgorithmDescription;
use crate::nts::DEFAULT_NUMBER_OF_COOKIES;
#[cfg(feature = "nts-pool")]
use crate::packet::Cipher;

use super::record::NtsRecord;
use super::{AeadAlgorithm, ErrorCode, NextProtocol, NtsError, WarningCode};

pub enum Request<'a> {
    KeyExchange {
        algorithms: Cow<'a, [AeadAlgorithm]>,
        #[cfg_attr(feature = "__internal-fuzz", allow(private_interfaces))]
        protocols: Cow<'a, [NextProtocol]>,
        #[cfg(feature = "nts-pool")]
        denied_servers: Cow<'a, [Cow<'a, str>]>,
    },
    #[cfg(feature = "nts-pool")]
    FixedKey {
        c2s_key: Box<dyn Cipher>,
        s2c_key: Box<dyn Cipher>,
        algorithm: AeadAlgorithm,
        #[cfg_attr(feature = "__internal-fuzz", allow(private_interfaces))]
        protocol: NextProtocol,
    },
    #[cfg(feature = "nts-pool")]
    Support {
        wants_protocols: bool,
        wants_algorithms: bool,
    },
}

impl Request<'_> {
    pub async fn parse(mut reader: impl AsyncRead + Unpin) -> Result<Self, NtsError> {
        let mut protocols = None;
        let mut algorithms = None;
        #[cfg(feature = "nts-pool")]
        let mut denied_servers = vec![];
        #[cfg(feature = "nts-pool")]
        let mut wants_protocols = false;
        #[cfg(feature = "nts-pool")]
        let mut wants_algorithms = false;
        #[cfg(feature = "nts-pool")]
        let mut key_bytes = None;

        loop {
            let record = NtsRecord::parse(&mut reader).await?;

            match record {
                NtsRecord::EndOfMessage => break,
                NtsRecord::NextProtocol { protocol_ids } => {
                    if protocols.is_some() {
                        return Err(NtsError::Invalid);
                    }

                    protocols = Some(protocol_ids);
                }
                NtsRecord::AeadAlgorithm { algorithm_ids } => {
                    if algorithms.is_some() {
                        return Err(NtsError::Invalid);
                    }

                    algorithms = Some(algorithm_ids);
                }
                #[cfg(feature = "nts-pool")]
                NtsRecord::FixedKeyRequest { c2s, s2c } => {
                    if key_bytes.is_some() {
                        return Err(NtsError::Invalid);
                    }

                    key_bytes = Some((c2s, s2c));
                }
                #[cfg(feature = "nts-pool")]
                NtsRecord::SupportedAlgorithmList { .. } => {
                    if wants_algorithms {
                        return Err(NtsError::Invalid);
                    }

                    wants_algorithms = true;
                }
                #[cfg(feature = "nts-pool")]
                NtsRecord::SupportedNextProtocolList { .. } => {
                    if wants_protocols {
                        return Err(NtsError::Invalid);
                    }

                    wants_protocols = true;
                }
                #[cfg(feature = "nts-pool")]
                NtsRecord::NtpServerDeny { denied } => {
                    denied_servers.push(denied);
                }
                // Unknown critical
                NtsRecord::Unknown { critical: true, .. } => {
                    return Err(NtsError::UnrecognizedCriticalRecord);
                }
                // Ignored
                NtsRecord::Unknown { .. } | NtsRecord::Server { .. } | NtsRecord::Port { .. } => {}
                #[cfg(feature = "nts-pool")]
                NtsRecord::KeepAlive => {}
                // not allowed
                NtsRecord::Error { .. }
                | NtsRecord::Warning { .. }
                | NtsRecord::NewCookie { .. } => return Err(NtsError::Invalid),
            }
        }

        #[cfg(feature = "nts-pool")]
        if wants_algorithms || wants_protocols {
            if key_bytes.is_some() || protocols.is_some() || algorithms.is_some() {
                return Err(NtsError::Invalid);
            }

            return Ok(Request::Support {
                wants_protocols,
                wants_algorithms,
            });
        } else if let Some(key_bytes) = key_bytes {
            return if let (Some(protocols), Some(algorithms)) = (protocols, algorithms) {
                use crate::packet::{AesSivCmac256, AesSivCmac512};

                if protocols.len() != 1 || algorithms.len() != 1 {
                    return Err(NtsError::Invalid);
                }

                let (c2s_key, s2c_key): (Box<dyn Cipher>, Box<dyn Cipher>) = match algorithms[0] {
                    AeadAlgorithm::AeadAesSivCmac256 => match (
                        AesSivCmac256::from_key_bytes(&key_bytes.0),
                        AesSivCmac256::from_key_bytes(&key_bytes.1),
                    ) {
                        (Ok(c2s), Ok(s2c)) => (Box::new(c2s), Box::new(s2c)),
                        _ => return Err(NtsError::IncorrectSizedKey),
                    },
                    AeadAlgorithm::AeadAesSivCmac512 => match (
                        AesSivCmac512::from_key_bytes(&key_bytes.0),
                        AesSivCmac512::from_key_bytes(&key_bytes.1),
                    ) {
                        (Ok(c2s), Ok(s2c)) => (Box::new(c2s), Box::new(s2c)),
                        _ => return Err(NtsError::IncorrectSizedKey),
                    },
                    AeadAlgorithm::Unknown(v) => return Err(NtsError::AeadNotSupported(v)),
                };

                Ok(Request::FixedKey {
                    c2s_key,
                    s2c_key,
                    algorithm: algorithms[0],
                    protocol: protocols[0],
                })
            } else {
                Err(NtsError::Invalid)
            };
        }

        if let (Some(protocols), Some(algorithms)) = (protocols, algorithms) {
            Ok(Request::KeyExchange {
                algorithms,
                protocols,
                #[cfg(feature = "nts-pool")]
                denied_servers: denied_servers.into(),
            })
        } else {
            Err(NtsError::Invalid)
        }
    }

    pub async fn serialize(
        self,
        mut writer: impl AsyncWrite + Unpin,
    ) -> Result<(), std::io::Error> {
        match self {
            Request::KeyExchange {
                algorithms,
                protocols,
                #[cfg(feature = "nts-pool")]
                denied_servers,
            } => {
                NtsRecord::NextProtocol {
                    protocol_ids: protocols,
                }
                .serialize(&mut writer)
                .await?;
                NtsRecord::AeadAlgorithm {
                    algorithm_ids: algorithms,
                }
                .serialize(&mut writer)
                .await?;
                #[cfg(feature = "nts-pool")]
                for denied in denied_servers.iter() {
                    use std::ops::Deref;

                    NtsRecord::NtpServerDeny {
                        denied: denied.deref().into(),
                    }
                    .serialize(&mut writer)
                    .await?;
                }
                NtsRecord::EndOfMessage.serialize(&mut writer).await?;
            }
            #[cfg(feature = "nts-pool")]
            Request::FixedKey {
                c2s_key,
                s2c_key,
                algorithm,
                protocol,
            } => {
                NtsRecord::FixedKeyRequest {
                    c2s: c2s_key.key_bytes().into(),
                    s2c: s2c_key.key_bytes().into(),
                }
                .serialize(&mut writer)
                .await?;
                NtsRecord::NextProtocol {
                    protocol_ids: [protocol].as_slice().into(),
                }
                .serialize(&mut writer)
                .await?;
                NtsRecord::AeadAlgorithm {
                    algorithm_ids: [algorithm].as_slice().into(),
                }
                .serialize(&mut writer)
                .await?;
                NtsRecord::EndOfMessage.serialize(&mut writer).await?;
            }
            #[cfg(feature = "nts-pool")]
            Request::Support {
                wants_protocols,
                wants_algorithms,
            } => {
                if wants_protocols {
                    NtsRecord::SupportedNextProtocolList {
                        supported_protocols: [].as_slice().into(),
                    }
                    .serialize(&mut writer)
                    .await?;
                }
                if wants_algorithms {
                    NtsRecord::SupportedAlgorithmList {
                        supported_algorithms: [].as_slice().into(),
                    }
                    .serialize(&mut writer)
                    .await?;
                }
                NtsRecord::EndOfMessage.serialize(&mut writer).await?;
            }
        }

        Ok(())
    }
}

pub struct KeyExchangeResponse<'a> {
    #[cfg_attr(feature = "__internal-fuzz", allow(private_interfaces))]
    pub protocol: NextProtocol,
    pub algorithm: AeadAlgorithm,
    pub cookies: Cow<'a, [Cow<'a, [u8]>]>,
    pub server: Option<Cow<'a, str>>,
    pub port: Option<u16>,
}

impl KeyExchangeResponse<'_> {
    pub async fn parse(mut reader: impl AsyncRead + Unpin) -> Result<Self, NtsError> {
        let mut protocol = None;
        let mut algorithm = None;
        let mut cookies = vec![];
        let mut server = None;
        let mut port = None;

        loop {
            let record = NtsRecord::parse(&mut reader).await?;

            match record {
                NtsRecord::EndOfMessage => break,
                NtsRecord::NextProtocol { protocol_ids } => {
                    if protocol.is_some() {
                        return Err(NtsError::Invalid);
                    }

                    match protocol_ids.split_first() {
                        None => return Err(NtsError::NoOverlappingProtocol),
                        Some((&id, [])) => protocol = Some(id),
                        _ => return Err(NtsError::Invalid),
                    }
                }
                NtsRecord::AeadAlgorithm { algorithm_ids } => {
                    if algorithm.is_some() {
                        return Err(NtsError::Invalid);
                    }

                    match algorithm_ids.split_first() {
                        None => return Err(NtsError::NoOverlappingAlgorithm),
                        Some((&id, [])) => algorithm = Some(id),
                        _ => return Err(NtsError::Invalid),
                    }
                }
                NtsRecord::NewCookie { cookie_data } => {
                    if cookies.len() < DEFAULT_NUMBER_OF_COOKIES {
                        cookies.push(cookie_data)
                    }
                }
                NtsRecord::Server { name } => {
                    if server.is_some() {
                        return Err(NtsError::Invalid);
                    }
                    server = Some(name)
                }
                NtsRecord::Port {
                    port: received_port,
                } => {
                    if port.is_some() {
                        return Err(NtsError::Invalid);
                    }
                    port = Some(received_port);
                }
                // Error
                NtsRecord::Error { errorcode } => return Err(NtsError::Error(errorcode)),
                // Warning
                NtsRecord::Warning { warningcode } => match warningcode {
                    WarningCode::Unknown(code) => return Err(NtsError::UnknownWarning(code)),
                },
                // Unknown critical
                NtsRecord::Unknown { critical: true, .. } => {
                    return Err(NtsError::UnrecognizedCriticalRecord);
                }
                // Ignored
                NtsRecord::Unknown { .. } => {}
                #[cfg(feature = "nts-pool")]
                NtsRecord::KeepAlive => {}
                // Not allowed
                #[cfg(feature = "nts-pool")]
                NtsRecord::NtpServerDeny { .. }
                | NtsRecord::FixedKeyRequest { .. }
                | NtsRecord::SupportedAlgorithmList { .. }
                | NtsRecord::SupportedNextProtocolList { .. } => return Err(NtsError::Invalid),
            }
        }

        if let (Some(protocol), Some(algorithm)) = (protocol, algorithm) {
            Ok(KeyExchangeResponse {
                protocol,
                algorithm,
                cookies: cookies.into(),
                server,
                port,
            })
        } else {
            Err(NtsError::Invalid)
        }
    }

    pub async fn serialize(
        self,
        mut writer: impl AsyncWrite + Unpin,
    ) -> Result<(), std::io::Error> {
        NtsRecord::NextProtocol {
            protocol_ids: [self.protocol].as_slice().into(),
        }
        .serialize(&mut writer)
        .await?;
        NtsRecord::AeadAlgorithm {
            algorithm_ids: [self.algorithm].as_slice().into(),
        }
        .serialize(&mut writer)
        .await?;
        for cookie_data in self.cookies.iter() {
            NtsRecord::NewCookie {
                cookie_data: Cow::Borrowed(cookie_data),
            }
            .serialize(&mut writer)
            .await?;
        }
        if let Some(name) = self.server {
            NtsRecord::Server { name }.serialize(&mut writer).await?;
        }
        if let Some(port) = self.port {
            NtsRecord::Port { port }.serialize(&mut writer).await?;
        }
        NtsRecord::EndOfMessage.serialize(&mut writer).await?;

        Ok(())
    }
}

pub enum NoOverlapResponse {
    NoOverlappingAlgorithm { protocol: NextProtocol },
    NoOverlappingProtocol,
}

impl NoOverlapResponse {
    pub async fn serialize(
        self,
        mut writer: impl AsyncWrite + Unpin,
    ) -> Result<(), std::io::Error> {
        match self {
            NoOverlapResponse::NoOverlappingAlgorithm { protocol } => {
                NtsRecord::NextProtocol {
                    protocol_ids: [protocol].as_slice().into(),
                }
                .serialize(&mut writer)
                .await?;
                NtsRecord::AeadAlgorithm {
                    algorithm_ids: [].as_slice().into(),
                }
                .serialize(&mut writer)
                .await?;
                NtsRecord::EndOfMessage.serialize(&mut writer).await?;
            }
            NoOverlapResponse::NoOverlappingProtocol => {
                NtsRecord::NextProtocol {
                    protocol_ids: [].as_slice().into(),
                }
                .serialize(&mut writer)
                .await?;
                NtsRecord::EndOfMessage.serialize(&mut writer).await?;
            }
        }

        Ok(())
    }
}

pub struct ErrorResponse {
    pub errorcode: ErrorCode,
}

impl ErrorResponse {
    pub async fn serialize(
        self,
        mut writer: impl AsyncWrite + Unpin,
    ) -> Result<(), std::io::Error> {
        NtsRecord::Error {
            errorcode: self.errorcode,
        }
        .serialize(&mut writer)
        .await?;
        NtsRecord::EndOfMessage.serialize(&mut writer).await?;

        Ok(())
    }
}

#[cfg(feature = "nts-pool")]
pub struct SupportsResponse<'a> {
    pub algorithms: Option<Cow<'a, [AlgorithmDescription]>>,
    pub protocols: Option<Cow<'a, [NextProtocol]>>,
}

#[cfg(feature = "nts-pool")]
impl SupportsResponse<'_> {
    pub async fn serialize(
        self,
        mut writer: impl AsyncWrite + Unpin,
    ) -> Result<(), std::io::Error> {
        if let Some(supported_algorithms) = self.algorithms {
            NtsRecord::SupportedAlgorithmList {
                supported_algorithms,
            }
            .serialize(&mut writer)
            .await?;
        }
        if let Some(supported_protocols) = self.protocols {
            NtsRecord::SupportedNextProtocolList {
                supported_protocols,
            }
            .serialize(&mut writer)
            .await?;
        }
        NtsRecord::EndOfMessage.serialize(&mut writer).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        io::Error,
        pin::pin,
        task::{Context, Poll, Waker},
    };

    use super::*;

    // wrapper for dealing with the fact that serialize functions are async in tests.
    fn swrap<'a, F, T, U>(f: F, t: T, buf: &'a mut Vec<u8>) -> Result<(), Error>
    where
        F: FnOnce(T, &'a mut Vec<u8>) -> U,
        U: Future<Output = Result<(), Error>>,
    {
        let Poll::Ready(result) = pin!(f(t, buf)).poll(&mut Context::from_waker(Waker::noop()))
        else {
            panic!("Future stalled unexpectedly.");
        };

        result
    }

    // wrapper for dealing with the fact that serialize functions are async in tests.
    fn pwrap<'a, F, T, U>(f: F, buf: &'a [u8]) -> Result<T, NtsError>
    where
        F: FnOnce(&'a [u8]) -> U,
        U: Future<Output = Result<T, NtsError>>,
    {
        let Poll::Ready(result) = pin!(f(buf)).poll(&mut Context::from_waker(Waker::noop())) else {
            panic!("Future stalled unexpectedly");
        };

        result
    }

    #[test]
    fn test_error_response() {
        let mut buf = vec![];
        assert!(matches!(
            swrap(
                ErrorResponse::serialize,
                ErrorResponse {
                    errorcode: ErrorCode::InternalServerError
                },
                &mut buf
            ),
            Ok(())
        ));
        assert_eq!(buf, [0x80, 2, 0, 2, 0, 2, 0x80, 0, 0, 0]);
    }

    #[test]
    fn test_request_basic() {
        let Ok(request) = pwrap(
            Request::parse,
            &[0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0x80, 0, 0, 0],
        ) else {
            panic!("Expected parse");
        };
        match request {
            Request::KeyExchange {
                algorithms,
                protocols,
                ..
            } => {
                assert_eq!(algorithms, [AeadAlgorithm::AeadAesSivCmac256].as_slice());
                assert_eq!(protocols, [NextProtocol::NTPv4].as_slice());
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Unexpected misparse of message"),
        }

        let Ok(request) = pwrap(
            Request::parse,
            &[
                0x80, 1, 0, 4, 0x80, 1, 0, 0, 0x80, 4, 0, 2, 0, 17, 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected parse");
        };
        match request {
            Request::KeyExchange {
                algorithms,
                protocols,
                ..
            } => {
                assert_eq!(algorithms, [AeadAlgorithm::AeadAesSivCmac512].as_slice());
                assert_eq!(
                    protocols,
                    [NextProtocol::DraftNTPv5, NextProtocol::NTPv4].as_slice()
                );
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Unexpected misparse of message"),
        }
    }

    #[test]
    fn test_request_basic_reject_incomplete() {
        assert!(pwrap(Request::parse, &[0x80, 1, 0, 2, 0, 0, 0x80, 0, 0, 0]).is_err());
        assert!(pwrap(Request::parse, &[0x80, 4, 0, 2, 0, 15, 0x80, 0, 0, 0]).is_err());
        assert!(pwrap(Request::parse, &[0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0]).is_err());
    }

    #[test]
    fn test_request_basic_reject_multiple() {
        assert!(
            pwrap(
                Request::parse,
                &[
                    0x80, 4, 0, 2, 0, 15, 0x80, 4, 0, 2, 0, 17, 0x80, 1, 0, 2, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );

        assert!(
            pwrap(
                Request::parse,
                &[
                    0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0x80, 1, 0, 2, 0x80, 1, 0x80, 0, 0,
                    0
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn test_request_basic_reject_problematic() {
        assert!(
            pwrap(
                Request::parse,
                &[
                    0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0xC0, 1, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );

        assert!(
            pwrap(
                Request::parse,
                &[
                    0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0xC0, 4, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );

        assert!(
            pwrap(
                Request::parse,
                &[
                    0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0x80, 2, 0, 2, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );

        assert!(
            pwrap(
                Request::parse,
                &[
                    0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0x80, 3, 0, 2, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );

        assert!(
            pwrap(
                Request::parse,
                &[
                    0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0, 5, 0, 4, 1, 2, 3, 4, 0x80, 0, 0,
                    0
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn test_request_basic_reject_unknown_critical() {
        assert!(
            pwrap(
                Request::parse,
                &[
                    0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0x80, 50, 0, 2, 0, 1, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn test_request_basic_ignore() {
        let Ok(request) = pwrap(
            Request::parse,
            &[
                0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0, 50, 0, 2, 1, 2, 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected parse");
        };
        match request {
            Request::KeyExchange {
                algorithms,
                protocols,
                ..
            } => {
                assert_eq!(algorithms, [AeadAlgorithm::AeadAesSivCmac256].as_slice());
                assert_eq!(protocols, [NextProtocol::NTPv4].as_slice());
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Unexpected misparse of message"),
        }

        let Ok(request) = pwrap(
            Request::parse,
            &[
                0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0x80, 6, 0, 2, b'h', b'i', 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected parse");
        };
        match request {
            Request::KeyExchange {
                algorithms,
                protocols,
                ..
            } => {
                assert_eq!(algorithms, [AeadAlgorithm::AeadAesSivCmac256].as_slice());
                assert_eq!(protocols, [NextProtocol::NTPv4].as_slice());
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Unexpected misparse of message"),
        }

        let Ok(request) = pwrap(
            Request::parse,
            &[
                0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0x80, 7, 0, 2, 0, 124, 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected parse");
        };
        match request {
            Request::KeyExchange {
                algorithms,
                protocols,
                ..
            } => {
                assert_eq!(algorithms, [AeadAlgorithm::AeadAesSivCmac256].as_slice());
                assert_eq!(protocols, [NextProtocol::NTPv4].as_slice());
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Unexpected misparse of message"),
        }

        let Ok(request) = pwrap(
            Request::parse,
            &[
                0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0x40, 3, 0, 2, b'h', b'i', 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected parse");
        };
        match request {
            Request::KeyExchange {
                algorithms,
                protocols,
                ..
            } => {
                assert_eq!(algorithms, [AeadAlgorithm::AeadAesSivCmac256].as_slice());
                assert_eq!(protocols, [NextProtocol::NTPv4].as_slice());
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Unexpected misparse of message"),
        }
    }

    #[cfg(feature = "nts-pool")]
    #[test]
    fn test_request_basic_denied_servers() {
        let Ok(request) = pwrap(
            Request::parse,
            &[
                0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0x40, 3, 0, 2, b'h', b'i', 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected parse");
        };
        match request {
            Request::KeyExchange {
                algorithms,
                protocols,
                denied_servers,
            } => {
                assert_eq!(algorithms, [AeadAlgorithm::AeadAesSivCmac256].as_slice());
                assert_eq!(protocols, [NextProtocol::NTPv4].as_slice());
                assert_eq!(denied_servers, ["hi"].as_slice());
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Unexpected misparse of message"),
        }
    }

    #[test]
    fn test_request_basic_serialize() {
        let mut buf = vec![];
        assert!(matches!(
            swrap(
                Request::serialize,
                Request::KeyExchange {
                    algorithms: [
                        AeadAlgorithm::AeadAesSivCmac512,
                        AeadAlgorithm::AeadAesSivCmac256
                    ]
                    .as_slice()
                    .into(),
                    protocols: [NextProtocol::NTPv4].as_slice().into(),
                    #[cfg(feature = "nts-pool")]
                    denied_servers: vec![].into(),
                },
                &mut buf
            ),
            Ok(())
        ));
        assert_eq!(
            buf,
            [
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 4, 0, 17, 0, 15, 0x80, 0, 0, 0
            ]
        );
    }

    #[cfg(feature = "nts-pool")]
    #[test]
    fn test_request_basic_serialize_denied_servers() {
        let mut buf = vec![];
        assert!(
            swrap(
                Request::serialize,
                Request::KeyExchange {
                    algorithms: [AeadAlgorithm::AeadAesSivCmac256].as_slice().into(),
                    protocols: [NextProtocol::NTPv4].as_slice().into(),
                    denied_servers: ["hi".into()].as_slice().into(),
                },
                &mut buf
            )
            .is_ok()
        );

        assert_eq!(
            buf,
            [
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 15, 0x40, 3, 0, 2, b'h', b'i', 0x80, 0, 0, 0
            ]
        );
    }

    #[cfg(feature = "nts-pool")]
    #[test]
    fn test_request_fixedkey() {
        let Ok(Request::FixedKey {
            c2s_key,
            s2c_key,
            algorithm,
            protocol,
        }) = pwrap(
            Request::parse,
            &[
                0xC0, 2, 0, 64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
                40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
                61, 62, 63, 0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 15, 0x80, 0, 0, 0,
            ],
        )
        else {
            panic!("Expected parse as fixedkey");
        };
        assert_eq!(
            c2s_key.key_bytes(),
            [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31
            ]
        );
        assert_eq!(
            s2c_key.key_bytes(),
            [
                32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
                53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63
            ]
        );
        assert_eq!(algorithm, AeadAlgorithm::AeadAesSivCmac256);
        assert_eq!(protocol, NextProtocol::NTPv4);

        let Ok(Request::FixedKey {
            c2s_key,
            s2c_key,
            algorithm,
            protocol,
        }) = pwrap(
            Request::parse,
            &[
                0xC0, 2, 0, 128, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
                40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
                61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81,
                82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101,
                102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117,
                118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 0x80, 1, 0, 2, 0, 0, 0x80, 4, 0,
                2, 0, 17, 0x80, 0, 0, 0,
            ],
        )
        else {
            panic!("Expected parse as fixedkey");
        };
        assert_eq!(
            c2s_key.key_bytes(),
            [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
                44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63
            ]
        );
        assert_eq!(
            s2c_key.key_bytes(),
            [
                64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84,
                85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103,
                104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
                120, 121, 122, 123, 124, 125, 126, 127
            ]
        );
        assert_eq!(algorithm, AeadAlgorithm::AeadAesSivCmac512);
        assert_eq!(protocol, NextProtocol::NTPv4);

        let Ok(Request::FixedKey {
            c2s_key,
            s2c_key,
            algorithm,
            protocol,
        }) = pwrap(
            Request::parse,
            &[
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 15, 0xC0, 2, 0, 64, 0, 1, 2, 3, 4, 5, 6, 7,
                8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
                29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
                50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 0x80, 0, 0, 0,
            ],
        )
        else {
            panic!("Expected parse as fixedkey");
        };
        assert_eq!(
            c2s_key.key_bytes(),
            [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31
            ]
        );
        assert_eq!(
            s2c_key.key_bytes(),
            [
                32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
                53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63
            ]
        );
        assert_eq!(algorithm, AeadAlgorithm::AeadAesSivCmac256);
        assert_eq!(protocol, NextProtocol::NTPv4);
    }

    #[cfg(feature = "nts-pool")]
    #[test]
    fn test_request_fixedkey_reject_incomplete() {
        assert!(
            pwrap(
                Request::parse,
                &[
                    0xC0, 2, 0, 64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
                    18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
                    38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
                    58, 59, 60, 61, 62, 63, 0x80, 4, 0, 2, 0, 15, 0x80, 0, 0, 0,
                ],
            )
            .is_err()
        );
        assert!(
            pwrap(
                Request::parse,
                &[
                    0xC0, 2, 0, 64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
                    18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
                    38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
                    58, 59, 60, 61, 62, 63, 0x80, 1, 0, 2, 0, 0, 0x80, 0, 0, 0,
                ],
            )
            .is_err()
        );
        assert!(
            pwrap(
                Request::parse,
                &[
                    0xC0, 2, 0, 64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
                    18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
                    38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
                    58, 59, 60, 61, 62, 63, 0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 15,
                ],
            )
            .is_err()
        );
    }

    #[cfg(feature = "nts-pool")]
    #[test]
    fn test_request_fixedkey_reject_multiple() {
        assert!(
            pwrap(
                Request::parse,
                &[
                    0xC0, 2, 0, 64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
                    18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
                    38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
                    58, 59, 60, 61, 62, 63, 0xC0, 2, 0, 64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
                    12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
                    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 0x80, 1, 0, 2, 0, 0, 0x80, 4,
                    0, 2, 0, 15, 0x80, 0, 0, 0,
                ]
            )
            .is_err()
        );

        assert!(
            pwrap(
                Request::parse,
                &[
                    0xC0, 2, 0, 64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
                    18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
                    38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
                    58, 59, 60, 61, 62, 63, 0x80, 1, 0, 4, 0, 0, 0x80, 1, 0x80, 4, 0, 2, 0, 15,
                    0x80, 0, 0, 0,
                ]
            )
            .is_err()
        );

        assert!(
            pwrap(
                Request::parse,
                &[
                    0xC0, 2, 0, 64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
                    18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
                    38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
                    58, 59, 60, 61, 62, 63, 0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 4, 0, 15, 0, 15, 0x80,
                    0, 0, 0,
                ]
            )
            .is_err()
        );
    }

    #[cfg(feature = "nts-pool")]
    #[test]
    fn test_request_fixedkey_reject_wrong_size_keys() {
        assert!(
            pwrap(
                Request::parse,
                &[
                    0xC0, 2, 0, 4, 1, 2, 3, 4, 0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 15, 0x80, 0,
                    0, 0
                ]
            )
            .is_err()
        );
    }

    #[cfg(feature = "nts-pool")]
    #[test]
    fn test_request_fixedkey_reject_unknown_algorithm() {
        assert!(
            pwrap(
                Request::parse,
                &[
                    0xC0, 2, 0, 64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
                    18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
                    38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
                    58, 59, 60, 61, 62, 63, 0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 2, 0x80, 0, 0,
                    0,
                ]
            )
            .is_err()
        );
    }

    #[cfg(feature = "nts-pool")]
    #[test]
    fn test_request_fixedkey_reject_problematic() {
        assert!(
            pwrap(
                Request::parse,
                &[
                    0xC0, 2, 0, 64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
                    18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
                    38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
                    58, 59, 60, 61, 62, 63, 0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 15, 0xC0, 1, 0,
                    0, 0x80, 0, 0, 0,
                ],
            )
            .is_err()
        );

        assert!(
            pwrap(
                Request::parse,
                &[
                    0xC0, 2, 0, 64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
                    18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
                    38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
                    58, 59, 60, 61, 62, 63, 0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 15, 0xC0, 4, 0,
                    0, 0x80, 0, 0, 0,
                ],
            )
            .is_err()
        );
    }

    #[cfg(feature = "nts-pool")]
    #[test]
    fn test_request_fixedkey_reject_unknown_critical() {
        assert!(
            pwrap(
                Request::parse,
                &[
                    0xC0, 2, 0, 64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
                    18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
                    38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
                    58, 59, 60, 61, 62, 63, 0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 15, 0x80, 50, 0,
                    2, 1, 2, 0x80, 0, 0, 0,
                ],
            )
            .is_err()
        );
    }

    #[cfg(feature = "nts-pool")]
    #[test]
    fn test_request_fixedkey_ignore() {
        let Ok(Request::FixedKey {
            c2s_key,
            s2c_key,
            algorithm,
            protocol,
        }) = pwrap(
            Request::parse,
            &[
                0xC0, 2, 0, 64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
                40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
                61, 62, 63, 0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 15, 0x80, 6, 0, 2, b'h', b'i',
                0x80, 0, 0, 0,
            ],
        )
        else {
            panic!("Expected parse as fixedkey");
        };
        assert_eq!(
            c2s_key.key_bytes(),
            [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31
            ]
        );
        assert_eq!(
            s2c_key.key_bytes(),
            [
                32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
                53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63
            ]
        );
        assert_eq!(algorithm, AeadAlgorithm::AeadAesSivCmac256);
        assert_eq!(protocol, NextProtocol::NTPv4);

        let Ok(Request::FixedKey {
            c2s_key,
            s2c_key,
            algorithm,
            protocol,
        }) = pwrap(
            Request::parse,
            &[
                0xC0, 2, 0, 64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
                40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
                61, 62, 63, 0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 15, 0x80, 7, 0, 2, 0, 124, 0x80,
                0, 0, 0,
            ],
        )
        else {
            panic!("Expected parse as fixedkey");
        };
        assert_eq!(
            c2s_key.key_bytes(),
            [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31
            ]
        );
        assert_eq!(
            s2c_key.key_bytes(),
            [
                32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
                53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63
            ]
        );
        assert_eq!(algorithm, AeadAlgorithm::AeadAesSivCmac256);
        assert_eq!(protocol, NextProtocol::NTPv4);

        let Ok(Request::FixedKey {
            c2s_key,
            s2c_key,
            algorithm,
            protocol,
        }) = pwrap(
            Request::parse,
            &[
                0xC0, 2, 0, 64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
                40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
                61, 62, 63, 0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 15, 0x40, 3, 0, 2, b'h', b'i',
                0x80, 0, 0, 0,
            ],
        )
        else {
            panic!("Expected parse as fixedkey");
        };
        assert_eq!(
            c2s_key.key_bytes(),
            [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31
            ]
        );
        assert_eq!(
            s2c_key.key_bytes(),
            [
                32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
                53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63
            ]
        );
        assert_eq!(algorithm, AeadAlgorithm::AeadAesSivCmac256);
        assert_eq!(protocol, NextProtocol::NTPv4);

        let Ok(Request::FixedKey {
            c2s_key,
            s2c_key,
            algorithm,
            protocol,
        }) = pwrap(
            Request::parse,
            &[
                0xC0, 2, 0, 64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
                40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
                61, 62, 63, 0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 15, 0, 50, 0, 2, 1, 2, 0x80, 0,
                0, 0,
            ],
        )
        else {
            panic!("Expected parse as fixedkey");
        };
        assert_eq!(
            c2s_key.key_bytes(),
            [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31
            ]
        );
        assert_eq!(
            s2c_key.key_bytes(),
            [
                32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
                53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63
            ]
        );
        assert_eq!(algorithm, AeadAlgorithm::AeadAesSivCmac256);
        assert_eq!(protocol, NextProtocol::NTPv4);
    }

    #[cfg(feature = "nts-pool")]
    #[test]
    fn test_request_fixedkey_serialize() {
        use crate::packet::AesSivCmac256;

        let mut buf = vec![];
        assert!(matches!(
            swrap(
                Request::serialize,
                Request::FixedKey {
                    c2s_key: Box::new(AesSivCmac256::new(
                        [
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                            20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
                        ]
                        .into()
                    )),
                    s2c_key: Box::new(AesSivCmac256::new(
                        [
                            32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
                            50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63
                        ]
                        .into()
                    )),
                    algorithm: AeadAlgorithm::AeadAesSivCmac256,
                    protocol: NextProtocol::NTPv4
                },
                &mut buf
            ),
            Ok(())
        ));
        assert_eq!(
            buf,
            [
                0xC0, 2, 0, 64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
                40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
                61, 62, 63, 0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 15, 0x80, 0, 0, 0
            ]
        );
    }

    #[cfg(feature = "nts-pool")]
    #[test]
    fn test_request_support() {
        let Ok(Request::Support {
            wants_protocols,
            wants_algorithms,
        }) = pwrap(Request::parse, &[0xC0, 1, 0, 0, 0x80, 0, 0, 0])
        else {
            panic!("Parse problem");
        };
        assert!(wants_algorithms);
        assert!(!wants_protocols);

        let Ok(Request::Support {
            wants_protocols,
            wants_algorithms,
        }) = pwrap(Request::parse, &[0xC0, 4, 0, 0, 0x80, 0, 0, 0])
        else {
            panic!("Parse problem");
        };
        assert!(!wants_algorithms);
        assert!(wants_protocols);

        let Ok(Request::Support {
            wants_protocols,
            wants_algorithms,
        }) = pwrap(
            Request::parse,
            &[0xC0, 1, 0, 0, 0xC0, 4, 0, 0, 0x80, 0, 0, 0],
        )
        else {
            panic!("Parse problem");
        };
        assert!(wants_algorithms);
        assert!(wants_protocols);
    }

    #[cfg(feature = "nts-pool")]
    #[test]
    fn test_request_support_reject_multiple() {
        assert!(
            pwrap(
                Request::parse,
                &[0xC0, 1, 0, 0, 0xC0, 1, 0, 0, 0x80, 0, 0, 0]
            )
            .is_err()
        );
        assert!(
            pwrap(
                Request::parse,
                &[0xC0, 4, 0, 0, 0xC0, 4, 0, 0, 0x80, 0, 0, 0]
            )
            .is_err()
        );
    }

    #[cfg(feature = "nts-pool")]
    #[test]
    fn test_request_support_reject_problematic() {
        assert!(
            pwrap(
                Request::parse,
                &[
                    0xC0, 1, 0, 0, 0xC0, 4, 0, 0, 0xC0, 2, 0, 2, 1, 2, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                Request::parse,
                &[
                    0xC0, 1, 0, 0, 0xC0, 4, 0, 0, 0x80, 2, 0, 2, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                Request::parse,
                &[
                    0xC0, 1, 0, 0, 0xC0, 4, 0, 0, 0x80, 3, 0, 2, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                Request::parse,
                &[
                    0xC0, 1, 0, 0, 0xC0, 4, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                Request::parse,
                &[
                    0xC0, 1, 0, 0, 0xC0, 4, 0, 0, 0x80, 4, 0, 2, 0, 15, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                Request::parse,
                &[
                    0xC0, 1, 0, 0, 0xC0, 4, 0, 0, 0x80, 5, 0, 2, 1, 2, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
    }

    #[cfg(feature = "nts-pool")]
    #[test]
    fn test_request_support_reject_unknown_critical() {
        assert!(
            pwrap(
                Request::parse,
                &[0xC0, 1, 0, 0, 0xC0, 4, 0, 0, 0x80, 50, 0, 0, 0x80, 0, 0, 0]
            )
            .is_err()
        );
    }

    #[cfg(feature = "nts-pool")]
    #[test]
    fn test_request_support_ignore() {
        let Ok(Request::Support {
            wants_protocols,
            wants_algorithms,
        }) = pwrap(
            Request::parse,
            &[
                0xC0, 1, 0, 0, 0xC0, 4, 0, 0, 0x80, 6, 0, 2, b'h', b'i', 0x80, 0, 0, 0,
            ],
        )
        else {
            panic!("Parse problem");
        };
        assert!(wants_algorithms);
        assert!(wants_protocols);

        let Ok(Request::Support {
            wants_protocols,
            wants_algorithms,
        }) = pwrap(
            Request::parse,
            &[
                0xC0, 1, 0, 0, 0xC0, 4, 0, 0, 0x80, 7, 0, 2, 0, 124, 0x80, 0, 0, 0,
            ],
        )
        else {
            panic!("Parse problem");
        };
        assert!(wants_algorithms);
        assert!(wants_protocols);

        let Ok(Request::Support {
            wants_protocols,
            wants_algorithms,
        }) = pwrap(
            Request::parse,
            &[
                0xC0, 1, 0, 0, 0xC0, 4, 0, 0, 0x40, 3, 0, 2, b'h', b'i', 0x80, 0, 0, 0,
            ],
        )
        else {
            panic!("Parse problem");
        };
        assert!(wants_algorithms);
        assert!(wants_protocols);

        let Ok(Request::Support {
            wants_protocols,
            wants_algorithms,
        }) = pwrap(
            Request::parse,
            &[0xC0, 1, 0, 0, 0xC0, 4, 0, 0, 0x40, 0, 0, 0, 0x80, 0, 0, 0],
        )
        else {
            panic!("Parse problem");
        };
        assert!(wants_algorithms);
        assert!(wants_protocols);
    }

    #[cfg(feature = "nts-pool")]
    #[test]
    fn test_request_support_serialize() {
        let mut buf = vec![];
        assert!(matches!(
            swrap(
                Request::serialize,
                Request::Support {
                    wants_algorithms: false,
                    wants_protocols: false
                },
                &mut buf
            ),
            Ok(())
        ));
        assert_eq!(buf, [0x80, 0, 0, 0]);

        let mut buf = vec![];
        assert!(matches!(
            swrap(
                Request::serialize,
                Request::Support {
                    wants_algorithms: true,
                    wants_protocols: false
                },
                &mut buf
            ),
            Ok(())
        ));
        assert_eq!(buf, [0xC0, 1, 0, 0, 0x80, 0, 0, 0]);

        let mut buf = vec![];
        assert!(matches!(
            swrap(
                Request::serialize,
                Request::Support {
                    wants_algorithms: false,
                    wants_protocols: true
                },
                &mut buf
            ),
            Ok(())
        ));
        assert_eq!(buf, [0xC0, 4, 0, 0, 0x80, 0, 0, 0]);

        let mut buf = vec![];
        assert!(matches!(
            swrap(
                Request::serialize,
                Request::Support {
                    wants_algorithms: true,
                    wants_protocols: true
                },
                &mut buf
            ),
            Ok(())
        ));
        assert_eq!(buf, [0xC0, 4, 0, 0, 0xC0, 1, 0, 0, 0x80, 0, 0, 0]);
    }

    #[test]
    fn test_key_exchange_response_parse_basic() {
        let Ok(response) = pwrap(
            KeyExchangeResponse::parse,
            &[0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 17, 0x80, 0, 0, 0],
        ) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(response.protocol, NextProtocol::NTPv4);
        assert_eq!(response.algorithm, AeadAlgorithm::AeadAesSivCmac512);
        assert_eq!(response.cookies, [].as_slice() as &[Cow<'static, [u8]>]);
        assert_eq!(response.port, None);
        assert_eq!(response.server, None);

        let Ok(response) = pwrap(
            KeyExchangeResponse::parse,
            &[
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 17, 0x80, 5, 0, 2, 1, 2, 0x80, 5, 0, 2, 3,
                4, 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(response.protocol, NextProtocol::NTPv4);
        assert_eq!(response.algorithm, AeadAlgorithm::AeadAesSivCmac512);
        assert_eq!(
            response.cookies,
            [[1u8, 2].as_slice().into(), [3u8, 4].as_slice().into()].as_slice()
                as &[Cow<'static, [u8]>]
        );
        assert_eq!(response.port, None);
        assert_eq!(response.server, None);

        let Ok(response) = pwrap(
            KeyExchangeResponse::parse,
            &[
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 15, 0x80, 6, 0, 2, b'h', b'i', 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(response.protocol, NextProtocol::NTPv4);
        assert_eq!(response.algorithm, AeadAlgorithm::AeadAesSivCmac256);
        assert_eq!(response.cookies, [].as_slice() as &[Cow<'static, [u8]>]);
        assert_eq!(response.port, None);
        assert_eq!(response.server, Some("hi".into()));

        let Ok(response) = pwrap(
            KeyExchangeResponse::parse,
            &[
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 15, 0x80, 7, 0, 2, 0, 5, 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(response.protocol, NextProtocol::NTPv4);
        assert_eq!(response.algorithm, AeadAlgorithm::AeadAesSivCmac256);
        assert_eq!(response.cookies, [].as_slice() as &[Cow<'static, [u8]>]);
        assert_eq!(response.port, Some(5));
        assert_eq!(response.server, None);

        let Ok(response) = pwrap(
            KeyExchangeResponse::parse,
            &[
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 17, 0x80, 5, 0, 2, 1, 2, 0x80, 5, 0, 2, 3,
                4, 0x80, 6, 0, 2, b'h', b'i', 0x80, 7, 0, 2, 0, 5, 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(response.protocol, NextProtocol::NTPv4);
        assert_eq!(response.algorithm, AeadAlgorithm::AeadAesSivCmac512);
        assert_eq!(
            response.cookies,
            [[1u8, 2].as_slice().into(), [3u8, 4].as_slice().into()].as_slice()
                as &[Cow<'static, [u8]>]
        );
        assert_eq!(response.port, Some(5));
        assert_eq!(response.server, Some("hi".into()));
    }

    #[test]
    fn test_key_exchange_response_reject_incomplete() {
        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4]
            )
            .is_err()
        );
        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[0x80, 1, 0, 2, 0, 0, 0x80, 0, 0, 0]
            )
            .is_err()
        );
        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[0x80, 4, 0, 2, 0, 4, 0x80, 0, 0, 0]
            )
            .is_err()
        );
    }

    #[test]
    fn test_key_exchange_response_reject_multiple() {
        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[
                    0x80, 1, 0, 4, 0, 0, 0x80, 1, 0x80, 4, 0, 2, 0, 15, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );

        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[
                    0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 4, 0, 15, 0, 17, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn test_key_exchange_response_reject_repeated() {
        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[
                    0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 15, 0x80, 4, 0, 2, 0, 17, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );

        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[
                    0x80, 1, 0, 2, 0, 0, 0x80, 1, 0, 2, 0x80, 1, 0x80, 4, 0, 2, 0, 15, 0x80, 0, 0,
                    0
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn test_key_exchange_response_reject_problematic() {
        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[
                    0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0xC0, 4, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[
                    0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0xC0, 1, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[
                    0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0xC0, 2, 0, 2, 1, 2, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[
                    0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0xC0, 3, 0, 2, b'h', b'i', 0x80, 0,
                    0, 0
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn test_key_exchange_response_reject_unknown_critical() {
        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[
                    0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x80, 50, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn test_key_exchange_response_ignore() {
        let Ok(response) = pwrap(
            KeyExchangeResponse::parse,
            &[
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0, 50, 0, 0, 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(response.protocol, NextProtocol::NTPv4);
        assert_eq!(response.algorithm, AeadAlgorithm::Unknown(4));
        assert_eq!(response.cookies, [].as_slice() as &[Cow<'static, [u8]>]);
        assert_eq!(response.port, None);
        assert_eq!(response.server, None);
    }

    #[test]
    fn test_key_exchange_response_parse_error_warning() {
        assert!(matches!(
            pwrap(
                KeyExchangeResponse::parse,
                &[0x80, 2, 0, 2, 0, 0, 0x80, 0, 0, 0]
            ),
            Err(NtsError::Error(ErrorCode::UnrecognizedCriticalRecord))
        ));
        assert!(matches!(
            pwrap(
                KeyExchangeResponse::parse,
                &[0x80, 3, 0, 2, 0, 1, 0x80, 0, 0, 0]
            ),
            Err(NtsError::UnknownWarning(1))
        ));
    }

    #[test]
    fn test_key_exchange_response_no_overlap() {
        assert!(matches!(
            pwrap(KeyExchangeResponse::parse, &[0x80, 1, 0, 0, 0x80, 0, 0, 0]),
            Err(NtsError::NoOverlappingProtocol)
        ));
        assert!(matches!(
            pwrap(
                KeyExchangeResponse::parse,
                &[0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 0, 0x80, 0, 0, 0]
            ),
            Err(NtsError::NoOverlappingAlgorithm)
        ));
    }

    #[test]
    fn test_key_exchange_response_serialize() {
        let mut buf = vec![];
        assert!(
            swrap(
                KeyExchangeResponse::serialize,
                KeyExchangeResponse {
                    protocol: NextProtocol::NTPv4,
                    algorithm: AeadAlgorithm::Unknown(4),
                    cookies: [].as_slice().into(),
                    server: None,
                    port: None
                },
                &mut buf
            )
            .is_ok()
        );
        assert_eq!(
            buf,
            [0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x80, 0, 0, 0]
        );

        let mut buf = vec![];
        assert!(
            swrap(
                KeyExchangeResponse::serialize,
                KeyExchangeResponse {
                    protocol: NextProtocol::NTPv4,
                    algorithm: AeadAlgorithm::Unknown(4),
                    cookies: [[1, 2, 3].as_slice().into(), [4, 5].as_slice().into()]
                        .as_slice()
                        .into(),
                    server: None,
                    port: None
                },
                &mut buf
            )
            .is_ok()
        );
        assert_eq!(
            buf,
            [
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0, 5, 0, 3, 1, 2, 3, 0, 5, 0, 2, 4, 5,
                0x80, 0, 0, 0
            ]
        );

        let mut buf = vec![];
        assert!(
            swrap(
                KeyExchangeResponse::serialize,
                KeyExchangeResponse {
                    protocol: NextProtocol::NTPv4,
                    algorithm: AeadAlgorithm::Unknown(4),
                    cookies: [].as_slice().into(),
                    server: Some("hi".into()),
                    port: None
                },
                &mut buf
            )
            .is_ok()
        );
        assert_eq!(
            buf,
            [
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x80, 6, 0, 2, b'h', b'i', 0x80, 0, 0, 0
            ]
        );

        let mut buf = vec![];
        assert!(
            swrap(
                KeyExchangeResponse::serialize,
                KeyExchangeResponse {
                    protocol: NextProtocol::NTPv4,
                    algorithm: AeadAlgorithm::Unknown(4),
                    cookies: [].as_slice().into(),
                    server: None,
                    port: Some(15)
                },
                &mut buf
            )
            .is_ok()
        );
        assert_eq!(
            buf,
            [
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x80, 7, 0, 2, 0, 15, 0x80, 0, 0, 0
            ]
        );

        let mut buf = vec![];
        assert!(
            swrap(
                KeyExchangeResponse::serialize,
                KeyExchangeResponse {
                    protocol: NextProtocol::NTPv4,
                    algorithm: AeadAlgorithm::Unknown(4),
                    cookies: [[1, 2, 3].as_slice().into(), [4, 5].as_slice().into()]
                        .as_slice()
                        .into(),
                    server: Some("hi".into()),
                    port: Some(15)
                },
                &mut buf
            )
            .is_ok()
        );
        assert_eq!(
            buf,
            [
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0, 5, 0, 3, 1, 2, 3, 0, 5, 0, 2, 4, 5,
                0x80, 6, 0, 2, b'h', b'i', 0x80, 7, 0, 2, 0, 15, 0x80, 0, 0, 0
            ]
        );
    }

    #[cfg(feature = "nts-pool")]
    #[test]
    fn test_support_response() {
        let mut buf = vec![];
        assert!(
            swrap(
                SupportsResponse::serialize,
                SupportsResponse {
                    algorithms: Some(
                        [AeadAlgorithm::AeadAesSivCmac256.description().unwrap()]
                            .as_slice()
                            .into()
                    ),
                    protocols: None
                },
                &mut buf
            )
            .is_ok()
        );
        assert_eq!(buf, [0xC0, 1, 0, 4, 0, 15, 0, 32, 0x80, 0, 0, 0]);

        let mut buf = vec![];
        assert!(
            swrap(
                SupportsResponse::serialize,
                SupportsResponse {
                    algorithms: Some(
                        [AeadAlgorithm::AeadAesSivCmac256.description().unwrap()]
                            .as_slice()
                            .into()
                    ),
                    protocols: Some([NextProtocol::NTPv4].as_slice().into()),
                },
                &mut buf
            )
            .is_ok()
        );
        assert_eq!(
            buf,
            [
                0xC0, 1, 0, 4, 0, 15, 0, 32, 0xC0, 4, 0, 2, 0, 0, 0x80, 0, 0, 0
            ]
        );

        let mut buf = vec![];
        assert!(
            swrap(
                SupportsResponse::serialize,
                SupportsResponse {
                    algorithms: None,
                    protocols: Some([NextProtocol::NTPv4].as_slice().into()),
                },
                &mut buf
            )
            .is_ok()
        );
        assert_eq!(buf, [0xC0, 4, 0, 2, 0, 0, 0x80, 0, 0, 0]);
    }

    #[test]
    fn test_no_overlap_response() {
        let mut buf = vec![];
        assert!(
            swrap(
                NoOverlapResponse::serialize,
                NoOverlapResponse::NoOverlappingAlgorithm {
                    protocol: NextProtocol::NTPv4
                },
                &mut buf
            )
            .is_ok()
        );
        assert_eq!(buf, [0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 0, 0x80, 0, 0, 0]);

        let mut buf = vec![];
        assert!(
            swrap(
                NoOverlapResponse::serialize,
                NoOverlapResponse::NoOverlappingProtocol,
                &mut buf
            )
            .is_ok()
        );
        assert_eq!(buf, [0x80, 1, 0, 0, 0x80, 0, 0, 0]);
    }
}
