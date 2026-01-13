use std::{
    borrow::Cow,
    io::{Error, ErrorKind},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Take};

use crate::nts::{AeadAlgorithm, NextProtocol};

use super::AlgorithmDescription;
use super::{ErrorCode, WarningCode};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NtsRecord<'a> {
    EndOfMessage,
    NextProtocol {
        #[cfg_attr(feature = "__internal-fuzz", allow(private_interfaces))]
        protocol_ids: Cow<'a, [NextProtocol]>,
    },
    Error {
        errorcode: ErrorCode,
    },
    Warning {
        warningcode: WarningCode,
    },
    AeadAlgorithm {
        algorithm_ids: Cow<'a, [AeadAlgorithm]>,
    },
    NewCookie {
        cookie_data: Cow<'a, [u8]>,
    },
    Server {
        name: Cow<'a, str>,
    },
    Port {
        port: u16,
    },
    Unknown {
        record_type: u16,
        critical: bool,
        data: Cow<'a, [u8]>,
    },
    KeepAlive,
    SupportedNextProtocolList {
        #[cfg_attr(feature = "__internal-fuzz", allow(private_interfaces))]
        supported_protocols: Cow<'a, [NextProtocol]>,
    },
    SupportedAlgorithmList {
        #[cfg_attr(feature = "__internal-fuzz", allow(private_interfaces))]
        supported_algorithms: Cow<'a, [AlgorithmDescription]>,
    },
    FixedKeyRequest {
        c2s: Cow<'a, [u8]>,
        s2c: Cow<'a, [u8]>,
    },
    NtpServerDeny {
        denied: Cow<'a, str>,
    },
    Authentication {
        key: Cow<'a, str>,
    },
}

impl NtsRecord<'_> {
    pub async fn parse(mut reader: impl AsyncRead + Unpin) -> Result<Self, Error> {
        let record_type = reader.read_u16().await?;
        let size = reader.read_u16().await?;

        let critical = (record_type & 0x8000) != 0;
        let record_type = record_type & 0x7FFF;
        let mut body = reader.take(size.into());

        match record_type {
            0 => Self::parse_end_of_message(body).await,
            1 => Self::parse_next_protocol(body).await,
            2 => Self::parse_error(body).await,
            3 => Self::parse_warning(body).await,
            4 => Self::parse_aead_algorithm(body).await,
            5 => Self::parse_new_cookie(body).await,
            6 => Self::parse_server(body).await,
            7 => Self::parse_port(body).await,
            0x4000 => Self::parse_keep_alive(body).await,
            0x4004 => Self::parse_supported_next_protocol_list(body).await,
            0x4001 => Self::parse_supported_algorithm_list(body).await,
            0x4002 => Self::parse_fixed_key_request(body).await,
            0x4003 => Self::parse_ntp_server_deny(body).await,
            0x4005 => Self::parse_authentication(body).await,
            _ => {
                let mut data = vec![0; size.into()];
                body.read_exact(&mut data).await?;
                Ok(Self::Unknown {
                    record_type,
                    critical,
                    data: data.into(),
                })
            }
        }
    }

    async fn parse_end_of_message(mut reader: Take<impl AsyncRead + Unpin>) -> Result<Self, Error> {
        let mut buf = [0; 512];
        while reader.read(&mut buf).await? != 0 {}
        if reader.limit() != 0 {
            Err(ErrorKind::UnexpectedEof.into())
        } else {
            Ok(NtsRecord::EndOfMessage)
        }
    }

    async fn parse_next_protocol(mut reader: Take<impl AsyncRead + Unpin>) -> Result<Self, Error> {
        let mut protocol_ids =
            Vec::with_capacity(reader.limit().try_into().unwrap_or(usize::MAX) / size_of::<u16>());
        while reader.limit() != 0 {
            protocol_ids.push(reader.read_u16().await?.into());
        }

        Ok(Self::NextProtocol {
            protocol_ids: protocol_ids.into(),
        })
    }

    async fn parse_error(mut reader: Take<impl AsyncRead + Unpin>) -> Result<Self, Error> {
        let errorcode = reader.read_u16().await?.into();
        if reader.limit() != 0 {
            Err(ErrorKind::InvalidData.into())
        } else {
            Ok(Self::Error { errorcode })
        }
    }

    async fn parse_warning(mut reader: Take<impl AsyncRead + Unpin>) -> Result<Self, Error> {
        let warningcode = reader.read_u16().await?.into();
        if reader.limit() != 0 {
            Err(ErrorKind::InvalidData.into())
        } else {
            Ok(Self::Warning { warningcode })
        }
    }

    async fn parse_aead_algorithm(mut reader: Take<impl AsyncRead + Unpin>) -> Result<Self, Error> {
        let mut algorithm_ids =
            Vec::with_capacity(reader.limit().try_into().unwrap_or(usize::MAX) / size_of::<u16>());
        while reader.limit() != 0 {
            algorithm_ids.push(reader.read_u16().await?.into());
        }

        Ok(Self::AeadAlgorithm {
            algorithm_ids: algorithm_ids.into(),
        })
    }

    async fn parse_new_cookie(mut reader: Take<impl AsyncRead + Unpin>) -> Result<Self, Error> {
        let mut cookie_data = vec![0; reader.limit().try_into().unwrap_or(usize::MAX)];
        reader.read_exact(&mut cookie_data).await?;
        Ok(Self::NewCookie {
            cookie_data: cookie_data.into(),
        })
    }

    async fn parse_server(mut reader: Take<impl AsyncRead + Unpin>) -> Result<Self, Error> {
        let mut name = String::new();
        reader.read_to_string(&mut name).await?;
        if reader.limit() != 0 {
            return Err(ErrorKind::UnexpectedEof.into());
        }

        Ok(Self::Server { name: name.into() })
    }

    async fn parse_port(mut reader: Take<impl AsyncRead + Unpin>) -> Result<Self, Error> {
        let port = reader.read_u16().await?;
        if reader.limit() != 0 {
            Err(ErrorKind::InvalidData.into())
        } else {
            Ok(Self::Port { port })
        }
    }

    async fn parse_keep_alive(mut reader: Take<impl AsyncRead + Unpin>) -> Result<Self, Error> {
        let mut buf = [0; 512];
        while reader.read(&mut buf).await? != 0 {}
        if reader.limit() != 0 {
            Err(ErrorKind::UnexpectedEof.into())
        } else {
            Ok(NtsRecord::KeepAlive)
        }
    }

    async fn parse_supported_next_protocol_list(
        mut reader: Take<impl AsyncRead + Unpin>,
    ) -> Result<Self, Error> {
        let mut supported_protocols =
            Vec::with_capacity(reader.limit().try_into().unwrap_or(usize::MAX) / size_of::<u16>());
        while reader.limit() != 0 {
            supported_protocols.push(reader.read_u16().await?.into());
        }
        Ok(Self::SupportedNextProtocolList {
            supported_protocols: supported_protocols.into(),
        })
    }

    async fn parse_supported_algorithm_list(
        mut reader: Take<impl AsyncRead + Unpin>,
    ) -> Result<Self, Error> {
        let mut supported_algorithms = Vec::with_capacity(
            reader.limit().try_into().unwrap_or(usize::MAX) / (2 * size_of::<u16>()),
        );
        while reader.limit() != 0 {
            supported_algorithms.push(AlgorithmDescription {
                id: reader.read_u16().await?.into(),
                keysize: reader.read_u16().await?,
            });
        }
        Ok(Self::SupportedAlgorithmList {
            supported_algorithms: supported_algorithms.into(),
        })
    }

    async fn parse_fixed_key_request(
        mut reader: Take<impl AsyncRead + Unpin>,
    ) -> Result<Self, Error> {
        let n = reader.limit() / 2;
        let mut c2s = vec![0; n.try_into().unwrap_or(usize::MAX)];
        reader.read_exact(&mut c2s).await?;
        let mut s2c = vec![0; n.try_into().unwrap_or(usize::MAX)];
        reader.read_exact(&mut s2c).await?;
        if reader.limit() != 0 {
            Err(ErrorKind::InvalidData.into())
        } else {
            Ok(Self::FixedKeyRequest {
                c2s: c2s.into(),
                s2c: s2c.into(),
            })
        }
    }

    async fn parse_ntp_server_deny(
        mut reader: Take<impl AsyncRead + Unpin>,
    ) -> Result<Self, Error> {
        let mut denied = String::new();
        reader.read_to_string(&mut denied).await?;
        if reader.limit() != 0 {
            return Err(ErrorKind::UnexpectedEof.into());
        }
        Ok(Self::NtpServerDeny {
            denied: denied.into(),
        })
    }

    async fn parse_authentication(mut reader: Take<impl AsyncRead + Unpin>) -> Result<Self, Error> {
        let mut key = String::new();
        reader.read_to_string(&mut key).await?;
        if reader.limit() != 0 {
            return Err(ErrorKind::UnexpectedEof.into());
        }
        Ok(Self::Authentication { key: key.into() })
    }

    pub async fn serialize(&self, mut writer: impl AsyncWrite + Unpin) -> Result<(), Error> {
        writer.write_u16(self.record_type()).await?;
        let size: u16 = self
            .body_size()
            .try_into()
            .map_err(|_| ErrorKind::InvalidInput)?;
        writer.write_u16(size).await?;
        match self {
            NtsRecord::EndOfMessage | NtsRecord::KeepAlive => {}
            NtsRecord::NextProtocol { protocol_ids } => {
                for &id in protocol_ids.iter() {
                    writer.write_u16(id.into()).await?;
                }
            }
            &NtsRecord::Error { errorcode } => writer.write_u16(errorcode.into()).await?,
            &NtsRecord::Warning { warningcode } => writer.write_u16(warningcode.into()).await?,
            NtsRecord::AeadAlgorithm { algorithm_ids } => {
                for &id in algorithm_ids.iter() {
                    writer.write_u16(id.into()).await?;
                }
            }
            NtsRecord::NewCookie { cookie_data } => writer.write_all(cookie_data).await?,
            NtsRecord::Server { name } => writer.write_all(name.as_bytes()).await?,
            NtsRecord::Port { port } => writer.write_u16(*port).await?,
            NtsRecord::Unknown { data, .. } => writer.write_all(data).await?,
            NtsRecord::SupportedNextProtocolList {
                supported_protocols,
            } => {
                for &id in supported_protocols.iter() {
                    writer.write_u16(id.into()).await?;
                }
            }
            NtsRecord::SupportedAlgorithmList {
                supported_algorithms,
            } => {
                for desc in supported_algorithms.iter() {
                    writer.write_u16(desc.id.into()).await?;
                    writer.write_u16(desc.keysize).await?;
                }
            }
            NtsRecord::FixedKeyRequest { c2s, s2c } => {
                writer.write_all(c2s).await?;
                writer.write_all(s2c).await?;
            }
            NtsRecord::NtpServerDeny { denied } => writer.write_all(denied.as_bytes()).await?,
            NtsRecord::Authentication { key } => writer.write_all(key.as_bytes()).await?,
        }
        Ok(())
    }

    fn record_type(&self) -> u16 {
        const CRITICAL_BIT: u16 = 0x8000;
        match self {
            #[expect(clippy::identity_op)]
            NtsRecord::EndOfMessage => 0 | CRITICAL_BIT,
            NtsRecord::NextProtocol { .. } => 1 | CRITICAL_BIT,
            NtsRecord::Error { .. } => 2 | CRITICAL_BIT,
            NtsRecord::Warning { .. } => 3 | CRITICAL_BIT,
            NtsRecord::AeadAlgorithm { .. } => 4 | CRITICAL_BIT,
            NtsRecord::NewCookie { .. } => 5,
            NtsRecord::Server { .. } => 6 | CRITICAL_BIT,
            NtsRecord::Port { .. } => 7 | CRITICAL_BIT,
            NtsRecord::Unknown {
                record_type,
                critical,
                ..
            } => record_type | if *critical { CRITICAL_BIT } else { 0 },
            NtsRecord::KeepAlive => 0x4000,
            NtsRecord::SupportedNextProtocolList { .. } => 0x4004 | CRITICAL_BIT,
            NtsRecord::SupportedAlgorithmList { .. } => 0x4001 | CRITICAL_BIT,
            NtsRecord::FixedKeyRequest { .. } => 0x4002 | CRITICAL_BIT,
            NtsRecord::NtpServerDeny { .. } => 0x4003,
            NtsRecord::Authentication { .. } => 0x4005,
        }
    }

    fn body_size(&self) -> usize {
        match self {
            NtsRecord::EndOfMessage | NtsRecord::KeepAlive => 0,
            NtsRecord::Error { .. } | NtsRecord::Warning { .. } | NtsRecord::Port { .. } => {
                size_of::<u16>()
            }
            NtsRecord::NextProtocol { protocol_ids } => protocol_ids.len() * size_of::<u16>(),
            NtsRecord::AeadAlgorithm { algorithm_ids } => algorithm_ids.len() * size_of::<u16>(),
            NtsRecord::NewCookie { cookie_data } => cookie_data.len(),
            NtsRecord::Server { name } => name.len(),
            NtsRecord::Unknown { data, .. } => data.len(),
            NtsRecord::SupportedNextProtocolList {
                supported_protocols,
            } => supported_protocols.len() * size_of::<u16>(),
            NtsRecord::SupportedAlgorithmList {
                supported_algorithms,
            } => supported_algorithms.len() * 2 * size_of::<u16>(),
            NtsRecord::FixedKeyRequest { c2s, s2c } => c2s.len() + s2c.len(),
            NtsRecord::NtpServerDeny { denied } => denied.len(),
            NtsRecord::Authentication { key } => key.len(),
        }
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

    fn parse(buf: &[u8]) -> Result<NtsRecord<'_>, Error> {
        let Poll::Ready(result) =
            pin!(NtsRecord::parse(buf)).poll(&mut Context::from_waker(Waker::noop()))
        else {
            panic!("Unexpected sleep in future");
        };

        result
    }

    fn serialize(record: NtsRecord, buf: &mut Vec<u8>) {
        assert!(matches!(
            pin!(record.serialize(buf)).poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        ));
    }

    #[test]
    fn test_end_of_message() {
        assert!(matches!(parse(&[0, 0, 0, 0]), Ok(NtsRecord::EndOfMessage)));
        assert!(matches!(
            parse(&[0x80, 0, 0, 0]),
            Ok(NtsRecord::EndOfMessage)
        ));
        assert!(matches!(
            parse([0x80, 0, 0, 0, 0, 0].as_ref()),
            Ok(NtsRecord::EndOfMessage)
        ));
        assert!(matches!(
            parse([0, 0, 0, 3, 1, 2, 3].as_ref()),
            Ok(NtsRecord::EndOfMessage)
        ));
        assert!(matches!(
            parse([0x80, 0, 0, 3, 1, 2, 3].as_ref()),
            Ok(NtsRecord::EndOfMessage)
        ));
        assert!(parse([0x80, 0, 0, 3].as_ref()).is_err());

        let mut buf = vec![];
        serialize(NtsRecord::EndOfMessage, &mut buf);
        assert_eq!(buf, [0x80, 0, 0, 0]);
    }

    #[test]
    fn test_next_protocol() {
        let Ok(NtsRecord::NextProtocol { protocol_ids }) = parse(&[0, 1, 0, 2, 0, 0]) else {
            panic!("Expected successfull parse");
        };
        assert_eq!(protocol_ids, [NextProtocol::NTPv4].as_slice());

        let Ok(NtsRecord::NextProtocol { protocol_ids }) = parse(&[0, 1, 0, 2, 0, 0, 0, 0]) else {
            panic!("Expected successfull parse");
        };
        assert_eq!(protocol_ids, [NextProtocol::NTPv4].as_slice());

        let Ok(NtsRecord::NextProtocol { protocol_ids }) = parse(&[0x80, 1, 0, 2, 0, 0]) else {
            panic!("Expected successfull parse");
        };
        assert_eq!(protocol_ids, [NextProtocol::NTPv4].as_slice());

        let Ok(NtsRecord::NextProtocol { protocol_ids }) = parse(&[0x80, 1, 0, 0]) else {
            panic!("Expected successfull parse");
        };
        assert_eq!(protocol_ids, [].as_slice());

        let Ok(NtsRecord::NextProtocol { protocol_ids }) = parse(&[0x80, 1, 0, 4, 0, 0, 0, 4])
        else {
            panic!("Expected successfull parse");
        };
        assert_eq!(
            protocol_ids,
            [NextProtocol::NTPv4, NextProtocol::Unknown(4)].as_slice()
        );

        assert!(parse([0x80, 1, 0, 1, 0].as_ref()).is_err());
        assert!(parse([0x80, 1, 0, 2, 0].as_ref()).is_err());

        let mut buf = vec![];
        serialize(
            NtsRecord::NextProtocol {
                protocol_ids: vec![NextProtocol::NTPv4, NextProtocol::Unknown(1)].into(),
            },
            &mut buf,
        );
        assert_eq!(buf, [0x80, 1, 0, 4, 0, 0, 0, 1]);
    }

    #[test]
    fn test_error() {
        assert!(matches!(
            parse(&[0x80, 2, 0, 2, 0, 0]),
            Ok(NtsRecord::Error {
                errorcode: ErrorCode::UnrecognizedCriticalRecord
            })
        ));
        assert!(matches!(
            parse(&[0, 2, 0, 2, 0, 0]),
            Ok(NtsRecord::Error {
                errorcode: ErrorCode::UnrecognizedCriticalRecord
            })
        ));
        assert!(matches!(
            parse(&[0x80, 2, 0, 2, 0, 1]),
            Ok(NtsRecord::Error {
                errorcode: ErrorCode::BadRequest
            })
        ));
        assert!(matches!(
            parse(&[0x80, 2, 0, 2, 0, 2]),
            Ok(NtsRecord::Error {
                errorcode: ErrorCode::InternalServerError
            })
        ));
        assert!(matches!(
            parse(&[0x80, 2, 0, 2, 0, 3]),
            Ok(NtsRecord::Error {
                errorcode: ErrorCode::Unknown(3)
            })
        ));
        assert!(parse(&[0x80, 2, 0, 4, 0, 3, 0, 0]).is_err());
        assert!(parse(&[0x80, 2, 0, 1, 0]).is_err());
        assert!(parse(&[0x80, 2, 0, 2, 0]).is_err());

        let mut buf = vec![];
        serialize(
            NtsRecord::Error {
                errorcode: ErrorCode::UnrecognizedCriticalRecord,
            },
            &mut buf,
        );
        assert_eq!(buf, [0x80, 2, 0, 2, 0, 0]);

        let mut buf = vec![];
        serialize(
            NtsRecord::Error {
                errorcode: ErrorCode::BadRequest,
            },
            &mut buf,
        );
        assert_eq!(buf, [0x80, 2, 0, 2, 0, 1]);

        let mut buf = vec![];
        serialize(
            NtsRecord::Error {
                errorcode: ErrorCode::InternalServerError,
            },
            &mut buf,
        );
        assert_eq!(buf, [0x80, 2, 0, 2, 0, 2]);

        let mut buf = vec![];
        serialize(
            NtsRecord::Error {
                errorcode: ErrorCode::Unknown(3),
            },
            &mut buf,
        );
        assert_eq!(buf, [0x80, 2, 0, 2, 0, 3]);
    }

    #[test]
    fn test_warning() {
        assert!(matches!(
            parse(&[0x80, 3, 0, 2, 0, 0]),
            Ok(NtsRecord::Warning {
                warningcode: WarningCode::Unknown(0)
            })
        ));
        assert!(matches!(
            parse(&[0, 3, 0, 2, 0, 0]),
            Ok(NtsRecord::Warning {
                warningcode: WarningCode::Unknown(0)
            })
        ));
        assert!(matches!(
            parse(&[0x80, 3, 0, 2, 0, 0, 0, 0]),
            Ok(NtsRecord::Warning {
                warningcode: WarningCode::Unknown(0)
            })
        ));
        assert!(parse(&[0x80, 3, 0, 2, 0]).is_err());
        assert!(parse(&[0x80, 3, 0, 1, 0]).is_err());
        assert!(parse(&[0x80, 3, 0, 3, 0, 0, 0]).is_err());

        let mut buf = vec![];
        serialize(
            NtsRecord::Warning {
                warningcode: WarningCode::Unknown(3),
            },
            &mut buf,
        );
        assert_eq!(buf, [0x80, 3, 0, 2, 0, 3]);
    }

    #[test]
    fn test_aead() {
        let Ok(NtsRecord::AeadAlgorithm { algorithm_ids }) = parse(&[0x80, 4, 0, 2, 0, 0]) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(algorithm_ids, [AeadAlgorithm::Unknown(0)].as_slice());

        let Ok(NtsRecord::AeadAlgorithm { algorithm_ids }) = parse(&[0, 4, 0, 4, 0, 15, 0, 17])
        else {
            panic!("Expected succesful parse");
        };
        assert_eq!(
            algorithm_ids,
            [
                AeadAlgorithm::AeadAesSivCmac256,
                AeadAlgorithm::AeadAesSivCmac512
            ]
            .as_slice()
        );

        let Ok(NtsRecord::AeadAlgorithm { algorithm_ids }) = parse(&[0, 4, 0, 2, 0, 0, 1, 2])
        else {
            panic!("Expected succesful parse");
        };
        assert_eq!(algorithm_ids, [AeadAlgorithm::Unknown(0)].as_slice());

        assert!(parse(&[0, 4, 0, 2, 0]).is_err());
        assert!(parse(&[0, 4, 0, 3, 0, 2, 0]).is_err());

        let mut buf = vec![];
        serialize(
            NtsRecord::AeadAlgorithm {
                algorithm_ids: vec![
                    AeadAlgorithm::AeadAesSivCmac256,
                    AeadAlgorithm::AeadAesSivCmac512,
                ]
                .into(),
            },
            &mut buf,
        );
        assert_eq!(buf, [0x80, 4, 0, 4, 0, 15, 0, 17]);
    }

    #[test]
    fn test_new_cookie() {
        let Ok(NtsRecord::NewCookie { cookie_data }) = parse(&[0x80, 5, 0, 2, 16, 17]) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(cookie_data, [16, 17].as_slice());

        let Ok(NtsRecord::NewCookie { cookie_data }) = parse(&[0, 5, 0, 0]) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(cookie_data, [].as_slice() as &[u8]);

        let Ok(NtsRecord::NewCookie { cookie_data }) = parse(&[0, 5, 0, 0, 16, 17]) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(cookie_data, [].as_slice() as &[u8]);

        assert!(parse(&[0x80, 5, 0, 3, 1, 2]).is_err());

        let mut buf = vec![];
        serialize(
            NtsRecord::NewCookie {
                cookie_data: [1, 2, 3].as_slice().into(),
            },
            &mut buf,
        );
        assert_eq!(buf, [0, 5, 0, 3, 1, 2, 3]);
    }

    #[test]
    fn test_server() {
        let Ok(NtsRecord::Server { name }) = parse(&[0x80, 6, 0, 5, b'h', b'e', b'l', b'l', b'o'])
        else {
            panic!("Expected succesful parse");
        };
        assert_eq!(name, "hello");
        let Ok(NtsRecord::Server { name }) =
            parse(&[0x80, 6, 0, 5, b'h', b'e', b'l', b'l', b'o', b' ', b'w'])
        else {
            panic!("Expected succesful parse");
        };
        assert_eq!(name, "hello");

        assert!(parse(&[0x80, 6, 0, 5, b'h', b'e', b'l']).is_err());

        let mut buf = vec![];
        serialize(NtsRecord::Server { name: "hi".into() }, &mut buf);
        assert_eq!(buf, &[0x80, 6, 0, 2, b'h', b'i']);
    }

    #[test]
    fn test_port() {
        assert!(matches!(
            parse(&[0x80, 7, 0, 2, 0, 123]),
            Ok(NtsRecord::Port { port: 123 })
        ));
        assert!(matches!(
            parse(&[0, 7, 0, 2, 0, 123, 5, 6, 7]),
            Ok(NtsRecord::Port { port: 123 })
        ));
        assert!(parse(&[0, 7, 0, 3, 0, 123, 5]).is_err());
        assert!(parse(&[0, 7, 0, 1, 0, 123]).is_err());
        assert!(parse(&[0, 7, 0, 2, 0]).is_err());

        let mut buf = vec![];
        serialize(NtsRecord::Port { port: 123 }, &mut buf);
        assert_eq!(buf, [0x80, 7, 0, 2, 0, 123]);
    }

    #[test]
    fn test_keep_alive() {
        assert!(matches!(parse(&[0x40, 0, 0, 0]), Ok(NtsRecord::KeepAlive)));
        assert!(matches!(
            parse(&[0xC0, 0, 0, 2, 0, 3]),
            Ok(NtsRecord::KeepAlive)
        ));
        assert!(matches!(
            parse(&[0x40, 0, 0, 0, 0, 3]),
            Ok(NtsRecord::KeepAlive)
        ));
        assert!(parse(&[0x40, 0, 0, 2]).is_err());

        let mut buf = vec![];
        serialize(NtsRecord::KeepAlive, &mut buf);
        assert_eq!(buf, [0x40, 0, 0, 0]);
    }

    #[test]
    fn test_supported_next_protocol_list() {
        let Ok(NtsRecord::SupportedNextProtocolList {
            supported_protocols,
        }) = parse(&[0xC0, 4, 0, 0])
        else {
            panic!("Expected succesful parse");
        };
        assert_eq!(supported_protocols, [].as_slice());

        let Ok(NtsRecord::SupportedNextProtocolList {
            supported_protocols,
        }) = parse(&[0xC0, 4, 0, 4, 0, 0, 0, 1])
        else {
            panic!("Expected succesful parse");
        };
        assert_eq!(
            supported_protocols,
            [NextProtocol::NTPv4, NextProtocol::Unknown(1)].as_slice()
        );

        let Ok(NtsRecord::SupportedNextProtocolList {
            supported_protocols,
        }) = parse(&[0x40, 4, 0, 4, 0, 0, 0, 1, 2, 3, 4, 5])
        else {
            panic!("Expected succesful parse");
        };
        assert_eq!(
            supported_protocols,
            [NextProtocol::NTPv4, NextProtocol::Unknown(1)].as_slice()
        );

        assert!(parse(&[0xC0, 4, 0, 4, 0, 0]).is_err());
        assert!(parse(&[0xC0, 4, 0, 3, 0, 0, 1]).is_err());

        let mut buf = vec![];
        serialize(
            NtsRecord::SupportedNextProtocolList {
                supported_protocols: [NextProtocol::Unknown(1), NextProtocol::Unknown(2)]
                    .as_slice()
                    .into(),
            },
            &mut buf,
        );
        assert_eq!(buf, [0xC0, 4, 0, 4, 0, 1, 0, 2]);

        let mut buf = vec![];
        serialize(
            NtsRecord::SupportedNextProtocolList {
                supported_protocols: [].as_slice().into(),
            },
            &mut buf,
        );
        assert_eq!(buf, [0xC0, 4, 0, 0]);
    }

    #[test]
    fn test_supported_algorithm_list() {
        let Ok(NtsRecord::SupportedAlgorithmList {
            supported_algorithms,
        }) = parse(&[0xC0, 1, 0, 0])
        else {
            panic!("Expected succesful parse");
        };
        assert_eq!(supported_algorithms, [].as_slice());

        let Ok(NtsRecord::SupportedAlgorithmList {
            supported_algorithms,
        }) = parse(&[0xC0, 1, 0, 8, 0, 15, 0, 32, 0, 17, 0, 64])
        else {
            panic!("Expected succesful parse");
        };
        assert_eq!(
            supported_algorithms,
            [
                AlgorithmDescription {
                    id: AeadAlgorithm::AeadAesSivCmac256,
                    keysize: 32
                },
                AlgorithmDescription {
                    id: AeadAlgorithm::AeadAesSivCmac512,
                    keysize: 64
                }
            ]
            .as_slice()
        );

        let Ok(NtsRecord::SupportedAlgorithmList {
            supported_algorithms,
        }) = parse(&[0xC0, 1, 0, 8, 0, 15, 0, 32, 0, 17, 0, 64])
        else {
            panic!("Expected succesful parse");
        };
        assert_eq!(
            supported_algorithms,
            [
                AlgorithmDescription {
                    id: AeadAlgorithm::AeadAesSivCmac256,
                    keysize: 32
                },
                AlgorithmDescription {
                    id: AeadAlgorithm::AeadAesSivCmac512,
                    keysize: 64
                }
            ]
            .as_slice()
        );

        let mut buf = vec![];
        serialize(
            NtsRecord::SupportedAlgorithmList {
                supported_algorithms: [].as_slice().into(),
            },
            &mut buf,
        );
        assert_eq!(buf, [0xc0, 1, 0, 0]);

        let mut buf = vec![];
        serialize(
            NtsRecord::SupportedAlgorithmList {
                supported_algorithms: [AlgorithmDescription {
                    id: AeadAlgorithm::AeadAesSivCmac512,
                    keysize: 64,
                }]
                .as_slice()
                .into(),
            },
            &mut buf,
        );
        assert_eq!(buf, [0xc0, 1, 0, 4, 0, 17, 0, 64]);
    }

    #[test]
    fn test_fixed_key_request() {
        let Ok(NtsRecord::FixedKeyRequest { c2s, s2c }) = parse(&[0xC0, 2, 0, 0]) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(c2s, [].as_slice() as &[u8]);
        assert_eq!(s2c, [].as_slice() as &[u8]);

        let Ok(NtsRecord::FixedKeyRequest { c2s, s2c }) = parse(&[0x40, 2, 0, 4, 1, 2, 3, 4])
        else {
            panic!("Expected succesful parse");
        };
        assert_eq!(c2s, [1, 2].as_slice());
        assert_eq!(s2c, [3, 4].as_slice());

        assert!(parse(&[0xC0, 2, 0, 3, 1, 2, 3]).is_err());
        assert!(parse(&[0xC0, 2, 0, 4, 1, 2, 3]).is_err());

        let mut buf = vec![];
        serialize(
            NtsRecord::FixedKeyRequest {
                c2s: [5, 6].as_slice().into(),
                s2c: [7, 8].as_slice().into(),
            },
            &mut buf,
        );
        assert_eq!(buf, [0xc0, 2, 0, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_server_deny() {
        let Ok(NtsRecord::NtpServerDeny { denied }) =
            parse(&[0x40, 3, 0, 5, b'h', b'e', b'l', b'l', b'o'])
        else {
            panic!("Expected succesful parse");
        };
        assert_eq!(denied, "hello");
        let Ok(NtsRecord::NtpServerDeny { denied }) =
            parse(&[0xC0, 3, 0, 5, b'h', b'e', b'l', b'l', b'o', b' ', b'w'])
        else {
            panic!("Expected succesful parse");
        };
        assert_eq!(denied, "hello");

        assert!(parse(&[0x40, 3, 0, 5, b'h', b'e', b'l']).is_err());

        let mut buf = vec![];
        serialize(
            NtsRecord::NtpServerDeny {
                denied: "hi".into(),
            },
            &mut buf,
        );
        assert_eq!(buf, &[0x40, 3, 0, 2, b'h', b'i']);
    }

    #[test]
    fn test_unknown() {
        let Ok(NtsRecord::Unknown {
            record_type,
            critical,
            data,
        }) = parse(&[0, 20, 0, 3, 1, 2, 3])
        else {
            panic!("Expected succesful parse");
        };
        assert_eq!(record_type, 20);
        assert!(!critical);
        assert_eq!(data, [1, 2, 3].as_slice());

        let Ok(NtsRecord::Unknown {
            record_type,
            critical,
            data,
        }) = parse(&[0x80, 21, 0, 2, 5, 6, 7, 8])
        else {
            panic!("Expected succesful parse");
        };
        assert_eq!(record_type, 21);
        assert!(critical);
        assert_eq!(data, [5, 6].as_slice());

        assert!(parse(&[0x80, 23, 0, 5, 1, 2]).is_err());

        let mut buf = vec![];
        serialize(
            NtsRecord::Unknown {
                record_type: 50,
                critical: false,
                data: [9, 10].as_slice().into(),
            },
            &mut buf,
        );
        assert_eq!(buf, [0, 50, 0, 2, 9, 10]);

        let mut buf = vec![];
        serialize(
            NtsRecord::Unknown {
                record_type: 51,
                critical: true,
                data: [].as_slice().into(),
            },
            &mut buf,
        );
        assert_eq!(buf, [0x80, 51, 0, 0]);
    }
}
