use std::{
    fmt::Display,
    io::{Read, Write},
    ops::ControlFlow,
    sync::Arc,
};

use rustls::pki_types::ServerName;

use crate::{
    cookiestash::CookieStash,
    io::{NonBlockingRead, NonBlockingWrite},
    keyset::{DecodedServerCookie, KeySet},
    packet::{AesSivCmac256, AesSivCmac512, Cipher},
    source::{ProtocolVersion, SourceNtsData},
};

#[derive(Debug)]
pub enum WriteError {
    Invalid,
    TooLong,
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid => f.write_str("Invalid NTS-KE record"),
            Self::TooLong => f.write_str("NTS-KE record too long"),
        }
    }
}

impl std::error::Error for WriteError {}

impl NtsRecord {
    fn record_type(&self) -> u16 {
        match self {
            NtsRecord::EndOfMessage => 0,
            NtsRecord::NextProtocol { .. } => 1,
            NtsRecord::Error { .. } => 2,
            NtsRecord::Warning { .. } => 3,
            NtsRecord::AeadAlgorithm { .. } => 4,
            NtsRecord::NewCookie { .. } => 5,
            NtsRecord::Server { .. } => 6,
            NtsRecord::Port { .. } => 7,
            #[cfg(feature = "nts-pool")]
            NtsRecord::KeepAlive { .. } => 0x4000,
            #[cfg(feature = "nts-pool")]
            NtsRecord::SupportedAlgorithmList { .. } => 0x4001,
            #[cfg(feature = "nts-pool")]
            NtsRecord::FixedKeyRequest { .. } => 0x4002,
            #[cfg(feature = "nts-pool")]
            NtsRecord::NtpServerDeny { .. } => 0x4003,
            #[cfg(feature = "ntpv5")]
            NtsRecord::DraftId { .. } => 0x4008,
            NtsRecord::Unknown { record_type, .. } => record_type & !0x8000,
        }
    }

    fn is_critical(&self) -> bool {
        match self {
            NtsRecord::EndOfMessage => true,
            NtsRecord::NextProtocol { .. } => true,
            NtsRecord::Error { .. } => true,
            NtsRecord::Warning { .. } => true,
            NtsRecord::AeadAlgorithm { critical, .. } => *critical,
            NtsRecord::NewCookie { .. } => false,
            NtsRecord::Server { critical, .. } => *critical,
            NtsRecord::Port { critical, .. } => *critical,
            #[cfg(feature = "nts-pool")]
            NtsRecord::KeepAlive { .. } => false,
            #[cfg(feature = "nts-pool")]
            NtsRecord::SupportedAlgorithmList { .. } => true,
            #[cfg(feature = "nts-pool")]
            NtsRecord::FixedKeyRequest { .. } => true,
            #[cfg(feature = "nts-pool")]
            NtsRecord::NtpServerDeny { .. } => false,
            #[cfg(feature = "ntpv5")]
            NtsRecord::DraftId { .. } => false,
            NtsRecord::Unknown { critical, .. } => *critical,
        }
    }

    fn validate(&self) -> Result<(), WriteError> {
        match self {
            NtsRecord::Unknown {
                record_type, data, ..
            } => {
                if *record_type & 0x8000 != 0 {
                    return Err(WriteError::Invalid);
                }
                if data.len() > u16::MAX as usize {
                    return Err(WriteError::TooLong);
                }
            }
            NtsRecord::NextProtocol { protocol_ids } => {
                if protocol_ids.len() >= (u16::MAX as usize) / 2 {
                    return Err(WriteError::TooLong);
                }
            }

            NtsRecord::AeadAlgorithm { algorithm_ids, .. } => {
                if algorithm_ids.len() >= (u16::MAX as usize) / 2 {
                    return Err(WriteError::TooLong);
                }
            }
            NtsRecord::NewCookie { cookie_data } => {
                if cookie_data.len() > u16::MAX as usize {
                    return Err(WriteError::TooLong);
                }
            }
            NtsRecord::Server { name, .. } => {
                if name.as_bytes().len() >= (u16::MAX as usize) {
                    return Err(WriteError::TooLong);
                }
            }

            _ => {}
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtsRecord {
    EndOfMessage,
    NextProtocol {
        protocol_ids: Vec<u16>,
    },
    Error {
        errorcode: u16,
    },
    Warning {
        warningcode: u16,
    },
    AeadAlgorithm {
        critical: bool,
        algorithm_ids: Vec<u16>,
    },
    NewCookie {
        cookie_data: Vec<u8>,
    },
    Server {
        critical: bool,
        name: String,
    },
    Port {
        critical: bool,
        port: u16,
    },
    Unknown {
        record_type: u16,
        critical: bool,
        data: Vec<u8>,
    },
    #[cfg(feature = "ntpv5")]
    DraftId {
        data: Vec<u8>,
    },
    #[cfg(feature = "nts-pool")]
    KeepAlive,
    #[cfg(feature = "nts-pool")]
    SupportedAlgorithmList {
        supported_algorithms: Vec<(u16, u16)>,
    },
    #[cfg(feature = "nts-pool")]
    FixedKeyRequest {
        c2s: Vec<u8>,
        s2c: Vec<u8>,
    },
    #[cfg(feature = "nts-pool")]
    NtpServerDeny {
        denied: String,
    },
}

fn read_u16_be(reader: &mut impl NonBlockingRead) -> std::io::Result<u16> {
    let mut bytes = [0, 0];
    reader.read_exact(&mut bytes)?;

    Ok(u16::from_be_bytes(bytes))
}

fn read_u16s_be(reader: &mut impl NonBlockingRead, length: usize) -> std::io::Result<Vec<u16>> {
    (0..length).map(|_| read_u16_be(reader)).collect()
}

#[cfg(feature = "nts-pool")]
fn read_u16_tuples_be(
    reader: &mut impl NonBlockingRead,
    length: usize,
) -> std::io::Result<Vec<(u16, u16)>> {
    (0..length)
        .map(|_| Ok((read_u16_be(reader)?, read_u16_be(reader)?)))
        .collect()
}

fn read_bytes_exact(reader: &mut impl NonBlockingRead, length: usize) -> std::io::Result<Vec<u8>> {
    let mut output = vec![0; length];
    reader.read_exact(&mut output)?;

    Ok(output)
}

impl NtsRecord {
    pub const UNRECOGNIZED_CRITICAL_RECORD: u16 = 0;
    pub const BAD_REQUEST: u16 = 1;
    pub const INTERNAL_SERVER_ERROR: u16 = 2;

    #[cfg_attr(not(feature = "nts-pool"), allow(unused_variables))]
    pub fn client_key_exchange_records(
        denied_servers: impl IntoIterator<Item = String>,
    ) -> Box<[NtsRecord]> {
        let mut base = vec![
            #[cfg(feature = "ntpv5")]
            NtsRecord::DraftId {
                data: crate::packet::v5::DRAFT_VERSION.as_bytes().into(),
            },
            NtsRecord::NextProtocol {
                protocol_ids: vec![
                    #[cfg(feature = "ntpv5")]
                    0x8001,
                    0,
                ],
            },
            NtsRecord::AeadAlgorithm {
                critical: false,
                algorithm_ids: AeadAlgorithm::IN_ORDER_OF_PREFERENCE
                    .iter()
                    .map(|algorithm| *algorithm as u16)
                    .collect(),
            },
        ];

        #[cfg(feature = "nts-pool")]
        base.extend(
            denied_servers
                .into_iter()
                .map(|server| NtsRecord::NtpServerDeny { denied: server }),
        );

        base.push(NtsRecord::EndOfMessage);

        base.into_boxed_slice()
    }

    #[cfg(feature = "nts-pool")]
    pub fn client_key_exchange_records_fixed(
        c2s: Vec<u8>,
        s2c: Vec<u8>,
    ) -> [NtsRecord; if cfg!(feature = "ntpv5") { 5 } else { 4 }] {
        [
            #[cfg(feature = "ntpv5")]
            NtsRecord::DraftId {
                data: crate::packet::v5::DRAFT_VERSION.as_bytes().into(),
            },
            NtsRecord::NextProtocol {
                protocol_ids: vec![
                    #[cfg(feature = "ntpv5")]
                    0x8001,
                    0,
                ],
            },
            NtsRecord::AeadAlgorithm {
                critical: false,
                algorithm_ids: AeadAlgorithm::IN_ORDER_OF_PREFERENCE
                    .iter()
                    .map(|algorithm| *algorithm as u16)
                    .collect(),
            },
            #[cfg(feature = "nts-pool")]
            NtsRecord::FixedKeyRequest { c2s, s2c },
            NtsRecord::EndOfMessage,
        ]
    }

    fn server_key_exchange_records(
        protocol: ProtocolId,
        algorithm: AeadAlgorithm,
        keyset: &KeySet,
        keys: NtsKeys,
        ntp_port: Option<u16>,
        ntp_server: Option<String>,
        #[cfg(feature = "nts-pool")] send_supported_algorithms: bool,
    ) -> Box<[NtsRecord]> {
        let cookie = DecodedServerCookie {
            algorithm,
            s2c: keys.s2c,
            c2s: keys.c2s,
        };

        let next_cookie = || -> NtsRecord {
            NtsRecord::NewCookie {
                cookie_data: keyset.encode_cookie(&cookie),
            }
        };

        let mut response = Vec::new();
        //Probably, a NTS request should not send this record while attempting
        //to negotiate a "standard key exchange" at the same time. The current spec
        //does not outright say this, however, so we will add it whenever requested.
        #[cfg(feature = "nts-pool")]
        if send_supported_algorithms {
            response.push(NtsRecord::SupportedAlgorithmList {
                supported_algorithms: crate::nts_record::AeadAlgorithm::IN_ORDER_OF_PREFERENCE
                    .iter()
                    .map(|&algo| (algo as u16, algo.key_size()))
                    .collect(),
            })
        }

        if let Some(ntp_port) = ntp_port {
            response.push(NtsRecord::Port {
                critical: ntp_port != 123,
                port: ntp_port,
            });
        }

        if let Some(ntp_server) = ntp_server {
            response.push(NtsRecord::Server {
                critical: true,
                name: ntp_server,
            });
        }

        response.extend(vec![
            NtsRecord::NextProtocol {
                protocol_ids: vec![protocol as u16],
            },
            NtsRecord::AeadAlgorithm {
                critical: false,
                algorithm_ids: vec![algorithm as u16],
            },
            next_cookie(),
            next_cookie(),
            next_cookie(),
            next_cookie(),
            next_cookie(),
            next_cookie(),
            next_cookie(),
            next_cookie(),
            NtsRecord::EndOfMessage,
        ]);

        response.into_boxed_slice()
    }

    pub fn read(reader: &mut impl NonBlockingRead) -> std::io::Result<NtsRecord> {
        let raw_record_type = read_u16_be(reader)?;
        let critical = raw_record_type & 0x8000 != 0;
        let record_type = raw_record_type & !0x8000;
        let record_len = read_u16_be(reader)? as usize;

        Ok(match record_type {
            0 if record_len == 0 && critical => NtsRecord::EndOfMessage,
            1 if record_len % 2 == 0 && critical => {
                let n_protocols = record_len / 2;
                let protocol_ids = read_u16s_be(reader, n_protocols)?;
                NtsRecord::NextProtocol { protocol_ids }
            }
            2 if record_len == 2 && critical => NtsRecord::Error {
                errorcode: read_u16_be(reader)?,
            },
            3 if record_len == 2 && critical => NtsRecord::Warning {
                warningcode: read_u16_be(reader)?,
            },
            4 if record_len % 2 == 0 => {
                let n_algorithms = record_len / 2;
                let algorithm_ids = read_u16s_be(reader, n_algorithms)?;
                NtsRecord::AeadAlgorithm {
                    critical,
                    algorithm_ids,
                }
            }
            5 if !critical => {
                let cookie_data = read_bytes_exact(reader, record_len)?;
                NtsRecord::NewCookie { cookie_data }
            }
            6 => {
                // NOTE: the string data should be ascii (not utf8) but we don't enforce that here
                let str_data = read_bytes_exact(reader, record_len)?;
                match String::from_utf8(str_data) {
                    Ok(name) => NtsRecord::Server { critical, name },
                    Err(e) => NtsRecord::Unknown {
                        record_type,
                        critical,
                        data: e.into_bytes(),
                    },
                }
            }
            7 if record_len == 2 => NtsRecord::Port {
                critical,
                port: read_u16_be(reader)?,
            },
            #[cfg(feature = "nts-pool")]
            0x4000 if !critical => NtsRecord::KeepAlive,
            #[cfg(feature = "nts-pool")]
            0x4001 if record_len % 4 == 0 && critical => {
                let n_algorithms = record_len / 4; // 4 bytes per element
                let supported_algorithms = read_u16_tuples_be(reader, n_algorithms)?;

                NtsRecord::SupportedAlgorithmList {
                    supported_algorithms,
                }
            }
            #[cfg(feature = "nts-pool")]
            0x4002 if record_len % 2 == 0 && critical => {
                let mut c2s = vec![0; record_len / 2];
                let mut s2c = vec![0; record_len / 2];

                reader.read_exact(&mut c2s)?;
                reader.read_exact(&mut s2c)?;

                NtsRecord::FixedKeyRequest { c2s, s2c }
            }
            #[cfg(feature = "nts-pool")]
            0x4003 => {
                // NOTE: the string data should be ascii (not utf8) but we don't enforce that here
                let str_data = read_bytes_exact(reader, record_len)?;
                match String::from_utf8(str_data) {
                    Ok(denied) => NtsRecord::NtpServerDeny { denied },
                    Err(e) => NtsRecord::Unknown {
                        record_type,
                        critical,
                        data: e.into_bytes(),
                    },
                }
            }
            #[cfg(feature = "ntpv5")]
            0x4008 => NtsRecord::DraftId {
                data: read_bytes_exact(reader, record_len)?,
            },
            _ => NtsRecord::Unknown {
                record_type,
                critical,
                data: read_bytes_exact(reader, record_len)?,
            },
        })
    }

    pub fn write(&self, mut writer: impl NonBlockingWrite) -> std::io::Result<()> {
        // error out early when the record is invalid
        if let Err(e) = self.validate() {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
        }

        // all messages start with the record type
        let record_type = self.record_type() | ((self.is_critical() as u16) << 15);
        writer.write_all(&record_type.to_be_bytes())?;

        let size_of_u16 = std::mem::size_of::<u16>() as u16;
        match self {
            NtsRecord::EndOfMessage => {
                writer.write_all(&0_u16.to_be_bytes())?;
            }
            NtsRecord::Unknown { data, .. } => {
                writer.write_all(&(data.len() as u16).to_be_bytes())?;
                writer.write_all(data)?;
            }
            NtsRecord::NextProtocol { protocol_ids } => {
                let length = size_of_u16 * protocol_ids.len() as u16;
                writer.write_all(&length.to_be_bytes())?;

                for id in protocol_ids {
                    writer.write_all(&id.to_be_bytes())?;
                }
            }
            NtsRecord::Error { errorcode } => {
                writer.write_all(&size_of_u16.to_be_bytes())?;
                writer.write_all(&errorcode.to_be_bytes())?;
            }
            NtsRecord::Warning { warningcode } => {
                writer.write_all(&size_of_u16.to_be_bytes())?;
                writer.write_all(&warningcode.to_be_bytes())?;
            }
            NtsRecord::AeadAlgorithm { algorithm_ids, .. } => {
                let length = size_of_u16 * algorithm_ids.len() as u16;
                writer.write_all(&length.to_be_bytes())?;

                for id in algorithm_ids {
                    writer.write_all(&id.to_be_bytes())?;
                }
            }
            NtsRecord::NewCookie { cookie_data } => {
                let length = cookie_data.len() as u16;
                writer.write_all(&length.to_be_bytes())?;

                writer.write_all(cookie_data)?;
            }
            NtsRecord::Server { name, .. } => {
                // NOTE: the server name should be ascii
                #[cfg(not(feature = "__internal-fuzz"))]
                debug_assert!(name.is_ascii());
                let length = name.len() as u16;
                writer.write_all(&length.to_be_bytes())?;

                writer.write_all(name.as_bytes())?;
            }
            NtsRecord::Port { port, .. } => {
                writer.write_all(&size_of_u16.to_be_bytes())?;
                writer.write_all(&port.to_be_bytes())?;
            }
            #[cfg(feature = "nts-pool")]
            NtsRecord::KeepAlive => {
                // nothing to encode; there is no payload
                let length = 0u16;
                writer.write_all(&length.to_be_bytes())?;
            }
            #[cfg(feature = "nts-pool")]
            NtsRecord::SupportedAlgorithmList {
                supported_algorithms,
            } => {
                let length = size_of_u16 * 2 * supported_algorithms.len() as u16;
                writer.write_all(&length.to_be_bytes())?;

                for (algorithm_id, key_length) in supported_algorithms {
                    writer.write_all(&algorithm_id.to_be_bytes())?;
                    writer.write_all(&key_length.to_be_bytes())?;
                }
            }
            #[cfg(feature = "nts-pool")]
            NtsRecord::FixedKeyRequest { c2s, s2c } => {
                debug_assert_eq!(c2s.len(), s2c.len());

                let length = (c2s.len() + s2c.len()) as u16;
                writer.write_all(&length.to_be_bytes())?;

                writer.write_all(c2s)?;
                writer.write_all(s2c)?;
            }
            #[cfg(feature = "nts-pool")]
            NtsRecord::NtpServerDeny { denied: name } => {
                // NOTE: the server name should be ascii
                #[cfg(not(feature = "__internal-fuzz"))]
                debug_assert!(name.is_ascii());
                let length = name.len() as u16;
                writer.write_all(&length.to_be_bytes())?;

                writer.write_all(name.as_bytes())?;
            }
            #[cfg(feature = "ntpv5")]
            NtsRecord::DraftId { data } => {
                writer.write_all(&(data.len() as u16).to_be_bytes())?;
                writer.write_all(data)?;
            }
        }

        Ok(())
    }

    pub fn decoder() -> NtsRecordDecoder {
        NtsRecordDecoder { bytes: vec![] }
    }
}

#[cfg(feature = "__internal-fuzz")]
impl<'a> arbitrary::Arbitrary<'a> for NtsRecord {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let record = u16::arbitrary(u)?;

        let critical = record & 0x8000 != 0;
        let record_type = record & !0x8000;

        use NtsRecord::*;
        Ok(match record_type {
            0 => EndOfMessage,
            1 => NextProtocol {
                protocol_ids: u.arbitrary()?,
            },
            2 => Error {
                errorcode: u.arbitrary()?,
            },
            3 => Warning {
                warningcode: u.arbitrary()?,
            },
            4 => AeadAlgorithm {
                critical,
                algorithm_ids: u.arbitrary()?,
            },
            5 => NewCookie {
                cookie_data: u.arbitrary()?,
            },
            6 => Server {
                critical,
                name: u.arbitrary()?,
            },
            7 => Port {
                critical,
                port: u.arbitrary()?,
            },
            _ => NtsRecord::Unknown {
                record_type,
                critical,
                data: u.arbitrary()?,
            },
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct NtsRecordDecoder {
    bytes: Vec<u8>,
}

impl Extend<u8> for NtsRecordDecoder {
    fn extend<T: IntoIterator<Item = u8>>(&mut self, iter: T) {
        self.bytes.extend(iter);
    }
}

impl NtsRecordDecoder {
    /// the size of the KE packet header:
    ///
    /// - 2 bytes for the record type + critical flag
    /// - 2 bytes for the record length
    const HEADER_BYTES: usize = 4;

    /// Try to decode the next record. Returns None when there are not enough bytes
    pub fn step(&mut self) -> std::io::Result<Option<NtsRecord>> {
        if self.bytes.len() < Self::HEADER_BYTES {
            return Ok(None);
        }

        let record_len = u16::from_be_bytes([self.bytes[2], self.bytes[3]]);
        let message_len = Self::HEADER_BYTES + record_len as usize;

        if self.bytes.len() >= message_len {
            let record = NtsRecord::read(&mut self.bytes.as_slice())?;

            // remove the first `message_len` bytes from the buffer
            self.bytes.copy_within(message_len.., 0);
            self.bytes.truncate(self.bytes.len() - message_len);

            Ok(Some(record))
        } else {
            Ok(None)
        }
    }

    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug)]
pub enum KeyExchangeError {
    UnrecognizedCriticalRecord,
    BadRequest,
    InternalServerError,
    UnknownErrorCode(u16),
    BadResponse,
    NoValidProtocol,
    NoValidAlgorithm,
    InvalidFixedKeyLength,
    NoCookies,
    Io(std::io::Error),
    Tls(rustls::Error),
    Certificate(rustls::Error),
    DnsName(rustls::pki_types::InvalidDnsNameError),
    IncompleteResponse,
}

impl Display for KeyExchangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnrecognizedCriticalRecord => {
                write!(f, "Unrecognized record is marked as critical")
            }
            Self::BadRequest => write!(f, "Remote: Bad request"),
            Self::InternalServerError => write!(f, "Remote: Internal server error"),
            Self::UnknownErrorCode(e) => write!(f, "Remote: Error with unknown code {e}"),
            Self::BadResponse => write!(f, "The server response is invalid"),
            Self::NoValidProtocol => write!(
                f,
                "No continuation protocol supported by both us and server"
            ),
            Self::NoValidAlgorithm => {
                write!(f, "No encryption algorithm supported by both us and server")
            }
            Self::InvalidFixedKeyLength => write!(
                f,
                "The length of a fixed key does not match the algorithm used"
            ),
            Self::NoCookies => write!(f, "Missing cookies"),
            Self::Io(e) => write!(f, "{e}"),
            Self::Tls(e) => write!(f, "{e}"),
            Self::Certificate(e) => write!(f, "{e}"),
            Self::DnsName(e) => write!(f, "{e}"),
            Self::IncompleteResponse => write!(f, "Incomplete response"),
        }
    }
}

impl From<std::io::Error> for KeyExchangeError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rustls::Error> for KeyExchangeError {
    fn from(value: rustls::Error) -> Self {
        Self::Tls(value)
    }
}

impl From<rustls::pki_types::InvalidDnsNameError> for KeyExchangeError {
    fn from(value: rustls::pki_types::InvalidDnsNameError) -> Self {
        Self::DnsName(value)
    }
}

impl std::error::Error for KeyExchangeError {}

impl KeyExchangeError {
    pub(crate) fn from_error_code(error_code: u16) -> Self {
        match error_code {
            0 => Self::UnrecognizedCriticalRecord,
            1 => Self::BadRequest,
            2 => Self::InternalServerError,
            _ => Self::UnknownErrorCode(error_code),
        }
    }

    pub fn to_error_code(&self) -> u16 {
        use KeyExchangeError::*;

        match self {
            UnrecognizedCriticalRecord => NtsRecord::UNRECOGNIZED_CRITICAL_RECORD,
            BadRequest => NtsRecord::BAD_REQUEST,
            InternalServerError | Io(_) => NtsRecord::INTERNAL_SERVER_ERROR,
            UnknownErrorCode(_)
            | BadResponse
            | NoValidProtocol
            | NoValidAlgorithm
            | InvalidFixedKeyLength
            | NoCookies
            | Tls(_)
            | Certificate(_)
            | DnsName(_)
            | IncompleteResponse => NtsRecord::BAD_REQUEST,
        }
    }
}

/// From https://www.rfc-editor.org/rfc/rfc8915.html#name-network-time-security-next-
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
#[repr(u16)]
pub enum ProtocolId {
    #[default]
    NtpV4 = 0,

    #[cfg(feature = "ntpv5")]
    NtpV5 = 0x8001,
}

impl ProtocolId {
    const IN_ORDER_OF_PREFERENCE: &'static [Self] = &[
        #[cfg(feature = "ntpv5")]
        Self::NtpV5,
        Self::NtpV4,
    ];

    pub const fn try_deserialize(number: u16) -> Option<Self> {
        match number {
            0 => Some(Self::NtpV4),
            _ => None,
        }
    }

    #[cfg(feature = "ntpv5")]
    pub const fn try_deserialize_v5(number: u16) -> Option<Self> {
        match number {
            0 => Some(Self::NtpV4),
            0x8001 => Some(Self::NtpV5),
            _ => None,
        }
    }
}

/// From https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
#[repr(u16)]
pub enum AeadAlgorithm {
    #[default]
    AeadAesSivCmac256 = 15,
    AeadAesSivCmac512 = 17,
}

impl AeadAlgorithm {
    // per https://www.rfc-editor.org/rfc/rfc8915.html#section-5.1
    pub const fn c2s_context(self, protocol: ProtocolId) -> [u8; 5] {
        // The final octet SHALL be 0x00 for the C2S key
        [
            (protocol as u16 >> 8) as u8,
            protocol as u8,
            (self as u16 >> 8) as u8,
            self as u8,
            0,
        ]
    }

    // per https://www.rfc-editor.org/rfc/rfc8915.html#section-5.1
    pub const fn s2c_context(self, protocol: ProtocolId) -> [u8; 5] {
        // The final octet SHALL be 0x01 for the S2C key
        [
            (protocol as u16 >> 8) as u8,
            protocol as u8,
            (self as u16 >> 8) as u8,
            self as u8,
            1,
        ]
    }

    pub const fn try_deserialize(number: u16) -> Option<AeadAlgorithm> {
        match number {
            15 => Some(AeadAlgorithm::AeadAesSivCmac256),
            17 => Some(AeadAlgorithm::AeadAesSivCmac512),
            _ => None,
        }
    }

    const IN_ORDER_OF_PREFERENCE: &'static [Self] =
        &[Self::AeadAesSivCmac512, Self::AeadAesSivCmac256];

    pub(crate) fn extract_nts_keys<ConnectionData>(
        &self,
        protocol: ProtocolId,
        tls_connection: &rustls::ConnectionCommon<ConnectionData>,
    ) -> Result<NtsKeys, rustls::Error> {
        match self {
            AeadAlgorithm::AeadAesSivCmac256 => {
                let c2s = extract_nts_key(tls_connection, self.c2s_context(protocol))?;
                let s2c = extract_nts_key(tls_connection, self.s2c_context(protocol))?;

                let c2s = Box::new(AesSivCmac256::new(c2s));
                let s2c = Box::new(AesSivCmac256::new(s2c));

                Ok(NtsKeys { c2s, s2c })
            }
            AeadAlgorithm::AeadAesSivCmac512 => {
                let c2s = extract_nts_key(tls_connection, self.c2s_context(protocol))?;
                let s2c = extract_nts_key(tls_connection, self.s2c_context(protocol))?;

                let c2s = Box::new(AesSivCmac512::new(c2s));
                let s2c = Box::new(AesSivCmac512::new(s2c));

                Ok(NtsKeys { c2s, s2c })
            }
        }
    }

    #[cfg(feature = "nts-pool")]
    fn try_into_nts_keys(&self, RequestedKeys { c2s, s2c }: &RequestedKeys) -> Option<NtsKeys> {
        match self {
            AeadAlgorithm::AeadAesSivCmac256 => {
                let c2s = Box::new(AesSivCmac256::from_key_bytes(c2s).ok()?);
                let s2c = Box::new(AesSivCmac256::from_key_bytes(s2c).ok()?);

                Some(NtsKeys { c2s, s2c })
            }
            AeadAlgorithm::AeadAesSivCmac512 => {
                let c2s = Box::new(AesSivCmac512::from_key_bytes(c2s).ok()?);
                let s2c = Box::new(AesSivCmac512::from_key_bytes(s2c).ok()?);

                Some(NtsKeys { c2s, s2c })
            }
        }
    }

    #[cfg(feature = "nts-pool")]
    fn key_size(&self) -> u16 {
        match self {
            AeadAlgorithm::AeadAesSivCmac256 => AesSivCmac256::key_size() as u16,
            AeadAlgorithm::AeadAesSivCmac512 => AesSivCmac512::key_size() as u16,
        }
    }
}

pub struct NtsKeys {
    c2s: Box<dyn Cipher>,
    s2c: Box<dyn Cipher>,
}

impl NtsKeys {
    #[cfg(feature = "nts-pool")]
    pub fn as_fixed_key_request(&self) -> NtsRecord {
        NtsRecord::FixedKeyRequest {
            c2s: self.c2s.key_bytes().to_vec(),
            s2c: self.s2c.key_bytes().to_vec(),
        }
    }
}

impl std::fmt::Debug for NtsKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NtsKeys")
            .field("c2s", &"<opaque>")
            .field("s2c", &"<opaque>")
            .finish()
    }
}

fn extract_nts_key<T: Default + AsMut<[u8]>, ConnectionData>(
    tls_connection: &rustls::ConnectionCommon<ConnectionData>,
    context: [u8; 5],
) -> Result<T, rustls::Error> {
    let mut key = T::default();
    tls_connection.export_keying_material(
        &mut key,
        b"EXPORTER-network-time-security",
        Some(context.as_slice()),
    )?;

    Ok(key)
}

#[derive(Debug, PartialEq, Eq)]
pub struct PartialKeyExchangeData {
    remote: Option<String>,
    port: Option<u16>,
    protocol: ProtocolId,
    algorithm: AeadAlgorithm,
    cookies: CookieStash,
    #[cfg(feature = "nts-pool")]
    supported_algorithms: Option<Box<[(AeadAlgorithm, u16)]>>,
}

#[derive(Debug, Default)]
pub struct KeyExchangeResultDecoder {
    decoder: NtsRecordDecoder,
    remote: Option<String>,
    port: Option<u16>,
    algorithm: Option<AeadAlgorithm>,
    protocol: Option<ProtocolId>,
    cookies: CookieStash,

    #[cfg(feature = "nts-pool")]
    keep_alive: bool,

    #[cfg(feature = "nts-pool")]
    supported_algorithms: Option<Box<[(AeadAlgorithm, u16)]>>,
}

impl KeyExchangeResultDecoder {
    pub fn step_with_slice(
        mut self,
        bytes: &[u8],
    ) -> ControlFlow<Result<PartialKeyExchangeData, KeyExchangeError>, Self> {
        self.decoder.extend(bytes.iter().copied());

        loop {
            match self.decoder.step() {
                Err(e) => return ControlFlow::Break(Err(e.into())),
                Ok(Some(record)) => self = self.step_with_record(record)?,
                Ok(None) => return ControlFlow::Continue(self),
            }
        }
    }

    #[inline(always)]
    fn step_with_record(
        self,
        record: NtsRecord,
    ) -> ControlFlow<Result<PartialKeyExchangeData, KeyExchangeError>, Self> {
        use self::AeadAlgorithm as Algorithm;
        use ControlFlow::{Break, Continue};
        use KeyExchangeError::*;
        use NtsRecord::*;

        let mut state = self;

        match record {
            EndOfMessage => {
                let Some(protocol) = state.protocol else {
                    return ControlFlow::Break(Err(KeyExchangeError::NoValidProtocol));
                };

                // the spec notes
                //
                // > If the NTS Next Protocol Negotiation record offers Protocol ID 0 (for NTPv4),
                // > then this record MUST be included exactly once. Other protocols MAY require it as well.
                //
                // but we only support Protocol ID 0 (and assume ntpv5 behaves like ntpv4 in this regard)
                let Some(algorithm) = state.algorithm else {
                    return ControlFlow::Break(Err(KeyExchangeError::NoValidAlgorithm));
                };

                if state.cookies.is_empty() {
                    Break(Err(KeyExchangeError::NoCookies))
                } else {
                    Break(Ok(PartialKeyExchangeData {
                        remote: state.remote,
                        port: state.port,
                        protocol,
                        algorithm,
                        cookies: state.cookies,
                        #[cfg(feature = "nts-pool")]
                        supported_algorithms: state.supported_algorithms,
                    }))
                }
            }
            #[cfg(feature = "ntpv5")]
            DraftId { .. } => {
                tracing::warn!("Unexpected draft id");
                Continue(state)
            }
            NewCookie { cookie_data } => {
                state.cookies.store(cookie_data);
                Continue(state)
            }
            Server { name, .. } => {
                state.remote = Some(name);
                Continue(state)
            }
            Port { port, .. } => {
                state.port = Some(port);
                Continue(state)
            }
            Error { errorcode } => {
                //
                Break(Err(KeyExchangeError::from_error_code(errorcode)))
            }
            Warning { warningcode } => {
                tracing::warn!(warningcode, "Received key exchange warning code");

                Continue(state)
            }
            NextProtocol { protocol_ids } => {
                let selected = ProtocolId::IN_ORDER_OF_PREFERENCE
                    .iter()
                    .find_map(|proto| protocol_ids.contains(&(*proto as u16)).then_some(*proto));

                match selected {
                    None => Break(Err(NoValidProtocol)),
                    Some(protocol) => {
                        // The NTS Next Protocol Negotiation record [..] MUST occur exactly once in every NTS-KE request and response.
                        match state.protocol {
                            None => {
                                state.protocol = Some(protocol);
                                Continue(state)
                            }
                            Some(_) => Break(Err(KeyExchangeError::BadResponse)),
                        }
                    }
                }
            }
            AeadAlgorithm { algorithm_ids, .. } => {
                // it MUST include at most one
                let algorithm_id = match algorithm_ids[..] {
                    [] => return Break(Err(NoValidAlgorithm)),
                    [algorithm_id] => algorithm_id,
                    _ => return Break(Err(BadResponse)),
                };

                let selected = Algorithm::IN_ORDER_OF_PREFERENCE
                    .iter()
                    .find(|algo| (algorithm_id == (**algo as u16)));

                match selected {
                    None => Break(Err(NoValidAlgorithm)),
                    Some(algorithm) => {
                        // for the protocol ids we support, the AeadAlgorithm record must be present
                        match state.algorithm {
                            None => {
                                state.algorithm = Some(*algorithm);
                                Continue(state)
                            }
                            Some(_) => Break(Err(KeyExchangeError::BadResponse)),
                        }
                    }
                }
            }

            Unknown { critical, .. } => {
                if critical {
                    Break(Err(KeyExchangeError::UnrecognizedCriticalRecord))
                } else {
                    Continue(state)
                }
            }
            #[cfg(feature = "nts-pool")]
            KeepAlive => {
                state.keep_alive = true;
                Continue(state)
            }
            #[cfg(feature = "nts-pool")]
            SupportedAlgorithmList {
                supported_algorithms,
            } => {
                use self::AeadAlgorithm;

                state.supported_algorithms = Some(
                    supported_algorithms
                        .into_iter()
                        .filter_map(|(aead_protocol_id, key_length)| {
                            let aead_algorithm = AeadAlgorithm::try_deserialize(aead_protocol_id)?;
                            Some((aead_algorithm, key_length))
                        })
                        .collect::<Vec<_>>()
                        .into_boxed_slice(),
                );

                Continue(state)
            }
            #[cfg(feature = "nts-pool")]
            FixedKeyRequest { .. } => {
                // a client should never receive a FixedKeyRequest
                tracing::warn!("Unexpected fixed key request");
                Continue(state)
            }
            #[cfg(feature = "nts-pool")]
            NtpServerDeny { .. } => {
                // a client should never receive a NtpServerDeny
                tracing::warn!("Unexpected ntp server deny");
                Continue(state)
            }
        }
    }

    fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug)]
pub struct KeyExchangeResult {
    pub remote: String,
    pub port: u16,
    pub nts: Box<SourceNtsData>,
    pub protocol_version: ProtocolVersion,

    #[cfg(feature = "nts-pool")]
    pub algorithms_reported_by_server: Option<Box<[(AeadAlgorithm, u16)]>>,
}

pub struct KeyExchangeClient {
    tls_connection: rustls::ClientConnection,
    decoder: KeyExchangeResultDecoder,
    server_name: String,
}

impl KeyExchangeClient {
    const NTP_DEFAULT_PORT: u16 = 123;

    pub fn wants_read(&self) -> bool {
        self.tls_connection.wants_read()
    }

    pub fn read_socket(&mut self, rd: &mut dyn Read) -> std::io::Result<usize> {
        self.tls_connection.read_tls(rd)
    }

    pub fn wants_write(&self) -> bool {
        self.tls_connection.wants_write()
    }

    pub fn write_socket(&mut self, wr: &mut dyn Write) -> std::io::Result<usize> {
        self.tls_connection.write_tls(wr)
    }

    pub fn progress(mut self) -> ControlFlow<Result<KeyExchangeResult, KeyExchangeError>, Self> {
        // Move any received data from tls to decoder
        let mut buf = [0; 128];
        loop {
            if let Err(e) = self.tls_connection.process_new_packets() {
                return ControlFlow::Break(Err(e.into()));
            }

            match self.tls_connection.reader().read(&mut buf) {
                Ok(0) => return ControlFlow::Break(Err(KeyExchangeError::IncompleteResponse)),
                Ok(n) => {
                    self.decoder = match self.decoder.step_with_slice(&buf[..n]) {
                        ControlFlow::Continue(decoder) => decoder,
                        ControlFlow::Break(Ok(result)) => {
                            let algorithm = result.algorithm;
                            let protocol = result.protocol;

                            tracing::debug!(?algorithm, "selected AEAD algorithm");

                            let keys = match algorithm
                                .extract_nts_keys(protocol, &self.tls_connection)
                            {
                                Ok(keys) => keys,
                                Err(e) => return ControlFlow::Break(Err(KeyExchangeError::Tls(e))),
                            };

                            let nts = Box::new(SourceNtsData {
                                cookies: result.cookies,
                                c2s: keys.c2s,
                                s2c: keys.s2c,
                            });

                            return ControlFlow::Break(Ok(KeyExchangeResult {
                                remote: result.remote.unwrap_or(self.server_name),
                                protocol_version: match protocol {
                                    ProtocolId::NtpV4 => ProtocolVersion::V4,
                                    #[cfg(feature = "ntpv5")]
                                    ProtocolId::NtpV5 => ProtocolVersion::V5,
                                },
                                port: result.port.unwrap_or(Self::NTP_DEFAULT_PORT),
                                nts,
                                #[cfg(feature = "nts-pool")]
                                algorithms_reported_by_server: result.supported_algorithms,
                            }));
                        }
                        ControlFlow::Break(Err(error)) => return ControlFlow::Break(Err(error)),
                    }
                }
                Err(e) => match e.kind() {
                    std::io::ErrorKind::WouldBlock => return ControlFlow::Continue(self),
                    _ => return ControlFlow::Break(Err(e.into())),
                },
            }
        }
    }

    // should only be used in tests!
    fn new_without_tls_write(
        server_name: String,
        mut tls_config: rustls::ClientConfig,
    ) -> Result<Self, KeyExchangeError> {
        // Ensure we send only ntske/1 as alpn
        tls_config.alpn_protocols.clear();
        tls_config.alpn_protocols.push(b"ntske/1".to_vec());

        // TLS only works when the server name is a DNS name; an IP address does not work
        let tls_connection = rustls::ClientConnection::new(
            Arc::new(tls_config),
            ServerName::try_from(&server_name as &str)?.to_owned(),
        )?;

        Ok(KeyExchangeClient {
            tls_connection,
            decoder: KeyExchangeResultDecoder::new(),
            server_name,
        })
    }

    pub fn new(
        server_name: String,
        tls_config: rustls::ClientConfig,
        denied_servers: impl IntoIterator<Item = String>,
    ) -> Result<Self, KeyExchangeError> {
        let mut client = Self::new_without_tls_write(server_name, tls_config)?;

        // Make the request immediately (note, this will only go out to the wire via the write functions above)
        // We use an intermediary buffer to ensure that all records are sent at once.
        // This should not be needed, but works around issues in some NTS-ke server implementations
        let mut buffer = Vec::with_capacity(1024);
        for record in NtsRecord::client_key_exchange_records(denied_servers).iter() {
            record.write(&mut buffer)?;
        }
        client.tls_connection.writer().write_all(&buffer)?;

        Ok(client)
    }
}

#[derive(Debug, Default)]
struct KeyExchangeServerDecoder {
    decoder: NtsRecordDecoder,
    /// AEAD algorithm that the client is able to use and that we support
    /// it may be that the server and client supported algorithms have no
    /// intersection!
    algorithm: Option<AeadAlgorithm>,
    /// Protocol (NTP version) that is supported by both client and server
    protocol: Option<ProtocolId>,

    #[cfg(feature = "ntpv5")]
    allow_v5: bool,

    #[cfg(feature = "nts-pool")]
    keep_alive: Option<bool>,
    #[cfg(feature = "nts-pool")]
    requested_supported_algorithms: bool,
    #[cfg(feature = "nts-pool")]
    fixed_key_request: Option<RequestedKeys>,
}

#[cfg(feature = "nts-pool")]
#[derive(Debug, PartialEq, Eq)]
struct RequestedKeys {
    c2s: Vec<u8>,
    s2c: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
struct ServerKeyExchangeData {
    algorithm: AeadAlgorithm,
    protocol: ProtocolId,
    /// By default, perform key extraction to acquire the c2s and s2c keys; otherwise, use the fixed keys.
    #[cfg(feature = "nts-pool")]
    fixed_keys: Option<RequestedKeys>,
    #[cfg(feature = "nts-pool")]
    requested_supported_algorithms: bool,
}

impl KeyExchangeServerDecoder {
    pub fn step_with_slice(
        mut self,
        bytes: &[u8],
    ) -> ControlFlow<Result<ServerKeyExchangeData, KeyExchangeError>, Self> {
        self.decoder.extend(bytes.iter().copied());

        loop {
            match self.decoder.step() {
                Err(e) => return ControlFlow::Break(Err(e.into())),
                Ok(Some(record)) => self = self.step_with_record(record)?,
                Ok(None) => return ControlFlow::Continue(self),
            }
        }
    }

    fn validate(self) -> Result<ServerKeyExchangeData, KeyExchangeError> {
        let Some(protocol) = self.protocol else {
            // The NTS Next Protocol Negotiation record [..] MUST occur exactly once in every NTS-KE request and response.
            return Err(KeyExchangeError::NoValidProtocol);
        };

        let Some(algorithm) = self.algorithm else {
            // for the protocol ids we support, the AeadAlgorithm record must be present
            return Err(KeyExchangeError::NoValidAlgorithm);
        };

        let result = ServerKeyExchangeData {
            algorithm,
            protocol,
            #[cfg(feature = "nts-pool")]
            fixed_keys: self.fixed_key_request,
            #[cfg(feature = "nts-pool")]
            requested_supported_algorithms: self.requested_supported_algorithms,
        };

        Ok(result)
    }

    #[cfg(feature = "nts-pool")]
    fn done(self) -> Result<ServerKeyExchangeData, KeyExchangeError> {
        if self.requested_supported_algorithms {
            let protocol = self.protocol.unwrap_or_default();
            let algorithm = self.algorithm.unwrap_or_default();

            let result = ServerKeyExchangeData {
                algorithm,
                protocol,
                #[cfg(feature = "nts-pool")]
                fixed_keys: self.fixed_key_request,
                #[cfg(feature = "nts-pool")]
                requested_supported_algorithms: self.requested_supported_algorithms,
            };

            Ok(result)
        } else {
            self.validate()
        }
    }

    #[cfg(not(feature = "nts-pool"))]
    fn done(self) -> Result<ServerKeyExchangeData, KeyExchangeError> {
        self.validate()
    }

    #[inline(always)]
    fn step_with_record(
        self,
        record: NtsRecord,
    ) -> ControlFlow<Result<ServerKeyExchangeData, KeyExchangeError>, Self> {
        use self::AeadAlgorithm as Algorithm;
        use ControlFlow::{Break, Continue};
        use KeyExchangeError::*;
        use NtsRecord::*;

        let mut state = self;

        match record {
            EndOfMessage => {
                // perform a final validation step: did we receive everything that we should?
                Break(state.done())
            }
            #[cfg(feature = "ntpv5")]
            DraftId { data } => {
                if data == crate::packet::v5::DRAFT_VERSION.as_bytes() {
                    state.allow_v5 = true;
                }
                Continue(state)
            }
            NewCookie { .. } => {
                // > Clients MUST NOT send records of this type
                //
                // TODO should we actively error when a client does?
                Continue(state)
            }
            Server { name: _, .. } => {
                // > When this record is sent by the client, it indicates that the client wishes to associate with the specified NTP
                // > server. The NTS-KE server MAY incorporate this request when deciding which NTPv4 Server Negotiation
                // > records to respond with, but honoring the client's preference is OPTIONAL. The client MUST NOT send more
                // > than one record of this type.
                //
                // we ignore the client's preference
                Continue(state)
            }
            Port { port: _, .. } => {
                // > When this record is sent by the client in conjunction with a NTPv4 Server Negotiation record, it indicates that
                // > the client wishes to associate with the NTP server at the specified port. The NTS-KE server MAY incorporate this
                // > request when deciding what NTPv4 Server Negotiation and NTPv4 Port Negotiation records to respond with,
                // > but honoring the client's preference is OPTIONAL
                //
                // we ignore the client's preference
                Continue(state)
            }
            Error { errorcode } => {
                //
                Break(Err(KeyExchangeError::from_error_code(errorcode)))
            }
            Warning { warningcode } => {
                tracing::debug!(warningcode, "Received key exchange warning code");

                Continue(state)
            }
            NextProtocol { protocol_ids } => {
                #[cfg(feature = "ntpv5")]
                let selected = if state.allow_v5 {
                    protocol_ids
                        .iter()
                        .copied()
                        .find_map(ProtocolId::try_deserialize_v5)
                } else {
                    protocol_ids
                        .iter()
                        .copied()
                        .find_map(ProtocolId::try_deserialize)
                };

                #[cfg(not(feature = "ntpv5"))]
                let selected = protocol_ids
                    .iter()
                    .copied()
                    .find_map(ProtocolId::try_deserialize);

                match selected {
                    None => Break(Err(NoValidProtocol)),
                    Some(protocol) => {
                        // The NTS Next Protocol Negotiation record [..] MUST occur exactly once in every NTS-KE request and response.
                        match state.protocol {
                            None => {
                                state.protocol = Some(protocol);
                                Continue(state)
                            }
                            Some(_) => Break(Err(KeyExchangeError::BadRequest)),
                        }
                    }
                }
            }
            AeadAlgorithm { algorithm_ids, .. } => {
                let selected = algorithm_ids
                    .iter()
                    .copied()
                    .find_map(Algorithm::try_deserialize);

                match selected {
                    None => Break(Err(NoValidAlgorithm)),
                    Some(algorithm) => {
                        // for the protocol ids we support, the AeadAlgorithm record must be present
                        match state.algorithm {
                            None => {
                                state.algorithm = Some(algorithm);
                                Continue(state)
                            }
                            Some(_) => Break(Err(KeyExchangeError::BadRequest)),
                        }
                    }
                }
            }

            #[cfg(feature = "nts-pool")]
            KeepAlive => {
                state.keep_alive = Some(true);
                Continue(state)
            }
            #[cfg(feature = "nts-pool")]
            SupportedAlgorithmList {
                supported_algorithms: _supported_algorithms,
            } => {
                #[cfg(not(feature = "__internal-fuzz"))]
                debug_assert_eq!(_supported_algorithms, &[]);

                state.requested_supported_algorithms = true;

                Continue(state)
            }
            #[cfg(feature = "nts-pool")]
            FixedKeyRequest { c2s, s2c } => {
                state.fixed_key_request = Some(RequestedKeys { c2s, s2c });
                Continue(state)
            }
            #[cfg(feature = "nts-pool")]
            NtpServerDeny { denied: _ } => {
                // we are not a NTS pool server, so we ignore this record
                Continue(state)
            }

            Unknown { critical, .. } => {
                if critical {
                    Break(Err(KeyExchangeError::UnrecognizedCriticalRecord))
                } else {
                    Continue(state)
                }
            }
        }
    }

    fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug)]
pub struct KeyExchangeServer {
    tls_connection: rustls::ServerConnection,
    state: State,
    keyset: Arc<KeySet>,
    ntp_port: Option<u16>,
    ntp_server: Option<String>,
    #[cfg(feature = "nts-pool")]
    pool_certificates: Arc<[rustls::pki_types::CertificateDer<'static>]>,
}

#[derive(Debug)]
enum State {
    Active { decoder: KeyExchangeServerDecoder },
    Done,
}

impl KeyExchangeServer {
    pub fn wants_read(&self) -> bool {
        self.tls_connection.wants_read()
    }

    pub fn read_socket(&mut self, rd: &mut dyn Read) -> std::io::Result<usize> {
        self.tls_connection.read_tls(rd)
    }

    pub fn wants_write(&self) -> bool {
        self.tls_connection.wants_write()
    }

    pub fn write_socket(&mut self, wr: &mut dyn Write) -> std::io::Result<usize> {
        self.tls_connection.write_tls(wr)
    }

    fn send_records(
        tls_connection: &mut rustls::ServerConnection,
        records: &[NtsRecord],
    ) -> std::io::Result<()> {
        let mut buffer = Vec::with_capacity(1024);
        for record in records.iter() {
            record.write(&mut buffer)?;
        }

        tls_connection.writer().write_all(&buffer)?;
        tls_connection.send_close_notify();

        Ok(())
    }

    fn send_error_record(mut tls_connection: rustls::ServerConnection, error: &KeyExchangeError) {
        let error_records = [
            NtsRecord::Error {
                errorcode: error.to_error_code(),
            },
            NtsRecord::NextProtocol {
                protocol_ids: vec![ProtocolId::NtpV4 as u16],
            },
            NtsRecord::EndOfMessage,
        ];

        if let Err(io) = Self::send_records(&mut tls_connection, &error_records) {
            tracing::debug!(key_exchange_error = ?error, io_error = ?io, "sending error record failed");
        }
    }

    pub fn progress(
        mut self,
    ) -> ControlFlow<Result<rustls::ServerConnection, KeyExchangeError>, Self> {
        // Move any received data from tls to decoder
        if let Err(e) = self.tls_connection.process_new_packets() {
            return ControlFlow::Break(Err(e.into()));
        }

        let mut buf = [0; 512];
        match self.tls_connection.reader().read(&mut buf) {
            Ok(0) => {
                // the connection was closed cleanly by the client
                // see https://docs.rs/rustls/latest/rustls/struct.Reader.html#method.read
                ControlFlow::Break(self.end_of_file())
            }
            Ok(n) => {
                match self.state {
                    State::Active { decoder } => match decoder.step_with_slice(&buf[..n]) {
                        ControlFlow::Continue(decoder) => {
                            // more bytes are needed
                            self.state = State::Active { decoder };

                            // recursively invoke the progress function. This is very unlikely!
                            //
                            // Normally, all records are written with a single write call, and
                            // received as one unit. Using many write calls does not really make
                            // sense for a client.
                            //
                            // So then, the other reason we could end up here is if the buffer is
                            // full. But 512 bytes is a lot of space for this interaction, and
                            // should be sufficient in most cases.
                            ControlFlow::Continue(self)
                        }
                        ControlFlow::Break(Ok(data)) => {
                            // all records have been decoded; send a response
                            // continues for a clean shutdown of the connection by the client
                            self.state = State::Done;
                            self.decoder_done(data)
                        }
                        ControlFlow::Break(Err(error)) => {
                            Self::send_error_record(self.tls_connection, &error);
                            ControlFlow::Break(Err(error))
                        }
                    },
                    State::Done => {
                        // client is sending more bytes, but we don't expect any more
                        // these extra bytes are ignored
                        ControlFlow::Continue(self)
                    }
                }
            }
            Err(e) => match e.kind() {
                std::io::ErrorKind::WouldBlock => {
                    // basically an await; give other tasks a chance
                    ControlFlow::Continue(self)
                }
                std::io::ErrorKind::UnexpectedEof => {
                    // the connection was closed uncleanly by the client
                    // see https://docs.rs/rustls/latest/rustls/struct.Reader.html#method.read
                    ControlFlow::Break(self.end_of_file())
                }
                _ => {
                    let error = KeyExchangeError::Io(e);
                    Self::send_error_record(self.tls_connection, &error);
                    ControlFlow::Break(Err(error))
                }
            },
        }
    }

    fn end_of_file(self) -> Result<rustls::ServerConnection, KeyExchangeError> {
        match self.state {
            State::Active { .. } => {
                // there are no more client bytes, but decoding was not finished yet
                Err(KeyExchangeError::IncompleteResponse)
            }
            State::Done => {
                // we're all done
                Ok(self.tls_connection)
            }
        }
    }

    #[cfg(feature = "nts-pool")]
    pub fn privileged_connection(&self) -> bool {
        self.tls_connection
            .peer_certificates()
            .and_then(|cert_chain| cert_chain.first())
            .map(|cert| self.pool_certificates.contains(cert))
            .unwrap_or(false)
    }

    #[cfg(feature = "nts-pool")]
    fn extract_nts_keys(&self, data: &ServerKeyExchangeData) -> Result<NtsKeys, KeyExchangeError> {
        if let Some(keys) = &data.fixed_keys {
            if self.privileged_connection() {
                tracing::debug!("using fixed keys for AEAD algorithm");
                data.algorithm
                    .try_into_nts_keys(keys)
                    .ok_or(KeyExchangeError::InvalidFixedKeyLength)
            } else {
                tracing::debug!("refused fixed key request due to improper authorization");
                Err(KeyExchangeError::UnrecognizedCriticalRecord)
            }
        } else {
            self.extract_nts_keys_tls(data)
        }
    }

    #[cfg(not(feature = "nts-pool"))]
    fn extract_nts_keys(&self, data: &ServerKeyExchangeData) -> Result<NtsKeys, KeyExchangeError> {
        self.extract_nts_keys_tls(data)
    }

    fn extract_nts_keys_tls(
        &self,
        data: &ServerKeyExchangeData,
    ) -> Result<NtsKeys, KeyExchangeError> {
        tracing::debug!("using AEAD keys extracted from TLS connection");

        data.algorithm
            .extract_nts_keys(data.protocol, &self.tls_connection)
            .map_err(KeyExchangeError::Tls)
    }

    fn decoder_done(
        mut self,
        data: ServerKeyExchangeData,
    ) -> ControlFlow<Result<rustls::ServerConnection, KeyExchangeError>, Self> {
        let algorithm = data.algorithm;
        let protocol = data.protocol;
        //TODO: see comment in fn server_key_exchange_records()
        #[cfg(feature = "nts-pool")]
        let send_algorithm_list = data.requested_supported_algorithms;

        tracing::debug!(?protocol, ?algorithm, "selected AEAD algorithm");

        match self.extract_nts_keys(&data) {
            Ok(keys) => {
                let records = NtsRecord::server_key_exchange_records(
                    protocol,
                    algorithm,
                    &self.keyset,
                    keys,
                    self.ntp_port,
                    self.ntp_server.clone(),
                    #[cfg(feature = "nts-pool")]
                    send_algorithm_list,
                );

                match Self::send_records(&mut self.tls_connection, &records) {
                    Err(e) => ControlFlow::Break(Err(KeyExchangeError::Io(e))),
                    Ok(()) => ControlFlow::Continue(self),
                }
            }
            Err(key_extract_error) => {
                Self::send_error_record(self.tls_connection, &key_extract_error);
                ControlFlow::Break(Err(key_extract_error))
            }
        }
    }

    pub fn new(
        tls_config: Arc<rustls::ServerConfig>,
        keyset: Arc<KeySet>,
        ntp_port: Option<u16>,
        ntp_server: Option<String>,
        pool_certificates: Arc<[rustls::pki_types::CertificateDer<'static>]>,
    ) -> Result<Self, KeyExchangeError> {
        // Ensure we send only ntske/1 as alpn
        debug_assert_eq!(tls_config.alpn_protocols, &[b"ntske/1".to_vec()]);

        // TLS only works when the server name is a DNS name; an IP address does not work
        let tls_connection = rustls::ServerConnection::new(tls_config)?;

        #[cfg(not(feature = "nts-pool"))]
        let _ = pool_certificates;

        Ok(Self {
            tls_connection,
            state: State::Active {
                decoder: KeyExchangeServerDecoder::new(),
            },
            keyset,
            ntp_port,
            ntp_server,
            #[cfg(feature = "nts-pool")]
            pool_certificates,
        })
    }
}

#[cfg(feature = "__internal-fuzz")]
pub fn fuzz_key_exchange_server_decoder(data: &[u8]) {
    // this fuzz harness is inspired by the server_decoder_finds_algorithm() test
    let mut decoder = KeyExchangeServerDecoder::new();

    let decode_output = || {
        // chunk size 24 is taken from the original test function, this may
        // benefit from additional changes
        for chunk in data.chunks(24) {
            decoder = match decoder.step_with_slice(chunk) {
                ControlFlow::Continue(d) => d,
                ControlFlow::Break(done) => return done,
            };
        }

        Err(KeyExchangeError::IncompleteResponse)
    };

    let _result = decode_output();
}

#[cfg(feature = "__internal-fuzz")]
pub fn fuzz_key_exchange_result_decoder(data: &[u8]) {
    let decoder = KeyExchangeResultDecoder::new();

    let _res = match decoder.step_with_slice(data) {
        ControlFlow::Continue(decoder) => decoder,
        ControlFlow::Break(_result) => return,
    };
}

#[cfg(test)]
mod test {
    use std::io::Cursor;
    use super::*;

    #[test]
    fn test_algorithm_decoding() {
        for i in 0..=u16::MAX {
            if let Some(alg) = AeadAlgorithm::try_deserialize(i) {
                assert_eq!(alg as u16, i);
            }
        }
    }

    #[test]
    fn test_protocol_decoding() {
        for i in 0..=u16::MAX {
            if let Some(proto) = ProtocolId::try_deserialize(i) {
                assert_eq!(proto as u16, i);
            }
        }
    }

    #[cfg(not(feature = "ntpv5"))]
    #[test]
    fn test_client_key_exchange_records() {
        let mut buffer = Vec::with_capacity(1024);
        for record in NtsRecord::client_key_exchange_records([]).iter() {
            record.write(&mut buffer).unwrap();
        }

        assert_eq!(
            buffer,
            &[128, 1, 0, 2, 0, 0, 0, 4, 0, 4, 0, 17, 0, 15, 128, 0, 0, 0]
        );
    }

    #[cfg(not(feature = "ntpv5"))]
    #[test]
    fn test_decode_client_key_exchange_records() {
        let bytes = [128, 1, 0, 2, 0, 0, 0, 4, 0, 4, 0, 17, 0, 15, 128, 0, 0, 0];

        let mut decoder = NtsRecord::decoder();
        decoder.extend(bytes);

        assert_eq!(
            [
                decoder.step().unwrap().unwrap(),
                decoder.step().unwrap().unwrap(),
                decoder.step().unwrap().unwrap(),
            ],
            NtsRecord::client_key_exchange_records(vec![]).as_ref()
        );

        assert!(decoder.step().unwrap().is_none());
    }

    #[test]
    fn encode_decode_server_invalid_utf8() {
        let buffer = vec![
            0, 6, // type
            0, 4, // length
            0xF8, 0x80, 0x80, 0x80, // content (invalid utf8 sequence)
        ];

        let record = NtsRecord::Unknown {
            record_type: 6,
            critical: false,
            data: vec![0xF8, 0x80, 0x80, 0x80],
        };

        let decoded = NtsRecord::read(&mut Cursor::new(buffer)).unwrap();

        assert_eq!(record, decoded);
    }

    #[test]
    fn encode_decode_error_record() {
        let mut buffer = Vec::new();

        let record = NtsRecord::Error { errorcode: 42 };

        record.write(&mut buffer).unwrap();

        let decoded = NtsRecord::read(&mut Cursor::new(buffer)).unwrap();

        assert_eq!(record, decoded);
    }

    #[test]
    fn encode_decode_warning_record() {
        let mut buffer = Vec::new();

        let record = NtsRecord::Warning { warningcode: 42 };

        record.write(&mut buffer).unwrap();

        let decoded = NtsRecord::read(&mut Cursor::new(buffer)).unwrap();

        assert_eq!(record, decoded);
    }

    #[test]
    fn encode_decode_unknown_record() {
        let mut buffer = Vec::new();

        let record = NtsRecord::Unknown {
            record_type: 8,
            critical: true,
            data: vec![1, 2, 3],
        };

        record.write(&mut buffer).unwrap();

        let decoded = NtsRecord::read(&mut Cursor::new(buffer)).unwrap();

        assert_eq!(record, decoded);
    }

    #[test]
    #[cfg(feature = "nts-pool")]
    fn encode_decode_keep_alive_record() {
        let mut buffer = Vec::new();

        let record = NtsRecord::KeepAlive;

        record.write(&mut buffer).unwrap();

        let decoded = NtsRecord::read(&mut Cursor::new(buffer)).unwrap();

        assert_eq!(record, decoded);
    }

    #[test]
    #[cfg(feature = "nts-pool")]
    fn encode_decode_supported_protocol_list_record() {
        let mut buffer = Vec::new();

        let record = NtsRecord::SupportedAlgorithmList {
            supported_algorithms: vec![
                (AeadAlgorithm::AeadAesSivCmac256 as u16, 256 / 8),
                (AeadAlgorithm::AeadAesSivCmac512 as u16, 512 / 8),
            ],
        };

        record.write(&mut buffer).unwrap();

        let decoded = NtsRecord::read(&mut Cursor::new(buffer)).unwrap();

        assert_eq!(record, decoded);
    }

    #[test]
    #[cfg(feature = "nts-pool")]
    fn encode_decode_fixed_key_request_record() {
        let mut buffer = Vec::new();

        let c2s: Vec<_> = (0..).take(8).collect();
        let s2c: Vec<_> = (0..).skip(8).take(8).collect();

        let record = NtsRecord::FixedKeyRequest { c2s, s2c };

        record.write(&mut buffer).unwrap();

        let decoded = NtsRecord::read(&mut Cursor::new(buffer)).unwrap();

        assert_eq!(record, decoded);
    }

    #[test]
    #[cfg(feature = "nts-pool")]
    fn encode_decode_server_deny_record() {
        let mut buffer = Vec::new();

        let record = NtsRecord::NtpServerDeny {
            denied: String::from("a string"),
        };

        record.write(&mut buffer).unwrap();

        let decoded = NtsRecord::read(&mut Cursor::new(buffer)).unwrap();

        assert_eq!(record, decoded);
    }

    #[test]
    #[cfg(feature = "nts-pool")]
    fn encode_decode_server_deny_invalid_utf8() {
        let [a, b] = 0x4003u16.to_be_bytes();

        let buffer = vec![
            a, b, // type
            0, 4, // length
            0xF8, 0x80, 0x80, 0x80, // content (invalid utf8 sequence)
        ];

        let record = NtsRecord::Unknown {
            record_type: 0x4003,
            critical: false,
            data: vec![0xF8, 0x80, 0x80, 0x80],
        };

        let decoded = NtsRecord::read(&mut Cursor::new(buffer)).unwrap();

        assert_eq!(record, decoded);
    }

    fn client_decode_records(
        records: &[NtsRecord],
    ) -> Result<PartialKeyExchangeData, KeyExchangeError> {
        let mut decoder = KeyExchangeResultDecoder::new();
        let mut buffer = Vec::with_capacity(1024);

        for record in records {
            buffer.clear();
            record.write(&mut buffer).unwrap();

            decoder = match decoder.step_with_slice(&buffer) {
                ControlFlow::Continue(decoder) => decoder,
                ControlFlow::Break(result) => return result,
            }
        }

        Err(KeyExchangeError::IncompleteResponse)
    }

    #[test]
    fn client_decoder_immediate_next_protocol_end_of_message() {
        assert!(matches!(
            client_decode_records(&[
                NtsRecord::NextProtocol {
                    protocol_ids: vec![0]
                },
                NtsRecord::AeadAlgorithm {
                    critical: true,
                    algorithm_ids: vec![15],
                },
                NtsRecord::EndOfMessage
            ]),
            Err(KeyExchangeError::NoCookies)
        ));
    }

    #[test]
    fn client_decoder_immediate_end_of_message() {
        assert!(matches!(
            client_decode_records(&[NtsRecord::EndOfMessage]),
            Err(KeyExchangeError::NoValidProtocol)
        ));
    }

    #[test]
    fn client_decoder_missing_aead_algorithm_record() {
        assert!(matches!(
            client_decode_records(&[
                NtsRecord::NextProtocol {
                    protocol_ids: vec![0]
                },
                NtsRecord::EndOfMessage
            ]),
            Err(KeyExchangeError::NoValidAlgorithm)
        ));
    }

    #[test]
    fn client_decoder_empty_aead_algorithm_list() {
        assert!(matches!(
            client_decode_records(&[
                NtsRecord::AeadAlgorithm {
                    critical: true,
                    algorithm_ids: vec![],
                },
                NtsRecord::NextProtocol {
                    protocol_ids: vec![0]
                },
                NtsRecord::EndOfMessage,
            ]),
            Err(KeyExchangeError::NoValidAlgorithm)
        ));
    }

    #[test]
    fn client_decoder_invalid_aead_algorithm_id() {
        assert!(matches!(
            client_decode_records(&[
                NtsRecord::AeadAlgorithm {
                    critical: true,
                    algorithm_ids: vec![42],
                },
                NtsRecord::NextProtocol {
                    protocol_ids: vec![0]
                },
                NtsRecord::EndOfMessage,
            ]),
            Err(KeyExchangeError::NoValidAlgorithm)
        ));
    }

    #[test]
    fn client_decoder_no_valid_protocol() {
        let records = [
            NtsRecord::NextProtocol {
                protocol_ids: vec![1234],
            },
            NtsRecord::EndOfMessage,
        ];

        let error = client_decode_records(&records).unwrap_err();

        assert!(matches!(error, KeyExchangeError::NoValidProtocol))
    }

    #[test]
    fn client_decoder_double_next_protocol() {
        let records = vec![
            NtsRecord::NextProtocol {
                protocol_ids: vec![0],
            },
            NtsRecord::NextProtocol {
                protocol_ids: vec![0],
            },
            NtsRecord::EndOfMessage,
        ];

        let error = client_decode_records(records.as_slice()).unwrap_err();
        assert!(matches!(error, KeyExchangeError::BadResponse));
    }

    #[test]
    fn client_decoder_double_aead_algorithm() {
        let records = vec![
            NtsRecord::NextProtocol {
                protocol_ids: vec![0],
            },
            NtsRecord::AeadAlgorithm {
                critical: true,
                algorithm_ids: vec![15, 16],
            },
            NtsRecord::EndOfMessage,
        ];

        let error = client_decode_records(records.as_slice()).unwrap_err();
        assert!(matches!(error, KeyExchangeError::BadResponse));
    }

    #[test]
    fn client_decoder_twice_aead_algorithm() {
        let records = vec![
            NtsRecord::NextProtocol {
                protocol_ids: vec![0],
            },
            NtsRecord::AeadAlgorithm {
                critical: true,
                algorithm_ids: vec![15],
            },
            NtsRecord::AeadAlgorithm {
                critical: true,
                algorithm_ids: vec![15],
            },
            NtsRecord::EndOfMessage,
        ];

        let error = client_decode_records(records.as_slice()).unwrap_err();
        assert!(matches!(error, KeyExchangeError::BadResponse));
    }

    #[test]
    fn host_port_updates() {
        let name = String::from("ntp.time.nl");
        let port = 4567;

        let records = [
            NtsRecord::NextProtocol {
                protocol_ids: vec![0],
            },
            NtsRecord::AeadAlgorithm {
                critical: true,
                algorithm_ids: vec![15],
            },
            NtsRecord::Server {
                critical: true,
                name: name.clone(),
            },
            NtsRecord::Port {
                critical: true,
                port,
            },
            NtsRecord::NewCookie {
                cookie_data: vec![
                    178, 15, 188, 164, 68, 107, 175, 34, 77, 63, 18, 34, 122, 22, 95, 242, 175,
                    224, 29, 173, 58, 187, 47, 11, 245, 247, 119, 89, 5, 8, 221, 162, 106, 66, 30,
                    65, 218, 13, 108, 238, 12, 29, 200, 9, 92, 218, 38, 20, 238, 251, 68, 35, 44,
                    129, 189, 132, 4, 93, 117, 136, 91, 234, 58, 195, 223, 171, 207, 247, 172, 128,
                    5, 219, 97, 21, 128, 107, 96, 220, 189, 53, 223, 111, 181, 164, 185, 173, 80,
                    101, 75, 18, 180, 129, 243, 140, 253, 236, 45, 62, 101, 155, 252, 51, 102, 97,
                ],
            },
            NtsRecord::EndOfMessage,
        ];

        let state = client_decode_records(records.as_slice()).unwrap();

        assert_eq!(state.remote, Some(name));
        assert_eq!(state.port, Some(port));
    }

    const EXAMPLE_COOKIE_DATA: &[u8] = &[
        178, 15, 188, 164, 68, 107, 175, 34, 77, 63, 18, 34, 122, 22, 95, 242, 175, 224, 29, 173,
        58, 187, 47, 11, 245, 247, 119, 89, 5, 8, 221, 162, 106, 66, 30, 65, 218, 13, 108, 238, 12,
        29, 200, 9, 92, 218, 38, 20, 238, 251, 68, 35, 44, 129, 189, 132, 4, 93, 117, 136, 91, 234,
        58, 195, 223, 171, 207, 247, 172, 128, 5, 219, 97, 21, 128, 107, 96, 220, 189, 53, 223,
        111, 181, 164, 185, 173, 80, 101, 75, 18, 180, 129, 243, 140, 253, 236, 45, 62, 101, 155,
        252, 51, 102, 97,
    ];

    #[test]
    fn hit_error_record() {
        let cookie = NtsRecord::NewCookie {
            cookie_data: EXAMPLE_COOKIE_DATA.to_vec(),
        };

        // this fails. In theory it's allright if the protocol ID is not 0,
        // but we do not support any. (we assume ntpv5 has the same behavior as ntpv4 here)
        let records = [
            cookie.clone(),
            NtsRecord::NextProtocol {
                protocol_ids: vec![0],
            },
            NtsRecord::EndOfMessage,
        ];

        assert!(matches!(
            client_decode_records(records.as_slice()),
            Err(KeyExchangeError::NoValidAlgorithm)
        ));

        // a warning does not change the outcome
        let records = [
            cookie.clone(),
            NtsRecord::Warning { warningcode: 42 },
            NtsRecord::NextProtocol {
                protocol_ids: vec![0],
            },
            NtsRecord::EndOfMessage,
        ];

        assert!(matches!(
            client_decode_records(records.as_slice()),
            Err(KeyExchangeError::NoValidAlgorithm)
        ));

        // an unknown non-critical does not change the outcome
        let records = [
            cookie.clone(),
            NtsRecord::Unknown {
                record_type: 8,
                critical: false,
                data: vec![1, 2, 3],
            },
            NtsRecord::NextProtocol {
                protocol_ids: vec![0],
            },
            NtsRecord::EndOfMessage,
        ];

        assert!(matches!(
            client_decode_records(records.as_slice()),
            Err(KeyExchangeError::NoValidAlgorithm)
        ));

        // fails with the expected error if there is an error record
        let records = [
            cookie.clone(),
            NtsRecord::Error { errorcode: 42 },
            NtsRecord::NextProtocol {
                protocol_ids: vec![0],
            },
            NtsRecord::EndOfMessage,
        ];

        let error = client_decode_records(records.as_slice()).unwrap_err();
        assert!(matches!(error, KeyExchangeError::UnknownErrorCode(42)));

        let _ = cookie;
    }

    #[test]
    fn client_critical_unknown_record() {
        // an unknown non-critical does not change the outcome
        let records = [
            NtsRecord::NextProtocol {
                protocol_ids: vec![0],
            },
            NtsRecord::Unknown {
                record_type: 8,
                critical: true,
                data: vec![1, 2, 3],
            },
            NtsRecord::EndOfMessage,
        ];

        assert!(matches!(
            client_decode_records(records.as_slice()),
            Err(KeyExchangeError::UnrecognizedCriticalRecord)
        ));
    }

    #[test]
    fn incomplete_response() {
        let error = client_decode_records(&[]).unwrap_err();
        assert!(matches!(error, KeyExchangeError::IncompleteResponse));

        // this succeeds on its own
        let records = [NtsRecord::NewCookie {
            cookie_data: EXAMPLE_COOKIE_DATA.to_vec(),
        }];

        let error = client_decode_records(records.as_slice()).unwrap_err();
        assert!(matches!(error, KeyExchangeError::IncompleteResponse));
    }

    const NTS_TIME_NL_RESPONSE: &[u8] = &[
        128, 1, 0, 2, 0, 0, 0, 4, 0, 2, 0, 15, 0, 5, 0, 104, 178, 15, 188, 164, 68, 107, 175, 34,
        77, 63, 18, 34, 122, 22, 95, 242, 175, 224, 29, 173, 58, 187, 47, 11, 245, 247, 119, 89, 5,
        8, 221, 162, 106, 66, 30, 65, 218, 13, 108, 238, 12, 29, 200, 9, 92, 218, 38, 20, 238, 251,
        68, 35, 44, 129, 189, 132, 4, 93, 117, 136, 91, 234, 58, 195, 223, 171, 207, 247, 172, 128,
        5, 219, 97, 21, 128, 107, 96, 220, 189, 53, 223, 111, 181, 164, 185, 173, 80, 101, 75, 18,
        180, 129, 243, 140, 253, 236, 45, 62, 101, 155, 252, 51, 102, 97, 0, 5, 0, 104, 178, 15,
        188, 164, 106, 99, 31, 229, 75, 104, 141, 204, 89, 184, 80, 227, 43, 85, 25, 33, 78, 82,
        22, 97, 167, 52, 65, 243, 216, 198, 99, 98, 161, 219, 215, 253, 165, 121, 130, 232, 131,
        150, 158, 136, 113, 141, 34, 223, 42, 122, 185, 132, 185, 153, 158, 249, 192, 80, 167, 251,
        116, 45, 179, 151, 82, 248, 13, 208, 33, 74, 125, 233, 176, 153, 61, 58, 25, 23, 54, 106,
        208, 31, 40, 155, 227, 63, 58, 219, 119, 76, 101, 62, 154, 34, 187, 212, 106, 162, 140,
        223, 37, 194, 20, 107, 0, 5, 0, 104, 178, 15, 188, 164, 240, 20, 28, 103, 149, 25, 37, 145,
        187, 196, 100, 113, 36, 76, 171, 29, 69, 40, 19, 70, 95, 60, 30, 27, 188, 25, 1, 148, 55,
        18, 253, 131, 8, 108, 44, 173, 236, 74, 227, 49, 47, 183, 156, 118, 152, 88, 31, 254, 134,
        220, 129, 254, 186, 117, 80, 163, 167, 223, 208, 8, 124, 141, 240, 43, 161, 240, 60, 54,
        241, 44, 87, 135, 116, 63, 236, 40, 138, 162, 65, 143, 193, 98, 44, 9, 61, 189, 89, 19, 45,
        94, 6, 102, 82, 8, 175, 206, 87, 132, 51, 63, 0, 5, 0, 104, 178, 15, 188, 164, 56, 48, 71,
        172, 153, 142, 223, 150, 73, 72, 201, 236, 26, 68, 29, 14, 139, 66, 190, 77, 218, 206, 90,
        117, 75, 128, 88, 186, 187, 156, 130, 57, 198, 118, 176, 199, 55, 56, 173, 109, 35, 37, 15,
        223, 17, 53, 110, 167, 251, 167, 208, 44, 158, 89, 113, 22, 178, 92, 235, 114, 176, 41,
        255, 172, 175, 191, 227, 29, 85, 70, 152, 125, 67, 125, 96, 151, 151, 160, 188, 8, 35, 205,
        152, 142, 225, 59, 71, 224, 254, 84, 20, 51, 162, 164, 94, 241, 7, 15, 9, 138, 0, 5, 0,
        104, 178, 15, 188, 164, 198, 114, 113, 134, 102, 130, 116, 104, 6, 6, 81, 118, 89, 146,
        119, 198, 80, 135, 104, 155, 101, 107, 51, 215, 243, 241, 163, 55, 84, 206, 179, 241, 105,
        210, 184, 30, 44, 133, 235, 227, 87, 7, 40, 230, 185, 47, 180, 189, 84, 157, 182, 81, 69,
        168, 147, 115, 94, 53, 242, 198, 132, 188, 56, 86, 70, 201, 78, 219, 140, 212, 94, 100, 38,
        106, 168, 35, 57, 236, 156, 41, 86, 176, 225, 129, 152, 206, 49, 176, 252, 29, 235, 180,
        161, 148, 195, 223, 27, 217, 85, 220, 0, 5, 0, 104, 178, 15, 188, 164, 52, 150, 226, 182,
        229, 113, 23, 67, 155, 54, 34, 141, 125, 225, 98, 4, 22, 105, 111, 150, 212, 32, 9, 204,
        212, 242, 161, 213, 135, 199, 246, 74, 160, 126, 167, 94, 174, 76, 11, 228, 13, 251, 20,
        135, 0, 197, 207, 18, 168, 118, 218, 39, 79, 100, 203, 234, 224, 116, 59, 234, 247, 156,
        128, 58, 104, 57, 204, 85, 48, 68, 229, 37, 20, 146, 159, 67, 49, 235, 142, 58, 225, 149,
        187, 3, 11, 146, 193, 114, 122, 160, 19, 180, 146, 196, 50, 229, 22, 10, 86, 219, 0, 5, 0,
        104, 178, 15, 188, 164, 98, 15, 6, 117, 71, 114, 79, 45, 197, 158, 30, 187, 51, 12, 43,
        131, 252, 74, 92, 251, 139, 159, 99, 163, 149, 111, 89, 184, 95, 125, 73, 106, 62, 214,
        210, 50, 190, 83, 138, 46, 65, 126, 152, 54, 137, 189, 19, 247, 37, 116, 79, 178, 83, 51,
        31, 129, 24, 172, 108, 58, 10, 171, 128, 40, 220, 250, 168, 133, 164, 32, 47, 19, 231, 181,
        124, 242, 192, 212, 153, 25, 10, 165, 52, 170, 177, 42, 232, 2, 77, 246, 118, 192, 68, 96,
        152, 77, 238, 130, 53, 128, 0, 5, 0, 104, 178, 15, 188, 164, 208, 86, 125, 128, 153, 10,
        107, 157, 50, 100, 148, 177, 10, 163, 41, 208, 32, 142, 176, 21, 10, 15, 39, 208, 111, 47,
        233, 154, 23, 161, 191, 192, 105, 242, 25, 68, 234, 211, 81, 89, 244, 142, 184, 187, 236,
        171, 34, 23, 227, 55, 207, 94, 48, 71, 236, 188, 146, 223, 77, 213, 74, 234, 190, 192, 151,
        172, 223, 158, 44, 230, 247, 248, 212, 245, 43, 131, 80, 57, 187, 105, 148, 232, 15, 107,
        239, 84, 131, 9, 222, 225, 137, 73, 202, 40, 48, 57, 122, 198, 245, 40, 128, 0, 0, 0,
    ];

    fn nts_time_nl_records() -> [NtsRecord; 11] {
        [
            NtsRecord::NextProtocol {
                protocol_ids: vec![0],
            },
            NtsRecord::AeadAlgorithm {
                critical: false,
                algorithm_ids: vec![15],
            },
            NtsRecord::NewCookie {
                cookie_data: vec![
                    178, 15, 188, 164, 68, 107, 175, 34, 77, 63, 18, 34, 122, 22, 95, 242, 175,
                    224, 29, 173, 58, 187, 47, 11, 245, 247, 119, 89, 5, 8, 221, 162, 106, 66, 30,
                    65, 218, 13, 108, 238, 12, 29, 200, 9, 92, 218, 38, 20, 238, 251, 68, 35, 44,
                    129, 189, 132, 4, 93, 117, 136, 91, 234, 58, 195, 223, 171, 207, 247, 172, 128,
                    5, 219, 97, 21, 128, 107, 96, 220, 189, 53, 223, 111, 181, 164, 185, 173, 80,
                    101, 75, 18, 180, 129, 243, 140, 253, 236, 45, 62, 101, 155, 252, 51, 102, 97,
                ],
            },
            NtsRecord::NewCookie {
                cookie_data: vec![
                    178, 15, 188, 164, 106, 99, 31, 229, 75, 104, 141, 204, 89, 184, 80, 227, 43,
                    85, 25, 33, 78, 82, 22, 97, 167, 52, 65, 243, 216, 198, 99, 98, 161, 219, 215,
                    253, 165, 121, 130, 232, 131, 150, 158, 136, 113, 141, 34, 223, 42, 122, 185,
                    132, 185, 153, 158, 249, 192, 80, 167, 251, 116, 45, 179, 151, 82, 248, 13,
                    208, 33, 74, 125, 233, 176, 153, 61, 58, 25, 23, 54, 106, 208, 31, 40, 155,
                    227, 63, 58, 219, 119, 76, 101, 62, 154, 34, 187, 212, 106, 162, 140, 223, 37,
                    194, 20, 107,
                ],
            },
            NtsRecord::NewCookie {
                cookie_data: vec![
                    178, 15, 188, 164, 240, 20, 28, 103, 149, 25, 37, 145, 187, 196, 100, 113, 36,
                    76, 171, 29, 69, 40, 19, 70, 95, 60, 30, 27, 188, 25, 1, 148, 55, 18, 253, 131,
                    8, 108, 44, 173, 236, 74, 227, 49, 47, 183, 156, 118, 152, 88, 31, 254, 134,
                    220, 129, 254, 186, 117, 80, 163, 167, 223, 208, 8, 124, 141, 240, 43, 161,
                    240, 60, 54, 241, 44, 87, 135, 116, 63, 236, 40, 138, 162, 65, 143, 193, 98,
                    44, 9, 61, 189, 89, 19, 45, 94, 6, 102, 82, 8, 175, 206, 87, 132, 51, 63,
                ],
            },
            NtsRecord::NewCookie {
                cookie_data: vec![
                    178, 15, 188, 164, 56, 48, 71, 172, 153, 142, 223, 150, 73, 72, 201, 236, 26,
                    68, 29, 14, 139, 66, 190, 77, 218, 206, 90, 117, 75, 128, 88, 186, 187, 156,
                    130, 57, 198, 118, 176, 199, 55, 56, 173, 109, 35, 37, 15, 223, 17, 53, 110,
                    167, 251, 167, 208, 44, 158, 89, 113, 22, 178, 92, 235, 114, 176, 41, 255, 172,
                    175, 191, 227, 29, 85, 70, 152, 125, 67, 125, 96, 151, 151, 160, 188, 8, 35,
                    205, 152, 142, 225, 59, 71, 224, 254, 84, 20, 51, 162, 164, 94, 241, 7, 15, 9,
                    138,
                ],
            },
            NtsRecord::NewCookie {
                cookie_data: vec![
                    178, 15, 188, 164, 198, 114, 113, 134, 102, 130, 116, 104, 6, 6, 81, 118, 89,
                    146, 119, 198, 80, 135, 104, 155, 101, 107, 51, 215, 243, 241, 163, 55, 84,
                    206, 179, 241, 105, 210, 184, 30, 44, 133, 235, 227, 87, 7, 40, 230, 185, 47,
                    180, 189, 84, 157, 182, 81, 69, 168, 147, 115, 94, 53, 242, 198, 132, 188, 56,
                    86, 70, 201, 78, 219, 140, 212, 94, 100, 38, 106, 168, 35, 57, 236, 156, 41,
                    86, 176, 225, 129, 152, 206, 49, 176, 252, 29, 235, 180, 161, 148, 195, 223,
                    27, 217, 85, 220,
                ],
            },
            NtsRecord::NewCookie {
                cookie_data: vec![
                    178, 15, 188, 164, 52, 150, 226, 182, 229, 113, 23, 67, 155, 54, 34, 141, 125,
                    225, 98, 4, 22, 105, 111, 150, 212, 32, 9, 204, 212, 242, 161, 213, 135, 199,
                    246, 74, 160, 126, 167, 94, 174, 76, 11, 228, 13, 251, 20, 135, 0, 197, 207,
                    18, 168, 118, 218, 39, 79, 100, 203, 234, 224, 116, 59, 234, 247, 156, 128, 58,
                    104, 57, 204, 85, 48, 68, 229, 37, 20, 146, 159, 67, 49, 235, 142, 58, 225,
                    149, 187, 3, 11, 146, 193, 114, 122, 160, 19, 180, 146, 196, 50, 229, 22, 10,
                    86, 219,
                ],
            },
            NtsRecord::NewCookie {
                cookie_data: vec![
                    178, 15, 188, 164, 98, 15, 6, 117, 71, 114, 79, 45, 197, 158, 30, 187, 51, 12,
                    43, 131, 252, 74, 92, 251, 139, 159, 99, 163, 149, 111, 89, 184, 95, 125, 73,
                    106, 62, 214, 210, 50, 190, 83, 138, 46, 65, 126, 152, 54, 137, 189, 19, 247,
                    37, 116, 79, 178, 83, 51, 31, 129, 24, 172, 108, 58, 10, 171, 128, 40, 220,
                    250, 168, 133, 164, 32, 47, 19, 231, 181, 124, 242, 192, 212, 153, 25, 10, 165,
                    52, 170, 177, 42, 232, 2, 77, 246, 118, 192, 68, 96, 152, 77, 238, 130, 53,
                    128,
                ],
            },
            NtsRecord::NewCookie {
                cookie_data: vec![
                    178, 15, 188, 164, 208, 86, 125, 128, 153, 10, 107, 157, 50, 100, 148, 177, 10,
                    163, 41, 208, 32, 142, 176, 21, 10, 15, 39, 208, 111, 47, 233, 154, 23, 161,
                    191, 192, 105, 242, 25, 68, 234, 211, 81, 89, 244, 142, 184, 187, 236, 171, 34,
                    23, 227, 55, 207, 94, 48, 71, 236, 188, 146, 223, 77, 213, 74, 234, 190, 192,
                    151, 172, 223, 158, 44, 230, 247, 248, 212, 245, 43, 131, 80, 57, 187, 105,
                    148, 232, 15, 107, 239, 84, 131, 9, 222, 225, 137, 73, 202, 40, 48, 57, 122,
                    198, 245, 40,
                ],
            },
            NtsRecord::EndOfMessage,
        ]
    }

    #[test]
    fn test_nts_time_nl_response() {
        let state = client_decode_records(nts_time_nl_records().as_slice()).unwrap();

        assert_eq!(state.remote, None);
        assert_eq!(state.port, None);
        assert_eq!(state.cookies.gap(), 0);
    }

    #[test]
    fn test_decode_nts_time_nl_response() {
        let mut decoder = NtsRecord::decoder();
        decoder.extend(NTS_TIME_NL_RESPONSE.iter().copied());

        assert_eq!(
            [
                decoder.step().unwrap().unwrap(),
                decoder.step().unwrap().unwrap(),
                // cookies
                decoder.step().unwrap().unwrap(),
                decoder.step().unwrap().unwrap(),
                decoder.step().unwrap().unwrap(),
                decoder.step().unwrap().unwrap(),
                decoder.step().unwrap().unwrap(),
                decoder.step().unwrap().unwrap(),
                decoder.step().unwrap().unwrap(),
                decoder.step().unwrap().unwrap(),
                // end of message
                decoder.step().unwrap().unwrap(),
            ],
            nts_time_nl_records()
        );

        assert!(decoder.step().unwrap().is_none());
    }

    fn server_decode_records(
        records: &[NtsRecord],
    ) -> Result<ServerKeyExchangeData, KeyExchangeError> {
        let mut bytes = Vec::with_capacity(1024);
        for record in records {
            record.write(&mut bytes).unwrap();
        }

        let mut decoder = KeyExchangeServerDecoder::new();

        for chunk in bytes.chunks(24) {
            decoder = match decoder.step_with_slice(chunk) {
                ControlFlow::Continue(d) => d,
                ControlFlow::Break(done) => return done,
            };
        }

        Err(KeyExchangeError::IncompleteResponse)
    }

    #[test]
    fn server_decoder_immediate_end_of_message() {
        assert!(matches!(
            server_decode_records(&[NtsRecord::EndOfMessage]),
            Err(KeyExchangeError::NoValidProtocol)
        ));
    }

    #[test]
    fn server_decoder_missing_aead_algorithm_record() {
        assert!(matches!(
            server_decode_records(&[
                NtsRecord::NextProtocol {
                    protocol_ids: vec![0]
                },
                NtsRecord::EndOfMessage
            ]),
            Err(KeyExchangeError::NoValidAlgorithm)
        ));
    }

    #[test]
    fn server_decoder_empty_aead_algorithm_list() {
        assert!(matches!(
            server_decode_records(&[
                NtsRecord::AeadAlgorithm {
                    critical: true,
                    algorithm_ids: vec![],
                },
                NtsRecord::NextProtocol {
                    protocol_ids: vec![0]
                },
                NtsRecord::EndOfMessage,
            ]),
            Err(KeyExchangeError::NoValidAlgorithm)
        ));
    }

    #[test]
    fn server_decoder_invalid_aead_algorithm_id() {
        assert!(matches!(
            server_decode_records(&[
                NtsRecord::AeadAlgorithm {
                    critical: true,
                    algorithm_ids: vec![42],
                },
                NtsRecord::NextProtocol {
                    protocol_ids: vec![0]
                },
                NtsRecord::EndOfMessage,
            ]),
            Err(KeyExchangeError::NoValidAlgorithm)
        ));
    }

    #[test]
    fn server_decoder_finds_algorithm() {
        let result =
            server_decode_records(&NtsRecord::client_key_exchange_records(vec![])).unwrap();

        assert_eq!(result.algorithm, AeadAlgorithm::AeadAesSivCmac512);
    }

    #[test]
    fn server_decoder_ignores_new_cookie() {
        let mut records = NtsRecord::client_key_exchange_records(vec![]).to_vec();
        records.insert(
            0,
            NtsRecord::NewCookie {
                cookie_data: EXAMPLE_COOKIE_DATA.to_vec(),
            },
        );

        let result = server_decode_records(&records).unwrap();
        assert_eq!(result.algorithm, AeadAlgorithm::AeadAesSivCmac512);
    }

    #[test]
    fn server_decoder_ignores_server_and_port_preference() {
        let mut records = NtsRecord::client_key_exchange_records(vec![]).to_vec();
        records.insert(
            0,
            NtsRecord::Server {
                critical: true,
                name: String::from("example.com"),
            },
        );

        records.insert(
            0,
            NtsRecord::Port {
                critical: true,
                port: 4242,
            },
        );

        let result = server_decode_records(&records).unwrap();
        assert_eq!(result.algorithm, AeadAlgorithm::AeadAesSivCmac512);
    }

    #[test]
    fn server_decoder_ignores_warn() {
        let mut records = NtsRecord::client_key_exchange_records(vec![]).to_vec();
        records.insert(0, NtsRecord::Warning { warningcode: 42 });

        let result = server_decode_records(&records).unwrap();
        assert_eq!(result.algorithm, AeadAlgorithm::AeadAesSivCmac512);
    }

    #[test]
    fn server_decoder_ignores_unknown_not_critical() {
        let mut records = NtsRecord::client_key_exchange_records(vec![]).to_vec();
        records.insert(
            0,
            NtsRecord::Unknown {
                record_type: 8,
                critical: false,
                data: vec![1, 2, 3],
            },
        );

        let result = server_decode_records(&records).unwrap();
        assert_eq!(result.algorithm, AeadAlgorithm::AeadAesSivCmac512);
    }

    #[test]
    fn server_decoder_reports_unknown_critical() {
        let mut records = NtsRecord::client_key_exchange_records(vec![]).to_vec();
        records.insert(
            0,
            NtsRecord::Unknown {
                record_type: 8,
                critical: true,
                data: vec![1, 2, 3],
            },
        );

        let result = server_decode_records(&records).unwrap_err();
        assert!(matches!(
            result,
            KeyExchangeError::UnrecognizedCriticalRecord
        ));
    }

    #[test]
    fn server_decoder_reports_error() {
        let mut records = NtsRecord::client_key_exchange_records(vec![]).to_vec();
        records.insert(0, NtsRecord::Error { errorcode: 2 });

        let error = server_decode_records(&records).unwrap_err();
        assert!(matches!(error, KeyExchangeError::InternalServerError));
    }

    #[test]
    fn server_decoder_no_valid_protocol() {
        let records = [
            NtsRecord::NextProtocol {
                protocol_ids: vec![42],
            },
            NtsRecord::EndOfMessage,
        ];

        let error = server_decode_records(&records).unwrap_err();
        assert!(matches!(error, KeyExchangeError::NoValidProtocol));
    }

    #[test]
    fn server_decoder_double_next_protocol() {
        let records = [
            NtsRecord::NextProtocol {
                protocol_ids: vec![42],
            },
            NtsRecord::EndOfMessage,
        ];

        let error = server_decode_records(&records).unwrap_err();
        assert!(matches!(error, KeyExchangeError::NoValidProtocol));
    }

    #[test]
    fn server_decoder_double_aead_algorithm() {
        let records = vec![
            NtsRecord::NextProtocol {
                protocol_ids: vec![0],
            },
            NtsRecord::AeadAlgorithm {
                critical: true,
                algorithm_ids: vec![15],
            },
            NtsRecord::AeadAlgorithm {
                critical: true,
                algorithm_ids: vec![15],
            },
            NtsRecord::EndOfMessage,
        ];

        let error = server_decode_records(records.as_slice()).unwrap_err();
        assert!(matches!(error, KeyExchangeError::BadRequest));
    }

    #[test]
    fn server_decoder_no_valid_algorithm() {
        let records = [
            NtsRecord::NextProtocol {
                protocol_ids: vec![0],
            },
            NtsRecord::AeadAlgorithm {
                critical: false,
                algorithm_ids: vec![1234],
            },
            NtsRecord::EndOfMessage,
        ];

        let error = server_decode_records(&records).unwrap_err();
        assert!(matches!(error, KeyExchangeError::NoValidAlgorithm));
    }

    #[test]
    fn server_decoder_incomplete_response() {
        let error = server_decode_records(&[]).unwrap_err();
        assert!(matches!(error, KeyExchangeError::IncompleteResponse));

        let records = [
            NtsRecord::NextProtocol {
                protocol_ids: vec![0],
            },
            NtsRecord::Unknown {
                record_type: 8,
                critical: false,
                data: vec![1, 2, 3],
            },
        ];

        let error = server_decode_records(&records).unwrap_err();
        assert!(matches!(error, KeyExchangeError::IncompleteResponse));
    }

    #[test]
    #[cfg(feature = "nts-pool")]
    fn server_decoder_supported_algorithms() {
        let records = vec![
            NtsRecord::NextProtocol {
                protocol_ids: vec![0],
            },
            NtsRecord::AeadAlgorithm {
                critical: true,
                algorithm_ids: vec![15],
            },
            NtsRecord::SupportedAlgorithmList {
                supported_algorithms: vec![],
            },
            NtsRecord::NewCookie {
                cookie_data: vec![],
            },
            NtsRecord::EndOfMessage,
        ];

        let data = server_decode_records(records.as_slice()).unwrap();
        assert!(data.requested_supported_algorithms);

        let records = vec![
            NtsRecord::SupportedAlgorithmList {
                supported_algorithms: vec![],
            },
            NtsRecord::NewCookie {
                cookie_data: vec![],
            },
            NtsRecord::EndOfMessage,
        ];

        let data = server_decode_records(records.as_slice()).unwrap();
        assert!(data.requested_supported_algorithms);
    }

    #[allow(dead_code)]
    enum ClientType {
        Uncertified,
        Certified,
    }

}
