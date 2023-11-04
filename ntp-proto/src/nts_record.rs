use std::{
    io::{Read, Write},
    ops::ControlFlow,
    sync::Arc,
};

use aead::KeySizeUser;
use aes_siv::{Aes128SivAead, Aes256SivAead};

use crate::{
    cookiestash::CookieStash,
    keyset::{DecodedServerCookie, KeySet},
    packet::AesSivCmac512,
    packet::{AesSivCmac256, Cipher},
    peer::{PeerNtsData, ProtocolVersion},
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
}

fn read_u16_be(reader: &mut impl Read) -> std::io::Result<u16> {
    let mut bytes = [0, 0];
    reader.read_exact(&mut bytes)?;

    Ok(u16::from_be_bytes(bytes))
}

fn read_u16s_be(reader: &mut impl Read, length: usize) -> std::io::Result<Vec<u16>> {
    (0..length).map(|_| read_u16_be(reader)).collect()
}

fn read_bytes_exact(reader: &mut impl Read, length: usize) -> std::io::Result<Vec<u8>> {
    let mut output = vec![0; length];
    reader.read_exact(&mut output)?;

    Ok(output)
}

impl NtsRecord {
    pub fn client_key_exchange_records() -> [NtsRecord; if cfg!(feature = "ntpv5") { 4 } else { 3 }]
    {
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
            NtsRecord::EndOfMessage,
        ]
    }

    fn server_key_exchange_records(
        protocol: ProtocolId,
        algorithm: AeadAlgorithm,
        keyset: &KeySet,
        keys: NtsKeys,
    ) -> [NtsRecord; 11] {
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

        [
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
        ]
    }

    pub fn read<A: Read>(reader: &mut A) -> std::io::Result<NtsRecord> {
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

    pub fn write<A: Write>(&self, writer: &mut A) -> std::io::Result<()> {
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

#[derive(Debug, thiserror::Error)]
pub enum KeyExchangeError {
    #[error("Unrecognized record is marked as critical")]
    UnrecognizedCriticalRecord,
    #[error("Remote: Bad request")]
    BadRequest,
    #[error("Remote: Internal server error")]
    InternalServerError,
    #[error("Remote: Error with unknown code {0}")]
    UnknownErrorCode(u16),
    #[error("No continuation protocol supported by both us and server")]
    NoValidProtocol,
    #[error("No encryption algorithm supported by both us and server")]
    NoValidAlgorithm,
    #[error("Missing cookies")]
    NoCookies,
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Tls(#[from] rustls::Error),
    #[error("{0}")]
    Certificate(rustls::Error),
    #[error("{0}")]
    DnsName(#[from] rustls::client::InvalidDnsNameError),
    #[error("Incomplete response")]
    IncompleteResponse,
}

impl KeyExchangeError {
    fn from_error_code(error_code: u16) -> Self {
        match error_code {
            0 => Self::UnrecognizedCriticalRecord,
            1 => Self::BadRequest,
            2 => Self::InternalServerError,
            _ => Self::UnknownErrorCode(error_code),
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

    fn extract_nts_keys<ConnectionData>(
        &self,
        protocol: ProtocolId,
        tls_connection: &rustls::ConnectionCommon<ConnectionData>,
    ) -> Result<NtsKeys, rustls::Error> {
        match self {
            AeadAlgorithm::AeadAesSivCmac256 => {
                let c2s = extract_nts_key::<Aes128SivAead, _>(
                    tls_connection,
                    self.c2s_context(protocol),
                )?;
                let s2c = extract_nts_key::<Aes128SivAead, _>(
                    tls_connection,
                    self.s2c_context(protocol),
                )?;

                let c2s = Box::new(AesSivCmac256::new(c2s));
                let s2c = Box::new(AesSivCmac256::new(s2c));

                Ok(NtsKeys { c2s, s2c })
            }
            AeadAlgorithm::AeadAesSivCmac512 => {
                let c2s = extract_nts_key::<Aes256SivAead, _>(
                    tls_connection,
                    self.c2s_context(protocol),
                )?;
                let s2c = extract_nts_key::<Aes256SivAead, _>(
                    tls_connection,
                    self.s2c_context(protocol),
                )?;

                let c2s = Box::new(AesSivCmac512::new(c2s));
                let s2c = Box::new(AesSivCmac512::new(s2c));

                Ok(NtsKeys { c2s, s2c })
            }
        }
    }
}

pub struct NtsKeys {
    c2s: Box<dyn Cipher>,
    s2c: Box<dyn Cipher>,
}

fn extract_nts_key<T: KeySizeUser, ConnectionData>(
    tls_connection: &rustls::ConnectionCommon<ConnectionData>,
    context: [u8; 5],
) -> Result<aead::Key<T>, rustls::Error> {
    let mut key: aead::Key<T> = Default::default();
    tls_connection.export_keying_material(
        &mut key,
        b"EXPORTER-network-time-security",
        Some(context.as_slice()),
    )?;

    Ok(key)
}

#[derive(Debug, PartialEq, Eq)]
struct PartialKeyExchangeData {
    remote: Option<String>,
    port: Option<u16>,
    protocol: Option<ProtocolId>,
    algorithm: Option<AeadAlgorithm>,
    cookies: CookieStash,
}

#[derive(Debug, Default)]
struct KeyExchangeResultDecoder {
    decoder: NtsRecordDecoder,
    remote: Option<String>,
    port: Option<u16>,
    algorithm: Option<AeadAlgorithm>,
    protocol: Option<ProtocolId>,
    cookies: CookieStash,
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
                if state.cookies.is_empty() {
                    Break(Err(KeyExchangeError::NoCookies))
                } else {
                    Break(Ok(PartialKeyExchangeData {
                        remote: state.remote,
                        port: state.port,
                        protocol: state.protocol,
                        algorithm: state.algorithm,
                        cookies: state.cookies,
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

                state.protocol = selected;

                match state.protocol {
                    None => Break(Err(NoValidProtocol)),
                    Some(_) => Continue(state),
                }
            }
            AeadAlgorithm { algorithm_ids, .. } => {
                let selected = Algorithm::IN_ORDER_OF_PREFERENCE
                    .iter()
                    .find_map(|algo| algorithm_ids.contains(&(*algo as u16)).then_some(*algo));

                state.algorithm = selected;

                match state.algorithm {
                    None => Break(Err(NoValidAlgorithm)),
                    Some(_) => Continue(state),
                }
            }

            Unknown { .. } => Continue(state),
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
    pub nts: Box<PeerNtsData>,
    pub protocol_version: ProtocolVersion,
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
            let read_result = self.tls_connection.reader().read(&mut buf);
            match read_result {
                Ok(0) => return ControlFlow::Break(Err(KeyExchangeError::IncompleteResponse)),
                Ok(n) => {
                    self.decoder = match self.decoder.step_with_slice(&buf[..n]) {
                        ControlFlow::Continue(decoder) => decoder,
                        ControlFlow::Break(Ok(result)) => {
                            let algorithm = match result.algorithm {
                                Some(algorithm) => algorithm,
                                None => {
                                    return ControlFlow::Break(Err(
                                        KeyExchangeError::NoValidAlgorithm,
                                    ))
                                }
                            };
                            let protocol = match result.protocol {
                                Some(protocol) => protocol,
                                None => {
                                    return ControlFlow::Break(Err(
                                        KeyExchangeError::NoValidProtocol,
                                    ))
                                }
                            };

                            tracing::debug!(?algorithm, "selected AEAD algorithm");

                            let keys = match algorithm
                                .extract_nts_keys(protocol, &self.tls_connection)
                            {
                                Ok(keys) => keys,
                                Err(e) => return ControlFlow::Break(Err(KeyExchangeError::Tls(e))),
                            };

                            let nts = Box::new(PeerNtsData {
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
            (server_name.as_ref() as &str).try_into()?,
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
    ) -> Result<Self, KeyExchangeError> {
        let mut client = Self::new_without_tls_write(server_name, tls_config)?;

        // Make the request immediately (note, this will only go out to the wire via the write functions above)
        // We use an intermediary buffer to ensure that all records are sent at once.
        // This should not be needed, but works around issues in some NTS-ke server implementations
        let mut buffer = Vec::with_capacity(1024);
        for record in NtsRecord::client_key_exchange_records() {
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
    algorithm: AeadAlgorithm,
    /// Protocol (NTP version) that is supported by both client and server
    protocol: ProtocolId,

    #[cfg(feature = "ntpv5")]
    allow_v5: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct ServerKeyExchangeData {
    algorithm: AeadAlgorithm,
    protocol: ProtocolId,
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
                let result = ServerKeyExchangeData {
                    algorithm: state.algorithm,
                    protocol: state.protocol,
                };

                Break(Ok(result))
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
                        state.protocol = protocol;
                        Continue(state)
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
                        state.algorithm = algorithm;
                        Continue(state)
                    }
                }
            }

            Unknown { .. } => Continue(state),
        }
    }

    fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug)]
pub struct KeyExchangeServer {
    tls_connection: rustls::ServerConnection,
    decoder: Option<KeyExchangeServerDecoder>,
    keyset: Arc<KeySet>,
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

    fn send_response(
        &mut self,
        protocol: ProtocolId,
        algorithm: AeadAlgorithm,
        keys: NtsKeys,
    ) -> std::io::Result<()> {
        let records =
            NtsRecord::server_key_exchange_records(protocol, algorithm, &self.keyset, keys);

        let mut buffer = Vec::with_capacity(1024);
        for record in records.into_iter() {
            record.write(&mut buffer)?;
        }

        self.tls_connection.writer().write_all(&buffer)?;
        self.tls_connection.send_close_notify();

        Ok(())
    }

    pub fn progress(self) -> ControlFlow<Result<(), KeyExchangeError>, Self> {
        match self.progress_help() {
            ControlFlow::Continue(c) => ControlFlow::Continue(c),
            ControlFlow::Break(b) => ControlFlow::Break(b.map(drop)),
        }
    }

    fn progress_help(mut self) -> ControlFlow<Result<Self, KeyExchangeError>, Self> {
        // Move any received data from tls to decoder
        let mut buf = [0; 128];
        loop {
            if let Err(e) = self.tls_connection.process_new_packets() {
                return ControlFlow::Break(Err(e.into()));
            }
            let read_result = self.tls_connection.reader().read(&mut buf);
            match read_result {
                Ok(0) => {
                    match self.decoder {
                        Some(_) => {
                            // there are no more client bytes, but decoding was not finished yet
                            return ControlFlow::Break(Err(KeyExchangeError::IncompleteResponse));
                        }
                        None => {
                            // we're all done
                            return ControlFlow::Break(Ok(self));
                        }
                    }
                }
                Ok(n) => {
                    match self.decoder {
                        Some(decoder) => match decoder.step_with_slice(&buf[..n]) {
                            ControlFlow::Continue(decoder) => {
                                self.decoder = Some(decoder);
                                continue;
                            }
                            ControlFlow::Break(Ok(result)) => {
                                self.decoder = None;
                                let algorithm = result.algorithm;
                                let protocol = result.protocol;

                                tracing::debug!(?algorithm, "selected AEAD algorithm");

                                let keys = match algorithm
                                    .extract_nts_keys(protocol, &self.tls_connection)
                                {
                                    Ok(keys) => keys,
                                    Err(e) => {
                                        return ControlFlow::Break(Err(KeyExchangeError::Tls(e)))
                                    }
                                };

                                return match self.send_response(protocol, algorithm, keys) {
                                    Err(e) => ControlFlow::Break(Err(KeyExchangeError::Io(e))),
                                    Ok(()) => ControlFlow::Continue(self),
                                };
                            }
                            ControlFlow::Break(Err(error)) => {
                                return ControlFlow::Break(Err(error))
                            }
                        },
                        None => {
                            // client is sending more bytes, but we don't expect any more
                            return ControlFlow::Break(Err(KeyExchangeError::InternalServerError));
                        }
                    }
                }
                Err(e) => match e.kind() {
                    std::io::ErrorKind::WouldBlock => return ControlFlow::Continue(self),
                    std::io::ErrorKind::UnexpectedEof if self.decoder.is_none() => {
                        // something we need in practice. If we're already done, an EOF is fine
                        return ControlFlow::Break(Ok(self));
                    }
                    _ => return ControlFlow::Break(Err(e.into())),
                },
            }
        }
    }

    pub fn new(
        tls_config: Arc<rustls::ServerConfig>,
        keyset: Arc<KeySet>,
    ) -> Result<Self, KeyExchangeError> {
        // Ensure we send only ntske/1 as alpn
        debug_assert_eq!(tls_config.alpn_protocols, &[b"ntske/1".to_vec()]);

        // TLS only works when the server name is a DNS name; an IP address does not work
        let tls_connection = rustls::ServerConnection::new(tls_config)?;

        Ok(Self {
            tls_connection,
            decoder: Some(KeyExchangeServerDecoder::new()),
            keyset,
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

    use crate::keyset::KeySetProvider;

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
        for record in NtsRecord::client_key_exchange_records() {
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
            NtsRecord::client_key_exchange_records()
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

    fn roundtrip(records: &[NtsRecord]) -> Result<PartialKeyExchangeData, KeyExchangeError> {
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
    fn immediate_end_of_message() {
        assert!(matches!(
            roundtrip(&[NtsRecord::EndOfMessage]),
            Err(KeyExchangeError::NoCookies)
        ));
    }

    #[test]
    fn no_valid_algorithm() {
        let algorithm = NtsRecord::AeadAlgorithm {
            critical: true,
            algorithm_ids: vec![],
        };

        assert!(matches!(
            roundtrip(&[algorithm]),
            Err(KeyExchangeError::NoValidAlgorithm)
        ));

        let algorithm = NtsRecord::AeadAlgorithm {
            critical: true,
            algorithm_ids: vec![42],
        };

        assert!(matches!(
            roundtrip(&[algorithm]),
            Err(KeyExchangeError::NoValidAlgorithm)
        ));
    }

    #[test]
    fn no_valid_protocol() {
        let records = [
            NtsRecord::NextProtocol {
                protocol_ids: vec![1234],
            },
            NtsRecord::EndOfMessage,
        ];

        let error = roundtrip(&records).unwrap_err();

        assert!(matches!(error, KeyExchangeError::NoValidProtocol))
    }

    #[test]
    fn host_port_updates() {
        let name = String::from("ntp.time.nl");
        let port = 4567;

        let records = [
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

        let state = roundtrip(records.as_slice()).unwrap();

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

        // this succeeds on its own
        let records = [cookie.clone(), NtsRecord::EndOfMessage];

        let state = roundtrip(records.as_slice()).unwrap();
        assert_eq!(state.cookies.len(), 1);

        // still succeeds if there is a warning
        let records = [
            cookie.clone(),
            NtsRecord::Warning { warningcode: 42 },
            NtsRecord::EndOfMessage,
        ];

        let state = roundtrip(records.as_slice()).unwrap();
        assert_eq!(state.cookies.len(), 1);

        // still succeeds if there is an unknown record
        let records = [
            cookie.clone(),
            NtsRecord::Unknown {
                record_type: 8,
                critical: true,
                data: vec![1, 2, 3],
            },
            NtsRecord::EndOfMessage,
        ];

        let state = roundtrip(records.as_slice()).unwrap();
        assert_eq!(state.cookies.len(), 1);

        // fails with the expected error if there is an error record
        let records = [
            cookie.clone(),
            NtsRecord::Error { errorcode: 42 },
            NtsRecord::EndOfMessage,
        ];

        let error = roundtrip(records.as_slice()).unwrap_err();
        assert!(matches!(error, KeyExchangeError::UnknownErrorCode(42)));

        let _ = cookie;
    }

    #[test]
    fn incomplete_response() {
        let error = roundtrip(&[]).unwrap_err();
        assert!(matches!(error, KeyExchangeError::IncompleteResponse));

        // this succeeds on its own
        let records = [NtsRecord::NewCookie {
            cookie_data: EXAMPLE_COOKIE_DATA.to_vec(),
        }];

        let error = roundtrip(records.as_slice()).unwrap_err();
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
        let state = roundtrip(nts_time_nl_records().as_slice()).unwrap();

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

    fn server_roundtrip(records: &[NtsRecord]) -> Result<ServerKeyExchangeData, KeyExchangeError> {
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
    fn server_decoder_finds_algorithm() {
        let result = server_roundtrip(&NtsRecord::client_key_exchange_records()).unwrap();

        assert_eq!(result.algorithm, AeadAlgorithm::AeadAesSivCmac512);
    }

    #[test]
    fn server_decoder_ignores_new_cookie() {
        let mut records = NtsRecord::client_key_exchange_records().to_vec();
        records.insert(
            0,
            NtsRecord::NewCookie {
                cookie_data: EXAMPLE_COOKIE_DATA.to_vec(),
            },
        );

        let result = server_roundtrip(&records).unwrap();
        assert_eq!(result.algorithm, AeadAlgorithm::AeadAesSivCmac512);
    }

    #[test]
    fn server_decoder_ignores_server_and_port_preference() {
        let mut records = NtsRecord::client_key_exchange_records().to_vec();
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

        let result = server_roundtrip(&records).unwrap();
        assert_eq!(result.algorithm, AeadAlgorithm::AeadAesSivCmac512);
    }

    #[test]
    fn server_decoder_ignores_warn() {
        let mut records = NtsRecord::client_key_exchange_records().to_vec();
        records.insert(0, NtsRecord::Warning { warningcode: 42 });

        let result = server_roundtrip(&records).unwrap();
        assert_eq!(result.algorithm, AeadAlgorithm::AeadAesSivCmac512);
    }

    #[test]
    fn server_decoder_ignores_unknown() {
        let mut records = NtsRecord::client_key_exchange_records().to_vec();
        records.insert(
            0,
            NtsRecord::Unknown {
                record_type: 8,
                critical: true,
                data: vec![1, 2, 3],
            },
        );

        let result = server_roundtrip(&records).unwrap();
        assert_eq!(result.algorithm, AeadAlgorithm::AeadAesSivCmac512);
    }

    #[test]
    fn server_decoder_reports_error() {
        let mut records = NtsRecord::client_key_exchange_records().to_vec();
        records.insert(0, NtsRecord::Error { errorcode: 2 });

        let error = server_roundtrip(&records).unwrap_err();
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

        let error = server_roundtrip(&records).unwrap_err();
        assert!(matches!(error, KeyExchangeError::NoValidProtocol));
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

        let error = server_roundtrip(&records).unwrap_err();
        assert!(matches!(error, KeyExchangeError::NoValidAlgorithm));
    }

    #[test]
    fn server_decoder_incomplete_response() {
        let error = server_roundtrip(&[]).unwrap_err();
        assert!(matches!(error, KeyExchangeError::IncompleteResponse));

        let records = [
            NtsRecord::NextProtocol {
                protocol_ids: vec![0],
            },
            NtsRecord::Unknown {
                record_type: 8,
                critical: true,
                data: vec![1, 2, 3],
            },
        ];

        let error = server_roundtrip(&records).unwrap_err();
        assert!(matches!(error, KeyExchangeError::IncompleteResponse));
    }

    #[test]
    fn test_keyexchange_client() {
        let cert_chain: Vec<rustls::Certificate> =
            rustls_pemfile::certs(&mut std::io::BufReader::new(include_bytes!(
                "../../test-keys/end.fullchain.pem"
            ) as &[u8]))
            .unwrap()
            .into_iter()
            .map(rustls::Certificate)
            .collect();
        let key_der = rustls::PrivateKey(
            rustls_pemfile::pkcs8_private_keys(&mut std::io::BufReader::new(include_bytes!(
                "../../test-keys/end.key"
            )
                as &[u8]))
            .unwrap()
            .into_iter()
            .next()
            .unwrap(),
        );
        let serverconfig = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key_der)
            .unwrap();
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_parsable_certificates(
            &rustls_pemfile::certs(&mut std::io::BufReader::new(include_bytes!(
                "../../test-keys/testca.pem"
            ) as &[u8]))
            .unwrap(),
        );

        let clientconfig = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let mut server = rustls::ServerConnection::new(Arc::new(serverconfig)).unwrap();
        let mut client = KeyExchangeClient::new("localhost".into(), clientconfig).unwrap();

        server.writer().write_all(NTS_TIME_NL_RESPONSE).unwrap();

        let mut buf = [0; 4096];
        let result = 'result: loop {
            while client.wants_write() {
                let size = client.write_socket(&mut &mut buf[..]).unwrap();
                let mut offset = 0;
                while offset < size {
                    let cur = server.read_tls(&mut &buf[offset..size]).unwrap();
                    offset += cur;
                    server.process_new_packets().unwrap();
                }
            }

            while server.wants_write() {
                let size = server.write_tls(&mut &mut buf[..]).unwrap();
                let mut offset = 0;
                while offset < size {
                    let cur = client.read_socket(&mut &buf[offset..size]).unwrap();
                    offset += cur;
                    client = match client.progress() {
                        ControlFlow::Continue(client) => client,
                        ControlFlow::Break(result) => break 'result result,
                    }
                }
            }
        }
        .unwrap();

        assert_eq!(result.remote, "localhost");
        assert_eq!(result.port, 123);
    }

    fn client_server_pair() -> (KeyExchangeClient, KeyExchangeServer) {
        let cert_chain: Vec<rustls::Certificate> =
            rustls_pemfile::certs(&mut std::io::BufReader::new(include_bytes!(
                "../../test-keys/end.fullchain.pem"
            ) as &[u8]))
            .unwrap()
            .into_iter()
            .map(rustls::Certificate)
            .collect();
        let key_der = rustls::PrivateKey(
            rustls_pemfile::pkcs8_private_keys(&mut std::io::BufReader::new(include_bytes!(
                "../../test-keys/end.key"
            )
                as &[u8]))
            .unwrap()
            .into_iter()
            .next()
            .unwrap(),
        );
        let mut serverconfig = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key_der)
            .unwrap();

        serverconfig.alpn_protocols.clear();
        serverconfig.alpn_protocols.push(b"ntske/1".to_vec());

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_parsable_certificates(
            &rustls_pemfile::certs(&mut std::io::BufReader::new(include_bytes!(
                "../../test-keys/testca.pem"
            ) as &[u8]))
            .unwrap(),
        );

        let clientconfig = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let keyset = KeySetProvider::new(8).get();

        let client =
            KeyExchangeClient::new_without_tls_write("localhost".into(), clientconfig).unwrap();
        let server = KeyExchangeServer::new(Arc::new(serverconfig), keyset).unwrap();

        (client, server)
    }

    fn keyexchange_loop(
        mut client: KeyExchangeClient,
        mut server: KeyExchangeServer,
    ) -> Result<KeyExchangeResult, KeyExchangeError> {
        let mut buf = [0; 4096];

        'result: loop {
            while server.wants_write() {
                let size = server.write_socket(&mut &mut buf[..]).unwrap();
                let mut offset = 0;
                while offset < size {
                    let cur = client
                        .tls_connection
                        .read_tls(&mut &buf[offset..size])
                        .unwrap();
                    offset += cur;
                    client = match client.progress() {
                        ControlFlow::Continue(client) => client,
                        ControlFlow::Break(result) => break 'result result,
                    }
                }
            }

            'client_write: while client.wants_write() {
                let size = client.tls_connection.write_tls(&mut &mut buf[..]).unwrap();
                let mut offset = 0;
                while offset < size {
                    let cur = server.read_socket(&mut &buf[offset..size]).unwrap();
                    offset += cur;
                    match server.progress_help() {
                        ControlFlow::Continue(new) => server = new,
                        ControlFlow::Break(result) => {
                            server = result?;

                            break 'client_write;
                        }
                    }
                }
            }

            if !server.wants_write() && !client.wants_write() {
                client.tls_connection.send_close_notify();
            }
        }
    }

    #[test]
    fn test_keyexchange_roundtrip() {
        let (mut client, server) = client_server_pair();

        let mut buffer = Vec::with_capacity(1024);
        for record in NtsRecord::client_key_exchange_records() {
            record.write(&mut buffer).unwrap();
        }
        client.tls_connection.writer().write_all(&buffer).unwrap();

        let result = keyexchange_loop(client, server).unwrap();

        assert_eq!(&result.remote, "localhost");
        assert_eq!(result.port, 123);

        assert_eq!(result.nts.cookies.len(), 8);

        #[cfg(feature = "ntpv5")]
        assert_eq!(result.protocol_version, ProtocolVersion::V5);
    }

    #[test]
    fn test_keyexchange_invalid_input() {
        let mut buffer = Vec::with_capacity(1024);
        for record in NtsRecord::client_key_exchange_records() {
            record.write(&mut buffer).unwrap();
        }

        for n in 0..buffer.len() {
            let (mut client, server) = client_server_pair();
            client
                .tls_connection
                .writer()
                .write_all(&buffer[..n])
                .unwrap();

            let error = keyexchange_loop(client, server).unwrap_err();
            assert!(matches!(error, KeyExchangeError::IncompleteResponse));
        }
    }
}
