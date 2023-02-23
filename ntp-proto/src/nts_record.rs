use std::{
    io::{Read, Write},
    ops::ControlFlow,
    sync::Arc,
};

use aead::KeySizeUser;
use aes_siv::{Aes128SivAead, Aes256SivAead};

use crate::{
    cookiestash::CookieStash, packet::AesSivCmac256, packet::AesSivCmac512, peer::PeerNtsData,
    Cipher, DecodedServerCookie, KeySet,
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
            NtsRecord::Unknown { critical, .. } => *critical,
        }
    }

    fn validate(&self) -> std::io::Result<()> {
        let invalid = || {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                WriteError::Invalid,
            ))
        };

        let too_long = || {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                WriteError::TooLong,
            ))
        };

        match self {
            NtsRecord::Unknown {
                record_type, data, ..
            } => {
                if *record_type & 0x8000 != 0 {
                    return invalid();
                }
                if data.len() > u16::MAX as usize {
                    return too_long();
                }
            }
            NtsRecord::NextProtocol { protocol_ids } => {
                if protocol_ids.len() >= (u16::MAX as usize) / 2 {
                    return too_long();
                }
            }

            NtsRecord::AeadAlgorithm { algorithm_ids, .. } => {
                if algorithm_ids.len() >= (u16::MAX as usize) / 2 {
                    return too_long();
                }
            }
            NtsRecord::NewCookie { cookie_data } => {
                if cookie_data.len() > u16::MAX as usize {
                    return too_long();
                }
            }
            NtsRecord::Server { name, .. } => {
                if name.as_bytes().len() >= (u16::MAX as usize) {
                    return too_long();
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
    pub fn client_key_exchange_records() -> [NtsRecord; 3] {
        [
            NtsRecord::NextProtocol {
                protocol_ids: vec![0],
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

    pub fn server_key_exchange_records(
        algorithm: AeadAlgorithm,
        keyset: &KeySet,
        keys: NtsKeys,
    ) -> std::io::Result<[NtsRecord; 11]> {
        let cookie = DecodedServerCookie {
            algorithm,
            s2c: keys.s2c,
            c2s: keys.c2s,
        };

        let next_cookie = || -> std::io::Result<NtsRecord> {
            Ok(NtsRecord::NewCookie {
                cookie_data: keyset.encode_cookie(&cookie),
            })
        };

        Ok([
            NtsRecord::NextProtocol {
                protocol_ids: vec![0],
            },
            NtsRecord::AeadAlgorithm {
                critical: false,
                algorithm_ids: vec![algorithm as u16],
            },
            next_cookie()?,
            next_cookie()?,
            next_cookie()?,
            next_cookie()?,
            next_cookie()?,
            next_cookie()?,
            next_cookie()?,
            next_cookie()?,
            NtsRecord::EndOfMessage,
        ])
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
            _ => NtsRecord::Unknown {
                record_type,
                critical,
                data: read_bytes_exact(reader, record_len)?,
            },
        })
    }

    pub fn write<A: Write>(&self, writer: &mut A) -> std::io::Result<()> {
        // error out early when the record is invalid
        self.validate()?;

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
                #[cfg(not(feature = "fuzz"))]
                debug_assert!(name.is_ascii());
                let length = name.len() as u16;
                writer.write_all(&length.to_be_bytes())?;

                writer.write_all(name.as_bytes())?;
            }
            NtsRecord::Port { port, .. } => {
                writer.write_all(&size_of_u16.to_be_bytes())?;
                writer.write_all(&port.to_be_bytes())?;
            }
        }

        Ok(())
    }

    pub fn decoder() -> NtsRecordDecoder {
        NtsRecordDecoder { bytes: vec![] }
    }
}

#[cfg(feature = "fuzz")]
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
    DnsName(#[from] rustls::client::InvalidDnsNameError),
    #[error("Incomplete response")]
    IncompleteResponse,
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
    pub const fn c2s_context(self) -> [u8; 5] {
        // The final octet SHALL be 0x00 for the C2S key
        [0, 0, (self as u16 >> 8) as u8, self as u8, 0]
    }

    // per https://www.rfc-editor.org/rfc/rfc8915.html#section-5.1
    pub const fn s2c_context(self) -> [u8; 5] {
        // The final octet SHALL be 0x01 for the S2C key
        [0, 0, (self as u16 >> 8) as u8, self as u8, 1]
    }

    pub fn try_deserialize(number: u16) -> Option<AeadAlgorithm> {
        match number {
            15 => Some(AeadAlgorithm::AeadAesSivCmac256),
            17 => Some(AeadAlgorithm::AeadAesSivCmac512),
            _ => None,
        }
    }

    const IN_ORDER_OF_PREFERENCE: &'static [Self] =
        &[Self::AeadAesSivCmac512, Self::AeadAesSivCmac256];

    pub(crate) const fn from_u16(value: u16) -> Option<Self> {
        match value {
            15 => Some(Self::AeadAesSivCmac256),
            17 => Some(Self::AeadAesSivCmac512),
            _ => None,
        }
    }

    fn extract_nts_keys<ConnectionData>(
        &self,
        tls_connection: &rustls::ConnectionCommon<ConnectionData>,
    ) -> Result<NtsKeys, rustls::Error> {
        match self {
            AeadAlgorithm::AeadAesSivCmac256 => {
                let c2s = extract_nts_key::<Aes128SivAead, _>(tls_connection, self.c2s_context())?;
                let s2c = extract_nts_key::<Aes128SivAead, _>(tls_connection, self.s2c_context())?;

                let c2s = Box::new(AesSivCmac256::new(c2s));
                let s2c = Box::new(AesSivCmac256::new(s2c));

                Ok(NtsKeys { c2s, s2c })
            }
            AeadAlgorithm::AeadAesSivCmac512 => {
                let c2s = extract_nts_key::<Aes256SivAead, _>(tls_connection, self.c2s_context())?;
                let s2c = extract_nts_key::<Aes256SivAead, _>(tls_connection, self.s2c_context())?;

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

fn extract_nts_key<T: KeySizeUser, U>(
    tls_connection: &rustls::ConnectionCommon<U>,
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
    algorithm: Option<AeadAlgorithm>,
    cookies: CookieStash,
}

#[derive(Debug, Default)]
struct KeyExchangeResultDecoder {
    decoder: NtsRecordDecoder,
    remote: Option<String>,
    port: Option<u16>,
    algorithm: Option<AeadAlgorithm>,
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
                        algorithm: state.algorithm,
                        cookies: state.cookies,
                    }))
                }
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
                let error = match errorcode {
                    0 => UnrecognizedCriticalRecord,
                    1 => BadRequest,
                    2 => InternalServerError,
                    _ => UnknownErrorCode(errorcode),
                };

                Break(Err(error))
            }
            Warning { warningcode } => {
                tracing::warn!(warningcode, "Received key exchange warning code");

                Continue(state)
            }
            NextProtocol { protocol_ids } => {
                // NTP4 has protocol id 0, it is the only protocol we support
                const NTP4: u16 = 0;

                if !protocol_ids.contains(&NTP4) {
                    Break(Err(NoValidProtocol))
                } else {
                    Continue(state)
                }
            }
            AeadAlgorithm { algorithm_ids, .. } => {
                let selected = Algorithm::IN_ORDER_OF_PREFERENCE
                    .iter()
                    .find_map(|algo| algorithm_ids.contains(&(*algo as u16)).then_some(*algo));

                match selected {
                    None => Break(Err(NoValidAlgorithm)),
                    Some(algorithm) => {
                        state.algorithm = Some(algorithm);
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
pub struct KeyExchangeClientResult {
    pub remote: String,
    pub port: u16,
    pub nts: Box<PeerNtsData>,
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

    pub fn progress(
        mut self,
    ) -> ControlFlow<Result<KeyExchangeClientResult, KeyExchangeError>, Self> {
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
                            let algorithm = result.algorithm.unwrap_or_default();

                            tracing::info!(?algorithm, "selected AEAD algorithm");

                            let keys = match algorithm.extract_nts_keys(&self.tls_connection) {
                                Ok(keys) => keys,
                                Err(e) => return ControlFlow::Break(Err(KeyExchangeError::Tls(e))),
                            };

                            let nts = Box::new(PeerNtsData {
                                cookies: result.cookies,
                                c2s: keys.c2s,
                                s2c: keys.s2c,
                            });

                            return ControlFlow::Break(Ok(KeyExchangeClientResult {
                                remote: result.remote.unwrap_or(self.server_name),
                                port: result.port.unwrap_or(Self::NTP_DEFAULT_PORT),
                                nts,
                            }));
                        }
                        ControlFlow::Break(Err(error)) => return ControlFlow::Break(Err(error)),
                    }
                }
                Err(e) => match dbg!(e.kind()) {
                    std::io::ErrorKind::WouldBlock => return ControlFlow::Continue(self),
                    _ => return ControlFlow::Break(Err(e.into())),
                },
            }
        }
    }

    pub fn new(
        server_name: String,
        mut tls_config: rustls::ClientConfig,
    ) -> Result<Self, KeyExchangeError> {
        // Ensure we send only ntske/1 as alpn
        tls_config.alpn_protocols.clear();
        tls_config.alpn_protocols.push(b"ntske/1".to_vec());

        // TLS only works when the server name is a DNS name; an IP address does not work
        let mut tls_connection = rustls::ClientConnection::new(
            Arc::new(tls_config),
            (server_name.as_ref() as &str).try_into()?,
        )?;

        // Make the request immediately (note, this will only go out to the wire via the write functions above)
        // We use an intermediary buffer to ensure that all records are sent at once.
        // This should not be needed, but works around issues in some NTS-ke server implementations
        let mut buffer = Vec::with_capacity(1024);
        for record in NtsRecord::client_key_exchange_records() {
            record.write(&mut buffer)?;
        }
        tls_connection.writer().write_all(&buffer)?;

        Ok(KeyExchangeClient {
            tls_connection,
            decoder: KeyExchangeResultDecoder::new(),
            server_name,
        })
    }
}

#[derive(Debug, Default)]
struct KeyExchangeServerDecoder {
    decoder: NtsRecordDecoder,
    // when NTPv5 is added we also need to store the protocol id here
    /// AEAD algorithm that the client is able to use and that we support
    /// it may be that the server and client supported algorithms have no
    /// intersection!
    algorithm: AeadAlgorithm,
}

#[derive(Debug, PartialEq, Eq)]
struct ServerKeyExchangeData {
    algorithm: AeadAlgorithm,
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
                };

                Break(Ok(result))
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
                let error = match errorcode {
                    0 => UnrecognizedCriticalRecord,
                    1 => BadRequest,
                    2 => InternalServerError,
                    _ => UnknownErrorCode(errorcode),
                };

                Break(Err(error))
            }
            Warning { warningcode } => {
                tracing::warn!(warningcode, "Received key exchange warning code");

                Continue(state)
            }
            NextProtocol { protocol_ids } => {
                // NTP4 has protocol id 0, it is the only protocol we support
                const NTP4: u16 = 0;

                if !protocol_ids.contains(&NTP4) {
                    Break(Err(NoValidProtocol))
                } else {
                    Continue(state)
                }
            }
            AeadAlgorithm { algorithm_ids, .. } => {
                let selected = algorithm_ids.iter().copied().find_map(Algorithm::from_u16);

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

    fn send_response(&mut self, algorithm: AeadAlgorithm, keys: NtsKeys) -> std::io::Result<()> {
        let records = NtsRecord::server_key_exchange_records(algorithm, &self.keyset, keys)?;

        let mut buffer = Vec::with_capacity(1024);
        for record in records.into_iter() {
            record.write(&mut buffer)?;
        }

        self.tls_connection.writer().write_all(&buffer)?;
        self.tls_connection.send_close_notify();

        Ok(())
    }

    pub fn progress(mut self) -> ControlFlow<Result<Self, KeyExchangeError>, Self> {
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
                Ok(n) => match self.decoder {
                    Some(decoder) => match decoder.step_with_slice(&buf[..n]) {
                        ControlFlow::Continue(decoder) => {
                            self.decoder = Some(decoder);
                            continue;
                        }
                        ControlFlow::Break(Ok(result)) => {
                            self.decoder = None;
                            let algorithm = result.algorithm;

                            tracing::info!(?algorithm, "selected AEAD algorithm");

                            let keys = match algorithm.extract_nts_keys(&self.tls_connection) {
                                Ok(keys) => keys,
                                Err(e) => return ControlFlow::Break(Err(KeyExchangeError::Tls(e))),
                            };

                            match self.send_response(algorithm, keys) {
                                Err(e) => return ControlFlow::Break(Err(KeyExchangeError::Io(e))),
                                Ok(()) => return ControlFlow::Continue(self),
                            }
                        }
                        ControlFlow::Break(Err(error)) => return ControlFlow::Break(Err(error)),
                    },
                    None => {
                        // error ?
                        panic!()
                    }
                },
                Err(e) => match e.kind() {
                    std::io::ErrorKind::WouldBlock => return ControlFlow::Continue(self),
                    std::io::ErrorKind::UnexpectedEof if self.decoder.is_none() => {
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

#[cfg(test)]
mod test {
    use crate::KeySetProvider;

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

    fn roundtrip(records: &[NtsRecord]) -> Result<PartialKeyExchangeData, KeyExchangeError> {
        let mut decoder = KeyExchangeResultDecoder::new();

        for record in records {
            let mut buffer = Vec::with_capacity(1024);
            record.write(&mut buffer).unwrap();

            decoder = match decoder.step_with_slice(&buffer) {
                ControlFlow::Continue(decoder) => decoder,
                ControlFlow::Break(result) => return result,
            }
        }

        Err(KeyExchangeError::IncompleteResponse)
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

    #[test]
    fn server_decoder_finds_algorithm() {
        let mut bytes = Vec::with_capacity(1024);
        for record in NtsRecord::client_key_exchange_records() {
            record.write(&mut bytes).unwrap();
        }

        let mut decoder = KeyExchangeServerDecoder::new();

        let decode_output = 'b: {
            for chunk in bytes.chunks(24) {
                decoder = match decoder.step_with_slice(chunk) {
                    ControlFlow::Continue(d) => d,
                    ControlFlow::Break(done) => break 'b done,
                };
            }

            Err(KeyExchangeError::IncompleteResponse)
        };

        let result = decode_output.unwrap();

        assert_eq!(result.algorithm, AeadAlgorithm::AeadAesSivCmac512);
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

    #[test]
    fn test_keyexchange_roundtrip() {
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
        let mut server = KeyExchangeServer::new(Arc::new(serverconfig), keyset).unwrap();
        let mut client = KeyExchangeClient::new("localhost".into(), clientconfig).unwrap();

        let mut bytes = Vec::with_capacity(1024);
        for record in NtsRecord::client_key_exchange_records() {
            record.write(&mut bytes).unwrap();
        }

        client.tls_connection.writer().write_all(&bytes).unwrap();

        let mut buf = [0; 4096];
        let result = 'result: loop {
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
                    match server.progress() {
                        ControlFlow::Continue(new) => server = new,
                        ControlFlow::Break(result) => {
                            server = result.unwrap();

                            break 'client_write;
                        }
                    }
                }
            }
        }
        .unwrap();

        assert_eq!(&result.remote, "localhost");
        assert_eq!(result.port, 123);

        assert_eq!(result.nts.cookies.len(), 8);
    }
}
