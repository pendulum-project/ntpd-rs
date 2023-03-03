use std::{borrow::Cow, io::Cursor};

use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};

use crate::{
    DecodedServerCookie, KeySet, NtpClock, NtpDuration, NtpTimestamp, PollInterval, ReferenceId,
    SystemSnapshot,
};

use self::{error::ParsingError, extensionfields::ExtensionFieldData, mac::Mac};

mod crypto;
mod error;
mod extensionfields;
mod mac;

pub use crypto::{
    AesSivCmac256, AesSivCmac512, Cipher, CipherHolder, CipherProvider, DecryptError,
    EncryptionResult, NoCipher,
};
pub use error::PacketParsingError;
pub use extensionfields::ExtensionField;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NtpLeapIndicator {
    NoWarning,
    Leap61,
    Leap59,
    Unknown,
}

impl NtpLeapIndicator {
    // This function should only ever be called with 2 bit values
    // (in the least significant position)
    fn from_bits(bits: u8) -> NtpLeapIndicator {
        match bits {
            0 => NtpLeapIndicator::NoWarning,
            1 => NtpLeapIndicator::Leap61,
            2 => NtpLeapIndicator::Leap59,
            3 => NtpLeapIndicator::Unknown,
            // This function should only ever be called from the packet parser
            // with just two bits, so this really should be unreachable
            _ => unreachable!(),
        }
    }

    fn to_bits(self) -> u8 {
        match self {
            NtpLeapIndicator::NoWarning => 0,
            NtpLeapIndicator::Leap61 => 1,
            NtpLeapIndicator::Leap59 => 2,
            NtpLeapIndicator::Unknown => 3,
        }
    }

    pub fn is_synchronized(&self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NtpAssociationMode {
    Reserved,
    SymmetricActive,
    SymmetricPassive,
    Client,
    Server,
    Broadcast,
    Control,
    Private,
}

impl NtpAssociationMode {
    // This function should only ever be called with 3 bit values
    // (in the least significant position)
    fn from_bits(bits: u8) -> NtpAssociationMode {
        match bits {
            0 => NtpAssociationMode::Reserved,
            1 => NtpAssociationMode::SymmetricActive,
            2 => NtpAssociationMode::SymmetricPassive,
            3 => NtpAssociationMode::Client,
            4 => NtpAssociationMode::Server,
            5 => NtpAssociationMode::Broadcast,
            6 => NtpAssociationMode::Control,
            7 => NtpAssociationMode::Private,
            // This function should only ever be called from the packet parser
            // with just three bits, so this really should be unreachable
            _ => unreachable!(),
        }
    }

    fn to_bits(self) -> u8 {
        match self {
            NtpAssociationMode::Reserved => 0,
            NtpAssociationMode::SymmetricActive => 1,
            NtpAssociationMode::SymmetricPassive => 2,
            NtpAssociationMode::Client => 3,
            NtpAssociationMode::Server => 4,
            NtpAssociationMode::Broadcast => 5,
            NtpAssociationMode::Control => 6,
            NtpAssociationMode::Private => 7,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtpPacket<'a> {
    header: NtpHeader,
    efdata: ExtensionFieldData<'a>,
    mac: Option<Mac<'a>>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum NtpHeader {
    V3(NtpHeaderV3V4),
    V4(NtpHeaderV3V4),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct NtpHeaderV3V4 {
    leap: NtpLeapIndicator,
    mode: NtpAssociationMode,
    stratum: u8,
    poll: i8,
    precision: i8,
    root_delay: NtpDuration,
    root_dispersion: NtpDuration,
    reference_id: ReferenceId,
    reference_timestamp: NtpTimestamp,
    /// Time at the client when the request departed for the server
    origin_timestamp: NtpTimestamp,
    /// Time at the server when the request arrived from the client
    receive_timestamp: NtpTimestamp,
    /// Time at the server when the response left for the client
    transmit_timestamp: NtpTimestamp,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct RequestIdentifier {
    expected_origin_timestamp: NtpTimestamp,
    uid: Option<[u8; 32]>,
}

impl NtpHeaderV3V4 {
    const LENGTH: usize = 48;

    /// A new, empty NtpHeader
    fn new() -> Self {
        Self {
            leap: NtpLeapIndicator::NoWarning,
            mode: NtpAssociationMode::Client,
            stratum: 0,
            poll: 0,
            precision: 0,
            root_delay: NtpDuration::default(),
            root_dispersion: NtpDuration::default(),
            reference_id: ReferenceId::from_int(0),
            reference_timestamp: NtpTimestamp::default(),
            origin_timestamp: NtpTimestamp::default(),
            receive_timestamp: NtpTimestamp::default(),
            transmit_timestamp: NtpTimestamp::default(),
        }
    }

    fn deserialize(data: &[u8]) -> Result<(Self, usize), ParsingError<std::convert::Infallible>> {
        if data.len() < Self::LENGTH {
            return Err(ParsingError::IncorrectLength);
        }

        Ok((
            Self {
                leap: NtpLeapIndicator::from_bits((data[0] & 0xC0) >> 6),
                mode: NtpAssociationMode::from_bits(data[0] & 0x07),
                stratum: data[1],
                poll: data[2] as i8,
                precision: data[3] as i8,
                root_delay: NtpDuration::from_bits_short(data[4..8].try_into().unwrap()),
                root_dispersion: NtpDuration::from_bits_short(data[8..12].try_into().unwrap()),
                reference_id: ReferenceId::from_bytes(data[12..16].try_into().unwrap()),
                reference_timestamp: NtpTimestamp::from_bits(data[16..24].try_into().unwrap()),
                origin_timestamp: NtpTimestamp::from_bits(data[24..32].try_into().unwrap()),
                receive_timestamp: NtpTimestamp::from_bits(data[32..40].try_into().unwrap()),
                transmit_timestamp: NtpTimestamp::from_bits(data[40..48].try_into().unwrap()),
            },
            Self::LENGTH,
        ))
    }

    fn serialize<W: std::io::Write>(&self, w: &mut W, version: u8) -> std::io::Result<()> {
        w.write_all(&[(self.leap.to_bits() << 6) | (version << 3) | self.mode.to_bits()])?;
        w.write_all(&[self.stratum, self.poll as u8, self.precision as u8])?;
        w.write_all(&self.root_delay.to_bits_short())?;
        w.write_all(&self.root_dispersion.to_bits_short())?;
        w.write_all(&self.reference_id.to_bytes())?;
        w.write_all(&self.reference_timestamp.to_bits())?;
        w.write_all(&self.origin_timestamp.to_bits())?;
        w.write_all(&self.receive_timestamp.to_bits())?;
        w.write_all(&self.transmit_timestamp.to_bits())?;
        Ok(())
    }

    fn poll_message(poll_interval: PollInterval) -> (Self, RequestIdentifier) {
        let mut packet = Self::new();
        let poll_interval = poll_interval;
        packet.poll = poll_interval.as_log();
        packet.mode = NtpAssociationMode::Client;

        // In order to increase the entropy of the transmit timestamp
        // it is just a randomly generated timestamp.
        // We then expect to get it back identically from the remote
        // in the origin field.
        let transmit_timestamp = thread_rng().gen();
        packet.transmit_timestamp = transmit_timestamp;

        (
            packet,
            RequestIdentifier {
                expected_origin_timestamp: transmit_timestamp,
                uid: None,
            },
        )
    }

    fn timestamp_response<C: NtpClock>(
        system: &SystemSnapshot,
        input: Self,
        recv_timestamp: NtpTimestamp,
        clock: &C,
    ) -> Self {
        Self {
            mode: NtpAssociationMode::Server,
            stratum: system.stratum,
            origin_timestamp: input.transmit_timestamp,
            receive_timestamp: recv_timestamp,
            reference_id: system.reference_id,
            poll: input.poll,
            precision: system.time_snapshot.precision.log2(),
            root_delay: system.time_snapshot.root_delay,
            root_dispersion: system.time_snapshot.root_dispersion,
            // Timestamp must be last to make it as accurate as possible.
            transmit_timestamp: clock.now().expect("Failed to read time"),
            ..Self::new()
        }
    }

    fn rate_limit_response(packet_from_client: Self) -> Self {
        Self {
            mode: NtpAssociationMode::Server,
            stratum: 0, // indicates a kiss code
            reference_id: ReferenceId::KISS_RATE,
            origin_timestamp: packet_from_client.transmit_timestamp,
            ..Self::new()
        }
    }

    fn deny_response(packet_from_client: Self) -> Self {
        Self {
            mode: NtpAssociationMode::Server,
            stratum: 0, // indicates a kiss code
            reference_id: ReferenceId::KISS_DENY,
            origin_timestamp: packet_from_client.transmit_timestamp,
            ..Self::new()
        }
    }
}

impl<'a> NtpPacket<'a> {
    pub fn into_owned(self) -> NtpPacket<'static> {
        NtpPacket::<'static> {
            header: self.header,
            efdata: self.efdata.into_owned(),
            mac: self.mac.map(|v| v.into_owned()),
        }
    }

    #[allow(clippy::result_large_err)]
    pub fn deserialize(
        data: &'a [u8],
        cipher: &impl CipherProvider,
    ) -> Result<(Self, Option<DecodedServerCookie>), PacketParsingError<'a>> {
        if data.is_empty() {
            return Err(PacketParsingError::IncorrectLength);
        }

        let version = (data[0] & 0b0011_1000) >> 3;

        match version {
            3 => {
                let (header, header_size) =
                    NtpHeaderV3V4::deserialize(data).map_err(|e| e.generalize())?;
                let mac = if header_size != data.len() {
                    Some(Mac::deserialize(&data[header_size..]).map_err(|e| e.generalize())?)
                } else {
                    None
                };
                Ok((
                    NtpPacket {
                        header: NtpHeader::V3(header),
                        efdata: ExtensionFieldData::default(),
                        mac,
                    },
                    None,
                ))
            }
            4 => {
                let mut has_invalid_nts = false;

                let (header, header_size) =
                    NtpHeaderV3V4::deserialize(data).map_err(|e| e.generalize())?;
                let (efdata, header_plus_fields_len, cookie) =
                    match ExtensionFieldData::deserialize(data, header_size, cipher) {
                        Ok(v) => v,
                        Err(e) => {
                            let ret = e.get_decrypt_error()?;
                            has_invalid_nts = true;
                            (ret.0, ret.1, None)
                        }
                    };

                let mac = if header_plus_fields_len != data.len() {
                    Some(
                        Mac::deserialize(&data[header_plus_fields_len..])
                            .map_err(|e| e.generalize())?,
                    )
                } else {
                    None
                };

                if has_invalid_nts {
                    Err(ParsingError::DecryptError(NtpPacket {
                        header: NtpHeader::V4(header),
                        efdata,
                        mac,
                    }))
                } else {
                    let packet = NtpPacket {
                        header: NtpHeader::V4(header),
                        efdata,
                        mac,
                    };

                    Ok((packet, cookie))
                }
            }
            _ => Err(PacketParsingError::InvalidVersion(version)),
        }
    }

    #[cfg(test)]
    pub fn serialize_without_encryption_vec(&self) -> std::io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; 1024];
        let mut cursor = Cursor::new(buffer.as_mut_slice());

        self.serialize(&mut cursor, &NoCipher)?;

        let length = cursor.position() as usize;
        let buffer = cursor.into_inner()[..length].to_vec();

        Ok(buffer)
    }

    pub fn serialize(
        &self,
        w: &mut Cursor<&mut [u8]>,
        cipher: &(impl CipherProvider + ?Sized),
    ) -> std::io::Result<()> {
        match self.header {
            NtpHeader::V3(header) => header.serialize(w, 3)?,
            NtpHeader::V4(header) => header.serialize(w, 4)?,
        };

        match self.header {
            NtpHeader::V3(_) => { /* No extension fields in V3 */ }
            NtpHeader::V4(_) => self.efdata.serialize(w, cipher)?,
        }

        if let Some(ref mac) = self.mac {
            mac.serialize(w)?;
        }

        Ok(())
    }

    pub fn nts_poll_message(
        cookie: &'a [u8],
        new_cookies: u8,
        poll_interval: PollInterval,
    ) -> (NtpPacket<'static>, RequestIdentifier) {
        let (header, id) = NtpHeaderV3V4::poll_message(poll_interval);

        let identifier: [u8; 32] = rand::thread_rng().gen();

        let mut authenticated = vec![
            ExtensionField::UniqueIdentifier(identifier.to_vec().into()),
            ExtensionField::NtsCookie(cookie.to_vec().into()),
        ];

        for _ in 1..new_cookies {
            authenticated.push(ExtensionField::NtsCookiePlaceholder {
                cookie_length: cookie.len() as u16,
            });
        }

        (
            NtpPacket {
                header: NtpHeader::V4(header),
                efdata: ExtensionFieldData {
                    authenticated,
                    encrypted: vec![],
                    untrusted: vec![],
                },
                mac: None,
            },
            RequestIdentifier {
                uid: Some(identifier),
                ..id
            },
        )
    }

    pub fn poll_message(poll_interval: PollInterval) -> (Self, RequestIdentifier) {
        let (header, id) = NtpHeaderV3V4::poll_message(poll_interval);
        (
            NtpPacket {
                header: NtpHeader::V4(header),
                efdata: Default::default(),
                mac: None,
            },
            id,
        )
    }

    pub fn timestamp_response<C: NtpClock>(
        system: &SystemSnapshot,
        input: Self,
        recv_timestamp: NtpTimestamp,
        clock: &C,
    ) -> Self {
        match input.header {
            NtpHeader::V3(header) => NtpPacket {
                header: NtpHeader::V3(NtpHeaderV3V4::timestamp_response(
                    system,
                    header,
                    recv_timestamp,
                    clock,
                )),
                efdata: Default::default(),
                mac: None,
            },
            NtpHeader::V4(header) => NtpPacket {
                header: NtpHeader::V4(NtpHeaderV3V4::timestamp_response(
                    system,
                    header,
                    recv_timestamp,
                    clock,
                )),
                efdata: ExtensionFieldData {
                    authenticated: vec![],
                    encrypted: vec![],
                    // Ignore encrypted so as not to accidentaly leak anything
                    untrusted: input
                        .efdata
                        .untrusted
                        .into_iter()
                        .chain(input.efdata.authenticated.into_iter())
                        .filter(|ef| matches!(ef, ExtensionField::UniqueIdentifier(_)))
                        .collect(),
                },
                mac: None,
            },
        }
    }

    pub fn nts_timestamp_response<C: NtpClock>(
        system: &SystemSnapshot,
        input: Self,
        recv_timestamp: NtpTimestamp,
        clock: &C,
        cookie: &DecodedServerCookie,
        keyset: &KeySet,
    ) -> Self {
        match input.header {
            NtpHeader::V3(_) => unreachable!("NTS shouldn't work with NTPv3"),
            NtpHeader::V4(header) => NtpPacket {
                header: NtpHeader::V4(NtpHeaderV3V4::timestamp_response(
                    system,
                    header,
                    recv_timestamp,
                    clock,
                )),
                efdata: ExtensionFieldData {
                    encrypted: input
                        .efdata
                        .authenticated
                        .iter()
                        .chain(input.efdata.encrypted.iter())
                        .filter_map(|f| match f {
                            ExtensionField::NtsCookiePlaceholder { cookie_length } => {
                                let new_cookie = keyset.encode_cookie(cookie);
                                if new_cookie.len() > *cookie_length as usize {
                                    None
                                } else {
                                    Some(ExtensionField::NtsCookie(Cow::Owned(new_cookie)))
                                }
                            }
                            ExtensionField::NtsCookie(old_cookie) => {
                                let new_cookie = keyset.encode_cookie(cookie);
                                if new_cookie.len() > old_cookie.len() {
                                    None
                                } else {
                                    Some(ExtensionField::NtsCookie(Cow::Owned(new_cookie)))
                                }
                            }
                            _ => None,
                        })
                        .collect(),
                    authenticated: input
                        .efdata
                        .authenticated
                        .into_iter()
                        .filter(|ef| matches!(ef, ExtensionField::UniqueIdentifier(_)))
                        .collect(),
                    // Ignore encrypted so as not to accidentaly leak anything
                    untrusted: vec![],
                },
                mac: None,
            },
        }
    }

    pub fn rate_limit_response(packet_from_client: Self) -> Self {
        match packet_from_client.header {
            NtpHeader::V3(header) => NtpPacket {
                header: NtpHeader::V3(NtpHeaderV3V4::rate_limit_response(header)),
                efdata: Default::default(),
                mac: None,
            },
            NtpHeader::V4(header) => NtpPacket {
                header: NtpHeader::V4(NtpHeaderV3V4::rate_limit_response(header)),
                efdata: ExtensionFieldData {
                    authenticated: vec![],
                    encrypted: vec![],
                    // Ignore encrypted so as not to accidentaly leak anything
                    untrusted: packet_from_client
                        .efdata
                        .untrusted
                        .into_iter()
                        .chain(packet_from_client.efdata.authenticated.into_iter())
                        .filter(|ef| matches!(ef, ExtensionField::UniqueIdentifier(_)))
                        .collect(),
                },
                mac: None,
            },
        }
    }

    pub fn nts_rate_limit_response(packet_from_client: Self) -> Self {
        match packet_from_client.header {
            NtpHeader::V3(_) => unreachable!("NTS shouldn't work with NTPv3"),
            NtpHeader::V4(header) => NtpPacket {
                header: NtpHeader::V4(NtpHeaderV3V4::rate_limit_response(header)),
                efdata: ExtensionFieldData {
                    authenticated: packet_from_client
                        .efdata
                        .authenticated
                        .into_iter()
                        .filter(|ef| matches!(ef, ExtensionField::UniqueIdentifier(_)))
                        .collect(),
                    encrypted: vec![],
                    untrusted: vec![],
                },
                mac: None,
            },
        }
    }

    pub fn deny_response(packet_from_client: Self) -> Self {
        match packet_from_client.header {
            NtpHeader::V3(header) => NtpPacket {
                header: NtpHeader::V3(NtpHeaderV3V4::deny_response(header)),
                efdata: Default::default(),
                mac: None,
            },
            NtpHeader::V4(header) => NtpPacket {
                header: NtpHeader::V4(NtpHeaderV3V4::deny_response(header)),
                efdata: ExtensionFieldData {
                    authenticated: vec![],
                    encrypted: vec![],
                    // Ignore encrypted so as not to accidentaly leak anything
                    untrusted: packet_from_client
                        .efdata
                        .untrusted
                        .into_iter()
                        .chain(packet_from_client.efdata.authenticated.into_iter())
                        .filter(|ef| matches!(ef, ExtensionField::UniqueIdentifier(_)))
                        .collect(),
                },
                mac: None,
            },
        }
    }

    pub fn nts_deny_response(packet_from_client: Self) -> Self {
        match packet_from_client.header {
            NtpHeader::V3(_) => unreachable!("NTS shouldn't work with NTPv3"),
            NtpHeader::V4(header) => NtpPacket {
                header: NtpHeader::V4(NtpHeaderV3V4::deny_response(header)),
                efdata: ExtensionFieldData {
                    authenticated: packet_from_client
                        .efdata
                        .authenticated
                        .into_iter()
                        .filter(|ef| matches!(ef, ExtensionField::UniqueIdentifier(_)))
                        .collect(),
                    encrypted: vec![],
                    untrusted: vec![],
                },
                mac: None,
            },
        }
    }
}

impl<'a> NtpPacket<'a> {
    pub fn new_cookies<'b: 'a>(&'b self) -> impl Iterator<Item = Vec<u8>> + 'b {
        self.efdata.encrypted.iter().filter_map(|ef| match ef {
            ExtensionField::NtsCookie(cookie) => Some(cookie.to_vec()),
            _ => None,
        })
    }

    pub fn leap(&self) -> NtpLeapIndicator {
        match self.header {
            NtpHeader::V3(header) => header.leap,
            NtpHeader::V4(header) => header.leap,
        }
    }

    pub fn mode(&self) -> NtpAssociationMode {
        match self.header {
            NtpHeader::V3(header) => header.mode,
            NtpHeader::V4(header) => header.mode,
        }
    }

    pub fn stratum(&self) -> u8 {
        match self.header {
            NtpHeader::V3(header) => header.stratum,
            NtpHeader::V4(header) => header.stratum,
        }
    }

    pub fn precision(&self) -> i8 {
        match self.header {
            NtpHeader::V3(header) => header.precision,
            NtpHeader::V4(header) => header.precision,
        }
    }

    pub fn root_delay(&self) -> NtpDuration {
        match self.header {
            NtpHeader::V3(header) => header.root_delay,
            NtpHeader::V4(header) => header.root_delay,
        }
    }

    pub fn root_dispersion(&self) -> NtpDuration {
        match self.header {
            NtpHeader::V3(header) => header.root_dispersion,
            NtpHeader::V4(header) => header.root_dispersion,
        }
    }

    pub fn receive_timestamp(&self) -> NtpTimestamp {
        match self.header {
            NtpHeader::V3(header) => header.receive_timestamp,
            NtpHeader::V4(header) => header.receive_timestamp,
        }
    }

    pub fn transmit_timestamp(&self) -> NtpTimestamp {
        match self.header {
            NtpHeader::V3(header) => header.transmit_timestamp,
            NtpHeader::V4(header) => header.transmit_timestamp,
        }
    }

    pub fn reference_id(&self) -> ReferenceId {
        match self.header {
            NtpHeader::V3(header) => header.reference_id,
            NtpHeader::V4(header) => header.reference_id,
        }
    }

    pub fn is_kiss(&self) -> bool {
        match self.header {
            NtpHeader::V3(header) => header.stratum == 0,
            NtpHeader::V4(header) => header.stratum == 0,
        }
    }

    pub fn is_kiss_deny(&self) -> bool {
        self.is_kiss() && self.reference_id().is_deny()
    }

    pub fn is_kiss_rate(&self) -> bool {
        self.is_kiss() && self.reference_id().is_rate()
    }

    pub fn is_kiss_rstr(&self) -> bool {
        self.is_kiss() && self.reference_id().is_rstr()
    }

    pub fn is_kiss_ntsn(&self) -> bool {
        self.is_kiss() && self.reference_id().is_ntsn()
    }

    pub fn valid_server_response(&self, identifier: RequestIdentifier, nts_enabled: bool) -> bool {
        if let Some(uid) = identifier.uid {
            let auth = check_uid_extensionfield(self.efdata.authenticated.iter(), &uid);
            let encr = check_uid_extensionfield(self.efdata.encrypted.iter(), &uid);
            let untrusted = check_uid_extensionfield(self.efdata.untrusted.iter(), &uid);

            // we need at least one uid ef that matches, and none should contradict
            // our uid. Untrusted uids should only be considered on nts naks or
            // non-nts requests.
            let uid_ok = auth != Some(false)
                && encr != Some(false)
                && (untrusted != Some(false) || (nts_enabled && !self.is_kiss_ntsn()))
                && (auth.is_some()
                    || encr.is_some()
                    || ((!nts_enabled || self.is_kiss_ntsn()) && untrusted.is_some()));
            if !uid_ok {
                return false;
            }
        }
        match self.header {
            NtpHeader::V3(header) => {
                header.origin_timestamp == identifier.expected_origin_timestamp
            }
            NtpHeader::V4(header) => {
                header.origin_timestamp == identifier.expected_origin_timestamp
            }
        }
    }
}

// Returns whether all uid extension fields found match the given uid, or
// None if there were none.
fn check_uid_extensionfield<'a, I: IntoIterator<Item = &'a ExtensionField<'a>>>(
    iter: I,
    uid: &[u8],
) -> Option<bool> {
    let mut found_uid = false;
    for ef in iter {
        if let ExtensionField::UniqueIdentifier(pid) = ef {
            if pid.len() < uid.len() || &pid[0..uid.len()] != uid {
                return Some(false);
            }
            found_uid = true;
        }
    }
    if found_uid {
        Some(true)
    } else {
        None
    }
}

#[cfg(any(test, feature = "fuzz", feature = "ext-test"))]
impl<'a> NtpPacket<'a> {
    pub fn test() -> Self {
        Self::default()
    }

    pub fn set_mode(&mut self, mode: NtpAssociationMode) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.mode = mode,
            NtpHeader::V4(ref mut header) => header.mode = mode,
        }
    }

    pub fn set_origin_timestamp(&mut self, timestamp: NtpTimestamp) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.origin_timestamp = timestamp,
            NtpHeader::V4(ref mut header) => header.origin_timestamp = timestamp,
        }
    }

    pub fn set_transmit_timestamp(&mut self, timestamp: NtpTimestamp) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.transmit_timestamp = timestamp,
            NtpHeader::V4(ref mut header) => header.transmit_timestamp = timestamp,
        }
    }

    pub fn set_receive_timestamp(&mut self, timestamp: NtpTimestamp) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.receive_timestamp = timestamp,
            NtpHeader::V4(ref mut header) => header.receive_timestamp = timestamp,
        }
    }

    pub fn set_precision(&mut self, precision: i8) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.precision = precision,
            NtpHeader::V4(ref mut header) => header.precision = precision,
        }
    }

    pub fn set_leap(&mut self, leap: NtpLeapIndicator) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.leap = leap,
            NtpHeader::V4(ref mut header) => header.leap = leap,
        }
    }

    pub fn set_stratum(&mut self, stratum: u8) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.stratum = stratum,
            NtpHeader::V4(ref mut header) => header.stratum = stratum,
        }
    }

    pub fn set_reference_id(&mut self, reference_id: ReferenceId) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.reference_id = reference_id,
            NtpHeader::V4(ref mut header) => header.reference_id = reference_id,
        }
    }

    pub fn set_root_delay(&mut self, root_delay: NtpDuration) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.root_delay = root_delay,
            NtpHeader::V4(ref mut header) => header.root_delay = root_delay,
        }
    }

    pub fn set_root_dispersion(&mut self, root_dispersion: NtpDuration) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.root_dispersion = root_dispersion,
            NtpHeader::V4(ref mut header) => header.root_dispersion = root_dispersion,
        }
    }
}

impl<'a> Default for NtpPacket<'a> {
    fn default() -> Self {
        Self {
            header: NtpHeader::V4(NtpHeaderV3V4::new()),
            efdata: Default::default(),
            mac: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use crate::{nts_record::AeadAlgorithm, KeySetProvider, PollIntervalLimits};

    use super::*;

    #[derive(Debug, Clone)]
    struct TestClock {
        now: NtpTimestamp,
    }

    impl NtpClock for TestClock {
        type Error = std::io::Error;

        fn now(&self) -> Result<NtpTimestamp, Self::Error> {
            Ok(self.now)
        }

        fn set_frequency(&self, _freq: f64) -> Result<NtpTimestamp, Self::Error> {
            panic!("Unexpected clock steer");
        }

        fn step_clock(&self, _offset: NtpDuration) -> Result<NtpTimestamp, Self::Error> {
            panic!("Unexpected clock steer");
        }

        fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
            panic!("Unexpected clock steer");
        }

        fn enable_ntp_algorithm(&self) -> Result<(), Self::Error> {
            panic!("Unexpected clock steer");
        }

        fn ntp_algorithm_update(
            &self,
            _offset: NtpDuration,
            _poll_interval: PollInterval,
        ) -> Result<(), Self::Error> {
            panic!("Unexpected clock steer");
        }

        fn error_estimate_update(
            &self,
            _est_error: NtpDuration,
            _max_error: NtpDuration,
        ) -> Result<(), Self::Error> {
            panic!("Unexpected clock steer");
        }

        fn status_update(&self, _leap_status: NtpLeapIndicator) -> Result<(), Self::Error> {
            panic!("Unexpected clock steer");
        }
    }

    #[test]
    fn roundtrip_bitrep_leap() {
        for i in 0..4u8 {
            let a = NtpLeapIndicator::from_bits(i);
            let b = a.to_bits();
            let c = NtpLeapIndicator::from_bits(b);
            assert_eq!(i, b);
            assert_eq!(a, c);
        }
    }

    #[test]
    fn roundtrip_bitrep_mode() {
        for i in 0..8u8 {
            let a = NtpAssociationMode::from_bits(i);
            let b = a.to_bits();
            let c = NtpAssociationMode::from_bits(b);
            assert_eq!(i, b);
            assert_eq!(a, c);
        }
    }

    #[test]
    fn test_captured_client() {
        let packet = b"\x23\x02\x06\xe8\x00\x00\x03\xff\x00\x00\x03\x7d\x5e\xc6\x9f\x0f\xe5\xf6\x62\x98\x7b\x61\xb9\xaf\xe5\xf6\x63\x66\x7b\x64\x99\x5d\xe5\xf6\x63\x66\x81\x40\x55\x90\xe5\xf6\x63\xa8\x76\x1d\xde\x48";
        let reference = NtpPacket {
            header: NtpHeader::V4(NtpHeaderV3V4 {
                leap: NtpLeapIndicator::NoWarning,
                mode: NtpAssociationMode::Client,
                stratum: 2,
                poll: 6,
                precision: -24,
                root_delay: NtpDuration::from_fixed_int(1023 << 16),
                root_dispersion: NtpDuration::from_fixed_int(893 << 16),
                reference_id: ReferenceId::from_int(0x5ec69f0f),
                reference_timestamp: NtpTimestamp::from_fixed_int(0xe5f662987b61b9af),
                origin_timestamp: NtpTimestamp::from_fixed_int(0xe5f663667b64995d),
                receive_timestamp: NtpTimestamp::from_fixed_int(0xe5f6636681405590),
                transmit_timestamp: NtpTimestamp::from_fixed_int(0xe5f663a8761dde48),
            }),
            efdata: Default::default(),
            mac: None,
        };

        assert_eq!(
            reference,
            NtpPacket::deserialize(packet, &NoCipher).unwrap().0
        );
        match reference.serialize_without_encryption_vec() {
            Ok(buf) => assert_eq!(packet[..], buf[..]),
            Err(e) => panic!("{e:?}"),
        }

        let packet = b"\x1B\x02\x06\xe8\x00\x00\x03\xff\x00\x00\x03\x7d\x5e\xc6\x9f\x0f\xe5\xf6\x62\x98\x7b\x61\xb9\xaf\xe5\xf6\x63\x66\x7b\x64\x99\x5d\xe5\xf6\x63\x66\x81\x40\x55\x90\xe5\xf6\x63\xa8\x76\x1d\xde\x48";
        let reference = NtpPacket {
            header: NtpHeader::V3(NtpHeaderV3V4 {
                leap: NtpLeapIndicator::NoWarning,
                mode: NtpAssociationMode::Client,
                stratum: 2,
                poll: 6,
                precision: -24,
                root_delay: NtpDuration::from_fixed_int(1023 << 16),
                root_dispersion: NtpDuration::from_fixed_int(893 << 16),
                reference_id: ReferenceId::from_int(0x5ec69f0f),
                reference_timestamp: NtpTimestamp::from_fixed_int(0xe5f662987b61b9af),
                origin_timestamp: NtpTimestamp::from_fixed_int(0xe5f663667b64995d),
                receive_timestamp: NtpTimestamp::from_fixed_int(0xe5f6636681405590),
                transmit_timestamp: NtpTimestamp::from_fixed_int(0xe5f663a8761dde48),
            }),
            efdata: Default::default(),
            mac: None,
        };

        assert_eq!(
            reference,
            NtpPacket::deserialize(packet, &NoCipher).unwrap().0
        );
        match reference.serialize_without_encryption_vec() {
            Ok(buf) => assert_eq!(packet[..], buf[..]),
            Err(e) => panic!("{e:?}"),
        }
    }

    #[test]
    fn test_captured_server() {
        let packet = b"\x24\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
        let reference = NtpPacket {
            header: NtpHeader::V4(NtpHeaderV3V4 {
                leap: NtpLeapIndicator::NoWarning,
                mode: NtpAssociationMode::Server,
                stratum: 2,
                poll: 6,
                precision: -23,
                root_delay: NtpDuration::from_fixed_int(566 << 16),
                root_dispersion: NtpDuration::from_fixed_int(951 << 16),
                reference_id: ReferenceId::from_int(0xc035676c),
                reference_timestamp: NtpTimestamp::from_fixed_int(0xe5f661fd6f165f03),
                origin_timestamp: NtpTimestamp::from_fixed_int(0xe5f663a87619ef40),
                receive_timestamp: NtpTimestamp::from_fixed_int(0xe5f663a8798c6581),
                transmit_timestamp: NtpTimestamp::from_fixed_int(0xe5f663a8798eae2b),
            }),
            efdata: Default::default(),
            mac: None,
        };

        assert_eq!(
            reference,
            NtpPacket::deserialize(packet, &NoCipher).unwrap().0
        );
        match reference.serialize_without_encryption_vec() {
            Ok(buf) => assert_eq!(packet[..], buf[..]),
            Err(e) => panic!("{e:?}"),
        }
    }

    #[test]
    fn test_version() {
        let packet = b"\x04\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
        assert!(NtpPacket::deserialize(packet, &NoCipher).is_err());
        let packet = b"\x0B\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
        assert!(NtpPacket::deserialize(packet, &NoCipher).is_err());
        let packet = b"\x14\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
        assert!(NtpPacket::deserialize(packet, &NoCipher).is_err());
        let packet = b"\x2B\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
        assert!(NtpPacket::deserialize(packet, &NoCipher).is_err());
        let packet = b"\x34\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
        assert!(NtpPacket::deserialize(packet, &NoCipher).is_err());
        let packet = b"\x3B\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
        assert!(NtpPacket::deserialize(packet, &NoCipher).is_err());
    }

    #[test]
    fn test_packed_flags() {
        let base = b"\x24\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b".to_owned();
        let base_structured = NtpPacket::deserialize(&base, &NoCipher).unwrap().0;

        for leap_type in 0..3 {
            for mode in 0..8 {
                let mut header = base_structured.clone();
                header.set_leap(NtpLeapIndicator::from_bits(leap_type));
                header.set_mode(NtpAssociationMode::from_bits(mode));

                let data = header.serialize_without_encryption_vec().unwrap();
                let copy = NtpPacket::deserialize(&data, &NoCipher).unwrap().0;
                assert_eq!(header, copy);
            }
        }

        for i in 0..=0xFF {
            let mut packet = base;
            packet[0] = i;

            if let Ok((a, _)) = NtpPacket::deserialize(&packet, &NoCipher) {
                let b = a.serialize_without_encryption_vec().unwrap();
                assert_eq!(packet[..], b[..]);
            }
        }
    }

    #[test]
    fn test_nts_poll_message() {
        let cookie = [0; 16];
        let (packet1, ref1) =
            NtpPacket::nts_poll_message(&cookie, 1, PollIntervalLimits::default().min);
        assert_eq!(0, packet1.efdata.encrypted.len());
        assert_eq!(0, packet1.efdata.untrusted.len());
        let mut have_uid = false;
        let mut have_cookie = false;
        let mut nplaceholders = 0;
        for ef in packet1.efdata.authenticated {
            match ef {
                ExtensionField::UniqueIdentifier(uid) => {
                    assert_eq!(ref1.uid.as_ref().unwrap(), uid.as_ref());
                    assert!(!have_uid);
                    have_uid = true;
                }
                ExtensionField::NtsCookie(cookie_p) => {
                    assert_eq!(&cookie, cookie_p.as_ref());
                    assert!(!have_cookie);
                    have_cookie = true;
                }
                ExtensionField::NtsCookiePlaceholder { cookie_length } => {
                    assert_eq!(cookie_length, cookie.len() as u16);
                    nplaceholders += 1;
                }
                _ => unreachable!(),
            }
        }
        assert!(have_cookie);
        assert!(have_uid);
        assert_eq!(nplaceholders, 0);

        let (packet2, ref2) =
            NtpPacket::nts_poll_message(&cookie, 3, PollIntervalLimits::default().min);
        assert_ne!(
            ref1.expected_origin_timestamp,
            ref2.expected_origin_timestamp
        );
        assert_ne!(ref1.uid, ref2.uid);

        assert_eq!(0, packet2.efdata.encrypted.len());
        assert_eq!(0, packet2.efdata.untrusted.len());
        let mut have_uid = false;
        let mut have_cookie = false;
        let mut nplaceholders = 0;
        for ef in packet2.efdata.authenticated {
            match ef {
                ExtensionField::UniqueIdentifier(uid) => {
                    assert_eq!(ref2.uid.as_ref().unwrap(), uid.as_ref());
                    assert!(!have_uid);
                    have_uid = true;
                }
                ExtensionField::NtsCookie(cookie_p) => {
                    assert_eq!(&cookie, cookie_p.as_ref());
                    assert!(!have_cookie);
                    have_cookie = true;
                }
                ExtensionField::NtsCookiePlaceholder { cookie_length } => {
                    assert_eq!(cookie_length, cookie.len() as u16);
                    nplaceholders += 1;
                }
                _ => unreachable!(),
            }
        }
        assert!(have_cookie);
        assert!(have_uid);
        assert_eq!(nplaceholders, 2);
    }

    #[test]
    fn test_nts_response_validation() {
        let cookie = [0; 16];
        let (packet, id) =
            NtpPacket::nts_poll_message(&cookie, 0, PollIntervalLimits::default().min);
        let mut response = NtpPacket::timestamp_response(
            &SystemSnapshot::default(),
            packet,
            NtpTimestamp::from_fixed_int(0),
            &TestClock {
                now: NtpTimestamp::from_fixed_int(2),
            },
        );

        assert!(response.valid_server_response(id, false));
        assert!(!response.valid_server_response(id, true));

        response
            .efdata
            .untrusted
            .push(ExtensionField::UniqueIdentifier(Cow::Borrowed(
                id.uid.as_ref().unwrap(),
            )));

        assert!(response.valid_server_response(id, false));
        assert!(!response.valid_server_response(id, true));

        response.efdata.untrusted.clear();
        response
            .efdata
            .authenticated
            .push(ExtensionField::UniqueIdentifier(Cow::Borrowed(
                id.uid.as_ref().unwrap(),
            )));

        assert!(response.valid_server_response(id, false));
        assert!(response.valid_server_response(id, true));

        response
            .efdata
            .untrusted
            .push(ExtensionField::UniqueIdentifier(Cow::Borrowed(&[])));

        assert!(!response.valid_server_response(id, false));
        assert!(response.valid_server_response(id, true));

        response.efdata.untrusted.clear();
        response
            .efdata
            .encrypted
            .push(ExtensionField::UniqueIdentifier(Cow::Borrowed(&[])));

        assert!(!response.valid_server_response(id, false));
        assert!(!response.valid_server_response(id, true));
    }

    #[test]
    fn test_timestamp_response() {
        let decoded = DecodedServerCookie {
            algorithm: AeadAlgorithm::AeadAesSivCmac256,
            s2c: Box::new(AesSivCmac256::new((0..32_u8).collect())),
            c2s: Box::new(AesSivCmac256::new((32..64_u8).collect())),
        };
        let keysetprovider = KeySetProvider::new(1);
        let cookie = keysetprovider.get().encode_cookie(&decoded);

        let (packet, _) =
            NtpPacket::nts_poll_message(&cookie, 0, PollIntervalLimits::default().min);
        let packet_id = packet
            .efdata
            .authenticated
            .iter()
            .find_map(|f| {
                if let ExtensionField::UniqueIdentifier(id) = f {
                    Some(id.clone().into_owned())
                } else {
                    None
                }
            })
            .unwrap();
        let response = NtpPacket::timestamp_response(
            &SystemSnapshot::default(),
            packet,
            NtpTimestamp::from_fixed_int(0),
            &TestClock {
                now: NtpTimestamp::from_fixed_int(1),
            },
        );
        let response_id = response
            .efdata
            .untrusted
            .iter()
            .find_map(|f| {
                if let ExtensionField::UniqueIdentifier(id) = f {
                    Some(id.clone().into_owned())
                } else {
                    None
                }
            })
            .unwrap();
        assert_eq!(packet_id, response_id);
        assert_eq!(
            response.receive_timestamp(),
            NtpTimestamp::from_fixed_int(0)
        );
        assert_eq!(
            response.transmit_timestamp(),
            NtpTimestamp::from_fixed_int(1)
        );

        let (mut packet, _) =
            NtpPacket::nts_poll_message(&cookie, 0, PollIntervalLimits::default().min);
        std::mem::swap(
            &mut packet.efdata.authenticated,
            &mut packet.efdata.untrusted,
        );
        let packet_id = packet
            .efdata
            .untrusted
            .iter()
            .find_map(|f| {
                if let ExtensionField::UniqueIdentifier(id) = f {
                    Some(id.clone().into_owned())
                } else {
                    None
                }
            })
            .unwrap();
        let response = NtpPacket::timestamp_response(
            &SystemSnapshot::default(),
            packet,
            NtpTimestamp::from_fixed_int(0),
            &TestClock {
                now: NtpTimestamp::from_fixed_int(1),
            },
        );
        let response_id = response
            .efdata
            .untrusted
            .iter()
            .find_map(|f| {
                if let ExtensionField::UniqueIdentifier(id) = f {
                    Some(id.clone().into_owned())
                } else {
                    None
                }
            })
            .unwrap();
        assert_eq!(packet_id, response_id);
        assert_eq!(
            response.receive_timestamp(),
            NtpTimestamp::from_fixed_int(0)
        );
        assert_eq!(
            response.transmit_timestamp(),
            NtpTimestamp::from_fixed_int(1)
        );

        let (packet, _) =
            NtpPacket::nts_poll_message(&cookie, 0, PollIntervalLimits::default().min);
        let packet_id = packet
            .efdata
            .authenticated
            .iter()
            .find_map(|f| {
                if let ExtensionField::UniqueIdentifier(id) = f {
                    Some(id.clone().into_owned())
                } else {
                    None
                }
            })
            .unwrap();
        let response = NtpPacket::nts_timestamp_response(
            &SystemSnapshot::default(),
            packet,
            NtpTimestamp::from_fixed_int(0),
            &TestClock {
                now: NtpTimestamp::from_fixed_int(1),
            },
            &decoded,
            &keysetprovider.get(),
        );
        let response_id = response
            .efdata
            .authenticated
            .iter()
            .find_map(|f| {
                if let ExtensionField::UniqueIdentifier(id) = f {
                    Some(id.clone().into_owned())
                } else {
                    None
                }
            })
            .unwrap();
        assert_eq!(packet_id, response_id);
        assert_eq!(
            response.receive_timestamp(),
            NtpTimestamp::from_fixed_int(0)
        );
        assert_eq!(
            response.transmit_timestamp(),
            NtpTimestamp::from_fixed_int(1)
        );

        let (mut packet, _) =
            NtpPacket::nts_poll_message(&cookie, 0, PollIntervalLimits::default().min);
        std::mem::swap(
            &mut packet.efdata.authenticated,
            &mut packet.efdata.untrusted,
        );
        let response = NtpPacket::nts_timestamp_response(
            &SystemSnapshot::default(),
            packet,
            NtpTimestamp::from_fixed_int(0),
            &TestClock {
                now: NtpTimestamp::from_fixed_int(1),
            },
            &decoded,
            &keysetprovider.get(),
        );
        assert!(response
            .efdata
            .authenticated
            .iter()
            .find_map(|f| {
                if let ExtensionField::UniqueIdentifier(id) = f {
                    Some(id.clone().into_owned())
                } else {
                    None
                }
            })
            .is_none());
        assert_eq!(
            response.receive_timestamp(),
            NtpTimestamp::from_fixed_int(0)
        );
        assert_eq!(
            response.transmit_timestamp(),
            NtpTimestamp::from_fixed_int(1)
        );
    }

    #[test]
    fn test_timestamp_cookies() {
        let decoded = DecodedServerCookie {
            algorithm: AeadAlgorithm::AeadAesSivCmac256,
            s2c: Box::new(AesSivCmac256::new((0..32_u8).collect())),
            c2s: Box::new(AesSivCmac256::new((32..64_u8).collect())),
        };
        let keysetprovider = KeySetProvider::new(1);
        let cookie = keysetprovider.get().encode_cookie(&decoded);

        let (packet, _) =
            NtpPacket::nts_poll_message(&cookie, 1, PollIntervalLimits::default().min);
        let response = NtpPacket::nts_timestamp_response(
            &SystemSnapshot::default(),
            packet,
            NtpTimestamp::from_fixed_int(0),
            &TestClock {
                now: NtpTimestamp::from_fixed_int(1),
            },
            &decoded,
            &keysetprovider.get(),
        );
        assert_eq!(response.new_cookies().count(), 1);

        let (packet, _) =
            NtpPacket::nts_poll_message(&cookie, 2, PollIntervalLimits::default().min);
        let response = NtpPacket::nts_timestamp_response(
            &SystemSnapshot::default(),
            packet,
            NtpTimestamp::from_fixed_int(0),
            &TestClock {
                now: NtpTimestamp::from_fixed_int(1),
            },
            &decoded,
            &keysetprovider.get(),
        );
        assert_eq!(response.new_cookies().count(), 2);

        let (packet, _) =
            NtpPacket::nts_poll_message(&cookie, 3, PollIntervalLimits::default().min);
        let response = NtpPacket::nts_timestamp_response(
            &SystemSnapshot::default(),
            packet,
            NtpTimestamp::from_fixed_int(0),
            &TestClock {
                now: NtpTimestamp::from_fixed_int(1),
            },
            &decoded,
            &keysetprovider.get(),
        );
        assert_eq!(response.new_cookies().count(), 3);

        let (packet, _) =
            NtpPacket::nts_poll_message(&cookie, 4, PollIntervalLimits::default().min);
        let response = NtpPacket::nts_timestamp_response(
            &SystemSnapshot::default(),
            packet,
            NtpTimestamp::from_fixed_int(0),
            &TestClock {
                now: NtpTimestamp::from_fixed_int(1),
            },
            &decoded,
            &keysetprovider.get(),
        );
        assert_eq!(response.new_cookies().count(), 4);
    }

    #[test]
    fn test_deny_response() {
        let decoded = DecodedServerCookie {
            algorithm: AeadAlgorithm::AeadAesSivCmac256,
            s2c: Box::new(AesSivCmac256::new((0..32_u8).collect())),
            c2s: Box::new(AesSivCmac256::new((32..64_u8).collect())),
        };
        let keysetprovider = KeySetProvider::new(1);
        let cookie = keysetprovider.get().encode_cookie(&decoded);

        let (packet, _) =
            NtpPacket::nts_poll_message(&cookie, 1, PollIntervalLimits::default().min);
        let packet_id = packet
            .efdata
            .authenticated
            .iter()
            .find_map(|f| {
                if let ExtensionField::UniqueIdentifier(id) = f {
                    Some(id.clone().into_owned())
                } else {
                    None
                }
            })
            .unwrap();
        let response = NtpPacket::deny_response(packet);
        let response_id = response
            .efdata
            .untrusted
            .iter()
            .find_map(|f| {
                if let ExtensionField::UniqueIdentifier(id) = f {
                    Some(id.clone().into_owned())
                } else {
                    None
                }
            })
            .unwrap();
        assert_eq!(packet_id, response_id);
        assert_eq!(response.new_cookies().count(), 0);
        assert!(response.is_kiss_deny());

        let (mut packet, _) =
            NtpPacket::nts_poll_message(&cookie, 1, PollIntervalLimits::default().min);
        let packet_id = packet
            .efdata
            .authenticated
            .iter()
            .find_map(|f| {
                if let ExtensionField::UniqueIdentifier(id) = f {
                    Some(id.clone().into_owned())
                } else {
                    None
                }
            })
            .unwrap();
        std::mem::swap(
            &mut packet.efdata.authenticated,
            &mut packet.efdata.untrusted,
        );
        let response = NtpPacket::deny_response(packet);
        let response_id = response
            .efdata
            .untrusted
            .iter()
            .find_map(|f| {
                if let ExtensionField::UniqueIdentifier(id) = f {
                    Some(id.clone().into_owned())
                } else {
                    None
                }
            })
            .unwrap();
        assert_eq!(packet_id, response_id);
        assert_eq!(response.new_cookies().count(), 0);
        assert!(response.is_kiss_deny());

        let (packet, _) =
            NtpPacket::nts_poll_message(&cookie, 1, PollIntervalLimits::default().min);
        let packet_id = packet
            .efdata
            .authenticated
            .iter()
            .find_map(|f| {
                if let ExtensionField::UniqueIdentifier(id) = f {
                    Some(id.clone().into_owned())
                } else {
                    None
                }
            })
            .unwrap();
        let response = NtpPacket::nts_deny_response(packet);
        let response_id = response
            .efdata
            .authenticated
            .iter()
            .find_map(|f| {
                if let ExtensionField::UniqueIdentifier(id) = f {
                    Some(id.clone().into_owned())
                } else {
                    None
                }
            })
            .unwrap();
        assert_eq!(packet_id, response_id);
        assert_eq!(response.new_cookies().count(), 0);
        assert!(response.is_kiss_deny());

        let (mut packet, _) =
            NtpPacket::nts_poll_message(&cookie, 1, PollIntervalLimits::default().min);
        std::mem::swap(
            &mut packet.efdata.authenticated,
            &mut packet.efdata.untrusted,
        );
        let response = NtpPacket::nts_deny_response(packet);
        assert!(response
            .efdata
            .authenticated
            .iter()
            .find_map(|f| {
                if let ExtensionField::UniqueIdentifier(id) = f {
                    Some(id.clone().into_owned())
                } else {
                    None
                }
            })
            .is_none());
        assert_eq!(response.new_cookies().count(), 0);
        assert!(response.is_kiss_deny());
    }

    #[test]
    fn test_rate_response() {
        let decoded = DecodedServerCookie {
            algorithm: AeadAlgorithm::AeadAesSivCmac256,
            s2c: Box::new(AesSivCmac256::new((0..32_u8).collect())),
            c2s: Box::new(AesSivCmac256::new((32..64_u8).collect())),
        };
        let keysetprovider = KeySetProvider::new(1);
        let cookie = keysetprovider.get().encode_cookie(&decoded);

        let (packet, _) =
            NtpPacket::nts_poll_message(&cookie, 1, PollIntervalLimits::default().min);
        let packet_id = packet
            .efdata
            .authenticated
            .iter()
            .find_map(|f| {
                if let ExtensionField::UniqueIdentifier(id) = f {
                    Some(id.clone().into_owned())
                } else {
                    None
                }
            })
            .unwrap();
        let response = NtpPacket::rate_limit_response(packet);
        let response_id = response
            .efdata
            .untrusted
            .iter()
            .find_map(|f| {
                if let ExtensionField::UniqueIdentifier(id) = f {
                    Some(id.clone().into_owned())
                } else {
                    None
                }
            })
            .unwrap();
        assert_eq!(packet_id, response_id);
        assert_eq!(response.new_cookies().count(), 0);
        assert!(response.is_kiss_rate());

        let (mut packet, _) =
            NtpPacket::nts_poll_message(&cookie, 1, PollIntervalLimits::default().min);
        let packet_id = packet
            .efdata
            .authenticated
            .iter()
            .find_map(|f| {
                if let ExtensionField::UniqueIdentifier(id) = f {
                    Some(id.clone().into_owned())
                } else {
                    None
                }
            })
            .unwrap();
        std::mem::swap(
            &mut packet.efdata.authenticated,
            &mut packet.efdata.untrusted,
        );
        let response = NtpPacket::rate_limit_response(packet);
        let response_id = response
            .efdata
            .untrusted
            .iter()
            .find_map(|f| {
                if let ExtensionField::UniqueIdentifier(id) = f {
                    Some(id.clone().into_owned())
                } else {
                    None
                }
            })
            .unwrap();
        assert_eq!(packet_id, response_id);
        assert_eq!(response.new_cookies().count(), 0);
        assert!(response.is_kiss_rate());

        let (packet, _) =
            NtpPacket::nts_poll_message(&cookie, 1, PollIntervalLimits::default().min);
        let packet_id = packet
            .efdata
            .authenticated
            .iter()
            .find_map(|f| {
                if let ExtensionField::UniqueIdentifier(id) = f {
                    Some(id.clone().into_owned())
                } else {
                    None
                }
            })
            .unwrap();
        let response = NtpPacket::nts_rate_limit_response(packet);
        let response_id = response
            .efdata
            .authenticated
            .iter()
            .find_map(|f| {
                if let ExtensionField::UniqueIdentifier(id) = f {
                    Some(id.clone().into_owned())
                } else {
                    None
                }
            })
            .unwrap();
        assert_eq!(packet_id, response_id);
        assert_eq!(response.new_cookies().count(), 0);
        assert!(response.is_kiss_rate());

        let (mut packet, _) =
            NtpPacket::nts_poll_message(&cookie, 1, PollIntervalLimits::default().min);
        std::mem::swap(
            &mut packet.efdata.authenticated,
            &mut packet.efdata.untrusted,
        );
        let response = NtpPacket::nts_rate_limit_response(packet);
        assert!(response
            .efdata
            .authenticated
            .iter()
            .find_map(|f| {
                if let ExtensionField::UniqueIdentifier(id) = f {
                    Some(id.clone().into_owned())
                } else {
                    None
                }
            })
            .is_none());
        assert_eq!(response.new_cookies().count(), 0);
        assert!(response.is_kiss_rate());
    }

    #[test]
    fn test_new_cookies_only_from_encrypted() {
        let allowed: [u8; 16] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let disallowed: [u8; 16] = [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let packet = NtpPacket {
            header: NtpHeader::V4(NtpHeaderV3V4::poll_message(PollIntervalLimits::default().min).0),
            efdata: ExtensionFieldData {
                authenticated: vec![ExtensionField::NtsCookie(Cow::Borrowed(&disallowed))],
                encrypted: vec![ExtensionField::NtsCookie(Cow::Borrowed(&allowed))],
                untrusted: vec![ExtensionField::NtsCookie(Cow::Borrowed(&disallowed))],
            },
            mac: None,
        };

        assert_eq!(1, packet.new_cookies().count());
        for cookie in packet.new_cookies() {
            assert_eq!(&cookie, &allowed);
        }
    }

    #[test]
    fn test_undersized_ef_in_encrypted_data() {
        let cipher = AesSivCmac256::new([0_u8; 32].into());
        let packet = [
            35, 2, 6, 232, 0, 0, 3, 255, 0, 0, 3, 125, 94, 198, 159, 15, 229, 246, 98, 152, 123,
            97, 185, 175, 229, 246, 99, 102, 123, 100, 153, 93, 229, 246, 99, 102, 129, 64, 85,
            144, 229, 246, 99, 168, 118, 29, 222, 72, 4, 4, 0, 44, 0, 16, 0, 18, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 39, 24, 181, 156, 166, 35, 154, 207, 38, 150, 15, 190,
            152, 87, 142, 206, 254, 105, 0, 0,
        ];
        //should not crash
        assert!(NtpPacket::deserialize(&packet, &cipher).is_err());
    }

    #[test]
    fn test_undersized_ef() {
        let packet = [
            35, 2, 6, 232, 0, 0, 3, 255, 0, 0, 3, 125, 94, 198, 159, 15, 229, 246, 98, 152, 123,
            97, 185, 175, 229, 246, 99, 102, 123, 100, 153, 93, 229, 246, 99, 102, 129, 64, 85,
            144, 229, 246, 99, 168, 118, 29, 222, 72, 4, 4,
        ];
        //should not crash
        assert!(NtpPacket::deserialize(&packet, &NoCipher).is_err());
    }

    #[test]
    fn test_undersized_nonce() {
        let input = [
            32, 206, 206, 206, 77, 206, 206, 255, 216, 216, 216, 127, 0, 0, 0, 0, 0, 0, 0, 216,
            216, 216, 216, 206, 217, 216, 216, 216, 216, 216, 216, 206, 206, 206, 1, 0, 0, 0, 206,
            206, 206, 4, 44, 4, 4, 4, 4, 4, 4, 4, 0, 4, 206, 206, 222, 206, 206, 206, 206, 0, 0, 0,
            206, 206, 206, 0, 0, 0, 206, 206, 206, 206, 206, 206, 131, 206, 206,
        ];
        //should not crash
        assert!(NtpPacket::deserialize(&input, &NoCipher).is_err());
    }

    #[test]
    fn test_undersized_encryption_ef() {
        let input = [
            32, 206, 206, 206, 77, 206, 216, 216, 127, 3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 216, 216, 216,
            216, 206, 217, 216, 216, 216, 216, 216, 216, 206, 206, 206, 1, 0, 0, 0, 206, 206, 206,
            4, 44, 4, 4, 4, 4, 4, 4, 4, 0, 4, 4, 0, 12, 206, 206, 222, 206, 206, 206, 206, 0, 0, 0,
            12, 206, 206, 222, 206, 206, 206, 206, 206, 206, 206, 206, 131, 206, 206,
        ];
        assert!(NtpPacket::deserialize(&input, &NoCipher).is_err());
    }
}
