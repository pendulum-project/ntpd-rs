use std::{borrow::Cow, io::Cursor};

use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};

use crate::{
    clock::NtpClock,
    identifiers::ReferenceId,
    io::NonBlockingWrite,
    keyset::{DecodedServerCookie, KeySet},
    system::SystemSnapshot,
    time_types::{NtpDuration, NtpTimestamp, PollInterval},
};

use self::{error::ParsingError, extension_fields::ExtensionFieldData, mac::Mac};

mod crypto;
mod error;
mod extension_fields;
mod mac;

#[cfg(feature = "ntpv5")]
pub mod v5;

pub use crypto::{
    AesSivCmac256, AesSivCmac512, Cipher, CipherHolder, CipherProvider, DecryptError,
    EncryptResult, NoCipher,
};
pub use error::PacketParsingError;
pub use extension_fields::{ExtensionField, ExtensionHeaderVersion};

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

    #[must_use]
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
pub enum NtpHeader {
    V3(NtpHeaderV3V4),
    V4(NtpHeaderV3V4),
    #[cfg(feature = "ntpv5")]
    V5(v5::NtpHeaderV5),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct NtpHeaderV3V4 {
    leap: NtpLeapIndicator,
    mode: NtpAssociationMode,
    stratum: u8,
    poll: PollInterval,
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
    const WIRE_LENGTH: usize = 48;

    /// A new, empty `NtpHeader`
    fn new() -> Self {
        Self {
            leap: NtpLeapIndicator::NoWarning,
            mode: NtpAssociationMode::Client,
            stratum: 0,
            poll: PollInterval::from_byte(0),
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

    #[allow(clippy::cast_possible_wrap)]
    fn deserialize(data: &[u8]) -> Result<(Self, usize), ParsingError<std::convert::Infallible>> {
        if data.len() < Self::WIRE_LENGTH {
            return Err(ParsingError::IncorrectLength);
        }

        Ok((
            Self {
                leap: NtpLeapIndicator::from_bits((data[0] & 0xC0) >> 6),
                mode: NtpAssociationMode::from_bits(data[0] & 0x07),
                stratum: data[1],
                poll: PollInterval::from_byte(data[2]),
                precision: data[3] as i8,
                root_delay: NtpDuration::from_bits_short(data[4..8].try_into().unwrap()),
                root_dispersion: NtpDuration::from_bits_short(data[8..12].try_into().unwrap()),
                reference_id: ReferenceId::from_bytes(data[12..16].try_into().unwrap()),
                reference_timestamp: NtpTimestamp::from_bits(data[16..24].try_into().unwrap()),
                origin_timestamp: NtpTimestamp::from_bits(data[24..32].try_into().unwrap()),
                receive_timestamp: NtpTimestamp::from_bits(data[32..40].try_into().unwrap()),
                transmit_timestamp: NtpTimestamp::from_bits(data[40..48].try_into().unwrap()),
            },
            Self::WIRE_LENGTH,
        ))
    }

    #[allow(clippy::cast_sign_loss)]
    fn serialize(&self, mut w: impl NonBlockingWrite, version: u8) -> std::io::Result<()> {
        w.write_all(&[(self.leap.to_bits() << 6) | (version << 3) | self.mode.to_bits()])?;
        w.write_all(&[self.stratum, self.poll.as_byte(), self.precision as u8])?;
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
        packet.poll = poll_interval;
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
            leap: system.time_snapshot.leap_indicator,
            reference_timestamp: NtpTimestamp::default(),
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

    fn nts_nak_response(packet_from_client: Self) -> Self {
        Self {
            mode: NtpAssociationMode::Server,
            stratum: 0,
            reference_id: ReferenceId::KISS_NTSN,
            origin_timestamp: packet_from_client.transmit_timestamp,
            ..Self::new()
        }
    }
}

impl<'a> NtpPacket<'a> {
    #[must_use]
    pub fn into_owned(self) -> NtpPacket<'static> {
        NtpPacket::<'static> {
            header: self.header,
            efdata: self.efdata.into_owned(),
            mac: self.mac.map(mac::Mac::into_owned),
        }
    }

    /// # Errors
    ///
    /// Returns error if `data` has incorrect length.
    /// Returns error if the parsing fails.
    #[allow(clippy::result_large_err)]
    pub fn deserialize(
        data: &'a [u8],
        cipher: &(impl CipherProvider + ?Sized),
    ) -> Result<(Self, Option<DecodedServerCookie>), PacketParsingError<'a>> {
        if data.is_empty() {
            return Err(PacketParsingError::IncorrectLength);
        }

        let version = (data[0] & 0b0011_1000) >> 3;

        match version {
            3 => Self::deserialize_v3(data),
            4 => Self::deserialize_v4(data, cipher),
            #[cfg(feature = "ntpv5")]
            5 => Self::deserialize_v5(data, cipher),
            _ => Err(PacketParsingError::InvalidVersion(version)),
        }
    }

    #[allow(clippy::result_large_err)]
    fn deserialize_v3(
        data: &'a [u8],
    ) -> Result<(Self, Option<DecodedServerCookie>), PacketParsingError<'a>> {
        let (header, header_size) =
            NtpHeaderV3V4::deserialize(data).map_err(error::ParsingError::generalize)?;
        let mac = if header_size == data.len() {
            None
        } else {
            Some(Mac::deserialize(&data[header_size..]).map_err(error::ParsingError::generalize)?)
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

    #[allow(clippy::result_large_err)]
    fn deserialize_v4(
        data: &'a [u8],
        cipher: &(impl CipherProvider + ?Sized),
    ) -> Result<(Self, Option<DecodedServerCookie>), PacketParsingError<'a>> {
        let (header, header_size) =
            NtpHeaderV3V4::deserialize(data).map_err(error::ParsingError::generalize)?;

        Self::deserialize_with_extension_fields(
            data,
            header_size,
            cipher,
            ExtensionHeaderVersion::V4,
            NtpHeader::V4,
            header,
        )
    }

    #[allow(clippy::result_large_err)]
    #[cfg(feature = "ntpv5")]
    fn deserialize_v5(
        data: &'a [u8],
        cipher: &(impl CipherProvider + ?Sized),
    ) -> Result<(Self, Option<DecodedServerCookie>), PacketParsingError<'a>> {
        let (header, header_size) =
            v5::NtpHeaderV5::deserialize(data).map_err(error::ParsingError::generalize)?;

        // TODO: Check extension field handling in V5
        let (packet, cookie) = Self::deserialize_with_extension_fields(
            data,
            header_size,
            cipher,
            ExtensionHeaderVersion::V5,
            NtpHeader::V5,
            header,
        )?;

        match packet.draft_id() {
            Some(id) if id == v5::DRAFT_VERSION => Ok((packet, cookie)),
            received @ (Some(_) | None) => {
                tracing::error!(
                    expected = v5::DRAFT_VERSION,
                    received,
                    "Mismatched draft ID ignoring packet!"
                );
                Err(PacketParsingError::V5(
                    v5::V5Error::InvalidDraftIdentification,
                ))
            }
        }
    }

    #[allow(clippy::result_large_err)]
    fn deserialize_with_extension_fields<H, F>(
        data: &'a [u8],
        header_size: usize,
        cipher: &(impl CipherProvider + ?Sized),
        extension_header_version: ExtensionHeaderVersion,
        header_constructor: F,
        header: H,
    ) -> Result<(Self, Option<DecodedServerCookie>), PacketParsingError<'a>>
    where
        F: Fn(H) -> NtpHeader,
    {
        let construct_packet = |remaining_bytes: &'a [u8], efdata| {
            let mac = if remaining_bytes.is_empty() {
                None
            } else {
                Some(Mac::deserialize(remaining_bytes)?)
            };

            let packet = NtpPacket {
                header: header_constructor(header),
                efdata,
                mac,
            };

            Ok::<_, ParsingError<std::convert::Infallible>>(packet)
        };

        match ExtensionFieldData::deserialize(data, header_size, cipher, extension_header_version) {
            Ok(decoded) => {
                let packet = construct_packet(decoded.remaining_bytes, decoded.efdata)
                    .map_err(error::ParsingError::generalize)?;

                Ok((packet, decoded.cookie))
            }
            Err(e) => {
                // return early if it is anything but a decrypt error
                let invalid = e.get_decrypt_error()?;

                let packet = construct_packet(invalid.remaining_bytes, invalid.efdata)
                    .map_err(error::ParsingError::generalize)?;

                Err(ParsingError::DecryptError(packet))
            }
        }
    }

    #[allow(clippy::missing_errors_doc)]
    #[allow(clippy::cast_possible_truncation)]
    #[cfg(test)]
    pub fn serialize_without_encryption_vec(
        &self,
        #[cfg_attr(not(feature = "ntpv5"), allow(unused_variables))] desired_size: Option<usize>,
    ) -> std::io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; 1024];
        let mut cursor = Cursor::new(buffer.as_mut_slice());

        self.serialize(&mut cursor, &NoCipher, desired_size)?;

        let length = cursor.position() as usize;
        let buffer = cursor.into_inner()[..length].to_vec();

        Ok(buffer)
    }

    /// # Errors
    ///
    /// Returns error if the serialization fails.
    #[allow(clippy::cast_possible_truncation)]
    pub fn serialize(
        &self,
        w: &mut Cursor<&mut [u8]>,
        cipher: &(impl CipherProvider + ?Sized),
        #[cfg_attr(not(feature = "ntpv5"), allow(unused_variables))] desired_size: Option<usize>,
    ) -> std::io::Result<()> {
        #[cfg(feature = "ntpv5")]
        let start = w.position();

        match self.header {
            NtpHeader::V3(header) => header.serialize(&mut *w, 3)?,
            NtpHeader::V4(header) => header.serialize(&mut *w, 4)?,
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(header) => header.serialize(&mut *w)?,
        };

        match self.header {
            NtpHeader::V3(_) => { /* No extension fields in V3 */ }
            NtpHeader::V4(_) => {
                self.efdata
                    .serialize(&mut *w, cipher, ExtensionHeaderVersion::V4)?;
            }
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(_) => {
                self.efdata
                    .serialize(&mut *w, cipher, ExtensionHeaderVersion::V5)?;
            }
        }

        if let Some(ref mac) = self.mac {
            mac.serialize(&mut *w)?;
        }

        #[cfg(feature = "ntpv5")]
        if let Some(desired_size) = desired_size {
            let written = (w.position() - start) as usize;
            if desired_size > written {
                ExtensionField::Padding(desired_size - written).serialize(
                    w,
                    4,
                    ExtensionHeaderVersion::V5,
                )?;
            }
        }

        Ok(())
    }

    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
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

    #[allow(clippy::cast_possible_truncation)]
    #[cfg(feature = "ntpv5")]
    #[must_use]
    pub fn nts_poll_message_v5(
        cookie: &'a [u8],
        new_cookies: u8,
        poll_interval: PollInterval,
    ) -> (NtpPacket<'static>, RequestIdentifier) {
        let (header, id) = v5::NtpHeaderV5::poll_message(poll_interval);

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

        let draft_id = ExtensionField::DraftIdentification(Cow::Borrowed(v5::DRAFT_VERSION));
        authenticated.push(draft_id);

        (
            NtpPacket {
                header: NtpHeader::V5(header),
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

    #[must_use]
    pub fn poll_message(poll_interval: PollInterval) -> (Self, RequestIdentifier) {
        let (header, id) = NtpHeaderV3V4::poll_message(poll_interval);
        (
            NtpPacket {
                header: NtpHeader::V4(header),
                efdata: ExtensionFieldData::default(),
                mac: None,
            },
            id,
        )
    }

    #[cfg(feature = "ntpv5")]
    #[must_use]
    pub fn poll_message_upgrade_request(poll_interval: PollInterval) -> (Self, RequestIdentifier) {
        let (mut header, id) = NtpHeaderV3V4::poll_message(poll_interval);

        header.reference_timestamp = v5::UPGRADE_TIMESTAMP;

        (
            NtpPacket {
                header: NtpHeader::V4(header),
                efdata: ExtensionFieldData {
                    authenticated: vec![],
                    encrypted: vec![],
                    untrusted: vec![],
                },
                mac: None,
            },
            id,
        )
    }

    #[cfg(feature = "ntpv5")]
    #[must_use]
    pub fn poll_message_v5(poll_interval: PollInterval) -> (Self, RequestIdentifier) {
        let (header, id) = v5::NtpHeaderV5::poll_message(poll_interval);

        let draft_id = ExtensionField::DraftIdentification(Cow::Borrowed(v5::DRAFT_VERSION));

        (
            NtpPacket {
                header: NtpHeader::V5(header),
                efdata: ExtensionFieldData {
                    authenticated: vec![],
                    encrypted: vec![],
                    untrusted: vec![draft_id],
                },
                mac: None,
            },
            id,
        )
    }

    #[cfg_attr(not(feature = "ntpv5"), allow(unused_mut))]
    pub fn timestamp_response<C: NtpClock>(
        system: &SystemSnapshot,
        input: Self,
        recv_timestamp: NtpTimestamp,
        clock: &C,
    ) -> Self {
        match &input.header {
            NtpHeader::V3(header) => NtpPacket {
                header: NtpHeader::V3(NtpHeaderV3V4::timestamp_response(
                    system,
                    *header,
                    recv_timestamp,
                    clock,
                )),
                efdata: ExtensionFieldData::default(),
                mac: None,
            },
            NtpHeader::V4(header) => {
                let mut response_header =
                    NtpHeaderV3V4::timestamp_response(system, *header, recv_timestamp, clock);

                #[cfg(feature = "ntpv5")]
                {
                    // Respond with the upgrade timestamp (NTP5NTP5) iff the input had it and the packet
                    // had the correct draft identification
                    if header.reference_timestamp == v5::UPGRADE_TIMESTAMP {
                        response_header.reference_timestamp = v5::UPGRADE_TIMESTAMP;
                    };
                }

                NtpPacket {
                    header: NtpHeader::V4(response_header),
                    efdata: ExtensionFieldData {
                        authenticated: vec![],
                        encrypted: vec![],
                        // Ignore encrypted so as not to accidentally leak anything
                        untrusted: input
                            .efdata
                            .untrusted
                            .into_iter()
                            .chain(input.efdata.authenticated)
                            .filter(|ef| matches!(ef, ExtensionField::UniqueIdentifier(_)))
                            .collect(),
                    },
                    mac: None,
                }
            }
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(header) => NtpPacket {
                // TODO deduplicate extension handling with V4
                header: NtpHeader::V5(v5::NtpHeaderV5::timestamp_response(
                    system,
                    *header,
                    recv_timestamp,
                    clock,
                )),
                efdata: ExtensionFieldData {
                    authenticated: vec![],
                    encrypted: vec![],
                    // Ignore encrypted so as not to accidentally leak anything
                    untrusted: input
                        .efdata
                        .untrusted
                        .into_iter()
                        .chain(input.efdata.authenticated)
                        .filter_map(|ef| match ef {
                            uid @ ExtensionField::UniqueIdentifier(_) => Some(uid),
                            ExtensionField::ReferenceIdRequest(req) => {
                                let response = req.to_response(&system.bloom_filter)?;
                                Some(ExtensionField::ReferenceIdResponse(response).into_owned())
                            }
                            _ => None,
                        })
                        .chain(std::iter::once(ExtensionField::DraftIdentification(
                            Cow::Borrowed(v5::DRAFT_VERSION),
                        )))
                        .collect(),
                },
                mac: None,
            },
        }
    }

    #[cfg(feature = "ntpv5")]
    fn draft_id(&self) -> Option<&'_ str> {
        self.efdata
            .untrusted
            .iter()
            .chain(self.efdata.authenticated.iter())
            .find_map(|ef| match ef {
                ExtensionField::DraftIdentification(id) => Some(&**id),
                _ => None,
            })
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
                    // Ignore encrypted so as not to accidentally leak anything
                    untrusted: vec![],
                },
                mac: None,
            },
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(header) => NtpPacket {
                header: NtpHeader::V5(v5::NtpHeaderV5::timestamp_response(
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
                        .filter_map(|ef| match ef {
                            uid @ ExtensionField::UniqueIdentifier(_) => Some(uid),
                            ExtensionField::ReferenceIdRequest(req) => {
                                let response = req.to_response(&system.bloom_filter)?;
                                Some(ExtensionField::ReferenceIdResponse(response).into_owned())
                            }
                            _ => None,
                        })
                        .chain(std::iter::once(ExtensionField::DraftIdentification(
                            Cow::Borrowed(v5::DRAFT_VERSION),
                        )))
                        .collect(),
                    untrusted: vec![],
                },
                mac: None,
            },
        }
    }

    #[must_use]
    pub fn rate_limit_response(packet_from_client: Self) -> Self {
        match packet_from_client.header {
            NtpHeader::V3(header) => NtpPacket {
                header: NtpHeader::V3(NtpHeaderV3V4::rate_limit_response(header)),
                efdata: ExtensionFieldData::default(),
                mac: None,
            },
            NtpHeader::V4(header) => NtpPacket {
                header: NtpHeader::V4(NtpHeaderV3V4::rate_limit_response(header)),
                efdata: ExtensionFieldData {
                    authenticated: vec![],
                    encrypted: vec![],
                    // Ignore encrypted so as not to accidentally leak anything
                    untrusted: packet_from_client
                        .efdata
                        .untrusted
                        .into_iter()
                        .chain(packet_from_client.efdata.authenticated)
                        .filter(|ef| matches!(ef, ExtensionField::UniqueIdentifier(_)))
                        .collect(),
                },
                mac: None,
            },
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(header) => NtpPacket {
                header: NtpHeader::V5(v5::NtpHeaderV5::rate_limit_response(header)),
                efdata: ExtensionFieldData {
                    authenticated: vec![],
                    encrypted: vec![],
                    // Ignore encrypted so as not to accidentally leak anything
                    untrusted: packet_from_client
                        .efdata
                        .untrusted
                        .into_iter()
                        .chain(packet_from_client.efdata.authenticated)
                        .filter(|ef| matches!(ef, ExtensionField::UniqueIdentifier(_)))
                        .chain(std::iter::once(ExtensionField::DraftIdentification(
                            Cow::Borrowed(v5::DRAFT_VERSION),
                        )))
                        .collect(),
                },
                mac: None,
            },
        }
    }

    #[must_use]
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
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(header) => NtpPacket {
                header: NtpHeader::V5(v5::NtpHeaderV5::rate_limit_response(header)),
                efdata: ExtensionFieldData {
                    authenticated: packet_from_client
                        .efdata
                        .authenticated
                        .into_iter()
                        .filter(|ef| matches!(ef, ExtensionField::UniqueIdentifier(_)))
                        .chain(std::iter::once(ExtensionField::DraftIdentification(
                            Cow::Borrowed(v5::DRAFT_VERSION),
                        )))
                        .collect(),
                    encrypted: vec![],
                    untrusted: vec![],
                },
                mac: None,
            },
        }
    }

    #[must_use]
    pub fn deny_response(packet_from_client: Self) -> Self {
        match packet_from_client.header {
            NtpHeader::V3(header) => NtpPacket {
                header: NtpHeader::V3(NtpHeaderV3V4::deny_response(header)),
                efdata: ExtensionFieldData::default(),
                mac: None,
            },
            NtpHeader::V4(header) => NtpPacket {
                header: NtpHeader::V4(NtpHeaderV3V4::deny_response(header)),
                efdata: ExtensionFieldData {
                    authenticated: vec![],
                    encrypted: vec![],
                    // Ignore encrypted so as not to accidentally leak anything
                    untrusted: packet_from_client
                        .efdata
                        .untrusted
                        .into_iter()
                        .chain(packet_from_client.efdata.authenticated)
                        .filter(|ef| matches!(ef, ExtensionField::UniqueIdentifier(_)))
                        .collect(),
                },
                mac: None,
            },
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(header) => NtpPacket {
                header: NtpHeader::V5(v5::NtpHeaderV5::deny_response(header)),
                efdata: ExtensionFieldData {
                    authenticated: vec![],
                    encrypted: vec![],
                    // Ignore encrypted so as not to accidentally leak anything
                    untrusted: packet_from_client
                        .efdata
                        .untrusted
                        .into_iter()
                        .chain(packet_from_client.efdata.authenticated)
                        .filter(|ef| matches!(ef, ExtensionField::UniqueIdentifier(_)))
                        .chain(std::iter::once(ExtensionField::DraftIdentification(
                            Cow::Borrowed(v5::DRAFT_VERSION),
                        )))
                        .collect(),
                },
                mac: None,
            },
        }
    }

    #[must_use]
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
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(header) => NtpPacket {
                header: NtpHeader::V5(v5::NtpHeaderV5::deny_response(header)),
                efdata: ExtensionFieldData {
                    authenticated: packet_from_client
                        .efdata
                        .authenticated
                        .into_iter()
                        .filter(|ef| matches!(ef, ExtensionField::UniqueIdentifier(_)))
                        .chain(std::iter::once(ExtensionField::DraftIdentification(
                            Cow::Borrowed(v5::DRAFT_VERSION),
                        )))
                        .collect(),
                    encrypted: vec![],
                    untrusted: vec![],
                },
                mac: None,
            },
        }
    }

    #[must_use]
    pub fn nts_nak_response(packet_from_client: Self) -> Self {
        match packet_from_client.header {
            NtpHeader::V3(_) => unreachable!("NTS shouldn't work with NTPv3"),
            NtpHeader::V4(header) => NtpPacket {
                header: NtpHeader::V4(NtpHeaderV3V4::nts_nak_response(header)),
                efdata: ExtensionFieldData {
                    authenticated: vec![],
                    encrypted: vec![],
                    untrusted: packet_from_client
                        .efdata
                        .untrusted
                        .into_iter()
                        .chain(packet_from_client.efdata.authenticated)
                        .filter(|ef| matches!(ef, ExtensionField::UniqueIdentifier(_)))
                        .collect(),
                },
                mac: None,
            },
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(header) => NtpPacket {
                header: NtpHeader::V5(v5::NtpHeaderV5::nts_nak_response(header)),
                efdata: ExtensionFieldData {
                    authenticated: vec![],
                    encrypted: vec![],
                    untrusted: packet_from_client
                        .efdata
                        .untrusted
                        .into_iter()
                        .chain(packet_from_client.efdata.authenticated)
                        .filter(|ef| matches!(ef, ExtensionField::UniqueIdentifier(_)))
                        .chain(std::iter::once(ExtensionField::DraftIdentification(
                            Cow::Borrowed(v5::DRAFT_VERSION),
                        )))
                        .collect(),
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

    #[must_use]
    pub fn version(&self) -> u8 {
        match self.header {
            NtpHeader::V3(_) => 3,
            NtpHeader::V4(_) => 4,
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(_) => 5,
        }
    }

    #[must_use]
    pub fn header(&self) -> NtpHeader {
        self.header
    }

    #[must_use]
    pub fn leap(&self) -> NtpLeapIndicator {
        match self.header {
            NtpHeader::V3(header) => header.leap,
            NtpHeader::V4(header) => header.leap,
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(header) => header.leap,
        }
    }

    #[must_use]
    pub fn mode(&self) -> NtpAssociationMode {
        match self.header {
            NtpHeader::V3(header) => header.mode,
            NtpHeader::V4(header) => header.mode,

            // FIXME long term the return type should change to capture both mode types
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(header) => match header.mode {
                v5::NtpMode::Request => NtpAssociationMode::Client,
                v5::NtpMode::Response => NtpAssociationMode::Server,
            },
        }
    }

    #[must_use]
    pub fn poll(&self) -> PollInterval {
        match self.header {
            NtpHeader::V3(h) | NtpHeader::V4(h) => h.poll,
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(h) => h.poll,
        }
    }

    #[must_use]
    pub fn stratum(&self) -> u8 {
        match self.header {
            NtpHeader::V3(header) => header.stratum,
            NtpHeader::V4(header) => header.stratum,
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(header) => header.stratum,
        }
    }

    #[must_use]
    pub fn precision(&self) -> i8 {
        match self.header {
            NtpHeader::V3(header) => header.precision,
            NtpHeader::V4(header) => header.precision,
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(header) => header.precision,
        }
    }

    #[must_use]
    pub fn root_delay(&self) -> NtpDuration {
        match self.header {
            NtpHeader::V3(header) => header.root_delay,
            NtpHeader::V4(header) => header.root_delay,
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(header) => header.root_delay,
        }
    }

    #[must_use]
    pub fn root_dispersion(&self) -> NtpDuration {
        match self.header {
            NtpHeader::V3(header) => header.root_dispersion,
            NtpHeader::V4(header) => header.root_dispersion,
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(header) => header.root_dispersion,
        }
    }

    #[must_use]
    pub fn receive_timestamp(&self) -> NtpTimestamp {
        match self.header {
            NtpHeader::V3(header) => header.receive_timestamp,
            NtpHeader::V4(header) => header.receive_timestamp,
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(header) => header.receive_timestamp,
        }
    }

    #[must_use]
    pub fn transmit_timestamp(&self) -> NtpTimestamp {
        match self.header {
            NtpHeader::V3(header) => header.transmit_timestamp,
            NtpHeader::V4(header) => header.transmit_timestamp,
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(header) => header.transmit_timestamp,
        }
    }

    #[must_use]
    pub fn reference_id(&self) -> ReferenceId {
        match self.header {
            NtpHeader::V3(header) => header.reference_id,
            NtpHeader::V4(header) => header.reference_id,
            #[cfg(feature = "ntpv5")]
            // TODO NTPv5 does not have reference IDs so this should always be None for now
            NtpHeader::V5(_header) => ReferenceId::NONE,
        }
    }

    fn kiss_code(&self) -> ReferenceId {
        match self.header {
            NtpHeader::V3(header) => header.reference_id,
            NtpHeader::V4(header) => header.reference_id,
            #[cfg(feature = "ntpv5")]
            // Kiss code in ntpv5 is the first four bytes of the server cookie
            NtpHeader::V5(header) => {
                ReferenceId::from_bytes(header.server_cookie.0[..4].try_into().unwrap())
            }
        }
    }

    #[must_use]
    pub fn is_kiss(&self) -> bool {
        match self.header {
            NtpHeader::V3(header) => header.stratum == 0,
            NtpHeader::V4(header) => header.stratum == 0,
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(header) => header.stratum == 0,
        }
    }

    #[must_use]
    pub fn is_kiss_deny(&self) -> bool {
        self.is_kiss()
            && match self.header {
                NtpHeader::V3(_) | NtpHeader::V4(_) => self.kiss_code().is_deny(),
                #[cfg(feature = "ntpv5")]
                NtpHeader::V5(header) => header.poll == PollInterval::NEVER,
            }
    }

    #[must_use]
    pub fn is_kiss_rate(
        &self,
        #[cfg_attr(not(feature = "ntpv5"), allow(unused))] own_interval: PollInterval,
    ) -> bool {
        self.is_kiss()
            && match self.header {
                NtpHeader::V3(_) | NtpHeader::V4(_) => self.kiss_code().is_rate(),
                #[cfg(feature = "ntpv5")]
                NtpHeader::V5(header) => {
                    header.poll > own_interval && header.poll != PollInterval::NEVER
                }
            }
    }

    #[must_use]
    pub fn is_kiss_rstr(&self) -> bool {
        self.is_kiss()
            && match self.header {
                NtpHeader::V3(_) | NtpHeader::V4(_) => self.kiss_code().is_rstr(),
                #[cfg(feature = "ntpv5")]
                NtpHeader::V5(_) => false,
            }
    }

    #[must_use]
    pub fn is_kiss_ntsn(&self) -> bool {
        self.is_kiss()
            && match self.header {
                NtpHeader::V3(_) | NtpHeader::V4(_) => self.kiss_code().is_ntsn(),
                #[cfg(feature = "ntpv5")]
                NtpHeader::V5(header) => header.flags.authnak,
            }
    }

    #[cfg(feature = "ntpv5")]
    #[must_use]
    pub fn is_upgrade(&self) -> bool {
        matches!(
            self.header,
            NtpHeader::V4(NtpHeaderV3V4 {
                reference_timestamp: v5::UPGRADE_TIMESTAMP,
                ..
            }),
        )
    }

    #[must_use]
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
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(header) => {
                header.client_cookie
                    == v5::NtpClientCookie::from_ntp_timestamp(identifier.expected_origin_timestamp)
            }
        }
    }

    pub fn untrusted_extension_fields(&self) -> impl Iterator<Item = &ExtensionField> {
        self.efdata.untrusted.iter()
    }

    pub fn authenticated_extension_fields(&self) -> impl Iterator<Item = &ExtensionField> {
        self.efdata.authenticated.iter()
    }

    pub fn push_additional(&mut self, ef: ExtensionField<'static>) {
        if !self.efdata.authenticated.is_empty() || !self.efdata.encrypted.is_empty() {
            self.efdata.authenticated.push(ef);
        } else {
            self.efdata.untrusted.push(ef);
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

#[cfg(any(test, feature = "__internal-fuzz", feature = "__internal-test"))]
impl<'a> NtpPacket<'a> {
    #[must_use]
    pub fn test() -> Self {
        Self::default()
    }

    pub fn set_mode(&mut self, mode: NtpAssociationMode) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.mode = mode,
            NtpHeader::V4(ref mut header) => header.mode = mode,
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(ref mut header) => {
                header.mode = match mode {
                    NtpAssociationMode::Client => v5::NtpMode::Request,
                    NtpAssociationMode::Server => v5::NtpMode::Response,
                    _ => todo!("NTPv5 can only handle client-server"),
                }
            }
        }
    }

    pub fn set_origin_timestamp(&mut self, timestamp: NtpTimestamp) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.origin_timestamp = timestamp,
            NtpHeader::V4(ref mut header) => header.origin_timestamp = timestamp,
            #[cfg(feature = "ntpv5")]
            // TODO can we just reuse the cookie as the origin timestamp?
            NtpHeader::V5(ref mut header) => {
                header.client_cookie = v5::NtpClientCookie::from_ntp_timestamp(timestamp);
            }
        }
    }

    pub fn set_transmit_timestamp(&mut self, timestamp: NtpTimestamp) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.transmit_timestamp = timestamp,
            NtpHeader::V4(ref mut header) => header.transmit_timestamp = timestamp,
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(ref mut header) => header.transmit_timestamp = timestamp,
        }
    }

    pub fn set_receive_timestamp(&mut self, timestamp: NtpTimestamp) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.receive_timestamp = timestamp,
            NtpHeader::V4(ref mut header) => header.receive_timestamp = timestamp,
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(ref mut header) => header.receive_timestamp = timestamp,
        }
    }

    pub fn set_precision(&mut self, precision: i8) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.precision = precision,
            NtpHeader::V4(ref mut header) => header.precision = precision,
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(ref mut header) => header.precision = precision,
        }
    }

    pub fn set_leap(&mut self, leap: NtpLeapIndicator) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.leap = leap,
            NtpHeader::V4(ref mut header) => header.leap = leap,
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(ref mut header) => header.leap = leap,
        }
    }

    pub fn set_stratum(&mut self, stratum: u8) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.stratum = stratum,
            NtpHeader::V4(ref mut header) => header.stratum = stratum,
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(ref mut header) => header.stratum = stratum,
        }
    }

    pub fn set_reference_id(&mut self, reference_id: ReferenceId) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.reference_id = reference_id,
            NtpHeader::V4(ref mut header) => header.reference_id = reference_id,
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(_header) => todo!("NTPv5 does not have reference IDs"),
        }
    }

    pub fn set_root_delay(&mut self, root_delay: NtpDuration) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.root_delay = root_delay,
            NtpHeader::V4(ref mut header) => header.root_delay = root_delay,
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(ref mut header) => header.root_delay = root_delay,
        }
    }

    pub fn set_root_dispersion(&mut self, root_dispersion: NtpDuration) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.root_dispersion = root_dispersion,
            NtpHeader::V4(ref mut header) => header.root_dispersion = root_dispersion,
            #[cfg(feature = "ntpv5")]
            NtpHeader::V5(ref mut header) => header.root_dispersion = root_dispersion,
        }
    }
}

impl<'a> Default for NtpPacket<'a> {
    fn default() -> Self {
        Self {
            header: NtpHeader::V4(NtpHeaderV3V4::new()),
            efdata: ExtensionFieldData::default(),
            mac: None,
        }
    }
}

#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::too_many_lines)]
#[cfg(test)]
mod tests {
    use crate::{
        keyset::KeySetProvider, nts_record::AeadAlgorithm, system::TimeSnapshot,
        time_types::PollIntervalLimits,
    };

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

        fn get_frequency(&self) -> Result<f64, Self::Error> {
            Ok(0.0)
        }

        fn step_clock(&self, _offset: NtpDuration) -> Result<NtpTimestamp, Self::Error> {
            panic!("Unexpected clock steer");
        }

        fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
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
                poll: PollInterval::from_byte(6),
                precision: -24,
                root_delay: NtpDuration::from_fixed_int(1023 << 16),
                root_dispersion: NtpDuration::from_fixed_int(893 << 16),
                reference_id: ReferenceId::from_int(0x5ec6_9f0f),
                reference_timestamp: NtpTimestamp::from_fixed_int(0xe5f6_6298_7b61_b9af),
                origin_timestamp: NtpTimestamp::from_fixed_int(0xe5f6_6366_7b64_995d),
                receive_timestamp: NtpTimestamp::from_fixed_int(0xe5f6_6366_8140_5590),
                transmit_timestamp: NtpTimestamp::from_fixed_int(0xe5f6_63a8_761d_de48),
            }),
            efdata: ExtensionFieldData::default(),
            mac: None,
        };

        assert_eq!(
            reference,
            NtpPacket::deserialize(packet, &NoCipher).unwrap().0
        );
        match reference.serialize_without_encryption_vec(None) {
            Ok(buf) => assert_eq!(packet[..], buf[..]),
            Err(e) => panic!("{e:?}"),
        }

        let packet = b"\x1B\x02\x06\xe8\x00\x00\x03\xff\x00\x00\x03\x7d\x5e\xc6\x9f\x0f\xe5\xf6\x62\x98\x7b\x61\xb9\xaf\xe5\xf6\x63\x66\x7b\x64\x99\x5d\xe5\xf6\x63\x66\x81\x40\x55\x90\xe5\xf6\x63\xa8\x76\x1d\xde\x48";
        let reference = NtpPacket {
            header: NtpHeader::V3(NtpHeaderV3V4 {
                leap: NtpLeapIndicator::NoWarning,
                mode: NtpAssociationMode::Client,
                stratum: 2,
                poll: PollInterval::from_byte(6),
                precision: -24,
                root_delay: NtpDuration::from_fixed_int(1023 << 16),
                root_dispersion: NtpDuration::from_fixed_int(893 << 16),
                reference_id: ReferenceId::from_int(0x5ec6_9f0f),
                reference_timestamp: NtpTimestamp::from_fixed_int(0xe5f6_6298_7b61_b9af),
                origin_timestamp: NtpTimestamp::from_fixed_int(0xe5f6_6366_7b64_995d),
                receive_timestamp: NtpTimestamp::from_fixed_int(0xe5f6_6366_8140_5590),
                transmit_timestamp: NtpTimestamp::from_fixed_int(0xe5f6_63a8_761d_de48),
            }),
            efdata: ExtensionFieldData::default(),
            mac: None,
        };

        assert_eq!(
            reference,
            NtpPacket::deserialize(packet, &NoCipher).unwrap().0
        );
        match reference.serialize_without_encryption_vec(None) {
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
                poll: PollInterval::from_byte(6),
                precision: -23,
                root_delay: NtpDuration::from_fixed_int(566 << 16),
                root_dispersion: NtpDuration::from_fixed_int(951 << 16),
                reference_id: ReferenceId::from_int(0xc035_676c),
                reference_timestamp: NtpTimestamp::from_fixed_int(0xe5f6_61fd_6f16_5f03),
                origin_timestamp: NtpTimestamp::from_fixed_int(0xe5f6_63a8_7619_ef40),
                receive_timestamp: NtpTimestamp::from_fixed_int(0xe5f6_63a8_798c_6581),
                transmit_timestamp: NtpTimestamp::from_fixed_int(0xe5f6_63a8_798e_ae2b),
            }),
            efdata: ExtensionFieldData::default(),
            mac: None,
        };

        assert_eq!(
            reference,
            NtpPacket::deserialize(packet, &NoCipher).unwrap().0
        );
        match reference.serialize_without_encryption_vec(None) {
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
        let packet = b"\x34\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
        assert!(NtpPacket::deserialize(packet, &NoCipher).is_err());
        let packet = b"\x3B\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
        assert!(NtpPacket::deserialize(packet, &NoCipher).is_err());

        #[cfg(not(feature = "ntpv5"))]
        {
            // Version 5 packet should not parse without the ntpv5 feature
            let packet = b"\x2C\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
            assert!(NtpPacket::deserialize(packet, &NoCipher).is_err());
        }
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

                let data = header.serialize_without_encryption_vec(None).unwrap();
                let copy = NtpPacket::deserialize(&data, &NoCipher).unwrap().0;
                assert_eq!(header, copy);
            }
        }

        for i in 0..=0xFF {
            let mut packet = base;
            packet[0] = i;

            if let Ok((a, _)) = NtpPacket::deserialize(&packet, &NoCipher) {
                let b = a.serialize_without_encryption_vec(None).unwrap();
                assert_eq!(packet[..], b[..]);
            }
        }
    }

    #[test]
    fn test_nts_roundtrip() {
        let cookie = [0; 16];
        let (packet1, _) =
            NtpPacket::nts_poll_message(&cookie, 1, PollIntervalLimits::default().min);
        let cipher = AesSivCmac512::new(std::array::from_fn::<_, 64, _>(|i| i as u8).into());

        let mut buffer = [0u8; 2048];
        let mut cursor = Cursor::new(buffer.as_mut());
        packet1.serialize(&mut cursor, &cipher, None).unwrap();
        let (packet2, _) =
            NtpPacket::deserialize(&cursor.get_ref()[..cursor.position() as usize], &cipher)
                .unwrap();
        assert_eq!(packet1, packet2);
    }

    #[test]
    fn test_nts_captured_server() {
        let packet = b"\x24\x01\x04\xe8\x00\x00\x00\x00\x00\x00\x00\x60\x54\x4d\x4e\x4c\xe8\x49\x48\x92\xf9\x29\x57\x9e\x62\x87\xdb\x47\x3f\xf7\x5f\x58\xe8\x49\x48\xb2\xb6\x40\xd7\x01\xe8\x49\x48\xb2\xb6\x44\xbf\xf8\x01\x04\x00\x24\xe4\x83\x3a\x8d\x60\x0e\x13\x42\x43\x5c\xb2\x9d\xe5\x50\xac\xc0\xf8\xd8\xfa\x16\xe5\xc5\x37\x0a\x62\x0b\x15\x5f\x58\x6a\xda\xd6\x04\x04\x00\xd4\x00\x10\x00\xbc\x6a\x1d\xe3\xc2\x6e\x13\xeb\x10\xc7\x39\xd7\x0b\x84\x1f\xad\x1b\x86\xe2\x30\xc6\x3e\x9e\xa5\xf7\x1b\x62\xa8\xa7\x98\x81\xce\x7c\x6b\x17\xcb\x31\x32\x49\x0f\xde\xcf\x21\x10\x56\x4e\x36\x88\x92\xdd\xee\xf1\xf4\x23\xf6\x55\x53\x41\xc2\xc9\x17\x61\x20\xa5\x18\xdc\x1a\x7e\xdc\x5e\xe3\xc8\x3b\x05\x08\x7b\x73\x03\xf7\xab\x86\xd5\x2c\xc7\x49\x0c\xe8\x29\x39\x72\x23\xdc\xef\x2d\x94\xfa\xf8\xd7\x1d\x12\x80\xda\x03\x2d\xd7\x04\x69\xe9\xac\x5f\x82\xef\x57\x81\xd2\x07\xfb\xac\xb4\xa8\xb6\x31\x91\x14\xd5\xf5\x6f\xb2\x2a\x0c\xb6\xd7\xdc\xf7\x7d\xf0\x21\x46\xf6\x7e\x46\x01\xb5\x3b\x21\x7c\xa8\xac\x1a\x4d\x97\xd5\x9b\xce\xeb\x98\x33\x99\x7f\x10\x0e\xd4\x69\x85\x8b\xcd\x73\x52\x01\xad\xec\x38\xcf\x8c\xb2\xc6\xd0\x54\x1a\x97\x67\xdd\xb3\xea\x09\x1d\x63\xd9\x8d\x03\xdd\x6e\x48\x15\x3d\xc9\xb6\x1f\xe5\xd9\x1d\x74\xae\x35\x48";
        let cipher = AesSivCmac512::new(
            [
                244, 6, 63, 13, 47, 226, 180, 25, 104, 212, 47, 14, 186, 70, 187, 93, 134, 140, 2,
                82, 238, 254, 113, 79, 90, 31, 135, 138, 123, 210, 121, 47, 228, 208, 243, 76, 126,
                213, 196, 233, 65, 15, 33, 163, 196, 30, 6, 197, 222, 105, 40, 14, 73, 138, 200,
                45, 235, 127, 48, 248, 171, 8, 141, 180,
            ]
            .into(),
        );

        assert!(NtpPacket::deserialize(packet, &cipher).is_ok());
    }

    #[test]
    fn test_nts_captured_client() {
        let packet = b"\x23\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x62\x87\xdb\x47\x3f\xf7\x5f\x58\x01\x04\x00\x24\xe4\x83\x3a\x8d\x60\x0e\x13\x42\x43\x5c\xb2\x9d\xe5\x50\xac\xc0\xf8\xd8\xfa\x16\xe5\xc5\x37\x0a\x62\x0b\x15\x5f\x58\x6a\xda\xd6\x02\x04\x00\xac\x1c\xc4\x0a\x94\xda\x3f\x94\xa4\xd1\x2a\xc2\xd6\x09\xf1\x6f\x72\x11\x59\x6a\x0a\xce\xfc\x62\xd1\x1f\x28\x3a\xd1\x08\xd8\x01\xb5\x91\x38\x5d\x9b\xf5\x07\xf9\x0d\x21\x82\xe6\x81\x2a\x58\xa7\x35\xdc\x49\xc4\xd3\xe9\xb7\x9c\x72\xb7\xf6\x44\x64\xf8\xfc\x0d\xed\x25\xea\x1f\x7c\x9b\x31\x5c\xd8\x60\x86\xfd\x67\x74\x90\xf5\x0e\x61\xe6\x68\x0e\x29\x0d\x49\x77\x0c\xed\x44\xd4\x2f\x2d\x9b\xa8\x9f\x4d\x5d\xce\x4f\xdd\x57\x49\x51\x49\x5a\x1f\x38\xdb\xc7\xec\x1b\x86\x5b\xa5\x8f\x23\x1e\xdd\x76\xee\x1d\xaf\xdd\x66\xb2\xb2\x64\x1f\x03\xc6\x47\x9b\x42\x9c\x7f\xf6\x59\x6b\x82\x44\xcf\x67\xb5\xa2\xcd\x20\x9d\x39\xbb\xe6\x40\x2b\xf6\x20\x45\xdf\x95\x50\xf0\x38\x77\x06\x89\x79\x12\x18\x04\x04\x00\x28\x00\x10\x00\x10\xce\x89\xee\x97\x34\x42\xbc\x0f\x43\xaa\xce\x49\x99\xbd\xf5\x8e\x8f\xee\x7b\x1a\x2d\x58\xaf\x6d\xe9\xa2\x0e\x56\x1f\x7f\xf0\x6a";
        let cipher = AesSivCmac512::new(
            [
                170, 111, 161, 118, 7, 200, 232, 128, 145, 250, 170, 186, 87, 143, 171, 252, 110,
                241, 170, 179, 13, 150, 134, 147, 211, 248, 62, 207, 122, 155, 198, 109, 167, 15,
                18, 118, 146, 63, 186, 146, 212, 188, 175, 27, 89, 3, 237, 212, 52, 113, 28, 21,
                203, 200, 230, 17, 8, 186, 126, 1, 52, 230, 86, 40,
            ]
            .into(),
        );

        assert!(NtpPacket::deserialize(packet, &cipher).is_ok());
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

    #[cfg(feature = "ntpv5")]
    #[test]
    fn v5_upgrade_packet() {
        let (packet, _) = NtpPacket::poll_message_upgrade_request(PollInterval::default());

        let response = NtpPacket::timestamp_response(
            &SystemSnapshot::default(),
            packet,
            NtpTimestamp::from_fixed_int(0),
            &TestClock {
                now: NtpTimestamp::from_fixed_int(1),
            },
        );

        let NtpHeader::V4(header) = response.header else {
            panic!("wrong version");
        };

        assert_eq!(
            header.reference_timestamp,
            NtpTimestamp::from_fixed_int(0x4E54_5035_4452_4654)
        );
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
            &SystemSnapshot {
                time_snapshot: TimeSnapshot {
                    leap_indicator: NtpLeapIndicator::Leap59,
                    ..Default::default()
                },
                ..Default::default()
            },
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
        assert_eq!(response.leap(), NtpLeapIndicator::Leap59);

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
        assert!(response.is_kiss_rate(PollIntervalLimits::default().min));

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
        assert!(response.is_kiss_rate(PollIntervalLimits::default().min));

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
        assert!(response.is_kiss_rate(PollIntervalLimits::default().min));

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
        assert!(response.is_kiss_rate(PollIntervalLimits::default().min));
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

    #[test]
    fn round_trip_with_ef() {
        let (mut p, _) = NtpPacket::poll_message(PollInterval::default());
        p.efdata.untrusted.push(ExtensionField::Unknown {
            type_id: 0x42,
            data: vec![].into(),
        });

        let serialized = p.serialize_without_encryption_vec(None).unwrap();

        let (mut out, _) = NtpPacket::deserialize(&serialized, &NoCipher).unwrap();

        // Strip any padding
        let ExtensionField::Unknown { data, .. } = &mut out.efdata.untrusted[0] else {
            panic!("wrong ef");
        };
        assert!(data.iter().all(|&e| e == 0));
        *data = vec![].into();

        assert_eq!(p, out);
    }

    #[cfg(feature = "ntpv5")]
    #[test]
    fn ef_with_missing_padding_v5() {
        let (packet, _) = NtpPacket::poll_message_v5(PollInterval::default());
        let mut data = packet.serialize_without_encryption_vec(None).unwrap();
        data.extend([
            0, 0, // Type = Unknown
            0, 6, // Length = 5
            1, 2, // Data
               // Missing 2 padding bytes
        ]);

        assert!(matches!(
            NtpPacket::deserialize(&data, &NoCipher),
            Err(ParsingError::IncorrectLength)
        ));
    }

    #[cfg(feature = "ntpv5")]
    #[test]
    fn padding_v5() {
        for i in 10..40 {
            let packet = NtpPacket::poll_message_v5(PollInterval::default()).0;

            let data = packet
                .serialize_without_encryption_vec(Some(4 * i))
                .unwrap();

            assert_eq!(data.len(), 76.max(i * 4));

            assert!(NtpPacket::deserialize(&data, &NoCipher).is_ok());
        }
    }
}
