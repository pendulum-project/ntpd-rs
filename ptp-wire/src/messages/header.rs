use super::MessageType;
use crate::{
    Error,
    common::{PortIdentity, TimeInterval},
};

/// The header of a PTP version 2 message.
///
/// For more details, see *IEEE1588-2019 section 13.3*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "Struct is a direct representation of the PTP header, which has a lot of boolean elements which don't all map well to enums."
)]
pub struct Header {
    /// Sdo ID of the profile in use for the message.
    pub sdo_id: SdoId,
    /// Specific version of PTP for this message.
    pub version: PtpVersion,
    /// The domain number of the message.
    ///
    /// This is used to allow multiple PTP setups to run within the same network
    /// without interfering with each other.
    pub domain_number: u8,
    /// Indicates whether the sender is an alternate master.
    ///
    /// This is used with the Grandmaster Cluster and Alternate Master optional
    /// PTP features. For more details, see *IEEE1588-2019 sections 17.2 and17.3*
    pub alternate_master_flag: bool,
    /// Indicates whether the message is part of a two-step time transmission.
    pub two_step_flag: bool,
    /// Indicates whether the message is sent via a unicast connection.
    pub unicast_flag: bool,
    /// Used for PTP profile-specific information.
    pub ptp_profile_specific_1: bool,
    /// Used for PTP profile-specific information.
    pub ptp_profile_specific_2: bool,
    /// In announce messages, indicates whether the last minute of the current
    /// UTC day shall have 61 seconds.
    pub leap61: bool,
    /// In announce messages, indicates whether the last minute of the current
    /// UTC day shall have 59 seconds.
    pub leap59: bool,
    /// In announce messages, indicates whether the offset between UTC and TAI
    /// is valid.
    pub current_utc_offset_valid: bool,
    /// In announce messages, indicates whether the timescale is TAI (when
    /// true), or something else.
    pub ptp_timescale: bool,
    /// In announce messages, indicates whether the time provided is traceable
    /// in the metrology sense.
    pub time_tracable: bool,
    /// In announce messages, indicates whether the frequency provided is
    /// traceable in the metrology sense.
    pub frequency_tracable: bool,
    /// In announce messages, a true value indicates that the time provider may
    /// not itself be properly synchronized.
    pub synchronization_uncertain: bool,
    /// Correction field to the timestamps in event messages.
    ///
    /// This is used to improve the precision of those timestamps, as well as
    /// to allow for compensating for the dwell time of messages in switches.
    pub correction_field: TimeInterval,
    /// Identity of the PTP port that sent this message.
    pub source_port_identity: PortIdentity,
    /// Rolling sequence id for the message.
    pub sequence_id: u16,
    /// Used for communication of message sending intervals for some messages
    ///
    /// See *IEEE1588 Table 42 in section 13.3.2.14* for more details.
    pub log_message_interval: i8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DeserializedHeader {
    pub(crate) header: Header,
    pub(crate) message_type: MessageType,
    pub(crate) message_length: u16,
}

impl Header {
    /// Get a new header initialized with default values for all of the fields.
    #[must_use]
    pub fn new(minor_ptp_version: u8) -> Self {
        Self {
            sdo_id: SdoId(0),
            version: PtpVersion {
                major: 2,
                minor: minor_ptp_version,
            },
            domain_number: 0,
            alternate_master_flag: false,
            two_step_flag: false,
            unicast_flag: false,
            ptp_profile_specific_1: false,
            ptp_profile_specific_2: false,
            leap59: false,
            leap61: false,
            current_utc_offset_valid: false,
            ptp_timescale: false,
            time_tracable: false,
            frequency_tracable: false,
            synchronization_uncertain: false,
            correction_field: TimeInterval::default(),
            source_port_identity: PortIdentity::default(),
            sequence_id: 0,
            log_message_interval: 0,
        }
    }

    pub(crate) fn wire_size(&self) -> usize {
        34
    }

    pub(crate) fn serialize_header(
        &self,
        content_type: MessageType,
        content_length: usize,
        buffer: &mut [u8],
    ) -> Result<(), Error> {
        let message_length =
            u16::try_from(content_length + self.wire_size()).map_err(|_| Error::Invalid)?;
        buffer[0] = ((self.sdo_id.high_byte()) << 4) | ((content_type as u8) & 0x0f);
        buffer[1] = self.version.as_byte();
        buffer[2..4].copy_from_slice(&message_length.to_be_bytes());
        buffer[4] = self.domain_number;
        buffer[5] = self.sdo_id.low_byte();
        buffer[6] = 0;
        buffer[7] = 0;
        buffer[6] |= u8::from(self.alternate_master_flag);
        buffer[6] |= u8::from(self.two_step_flag) << 1;
        buffer[6] |= u8::from(self.unicast_flag) << 2;
        buffer[6] |= u8::from(self.ptp_profile_specific_1) << 5;
        buffer[6] |= u8::from(self.ptp_profile_specific_2) << 6;
        buffer[7] |= u8::from(self.leap61);
        buffer[7] |= u8::from(self.leap59) << 1;
        buffer[7] |= u8::from(self.current_utc_offset_valid) << 2;
        buffer[7] |= u8::from(self.ptp_timescale) << 3;
        buffer[7] |= u8::from(self.time_tracable) << 4;
        buffer[7] |= u8::from(self.frequency_tracable) << 5;
        buffer[7] |= u8::from(self.synchronization_uncertain) << 6;
        self.correction_field.serialize(&mut buffer[8..16])?;
        buffer[16..20].copy_from_slice(&[0, 0, 0, 0]);
        self.source_port_identity.serialize(&mut buffer[20..30])?;
        buffer[30..32].copy_from_slice(&self.sequence_id.to_be_bytes());
        buffer[32] = 0;
        buffer[33] = self.log_message_interval.cast_unsigned();

        Ok(())
    }

    pub(crate) fn deserialize_header(buffer: &[u8]) -> Result<DeserializedHeader, Error> {
        if buffer.len() < 34 {
            return Err(Error::BufferTooShort);
        }

        let version = PtpVersion::from_byte(buffer[1]);
        let sdo_id = SdoId((u16::from(buffer[0] & 0xf0) << 4) | u16::from(buffer[5]));

        Ok(DeserializedHeader {
            header: Self {
                sdo_id,
                version,
                domain_number: buffer[4],
                alternate_master_flag: (buffer[6] & (1 << 0)) > 0,
                two_step_flag: (buffer[6] & (1 << 1)) > 0,
                unicast_flag: (buffer[6] & (1 << 2)) > 0,
                ptp_profile_specific_1: (buffer[6] & (1 << 5)) > 0,
                ptp_profile_specific_2: (buffer[6] & (1 << 6)) > 0,
                leap61: (buffer[7] & (1 << 0)) > 0,
                leap59: (buffer[7] & (1 << 1)) > 0,
                current_utc_offset_valid: (buffer[7] & (1 << 2)) > 0,
                ptp_timescale: (buffer[7] & (1 << 3)) > 0,
                time_tracable: (buffer[7] & (1 << 4)) > 0,
                frequency_tracable: (buffer[7] & (1 << 5)) > 0,
                synchronization_uncertain: (buffer[7] & (1 << 6)) > 0,
                correction_field: TimeInterval::deserialize(&buffer[8..16])?,
                source_port_identity: PortIdentity::deserialize(&buffer[20..30])?,
                sequence_id: u16::from_be_bytes(buffer[30..32].try_into().unwrap()),
                log_message_interval: buffer[33].cast_signed(),
            },
            message_type: (buffer[0] & 0x0f).try_into()?,
            message_length: u16::from_be_bytes(buffer[2..4].try_into().unwrap()),
        })
    }
}

/// A wrapper type for PTP Sdo Identifiers.
///
/// Because `SdoId`s are 12 bit values they always lie within `0..=0xFFF`.
///
/// For more details, see *IEEE1588-2019 table 2 in section 7.1.4*.
///
/// # Example
/// ```
/// # use ptp_wire::SdoId;
/// assert_eq!(SdoId::default(), SdoId::try_from(0x000).unwrap());
///
/// let sdo_id = SdoId::try_from(0x100).unwrap();
/// assert_eq!(u16::from(sdo_id), 0x100);
///
/// assert!(SdoId::try_from(0x1000).is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SdoId(u16);

impl core::fmt::Display for SdoId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl SdoId {
    const fn high_byte(self) -> u8 {
        (self.0 >> 8) as u8
    }

    const fn low_byte(self) -> u8 {
        (self.0 & 0xFF) as u8
    }
}

#[cfg(feature = "serde")]
struct SdoIdVisitor;

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SdoId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_newtype_struct("SdoId", SdoIdVisitor)
    }
}

#[cfg(all(feature = "serde", feature = "std"))]
impl<'de> serde::de::Visitor<'de> for SdoIdVisitor {
    type Value = SdoId;

    fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        formatter.write_str("a 12 bit value within the 0..=0xFFF range")
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::{Deserialize, de::Error};
        let v = u16::deserialize(deserializer)?;
        SdoId::try_from(v).or(Err(D::Error::custom(std::format!(
            "SdoId not in range of 0..=0xFFF: {}",
            v
        ))))
    }

    fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        SdoId::try_from(v).or(Err(E::custom(std::format!(
            "SdoId not in range of 0..=0xFFF: {}",
            v
        ))))
    }
}

impl TryFrom<u16> for SdoId {
    type Error = Error;

    /// Turn a `u16` into a `SdoId` ensuring it is in the range `0..=0xFFF`.
    fn try_from(sdo_id: u16) -> Result<Self, Self::Error> {
        (0..=0xfff)
            .contains(&sdo_id)
            .then_some(Self(sdo_id))
            .ok_or(Error::Invalid)
    }
}

impl From<SdoId> for u16 {
    fn from(value: SdoId) -> Self {
        value.0
    }
}

/// The PTP version of a message.
///
/// For most uses of this library, the major version of this version number
/// will be 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtpVersion {
    major: u8,
    minor: u8,
}

impl PtpVersion {
    /// Get a new [`PtpVersion`] instance with the given major and minor version.
    ///
    /// # Errors
    /// This fails when either the major or minor version is larger than 15.
    pub fn new(major: u8, minor: u8) -> Result<Self, Error> {
        if major >= 0x10 || minor >= 0x10 {
            Err(Error::Invalid)
        } else {
            Ok(Self { major, minor })
        }
    }

    /// The major part of the PTP version number.
    #[must_use]
    pub fn major(self) -> u8 {
        self.major
    }

    /// The minor part of the PTP version number.
    #[must_use]
    pub fn minor(self) -> u8 {
        self.minor
    }

    fn as_byte(self) -> u8 {
        (self.minor << 4) | self.major
    }

    fn from_byte(byte: u8) -> Self {
        Self {
            major: byte & 0x0f,
            minor: byte >> 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::ClockIdentity;

    #[test]
    fn flagfield_wireformat() {
        #[rustfmt::skip]
        let representations = [
            ([0x00, 0x00u8], Header::new(1)),
            ([0x01, 0x00u8], Header { alternate_master_flag: true, ..Header::new(1) }),
            ([0x02, 0x00u8], Header { two_step_flag: true, ..Header::new(1) }),
            ([0x04, 0x00u8], Header { unicast_flag: true, ..Header::new(1) }),
            ([0x20, 0x00u8], Header { ptp_profile_specific_1: true, ..Header::new(1) }),
            ([0x40, 0x00u8], Header { ptp_profile_specific_2: true, ..Header::new(1) }),
            ([0x00, 0x01u8], Header { leap61: true, ..Header::new(1) }),
            ([0x00, 0x02u8], Header { leap59: true, ..Header::new(1) }),
            ([0x00, 0x04u8], Header { current_utc_offset_valid: true, ..Header::new(1) }),
            ([0x00, 0x08u8], Header { ptp_timescale: true, ..Header::new(1) }),
            ([0x00, 0x10u8], Header { time_tracable: true, ..Header::new(1) }),
            ([0x00, 0x20u8], Header { frequency_tracable: true, ..Header::new(1) }),
            ([0x00, 0x40u8], Header { synchronization_uncertain: true, ..Header::new(1) }),
        ];

        for (i, (byte_representation, flag_representation)) in
            representations.into_iter().enumerate()
        {
            // Test the serialization output
            let mut serialization_buffer = [0; 34];
            flag_representation
                .serialize_header(MessageType::Sync, 0, &mut serialization_buffer)
                .unwrap();
            assert_eq!(
                serialization_buffer[6..8],
                byte_representation,
                "The serialized flag field is not what it's supposed to for variant {}",
                i
            );

            // Test the deserialization output
            serialization_buffer[6] = byte_representation[0];
            serialization_buffer[7] = byte_representation[1];
            let deserialized_flag_field =
                Header::deserialize_header(&serialization_buffer).unwrap();
            assert_eq!(
                deserialized_flag_field.header, flag_representation,
                "The deserialized flag field is not what it's supposed to for variant {}",
                i
            );
        }
    }

    #[test]
    fn header_wireformat() {
        let representations = [(
            [
                0x59,
                0xa1,
                0x12,
                0x34,
                0xaa,
                0xbb,
                0b0100_0101,
                0b0010_1010,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x01,
                0x80,
                0x00,
                0,
                0,
                0,
                0,
                0,
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                0x55,
                0x55,
                0xde,
                0xad,
                0x00,
                0x16,
            ],
            DeserializedHeader {
                header: Header {
                    sdo_id: SdoId(0x5bb),
                    version: PtpVersion {
                        major: 0x1,
                        minor: 0xa,
                    },
                    domain_number: 0xaa,
                    alternate_master_flag: true,
                    two_step_flag: false,
                    unicast_flag: true,
                    ptp_profile_specific_1: false,
                    ptp_profile_specific_2: true,
                    leap61: false,
                    leap59: true,
                    current_utc_offset_valid: false,
                    ptp_timescale: true,
                    time_tracable: false,
                    frequency_tracable: true,
                    synchronization_uncertain: false,
                    correction_field: TimeInterval::from_nanos(1.5f64).unwrap(),
                    source_port_identity: PortIdentity {
                        clock_identity: ClockIdentity([0, 1, 2, 3, 4, 5, 6, 7]),
                        port_number: 0x5555,
                    },
                    sequence_id: 0xdead,
                    log_message_interval: 0x16,
                },
                message_type: MessageType::DelayResp,
                message_length: 0x1234,
            },
        )];

        for (byte_representation, object_representation) in representations {
            // Test the serialization output
            let mut serialization_buffer = [0; 34];
            object_representation
                .header
                .serialize_header(
                    object_representation.message_type,
                    object_representation.message_length as usize
                        - object_representation.header.wire_size(),
                    &mut serialization_buffer,
                )
                .unwrap();
            assert_eq!(serialization_buffer, byte_representation);

            // Test the deserialization output
            let deserialized_data = Header::deserialize_header(&byte_representation).unwrap();
            assert_eq!(deserialized_data, object_representation);
        }
    }

    #[test]
    fn sdo_id_checks() {
        use serde_test::{Token, assert_de_tokens_error, assert_tokens};
        let correct_sdo_id = SdoId::try_from(0xfff).unwrap();
        let faulty_sdo_id = SdoId::try_from(0x1000);

        assert_eq!(0xfff, u16::from(correct_sdo_id));
        assert!(faulty_sdo_id.is_err());

        assert_tokens(
            &correct_sdo_id,
            &[Token::NewtypeStruct { name: "SdoId" }, Token::U16(4095)],
        );

        assert_de_tokens_error::<SdoId>(
            &[Token::NewtypeStruct { name: "SdoId" }, Token::U16(4096)],
            "SdoId not in range of 0..=0xFFF: 4096",
        );
    }
}
