use getset::CopyGetters;

use super::{control_field::ControlField, MessageType};
use crate::datastructures::{
    common::{PortIdentity, TimeInterval},
    WireFormat, WireFormatError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, CopyGetters)]
#[getset(get_copy = "pub")]
pub struct Header {
    pub(crate) sdo_id: SdoId,
    pub(crate) version: PtpVersion,
    pub(crate) domain_number: u8,
    pub(crate) alternate_master_flag: bool,
    pub(crate) two_step_flag: bool,
    pub(crate) unicast_flag: bool,
    pub(crate) ptp_profile_specific_1: bool,
    pub(crate) ptp_profile_specific_2: bool,
    pub(crate) leap61: bool,
    pub(crate) leap59: bool,
    pub(crate) current_utc_offset_valid: bool,
    pub(crate) ptp_timescale: bool,
    pub(crate) time_tracable: bool,
    pub(crate) frequency_tracable: bool,
    pub(crate) synchronization_uncertain: bool,
    pub(crate) correction_field: TimeInterval,
    pub(crate) source_port_identity: PortIdentity,
    pub(crate) sequence_id: u16,
    pub(crate) log_message_interval: i8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeserializedHeader {
    pub header: Header,
    pub message_type: MessageType,
    pub message_length: u16,
}

impl Header {
    pub(super) fn new() -> Self {
        Self {
            sdo_id: SdoId(0),
            version: PtpVersion { major: 2, minor: 1 },
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

    pub fn wire_size(&self) -> usize {
        34
    }

    pub fn serialize_header(
        &self,
        content_type: MessageType,
        content_length: usize,
        buffer: &mut [u8],
    ) -> Result<(), WireFormatError> {
        buffer[0] = ((self.sdo_id.high_byte()) << 4) | ((content_type as u8) & 0x0f);
        buffer[1] = self.version.as_byte();
        buffer[2..4].copy_from_slice(&((content_length + self.wire_size()) as u16).to_be_bytes());
        buffer[4] = self.domain_number;
        buffer[5] = self.sdo_id.low_byte();
        buffer[6] = 0;
        buffer[7] = 0;
        buffer[6] |= self.alternate_master_flag as u8;
        buffer[6] |= (self.two_step_flag as u8) << 1;
        buffer[6] |= (self.unicast_flag as u8) << 2;
        buffer[6] |= (self.ptp_profile_specific_1 as u8) << 5;
        buffer[6] |= (self.ptp_profile_specific_2 as u8) << 6;
        buffer[7] |= self.leap61 as u8;
        buffer[7] |= (self.leap59 as u8) << 1;
        buffer[7] |= (self.current_utc_offset_valid as u8) << 2;
        buffer[7] |= (self.ptp_timescale as u8) << 3;
        buffer[7] |= (self.time_tracable as u8) << 4;
        buffer[7] |= (self.frequency_tracable as u8) << 5;
        buffer[7] |= (self.synchronization_uncertain as u8) << 6;
        self.correction_field.serialize(&mut buffer[8..16])?;
        buffer[16..20].copy_from_slice(&[0, 0, 0, 0]);
        self.source_port_identity.serialize(&mut buffer[20..30])?;
        buffer[30..32].copy_from_slice(&self.sequence_id.to_be_bytes());
        buffer[32] = ControlField::from(content_type).to_primitive();
        buffer[33] = self.log_message_interval as u8;

        Ok(())
    }

    pub fn deserialize_header(buffer: &[u8]) -> Result<DeserializedHeader, WireFormatError> {
        if buffer.len() < 34 {
            return Err(WireFormatError::BufferTooShort);
        }

        let version = PtpVersion::from_byte(buffer[1]);
        let sdo_id = SdoId((((buffer[0] & 0xf0) as u16) << 4) | (buffer[5] as u16));

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
                log_message_interval: buffer[33] as i8,
            },
            message_type: (buffer[0] & 0x0f).try_into()?,
            message_length: u16::from_be_bytes(buffer[2..4].try_into().unwrap()),
        })
    }
}

impl Default for Header {
    fn default() -> Self {
        Self::new()
    }
}

/// A wrapper type for PTP Sdo Identifiers.
///
/// This is a separate type as sdo identifiers should be in the range 0-4095
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct SdoId(u16);

impl core::fmt::Display for SdoId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl SdoId {
    /// Create a new sdo id
    ///
    /// This function only returns an `SdoId` instance if the given identifier
    /// is actually between 0 and 4095. Otherwise, `None` is returned.
    pub fn new(sdo_id: u16) -> Option<Self> {
        (0..=0x1000).contains(&sdo_id).then_some(Self(sdo_id))
    }

    const fn high_byte(self) -> u8 {
        (self.0 >> 8) as u8
    }

    const fn low_byte(self) -> u8 {
        self.0 as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtpVersion {
    major: u8,
    minor: u8,
}

impl PtpVersion {
    #[allow(unused)]
    pub fn new(major: u8, minor: u8) -> Option<Self> {
        if major >= 0x10 || minor >= 0x10 {
            None
        } else {
            Some(Self { major, minor })
        }
    }

    fn as_byte(&self) -> u8 {
        self.minor << 4 | self.major
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
    use fixed::types::I48F16;

    use super::*;
    use crate::datastructures::common::ClockIdentity;

    #[test]
    fn flagfield_wireformat() {
        #[rustfmt::skip]
        let representations = [
            ([0x00, 0x00u8], Header::default()),
            ([0x01, 0x00u8], Header { alternate_master_flag: true, ..Default::default() }),
            ([0x02, 0x00u8], Header { two_step_flag: true, ..Default::default() }),
            ([0x04, 0x00u8], Header { unicast_flag: true, ..Default::default() }),
            ([0x20, 0x00u8], Header { ptp_profile_specific_1: true, ..Default::default() }),
            ([0x40, 0x00u8], Header { ptp_profile_specific_2: true, ..Default::default() }),
            ([0x00, 0x01u8], Header { leap61: true, ..Default::default() }),
            ([0x00, 0x02u8], Header { leap59: true, ..Default::default() }),
            ([0x00, 0x04u8], Header { current_utc_offset_valid: true, ..Default::default() }),
            ([0x00, 0x08u8], Header { ptp_timescale: true, ..Default::default() }),
            ([0x00, 0x10u8], Header { time_tracable: true, ..Default::default() }),
            ([0x00, 0x20u8], Header { frequency_tracable: true, ..Default::default() }),
            ([0x00, 0x40u8], Header { synchronization_uncertain: true, ..Default::default() }),
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
                0x03,
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
                    correction_field: TimeInterval(I48F16::from_num(1.5f64)),
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
}
