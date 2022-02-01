use super::{flag_field::FlagField, ControlField, MessageType};
use crate::datastructures::{
    common::{PortIdentity, TimeInterval},
    WireFormat, WireFormatError,
};
use getset::CopyGetters;

#[derive(Debug, Clone, Copy, PartialEq, Eq, CopyGetters)]
#[getset(get_copy = "pub")]
pub struct Header {
    pub(super) sdo_id: u16,
    pub(super) message_type: MessageType,
    pub(super) minor_version_ptp: u8,
    pub(super) version_ptp: u8,
    pub(super) message_length: u16,
    pub(super) domain_number: u8,
    pub(super) flag_field: FlagField,
    pub(super) correction_field: TimeInterval,
    pub(super) message_type_specific: [u8; 4],
    pub(super) source_port_identity: PortIdentity,
    pub(super) sequence_id: u16,
    pub(super) control_field: ControlField,
    pub(super) log_message_interval: u8,
}

impl Header {
    pub(super) fn new() -> Self {
        Self {
            sdo_id: 0,
            message_type: MessageType::Sync,
            minor_version_ptp: 1,
            version_ptp: 2,
            message_length: 0,
            domain_number: 0,
            flag_field: FlagField::default(),
            correction_field: TimeInterval::default(),
            message_type_specific: [0, 0, 0, 0],
            source_port_identity: PortIdentity::default(),
            sequence_id: 0,
            control_field: ControlField::Sync,
            log_message_interval: 0,
        }
    }
}

impl WireFormat for Header {
    fn wire_size(&self) -> usize {
        34
    }

    fn serialize(&self, buffer: &mut [u8]) -> Result<(), WireFormatError> {
        buffer[0] = (((self.sdo_id & 0xF00) >> 4) as u8) | (u8::from(self.message_type) & 0x0F);
        buffer[1] = ((self.minor_version_ptp & 0x0F) << 4) | (self.version_ptp & 0x0F);
        buffer[2..4].copy_from_slice(&self.message_length.to_be_bytes());
        buffer[4] = self.domain_number;
        buffer[5] = (self.sdo_id & 0xFF) as u8;
        self.flag_field.serialize(&mut buffer[6..8])?;
        self.correction_field.serialize(&mut buffer[8..16])?;
        buffer[16..20].copy_from_slice(&self.message_type_specific);
        self.source_port_identity.serialize(&mut buffer[20..30])?;
        buffer[30..32].copy_from_slice(&self.sequence_id.to_be_bytes());
        buffer[32] = self.control_field.to_primitive();
        buffer[33] = self.log_message_interval;

        Ok(())
    }

    fn deserialize(buffer: &[u8]) -> Result<Self, WireFormatError> {
        Ok(Self {
            sdo_id: (((buffer[0] & 0xF0) as u16) << 4) | (buffer[5] as u16),
            message_type: (buffer[0] & 0x0F).try_into()?,
            minor_version_ptp: (buffer[1] >> 4) & 0x0F,
            version_ptp: buffer[1] & 0x0F,
            message_length: u16::from_be_bytes(buffer[2..4].try_into().unwrap()),
            domain_number: buffer[4],
            flag_field: FlagField::deserialize(&buffer[6..8])?,
            correction_field: TimeInterval::deserialize(&buffer[8..16])?,
            message_type_specific: buffer[16..20].try_into().unwrap(),
            source_port_identity: PortIdentity::deserialize(&buffer[20..30])?,
            sequence_id: u16::from_be_bytes(buffer[30..32].try_into().unwrap()),
            control_field: ControlField::from_primitive(buffer[32]),
            log_message_interval: buffer[33],
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::datastructures::common::ClockIdentity;

    use super::*;
    use fixed::types::I48F16;

    #[test]
    fn header_wireformat() {
        let representations = [(
            [
                0x59,
                0xA1,
                0x12,
                0x34,
                0xAA,
                0xBB,
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
                5,
                6,
                7,
                8,
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
                0xDE,
                0xAD,
                0x02,
                0x16,
            ],
            Header {
                sdo_id: 0x5BB,
                message_type: MessageType::DelayResp,
                minor_version_ptp: 0xA,
                version_ptp: 0x1,
                message_length: 0x1234,
                domain_number: 0xAA,
                flag_field: FlagField {
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
                },
                correction_field: TimeInterval(I48F16::from_num(1.5f64)),
                message_type_specific: [5, 6, 7, 8],
                source_port_identity: PortIdentity {
                    clock_identity: ClockIdentity([0, 1, 2, 3, 4, 5, 6, 7]),
                    port_number: 0x5555,
                },
                sequence_id: 0xDEAD,
                control_field: ControlField::FollowUp,
                log_message_interval: 0x16,
            },
        )];

        for (byte_representation, object_representation) in representations {
            // Test the serialization output
            let mut serialization_buffer = [0; 34];
            object_representation
                .serialize(&mut serialization_buffer)
                .unwrap();
            assert_eq!(serialization_buffer, byte_representation);

            // Test the deserialization output
            let deserialized_data = Header::deserialize(&byte_representation).unwrap();
            assert_eq!(deserialized_data, object_representation);
        }
    }
}
