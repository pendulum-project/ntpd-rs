use super::Header;
use crate::datastructures::{
    common::{ClockIdentity, ClockQuality, TimeSource, Timestamp},
    WireFormat,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnnounceMessage {
    pub header: Header,
    pub origin_timestamp: Timestamp,
    pub current_utc_offset: u16,
    pub grandmaster_priority_1: u8,
    pub grandmaster_clock_quality: ClockQuality,
    pub grandmaster_priority_2: u8,
    pub grandmaster_identity: ClockIdentity,
    pub steps_removed: u16,
    pub time_source: TimeSource,
}

impl WireFormat for AnnounceMessage {
    fn serialize(
        &self,
        buffer: &mut [u8],
    ) -> Result<usize, crate::datastructures::WireFormatError> {
        self.header.serialize(&mut buffer[0..34])?;
        self.origin_timestamp.serialize(&mut buffer[34..44])?;
        buffer[44..46].copy_from_slice(&self.current_utc_offset.to_be_bytes());
        buffer[47] = self.grandmaster_priority_1;
        self.grandmaster_clock_quality
            .serialize(&mut buffer[48..52])?;
        buffer[52] = self.grandmaster_priority_2;
        self.grandmaster_identity.serialize(&mut buffer[53..61])?;
        buffer[61..63].copy_from_slice(&self.steps_removed.to_be_bytes());
        buffer[63] = self.time_source.to_primitive();

        Ok(64)
    }

    fn deserialize(buffer: &[u8]) -> Result<(Self, usize), crate::datastructures::WireFormatError> {
        Ok((
            Self {
                header: Header::deserialize(&buffer[0..34])?.0,
                origin_timestamp: Timestamp::deserialize(&buffer[34..44])?.0,
                current_utc_offset: u16::from_be_bytes(buffer[44..46].try_into().unwrap()),
                grandmaster_priority_1: buffer[47],
                grandmaster_clock_quality: ClockQuality::deserialize(&buffer[48..52])?.0,
                grandmaster_priority_2: buffer[52],
                grandmaster_identity: ClockIdentity::deserialize(&buffer[53..61])?.0,
                steps_removed: u16::from_be_bytes(buffer[61..63].try_into().unwrap()),
                time_source: TimeSource::from_primitive(buffer[63]),
            },
            64,
        ))
    }
}

#[cfg(test)]
mod tests {
    use fixed::types::I48F16;

    use crate::datastructures::{
        common::{ClockAccuracy, PortIdentity, TimeInterval},
        messages::{ControlField, FlagField, MessageType},
    };

    use super::*;

    #[test]
    fn announce_wireformat() {
        let representations = [(
            [
                0x1b, 0x02, 0x00, 0x40, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x63, 0xff, 0xff, 0x00, 0x09, 0xba,
                0x00, 0x01, 0x00, 0x3a, 0x05, 0x01, 0x00, 0x00, 0x45, 0xb1, 0x11, 0x5a, 0x0a, 0x73,
                0x46, 0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x80, 0x63, 0xff, 0xff, 0x00,
                0x09, 0xba, 0xf8, 0x21, 0x00, 0x00, 0x80, 0x80,
            ],
            AnnounceMessage {
                header: Header {
                    major_sdo_id: 0x01,
                    message_type: MessageType::Announce,
                    minor_version_ptp: 0x00,
                    version_ptp: 0x02,
                    message_length: 64,
                    domain_number: 0,
                    minor_sdo_id: 0,
                    flag_field: FlagField {
                        ptp_timescale: true,
                        current_utc_offset_valid: true,
                        ..Default::default()
                    },
                    correction_field: TimeInterval(I48F16::from_num(0.0f64)),
                    message_type_specific: [0; 4],
                    source_port_identity: PortIdentity {
                        clock_identity: ClockIdentity([
                            0x00, 0x80, 0x63, 0xff, 0xff, 0x00, 0x09, 0xba,
                        ]),
                        port_number: 1,
                    },
                    sequence_id: 58,
                    control_field: ControlField::AllOthers,
                    log_message_interval: 1,
                },
                origin_timestamp: Timestamp {
                    seconds: 1169232218,
                    nanos: 175326816,
                },
                current_utc_offset: 0,
                grandmaster_priority_1: 96,
                grandmaster_clock_quality: ClockQuality {
                    clock_class: 0,
                    clock_accuracy: ClockAccuracy::Reserved,
                    offset_scaled_log_variance: 128,
                },
                grandmaster_priority_2: 99,
                grandmaster_identity: ClockIdentity([
                    0xff, 0xff, 0x00, 0x09, 0xba, 0xf8, 0x21, 0x00,
                ]),
                steps_removed: 128,
                time_source: TimeSource::Unknown(0x80),
            },
        )];

        for (byte_representation, object_representation) in representations {
            // Test the serialization output
            let mut serialization_buffer = [0; 64];
            object_representation
                .serialize(&mut serialization_buffer)
                .unwrap();
            assert_eq!(serialization_buffer, byte_representation);

            // Test the deserialization output
            let deserialized_data = AnnounceMessage::deserialize(&byte_representation)
                .unwrap()
                .0;
            assert_eq!(deserialized_data, object_representation);
        }
    }
}
