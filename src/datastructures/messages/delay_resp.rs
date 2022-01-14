use super::Header;
use crate::datastructures::{
    common::{PortIdentity, Timestamp},
    WireFormat,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelayRespMessage {
    pub header: Header,
    pub receive_timestamp: Timestamp,
    pub requesting_port_identity: PortIdentity,
}

impl WireFormat for DelayRespMessage {
    fn serialize(
        &self,
        buffer: &mut [u8],
    ) -> Result<usize, crate::datastructures::WireFormatError> {
        self.header.serialize(&mut buffer[0..34])?;
        self.receive_timestamp.serialize(&mut buffer[34..44])?;
        self.requesting_port_identity
            .serialize(&mut buffer[44..54])?;

        Ok(54)
    }

    fn deserialize(buffer: &[u8]) -> Result<(Self, usize), crate::datastructures::WireFormatError> {
        Ok((
            Self {
                header: Header::deserialize(&buffer[0..34])?.0,
                receive_timestamp: Timestamp::deserialize(&buffer[34..44])?.0,
                requesting_port_identity: PortIdentity::deserialize(&buffer[44..54])?.0,
            },
            54,
        ))
    }
}

#[cfg(test)]
mod tests {
    use fixed::types::I48F16;

    use crate::datastructures::{
        common::{ClockIdentity, PortIdentity, TimeInterval},
        messages::{ControlField, MessageType},
    };

    use super::*;

    #[test]
    fn timestamp_wireformat() {
        let representations = [(
            [
                0x19, 0x02, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x63, 0xff, 0xff, 0x00, 0x09, 0xba,
                0x00, 0x01, 0x00, 0x74, 0x03, 0x00, 0x00, 0x00, 0x45, 0xb1, 0x11, 0x5a, 0x0a, 0x64,
                0xfa, 0xb0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            ],
            DelayRespMessage {
                header: Header {
                    major_sdo_id: 0x01,
                    message_type: MessageType::DelayResp,
                    minor_version_ptp: 0x00,
                    version_ptp: 0x02,
                    message_length: 44,
                    domain_number: 0,
                    minor_sdo_id: 0,
                    flag_field: Default::default(),
                    correction_field: TimeInterval(I48F16::from_num(0.0f64)),
                    message_type_specific: [0; 4],
                    source_port_identity: PortIdentity {
                        clock_identity: ClockIdentity([
                            0x00, 0x80, 0x63, 0xff, 0xff, 0x00, 0x09, 0xba,
                        ]),
                        port_number: 1,
                    },
                    sequence_id: 116,
                    control_field: ControlField::DelayResp,
                    log_message_interval: 0,
                },
                receive_timestamp: Timestamp {
                    seconds: 1169232218,
                    nanos: 174389936,
                },
                requesting_port_identity: PortIdentity {
                    clock_identity: ClockIdentity([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
                    port_number: 0x090A,
                },
            },
        )];

        for (byte_representation, object_representation) in representations {
            // Test the serialization output
            let mut serialization_buffer = [0; 54];
            object_representation
                .serialize(&mut serialization_buffer)
                .unwrap();
            assert_eq!(serialization_buffer, byte_representation);

            // Test the deserialization output
            let deserialized_data = DelayRespMessage::deserialize(&byte_representation)
                .unwrap()
                .0;
            assert_eq!(deserialized_data, object_representation);
        }
    }
}
