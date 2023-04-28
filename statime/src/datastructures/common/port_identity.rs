use super::clock_identity::ClockIdentity;
use crate::datastructures::{WireFormat, WireFormatError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord)]
pub struct PortIdentity {
    pub clock_identity: ClockIdentity,
    pub port_number: u16,
}

impl WireFormat for PortIdentity {
    fn wire_size(&self) -> usize {
        10
    }

    fn serialize(&self, buffer: &mut [u8]) -> Result<(), WireFormatError> {
        self.clock_identity.serialize(&mut buffer[0..8])?;
        buffer[8..10].copy_from_slice(&self.port_number.to_be_bytes());
        Ok(())
    }

    fn deserialize(buffer: &[u8]) -> Result<Self, WireFormatError> {
        Ok(Self {
            clock_identity: ClockIdentity::deserialize(&buffer[0..8])?,
            port_number: u16::from_be_bytes(buffer[8..10].try_into().unwrap()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_wireformat() {
        let representations = [
            (
                [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x15, 0xb3u8],
                PortIdentity {
                    clock_identity: ClockIdentity([0, 1, 2, 3, 4, 5, 6, 7]),
                    port_number: 5555,
                },
            ),
            (
                [0x40, 0x6d, 0x16, 0x36, 0xc4, 0x24, 0x0e, 0x38, 0x04, 0xd2u8],
                PortIdentity {
                    clock_identity: ClockIdentity([64, 109, 22, 54, 196, 36, 14, 56]),
                    port_number: 1234,
                },
            ),
        ];

        for (byte_representation, object_representation) in representations {
            // Test the serialization output
            let mut serialization_buffer = [0; 10];
            object_representation
                .serialize(&mut serialization_buffer)
                .unwrap();
            assert_eq!(serialization_buffer, byte_representation);

            // Test the deserialization output
            let deserialized_data = PortIdentity::deserialize(&byte_representation).unwrap();
            assert_eq!(deserialized_data, object_representation);
        }
    }
}
