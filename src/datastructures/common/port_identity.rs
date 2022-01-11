use super::clock_identity::ClockIdentity;
use crate::datastructures::{WireFormat, WireFormatError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortIdentity {
    pub clock_identity: ClockIdentity,
    pub port_number: u16,
}

impl WireFormat for PortIdentity {
    fn serialize(&self, buffer: &mut [u8]) -> Result<usize, WireFormatError> {
        let clock_identity_length = self.clock_identity.serialize(&mut buffer[0..])?;
        buffer[clock_identity_length..][..2].copy_from_slice(&self.port_number.to_be_bytes());
        Ok(clock_identity_length + 2)
    }

    fn deserialize(buffer: &[u8]) -> Result<(Self, usize), WireFormatError> {
        let (clock_identity, clock_identity_length) = ClockIdentity::deserialize(&buffer[0..])?;

        Ok((
            Self {
                clock_identity,
                port_number: u16::from_be_bytes(
                    buffer[clock_identity_length..][..2].try_into().unwrap(),
                ),
            },
            clock_identity_length + 2,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_wireformat() {
        let representations = [
            (
                [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x15, 0xB3u8],
                PortIdentity {
                    clock_identity: ClockIdentity([0, 1, 2, 3, 4, 5, 6, 7]),
                    port_number: 5555,
                },
            ),
            (
                [0x40, 0x6D, 0x16, 0x36, 0xC4, 0x24, 0x0E, 0x38, 0x04, 0xD2u8],
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
            let deserialized_data = PortIdentity::deserialize(&byte_representation).unwrap().0;
            assert_eq!(deserialized_data, object_representation);
        }
    }
}
