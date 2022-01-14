use crate::datastructures::{WireFormat, WireFormatError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockIdentity(pub [u8; 8]);

impl WireFormat for ClockIdentity {
    const STATIC_SIZE: Option<usize> = Some(8);

    fn serialize(&self, buffer: &mut [u8]) -> Result<usize, WireFormatError> {
        buffer[0..8].copy_from_slice(&self.0);
        Ok(8)
    }

    fn deserialize(buffer: &[u8]) -> Result<(Self, usize), WireFormatError> {
        Ok((Self(buffer[0..8].try_into().unwrap()), 8))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_wireformat() {
        let representations = [(
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08u8],
            ClockIdentity([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
        )];

        for (byte_representation, object_representation) in representations {
            // Test the serialization output
            let mut serialization_buffer = [0; 8];
            object_representation
                .serialize(&mut serialization_buffer)
                .unwrap();
            assert_eq!(serialization_buffer, byte_representation);

            // Test the deserialization output
            let deserialized_data = ClockIdentity::deserialize(&byte_representation).unwrap().0;
            assert_eq!(deserialized_data, object_representation);
        }
    }
}
