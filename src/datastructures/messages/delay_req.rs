use crate::datastructures::{common::Timestamp, WireFormat};
use getset::CopyGetters;

#[derive(Debug, Clone, Copy, PartialEq, Eq, CopyGetters)]
#[getset(get_copy = "pub")]
pub struct DelayReqMessage {
    pub(crate) origin_timestamp: Timestamp,
}

impl WireFormat for DelayReqMessage {
    fn wire_size(&self) -> usize {
        10
    }

    fn serialize(&self, buffer: &mut [u8]) -> Result<(), crate::datastructures::WireFormatError> {
        self.origin_timestamp.serialize(&mut buffer[0..10])?;

        Ok(())
    }

    fn deserialize(buffer: &[u8]) -> Result<Self, crate::datastructures::WireFormatError> {
        Ok(Self {
            origin_timestamp: Timestamp::deserialize(&buffer[0..10])?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_wireformat() {
        let representations = [(
            [0x00, 0x00, 0x45, 0xb1, 0x11, 0x5a, 0x0a, 0x64, 0xfa, 0xb0],
            DelayReqMessage {
                origin_timestamp: Timestamp {
                    seconds: 1169232218,
                    nanos: 174389936,
                },
            },
        )];

        for (byte_representation, object_representation) in representations {
            // Test the serialization output
            let mut serialization_buffer = [0; 10];
            object_representation
                .serialize(&mut serialization_buffer)
                .unwrap();
            assert_eq!(serialization_buffer, byte_representation);

            // Test the deserialization output
            let deserialized_data = DelayReqMessage::deserialize(&byte_representation).unwrap();
            assert_eq!(deserialized_data, object_representation);
        }
    }
}
