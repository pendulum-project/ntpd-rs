use super::clock_accuracy::ClockAccuracy;
use crate::datastructures::{WireFormat, WireFormatError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClockQuality {
    pub clock_class: u8,
    pub clock_accuracy: ClockAccuracy,
    pub offset_scaled_log_variance: u16,
}

impl WireFormat for ClockQuality {
    fn wire_size(&self) -> usize {
        4
    }

    fn serialize(&self, buffer: &mut [u8]) -> Result<(), WireFormatError> {
        buffer[0] = self.clock_class;
        buffer[1] = self.clock_accuracy.to_primitive();
        buffer[2..4].copy_from_slice(&self.offset_scaled_log_variance.to_be_bytes());
        Ok(())
    }

    fn deserialize(buffer: &[u8]) -> Result<Self, WireFormatError> {
        Ok(Self {
            clock_class: buffer[0],
            clock_accuracy: ClockAccuracy::from_primitive(buffer[1]),
            offset_scaled_log_variance: u16::from_be_bytes(buffer[2..4].try_into().unwrap()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_wireformat() {
        let representations = [(
            [0x7A, 0x2A, 0x12, 0x34u8],
            ClockQuality {
                clock_class: 122,
                clock_accuracy: ClockAccuracy::MS2_5,
                offset_scaled_log_variance: 0x1234,
            },
        )];

        for (byte_representation, object_representation) in representations {
            // Test the serialization output
            let mut serialization_buffer = [0; 4];
            object_representation
                .serialize(&mut serialization_buffer)
                .unwrap();
            assert_eq!(serialization_buffer, byte_representation);

            // Test the deserialization output
            let deserialized_data = ClockQuality::deserialize(&byte_representation).unwrap();
            assert_eq!(deserialized_data, object_representation);
        }
    }
}
