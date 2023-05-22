use super::clock_accuracy::ClockAccuracy;
use crate::datastructures::{WireFormat, WireFormatError};

/// A description of the accuracy and type of a clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClockQuality {
    /// The PTP clock class.
    ///
    /// Per the standard, 248 is the default, and a good option for most use
    /// cases. For grandmaster clocks, this should be below 128 to ensure the
    /// clock never takes time from another source. A value of 6 is a good
    /// option for a node with an external time source.
    ///
    /// For other potential values, see IEEE1588-2019 section 7.6.2.5
    pub clock_class: u8,

    /// The accuracy of the clock
    pub clock_accuracy: ClockAccuracy,

    /// 2-log of the variance (in seconds^2) of the clock when not synchronized.
    /// See IEEE1588-2019 section 7.6.3.5 for more details.
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
            [0x7a, 0x2a, 0x12, 0x34u8],
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
