use super::clock_accuracy::ClockAccuracy;
use crate::datastructures::{WireFormat, WireFormatError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClockQuality {
    pub clock_class: u8,
    pub clock_accuracy: ClockAccuracy,
    pub offset_scaled_log_variance: u16,
}

impl ClockQuality {
    pub fn new(slave_only: bool) -> Self {
        let clock_class = ClockQuality::determine_class(slave_only);

        ClockQuality {
            clock_class,
            clock_accuracy: Default::default(),
            offset_scaled_log_variance: 0,
        }
    }

    fn determine_class(slave_only: bool) -> u8 {
        if slave_only {
            255
        } else if false {
            // If defaultDS.slaveOnly is FALSE and the applicable PTP Profile specifies the
            // clockClass to be 52, 58, 187, 193, or in the ranges 68 through 122, 133 through 170,
            // or 216 through 232, then the PTP Profile specified clockClass value shall be used for
            // initialization.
            todo!()
        } else if false {
            // If defaultDS.slaveOnly is FALSE and if the PTP Instance is designed as a clockClass 6
            // or 13, the clockClass initialization value shall be 6 or 13, respectively, if these
            // represent the clockClass of the PTP Instance upon exiting the INITIALIZING state. If
            // the clockClass 6 or 13, respectively, does not represent the PTP Instance upon
            // exiting the INITIALIZING state, the clockClass initialization value shall be as
            // follows:
            // 1) Either 52, 187, or 248, as specified in the applicable PTP Profile, for a PTP
            // Instance designed as class 6.
            // 2) Either 58, 193, or 248, as specified in the applicable PTP Profile, for a PTP
            // Instance designed as class 13.
            todo!()
        } else {
            248
        }
    }
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
