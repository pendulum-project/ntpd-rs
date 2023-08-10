use core::ops::{Deref, DerefMut};

use fixed::types::I48F16;

use crate::{
    datastructures::{WireFormat, WireFormatError},
    time::Duration,
};

/// Represents time intervals in nanoseconds
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct TimeInterval(pub I48F16);

impl Deref for TimeInterval {
    type Target = I48F16;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TimeInterval {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl WireFormat for TimeInterval {
    fn wire_size(&self) -> usize {
        8
    }

    fn serialize(&self, buffer: &mut [u8]) -> Result<(), WireFormatError> {
        buffer[0..8].copy_from_slice(&self.0.to_bits().to_be_bytes());
        Ok(())
    }

    fn deserialize(buffer: &[u8]) -> Result<Self, WireFormatError> {
        Ok(Self(I48F16::from_bits(i64::from_be_bytes(
            buffer[0..8].try_into().unwrap(),
        ))))
    }
}

impl From<Duration> for TimeInterval {
    fn from(duration: Duration) -> Self {
        let val = (duration.nanos().to_bits() >> 16) as i64;
        TimeInterval(fixed::types::I48F16::from_bits(val))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_interval_wireformat() {
        let representations = [
            (
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x80, 0x00u8],
                TimeInterval(I48F16::from_num(2.5f64)),
            ),
            (
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01u8],
                TimeInterval(I48F16::from_num(1.0f64 / u16::MAX as f64)),
            ),
            (
                [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00u8],
                TimeInterval(I48F16::from_num(-1.0f64)),
            ),
        ];

        for (byte_representation, object_representation) in representations {
            // Test the serialization output
            let mut serialization_buffer = [0; 8];
            object_representation
                .serialize(&mut serialization_buffer)
                .unwrap();
            assert_eq!(serialization_buffer, byte_representation);

            // Test the deserialization output
            let deserialized_data = TimeInterval::deserialize(&byte_representation).unwrap();
            assert_eq!(deserialized_data, object_representation);
        }
    }
}
