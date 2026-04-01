use core::ops::{Deref, DerefMut};

use fixed::types::I48F16;

use crate::{WireFormat, WireFormatError};

/// Represents time intervals in nanoseconds
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TimeInterval(pub I48F16);

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for TimeInterval {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(TimeInterval(I48F16::from_bits(i64::deserialize(
            deserializer,
        )?)))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for TimeInterval {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_i64(self.0.to_bits())
    }
}

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
    fn serialize(&self, buffer: &mut [u8]) -> Result<(), WireFormatError> {
        buffer
            .get_mut(0..8)
            .ok_or(WireFormatError::BufferTooShort)?
            .copy_from_slice(&self.0.to_bits().to_be_bytes());
        Ok(())
    }

    fn deserialize(buffer: &[u8]) -> Result<Self, WireFormatError> {
        Ok(Self(I48F16::from_bits(i64::from_be_bytes(
            buffer
                .get(0..8)
                .ok_or(WireFormatError::BufferTooShort)?
                .try_into()
                .unwrap(),
        ))))
    }
}

impl TimeInterval {
    #[must_use]
    #[expect(
        clippy::cast_precision_loss,
        reason = "Precision loss here is acceptable as it only happens when the interval is relatively large"
    )]
    pub fn to_nanos(self) -> f64 {
        (self.0.to_bits() as f64) / f64::from(1 << 16)
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
                TimeInterval(I48F16::from_num(1.0f64 / f64::from(u16::MAX))),
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
