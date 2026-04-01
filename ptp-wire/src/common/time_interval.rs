use crate::Error;

/// An interval of passed time as represented in PTP messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TimeInterval(
    /// The length of the time intervals in 2^16ths of a nanoseconds.
    pub i64,
);

impl TimeInterval {
    pub(crate) fn serialize(self, buffer: &mut [u8]) -> Result<(), Error> {
        buffer
            .get_mut(0..8)
            .ok_or(Error::BufferTooShort)?
            .copy_from_slice(&self.0.to_be_bytes());
        Ok(())
    }

    pub(crate) fn deserialize(buffer: &[u8]) -> Result<Self, Error> {
        Ok(Self(i64::from_be_bytes(
            buffer
                .get(0..8)
                .ok_or(Error::BufferTooShort)?
                .try_into()
                .unwrap(),
        )))
    }

    /// Length of this interval in nano seconds
    #[must_use]
    #[expect(
        clippy::cast_precision_loss,
        reason = "Precision loss here is acceptable as it only happens when the interval is relatively large"
    )]
    pub fn to_nanos(self) -> f64 {
        (self.0 as f64) / f64::from(1 << 16)
    }

    /// Create a new interval with the given length.
    ///
    /// This will round to the closest possible value.
    ///
    /// # Errors
    /// This will error if the input is NaN or of magnitude larger than
    /// about 2^47 nanoseconds
    pub fn from_nanos(nanos: f64) -> Result<Self, Error> {
        // We need to do the checks for the conversion manually unfortunately,
        // as rust doesn't have usable builtin conversions for floats.
        let ticks = (nanos * f64::from(1 << 16)).round();
        // The as casts in the check are not exact, but that is acceptable as
        // the MAX value rounds up by 1, which can be solved with checking for
        // equality as well, and the MIN value is exactly representable. After
        // the check, the as cast back to integer from the float will be exact.
        #[expect(clippy::cast_precision_loss)]
        #[expect(clippy::cast_possible_truncation)]
        if ticks.is_nan() || ticks >= (i64::MAX as f64) || ticks < (i64::MIN as f64) {
            Err(Error::Invalid)
        } else {
            Ok(Self((nanos * f64::from(1 << 16)) as i64))
        }
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
                TimeInterval::from_nanos(2.5f64).unwrap(),
            ),
            (
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01u8],
                TimeInterval::from_nanos(1.0f64 / f64::from(u16::MAX)).unwrap(),
            ),
            (
                [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00u8],
                TimeInterval::from_nanos(-1.0f64).unwrap(),
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
