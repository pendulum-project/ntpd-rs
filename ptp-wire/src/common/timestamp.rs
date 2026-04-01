use crate::Error;

/// A timestamp as they occur in PTP messages.
///
/// This is a number of seconds and nanoseconds since the epoch of the timescale
/// in use. For the PTP timescale the epoch is 00:00:00TAI on January 1, 1970.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord)]
pub struct Timestamp {
    /// The seconds field of the timestamp.
    /// 48-bit, must be less than 281474976710656
    seconds: u64,
    /// The nanoseconds field of the timestamp.
    /// Must be less than 10^9
    nanos: u32,
}

impl Timestamp {
    /// Try to create a new timestamp with the given number of seconds and
    /// nanoseconds since the epoch.
    ///
    /// # Errors
    /// This function fails if the number of seconds is larger than or equal to
    /// 2^48, or when the number of nanoseconds represents more than a whole
    /// second.
    pub fn new(seconds: u64, nanos: u32) -> Result<Self, Error> {
        if seconds >= (1 << 48) || nanos >= 1_000_000_000 {
            Err(Error::Invalid)
        } else {
            Ok(Self { seconds, nanos })
        }
    }

    /// The number of whole seconds passed since the epoch.
    #[must_use]
    pub fn seconds(self) -> u64 {
        self.seconds
    }

    /// The number of nanoseconds passed in addition to the whole seconds.
    #[must_use]
    pub fn nanos(self) -> u32 {
        self.nanos
    }

    /// Update the whole number of seconds since the epoch.
    ///
    /// # Errors
    /// This fails when the number of seconds is larger than or eque
    pub fn try_set_seconds(&mut self, seconds: u64) -> Result<(), Error> {
        if seconds >= (1 << 48) {
            Err(Error::Invalid)
        } else {
            self.seconds = seconds;
            Ok(())
        }
    }

    /// Update the number of nanoseconds passed.
    ///
    /// # Errors
    /// This fails when the number of nanoseconds is larger than a whole second.
    pub fn try_set_nanos(&mut self, nanos: u32) -> Result<(), Error> {
        if nanos >= 1_000_000_000 {
            Err(Error::Invalid)
        } else {
            self.nanos = nanos;
            Ok(())
        }
    }

    pub(crate) fn serialize(self, buffer: &mut [u8]) -> Result<(), Error> {
        buffer
            .get_mut(0..6)
            .ok_or(Error::BufferTooShort)?
            .copy_from_slice(&self.seconds.to_be_bytes()[2..8]);
        buffer
            .get_mut(6..10)
            .ok_or(Error::BufferTooShort)?
            .copy_from_slice(&self.nanos.to_be_bytes());
        Ok(())
    }

    pub(crate) fn deserialize(buffer: &[u8]) -> Result<Self, Error> {
        let mut seconds_buffer = [0; 8];
        seconds_buffer[2..8].copy_from_slice(buffer.get(0..6).ok_or(Error::BufferTooShort)?);

        let nanos = u32::from_be_bytes(
            buffer
                .get(6..10)
                .ok_or(Error::BufferTooShort)?
                .try_into()
                .unwrap(),
        );

        if nanos > 1_000_000_000 {
            return Err(Error::Invalid);
        }

        Ok(Self {
            seconds: u64::from_be_bytes(seconds_buffer),
            nanos,
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
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01u8],
                Timestamp {
                    seconds: 0x0000_0000_0002,
                    nanos: 0x0000_0001,
                },
            ),
            (
                [0x10, 0x00, 0x00, 0x00, 0x00, 0x02, 0x10, 0x00, 0x00, 0x01u8],
                Timestamp {
                    seconds: 0x1000_0000_0002,
                    nanos: 0x1000_0001,
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
            let deserialized_data = Timestamp::deserialize(&byte_representation).unwrap();
            assert_eq!(deserialized_data, object_representation);
        }
    }
}
