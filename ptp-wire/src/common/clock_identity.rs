use crate::{WireFormat, WireFormatError};

/// The identity of a PTP node.
///
/// All ptp clocks in a network need a unique clock identity. A common approach
/// is to use a mac address of the device to generate a unique identifier (see
/// [`from_mac_address`](`Self::from_mac_address`)).
///
/// For more details, see *IEEE1588-2019 section 7.5.2.2.2*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ClockIdentity(pub [u8; 8]);

impl ClockIdentity {
    /// Create a [`ClockIdentity`] from a mac address.
    ///
    /// Fills the first six bytes with the mac address and the rest with zeroes.
    ///
    /// # Example
    /// ```
    /// # use statime::config::ClockIdentity;
    /// let id = ClockIdentity::from_mac_address([0xA, 0xB, 0xC, 0xD, 0xE, 0xF]);
    /// assert_eq!(id.0, [0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x0]);
    /// ```
    #[must_use]
    pub fn from_mac_address(addr: [u8; 6]) -> Self {
        let mut this = Self([0; 8]);

        this.0[0..6].copy_from_slice(&addr);

        this
    }
}

impl WireFormat for ClockIdentity {
    fn serialize(&self, buffer: &mut [u8]) -> Result<(), WireFormatError> {
        buffer[0..8].copy_from_slice(&self.0);
        Ok(())
    }

    fn deserialize(buffer: &[u8]) -> Result<Self, WireFormatError> {
        Ok(Self(buffer[0..8].try_into().unwrap()))
    }
}

#[cfg(feature = "std")]
impl core::fmt::Display for ClockIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (i, val) in self.0.iter().enumerate() {
            if i != 0 {
                write!(f, ":")?;
            }

            write!(f, "{:02x}", val)?;
        }

        Ok(())
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
            let deserialized_data = ClockIdentity::deserialize(&byte_representation).unwrap();
            assert_eq!(deserialized_data, object_representation);
        }
    }

    #[test]
    fn from_mac() {
        let mac = [1, 2, 3, 4, 5, 6];
        let id = ClockIdentity::from_mac_address(mac);
        assert_eq!(id, ClockIdentity([1, 2, 3, 4, 5, 6, 0, 0]));
    }
}
