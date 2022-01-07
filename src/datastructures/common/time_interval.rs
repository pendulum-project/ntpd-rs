use crate::datastructures::WireFormat;
use bitvec::field::BitField;
use fixed::types::I48F16;
use std::ops::{Deref, DerefMut};

/// Represents time intervals in nanoseconds
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeInterval(pub I48F16);

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
    const BITSIZE: usize = 64;

    fn serialize<T>(&self, buffer: &mut bitvec::slice::BitSlice<bitvec::order::Lsb0, T>)
    where
        T: bitvec::store::BitStore,
    {
        buffer[0..64].store_be(self.0.to_bits() as u64)
    }

    fn deserialize<T>(buffer: &bitvec::slice::BitSlice<bitvec::order::Lsb0, T>) -> Self
    where
        T: bitvec::store::BitStore,
    {
        Self(I48F16::from_bits(buffer[0..64].load_be::<u64>() as i64))
    }
}

#[cfg(test)]
mod tests {
    use bitvec::{bitarr, order::Lsb0, store::BitStore, view::BitView};

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
                [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00u8],
                TimeInterval(I48F16::from_num(-1.0f64)),
            ),
        ];

        for (bit_representation, object_representation) in representations {
            // Test the serialization output
            let mut serialization_buffer = bitarr![const Lsb0, u8; 0; TimeInterval::BITSIZE];
            object_representation.serialize(&mut serialization_buffer);
            assert_eq!(serialization_buffer, bit_representation.view_bits::<Lsb0>());

            // Test the deserialization output
            let deserialized_data =
                TimeInterval::deserialize(bit_representation.view_bits::<Lsb0>());
            assert_eq!(deserialized_data, object_representation);
        }
    }
}
