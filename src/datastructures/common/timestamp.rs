use crate::datastructures::WireFormat;
use bitvec::field::BitField;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp {
    /// The seconds field of the timestamp.
    /// 48-bit, must be less than 281474976710656
    pub seconds: u64,
    /// The nanoseconds field of the timestamp.
    /// Must be less than 10^9
    pub nanos: u32,
}

impl WireFormat for Timestamp {
    const BITSIZE: usize = 48 + 32;

    fn serialize<T>(&self, buffer: &mut bitvec::slice::BitSlice<bitvec::order::Lsb0, T>)
    where
        T: bitvec::store::BitStore,
    {
        buffer[0..48].store_be(self.seconds);
        buffer[48..80].store_be(self.nanos);
    }

    fn deserialize<T>(buffer: &bitvec::slice::BitSlice<bitvec::order::Lsb0, T>) -> Self
    where
        T: bitvec::store::BitStore,
    {
        Self {
            seconds: buffer[0..48].load_be(),
            nanos: buffer[48..80].load_be(),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitvec::{bitarr, order::Lsb0, store::BitStore, view::BitView};

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

        for (bit_representation, object_representation) in representations {
            // Test the serialization output
            let mut serialization_buffer = bitarr![const Lsb0, u8; 0; Timestamp::BITSIZE];
            object_representation.serialize(&mut serialization_buffer);
            assert_eq!(serialization_buffer, bit_representation.view_bits::<Lsb0>());

            // Test the deserialization output
            let deserialized_data = Timestamp::deserialize(bit_representation.view_bits::<Lsb0>());
            assert_eq!(deserialized_data, object_representation);
        }
    }
}
