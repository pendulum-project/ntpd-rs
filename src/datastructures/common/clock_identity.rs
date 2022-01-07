use crate::datastructures::WireFormat;
use bitvec::{order::Lsb0, view::BitView};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockIdentity(pub [u8; 8]);

impl WireFormat for ClockIdentity {
    const BITSIZE: usize = 64;

    fn serialize<T>(&self, buffer: &mut bitvec::slice::BitSlice<bitvec::order::Lsb0, T>)
    where
        T: bitvec::store::BitStore,
    {
        buffer[0..64].clone_from_bitslice(self.0.view_bits::<Lsb0>());
    }

    fn deserialize<T>(buffer: &bitvec::slice::BitSlice<bitvec::order::Lsb0, T>) -> Self
    where
        T: bitvec::store::BitStore,
    {
        let mut id_value = [0; 8];
        id_value
            .view_bits_mut::<Lsb0>()
            .clone_from_bitslice(&buffer[0..64]);
        Self(id_value)
    }
}

#[cfg(test)]
mod tests {
    use bitvec::{bitarr, order::Lsb0, store::BitStore, view::BitView};

    use super::*;

    #[test]
    fn timestamp_wireformat() {
        let representations = [(
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08u8],
            ClockIdentity([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
        )];

        for (bit_representation, object_representation) in representations {
            // Test the serialization output
            let mut serialization_buffer = bitarr![const Lsb0, u8; 0; 64];
            object_representation.serialize(&mut serialization_buffer);
            assert_eq!(serialization_buffer, bit_representation.view_bits::<Lsb0>());

            // Test the deserialization output
            let deserialized_data =
                ClockIdentity::deserialize(bit_representation.view_bits::<Lsb0>());
            assert_eq!(deserialized_data, object_representation);
        }
    }
}
