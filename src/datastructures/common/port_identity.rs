use crate::datastructures::WireFormat;
use bitvec::field::BitField;

use super::clock_identity::ClockIdentity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortIdentity {
    pub clock_identity: ClockIdentity,
    pub port_number: u16,
}

impl WireFormat for PortIdentity {
    const BITSIZE: usize = ClockIdentity::BITSIZE + 16;

    fn serialize<T>(&self, buffer: &mut bitvec::slice::BitSlice<bitvec::order::Lsb0, T>)
    where
        T: bitvec::store::BitStore,
    {
        self.clock_identity.serialize(&mut buffer[0..64]);
        buffer[64..80].store_be(self.port_number);
    }

    fn deserialize<T>(buffer: &bitvec::slice::BitSlice<bitvec::order::Lsb0, T>) -> Self
    where
        T: bitvec::store::BitStore,
    {
        Self {
            clock_identity: ClockIdentity::deserialize(&buffer[0..64]),
            port_number: buffer[64..80].load_be(),
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
                [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x15, 0xB3u8],
                PortIdentity {
                    clock_identity: ClockIdentity([0, 1, 2, 3, 4, 5, 6, 7]),
                    port_number: 5555,
                },
            ),
            (
                [0x40, 0x6D, 0x16, 0x36, 0xC4, 0x24, 0x0E, 0x38, 0x04, 0xD2u8],
                PortIdentity {
                    clock_identity: ClockIdentity([64, 109, 22, 54, 196, 36, 14, 56]),
                    port_number: 1234,
                },
            ),
        ];

        for (bit_representation, object_representation) in representations {
            // Test the serialization output
            let mut serialization_buffer = bitarr![const Lsb0, u8; 0; 80];
            object_representation.serialize(&mut serialization_buffer);
            assert_eq!(serialization_buffer, bit_representation.view_bits::<Lsb0>());

            // Test the deserialization output
            let deserialized_data =
                PortIdentity::deserialize(bit_representation.view_bits::<Lsb0>());
            assert_eq!(deserialized_data, object_representation);
        }
    }
}
