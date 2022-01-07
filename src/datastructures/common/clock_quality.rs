use super::clock_accuracy::ClockAccuracy;
use crate::datastructures::WireFormat;
use bitvec::field::BitField;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockQuality {
    pub clock_class: u8,
    pub clock_accuracy: ClockAccuracy,
    pub offset_scaled_log_variance: u16,
}

impl WireFormat for ClockQuality {
    const BITSIZE: usize = 32;

    fn serialize<T>(&self, buffer: &mut bitvec::slice::BitSlice<bitvec::order::Lsb0, T>)
    where
        T: bitvec::store::BitStore,
    {
        buffer[0..8].store_be(self.clock_class);
        buffer[8..16].store_be(self.clock_accuracy.to_primitive());
        buffer[16..32].store_be(self.offset_scaled_log_variance);
    }

    fn deserialize<T>(buffer: &bitvec::slice::BitSlice<bitvec::order::Lsb0, T>) -> Self
    where
        T: bitvec::store::BitStore,
    {
        Self {
            clock_class: buffer[0..8].load_be(),
            clock_accuracy: ClockAccuracy::from_primitive(buffer[8..16].load_be()),
            offset_scaled_log_variance: buffer[16..32].load_be(),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitvec::{bitarr, order::Lsb0, store::BitStore, view::BitView};

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

        for (bit_representation, object_representation) in representations {
            // Test the serialization output
            let mut serialization_buffer = bitarr![const Lsb0, u8; 0; ClockQuality::BITSIZE];
            object_representation.serialize(&mut serialization_buffer);
            assert_eq!(serialization_buffer, bit_representation.view_bits::<Lsb0>());

            // Test the deserialization output
            let deserialized_data =
                ClockQuality::deserialize(bit_representation.view_bits::<Lsb0>());
            assert_eq!(deserialized_data, object_representation);
        }
    }
}
