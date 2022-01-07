use super::network_protocol::NetworkProtocol;
use crate::datastructures::WireFormat;
use arrayvec::ArrayVec;
use bitvec::{field::BitField, order::Lsb0, view::BitView};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortAddress {
    pub network_protocol: NetworkProtocol,
    pub address: ArrayVec<u8, 16>,
}

impl WireFormat for PortAddress {
    const BITSIZE: usize = 160;

    fn serialize<T>(&self, buffer: &mut bitvec::slice::BitSlice<bitvec::order::Lsb0, T>)
    where
        T: bitvec::store::BitStore,
    {
        buffer[0..16].store_be(self.network_protocol.to_primitive());
        buffer[16..32].store_be(self.address.len() as u16);
        buffer[32..][..self.address.len() * 8]
            .clone_from_bitslice(self.address.view_bits::<Lsb0>());
    }

    fn deserialize<T>(buffer: &bitvec::slice::BitSlice<bitvec::order::Lsb0, T>) -> Self
    where
        T: bitvec::store::BitStore,
    {
        let length: u16 = buffer[16..32].load_be();

        Self {
            network_protocol: NetworkProtocol::from_primitive(buffer[0..16].load_be()),
            address: ArrayVec::from_iter(
                buffer[32..160]
                    .chunks_exact(8)
                    .take(length as usize)
                    .map(|slice| slice.load()),
            ),
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
                [
                    0x00, 0x01, 0x00, 0x04, 0xC0, 0xA8, 0x00, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00u8,
                ],
                PortAddress {
                    network_protocol: NetworkProtocol::UdpIPv4,
                    address: ArrayVec::from_iter([192, 168, 0, 25]),
                },
            ),
            (
                [
                    0x00, 0x06, 0x00, 0x09, 0x6D, 0x79, 0x20, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00u8,
                ],
                PortAddress {
                    network_protocol: NetworkProtocol::Profinet,
                    address: ArrayVec::from_iter(b"my device".iter().copied()),
                },
            ),
        ];

        for (bit_representation, object_representation) in representations {
            // Test the serialization output
            let mut serialization_buffer = bitarr![const Lsb0, u8; 0; PortAddress::BITSIZE];
            object_representation.serialize(&mut serialization_buffer);
            assert_eq!(serialization_buffer, bit_representation.view_bits::<Lsb0>());

            // Test the deserialization output
            let deserialized_data =
                PortAddress::deserialize(bit_representation.view_bits::<Lsb0>());
            assert_eq!(deserialized_data, object_representation);
        }
    }
}
