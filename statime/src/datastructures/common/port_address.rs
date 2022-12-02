use super::network_protocol::NetworkProtocol;
use crate::datastructures::{WireFormat, WireFormatError};
use arrayvec::ArrayVec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortAddress {
    pub network_protocol: NetworkProtocol,
    pub address: ArrayVec<u8, 16>,
}

impl WireFormat for PortAddress {
    fn wire_size(&self) -> usize {
        4 + self.address.len()
    }

    fn serialize(&self, buffer: &mut [u8]) -> Result<(), WireFormatError> {
        buffer[0..2].copy_from_slice(&self.network_protocol.to_primitive().to_be_bytes());
        buffer[2..4].copy_from_slice(&(self.address.len() as u16).to_be_bytes());
        buffer[4..][..self.address.len()].clone_from_slice(&self.address);
        Ok(())
    }

    fn deserialize(buffer: &[u8]) -> Result<Self, WireFormatError> {
        let length: usize = u16::from_be_bytes(buffer[2..4].try_into().unwrap()) as usize;

        Ok(Self {
            network_protocol: NetworkProtocol::from_primitive(u16::from_be_bytes(
                buffer[0..2].try_into().unwrap(),
            )),
            address: ArrayVec::from_iter(buffer[4..][..length].iter().copied()),
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

        for (byte_representation, object_representation) in representations {
            // Test the serialization output
            let mut serialization_buffer = [0; 20];
            object_representation
                .serialize(&mut serialization_buffer)
                .unwrap();
            assert_eq!(serialization_buffer, byte_representation);

            // Test the deserialization output
            let deserialized_data = PortAddress::deserialize(&byte_representation).unwrap();
            assert_eq!(deserialized_data, object_representation);
        }
    }
}
