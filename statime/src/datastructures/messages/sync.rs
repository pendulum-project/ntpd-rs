use super::Header;
use crate::datastructures::{common::WireTimestamp, WireFormat, WireFormatError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SyncMessage {
    pub(crate) header: Header,
    pub(crate) origin_timestamp: WireTimestamp,
}

impl SyncMessage {
    pub(crate) fn content_size(&self) -> usize {
        10
    }

    pub(crate) fn serialize_content(&self, buffer: &mut [u8]) -> Result<(), WireFormatError> {
        self.origin_timestamp.serialize(&mut buffer[0..10])?;
        Ok(())
    }

    pub(crate) fn deserialize_content(
        header: Header,
        buffer: &[u8],
    ) -> Result<Self, WireFormatError> {
        match buffer.get(0..10) {
            None => Err(WireFormatError::BufferTooShort),
            Some(slice) => Ok(Self {
                header,
                origin_timestamp: WireTimestamp::deserialize(slice)?,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_wireformat() {
        let representations = [(
            [0x00, 0x00, 0x45, 0xb1, 0x11, 0x5a, 0x0a, 0x64, 0xfa, 0xb0],
            SyncMessage {
                header: Header::default(),
                origin_timestamp: WireTimestamp {
                    seconds: 1169232218,
                    nanos: 174389936,
                },
            },
        )];

        for (byte_representation, object_representation) in representations {
            // Test the serialization output
            let mut serialization_buffer = [0; 10];
            object_representation
                .serialize_content(&mut serialization_buffer)
                .unwrap();
            assert_eq!(serialization_buffer, byte_representation);

            // Test the deserialization output
            let deserialized_data =
                SyncMessage::deserialize_content(Header::default(), &byte_representation).unwrap();
            assert_eq!(deserialized_data, object_representation);
        }
    }
}
