use crate::{Error, common::WireTimestamp};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncMessage {
    pub origin_timestamp: WireTimestamp,
}

impl SyncMessage {
    pub(crate) fn content_size(&self) -> usize {
        10
    }

    pub(crate) fn serialize_content(&self, buffer: &mut [u8]) -> Result<(), Error> {
        self.origin_timestamp
            .serialize(buffer.get_mut(0..10).ok_or(Error::BufferTooShort)?)?;
        Ok(())
    }

    pub(crate) fn deserialize_content(buffer: &[u8]) -> Result<Self, Error> {
        match buffer.get(0..10) {
            None => Err(Error::BufferTooShort),
            Some(slice) => Ok(Self {
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
                origin_timestamp: WireTimestamp::new(1_169_232_218, 174_389_936).unwrap(),
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
            let deserialized_data = SyncMessage::deserialize_content(&byte_representation).unwrap();
            assert_eq!(deserialized_data, object_representation);
        }
    }
}
