use crate::{Error, common::Timestamp};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PDelayReqMessage {
    pub origin_timestamp: Timestamp,
}

impl PDelayReqMessage {
    pub(crate) fn content_size(&self) -> usize {
        20
    }

    pub(crate) fn serialize_content(&self, buffer: &mut [u8]) -> Result<(), crate::Error> {
        if buffer.len() < 20 {
            return Err(Error::BufferTooShort);
        }

        self.origin_timestamp.serialize(&mut buffer[0..10])?;
        buffer[10..20].fill(0);

        Ok(())
    }

    pub(crate) fn deserialize_content(buffer: &[u8]) -> Result<Self, crate::Error> {
        let slice = buffer.get(0..20).ok_or(Error::BufferTooShort)?;

        Ok(Self {
            origin_timestamp: Timestamp::deserialize(slice)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_wireformat() {
        let representations = [(
            [
                0x00, 0x00, 0x45, 0xb1, 0x11, 0x5a, 0x0a, 0x64, 0xfa, 0xb0, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            PDelayReqMessage {
                origin_timestamp: Timestamp::new(1_169_232_218, 174_389_936).unwrap(),
            },
        )];

        for (byte_representation, object_representation) in representations {
            // Test the serialization output
            let mut serialization_buffer = [0; 20];
            object_representation
                .serialize_content(&mut serialization_buffer)
                .unwrap();
            assert_eq!(serialization_buffer, byte_representation);

            // Test the deserialization output
            let deserialized_data =
                PDelayReqMessage::deserialize_content(&byte_representation).unwrap();
            assert_eq!(deserialized_data, object_representation);
        }
    }
}
