use crate::{WireFormat, WireFormatError, common::WireTimestamp};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PDelayReqMessage {
    pub(super) origin_timestamp: WireTimestamp,
}

impl PDelayReqMessage {
    pub(crate) fn content_size(&self) -> usize {
        20
    }

    pub(crate) fn serialize_content(
        &self,
        buffer: &mut [u8],
    ) -> Result<(), crate::WireFormatError> {
        if buffer.len() < 20 {
            return Err(WireFormatError::BufferTooShort);
        }

        self.origin_timestamp.serialize(&mut buffer[0..10])?;
        buffer[10..20].fill(0);

        Ok(())
    }

    pub(crate) fn deserialize_content(buffer: &[u8]) -> Result<Self, crate::WireFormatError> {
        let slice = buffer.get(0..20).ok_or(WireFormatError::BufferTooShort)?;

        Ok(Self {
            origin_timestamp: WireTimestamp::deserialize(slice)?,
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
                origin_timestamp: WireTimestamp {
                    seconds: 1169232218,
                    nanos: 174389936,
                },
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
