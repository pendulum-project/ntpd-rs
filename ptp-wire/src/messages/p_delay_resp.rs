use crate::{
    Error,
    common::{PortIdentity, Timestamp},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PDelayRespMessage {
    pub request_receive_timestamp: Timestamp,
    pub requesting_port_identity: PortIdentity,
}

impl PDelayRespMessage {
    pub(crate) fn content_size(&self) -> usize {
        20
    }

    pub(crate) fn serialize_content(&self, buffer: &mut [u8]) -> Result<(), crate::Error> {
        if buffer.len() < 20 {
            return Err(Error::BufferTooShort);
        }
        self.request_receive_timestamp
            .serialize(&mut buffer[0..10])?;
        self.requesting_port_identity
            .serialize(&mut buffer[10..20])?;

        Ok(())
    }

    pub(crate) fn deserialize_content(buffer: &[u8]) -> Result<Self, crate::Error> {
        if buffer.len() < 20 {
            return Err(Error::BufferTooShort);
        }
        Ok(Self {
            request_receive_timestamp: Timestamp::deserialize(&buffer[0..10])?,
            requesting_port_identity: PortIdentity::deserialize(&buffer[10..20])?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{ClockIdentity, PortIdentity};

    #[test]
    fn timestamp_wireformat() {
        let representations = [(
            [
                0x00, 0x00, 0x45, 0xb1, 0x11, 0x5a, 0x0a, 0x64, 0xfa, 0xb0, 0x01, 0x02, 0x03, 0x04,
                0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            ],
            PDelayRespMessage {
                request_receive_timestamp: Timestamp::new(1_169_232_218, 174_389_936).unwrap(),
                requesting_port_identity: PortIdentity {
                    clock_identity: ClockIdentity([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
                    port_number: 0x090a,
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
                PDelayRespMessage::deserialize_content(&byte_representation).unwrap();
            assert_eq!(deserialized_data, object_representation);
        }
    }
}
