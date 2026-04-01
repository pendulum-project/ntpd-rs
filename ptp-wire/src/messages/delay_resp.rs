use crate::{
    Error,
    common::{PortIdentity, WireTimestamp},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelayRespMessage {
    pub receive_timestamp: WireTimestamp,
    pub requesting_port_identity: PortIdentity,
}

impl DelayRespMessage {
    pub(crate) fn content_size(&self) -> usize {
        20
    }

    pub(crate) fn serialize_content(&self, buffer: &mut [u8]) -> Result<(), Error> {
        self.receive_timestamp
            .serialize(buffer.get_mut(0..10).ok_or(Error::BufferTooShort)?)?;
        self.requesting_port_identity
            .serialize(buffer.get_mut(10..20).ok_or(Error::BufferTooShort)?)?;

        Ok(())
    }

    pub(crate) fn deserialize_content(buffer: &[u8]) -> Result<Self, Error> {
        let slice = buffer.get(0..20).ok_or(Error::BufferTooShort)?;
        let receive_timestamp = WireTimestamp::deserialize(&slice[0..10])?;
        let requesting_port_identity = PortIdentity::deserialize(&slice[10..20])?;

        Ok(Self {
            receive_timestamp,
            requesting_port_identity,
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
            DelayRespMessage {
                receive_timestamp: WireTimestamp::new(1_169_232_218, 174_389_936).unwrap(),
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
                DelayRespMessage::deserialize_content(&byte_representation).unwrap();
            assert_eq!(deserialized_data, object_representation);
        }
    }
}
