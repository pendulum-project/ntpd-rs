use crate::datastructures::{common::PortIdentity, WireFormat, WireFormatError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignalingMessage {
    pub(super) target_port_identity: PortIdentity,
}

impl SignalingMessage {
    pub(crate) fn content_size(&self) -> usize {
        10
    }

    pub(crate) fn serialize_content(&self, buffer: &mut [u8]) -> Result<(), WireFormatError> {
        if buffer.len() < 11 {
            return Err(WireFormatError::BufferTooShort);
        }

        let (left, _) = buffer.split_at_mut(10);

        self.target_port_identity.serialize(left)?;

        Ok(())
    }

    pub(crate) fn deserialize_content(buffer: &[u8]) -> Result<Self, WireFormatError> {
        let identity_bytes = buffer.get(0..10).ok_or(WireFormatError::BufferTooShort)?;
        let target_port_identity = PortIdentity::deserialize(identity_bytes)?;

        Ok(Self {
            target_port_identity,
        })
    }
}
