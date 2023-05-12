use arrayvec::ArrayVec;

use super::Header;
use crate::datastructures::{
    common::{PortIdentity, TLV},
    WireFormat, WireFormatError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalingMessage {
    pub(super) header: Header,
    pub(super) target_port_identity: PortIdentity,

    pub(super) value: ArrayVec<TLV, { Self::CAPACITY }>,
}

impl SignalingMessage {
    // TODO: determine the best max length value
    const CAPACITY: usize = 4;

    pub fn content_size(&self) -> usize {
        10
    }

    pub fn serialize_content(&self, buffer: &mut [u8]) -> Result<(), WireFormatError> {
        if buffer.len() < 11 {
            return Err(WireFormatError::BufferTooShort);
        }

        let (left, mut buffer) = buffer.split_at_mut(10);

        self.target_port_identity.serialize(left)?;

        for tlv in &self.value {
            let width = tlv.wire_size();

            tlv.serialize(buffer)?;

            buffer = &mut buffer[width..];
        }

        Ok(())
    }

    pub fn deserialize_content(header: Header, buffer: &[u8]) -> Result<Self, WireFormatError> {
        let identity_bytes = buffer.get(0..10).ok_or(WireFormatError::BufferTooShort)?;
        let target_port_identity = PortIdentity::deserialize(identity_bytes)?;

        let mut buffer = &buffer[10..];

        let mut tlvs = ArrayVec::<TLV, { Self::CAPACITY }>::new();
        while buffer.len() > 4 {
            let tlv = TLV::deserialize(buffer)?;

            buffer = &buffer[tlv.wire_size()..];

            tlvs.try_push(tlv)
                .map_err(|_| WireFormatError::CapacityError)?;
        }

        Ok(Self {
            header,
            target_port_identity,
            value: tlvs,
        })
    }
}
