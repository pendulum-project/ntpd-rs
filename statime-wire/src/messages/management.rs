use crate::{Error, common::PortIdentity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagementMessage {
    pub target_port_identity: PortIdentity,
    pub starting_boundary_hops: u8,
    pub boundary_hops: u8,
    pub action: ManagementAction,
}

impl ManagementMessage {
    pub(crate) fn content_size(&self) -> usize {
        14
    }

    pub(crate) fn serialize_content(&self, buffer: &mut [u8]) -> Result<(), crate::Error> {
        self.target_port_identity
            .serialize(buffer.get_mut(0..10).ok_or(Error::BufferTooShort)?)?;
        *buffer.get_mut(11).ok_or(Error::BufferTooShort)? = self.starting_boundary_hops;
        *buffer.get_mut(12).ok_or(Error::BufferTooShort)? = self.boundary_hops;
        *buffer.get_mut(13).ok_or(Error::BufferTooShort)? = self.action.to_primitive();

        Ok(())
    }

    pub(crate) fn deserialize_content(buffer: &[u8]) -> Result<Self, crate::Error> {
        if buffer.len() < 14 {
            return Err(Error::BufferTooShort);
        }
        Ok(Self {
            target_port_identity: PortIdentity::deserialize(&buffer[0..10])?,
            starting_boundary_hops: buffer[11],
            boundary_hops: buffer[12],
            action: ManagementAction::from_primitive(buffer[13]),
        })
    }
}

/// See: 15.4.1.6
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::upper_case_acronyms,
    reason = "Match the exact terminology used in IEEE1588.2019"
)]
pub enum ManagementAction {
    Reserved,
    GET,
    SET,
    RESPONSE,
    COMMAND,
    ACKNOWLEDGE,
}

impl ManagementAction {
    pub(crate) fn to_primitive(self) -> u8 {
        match self {
            Self::GET => 0x0,
            Self::SET => 0x1,
            Self::RESPONSE => 0x2,
            Self::COMMAND => 0x3,
            Self::ACKNOWLEDGE => 0x4,
            Self::Reserved => 0x5,
        }
    }

    pub(crate) fn from_primitive(value: u8) -> Self {
        match value {
            0x0 => Self::GET,
            0x1 => Self::SET,
            0x2 => Self::RESPONSE,
            0x3 => Self::COMMAND,
            0x4 => Self::ACKNOWLEDGE,
            0x5..=u8::MAX => Self::Reserved,
        }
    }
}
