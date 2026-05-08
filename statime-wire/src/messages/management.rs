use crate::{Error, common::PortIdentity};

/// Management message body
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagementMessage {
    /// Port identity of the port to which this management message applies
    pub target_port_identity: PortIdentity,
    /// Maximum number of times this message can be forwarded by boundary clocks in total.
    pub starting_boundary_hops: u8,
    /// Number of further times this message can be forwarded by a boundary clock.
    pub boundary_hops: u8,
    /// The requested management action.
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

/// Requested action for management of the port, see: 15.4.1.6
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    clippy::upper_case_acronyms,
    reason = "Match the exact terminology used in IEEE1588.2019"
)]
pub enum ManagementAction {
    /// Reserved for future use
    Reserved,
    /// Get the requested values
    GET,
    /// Set the requested values
    SET,
    /// Response to an earlier management request
    RESPONSE,
    /// Request the receiver to perform an action
    COMMAND,
    /// Acknowledgement of an earlier management request.
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
