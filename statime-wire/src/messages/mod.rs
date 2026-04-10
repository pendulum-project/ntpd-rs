//! Ptp network messages

pub(crate) use announce::*;
pub(crate) use delay_req::*;
pub(crate) use delay_resp::*;
pub(crate) use follow_up::*;
pub use header::*;
pub(crate) use p_delay_req::*;
pub(crate) use p_delay_resp::*;
pub(crate) use p_delay_resp_follow_up::*;
pub(crate) use sync::*;

use self::{management::ManagementMessage, signalling::SignalingMessage};
use super::{Error, common::TlvSet};

mod announce;
mod delay_req;
mod delay_resp;
mod follow_up;
mod header;
mod management;
mod p_delay_req;
mod p_delay_resp;
mod p_delay_resp_follow_up;
mod signalling;
mod sync;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum MessageType {
    Sync = 0x0,
    DelayReq = 0x1,
    PDelayReq = 0x2,
    PDelayResp = 0x3,
    FollowUp = 0x8,
    DelayResp = 0x9,
    PDelayRespFollowUp = 0xa,
    Announce = 0xb,
    Signaling = 0xc,
    Management = 0xd,
}

impl TryFrom<u8> for MessageType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use MessageType::{
            Announce, DelayReq, DelayResp, FollowUp, Management, PDelayReq, PDelayResp,
            PDelayRespFollowUp, Signaling, Sync,
        };

        match value {
            0x0 => Ok(Sync),
            0x1 => Ok(DelayReq),
            0x2 => Ok(PDelayReq),
            0x3 => Ok(PDelayResp),
            0x8 => Ok(FollowUp),
            0x9 => Ok(DelayResp),
            0xa => Ok(PDelayRespFollowUp),
            0xb => Ok(Announce),
            0xc => Ok(Signaling),
            0xd => Ok(Management),
            _ => Err(Error::Invalid),
        }
    }
}

/// A PTP version 2 Message.
///
/// For more details, see the individual parts, as well as *IEEE1588-2019 clause 13*
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<'a> {
    /// The header of the message.
    pub header: Header,
    /// The main data in the message body.
    pub body: MessageBody,
    /// Any extensions sent along with the message.
    pub suffix: TlvSet<'a>,
}

/// The main body of a message.
///
/// For more details, see *IEEE1588-2019 section 13.3*
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageBody {
    /// A synchronization message.
    Sync(SyncMessage),
    /// A delay request message.
    DelayReq(DelayReqMessage),
    /// A peer delay request message.
    PDelayReq(PDelayReqMessage),
    /// A peer delay response message.
    PDelayResp(PDelayRespMessage),
    /// A followup for a two-step timing message.
    FollowUp(FollowUpMessage),
    /// A delay response message.
    DelayResp(DelayRespMessage),
    /// A peer delay response follow up message used for
    /// two step timing of peer delay response messages.
    PDelayRespFollowUp(PDelayRespFollowUpMessage),
    /// An announce message
    Announce(AnnounceMessage),
    /// A signalling message.
    ///
    /// These messages are used purely as a vehicle for TLVs.
    Signaling(SignalingMessage),
    /// A management message.
    Management(ManagementMessage),
}

impl MessageBody {
    /// The size this message will have once encoded for transmission.
    fn wire_size(&self) -> usize {
        match &self {
            MessageBody::Sync(m) => m.content_size(),
            MessageBody::DelayReq(m) => m.content_size(),
            MessageBody::PDelayReq(m) => m.content_size(),
            MessageBody::PDelayResp(m) => m.content_size(),
            MessageBody::FollowUp(m) => m.content_size(),
            MessageBody::DelayResp(m) => m.content_size(),
            MessageBody::PDelayRespFollowUp(m) => m.content_size(),
            MessageBody::Announce(m) => m.content_size(),
            MessageBody::Signaling(m) => m.content_size(),
            MessageBody::Management(m) => m.content_size(),
        }
    }

    fn content_type(&self) -> MessageType {
        match self {
            MessageBody::Sync(_) => MessageType::Sync,
            MessageBody::DelayReq(_) => MessageType::DelayReq,
            MessageBody::PDelayReq(_) => MessageType::PDelayReq,
            MessageBody::PDelayResp(_) => MessageType::PDelayResp,
            MessageBody::FollowUp(_) => MessageType::FollowUp,
            MessageBody::DelayResp(_) => MessageType::DelayResp,
            MessageBody::PDelayRespFollowUp(_) => MessageType::PDelayRespFollowUp,
            MessageBody::Announce(_) => MessageType::Announce,
            MessageBody::Signaling(_) => MessageType::Signaling,
            MessageBody::Management(_) => MessageType::Management,
        }
    }

    /// Serialize this message into a buffer of bytes.
    pub(crate) fn serialize(&self, buffer: &mut [u8]) -> Result<usize, super::Error> {
        match &self {
            MessageBody::Sync(m) => m.serialize_content(buffer)?,
            MessageBody::DelayReq(m) => m.serialize_content(buffer)?,
            MessageBody::PDelayReq(m) => m.serialize_content(buffer)?,
            MessageBody::PDelayResp(m) => m.serialize_content(buffer)?,
            MessageBody::FollowUp(m) => m.serialize_content(buffer)?,
            MessageBody::DelayResp(m) => m.serialize_content(buffer)?,
            MessageBody::PDelayRespFollowUp(m) => m.serialize_content(buffer)?,
            MessageBody::Announce(m) => m.serialize_content(buffer)?,
            MessageBody::Signaling(m) => m.serialize_content(buffer)?,
            MessageBody::Management(m) => m.serialize_content(buffer)?,
        }

        Ok(self.wire_size())
    }

    /// Deserialize a message from a received buffer of bytes.
    pub(crate) fn deserialize(
        message_type: MessageType,
        header: &Header,
        buffer: &[u8],
    ) -> Result<Self, super::Error> {
        let body = match message_type {
            MessageType::Sync => MessageBody::Sync(SyncMessage::deserialize_content(buffer)?),
            MessageType::DelayReq => {
                MessageBody::DelayReq(DelayReqMessage::deserialize_content(buffer)?)
            }
            MessageType::PDelayReq => {
                MessageBody::PDelayReq(PDelayReqMessage::deserialize_content(buffer)?)
            }
            MessageType::PDelayResp => {
                MessageBody::PDelayResp(PDelayRespMessage::deserialize_content(buffer)?)
            }
            MessageType::FollowUp => {
                MessageBody::FollowUp(FollowUpMessage::deserialize_content(buffer)?)
            }
            MessageType::DelayResp => {
                MessageBody::DelayResp(DelayRespMessage::deserialize_content(buffer)?)
            }
            MessageType::PDelayRespFollowUp => MessageBody::PDelayRespFollowUp(
                PDelayRespFollowUpMessage::deserialize_content(buffer)?,
            ),
            MessageType::Announce => {
                MessageBody::Announce(AnnounceMessage::deserialize_content(*header, buffer)?)
            }
            MessageType::Signaling => {
                MessageBody::Signaling(SignalingMessage::deserialize_content(buffer)?)
            }
            MessageType::Management => {
                MessageBody::Management(ManagementMessage::deserialize_content(buffer)?)
            }
        };

        Ok(body)
    }
}

/// Checks whether message is of a PTP revision compatible with this crate.
#[must_use]
pub fn is_compatible(buffer: &[u8]) -> bool {
    // this ensures that versionPTP in the header is 2
    // it will never happen in PTPv1 packets because this octet is the LSB of
    // versionPTP there
    (buffer.len() >= 2) && (buffer[1] & 0xf) == 2
}

impl<'a> Message<'a> {
    /// The byte size on the wire of this message
    #[must_use]
    pub fn wire_size(&self) -> usize {
        self.header.wire_size() + self.body.wire_size() + self.suffix.wire_size()
    }

    /// Serializes the object into the PTP wire format.
    ///
    /// Returns the ammount of buffer used to serialize the message.
    ///
    /// # Errors
    /// The function fails when:
    ///  - The message total size or any of its dynamically sized parts exceed 2^16 bytes
    ///  - The message does not fit into the provided buffer.
    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, super::Error> {
        let (header, rest) = buffer
            .split_at_mut_checked(34)
            .ok_or(Error::BufferTooShort)?;
        let (body, tlv) = rest
            .split_at_mut_checked(self.body.wire_size())
            .ok_or(Error::BufferTooShort)?;

        self.header.serialize_header(
            self.body.content_type(),
            self.body.wire_size() + self.suffix.wire_size(),
            header,
        )?;

        self.body.serialize(body)?;

        self.suffix.serialize(tlv)?;

        Ok(self.wire_size())
    }

    /// Deserializes a message from the PTP wire format.
    ///
    /// # Errors
    /// This returns an error when the provided buffer does not contain a valid
    /// PTP message, or when the provided message is incomplete.
    pub fn deserialize(buffer: &'a [u8]) -> Result<Self, super::Error> {
        let header_data = Header::deserialize_header(buffer)?;

        if header_data.message_length < 34 {
            return Err(Error::Invalid);
        }

        // Ensure we have the entire message and ignore potential padding
        // Skip the header bytes and only keep the content
        let content_buffer = buffer
            .get(34..(header_data.message_length as usize))
            .ok_or(Error::BufferTooShort)?;

        let body = MessageBody::deserialize(
            header_data.message_type,
            &header_data.header,
            content_buffer,
        )?;

        let tlv_buffer = &content_buffer
            .get(body.wire_size()..)
            .ok_or(super::Error::BufferTooShort)?;
        let suffix = TlvSet::deserialize(tlv_buffer)?;

        Ok(Message {
            header: header_data.header,
            body,
            suffix,
        })
    }
}
