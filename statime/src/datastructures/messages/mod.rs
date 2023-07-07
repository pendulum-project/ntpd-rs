//! Ptp network messages

pub use announce::*;
use arrayvec::ArrayVec;
pub use delay_req::*;
pub use delay_resp::*;
pub use follow_up::*;
pub use header::*;
pub use message_builder::*;
use num_enum::{IntoPrimitive, TryFromPrimitive};
pub use sync::*;

use self::{
    management::ManagementMessage, p_delay_req::PDelayReqMessage, p_delay_resp::PDelayRespMessage,
    p_delay_resp_follow_up::PDelayRespFollowUpMessage, signalling::SignalingMessage,
};

mod announce;
mod control_field;
mod delay_req;
mod delay_resp;
mod follow_up;
mod header;
mod management;
mod message_builder;
mod p_delay_req;
mod p_delay_resp;
mod p_delay_resp_follow_up;
mod signalling;
mod sync;

pub const MAX_DATA_LEN: usize = 255;

#[derive(Debug, Clone, Copy, TryFromPrimitive, IntoPrimitive, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Sync(SyncMessage),
    DelayReq(DelayReqMessage),
    PDelayReq(PDelayReqMessage),
    PDelayResp(PDelayRespMessage),
    FollowUp(FollowUpMessage),
    DelayResp(DelayRespMessage),
    PDelayRespFollowUp(PDelayRespFollowUpMessage),
    Announce(AnnounceMessage),
    Signaling(SignalingMessage),
    Management(ManagementMessage),
}

impl Message {
    #[allow(unused)]
    pub fn builder() -> MessageBuilder {
        MessageBuilder::new()
    }

    pub fn header(&self) -> &Header {
        match self {
            Message::Sync(m) => &m.header,
            Message::DelayReq(m) => &m.header,
            Message::PDelayReq(m) => &m.header,
            Message::PDelayResp(m) => &m.header,
            Message::FollowUp(m) => &m.header,
            Message::DelayResp(m) => &m.header,
            Message::PDelayRespFollowUp(m) => &m.header,
            Message::Announce(m) => &m.header,
            Message::Signaling(m) => &m.header,
            Message::Management(m) => &m.header,
        }
    }

    /// The byte size on the wire of this message
    pub fn wire_size(&self) -> usize {
        self.header().wire_size() + self.content_size()
    }

    fn content_size(&self) -> usize {
        match self {
            Message::Sync(m) => m.content_size(),
            Message::DelayReq(m) => m.content_size(),
            Message::PDelayReq(m) => m.content_size(),
            Message::PDelayResp(m) => m.content_size(),
            Message::FollowUp(m) => m.content_size(),
            Message::DelayResp(m) => m.content_size(),
            Message::PDelayRespFollowUp(m) => m.content_size(),
            Message::Announce(m) => m.content_size(),
            Message::Signaling(m) => m.content_size(),
            Message::Management(m) => m.content_size(),
        }
    }

    fn content_type(&self) -> MessageType {
        match self {
            Message::Sync(_) => MessageType::Sync,
            Message::DelayReq(_) => MessageType::DelayReq,
            Message::PDelayReq(_) => MessageType::PDelayReq,
            Message::PDelayResp(_) => MessageType::PDelayResp,
            Message::FollowUp(_) => MessageType::FollowUp,
            Message::DelayResp(_) => MessageType::DelayResp,
            Message::PDelayRespFollowUp(_) => MessageType::PDelayRespFollowUp,
            Message::Announce(_) => MessageType::Announce,
            Message::Signaling(_) => MessageType::Signaling,
            Message::Management(_) => MessageType::Management,
        }
    }

    /// Serializes the object into the PTP wire format.
    ///
    /// Returns the used buffer size that contains the message or an error.
    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, super::WireFormatError> {
        let (header, rest) = buffer.split_at_mut(34);

        self.header()
            .serialize_header(self.content_type(), self.content_size(), header)?;

        match self {
            Message::Sync(m) => m.serialize_content(rest)?,
            Message::DelayReq(m) => m.serialize_content(rest)?,
            Message::PDelayReq(m) => m.serialize_content(rest)?,
            Message::PDelayResp(m) => m.serialize_content(rest)?,
            Message::FollowUp(m) => m.serialize_content(rest)?,
            Message::DelayResp(m) => m.serialize_content(rest)?,
            Message::PDelayRespFollowUp(m) => m.serialize_content(rest)?,
            Message::Announce(m) => m.serialize_content(rest)?,
            Message::Signaling(m) => m.serialize_content(rest)?,
            Message::Management(m) => m.serialize_content(rest)?,
        }

        Ok(self.wire_size())
    }

    /// Serializes the message into the PTP wire format.
    ///
    /// Returns a vector with the bytes of the message or an error.
    pub fn serialize_vec(&self) -> Result<ArrayVec<u8, MAX_DATA_LEN>, super::WireFormatError> {
        let mut buffer = ArrayVec::from([0; MAX_DATA_LEN]);
        buffer.truncate(self.wire_size());
        self.serialize(&mut buffer)?;
        Ok(buffer)
    }

    /// Deserializes a message from the PTP wire format.
    ///
    /// Returns the message or an error.
    pub fn deserialize(buffer: &[u8]) -> Result<Self, super::WireFormatError> {
        let header_data = Header::deserialize_header(buffer)?;

        // Skip the header bytes and only keep the content
        let content_buffer = &buffer[34..];

        Ok(match header_data.message_type {
            MessageType::Sync => Message::Sync(SyncMessage::deserialize_content(
                header_data.header,
                content_buffer,
            )?),
            MessageType::DelayReq => Message::DelayReq(DelayReqMessage::deserialize_content(
                header_data.header,
                content_buffer,
            )?),
            MessageType::PDelayReq => Message::PDelayReq(PDelayReqMessage::deserialize_content(
                header_data.header,
                content_buffer,
            )?),
            MessageType::PDelayResp => Message::PDelayResp(PDelayRespMessage::deserialize_content(
                header_data.header,
                content_buffer,
            )?),
            MessageType::FollowUp => Message::FollowUp(FollowUpMessage::deserialize_content(
                header_data.header,
                content_buffer,
            )?),
            MessageType::DelayResp => Message::DelayResp(DelayRespMessage::deserialize_content(
                header_data.header,
                content_buffer,
            )?),
            MessageType::PDelayRespFollowUp => Message::PDelayRespFollowUp(
                PDelayRespFollowUpMessage::deserialize_content(header_data.header, content_buffer)?,
            ),
            MessageType::Announce => Message::Announce(AnnounceMessage::deserialize_content(
                header_data.header,
                content_buffer,
            )?),
            MessageType::Signaling => Message::Signaling(SignalingMessage::deserialize_content(
                header_data.header,
                content_buffer,
            )?),
            MessageType::Management => Message::Management(ManagementMessage::deserialize_content(
                header_data.header,
                content_buffer,
            )?),
        })
    }
}
