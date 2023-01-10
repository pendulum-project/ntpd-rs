//! Ptp network messages

use alloc::vec::Vec;

use num_enum::{IntoPrimitive, TryFromPrimitive};

mod announce;
mod control_field;
mod delay_req;
mod delay_resp;
mod follow_up;
mod header;
mod message_builder;
mod sync;

pub use announce::*;
pub use delay_req::*;
pub use delay_resp::*;
pub use follow_up::*;
pub use header::*;
pub use message_builder::*;
pub use sync::*;

#[derive(Debug, Clone, Copy, TryFromPrimitive, IntoPrimitive, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Sync = 0x0,
    DelayReq = 0x1,
    PDelayReq = 0x2,
    PDelayResp = 0x3,
    FollowUp = 0x8,
    DelayResp = 0x9,
    PDelayRespFollowUp = 0xA,
    Announce = 0xB,
    Signaling = 0xC,
    Management = 0xD,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Message {
    Sync(SyncMessage),
    DelayReq(DelayReqMessage),
    PDelayReq(Header),  // TODO
    PDelayResp(Header), // TODO
    FollowUp(FollowUpMessage),
    DelayResp(DelayRespMessage),
    PDelayRespFollowUp(Header), // TODO
    Announce(AnnounceMessage),
    Signaling(Header),  // TODO
    Management(Header), // TODO
}

impl Message {
    pub fn builder() -> MessageBuilder {
        MessageBuilder::new()
    }

    pub fn header(&self) -> &Header {
        match self {
            Message::Sync(m) => &m.header,
            Message::DelayReq(m) => &m.header,
            Message::PDelayReq(h) => h,
            Message::PDelayResp(h) => h,
            Message::FollowUp(m) => &m.header,
            Message::DelayResp(m) => &m.header,
            Message::PDelayRespFollowUp(h) => h,
            Message::Announce(m) => &m.header,
            Message::Signaling(h) => h,
            Message::Management(h) => h,
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
            Message::PDelayReq(_) => todo!(),
            Message::PDelayResp(_) => todo!(),
            Message::FollowUp(m) => m.content_size(),
            Message::DelayResp(m) => m.content_size(),
            Message::PDelayRespFollowUp(_) => todo!(),
            Message::Announce(m) => m.content_size(),
            Message::Signaling(_) => todo!(),
            Message::Management(_) => todo!(),
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
    pub fn serialize(&self, buffer: &mut [u8]) -> Result<(), super::WireFormatError> {
        self.header().serialize_header(
            self.content_type(),
            self.content_size(),
            &mut buffer[0..34],
        )?;
        match self {
            Message::Sync(m) => m.serialize_content(&mut buffer[34..]),
            Message::DelayReq(m) => m.serialize_content(&mut buffer[34..]),
            Message::PDelayReq(_) => todo!(),
            Message::PDelayResp(_) => todo!(),
            Message::FollowUp(m) => m.serialize_content(&mut buffer[34..]),
            Message::DelayResp(m) => m.serialize_content(&mut buffer[34..]),
            Message::PDelayRespFollowUp(_) => todo!(),
            Message::Announce(m) => m.serialize_content(&mut buffer[34..]),
            Message::Signaling(_) => todo!(),
            Message::Management(_) => todo!(),
        }
    }

    /// Serializes the message into the PTP wire format.
    ///
    /// Returns a vector with the bytes of the message or an error.
    pub fn serialize_vec(&self) -> Result<Vec<u8>, super::WireFormatError> {
        let mut buffer = vec![0; self.wire_size()];
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
            MessageType::PDelayReq => Message::PDelayReq(header_data.header),
            MessageType::PDelayResp => Message::PDelayResp(header_data.header),
            MessageType::FollowUp => Message::FollowUp(FollowUpMessage::deserialize_content(
                header_data.header,
                content_buffer,
            )?),
            MessageType::DelayResp => Message::DelayResp(DelayRespMessage::deserialize_content(
                header_data.header,
                content_buffer,
            )?),
            MessageType::PDelayRespFollowUp => Message::PDelayRespFollowUp(header_data.header),
            MessageType::Announce => Message::Announce(AnnounceMessage::deserialize_content(
                header_data.header,
                content_buffer,
            )?),
            MessageType::Signaling => Message::Signaling(header_data.header),
            MessageType::Management => Message::Management(header_data.header),
        })
    }
}
