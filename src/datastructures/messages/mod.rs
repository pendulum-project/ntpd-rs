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
pub use control_field::*;
pub use delay_req::*;
pub use delay_resp::*;
pub use follow_up::*;
pub use header::*;
pub use message_builder::*;
pub use sync::*;

use super::WireFormat;

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
}

impl WireFormat for Message {
    fn wire_size(&self) -> usize {
        let header_length = self.header().wire_size();
        let content_length = match self {
            Message::Sync(m) => m.wire_size(),
            Message::DelayReq(m) => m.wire_size(),
            Message::PDelayReq(_) => todo!(),
            Message::PDelayResp(_) => todo!(),
            Message::FollowUp(m) => m.wire_size(),
            Message::DelayResp(m) => m.wire_size(),
            Message::PDelayRespFollowUp(_) => todo!(),
            Message::Announce(m) => m.wire_size(),
            Message::Signaling(_) => todo!(),
            Message::Management(_) => todo!(),
        };

        header_length + content_length
    }

    fn serialize(&self, buffer: &mut [u8]) -> Result<(), super::WireFormatError> {
        self.header().serialize(&mut buffer[0..34])?;
        match self {
            Message::Sync(m) => m.serialize(&mut buffer[34..]),
            Message::DelayReq(m) => m.serialize(&mut buffer[34..]),
            Message::PDelayReq(_) => todo!(),
            Message::PDelayResp(_) => todo!(),
            Message::FollowUp(m) => m.serialize(&mut buffer[34..]),
            Message::DelayResp(m) => m.serialize(&mut buffer[34..]),
            Message::PDelayRespFollowUp(_) => todo!(),
            Message::Announce(m) => m.serialize(&mut buffer[34..]),
            Message::Signaling(_) => todo!(),
            Message::Management(_) => todo!(),
        }
    }

    fn deserialize(buffer: &[u8]) -> Result<Self, super::WireFormatError> {
        let header = Header::deserialize(buffer)?;

        // Skip the header bytes and only keep the content
        let content_buffer = &buffer[34..];

        Ok(match header.message_type() {
            MessageType::Sync => {
                let mut content = SyncMessage::deserialize(content_buffer)?;
                content.header = header;
                Message::Sync(content)
            }
            MessageType::DelayReq => {
                let mut content = DelayReqMessage::deserialize(content_buffer)?;
                content.header = header;
                Message::DelayReq(content)
            }
            MessageType::PDelayReq => Message::PDelayReq(header),
            MessageType::PDelayResp => Message::PDelayResp(header),
            MessageType::FollowUp => {
                let mut content = FollowUpMessage::deserialize(content_buffer)?;
                content.header = header;
                Message::FollowUp(content)
            }
            MessageType::DelayResp => {
                let mut content = DelayRespMessage::deserialize(content_buffer)?;
                content.header = header;
                Message::DelayResp(content)
            }
            MessageType::PDelayRespFollowUp => Message::PDelayRespFollowUp(header),
            MessageType::Announce => {
                let mut content = AnnounceMessage::deserialize(content_buffer)?;
                content.header = header;
                Message::Announce(content)
            }
            MessageType::Signaling => Message::Signaling(header),
            MessageType::Management => Message::Management(header),
        })
    }
}
