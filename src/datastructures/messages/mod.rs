use getset::CopyGetters;
use num_enum::{IntoPrimitive, TryFromPrimitive};

mod announce;
mod control_field;
mod delay_req;
mod delay_resp;
mod flag_field;
mod follow_up;
mod header;
mod message_builder;
mod sync;

pub use announce::*;
pub use control_field::*;
pub use delay_req::*;
pub use delay_resp::*;
pub use flag_field::*;
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
pub enum MessageContent {
    Sync(SyncMessage),
    DelayReq(DelayReqMessage),
    PDelayReq,  // TODO
    PDelayResp, // TODO
    FollowUp(FollowUpMessage),
    DelayResp(DelayRespMessage),
    PDelayRespFollowUp, // TODO
    Announce(AnnounceMessage),
    Signaling,  // TODO
    Management, // TODO
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, CopyGetters)]
#[getset(get_copy = "pub")]
pub struct Message {
    header: Header,
    content: MessageContent,
}

impl Message {
    pub fn builder() -> MessageBuilder {
        MessageBuilder::new()
    }
}

impl WireFormat for Message {
    fn wire_size(&self) -> usize {
        let header_length = self.header.wire_size();
        let content_length = match self.content {
            MessageContent::Sync(m) => m.wire_size(),
            MessageContent::DelayReq(m) => m.wire_size(),
            MessageContent::PDelayReq => todo!(),
            MessageContent::PDelayResp => todo!(),
            MessageContent::FollowUp(m) => m.wire_size(),
            MessageContent::DelayResp(m) => m.wire_size(),
            MessageContent::PDelayRespFollowUp => todo!(),
            MessageContent::Announce(m) => m.wire_size(),
            MessageContent::Signaling => todo!(),
            MessageContent::Management => todo!(),
        };

        header_length + content_length
    }

    fn serialize(&self, buffer: &mut [u8]) -> Result<(), super::WireFormatError> {
        self.header.serialize(&mut buffer[0..34])?;
        match self.content {
            MessageContent::Sync(m) => m.serialize(&mut buffer[34..]),
            MessageContent::DelayReq(m) => m.serialize(&mut buffer[34..]),
            MessageContent::PDelayReq => todo!(),
            MessageContent::PDelayResp => todo!(),
            MessageContent::FollowUp(m) => m.serialize(&mut buffer[34..]),
            MessageContent::DelayResp(m) => m.serialize(&mut buffer[34..]),
            MessageContent::PDelayRespFollowUp => todo!(),
            MessageContent::Announce(m) => m.serialize(&mut buffer[34..]),
            MessageContent::Signaling => todo!(),
            MessageContent::Management => todo!(),
        }
    }

    fn deserialize(buffer: &[u8]) -> Result<Self, super::WireFormatError> {
        let header = Header::deserialize(buffer)?;

        // Skip the header bytes and only keep the content
        let content_buffer = &buffer[34..];

        let content = match header.message_type() {
            MessageType::Sync => MessageContent::Sync(SyncMessage::deserialize(content_buffer)?),
            MessageType::DelayReq => {
                MessageContent::DelayReq(DelayReqMessage::deserialize(content_buffer)?)
            }
            MessageType::PDelayReq => MessageContent::PDelayReq,
            MessageType::PDelayResp => MessageContent::PDelayResp,
            MessageType::FollowUp => {
                MessageContent::FollowUp(FollowUpMessage::deserialize(content_buffer)?)
            }
            MessageType::DelayResp => {
                MessageContent::DelayResp(DelayRespMessage::deserialize(content_buffer)?)
            }
            MessageType::PDelayRespFollowUp => MessageContent::PDelayRespFollowUp,
            MessageType::Announce => {
                MessageContent::Announce(AnnounceMessage::deserialize(content_buffer)?)
            }
            MessageType::Signaling => MessageContent::Signaling,
            MessageType::Management => MessageContent::Management,
        };

        Ok(Self { header, content })
    }
}
