use num_enum::{IntoPrimitive, TryFromPrimitive};

mod announce;
mod control_field;
mod delay_req;
mod delay_resp;
mod flag_field;
mod follow_up;
mod header;
mod sync;

pub use announce::*;
pub use control_field::*;
pub use delay_req::*;
pub use delay_resp::*;
pub use flag_field::*;
pub use follow_up::*;
pub use header::*;
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

impl WireFormat for Message {
    const STATIC_SIZE: Option<usize> = None;

    fn serialize_vec(&self) -> Result<Vec<u8>, super::WireFormatError> {
        match self {
            Message::Sync(m) => m.serialize_vec(),
            Message::DelayReq(m) => m.serialize_vec(),
            Message::PDelayReq(_) => todo!(),
            Message::PDelayResp(_) => todo!(),
            Message::FollowUp(m) => m.serialize_vec(),
            Message::DelayResp(m) => m.serialize_vec(),
            Message::PDelayRespFollowUp(_) => todo!(),
            Message::Announce(m) => m.serialize_vec(),
            Message::Signaling(_) => todo!(),
            Message::Management(_) => todo!(),
        }
    }

    fn serialize(&self, buffer: &mut [u8]) -> Result<usize, super::WireFormatError> {
        match self {
            Message::Sync(m) => m.serialize(buffer),
            Message::DelayReq(m) => m.serialize(buffer),
            Message::PDelayReq(_) => todo!(),
            Message::PDelayResp(_) => todo!(),
            Message::FollowUp(m) => m.serialize(buffer),
            Message::DelayResp(m) => m.serialize(buffer),
            Message::PDelayRespFollowUp(_) => todo!(),
            Message::Announce(m) => m.serialize(buffer),
            Message::Signaling(_) => todo!(),
            Message::Management(_) => todo!(),
        }
    }

    fn deserialize(buffer: &[u8]) -> Result<(Self, usize), super::WireFormatError> {
        let header = Header::deserialize(buffer)?.0;

        let message = match header.message_type {
            MessageType::Sync => Self::Sync(SyncMessage::deserialize(buffer)?.0),
            MessageType::DelayReq => Self::DelayReq(DelayReqMessage::deserialize(buffer)?.0),
            MessageType::PDelayReq => Self::PDelayReq(header),
            MessageType::PDelayResp => Self::PDelayResp(header),
            MessageType::FollowUp => Self::FollowUp(FollowUpMessage::deserialize(buffer)?.0),
            MessageType::DelayResp => Self::DelayResp(DelayRespMessage::deserialize(buffer)?.0),
            MessageType::PDelayRespFollowUp => Self::PDelayRespFollowUp(header),
            MessageType::Announce => Self::Announce(AnnounceMessage::deserialize(buffer)?.0),
            MessageType::Signaling => Self::Signaling(header),
            MessageType::Management => Self::Management(header),
        };

        Ok((message, header.message_length as usize))
    }
}
