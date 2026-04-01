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
use super::{WireFormatError, common::TlvSet};

mod announce;
mod control_field;
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

/// Maximum length of a packet
///
/// This can be used to preallocate buffers that can always fit packets send by
/// `statime`.
pub const MAX_DATA_LEN: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

pub struct EnumConversionError;

impl TryFrom<u8> for MessageType {
    type Error = EnumConversionError;

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
            _ => Err(EnumConversionError),
        }
    }
}

#[cfg(feature = "fuzz")]
pub use fuzz::FuzzMessage;

#[cfg(feature = "fuzz")]
#[allow(missing_docs)] // These are only used for internal fuzzing
mod fuzz {
    use super::Message;
    use crate::{WireFormatError, common::Tlv};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FuzzMessage<'a> {
        inner: Message<'a>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FuzzTlv<'a>(Tlv<'a>);

    impl<'a> FuzzMessage<'a> {
        pub fn deserialize(buffer: &'a [u8]) -> Result<Self, impl std::error::Error> {
            Ok::<FuzzMessage, WireFormatError>(FuzzMessage {
                inner: Message::deserialize(buffer)?,
            })
        }

        pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, impl std::error::Error> {
            self.inner.serialize(buffer)
        }

        pub fn tlv(&self) -> impl Iterator<Item = FuzzTlv<'_>> + '_ {
            self.inner.suffix.tlv().map(FuzzTlv)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Message<'a> {
    pub(crate) header: Header,
    pub(crate) body: MessageBody,
    pub(crate) suffix: TlvSet<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MessageBody {
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

impl MessageBody {
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

    pub(crate) fn serialize(&self, buffer: &mut [u8]) -> Result<usize, super::WireFormatError> {
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

    pub(crate) fn deserialize(
        message_type: MessageType,
        header: &Header,
        buffer: &[u8],
    ) -> Result<Self, super::WireFormatError> {
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

/// Checks whether message is of PTP revision compatible with Statime
#[must_use]
pub fn is_compatible(buffer: &[u8]) -> bool {
    // this ensures that versionPTP in the header is 2
    // it will never happen in PTPv1 packets because this octet is the LSB of
    // versionPTP there
    (buffer.len() >= 2) && (buffer[1] & 0xf) == 2
}

impl<'a> Message<'a> {
    pub(crate) fn header(&self) -> &Header {
        &self.header
    }

    /// The byte size on the wire of this message
    pub(crate) fn wire_size(&self) -> usize {
        self.header.wire_size() + self.body.wire_size() + self.suffix.wire_size()
    }

    /// Serializes the object into the PTP wire format.
    ///
    /// Returns the used buffer size that contains the message or an error.
    pub(crate) fn serialize(&self, buffer: &mut [u8]) -> Result<usize, super::WireFormatError> {
        let (header, rest) = buffer.split_at_mut(34);
        let (body, tlv) = rest.split_at_mut(self.body.wire_size());

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
    /// Returns the message or an error.
    pub(crate) fn deserialize(buffer: &'a [u8]) -> Result<Self, super::WireFormatError> {
        let header_data = Header::deserialize_header(buffer)?;

        if header_data.message_length < 34 {
            return Err(WireFormatError::Invalid);
        }

        // Ensure we have the entire message and ignore potential padding
        // Skip the header bytes and only keep the content
        let content_buffer = buffer
            .get(34..(header_data.message_length as usize))
            .ok_or(WireFormatError::BufferTooShort)?;

        let body = MessageBody::deserialize(
            header_data.message_type,
            &header_data.header,
            content_buffer,
        )?;

        let tlv_buffer = &content_buffer
            .get(body.wire_size()..)
            .ok_or(super::WireFormatError::BufferTooShort)?;
        let suffix = TlvSet::deserialize(tlv_buffer)?;

        Ok(Message {
            header: header_data.header,
            body,
            suffix,
        })
    }
}
