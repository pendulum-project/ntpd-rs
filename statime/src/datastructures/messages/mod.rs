//! Ptp network messages

pub(crate) use announce::*;
use arrayvec::ArrayVec;
pub(crate) use delay_req::*;
pub(crate) use delay_resp::*;
pub(crate) use follow_up::*;
pub use header::*;
pub(crate) use sync::*;

use self::{
    management::ManagementMessage, p_delay_req::PDelayReqMessage, p_delay_resp::PDelayRespMessage,
    p_delay_resp_follow_up::PDelayRespFollowUpMessage, signalling::SignalingMessage,
};
use super::{
    common::{PortIdentity, TimeInterval, Tlv, WireTimestamp},
    datasets::DefaultDS,
};
use crate::{ptp_instance::PtpInstanceState, Interval, LeapIndicator, Time};

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

pub const MAX_DATA_LEN: usize = 255;

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

pub struct EnumConversionError(u8);

impl TryFrom<u8> for MessageType {
    type Error = EnumConversionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use MessageType::*;

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
            _ => Err(EnumConversionError(value)),
        }
    }
}

#[cfg(feature = "fuzz")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzMessage {
    inner: Message,
}

#[cfg(feature = "fuzz")]
impl FuzzMessage {
    pub fn deserialize(buffer: &[u8]) -> Result<Self, impl std::error::Error> {
        Ok::<FuzzMessage, super::WireFormatError>(FuzzMessage {
            inner: Message::deserialize(buffer)?,
        })
    }

    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, impl std::error::Error> {
        self.inner.serialize(buffer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Message {
    pub(crate) header: Header,
    pub(crate) body: MessageBody,
    pub(crate) suffix: ArrayVec<Tlv, 4>,
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

fn base_header(default_ds: &DefaultDS, port_identity: PortIdentity, sequence_id: u16) -> Header {
    Header {
        sdo_id: default_ds.sdo_id,
        domain_number: default_ds.domain_number,
        source_port_identity: port_identity,
        sequence_id,
        ..Default::default()
    }
}

impl Message {
    pub(crate) fn sync(
        default_ds: &DefaultDS,
        port_identity: PortIdentity,
        sequence_id: u16,
    ) -> Self {
        let header = Header {
            two_step_flag: true,
            ..base_header(default_ds, port_identity, sequence_id)
        };

        Message {
            header,
            body: MessageBody::Sync(SyncMessage {
                origin_timestamp: Default::default(),
            }),
            suffix: ArrayVec::default(),
        }
    }

    pub(crate) fn follow_up(
        default_ds: &DefaultDS,
        port_identity: PortIdentity,
        sequence_id: u16,
        timestamp: Time,
    ) -> Self {
        let header = Header {
            correction_field: timestamp.subnano(),
            ..base_header(default_ds, port_identity, sequence_id)
        };

        Message {
            header,
            body: MessageBody::FollowUp(FollowUpMessage {
                precise_origin_timestamp: timestamp.into(),
            }),
            suffix: ArrayVec::default(),
        }
    }

    pub(crate) fn announce(
        global: &PtpInstanceState,
        port_identity: PortIdentity,
        sequence_id: u16,
    ) -> Self {
        let time_properties_ds = &global.time_properties_ds;

        let header = Header {
            leap59: time_properties_ds.leap_indicator == LeapIndicator::Leap59,
            leap61: time_properties_ds.leap_indicator == LeapIndicator::Leap61,
            current_utc_offset_valid: time_properties_ds.current_utc_offset.is_some(),
            ptp_timescale: time_properties_ds.ptp_timescale,
            time_tracable: time_properties_ds.time_traceable,
            frequency_tracable: time_properties_ds.frequency_traceable,
            ..base_header(&global.default_ds, port_identity, sequence_id)
        };

        let body = MessageBody::Announce(AnnounceMessage {
            header,
            origin_timestamp: Default::default(),
            current_utc_offset: time_properties_ds.current_utc_offset.unwrap_or_default(),
            grandmaster_priority_1: global.parent_ds.grandmaster_priority_1,
            grandmaster_clock_quality: global.parent_ds.grandmaster_clock_quality,
            grandmaster_priority_2: global.parent_ds.grandmaster_priority_2,
            grandmaster_identity: global.parent_ds.grandmaster_identity,
            steps_removed: global.current_ds.steps_removed,
            time_source: time_properties_ds.time_source,
        });

        Message {
            header,
            body,
            suffix: ArrayVec::default(),
        }
    }

    pub(crate) fn delay_req(
        default_ds: &DefaultDS,
        port_identity: PortIdentity,
        sequence_id: u16,
    ) -> Self {
        let header = Header {
            log_message_interval: 0x7f,
            ..base_header(default_ds, port_identity, sequence_id)
        };

        Message {
            header,
            body: MessageBody::DelayReq(DelayReqMessage {
                origin_timestamp: WireTimestamp::default(),
            }),
            suffix: ArrayVec::default(),
        }
    }

    pub(crate) fn delay_resp(
        request_header: Header,
        request: DelayReqMessage,
        port_identity: PortIdentity,
        min_delay_req_interval: Interval,
        timestamp: Time,
    ) -> Self {
        // TODO is it really correct that we don't use any of the data?
        let _ = request;

        let header = Header {
            two_step_flag: false,
            source_port_identity: port_identity,
            correction_field: TimeInterval(
                request_header.correction_field.0 + timestamp.subnano().0,
            ),
            log_message_interval: min_delay_req_interval.as_log_2(),
            ..request_header
        };

        let body = MessageBody::DelayResp(DelayRespMessage {
            receive_timestamp: timestamp.into(),
            requesting_port_identity: request_header.source_port_identity,
        });

        Message {
            header,
            body,
            suffix: ArrayVec::default(),
        }
    }
}

impl Message {
    pub(crate) fn header(&self) -> &Header {
        &self.header
    }

    /// The byte size on the wire of this message
    pub(crate) fn wire_size(&self) -> usize {
        self.header.wire_size() + self.content_size()
    }

    fn content_size(&self) -> usize {
        match &self.body {
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
        match self.body {
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

    /// Serializes the object into the PTP wire format.
    ///
    /// Returns the used buffer size that contains the message or an error.
    pub(crate) fn serialize(&self, buffer: &mut [u8]) -> Result<usize, super::WireFormatError> {
        let (header, rest) = buffer.split_at_mut(34);

        self.header
            .serialize_header(self.content_type(), self.content_size(), header)?;

        match &self.body {
            MessageBody::Sync(m) => m.serialize_content(rest)?,
            MessageBody::DelayReq(m) => m.serialize_content(rest)?,
            MessageBody::PDelayReq(m) => m.serialize_content(rest)?,
            MessageBody::PDelayResp(m) => m.serialize_content(rest)?,
            MessageBody::FollowUp(m) => m.serialize_content(rest)?,
            MessageBody::DelayResp(m) => m.serialize_content(rest)?,
            MessageBody::PDelayRespFollowUp(m) => m.serialize_content(rest)?,
            MessageBody::Announce(m) => m.serialize_content(rest)?,
            MessageBody::Signaling(m) => m.serialize_content(rest)?,
            MessageBody::Management(m) => m.serialize_content(rest)?,
        }

        Ok(self.wire_size())
    }

    /// Deserializes a message from the PTP wire format.
    ///
    /// Returns the message or an error.
    pub(crate) fn deserialize(buffer: &[u8]) -> Result<Self, super::WireFormatError> {
        let header_data = Header::deserialize_header(buffer)?;

        // Skip the header bytes and only keep the content
        let content_buffer = &buffer[34..];

        let body = match header_data.message_type {
            MessageType::Sync => {
                MessageBody::Sync(SyncMessage::deserialize_content(content_buffer)?)
            }
            MessageType::DelayReq => {
                MessageBody::DelayReq(DelayReqMessage::deserialize_content(content_buffer)?)
            }
            MessageType::PDelayReq => {
                MessageBody::PDelayReq(PDelayReqMessage::deserialize_content(content_buffer)?)
            }
            MessageType::PDelayResp => {
                MessageBody::PDelayResp(PDelayRespMessage::deserialize_content(content_buffer)?)
            }
            MessageType::FollowUp => {
                MessageBody::FollowUp(FollowUpMessage::deserialize_content(content_buffer)?)
            }
            MessageType::DelayResp => {
                MessageBody::DelayResp(DelayRespMessage::deserialize_content(content_buffer)?)
            }
            MessageType::PDelayRespFollowUp => MessageBody::PDelayRespFollowUp(
                PDelayRespFollowUpMessage::deserialize_content(content_buffer)?,
            ),
            MessageType::Announce => MessageBody::Announce(AnnounceMessage::deserialize_content(
                header_data.header,
                content_buffer,
            )?),
            MessageType::Signaling => {
                MessageBody::Signaling(SignalingMessage::deserialize_content(content_buffer)?)
            }
            MessageType::Management => {
                MessageBody::Management(ManagementMessage::deserialize_content(content_buffer)?)
            }
        };

        Ok(Message {
            header: header_data.header,
            body,
            suffix: ArrayVec::default(),
        })
    }
}
