//! Ptp network messages

pub use announce::*;
pub use delay_req::*;
pub use delay_resp::*;
pub use follow_up::*;
pub use header::*;
pub use sync::*;

use self::{
    management::ManagementMessage, p_delay_req::PDelayReqMessage, p_delay_resp::PDelayRespMessage,
    p_delay_resp_follow_up::PDelayRespFollowUpMessage, signalling::SignalingMessage,
};
use super::{
    common::{TimeInterval, WireTimestamp},
    datasets::DefaultDS,
};
use crate::{ptp_instance::PtpInstanceState, Interval, LeapIndicator, PortIdentity, Time};

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
        current_time: Time,
    ) -> Self {
        Message::Sync(SyncMessage {
            header: Header {
                two_step_flag: true,
                ..base_header(default_ds, port_identity, sequence_id)
            },
            origin_timestamp: current_time.into(),
        })
    }

    pub(crate) fn follow_up(
        default_ds: &DefaultDS,
        port_identity: PortIdentity,
        sequence_id: u16,
        timestamp: Time,
    ) -> Self {
        Message::FollowUp(FollowUpMessage {
            header: Header {
                correction_field: timestamp.subnano(),
                ..base_header(default_ds, port_identity, sequence_id)
            },
            precise_origin_timestamp: timestamp.into(),
        })
    }

    pub(crate) fn announce<C, F>(
        global: &PtpInstanceState<C, F>,
        port_identity: PortIdentity,
        sequence_id: u16,
        current_time: Time,
    ) -> Self {
        Message::Announce(AnnounceMessage {
            header: Header {
                leap59: global.time_properties_ds.leap_indicator == LeapIndicator::Leap59,
                leap61: global.time_properties_ds.leap_indicator == LeapIndicator::Leap61,
                current_utc_offset_valid: global.time_properties_ds.current_utc_offset_valid,
                ptp_timescale: global.time_properties_ds.ptp_timescale,
                time_tracable: global.time_properties_ds.time_traceable,
                frequency_tracable: global.time_properties_ds.frequency_traceable,
                ..base_header(&global.default_ds, port_identity, sequence_id)
            },
            origin_timestamp: current_time.into(),
            current_utc_offset: global.time_properties_ds.current_utc_offset,
            grandmaster_priority_1: global.parent_ds.grandmaster_priority_1,
            grandmaster_clock_quality: global.parent_ds.grandmaster_clock_quality,
            grandmaster_priority_2: global.parent_ds.grandmaster_priority_2,
            grandmaster_identity: global.parent_ds.grandmaster_identity,
            steps_removed: global.current_ds.steps_removed,
            time_source: global.time_properties_ds.time_source,
        })
    }

    pub(crate) fn delay_req(
        default_ds: &DefaultDS,
        port_identity: PortIdentity,
        sequence_id: u16,
    ) -> Self {
        Message::DelayReq(DelayReqMessage {
            header: Header {
                log_message_interval: 0x7f,
                ..base_header(default_ds, port_identity, sequence_id)
            },
            origin_timestamp: WireTimestamp::default(),
        })
    }

    pub(crate) fn delay_resp(
        request: &DelayReqMessage,
        port_identity: PortIdentity,
        min_delay_req_interval: Interval,
        timestamp: Time,
    ) -> Self {
        Message::DelayResp(DelayRespMessage {
            header: Header {
                two_step_flag: false,
                source_port_identity: port_identity,
                correction_field: TimeInterval(
                    request.header.correction_field.0 + timestamp.subnano().0,
                ),
                log_message_interval: min_delay_req_interval.as_log_2(),
                ..request.header
            },
            receive_timestamp: timestamp.into(),
            requesting_port_identity: request.header.source_port_identity,
        })
    }
}

impl Message {
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
