use std::marker::PhantomData;

use crate::datastructures::{
    common::{ClockIdentity, ClockQuality, PortIdentity, TimeInterval, TimeSource, Timestamp},
    WireFormat,
};

use super::{
    AnnounceMessage, ControlField, DelayReqMessage, DelayRespMessage, FlagField, FollowUpMessage,
    Header, Message, MessageContent, MessageType, SyncMessage,
};

#[derive(Debug, Clone)]
pub enum MessageBuilderError {
    IllegalValue,
}

/// A builder to build messages with.
/// 
/// This pattern is used because it is possible to construct messages that are invalid.
/// The length field in the header has to match the length of the message (this might not be strictly necessary when using UDP, but there are other transports as well).
/// The message type field in the header has to match the content type.
/// These are the two major ones, but there are more.
/// 
/// By using a builder and then making the messages immutable, we guarantee that all messages are valid.
pub struct MessageBuilder<S: MessageBuilderState> {
    header: Header,
    content: Option<MessageContent>,
    phantom: PhantomData<S>,
}

impl MessageBuilder<HeaderBuilding> {
    /// Start the process of building a new message
    pub fn new() -> MessageBuilder<HeaderBuilding> {
        MessageBuilder {
            header: Header::new(),
            content: Default::default(),
            phantom: Default::default(),
        }
    }
}

impl MessageBuilder<HeaderBuilding> {
    /// Assign the fields of the header
    pub fn header(
        mut self,
        major_sdo_id: u8,
        minor_version_ptp: u8,
        version_ptp: u8,
        domain_number: u8,
        minor_sdo_id: u8,
        flag_field: FlagField,
        correction_field: TimeInterval,
        message_type_specific: [u8; 4],
        source_port_identity: PortIdentity,
        sequence_id: u16,
        log_message_interval: u8,
    ) -> Result<MessageBuilder<ContentBuilding>, MessageBuilderError> {
        if major_sdo_id >= 0x10 {
            Err(MessageBuilderError::IllegalValue)
        } else if minor_version_ptp >= 0x10 {
            Err(MessageBuilderError::IllegalValue)
        } else if version_ptp >= 0x10 {
            Err(MessageBuilderError::IllegalValue)
        } else {
            self.header.major_sdo_id = major_sdo_id;
            self.header.minor_version_ptp = minor_version_ptp;
            self.header.version_ptp = version_ptp;
            self.header.domain_number = domain_number;
            self.header.minor_sdo_id = minor_sdo_id;
            self.header.flag_field = flag_field;
            self.header.correction_field = correction_field;
            self.header.message_type_specific = message_type_specific;
            self.header.source_port_identity = source_port_identity;
            self.header.sequence_id = sequence_id;
            self.header.log_message_interval = log_message_interval;

            Ok(MessageBuilder {
                header: self.header,
                content: self.content,
                phantom: Default::default(),
            })
        }
    }
}

impl MessageBuilder<ContentBuilding> {
    pub fn sync_message(mut self, origin_timestamp: Timestamp) -> MessageBuilder<FinishBuilding> {
        self.header.message_type = MessageType::Sync;
        self.header.control_field = ControlField::Sync;
        self.content = Some(MessageContent::Sync(SyncMessage { origin_timestamp }));

        MessageBuilder {
            header: self.header,
            content: self.content,
            phantom: Default::default(),
        }
    }

    pub fn delay_req_message(
        mut self,
        origin_timestamp: Timestamp,
    ) -> MessageBuilder<FinishBuilding> {
        self.header.message_type = MessageType::DelayReq;
        self.header.control_field = ControlField::DelayReq;
        self.content = Some(MessageContent::DelayReq(DelayReqMessage {
            origin_timestamp,
        }));

        MessageBuilder {
            header: self.header,
            content: self.content,
            phantom: Default::default(),
        }
    }

    pub fn follow_up_message(
        mut self,
        precise_origin_timestamp: Timestamp,
    ) -> MessageBuilder<FinishBuilding> {
        self.header.message_type = MessageType::FollowUp;
        self.header.control_field = ControlField::FollowUp;
        self.content = Some(MessageContent::FollowUp(FollowUpMessage {
            precise_origin_timestamp,
        }));

        MessageBuilder {
            header: self.header,
            content: self.content,
            phantom: Default::default(),
        }
    }

    pub fn delay_resp_message(
        mut self,
        receive_timestamp: Timestamp,
        requesting_port_identity: PortIdentity,
    ) -> MessageBuilder<FinishBuilding> {
        self.header.message_type = MessageType::DelayResp;
        self.header.control_field = ControlField::DelayResp;
        self.content = Some(MessageContent::DelayResp(DelayRespMessage {
            receive_timestamp,
            requesting_port_identity,
        }));

        MessageBuilder {
            header: self.header,
            content: self.content,
            phantom: Default::default(),
        }
    }

    pub fn announce_message(
        mut self,
        origin_timestamp: Timestamp,
        current_utc_offset: u16,
        grandmaster_priority_1: u8,
        grandmaster_clock_quality: ClockQuality,
        grandmaster_priority_2: u8,
        grandmaster_identity: ClockIdentity,
        steps_removed: u16,
        time_source: TimeSource,
    ) -> MessageBuilder<FinishBuilding> {
        self.header.message_type = MessageType::Announce;
        self.header.control_field = ControlField::AllOthers;
        self.content = Some(MessageContent::Announce(AnnounceMessage {
            origin_timestamp,
            current_utc_offset,
            grandmaster_priority_1,
            grandmaster_clock_quality,
            grandmaster_priority_2,
            grandmaster_identity,
            steps_removed,
            time_source,
        }));

        MessageBuilder {
            header: self.header,
            content: self.content,
            phantom: Default::default(),
        }
    }
}

impl MessageBuilder<FinishBuilding> {
    pub fn finish(self) -> Message {
        let mut message = Message {
            header: self.header,
            content: self.content.unwrap(),
        };

        message.header.message_length = message.wire_size() as u16;

        message
    }
}

pub trait MessageBuilderState {}

pub struct HeaderBuilding;
impl MessageBuilderState for HeaderBuilding {}
pub struct ContentBuilding;
impl MessageBuilderState for ContentBuilding {}
pub struct FinishBuilding;
impl MessageBuilderState for FinishBuilding {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_sync_message() {
        let built_message = Message::builder()
            .header(
                0,
                0,
                0,
                0,
                0,
                FlagField::default(),
                TimeInterval::default(),
                [0, 0, 0, 0],
                PortIdentity::default(),
                0,
                0,
            )
            .unwrap()
            .sync_message(Timestamp::default())
            .finish();

        assert_eq!(
            built_message.header.message_length() as usize,
            built_message.wire_size()
        );
        assert!(matches!(built_message.content, MessageContent::Sync(_)));
    }
}
