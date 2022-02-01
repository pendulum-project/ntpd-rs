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
pub struct MessageBuilder {
    header: Header,
}

impl MessageBuilder {
    /// Start the process of building a new message
    pub fn new() -> MessageBuilder {
        MessageBuilder {
            header: Header::new(),
        }
    }
}

impl MessageBuilder {
    pub fn sdo_id(mut self, sdo_id: u16) -> Result<Self, MessageBuilderError> {
        if sdo_id >= 0x1000 {
            return Err(MessageBuilderError::IllegalValue);
        }
        self.header.sdo_id = sdo_id;
        Ok(self)
    }

    pub fn version_ptp(mut self, major: u8, minor: u8) -> Result<Self, MessageBuilderError> {
        if major >= 0x10 || minor >= 0x10 {
            return Err(MessageBuilderError::IllegalValue);
        }
        self.header.version_ptp = major;
        self.header.minor_version_ptp = minor;
        Ok(self)
    }

    pub fn domain_number(mut self, domain_number: u8) -> Self {
        self.header.domain_number = domain_number;
        self
    }

    pub fn flag_field(mut self, flag_field: FlagField) -> Self {
        self.header.flag_field = flag_field;
        self
    }

    pub fn correction_field(mut self, correction_field: TimeInterval) -> Self {
        self.header.correction_field = correction_field;
        self
    }

    pub fn message_type_specific(mut self, message_type_specific: [u8; 4]) -> Self {
        self.header.message_type_specific = message_type_specific;
        self
    }

    pub fn source_port_identity(mut self, source_port_identity: PortIdentity) -> Self {
        self.header.source_port_identity = source_port_identity;
        self
    }

    pub fn sequence_id(mut self, sequence_id: u16) -> Self {
        self.header.sequence_id = sequence_id;
        self
    }

    pub fn log_message_interval(mut self, log_message_interval: u8) -> Self {
        self.header.log_message_interval = log_message_interval;
        self
    }

    pub fn sync_message(mut self, origin_timestamp: Timestamp) -> Message {
        self.header.message_type = MessageType::Sync;
        self.header.control_field = ControlField::Sync;

        let mut message = Message {
            header: self.header,
            content: MessageContent::Sync(SyncMessage { origin_timestamp }),
        };
        message.header.message_length = message.wire_size() as u16;
        message
    }

    pub fn delay_req_message(mut self, origin_timestamp: Timestamp) -> Message {
        self.header.message_type = MessageType::DelayReq;
        self.header.control_field = ControlField::DelayReq;

        let mut message = Message {
            header: self.header,
            content: MessageContent::DelayReq(DelayReqMessage { origin_timestamp }),
        };
        message.header.message_length = message.wire_size() as u16;
        message
    }

    pub fn follow_up_message(mut self, precise_origin_timestamp: Timestamp) -> Message {
        self.header.message_type = MessageType::FollowUp;
        self.header.control_field = ControlField::FollowUp;

        let mut message = Message {
            header: self.header,
            content: MessageContent::FollowUp(FollowUpMessage {
                precise_origin_timestamp,
            }),
        };
        message.header.message_length = message.wire_size() as u16;
        message
    }

    pub fn delay_resp_message(
        mut self,
        receive_timestamp: Timestamp,
        requesting_port_identity: PortIdentity,
    ) -> Message {
        self.header.message_type = MessageType::DelayResp;
        self.header.control_field = ControlField::DelayResp;

        let mut message = Message {
            header: self.header,
            content: MessageContent::DelayResp(DelayRespMessage {
                receive_timestamp,
                requesting_port_identity,
            }),
        };
        message.header.message_length = message.wire_size() as u16;
        message
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
    ) -> Message {
        self.header.message_type = MessageType::Announce;
        self.header.control_field = ControlField::AllOthers;

        let mut message = Message {
            header: self.header,
            content: MessageContent::Announce(AnnounceMessage {
                origin_timestamp,
                current_utc_offset,
                grandmaster_priority_1,
                grandmaster_clock_quality,
                grandmaster_priority_2,
                grandmaster_identity,
                steps_removed,
                time_source,
            }),
        };
        message.header.message_length = message.wire_size() as u16;
        message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_sync_message() {
        let built_message = Message::builder().sync_message(Timestamp::default());

        assert_eq!(
            built_message.header.message_length() as usize,
            built_message.wire_size()
        );
        assert!(matches!(built_message.content, MessageContent::Sync(_)));
    }
}
