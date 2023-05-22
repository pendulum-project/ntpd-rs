use super::{
    AnnounceMessage, DelayReqMessage, DelayRespMessage, FollowUpMessage, Header, Message,
    PtpVersion, SdoId, SyncMessage,
};
use crate::datastructures::common::{
    ClockIdentity, ClockQuality, PortIdentity, TimeInterval, TimeSource, Timestamp,
};

#[derive(Debug, Clone)]
pub enum MessageBuilderError {
    #[allow(unused)]
    IllegalValue,
}

/// A builder to build messages with.
///
/// This pattern is used because it is possible to construct messages that are
/// invalid. The length field in the header has to match the length of the
/// message (this might not be strictly necessary when using UDP, but there are
/// other transports as well). The message type field in the header has to match
/// the content type. These are the two major ones, but there are more.
///
/// By using a builder and then making the messages immutable, we guarantee that
/// all messages are valid.
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

    pub fn copy_header(mut self, message: Message) -> Self {
        self.header = *message.header();
        self
    }

    pub fn sdo_id(mut self, sdo_id: SdoId) -> Self {
        self.header.sdo_id = sdo_id;
        self
    }

    pub fn version_ptp(mut self, version: PtpVersion) -> Self {
        self.header.version = version;
        self
    }

    pub fn domain_number(mut self, domain_number: u8) -> Self {
        self.header.domain_number = domain_number;
        self
    }

    pub fn alternate_master_flag(mut self, alternate_master_flag: bool) -> Self {
        self.header.alternate_master_flag = alternate_master_flag;
        self
    }

    pub fn two_step_flag(mut self, two_step_flag: bool) -> Self {
        self.header.two_step_flag = two_step_flag;
        self
    }

    pub fn unicast_flag(mut self, unicast_flag: bool) -> Self {
        self.header.unicast_flag = unicast_flag;
        self
    }

    pub fn ptp_profile_specific_1(mut self, ptp_profile_specific_1: bool) -> Self {
        self.header.ptp_profile_specific_1 = ptp_profile_specific_1;
        self
    }

    pub fn ptp_profile_specific_2(mut self, ptp_profile_specific_2: bool) -> Self {
        self.header.ptp_profile_specific_2 = ptp_profile_specific_2;
        self
    }

    pub fn leap61(mut self, leap61: bool) -> Self {
        self.header.leap61 = leap61;
        self
    }

    pub fn leap59(mut self, leap59: bool) -> Self {
        self.header.leap59 = leap59;
        self
    }

    pub fn current_utc_offset_valid(mut self, current_utc_offset_valid: bool) -> Self {
        self.header.current_utc_offset_valid = current_utc_offset_valid;
        self
    }

    pub fn ptp_timescale(mut self, ptp_timescale: bool) -> Self {
        self.header.ptp_timescale = ptp_timescale;
        self
    }

    pub fn time_tracable(mut self, time_tracable: bool) -> Self {
        self.header.time_tracable = time_tracable;
        self
    }

    pub fn frequency_tracable(mut self, frequency_tracable: bool) -> Self {
        self.header.frequency_tracable = frequency_tracable;
        self
    }

    pub fn synchronization_uncertain(mut self, synchronization_uncertain: bool) -> Self {
        self.header.synchronization_uncertain = synchronization_uncertain;
        self
    }

    pub fn add_to_correction(mut self, correction: TimeInterval) -> Self {
        self.header.correction_field.0 += correction.0;
        self
    }

    pub fn correction_field(mut self, correction_field: TimeInterval) -> Self {
        self.header.correction_field = correction_field;
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

    pub fn log_message_interval(mut self, log_message_interval: i8) -> Self {
        self.header.log_message_interval = log_message_interval;
        self
    }

    pub fn sync_message(self, origin_timestamp: Timestamp) -> Message {
        Message::Sync(SyncMessage {
            header: self.header,
            origin_timestamp,
        })
    }

    pub fn delay_req_message(self, origin_timestamp: Timestamp) -> Message {
        Message::DelayReq(DelayReqMessage {
            header: self.header,
            origin_timestamp,
        })
    }

    pub fn follow_up_message(self, precise_origin_timestamp: Timestamp) -> Message {
        Message::FollowUp(FollowUpMessage {
            header: self.header,
            precise_origin_timestamp,
        })
    }

    pub fn delay_resp_message(
        self,
        receive_timestamp: Timestamp,
        requesting_port_identity: PortIdentity,
    ) -> Message {
        Message::DelayResp(DelayRespMessage {
            header: self.header,
            receive_timestamp,
            requesting_port_identity,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn announce_message(
        self,
        origin_timestamp: Timestamp,
        current_utc_offset: i16,
        grandmaster_priority_1: u8,
        grandmaster_clock_quality: ClockQuality,
        grandmaster_priority_2: u8,
        grandmaster_identity: ClockIdentity,
        steps_removed: u16,
        time_source: TimeSource,
    ) -> Message {
        Message::Announce(AnnounceMessage {
            header: self.header,
            origin_timestamp,
            current_utc_offset,
            grandmaster_priority_1,
            grandmaster_clock_quality,
            grandmaster_priority_2,
            grandmaster_identity,
            steps_removed,
            time_source,
        })
    }
}

impl Default for MessageBuilder {
    fn default() -> Self {
        MessageBuilder::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_sync_message() {
        let built_message = Message::builder().sync_message(Timestamp::default());

        assert!(matches!(built_message, Message::Sync(_)));
    }
}
