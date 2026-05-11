use core::ops::Deref;

use ntp_proto::{NtpLeapIndicator, TimeSnapshot};
use statime_wire::{
    ClockIdentity, FollowUpMessage, Header, Message, MessageBody, PortIdentity, PtpVersion, SdoId,
    SyncMessage, TimeInterval, Timestamp, TlvSetBuilder, TlvType,
};

use crate::{
    CsptpState,
    messages::tlvs::{CsptpRequestTlv, CsptpResponseTlv, CsptpStatusTlv},
};

mod tlvs;

pub(crate) const MAX_MESSAGE_SIZE: usize = 512;

/// A message with additional restrictions to ensure it is a valid CSPTP Message.
pub(crate) struct CsptpMessage<'a> {
    message: Message<'a>,
}

fn csptp_header(domain_number: u8, sequence_id: u16) -> Header {
    Header {
        sdo_id: SdoId::try_from(0x300).unwrap(),
        version: PtpVersion::new(2, 1).unwrap(),
        domain_number,
        alternate_master_flag: false,
        two_step_flag: false,
        unicast_flag: true,
        ptp_profile_specific_1: false,
        ptp_profile_specific_2: false,
        leap61: false,
        leap59: false,
        current_utc_offset_valid: false,
        ptp_timescale: false,
        time_tracable: false,
        frequency_tracable: false,
        synchronization_uncertain: false,
        correction_field: TimeInterval(0),
        source_port_identity: PortIdentity {
            clock_identity: ClockIdentity([0; _]),
            port_number: 0,
        },
        sequence_id,
        log_message_interval: 0x7f,
    }
}

impl<'a> CsptpMessage<'a> {
    /// Deserializes a message from the PTP wire format.
    ///
    /// # Errors
    /// This returns an error when the provided buffer does not contain a valid
    /// PTP message, or when the provided message is incomplete.
    pub(crate) fn deserialize(buffer: &'a [u8]) -> Result<Self, statime_wire::Error> {
        let message = Message::deserialize(buffer)?;
        if message.header.sdo_id != SdoId::try_from(0x300).unwrap()
            || message.header.version.major() != 2
        {
            return Err(statime_wire::Error::Invalid);
        }
        match message.body {
            statime_wire::MessageBody::Sync(_) => {
                let num_request_tlvs = message
                    .suffix
                    .tlvs()
                    .filter(|tlv| tlv.tlv_type == TlvType::CsptpRequest)
                    .count();
                let num_valid_request_tlvs = message
                    .suffix
                    .tlvs()
                    .filter_map(|tlv| CsptpRequestTlv::try_from(&tlv))
                    .count();
                let num_response_tlvs = message
                    .suffix
                    .tlvs()
                    .filter(|tlv| tlv.tlv_type == TlvType::CsptpResponse)
                    .count();
                let num_valid_response_tlvs = message
                    .suffix
                    .tlvs()
                    .filter_map(|tlv| CsptpResponseTlv::try_from(&tlv))
                    .count();
                if num_request_tlvs + num_response_tlvs != 1
                    || num_request_tlvs != num_valid_request_tlvs
                    || num_response_tlvs != num_valid_response_tlvs
                {
                    return Err(statime_wire::Error::Invalid);
                }
            }
            statime_wire::MessageBody::FollowUp(_) => {
                // No additional requirements on FollowUp messages
            }
            _ => return Err(statime_wire::Error::Invalid),
        }
        Ok(CsptpMessage { message })
    }

    pub(crate) fn is_request(&self) -> bool {
        matches!(self.message.body, MessageBody::Sync(_))
            && self
                .message
                .suffix
                .tlvs()
                .any(|tlv| tlv.tlv_type == TlvType::CsptpRequest)
    }

    pub(crate) fn is_response(&self) -> bool {
        matches!(self.message.body, MessageBody::Sync(_))
            && self
                .message
                .suffix
                .tlvs()
                .any(|tlv| tlv.tlv_type == TlvType::CsptpResponse)
    }

    /// Generate a new request message. The buffer must be at least 8 bytes long
    #[expect(unused)]
    pub(crate) fn new_request(
        buffer: &'a mut [u8],
        domain_number: u8,
        sequence_id: u16,
    ) -> Result<Self, statime_wire::Error> {
        let mut tlv_builder = TlvSetBuilder::new(buffer);
        CsptpRequestTlv {
            csptp_status: true,
            alt_timescale: false,
        }
        .add_to(&mut tlv_builder)?;

        Ok(CsptpMessage {
            message: Message {
                header: csptp_header(domain_number, sequence_id),
                body: MessageBody::Sync(SyncMessage {
                    origin_timestamp: Timestamp::new(0, 0).unwrap(),
                }),
                suffix: tlv_builder.build(),
            },
        })
    }

    /// Generate a response to a request. A buffer of 30 bytes will always be able to contain the response
    pub(crate) fn new_response(
        buffer: &'a mut [u8],
        request: &CsptpMessage<'_>,
        recv_timestamp: Timestamp,
        send_timestamp: Option<Timestamp>,
        time_snapshot: &TimeSnapshot,
        csptp_state: &CsptpState,
    ) -> Result<Self, statime_wire::Error> {
        // Sanity check
        if !matches!(request.message.body, MessageBody::Sync(_)) {
            return Err(statime_wire::Error::Invalid);
        }

        let Some(request_tlv) = request
            .message
            .suffix
            .tlvs()
            .find_map(|tlv| CsptpRequestTlv::try_from(&tlv))
        else {
            return Err(statime_wire::Error::Invalid);
        };

        let mut tlv_builder = TlvSetBuilder::new(buffer);
        CsptpResponseTlv {
            req_ingress_timestamp: recv_timestamp,
            req_correction_field: request.header.correction_field,
        }
        .add_to(&mut tlv_builder)?;
        if request_tlv.csptp_status {
            CsptpStatusTlv {
                grandmaster_priority1: csptp_state.grandmaster_priority_1,
                grandmaster_clock_quality: csptp_state.grandmaster_clock_quality,
                grandmaster_priority2: csptp_state.grandmaster_priority_2,
                steps_removed: csptp_state.steps_removed,
                current_utc_offset: 0,
                grandmaster_identity: csptp_state.grandmaster_identity,
            }
            .add_to(&mut tlv_builder)?;
        }

        Ok(CsptpMessage {
            message: Message {
                header: Header {
                    leap61: time_snapshot.leap_indicator == NtpLeapIndicator::Leap61,
                    leap59: time_snapshot.leap_indicator == NtpLeapIndicator::Leap59,
                    current_utc_offset_valid: false,
                    ptp_timescale: csptp_state.ptp_timescale,
                    time_tracable: csptp_state.time_traceable,
                    frequency_tracable: csptp_state.frequency_traceable,
                    two_step_flag: send_timestamp.is_none(),
                    ..csptp_header(request.header.domain_number, request.header.sequence_id)
                },
                body: MessageBody::Sync(SyncMessage {
                    origin_timestamp: send_timestamp.unwrap_or_default(),
                }),
                suffix: tlv_builder.build(),
            },
        })
    }

    pub(crate) fn new_follow_up(
        response: &CsptpMessage<'_>,
        send_timestamp: Timestamp,
    ) -> Result<Self, statime_wire::Error> {
        // Sanity check
        if !response.is_response() || !response.message.header.two_step_flag {
            return Err(statime_wire::Error::Invalid);
        }

        Ok(CsptpMessage {
            message: Message {
                header: Header {
                    two_step_flag: true,
                    ..csptp_header(
                        response.message.header.domain_number,
                        response.message.header.sequence_id,
                    )
                },
                body: MessageBody::FollowUp(FollowUpMessage {
                    precise_origin_timestamp: send_timestamp,
                }),
                suffix: TlvSetBuilder::new(&mut []).build(),
            },
        })
    }
}

impl<'a> Deref for CsptpMessage<'a> {
    type Target = Message<'a>;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}
